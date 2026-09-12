/*
 * Журнал сервиса контура: порог, приёмник waf.log и живая настройка уровня.
 *
 * Инспекторы отдают журнал в waf.log с самого начала (internal/logsink у
 * каждого), а сервисы -- агенты, keeper, geo, логгер, поиск, crypto -- писали
 * только в stdout. На вопрос «что писал keeper, пока отказывала калитка»
 * отвечал только docker compose logs того контейнера, про который заранее
 * знали, что спрашивать надо его. Пакет закрывает эту дыру: та же пачка
 * kind=log в тот же WAF_LOG, тот же словарь уровней (docs/logger/logs.md).
 *
 * Уровень живой, как у инспектора, но источник другой: записи каталога и
 * поколения у сервиса нет. Порог едет документом policy/log-levels в KV
 * WAF_DESIRED -- одним на весь контур, по ключу имени сервиса (levels.go).
 * Переменная окружения -- стартовое значение и то, куда порог возвращается,
 * когда контроллер своё значение снимает.
 *
 * Порог -- слово из loglevel, общего словаря инспекторов и сервисов: оператор
 * ставит уровень краю, инспектору и сервису одними словами, ничего не
 * переводя. Стартовое значение -- loglevel.Env по переменной процесса.
 */

package logkit

import (
	"context"
	"log/slog"
	"os"
	"strings"
	"sync"

	"github.com/nats-io/nats.go"
)

// Options -- чем журнал сервиса отличается от соседнего.
type Options struct {
	// Service -- колонка service в waf.log и ключ в policy/log-levels.
	Service string
	// Writer -- колонка writer. Пусто -- WAF_LOG_WRITER, потом имя машины.
	Writer string
	// Level -- стартовый порог (переменная окружения процесса).
	Level slog.Level
	// IO -- канал log в пульсе. nil -- потери видны только в Dropped/Failed.
	IO Counter
}

/*
 * Journal -- журнал сервиса целиком. Log печатает в stdout и, если доставка
 * не выключена, тем же вызовом кладёт строку в пачку.
 */
type Journal struct {
	Log *slog.Logger

	service string
	base    slog.Level
	level   *slog.LevelVar
	sink    *Sink
	quiet   *slog.Logger

	mu     sync.Mutex
	cancel context.CancelFunc
}

/*
 * Open поднимает журнал до шины: конфиг читается раньше NATS, а строки о том,
 * как он читался, -- ровно те, которые нужнее всего. До Attach они копятся и
 * уезжают первой же пачкой.
 */
func Open(o Options) *Journal {
	level := new(slog.LevelVar)
	level.Set(o.Level)

	var sink *Sink

	if Ship() {
		writer := o.Writer
		if writer == "" {
			writer = WriterName(o.Service)
		}

		sink = NewSink(writer, o.Service, o.IO)
	}

	opts := &slog.HandlerOptions{Level: level}

	return &Journal{
		Log:     slog.New(slog.NewJSONHandler(sink.Tee(os.Stdout), opts)),
		service: o.Service,
		base:    o.Level,
		level:   level,
		sink:    sink,
		quiet:   slog.New(slog.NewJSONHandler(os.Stdout, opts)),
	}
}

/*
 * Attach подключает журнал к шине: заводит поток, если его ещё нет, включает
 * публикацию накопленного и подписывается на policy/log-levels. Ничего здесь
 * не валит процесс: без шины журнал остаётся в stdout, порог -- стартовым.
 *
 * Повторный вызов (новое соединение после рестарта шины у процесса, который
 * держит своё) переподписывает уровень на новое соединение.
 */
func (j *Journal) Attach(ctx context.Context, nc *nats.Conn) {
	if j == nil || nc == nil {
		return
	}

	if j.sink != nil {
		if err := Ensure(nc); err != nil {
			j.Log.Warn("log stream", "error", err.Error())
		}

		j.sink.Attach(nc)
		j.Log.Info("log stream", "stream", Stream,
			"subject", Subject(j.sink.Writer()), "service", j.service)
	}

	watchCtx, cancel := context.WithCancel(ctx)

	j.mu.Lock()
	if j.cancel != nil {
		j.cancel()
	}
	j.cancel = cancel
	j.mu.Unlock()

	go j.watch(watchCtx, nc)
}

// Close добивает накопленное и снимает подписку на уровень.
func (j *Journal) Close() {
	if j == nil {
		return
	}

	j.mu.Lock()
	if j.cancel != nil {
		j.cancel()
		j.cancel = nil
	}
	j.mu.Unlock()

	j.sink.Close()
}

// Level -- живой порог. Отдаётся наружу ради пульса и тестов, не для записи:
// пишет его только документ контроллера.
func (j *Journal) Level() slog.Level {
	return j.level.Level()
}

// Service -- имя сервиса: колонка service и ключ в policy/log-levels.
func (j *Journal) Service() string {
	return j.service
}

// Sink -- приёмник для строк чужого писателя (syslog рядом с процессом).
// nil при WAF_LOG_SHIP=off -- все методы приёмника это переживают.
func (j *Journal) Sink() *Sink {
	return j.sink
}

/*
 * Quiet -- тот же порог, но только stdout. Для строк, которые в журнал ехать
 * не могут по построению: разбор потока WAF_LOG, пишущий о каждой вставке,
 * порождал бы вставку на каждую свою строку -- петлю.
 */
func (j *Journal) Quiet() *slog.Logger {
	return j.quiet
}

/*
 * Ship -- WAF_LOG_SHIP. Переменная общая для всего контура, без имени
 * процесса: выключать доставку десятью разными переменными незачем. off
 * оставляет журнал только в stdout -- для машины, где его собирает кто-то
 * другой. Объём ею не режут: для объёма есть уровень.
 */
func Ship() bool {
	switch strings.ToLower(strings.TrimSpace(os.Getenv("WAF_LOG_SHIP"))) {
	case "off", "0", "no", "false":
		return false
	default:
		return true
	}
}

/*
 * WriterName -- колонка writer: WAF_LOG_WRITER, потом имя машины, потом
 * fallback. Имя машины -- то же, что уходит hostname кадра присутствия: по
 * нему строка журнала и кадр сходятся на один процесс.
 */
func WriterName(fallback string) string {
	if v := strings.TrimSpace(os.Getenv("WAF_LOG_WRITER")); v != "" {
		return v
	}

	if name, err := os.Hostname(); err == nil && name != "" {
		return name
	}

	return fallback
}

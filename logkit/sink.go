/*
 * Журнал процесса в общий обменник: та же таблица waf.log, что и у строк nginx.
 *
 * Порт inspectors/<имя>/internal/logsink: одна форма на проводе -- один разбор в
 * logger/internal/model.FromLog. Границы пачки те же (500 строк, 256 КБ,
 * 200 мс), потолок буфера тот же, и при переполнении так же выбрасывается
 * голова: свежая строка объясняет, что происходит сейчас.
 *
 * Отличий два. Счётчик канала -- интерфейс, а не тип: у модулей свой flow
 * или нет его вовсе. И строку можно положить
 * готовой (Add): приёмник syslog рядом с процессом (haproxy у своего агента)
 * кладёт в ту же пачку строки чужого писателя со своим сервисом и уровнем.
 *
 * Копия, а не перенос. Строка по-прежнему уходит в stdout, и
 * `docker compose logs <сервис>` остаётся первым местом, куда смотрят, -- в том
 * числе когда лежит сам контур доставки.
 *
 * Своей публикации ошибок здесь нет и быть не может: журнал, который пишет в
 * журнал о том, что не смог написать в журнал, -- это петля. Потери едут
 * ошибками канала `log` в секции `io` кадра присутствия там, где она есть, и
 * счётчиками Dropped/Failed.
 */

package logkit

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
	"sync"
	"time"

	"github.com/nats-io/nats.go"
)

const (
	Stream  = "WAF_LOG"
	Kind    = "log"
	Version = 1

	// maxText -- потолок текста строки, тот же, что у агента и у логгера.
	maxText = 8 << 10

	// Границы пачки. Совпадают с nginxlog и logsink инспекторов.
	maxLines = 500
	maxSize  = 256 << 10

	flushEvery = 200 * time.Millisecond

	// Потолок буфера при недоступной шине. Дальше выбрасываем самые старые.
	maxPending = 20000

	MaxAge      = 24 * time.Hour
	StreamBytes = 128 << 20
)

// Counter -- канал log в секции io кадра присутствия: flow.Counter процесса.
type Counter interface {
	AddN(n int, in, out uint64, isErr bool, latency time.Duration)
}

// Subject -- куда едет пачка: `waf.log.<писатель>`, как у агента и инспекторов.
func Subject(writer string) string {
	if writer == "" {
		writer = "unknown"
	}

	return "waf.log." + token(writer)
}

// Line -- одна строка журнала, как её увидит обменник.
type Line struct {
	TS       time.Time `json:"ts"`
	Service  string    `json:"service"`
	Severity string    `json:"severity,omitempty"`
	Text     string    `json:"text"`
}

// batch -- то, что уезжает одним сообщением.
type batch struct {
	V      int    `json:"v"`
	Kind   string `json:"kind"`
	Writer string `json:"writer"`
	Lines  []Line `json:"lines"`
}

/*
 * Sink копит строки и отправляет их пачками. Публикация идёт из своей
 * горутины: slog не должен ждать шину на вызове log.Info.
 *
 * Nil-приёмник -- рабочее состояние, а не ошибка: он значит «журнал только в
 * stdout» (WAF_LOG_SHIP=off), и все методы его переживают.
 */
type Sink struct {
	writer  string
	service string
	io      Counter

	mu      sync.Mutex
	nc      *nats.Conn
	pending []Line
	size    int
	dropped uint64
	failed  uint64

	wake chan struct{}
	done chan struct{}
	stop chan struct{}
	once sync.Once
}

// NewSink поднимает приёмник до подключения к шине: строки старта копятся и
// уезжают первой же пачкой после Attach.
func NewSink(writer, service string, io Counter) *Sink {
	if writer == "" {
		writer = "unknown"
	}

	if service == "" {
		service = "unknown"
	}

	s := &Sink{
		writer:  writer,
		service: service,
		io:      io,
		wake:    make(chan struct{}, 1),
		done:    make(chan struct{}),
		stop:    make(chan struct{}),
	}

	go s.loop()

	return s
}

// Attach включает публикацию. До неё пачки не уезжают, но копятся.
func (s *Sink) Attach(nc *nats.Conn) {
	if s == nil || nc == nil {
		return
	}

	s.mu.Lock()
	s.nc = nc
	s.mu.Unlock()

	s.kick()
}

// Tee подмешивает приёмник к обычному выводу; без приёмника отдаёт out.
func (s *Sink) Tee(out io.Writer) io.Writer {
	if s == nil {
		return out
	}

	return io.MultiWriter(out, s)
}

/*
 * Write -- io.Writer для обработчика slog: одна запись -- один вызов. Строка
 * едет в таблицу ровно той же, какой её напечатали в stdout.
 *
 * Не блокирует и не ошибается: slog держит на этом вызове свой мьютекс.
 */
func (s *Sink) Write(p []byte) (int, error) {
	if s == nil {
		return len(p), nil
	}

	text := strings.TrimRight(string(p), "\x00\r\n")
	if text == "" {
		return len(p), nil
	}

	s.Add(Line{
		TS:       time.Now().UTC(),
		Service:  s.service,
		Severity: severity(p),
		Text:     text,
	})

	return len(p), nil
}

/*
 * Add кладёт готовую строку в пачку. Пустые время и сервис заполняются своими:
 * у строки из чужого сокета нет ни того, ни другого, если шапка не разобралась.
 */
func (s *Sink) Add(line Line) {
	if s == nil || line.Text == "" {
		return
	}

	if line.TS.IsZero() {
		line.TS = time.Now().UTC()
	}

	if line.Service == "" {
		line.Service = s.service
	}

	if len(line.Text) > maxText {
		line.Text = line.Text[:maxText]
	}

	s.add(line)
}

// Writer -- чем подписан журнал (колонка writer).
func (s *Sink) Writer() string {
	if s == nil {
		return ""
	}

	return s.writer
}

// Dropped -- сколько строк выброшено переполнением буфера за всё время.
func (s *Sink) Dropped() uint64 {
	if s == nil {
		return 0
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	return s.dropped
}

// Failed -- сколько строк потеряно сорванной публикацией.
func (s *Sink) Failed() uint64 {
	if s == nil {
		return 0
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	return s.failed
}

// Pending -- сколько строк ждёт отправки: шины нет или пачка ещё не ушла.
func (s *Sink) Pending() int {
	if s == nil {
		return 0
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	return len(s.pending)
}

// Close добивает накопленное и останавливает отправку.
func (s *Sink) Close() {
	if s == nil {
		return
	}

	s.once.Do(func() {
		close(s.stop)
		<-s.done
	})
}

func (s *Sink) add(line Line) {
	s.mu.Lock()

	s.pending = append(s.pending, line)
	s.size += len(line.Text) + 64

	var cut int

	if len(s.pending) > maxPending {
		cut = len(s.pending) - maxPending
		s.dropped += uint64(cut)
		s.pending = append(s.pending[:0], s.pending[cut:]...)
	}

	full := len(s.pending) >= maxLines || s.size >= maxSize
	s.mu.Unlock()

	// Потеря -- ошибка канала, а не строка в журнале: писать о ней тем же
	// логгером значит замкнуть переполнение само на себя.
	if cut > 0 && s.io != nil {
		s.io.AddN(cut, 0, 0, true, 0)
	}

	if full {
		s.kick()
	}
}

func (s *Sink) kick() {
	select {
	case s.wake <- struct{}{}:
	default:
	}
}

func (s *Sink) loop() {
	defer close(s.done)

	tick := time.NewTicker(flushEvery)
	defer tick.Stop()

	for {
		select {
		case <-s.stop:
			s.flush()
			return
		case <-s.wake:
			s.flush()
		case <-tick.C:
			s.flush()
		}
	}
}

func (s *Sink) flush() {
	for {
		s.mu.Lock()

		// Шины ещё нет: держим накопленное, а не выбрасываем.
		if s.nc == nil || len(s.pending) == 0 {
			s.mu.Unlock()

			return
		}

		n := len(s.pending)
		if n > maxLines {
			n = maxLines
		}

		lines := make([]Line, n)
		copy(lines, s.pending[:n])

		s.pending = append(s.pending[:0], s.pending[n:]...)
		s.size = 0

		for _, l := range s.pending {
			s.size += len(l.Text) + 64
		}

		nc := s.nc
		s.mu.Unlock()

		s.publish(nc, lines)
	}
}

func (s *Sink) publish(nc *nats.Conn, lines []Line) {
	start := time.Now()

	body, err := json.Marshal(batch{
		V:      Version,
		Kind:   Kind,
		Writer: s.writer,
		Lines:  lines,
	})
	if err == nil {
		err = nc.Publish(Subject(s.writer), body)
	}

	if err != nil {
		s.mu.Lock()
		s.failed += uint64(len(lines))
		s.mu.Unlock()
	}

	if s.io != nil {
		s.io.AddN(len(lines), 0, uint64(len(body)), err != nil, time.Since(start))
	}
}

/*
 * Ensure создаёт поток логов, если его ещё нет. Конфиг совпадает с
 * nginx/agent/internal/nginxlog, logsink инспекторов и tests/streams/streams.sh:
 * поток заводит тот писатель, который пришёл первым.
 */
func Ensure(nc *nats.Conn) error {
	if nc == nil {
		return fmt.Errorf("logkit: nats connection is nil")
	}

	js, err := nc.JetStream()
	if err != nil {
		return err
	}

	_, err = js.AddStream(&nats.StreamConfig{
		Name:      Stream,
		Subjects:  []string{"waf.log.>"},
		Storage:   nats.FileStorage,
		Retention: nats.LimitsPolicy,
		MaxAge:    MaxAge,
		MaxBytes:  StreamBytes,
		Discard:   nats.DiscardOld,
	})
	if err == nil || errors.Is(err, nats.ErrStreamNameAlreadyInUse) {
		return nil
	}

	return err
}

// levelKey -- поле уровня в строке, которую печатает slog.NewJSONHandler.
var levelKey = []byte(`"level":"`)

// severity вынимает уровень из уже напечатанной строки. Не нашлось --
// уровень пустой: severity в waf.log необязательна, а терять строку нельзя.
func severity(p []byte) string {
	at := bytes.Index(p, levelKey)
	if at < 0 {
		return ""
	}

	rest := p[at+len(levelKey):]

	end := bytes.IndexByte(rest, '"')
	if end <= 0 {
		return ""
	}

	name := string(rest[:end])

	// INFO+2 -- это тоже info: в колонке закрытый набор syslog-имён.
	if cut := strings.IndexAny(name, "+-"); cut > 0 {
		name = name[:cut]
	}

	return strings.ToLower(name)
}

// token убирает из имени писателя то, что шина считает разделителем.
func token(s string) string {
	return strings.NewReplacer(">", "_", "*", "_", " ", "_", "\t", "_").Replace(s)
}

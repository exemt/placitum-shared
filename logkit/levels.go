/*
 * Живой уровень сервиса: документ policy/log-levels в KV WAF_DESIRED.
 *
 *     {"v":1,"kind":"log-levels","rev":3,"levels":{"keeper":"debug","geo":"warn"}}
 *
 * Один документ на контур, ключ -- имя сервиса (колонка service в waf.log).
 * Пишет его контроллер (панель «Журналы → Уровни»), читают все сервисы.
 * Инспекторов здесь нет: их уровень -- запись каталога, едет поколением
 * (docs/inspector-config-distribution.md), и второй источник для того же
 * порога только спорил бы с первым.
 *
 * Своего ключа в документе нет -- порог возвращается к стартовому значению из
 * окружения. Так «снять» значит «вернуть как было», а не «угадать, как было».
 * Чужое слово в своём ключе -- строка предупреждения и прежний порог: документ
 * пишет контроллер, и слово вне словаря значит, что его положили руками.
 *
 * Отдельный документ, а не поле пульса или subject с командой: KV помнит
 * значение, и сервис, поднявшийся после правки, получает его первым же
 * событием watch, а не ждёт следующей.
 */

package logkit

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/nats-io/nats.go"
	"github.com/nats-io/nats.go/jetstream"

	"github.com/exemt/placitum-shared/loglevel"
)

const (
	LevelsBucket = "WAF_DESIRED"
	LevelsKey    = "policy/log-levels"
	LevelsKind   = "log-levels"

	// Пауза между попытками подписаться. Бакета нет, пока ни контроллер, ни
	// агент ноды не поднимались: ждать его дешевле, чем заводить самим.
	watchRetry = 5 * time.Second
)

// Levels -- документ policy/log-levels.
type Levels struct {
	V      int               `json:"v"`
	Kind   string            `json:"kind"`
	Rev    int               `json:"rev"`
	Levels map[string]string `json:"levels"`
}

// ParseLevels разбирает документ. Слова не проверяются здесь: чужое слово у
// соседнего сервиса -- не повод отвергать своё.
func ParseLevels(raw []byte) (*Levels, error) {
	var doc Levels

	if err := json.Unmarshal(raw, &doc); err != nil {
		return nil, err
	}

	if doc.V != 1 || doc.Kind != LevelsKind {
		return nil, fmt.Errorf("unexpected document v=%d kind=%q", doc.V, doc.Kind)
	}

	return &doc, nil
}

/*
 * resolve -- порог сервиса по документу и откуда он взялся. nil-документ --
 * ключа в KV нет или его сняли: стартовое значение.
 */
func resolve(doc *Levels, service string, base slog.Level) (slog.Level, string, error) {
	if doc == nil {
		return base, "env", nil
	}

	word, ok := doc.Levels[service]
	if !ok {
		return base, "env", nil
	}

	level, err := loglevel.Parse(word)
	if err != nil {
		return base, "env", err
	}

	return level, "controller", nil
}

/*
 * apply ставит порог по документу. Сначала порог, потом строка о нём -- как у
 * инспекторов: строка появляется ровно тогда, когда новый порог её пропускает,
 * и это же подтверждение, что он вступил в силу.
 */
func (j *Journal) apply(doc *Levels) {
	level, from, err := resolve(doc, j.service, j.base)
	if err != nil {
		j.Log.Warn("log level rejected", "service", j.service, "error", err.Error())
	}

	if j.level.Level() == level {
		return
	}

	rev := 0
	if doc != nil {
		rev = doc.Rev
	}

	// Ключ log_level, а не level: level -- уровень самой строки, и второй
	// такой ключ в том же JSON разобранный текст прочитал бы последним.
	j.level.Set(level)
	j.Log.Info("log level applied", "log_level", loglevel.String(level), "source", from, "rev", rev)
}

/*
 * watch держит подписку на документ, пока жив контекст. Сорвалась -- новая
 * попытка через паузу; первая неудача пишется строкой, повторы -- нет: иначе
 * контур без бакета писал бы по строке каждые пять секунд с каждого сервиса.
 */
func (j *Journal) watch(ctx context.Context, nc *nats.Conn) {
	said := false

	for {
		err := j.watchOnce(ctx, nc)
		if ctx.Err() != nil {
			return
		}

		if !said && err != nil {
			j.Log.Warn("log levels watch", "key", LevelsKey, "error", err.Error())
			said = true
		}

		select {
		case <-ctx.Done():
			return
		case <-time.After(watchRetry):
		}
	}
}

func (j *Journal) watchOnce(ctx context.Context, nc *nats.Conn) error {
	js, err := jetstream.New(nc)
	if err != nil {
		return err
	}

	kv, err := js.KeyValue(ctx, LevelsBucket)
	if err != nil {
		return err
	}

	watcher, err := kv.Watch(ctx, LevelsKey)
	if err != nil {
		return err
	}

	defer watcher.Stop()

	for {
		select {
		case <-ctx.Done():
			return nil
		case entry, ok := <-watcher.Updates():
			if !ok {
				return errors.New("watch closed")
			}

			// nil -- «начальные значения кончились»: ключа нет, и порог
			// остаётся стартовым.
			if entry == nil {
				continue
			}

			switch entry.Operation() {
			case jetstream.KeyValueDelete, jetstream.KeyValuePurge:
				j.apply(nil)
				continue
			}

			doc, err := ParseLevels(entry.Value())
			if err != nil {
				j.Log.Warn("log levels rejected", "key", LevelsKey, "error", err.Error())
				continue
			}

			j.apply(doc)
		}
	}
}

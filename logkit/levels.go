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

	watchRetry = 5 * time.Second
)

type Levels struct {
	V      int               `json:"v"`
	Kind   string            `json:"kind"`
	Rev    int               `json:"rev"`
	Levels map[string]string `json:"levels"`
}

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

	j.level.Set(level)
	j.Log.Info("log level applied", "log_level", loglevel.String(level), "source", from, "rev", rev)
}

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

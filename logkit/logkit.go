package logkit

import (
	"context"
	"log/slog"
	"os"
	"strings"
	"sync"

	"github.com/nats-io/nats.go"
)

type Options struct {
	Service string
	Writer  string
	Level   slog.Level
	IO      Counter
}

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

func (j *Journal) Level() slog.Level {
	return j.level.Level()
}

func (j *Journal) Service() string {
	return j.service
}

func (j *Journal) Sink() *Sink {
	return j.sink
}

func (j *Journal) Quiet() *slog.Logger {
	return j.quiet
}

func Ship() bool {
	switch strings.ToLower(strings.TrimSpace(os.Getenv("WAF_LOG_SHIP"))) {
	case "off", "0", "no", "false":
		return false
	default:
		return true
	}
}

func WriterName(fallback string) string {
	if v := strings.TrimSpace(os.Getenv("WAF_LOG_WRITER")); v != "" {
		return v
	}

	if name, err := os.Hostname(); err == nil && name != "" {
		return name
	}

	return fallback
}

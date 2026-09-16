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

	maxText = 8 << 10

	maxLines = 500
	maxSize  = 256 << 10

	flushEvery = 200 * time.Millisecond

	maxPending = 20000

	MaxAge      = 24 * time.Hour
	StreamBytes = 128 << 20
)

type Counter interface {
	AddN(n int, in, out uint64, isErr bool, latency time.Duration)
}

func Subject(writer string) string {
	if writer == "" {
		writer = "unknown"
	}

	return "waf.log." + token(writer)
}

type Line struct {
	TS       time.Time `json:"ts"`
	Service  string    `json:"service"`
	Severity string    `json:"severity,omitempty"`
	Text     string    `json:"text"`
}

type batch struct {
	V      int    `json:"v"`
	Kind   string `json:"kind"`
	Writer string `json:"writer"`
	Lines  []Line `json:"lines"`
}

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

func (s *Sink) Attach(nc *nats.Conn) {
	if s == nil || nc == nil {
		return
	}

	s.mu.Lock()
	s.nc = nc
	s.mu.Unlock()

	s.kick()
}

func (s *Sink) Tee(out io.Writer) io.Writer {
	if s == nil {
		return out
	}

	return io.MultiWriter(out, s)
}

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

func (s *Sink) Writer() string {
	if s == nil {
		return ""
	}

	return s.writer
}

func (s *Sink) Dropped() uint64 {
	if s == nil {
		return 0
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	return s.dropped
}

func (s *Sink) Failed() uint64 {
	if s == nil {
		return 0
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	return s.failed
}

func (s *Sink) Pending() int {
	if s == nil {
		return 0
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	return len(s.pending)
}

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

var levelKey = []byte(`"level":"`)

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

	if cut := strings.IndexAny(name, "+-"); cut > 0 {
		name = name[:cut]
	}

	return strings.ToLower(name)
}

func token(s string) string {
	return strings.NewReplacer(">", "_", "*", "_", " ", "_", "\t", "_").Replace(s)
}

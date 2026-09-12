package logkit

import (
	"bytes"
	"encoding/json"
	"io"
	"log/slog"
	"strings"
	"testing"
)

// Свой ключ -- порог из документа; ключа нет -- стартовый; слово чужое --
// стартовый и ошибка, а не молчаливый info.
func TestResolve(t *testing.T) {
	doc := &Levels{V: 1, Kind: LevelsKind, Rev: 2, Levels: map[string]string{
		"keeper": "debug",
		"geo":    "loud",
	}}

	if got, from, err := resolve(doc, "keeper", slog.LevelInfo); err != nil ||
		got != slog.LevelDebug || from != "controller" {
		t.Fatalf("свой ключ: %v %s %v", got, from, err)
	}

	if got, from, _ := resolve(doc, "logger", slog.LevelWarn); got != slog.LevelWarn || from != "env" {
		t.Fatalf("без ключа: %v %s", got, from)
	}

	if got, _, err := resolve(doc, "geo", slog.LevelInfo); err == nil || got != slog.LevelInfo {
		t.Fatalf("чужое слово: %v %v", got, err)
	}

	if got, from, _ := resolve(nil, "keeper", slog.LevelError); got != slog.LevelError || from != "env" {
		t.Fatalf("документа нет: %v %s", got, from)
	}
}

func TestParseLevelsRejectsForeignKind(t *testing.T) {
	if _, err := ParseLevels([]byte(`{"v":1,"kind":"agent-conf","levels":{}}`)); err == nil {
		t.Fatal("чужой документ принят")
	}

	doc, err := ParseLevels([]byte(`{"v":1,"kind":"log-levels","rev":7,"levels":{"geo":"warn"}}`))
	if err != nil || doc.Rev != 7 || doc.Levels["geo"] != "warn" {
		t.Fatalf("документ: %+v %v", doc, err)
	}
}

// Правка документа переставляет порог на ходу, снятие ключа возвращает
// стартовый -- без рестарта, ради чего документ и заведён.
func TestApplySwitchesAndRestores(t *testing.T) {
	t.Setenv("WAF_LOG_SHIP", "off")

	j := Open(Options{Service: "keeper", Level: slog.LevelInfo})
	j.Log = slog.New(slog.NewJSONHandler(io.Discard, nil))

	j.apply(&Levels{V: 1, Kind: LevelsKind, Levels: map[string]string{"keeper": "debug"}})

	if j.Level() != slog.LevelDebug {
		t.Fatalf("после документа: %v", j.Level())
	}

	j.apply(&Levels{V: 1, Kind: LevelsKind, Levels: map[string]string{}})

	if j.Level() != slog.LevelInfo {
		t.Fatalf("после снятия ключа: %v", j.Level())
	}

	j.apply(&Levels{V: 1, Kind: LevelsKind, Levels: map[string]string{"keeper": "crit"}})
	j.apply(nil)

	if j.Level() != slog.LevelInfo {
		t.Fatalf("после удаления документа: %v", j.Level())
	}
}

// Уровень едет в таблицу из той же строки, что и текст.
func TestSeverityFromSlogLine(t *testing.T) {
	cases := map[string]string{
		`{"time":"2026-08-24T10:00:00Z","level":"INFO","msg":"connected"}`: "info",
		`{"time":"2026-08-24T10:00:00Z","level":"WARN","msg":"bus down"}`:  "warn",
		`{"time":"2026-08-24T10:00:00Z","level":"ERROR","msg":"boom"}`:     "error",
		`{"time":"2026-08-24T10:00:00Z","level":"DEBUG","msg":"tick"}`:     "debug",
		`{"time":"2026-08-24T10:00:00Z","level":"INFO+2","msg":"loud"}`:    "info",
		`{"time":"2026-08-24T10:00:00Z","msg":"no level at all"}`:          "",
	}

	for line, want := range cases {
		if got := severity([]byte(line)); got != want {
			t.Fatalf("severity(%s) = %q, ждали %q", line, got, want)
		}
	}
}

func TestWriteTakesSlogLine(t *testing.T) {
	s := NewSink("edge-01", "agent", nil)
	defer s.Close()

	log := slog.New(slog.NewJSONHandler(s, &slog.HandlerOptions{Level: slog.LevelDebug}))
	log.Warn("agent conf apply failed", "error", "no such bucket")

	lines := s.take()
	if len(lines) != 1 {
		t.Fatalf("строк: %d", len(lines))
	}

	if lines[0].Severity != "warn" || lines[0].Service != "agent" {
		t.Fatalf("строка: %+v", lines[0])
	}

	if !strings.Contains(lines[0].Text, `"msg":"agent conf apply failed"`) ||
		strings.HasSuffix(lines[0].Text, "\n") {
		t.Fatalf("text: %q", lines[0].Text)
	}
}

// Строка чужого писателя сохраняет свой сервис и уровень: haproxy у своего
// агента -- это haproxy, а не haproxy-agent.
func TestAddKeepsForeignService(t *testing.T) {
	s := NewSink("lb-1", "haproxy-agent", nil)
	defer s.Close()

	s.Add(Line{Service: "haproxy", Severity: "info", Text: "GET / 200"})
	s.Add(Line{Text: "no header"})
	s.Add(Line{})

	lines := s.take()
	if len(lines) != 2 {
		t.Fatalf("строк: %d", len(lines))
	}

	if lines[0].Service != "haproxy" || lines[1].Service != "haproxy-agent" {
		t.Fatalf("сервисы: %q %q", lines[0].Service, lines[1].Service)
	}

	if lines[0].TS.IsZero() {
		t.Fatal("нет отметки времени")
	}
}

func TestBatchEnvelope(t *testing.T) {
	body, err := json.Marshal(batch{
		V:      Version,
		Kind:   Kind,
		Writer: "keeper-1",
		Lines:  []Line{{Service: "keeper", Severity: "info", Text: "hello"}},
	})
	if err != nil {
		t.Fatal(err)
	}

	var got struct {
		V      int    `json:"v"`
		Kind   string `json:"kind"`
		Writer string `json:"writer"`
		Lines  []struct {
			Service string `json:"service"`
			Text    string `json:"text"`
		} `json:"lines"`
	}

	if err := json.Unmarshal(body, &got); err != nil {
		t.Fatal(err)
	}

	if got.V != 1 || got.Kind != "log" || got.Writer != "keeper-1" ||
		len(got.Lines) != 1 || got.Lines[0].Service != "keeper" {
		t.Fatalf("конверт: %s", body)
	}
}

func TestOverflowDropsHead(t *testing.T) {
	s := NewSink("edge-01", "agent", nil)
	defer s.Close()

	for i := 0; i < maxPending+10; i++ {
		s.add(Line{Text: "line"})
	}

	if got := s.Dropped(); got != 10 {
		t.Fatalf("выброшено: %d", got)
	}
}

func TestFlushHoldsUntilAttach(t *testing.T) {
	s := NewSink("edge-01", "agent", nil)
	defer s.Close()

	s.add(Line{Text: "before the bus"})
	s.flush()

	s.mu.Lock()
	n := len(s.pending)
	s.mu.Unlock()

	if n != 1 {
		t.Fatalf("строка потеряна до Attach: осталось %d", n)
	}
}

// Выключенная доставка -- рабочее состояние: журнал остаётся в stdout, а
// Attach и Close ничего не ломают.
func TestShipOffKeepsStdout(t *testing.T) {
	t.Setenv("WAF_LOG_SHIP", "off")

	j := Open(Options{Service: "geo", Level: slog.LevelInfo})
	if j.Sink() != nil {
		t.Fatal("приёмник при WAF_LOG_SHIP=off")
	}

	var s *Sink

	out := &bytes.Buffer{}
	log := slog.New(slog.NewJSONHandler(s.Tee(out), nil))
	log.Info("still on stdout")

	s.Attach(nil)
	s.Add(Line{Text: "dropped quietly"})
	s.Close()
	j.Attach(t.Context(), nil)
	j.Close()

	if !strings.Contains(out.String(), "still on stdout") {
		t.Fatalf("вывод: %q", out.String())
	}
}

// Quiet пишет тем же порогом, но мимо приёмника: строки разбора WAF_LOG
// в сам WAF_LOG не едут.
func TestQuietBypassesSink(t *testing.T) {
	t.Setenv("WAF_LOG_SHIP", "on")

	j := Open(Options{Service: "logger", Writer: "logger-1", Level: slog.LevelInfo})
	defer j.Close()

	j.Quiet().Info("inserted logs", "lines", 1)
	j.Quiet().Debug("below the threshold")

	if n := len(j.Sink().take()); n != 0 {
		t.Fatalf("Quiet попал в приёмник: %d строк", n)
	}

	j.Log.Info("shipped")

	if n := len(j.Sink().take()); n != 1 {
		t.Fatalf("Log не попал в приёмник: %d строк", n)
	}
}

func TestSubject(t *testing.T) {
	if got := Subject("edge-01"); got != "waf.log.edge-01" {
		t.Fatalf("subject: %q", got)
	}

	if got := Subject("a b>c*"); got != "waf.log.a_b_c_" {
		t.Fatalf("subject: %q", got)
	}

	if got := Subject(""); got != "waf.log.unknown" {
		t.Fatalf("subject: %q", got)
	}
}

// take -- только для тестов: снять накопленное, не публикуя.
func (s *Sink) take() []Line {
	s.mu.Lock()
	defer s.mu.Unlock()

	out := s.pending
	s.pending = nil
	s.size = 0

	return out
}

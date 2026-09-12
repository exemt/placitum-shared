package loglevel

import (
	"context"
	"log/slog"
	"strings"
	"testing"
)

func TestParseKnowsNginxDictionary(t *testing.T) {
	want := map[string]slog.Level{
		"debug":  slog.LevelDebug,
		"info":   slog.LevelInfo,
		"notice": Notice,
		"warn":   slog.LevelWarn,
		"error":  slog.LevelError,
		"crit":   Crit,
		"alert":  Alert,
		// Старое значение переменной окружения: принимается как warn.
		"warning": slog.LevelWarn,
		" Error ": slog.LevelError,
	}

	for name, level := range want {
		got, err := Parse(name)
		if err != nil {
			t.Fatalf("%q: %v", name, err)
		}

		if got != level {
			t.Fatalf("%q: got %v, want %v", name, got, level)
		}
	}
}

func TestParseRejectsForeignWords(t *testing.T) {
	// emerg нарочно не в словаре: процессу нечего сказать на этом уровне.
	for _, name := range []string{"", "emerg", "trace", "INFO2"} {
		if _, err := Parse(name); err == nil {
			t.Fatalf("%q accepted", name)
		}
	}
}

func TestOrderIsQuietTowardsTheEnd(t *testing.T) {
	names := Names()

	if len(names) != 7 || names[0] != "debug" || names[6] != "alert" {
		t.Fatalf("unexpected dictionary: %v", names)
	}

	prev, _ := Parse(names[0])

	for _, name := range names[1:] {
		level, _ := Parse(name)

		if level <= prev {
			t.Fatalf("%s is not quieter than its predecessor", name)
		}

		prev = level
	}
}

func TestStringRoundTrips(t *testing.T) {
	for _, name := range Names() {
		level, _ := Parse(name)

		if String(level) != name {
			t.Fatalf("%s -> %v -> %s", name, level, String(level))
		}
	}
}

func TestEnvNamesVariable(t *testing.T) {
	t.Setenv("WAF_TEST_LOG", "loud")

	if _, err := Env("WAF_TEST_LOG", "info"); err == nil ||
		!strings.Contains(err.Error(), "WAF_TEST_LOG") {
		t.Fatalf("ошибка без имени переменной: %v", err)
	}

	t.Setenv("WAF_TEST_LOG", "")

	if got, err := Env("WAF_TEST_LOG", "warn"); err != nil || got != slog.LevelWarn {
		t.Fatalf("fallback: %v %v", got, err)
	}
}

func TestLevelVarSwitchesOnTheFly(t *testing.T) {
	// Ради этого всё и заведено: порог меняется без пересборки обработчика.
	var v slog.LevelVar

	v.Set(slog.LevelInfo)

	h := slog.NewTextHandler(discard{}, &slog.HandlerOptions{Level: &v})

	if !h.Enabled(context.Background(), slog.LevelInfo) {
		t.Fatal("info is silent at the start")
	}

	crit, _ := Parse("crit")
	v.Set(crit)

	if h.Enabled(context.Background(), slog.LevelError) {
		t.Fatal("error still passes after crit was set")
	}

	v.Set(slog.LevelDebug)

	if !h.Enabled(context.Background(), slog.LevelDebug) {
		t.Fatal("debug is silent after the threshold was lowered")
	}
}

type discard struct{}

func (discard) Write(p []byte) (int, error) { return len(p), nil }

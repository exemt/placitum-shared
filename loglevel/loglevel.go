package loglevel

import (
	"fmt"
	"log/slog"
	"os"
	"strings"
)

const (
	Notice slog.Level = slog.LevelInfo + 2
	Crit   slog.Level = slog.LevelError + 4
	Alert  slog.Level = slog.LevelError + 8
)

var table = [...]struct {
	name  string
	level slog.Level
}{
	{"debug", slog.LevelDebug},
	{"info", slog.LevelInfo},
	{"notice", Notice},
	{"warn", slog.LevelWarn},
	{"error", slog.LevelError},
	{"crit", Crit},
	{"alert", Alert},
}

func Names() []string {
	out := make([]string, 0, len(table))

	for _, row := range table {
		out = append(out, row.name)
	}

	return out
}

func Parse(s string) (slog.Level, error) {
	name := strings.ToLower(strings.TrimSpace(s))

	if name == "warning" {
		name = "warn"
	}

	for _, row := range table {
		if row.name == name {
			return row.level, nil
		}
	}

	return 0, fmt.Errorf("expected one of %s, got %q",
		strings.Join(Names(), ", "), s)
}

func String(level slog.Level) string {
	for _, row := range table {
		if row.level == level {
			return row.name
		}
	}

	return level.String()
}

func Env(name, fallback string) (slog.Level, error) {
	value := strings.TrimSpace(os.Getenv(name))
	if value == "" {
		value = fallback
	}

	level, err := Parse(value)
	if err != nil {
		return 0, fmt.Errorf("%s: %w", name, err)
	}

	return level, nil
}

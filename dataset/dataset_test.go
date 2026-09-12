package dataset

import (
	"testing"
	"time"
)

/*
 * Пачка едет без value -- и проверка кадра обязана её пропускать: прежняя
 * «value непустой» отвергала каждую пачку до keeper, и бан по анонсам и
 * составу системы молча не записывался, стоило префиксов оказаться больше
 * одного.
 */
func TestEventCheck(t *testing.T) {
	cases := []struct {
		name string
		ev   Event
		ok   bool
	}{
		{"one value", Event{Set: "ban", Value: "8.8.8.8"}, true},
		{"batch without value", Event{Set: "ban", Values: []string{"8.8.4.0/24", "8.8.8.0/24"}}, true},
		{"no set", Event{Values: []string{"8.8.8.0/24"}}, false},
		{"nothing to write", Event{Set: "ban"}, false},
	}

	for _, tc := range cases {
		if err := tc.ev.check(); (err == nil) != tc.ok {
			t.Fatalf("%s: check = %v, want ok %v", tc.name, err, tc.ok)
		}
	}
}

// Без шины писатель молчит, а не падает: инспектор без keeper работает,
// просто не записывает.
func TestNilPublisherIsNoop(t *testing.T) {
	var p *Publisher

	if err := p.Add("ban", "8.8.8.8", time.Minute, "test"); err != nil {
		t.Fatal(err)
	}

	if err := New(nil, "test").Remove("ban", "8.8.8.8", "test"); err != nil {
		t.Fatal(err)
	}
}

func TestAddRequiresTTL(t *testing.T) {
	if err := New(nil, "test").Add("ban", "8.8.8.8", 0, "test"); err == nil {
		t.Fatal("add без ttl принят")
	}
}

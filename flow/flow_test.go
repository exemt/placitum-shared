package flow

import (
	"testing"
	"time"
)

func TestOpsIsSumOverTenSeconds(t *testing.T) {
	var now int64 = 1_000
	c := &Counter{now: func() int64 { return now }}

	for i := 0; i < 20; i++ {
		c.Add(100, 200, false, 0)
	}

	got := c.Snapshot()
	if got.Ops != 2 {
		t.Fatalf("20 ops in one second: ops = %v, want 2", got.Ops)
	}
	if got.In != 200 || got.Out != 400 {
		t.Fatalf("bytes = %+v, want in=200 out=400", got)
	}

	now += 10
	got = c.Snapshot()
	if got.Ops != 0 {
		t.Fatalf("after 10s: ops = %v, want 0", got.Ops)
	}
}

func TestEmptyIsZero(t *testing.T) {
	c := New()
	got := c.Snapshot()
	if got != (Flow{}) {
		t.Fatalf("empty: %+v", got)
	}
}

func TestErrRate(t *testing.T) {
	var now int64 = 1_000
	c := &Counter{now: func() int64 { return now }}

	for i := 0; i < 9; i++ {
		c.Add(0, 0, false, 0)
	}
	c.Add(0, 0, true, 0)

	got := c.Snapshot()
	if got.Ops != 1 || got.Err != 0.1 {
		t.Fatalf("ops/err = %v/%v, want 1/0.1", got.Ops, got.Err)
	}
}

func TestLatencyPercentiles(t *testing.T) {
	var now int64 = 1_000
	c := &Counter{now: func() int64 { return now }}

	// 9 операций около 1мс, одна на 100мс: p50 в дешёвой корзине, max её видит.
	for i := 0; i < 9; i++ {
		c.Add(0, 0, false, time.Millisecond)
	}
	c.Add(0, 0, false, 100*time.Millisecond)

	got := c.Snapshot()
	if got.P50Ms <= 0 || got.P50Ms >= 4 {
		t.Fatalf("p50 = %v, want small bucket near 1ms", got.P50Ms)
	}
	if got.P95Ms < 64 {
		t.Fatalf("p95 = %v, want the 100ms outlier's bucket", got.P95Ms)
	}
	if got.MaxMs != 100 {
		t.Fatalf("max = %v, want exact 100", got.MaxMs)
	}
	if got.AvgMs != 10.9 {
		t.Fatalf("avg = %v, want 10.9", got.AvgMs)
	}
}

func TestAddNCountsRowsUnderOneLatency(t *testing.T) {
	var now int64 = 1_000
	c := &Counter{now: func() int64 { return now }}

	c.AddN(500, 0, 0, false, 50*time.Millisecond)

	got := c.Snapshot()
	if got.Ops != 50 {
		t.Fatalf("500 rows in one second: ops = %v, want 50", got.Ops)
	}
	if got.P50Ms < 32 || got.P50Ms > 64 {
		t.Fatalf("p50 = %v, want the 50ms batch's bucket", got.P50Ms)
	}
	if got.MaxMs != 50 {
		t.Fatalf("max = %v, want the exact 50ms batch latency", got.MaxMs)
	}
	if got.AvgMs != 50 {
		t.Fatalf("avg = %v, want the exact 50ms batch latency", got.AvgMs)
	}
}

func TestWindowSlidesGradually(t *testing.T) {
	var now int64 = 1_000
	c := &Counter{now: func() int64 { return now }}

	c.Add(0, 0, false, 0)
	now += 3
	c.Add(0, 0, false, 0)

	got := c.Snapshot()
	if got.Ops != 0.2 {
		t.Fatalf("two ops across 10s window: ops = %v, want 0.2", got.Ops)
	}

	now += 7
	got = c.Snapshot()
	if got.Ops != 0.1 {
		t.Fatalf("first op fell out of the window: ops = %v, want 0.1", got.Ops)
	}
}

func TestNilCounterIsNoop(t *testing.T) {
	var c *Counter
	c.Add(1, 2, true, time.Millisecond)
	c.AddN(3, 1, 1, false, time.Millisecond)
	if got := c.Snapshot(); got != (Flow{}) {
		t.Fatalf("nil snapshot: %+v", got)
	}
}

/*
 * Темп одного канала секции `io` кадра присутствия — docs/messages/fleet-pulse.md.
 *
 * То же кольцо секундных корзин, что у internal/rps, только на произвольный
 * канал и с задержкой операции. Гистограмма на 24 лог-корзины (мс, до
 * нескольких часов с запасом) даёт p50/p95 без хранения самих значений;
 * максимум — отдельным полем на корзину, потому что гистограмма смазывает
 * ровно ту одну застрявшую операцию, ради которой max и нужен.
 */

package flow

import (
	"math"
	"sync"
	"time"
)

const (
	Window  = 10
	buckets = 24
)

// Flow — темп канала за Window секунд. In/Out нулём, если канал байты не
// считает: omitempty стирает поле, а не выдаёт "0", неотличимое от того, что
// операции реально ничего не передали.
type Flow struct {
	Ops   float64 `json:"ops"`
	In    float64 `json:"in,omitempty"`
	Out   float64 `json:"out,omitempty"`
	Err   float64 `json:"err,omitempty"`
	P50Ms float64 `json:"p50_ms,omitempty"`
	P95Ms float64 `json:"p95_ms,omitempty"`
	MaxMs float64 `json:"max_ms,omitempty"`
	AvgMs float64 `json:"avg_ms,omitempty"`
}

type Counter struct {
	mu    sync.Mutex
	ops   [Window]uint64
	in    [Window]uint64
	out   [Window]uint64
	errs  [Window]uint64
	hist  [Window][buckets]uint64
	maxMs [Window]float64
	sumMs [Window]float64
	epoch int64
	now   func() int64
}

func New() *Counter {
	return &Counter{}
}

// Add — одна операция канала. Байты, которых у канала нет, передаются нулём.
func (c *Counter) Add(in, out uint64, isErr bool, latency time.Duration) {
	c.AddN(1, in, out, isErr, latency)
}

// AddN — n операций одной пачки, померенных одним общим временем: например,
// вставка n строк за один сетевой поход к ClickHouse. Темп (ops) от этого
// точен, задержка — это задержка пачки, приписанная каждой строке в ней, а
// не время самой строки, которую поштучно измерить не выйдет.
func (c *Counter) AddN(n int, in, out uint64, isErr bool, latency time.Duration) {
	if c == nil || n <= 0 {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	now := c.unix()
	c.advance(now)
	slot := now % Window
	c.ops[slot] += uint64(n)
	c.in[slot] += in
	c.out[slot] += out
	if isErr {
		c.errs[slot] += uint64(n)
	}
	ms := float64(latency) / float64(time.Millisecond)
	if ms < 0 {
		ms = 0
	}
	c.hist[slot][bucketOf(ms)] += uint64(n)
	c.sumMs[slot] += ms * float64(n)
	if ms > c.maxMs[slot] {
		c.maxMs[slot] = ms
	}
}

// Snapshot -- темп за окно. Nil-счётчик -- канал, которого у процесса нет:
// пустой темп, а не паника в кадре присутствия.
func (c *Counter) Snapshot() Flow {
	if c == nil {
		return Flow{}
	}

	c.mu.Lock()
	defer c.mu.Unlock()
	now := c.unix()
	c.advance(now)

	var ops, in, out, errs uint64
	var hist [buckets]uint64
	var maxMs, sumMs float64
	for i := 0; i < Window; i++ {
		ops += c.ops[i]
		in += c.in[i]
		out += c.out[i]
		errs += c.errs[i]
		sumMs += c.sumMs[i]
		if c.maxMs[i] > maxMs {
			maxMs = c.maxMs[i]
		}
		for b := 0; b < buckets; b++ {
			hist[b] += c.hist[i][b]
		}
	}

	f := Flow{
		Ops: round1(float64(ops) / Window),
		In:  round1(float64(in) / Window),
		Out: round1(float64(out) / Window),
		Err: round1(float64(errs) / Window),
	}
	if ops > 0 {
		f.P50Ms = percentile(hist, ops, 0.5)
		f.P95Ms = percentile(hist, ops, 0.95)
		f.MaxMs = round1(maxMs)
		f.AvgMs = round1(sumMs / float64(ops))
	}
	return f
}

func (c *Counter) unix() int64 {
	if c.now != nil {
		return c.now()
	}
	return time.Now().Unix()
}

func (c *Counter) advance(now int64) {
	if c.epoch == 0 {
		c.epoch = now
		return
	}
	if now <= c.epoch {
		return
	}
	dt := now - c.epoch
	if dt >= Window {
		for i := 0; i < Window; i++ {
			c.clear(i)
		}
	} else {
		for i := int64(1); i <= dt; i++ {
			c.clear(int((c.epoch + i) % Window))
		}
	}
	c.epoch = now
}

func (c *Counter) clear(i int) {
	c.ops[i] = 0
	c.in[i] = 0
	c.out[i] = 0
	c.errs[i] = 0
	c.maxMs[i] = 0
	c.sumMs[i] = 0
	for b := 0; b < buckets; b++ {
		c.hist[i][b] = 0
	}
}

// bucketOf — лог2-корзина: 0 -> [0,1) мс, b>=1 -> [2^(b-1), 2^b) мс.
func bucketOf(ms float64) int {
	if ms < 1 {
		return 0
	}
	b := int(math.Log2(ms)) + 1
	if b >= buckets {
		return buckets - 1
	}
	return b
}

func bucketMid(b int) float64 {
	if b == 0 {
		return 0.5
	}
	lo := math.Exp2(float64(b - 1))
	hi := math.Exp2(float64(b))
	return (lo + hi) / 2
}

func percentile(hist [buckets]uint64, total uint64, frac float64) float64 {
	if total == 0 {
		return 0
	}
	target := uint64(math.Ceil(frac * float64(total)))
	if target < 1 {
		target = 1
	}
	var acc uint64
	for b := 0; b < buckets; b++ {
		acc += hist[b]
		if acc >= target {
			return round1(bucketMid(b))
		}
	}
	return round1(bucketMid(buckets - 1))
}

func round1(v float64) float64 {
	return math.Round(v*10) / 10
}

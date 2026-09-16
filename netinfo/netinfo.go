package netinfo

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/netip"
	"sort"
	"sync"
	"sync/atomic"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"

	geopb "github.com/exemt/placitum-shared/geopb"
)

const (
	negTTL         = 10 * time.Minute
	negMaxDefault  = 1000000
	negKeep        = 0.9
	recvMax        = 256 << 20
	warnEvery      = time.Second
	defaultTimeout = 500 * time.Millisecond
)

var ErrUnavailable = errors.New("geo unavailable")

type Announce struct {
	Prefix    netip.Prefix
	ASN       uint32
	Name      string
	Effective bool
	Prefixes  []netip.Prefix
}

type Info struct {
	Gen       uint64
	Lo, Hi    netip.Addr
	Announces []Announce
}

type span struct {
	lo, hi netip.Addr
	info   Info
}

type table struct {
	v4 []span
	v6 []span
}

type composition struct {
	gen      uint64
	prefixes []netip.Prefix
}

type Resolver struct {
	conn    *grpc.ClientConn
	client  geopb.GeoClient
	timeout time.Duration
	log     *slog.Logger

	spans atomic.Pointer[table]
	gen   atomic.Uint64

	mu       sync.Mutex
	neg      map[netip.Addr]time.Time
	negMax   int
	comps    map[uint32]composition
	inflight map[string]chan struct{}

	lastWarn atomic.Int64
}

func New(target string, timeout time.Duration, negMax int, log *slog.Logger) (*Resolver, error) {
	if target == "" {
		return nil, nil
	}

	if timeout <= 0 {
		timeout = defaultTimeout
	}

	if negMax <= 0 {
		negMax = negMaxDefault
	}

	conn, err := grpc.NewClient(target,
		grpc.WithTransportCredentials(insecure.NewCredentials()),
		grpc.WithDefaultCallOptions(grpc.MaxCallRecvMsgSize(recvMax)),
		grpc.WithDisableServiceConfig(),
		grpc.WithIdleTimeout(0),
	)
	if err != nil {
		return nil, fmt.Errorf("geo client %q: %w", target, err)
	}

	conn.Connect()

	r := &Resolver{
		conn:     conn,
		client:   geopb.NewGeoClient(conn),
		timeout:  timeout,
		log:      log,
		neg:      map[netip.Addr]time.Time{},
		negMax:   negMax,
		comps:    map[uint32]composition{},
		inflight: map[string]chan struct{}{},
	}

	r.spans.Store(&table{})

	return r, nil
}

func (r *Resolver) Close() {
	if r != nil && r.conn != nil {
		_ = r.conn.Close()
	}
}

func (r *Resolver) Gen() uint64 {
	if r == nil {
		return 0
	}

	return r.gen.Load()
}

func (r *Resolver) Resolve(ctx context.Context, raw string) (network, router string) {
	if r == nil {
		return "", ""
	}

	addr, err := netip.ParseAddr(raw)
	if err != nil {
		return "", ""
	}

	info, err := r.Lookup(ctx, addr, false)
	if err != nil {
		r.warn("geo lookup failed", "addr", raw, "error", err.Error())

		return "", ""
	}

	for _, a := range info.Announces {
		if a.Effective {
			return a.Prefix.String(), fmt.Sprintf("%d", a.ASN)
		}
	}

	return "", ""
}

func (r *Resolver) Lookup(ctx context.Context, addr netip.Addr, expand bool) (Info, error) {
	if r == nil {
		return Info{}, ErrUnavailable
	}

	addr = addr.Unmap()
	if !addr.Is4() && !addr.Is6() {
		return Info{}, fmt.Errorf("%w: not an ip", ErrUnavailable)
	}

	for {
		if info, ok := r.cached(addr, expand); ok {
			return info, nil
		}

		if r.negative(addr) {
			return Info{Gen: r.gen.Load()}, nil
		}

		key := addr.String()
		if expand {
			key += "+asn"
		}

		wait, leader := r.claim(key)
		if !leader {
			select {
			case <-wait:
				continue
			case <-ctx.Done():
				return Info{}, fmt.Errorf("%w: %v", ErrUnavailable, ctx.Err())
			}
		}

		info, err := r.fetch(ctx, addr, expand)
		r.release(key)

		return info, err
	}
}

const (
	WriteNet    = "net"
	WriteNetAll = "net_all"
	WriteASN    = "asn"
)

func Networked(write string) bool {
	return write == WriteNet || write == WriteNetAll || write == WriteASN
}

func Values(info Info, write string) []string {
	seen := map[string]struct{}{}
	out := make([]string, 0, len(info.Announces))

	add := func(p netip.Prefix) {
		s := p.String()

		if _, dup := seen[s]; dup {
			return
		}

		seen[s] = struct{}{}
		out = append(out, s)
	}

	for _, a := range info.Announces {
		switch write {
		case WriteNetAll:
			add(a.Prefix)

		case WriteNet:
			if a.Effective {
				add(a.Prefix)
			}

		case WriteASN:
			if a.Effective {
				for _, p := range a.Prefixes {
					add(p)
				}
			}
		}
	}

	return out
}

func (r *Resolver) Write(ctx context.Context, write, raw string) ([]string, error) {
	addr, err := netip.ParseAddr(raw)
	if err != nil {
		return nil, nil
	}

	info, err := r.Lookup(ctx, addr, write == WriteASN)
	if err != nil {
		return nil, fmt.Errorf("write %s for %s: %w", write, raw, err)
	}

	return Values(info, write), nil
}

func (r *Resolver) cached(addr netip.Addr, expand bool) (Info, bool) {
	sp, ok := lookup(r.family(r.spans.Load(), addr), addr)
	if !ok {
		return Info{}, false
	}

	info := sp.info

	if !expand {
		return info, true
	}

	gen := r.gen.Load()

	r.mu.Lock()
	defer r.mu.Unlock()

	out := make([]Announce, len(info.Announces))

	for i, a := range info.Announces {
		c, ok := r.comps[a.ASN]
		if !ok || c.gen != gen {
			return Info{}, false
		}

		out[i] = a
		out[i].Prefixes = c.prefixes
	}

	info.Announces = out

	return info, true
}

func (r *Resolver) negative(addr netip.Addr) bool {
	r.mu.Lock()
	defer r.mu.Unlock()

	until, ok := r.neg[addr]

	return ok && time.Now().Before(until)
}

func (r *Resolver) family(t *table, addr netip.Addr) []span {
	if addr.Is4() {
		return t.v4
	}

	return t.v6
}

func lookup(s []span, addr netip.Addr) (span, bool) {
	i := sort.Search(len(s), func(i int) bool {
		return s[i].lo.Compare(addr) > 0
	})

	if i == 0 {
		return span{}, false
	}

	if sp := s[i-1]; addr.Compare(sp.hi) <= 0 {
		return sp, true
	}

	return span{}, false
}

func (r *Resolver) insert(sp span) {
	r.mu.Lock()
	defer r.mu.Unlock()

	old := r.spans.Load()
	next := &table{v4: old.v4, v6: old.v6}
	target := &next.v4

	if !sp.lo.Is4() {
		target = &next.v6
	}

	s := *target

	i := sort.Search(len(s), func(i int) bool {
		return s[i].lo.Compare(sp.lo) >= 0
	})

	if i < len(s) && s[i].lo.Compare(sp.hi) <= 0 {
		return
	}

	if i > 0 && sp.lo.Compare(s[i-1].hi) <= 0 {
		return
	}

	grown := make([]span, 0, len(s)+1)
	grown = append(grown, s[:i]...)
	grown = append(grown, sp)
	grown = append(grown, s[i:]...)
	*target = grown

	r.spans.Store(next)
}

func (r *Resolver) reset(gen uint64) {
	r.mu.Lock()
	defer r.mu.Unlock()

	if r.gen.Load() == gen {
		return
	}

	r.spans.Store(&table{})
	r.neg = map[netip.Addr]time.Time{}
	r.comps = map[uint32]composition{}
	r.gen.Store(gen)
}

func (r *Resolver) claim(key string) (chan struct{}, bool) {
	r.mu.Lock()
	defer r.mu.Unlock()

	if ch, busy := r.inflight[key]; busy {
		return ch, false
	}

	ch := make(chan struct{})
	r.inflight[key] = ch

	return ch, true
}

func (r *Resolver) release(key string) {
	r.mu.Lock()
	ch := r.inflight[key]
	delete(r.inflight, key)
	r.mu.Unlock()

	if ch != nil {
		close(ch)
	}
}

func (r *Resolver) fetch(ctx context.Context, addr netip.Addr, expand bool) (Info, error) {
	ctx, cancel := context.WithTimeout(ctx, r.timeout)
	defer cancel()

	reply, err := r.client.Lookup(ctx, &geopb.LookupRequest{Addr: addr.String(), ExpandAsn: expand})
	if err != nil {
		return Info{}, fmt.Errorf("%w: %v", ErrUnavailable, err)
	}

	if reply.GetGen() != r.gen.Load() {
		r.reset(reply.GetGen())
	}

	info := Info{Gen: reply.GetGen()}

	for _, row := range reply.GetAsns() {
		p, err := netip.ParsePrefix(row.GetPrefix())
		if err != nil {
			return Info{}, fmt.Errorf("%w: bad prefix %q", ErrUnavailable, row.GetPrefix())
		}

		a := Announce{Prefix: p, ASN: row.GetAsn(), Name: row.GetName(), Effective: row.GetEffective()}

		if a.Effective {
			lo, err1 := netip.ParseAddr(row.GetRange().GetStart())
			hi, err2 := netip.ParseAddr(row.GetRange().GetEnd())

			if err1 != nil || err2 != nil {
				return Info{}, fmt.Errorf("%w: bad range for %q", ErrUnavailable, row.GetPrefix())
			}

			info.Lo, info.Hi = lo.Unmap(), hi.Unmap()
		}

		if expand {
			a.Prefixes = make([]netip.Prefix, 0, len(row.GetPrefixes()))

			for _, s := range row.GetPrefixes() {
				if p, err := netip.ParsePrefix(s); err == nil {
					a.Prefixes = append(a.Prefixes, p)
				}
			}
		}

		info.Announces = append(info.Announces, a)
	}

	if len(info.Announces) == 0 || !info.Lo.IsValid() {
		r.remember(addr)

		return Info{Gen: info.Gen}, nil
	}

	light := info
	light.Announces = make([]Announce, len(info.Announces))

	for i, a := range info.Announces {
		light.Announces[i] = a
		light.Announces[i].Prefixes = nil
	}

	r.insert(span{lo: info.Lo, hi: info.Hi, info: light})

	if expand {
		r.mu.Lock()

		for _, a := range info.Announces {
			r.comps[a.ASN] = composition{gen: info.Gen, prefixes: a.Prefixes}
		}

		r.mu.Unlock()
	}

	return info, nil
}

func (r *Resolver) remember(addr netip.Addr) {
	now := time.Now()

	r.mu.Lock()
	defer r.mu.Unlock()

	if len(r.neg) >= r.negMax {
		r.evictNegLocked(now)
	}

	r.neg[addr] = now.Add(negTTL)
}

func (r *Resolver) evictNegLocked(now time.Time) {
	for addr, until := range r.neg {
		if !now.Before(until) {
			delete(r.neg, addr)
		}
	}

	keep := int(float64(r.negMax) * negKeep)

	for addr := range r.neg {
		if len(r.neg) <= keep {
			return
		}

		delete(r.neg, addr)
	}
}

func (r *Resolver) warn(msg string, args ...any) {
	now := time.Now().UnixNano()
	last := r.lastWarn.Load()

	if now-last < int64(warnEvery) || !r.lastWarn.CompareAndSwap(last, now) {
		return
	}

	r.log.Warn(msg, args...)
}

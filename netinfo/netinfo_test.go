package netinfo

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/netip"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/status"
	"google.golang.org/grpc/test/bufconn"

	geopb "github.com/exemt/placitum-shared/geopb"
)

/*
 * Кодер-заглушка с перекрытием: 104.16.0.0/13 у 13335, а внутри него
 * 104.16.7.0/24 у 64496. Эффективные куски -- как их сплющил бы настоящий
 * кодер. gen переключается тестом.
 */
type coder struct {
	geopb.UnimplementedGeoServer
	hits atomic.Int64
	gen  atomic.Uint64
	down atomic.Bool
}

func (c *coder) Lookup(_ context.Context, req *geopb.LookupRequest) (*geopb.LookupResponse, error) {
	c.hits.Add(1)

	if c.down.Load() {
		return nil, status.Error(codes.Unavailable, "down")
	}

	addr := netip.MustParseAddr(req.GetAddr())
	out := &geopb.LookupResponse{Gen: c.gen.Load()}

	wide := &geopb.ASN{Asn: 13335, Name: "CLOUDFLARE", Prefix: "104.16.0.0/13"}
	narrow := &geopb.ASN{Asn: 64496, Name: "TENANT", Prefix: "104.16.7.0/24"}

	if req.GetExpandAsn() {
		wide.Prefixes = []string{"104.16.0.0/13", "104.24.0.0/14"}
		narrow.Prefixes = []string{"104.16.7.0/24"}
	}

	switch {
	case netip.MustParsePrefix("104.16.7.0/24").Contains(addr):
		narrow.Effective = true
		narrow.Range = &geopb.Range{Start: "104.16.7.0", End: "104.16.7.255"}
		out.Asns = []*geopb.ASN{narrow, wide}

	case netip.MustParsePrefix("104.16.0.0/13").Contains(addr):
		wide.Effective = true
		// Кусок /13 после вычета /24 -- ниже него: от начала до 104.16.6.255.
		wide.Range = &geopb.Range{Start: "104.16.0.0", End: "104.16.6.255"}

		if addr.Compare(netip.MustParseAddr("104.16.7.255")) > 0 {
			wide.Range = &geopb.Range{Start: "104.16.8.0", End: "104.23.255.255"}
		}

		out.Asns = []*geopb.ASN{wide}
	}

	return out, nil
}

func start(t *testing.T) (*Resolver, *coder) {
	t.Helper()

	c := &coder{}
	c.gen.Store(1)

	lis := bufconn.Listen(1 << 20)
	gs := grpc.NewServer()
	geopb.RegisterGeoServer(gs, c)

	go func() { _ = gs.Serve(lis) }()

	conn, err := grpc.NewClient("passthrough:///bufnet",
		grpc.WithTransportCredentials(insecure.NewCredentials()),
		grpc.WithContextDialer(func(context.Context, string) (net.Conn, error) { return lis.Dial() }),
	)
	if err != nil {
		t.Fatal(err)
	}

	r := &Resolver{
		conn: conn, client: geopb.NewGeoClient(conn), timeout: time.Second,
		log: slog.New(slog.NewTextHandler(io.Discard, nil)),
		neg: map[netip.Addr]time.Time{}, negMax: negMaxDefault,
		comps:    map[uint32]composition{},
		inflight: map[string]chan struct{}{},
	}
	r.spans.Store(&table{})

	t.Cleanup(func() {
		r.Close()
		gs.Stop()
		_ = lis.Close()
	})

	return r, c
}

func ctx(t *testing.T) context.Context {
	t.Helper()

	c, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	t.Cleanup(cancel)

	return c
}

/*
 * Промах ждёт кодер и отвечает сразу; второй адрес того же куска -- из кэша,
 * без похода. Ключ корзины -- эффективный анонс, не самый широкий.
 */
func TestResolveWaitsAndCachesByRange(t *testing.T) {
	r, c := start(t)

	network, router := r.Resolve(ctx(t), "104.16.7.7")
	if network != "104.16.7.0/24" || router != "64496" {
		t.Fatalf("first resolve: %q %q", network, router)
	}

	if c.hits.Load() != 1 {
		t.Fatalf("hits %d, want 1", c.hits.Load())
	}

	if network, _ := r.Resolve(ctx(t), "104.16.7.200"); network != "104.16.7.0/24" {
		t.Fatalf("same range must hit the cache: %q", network)
	}

	if c.hits.Load() != 1 {
		t.Fatalf("second address of the range hit the coder")
	}

	// Адрес широкого анонса вне узкого -- свой кусок, свой поход, свой анонс.
	if network, router := r.Resolve(ctx(t), "104.16.1.1"); network != "104.16.0.0/13" || router != "13335" {
		t.Fatalf("wide range: %q %q", network, router)
	}

	if c.hits.Load() != 2 {
		t.Fatalf("hits %d, want 2", c.hits.Load())
	}
}

/* Перекрытие: узкий адрес никогда не получает широкий анонс из кэша. */
func TestLookupOverlapIsSafe(t *testing.T) {
	r, _ := start(t)

	if _, err := r.Lookup(ctx(t), netip.MustParseAddr("104.16.1.1"), false); err != nil {
		t.Fatal(err)
	}

	info, err := r.Lookup(ctx(t), netip.MustParseAddr("104.16.7.7"), false)
	if err != nil {
		t.Fatal(err)
	}

	if len(info.Announces) != 2 || !info.Announces[0].Effective || info.Announces[0].ASN != 64496 {
		t.Fatalf("narrow first, effective: %+v", info.Announces)
	}

	if info.Announces[1].ASN != 13335 || info.Announces[1].Effective {
		t.Fatalf("wide second, not effective: %+v", info.Announces)
	}

	if info.Lo.String() != "104.16.7.0" || info.Hi.String() != "104.16.7.255" {
		t.Fatalf("range: %s-%s", info.Lo, info.Hi)
	}
}

/* Состав: спрашивается один раз на систему, дальше из кэша до смены gen. */
func TestLookupExpandCachesComposition(t *testing.T) {
	r, c := start(t)

	info, err := r.Lookup(ctx(t), netip.MustParseAddr("104.16.7.7"), true)
	if err != nil {
		t.Fatal(err)
	}

	if len(info.Announces[0].Prefixes) != 1 || len(info.Announces[1].Prefixes) != 2 {
		t.Fatalf("compositions: %+v", info.Announces)
	}

	// Второй адрес того же куска с составом -- всё из кэша.
	if _, err := r.Lookup(ctx(t), netip.MustParseAddr("104.16.7.9"), true); err != nil {
		t.Fatal(err)
	}

	if c.hits.Load() != 1 {
		t.Fatalf("composition must come from the cache, hits %d", c.hits.Load())
	}

	// Без состава спросили раньше -- состав дозапрашивается один раз.
	if _, err := r.Lookup(ctx(t), netip.MustParseAddr("104.16.1.1"), false); err != nil {
		t.Fatal(err)
	}

	if _, err := r.Lookup(ctx(t), netip.MustParseAddr("104.16.1.1"), true); err != nil {
		t.Fatal(err)
	}

	if c.hits.Load() != 2 {
		t.Fatalf("hits %d: 13335 was already expanded, the wide range must not refetch", c.hits.Load())
	}
}

/* Новое поколение кодера сбрасывает всё: диапазоны, составы, отрицательный. */
func TestGenResetsCache(t *testing.T) {
	r, c := start(t)

	if _, err := r.Lookup(ctx(t), netip.MustParseAddr("104.16.7.7"), true); err != nil {
		t.Fatal(err)
	}

	if _, err := r.Lookup(ctx(t), netip.MustParseAddr("192.0.2.1"), false); err != nil {
		t.Fatal(err)
	}

	if r.Gen() != 1 || c.hits.Load() != 2 {
		t.Fatalf("gen %d hits %d", r.Gen(), c.hits.Load())
	}

	c.gen.Store(2)

	// Любой промах приносит новое поколение и опустошает кэш.
	if _, err := r.Lookup(ctx(t), netip.MustParseAddr("104.16.1.1"), false); err != nil {
		t.Fatal(err)
	}

	if r.Gen() != 2 {
		t.Fatalf("gen %d, want 2", r.Gen())
	}

	before := c.hits.Load()

	if _, err := r.Lookup(ctx(t), netip.MustParseAddr("104.16.7.7"), true); err != nil {
		t.Fatal(err)
	}

	if c.hits.Load() != before+1 {
		t.Fatalf("stale composition served after gen change")
	}

	if _, err := r.Lookup(ctx(t), netip.MustParseAddr("192.0.2.1"), false); err != nil {
		t.Fatal(err)
	}

	if c.hits.Load() != before+2 {
		t.Fatalf("stale negative served after gen change")
	}
}

/* Адрес без системы -- пустой ответ, не ошибка, и кодер о нём не спрашивают дважды. */
func TestNegativeCache(t *testing.T) {
	r, c := start(t)

	info, err := r.Lookup(ctx(t), netip.MustParseAddr("192.0.2.1"), false)
	if err != nil || len(info.Announces) != 0 {
		t.Fatalf("unknown addr: %+v %v", info, err)
	}

	for i := 0; i < 5; i++ {
		r.Resolve(ctx(t), "192.0.2.1")
	}

	if c.hits.Load() != 1 {
		t.Fatalf("negative cache leaked: hits %d", c.hits.Load())
	}
}

/*
 * Потолок отрицательного кэша: он вытесняется, а не обнуляется. Протухшее
 * уходит первым -- и пока его хватает, свежие записи остаются на месте.
 */
func TestNegativeEviction(t *testing.T) {
	r, _ := start(t)
	r.negMax = 100

	stale := netip.MustParseAddr("192.0.2.200")
	fresh := netip.MustParseAddr("192.0.2.201")

	r.mu.Lock()
	for i := range 98 {
		/* Протухшие: срок в прошлом. */
		r.neg[netip.AddrFrom4([4]byte{198, 51, 100, byte(i)})] = time.Now().Add(-time.Minute)
	}
	r.neg[stale] = time.Now().Add(-time.Minute)
	r.neg[fresh] = time.Now().Add(negTTL)
	r.mu.Unlock()

	r.remember(netip.MustParseAddr("192.0.2.202"))

	r.mu.Lock()
	n := len(r.neg)
	_, keptFresh := r.neg[fresh]
	_, keptStale := r.neg[stale]
	r.mu.Unlock()

	if n == 0 {
		t.Fatal("кэш обнулён целиком, а должен вытесняться")
	}

	if n > 91 {
		t.Fatalf("не вытеснили до девяти десятых потолка: осталось %d", n)
	}

	if !keptFresh {
		t.Fatal("свежая запись снята, хотя протухших хватало")
	}

	if keptStale {
		t.Fatal("протухшая запись осталась")
	}
}

/*
 * Скан уникальными адресами: протухшего нет вовсе, и вытеснять приходится
 * живое -- но кэш всё равно не обнуляется, а держится у потолка.
 */
func TestNegativeEvictionAllFresh(t *testing.T) {
	r, _ := start(t)
	r.negMax = 100

	for i := range 250 {
		r.remember(netip.AddrFrom4([4]byte{203, 0, byte(i / 256), byte(i % 256)}))
	}

	r.mu.Lock()
	n := len(r.neg)
	r.mu.Unlock()

	if n < 80 || n > 100 {
		t.Fatalf("кэш держится не у потолка: %d", n)
	}
}

/* Молчащий кодер: Lookup -- ошибка, Resolve -- пустые ключи, ничего не кэшируется. */
func TestUnavailable(t *testing.T) {
	r, c := start(t)
	c.down.Store(true)

	if _, err := r.Lookup(ctx(t), netip.MustParseAddr("104.16.7.7"), false); err == nil {
		t.Fatal("down coder must fail the lookup")
	}

	if network, router := r.Resolve(ctx(t), "104.16.7.7"); network != "" || router != "" {
		t.Fatalf("down coder must give empty keys: %q %q", network, router)
	}

	c.down.Store(false)

	if network, _ := r.Resolve(ctx(t), "104.16.7.7"); network != "104.16.7.0/24" {
		t.Fatalf("after recovery: %q", network)
	}
}

func TestNilResolver(t *testing.T) {
	var r *Resolver

	if network, router := r.Resolve(context.Background(), "1.2.3.4"); network != "" || router != "" {
		t.Fatal("nil resolver resolved something")
	}

	if _, err := r.Lookup(context.Background(), netip.MustParseAddr("1.2.3.4"), true); err == nil {
		t.Fatal("nil resolver must report unavailable")
	}

	if r.Gen() != 0 {
		t.Fatal("nil gen")
	}

	r.Close()
}

func TestNewEmptyTarget(t *testing.T) {
	r, err := New("", time.Second, 0, slog.Default())
	if err != nil || r != nil {
		t.Fatalf("empty target: %v %v", r, err)
	}
}

/*
 * Три охвата записи на одном адресе: лайт -- свой узкий анонс, хард -- все
 * накрывающие от узкого к широкому, система -- состав эффективного анонса, а
 * не того, кто анонсирует шире.
 */
func TestWriteScopes(t *testing.T) {
	r, _ := start(t)

	cases := []struct {
		write, addr string
		want        []string
	}{
		{WriteNet, "104.16.7.7", []string{"104.16.7.0/24"}},
		{WriteNetAll, "104.16.7.7", []string{"104.16.7.0/24", "104.16.0.0/13"}},
		{WriteASN, "104.16.7.7", []string{"104.16.7.0/24"}},
		{WriteNet, "104.16.1.1", []string{"104.16.0.0/13"}},
		{WriteASN, "104.16.1.1", []string{"104.16.0.0/13", "104.24.0.0/14"}},
	}

	for _, tc := range cases {
		got, err := r.Write(ctx(t), tc.write, tc.addr)
		if err != nil {
			t.Fatal(err)
		}

		if strings.Join(got, " ") != strings.Join(tc.want, " ") {
			t.Fatalf("write %s for %s: %v, want %v", tc.write, tc.addr, got, tc.want)
		}
	}
}

/* Адрес без системы -- пустая пачка без ошибки; молчащий или несуществующий кодер -- ошибка. */
func TestWriteUnknownAndUnavailable(t *testing.T) {
	r, c := start(t)

	if got, err := r.Write(ctx(t), WriteNetAll, "192.0.2.1"); err != nil || len(got) != 0 {
		t.Fatalf("unknown addr: %v %v", got, err)
	}

	c.down.Store(true)

	if _, err := r.Write(ctx(t), WriteNet, "104.16.7.7"); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("down coder: %v", err)
	}

	var none *Resolver

	if _, err := none.Write(context.Background(), WriteASN, "104.16.7.7"); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("nil resolver: %v", err)
	}

	if Networked("addr") || Networked("cid") || !Networked(WriteNetAll) {
		t.Fatal("only net, net_all and asn need the coder")
	}
}

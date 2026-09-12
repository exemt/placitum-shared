/*
 * Адрес -> накрывающие анонсы, эффективный кусок под адресом, состав системы.
 *
 * Источник один -- кодер гео внутри контура, по gRPC (`geo.v1.Geo/Lookup`).
 * Резолв синхронный: промах -- один поход в кодер в таймаут, и ответ ждут
 * здесь же, потому что модуль всё равно ждёт инспектора до дедлайна маршрута,
 * а «пусто на первом запросе» -- это молча несостоявшийся бан. Стоит промах
 * один локальный RTT, один раз на диапазон.
 *
 * Кэш -- два уровня, оба без лимитов и без сроков: данные кодера меняются
 * поколениями, и единственная причина забыть -- новое поколение (`gen` в
 * каждом ответе). Диапазоны: неизменяемый отсортированный массив
 * непересекающихся эффективных кусков, двоичный поиск, подмена указателя на
 * вставке -- чтения без блокировок. Составы систем: карта по номеру.
 *
 * Перекрытия анонсов кэшу не страшны по построению: он хранит не анонсы, а
 * эффективные куски, которые кодер уже сплющил -- узкий /24 внутри /9 другой
 * системы никогда не отдаст /9 адресу из /24.
 *
 * Спека -- docs/inspectors/captcha/buckets.md.
 */

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
	// negTTL -- срок отрицательного кэша: адрес без анонса не спрашивается
	// чаще. Это единственное, что здесь протухает по времени: отрицательный
	// ответ -- не данные, а их отсутствие, и держать его вечно незачем.
	negTTL = 10 * time.Minute
	// negMaxDefault -- потолок отрицательного кэша, когда его не задали:
	// скан уникальными адресами не должен превращаться в рост памяти. Запись
	// стоит около сотни байт, так что умолчание -- это десятки мегабайт.
	negMaxDefault = 1000000
	// negKeep -- сколько записей остаётся после вытеснения, в долях потолка.
	// Не ноль: сброс целиком означал бы, что после потолка кодера снова
	// спрашивают обо всех адресах разом -- ровно в тот момент, когда их и так
	// слишком много.
	negKeep = 0.9
	// recvMax -- потолок входящего сообщения gRPC. Умолчание -- 4 МБ, и
	// состав крупной системы в него не влезет так же молча, как прежде не
	// влезал в LimitReader. Читаем целиком, держим целиком.
	recvMax = 256 << 20
	// warnEvery -- как часто жаловаться на молчащий кодер с горячего пути.
	warnEvery = time.Second
	// defaultTimeout -- сколько ждать кодер, когда срок не задан. Сам ответ
	// стоит доли миллисекунды (p50 0,22 мс, p99 0,5 мс на стенде, состав
	// системы -- столько же); весь бюджет здесь -- на дурную минуту сети, а
	// не на работу кодера. Полсекунды -- чтобы промах не превращался в
	// несостоявшийся бан.
	defaultTimeout = 500 * time.Millisecond
)

// ErrUnavailable -- кодер не ответил в срок, недоступен или отдал негодное.
var ErrUnavailable = errors.New("geo unavailable")

// Announce -- анонс, накрывающий адрес. Prefixes -- состав его системы,
// только когда спрашивали (Lookup с expand).
type Announce struct {
	Prefix    netip.Prefix
	ASN       uint32
	Name      string
	Effective bool
	Prefixes  []netip.Prefix
}

/*
 * Info -- что кодер знает об адресе: все накрывающие анонсы, эффективный
 * первым, и кусок [Lo, Hi] под адресом. Пустые Announces -- адрес без системы.
 */
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

// New поднимает клиент. target пустой -- резолвера нет (New возвращает nil,
// методы nil-safe): корзины по системам молчат, а правила с write: net|asn
// отвечают error. Соединение заводится сразу и держится вечно, но старт не
// блокирует: недоступный кодер виден на первом промахе, как и раньше.
// negMax -- потолок отрицательного кэша, 0 -- взять умолчание.
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

	/*
	 * Канал один на процесс, и заводится он заранее: ждать соединение в
	 * бюджете сообщения нечестно -- бюджет отмерян на ответ кодера, а не на
	 * знакомство с ним. Два умолчания grpc-go при этом сняты намеренно:
	 *
	 *   - сервис-конфиг: перед первым вызовом клиент спрашивает у DNS запись
	 *     TXT `_grpc_config.<host>`. В контуре её нет и не будет, а
	 *     встроенный DNS Docker отвечает на неё 5--25 мс и иногда --
	 *     «server misbehaving» через 8 с. Именно это съедало бюджет на первой
	 *     записи подсети, а не кодер: холодный вызов p99 3 с против 2 мс без
	 *     этого похода;
	 *   - простой: по умолчанию канал без вызовов закрывается через полчаса.
	 *     Кодера спрашивают редко -- только записи net|net_all|asn и корзины
	 *     по сетям, -- так что к каждому вызову он успевал остыть заново.
	 */
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

// Gen -- поколение кодера, под которым собран кэш. Ноль -- ещё ничего не
// спрашивали.
func (r *Resolver) Gen() uint64 {
	if r == nil {
		return 0
	}

	return r.gen.Load()
}

/*
 * Resolve -- эффективный анонс и номер системы для ключей корзин: `net` --
 * анонс, `router` -- номер строкой. Ждёт кодер в таймаут; молчащий кодер даёт
 * пустые ключи -- корзины по системам этот запрос не считают, и это видно в
 * журнале, но вердикт из-за ключей не рушится: ключ -- не запись в набор.
 */
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

/*
 * Lookup -- всё, что кодер знает об адресе. expand -- дописать каждой системе
 * её состав; составы кэшируются по номеру и не спрашиваются заново, пока не
 * сменилось поколение. Ошибка -- только когда кодер не ответил; адрес без
 * системы -- не ошибка, а пустой ответ.
 */
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

/* --- записи в набор ------------------------------------------------------- */

/*
 * Кого писать в набор, когда это не адрес. Слова одни на всех отправителей, и
 * разворачиваются они здесь, одной функцией: своя копия у каждого считала бы
 * «подсеть» по-своему -- и однажды уже считала (asn у modsec, json и счётчика
 * писал номер системы, а не её анонсы).
 */
const (
	// WriteNet -- лайт: эффективный анонс, самый узкий из накрывающих адрес;
	// та же сеть, по которой считаются корзины.
	WriteNet = "net"
	// WriteNetAll -- хард: все анонсы, накрывающие адрес, от узкого к
	// широкому, включая чужие широкие -- «всё, во что попал адрес».
	WriteNetAll = "net_all"
	// WriteASN -- система эффективного анонса целиком, её состав: адрес
	// принадлежит ей, а не тем, кто анонсирует шире.
	WriteASN = "asn"
)

// Networked -- записи нужен кодер. Адресу он не нужен.
func Networked(write string) bool {
	return write == WriteNet || write == WriteNetAll || write == WriteASN
}

/*
 * Values -- пачка записи net | net_all | asn по ответу кодера: префиксы без
 * повторов в его порядке -- от узкого к широкому, состав как отдан. Пустая --
 * у адреса нет системы; чужое слово -- тоже пустая: адрес кодера не требует.
 */
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

/*
 * Write -- пачка записи net | net_all | asn для адреса: кодер синхронно, в
 * бюджете сообщения, состав системы -- только у asn. Ошибка -- кодер нужен и
 * молчит либо его нет вовсе: записи не будет, и молча пропускать её нельзя.
 * Пустая пачка без ошибки -- кодер ответил, но системы у адреса нет, либо
 * адрес не разобрался.
 */
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

/* --- кэш ------------------------------------------------------------------ */

func (r *Resolver) cached(addr netip.Addr, expand bool) (Info, bool) {
	sp, ok := lookup(r.family(r.spans.Load(), addr), addr)
	if !ok {
		return Info{}, false
	}

	info := sp.info

	if !expand {
		return info, true
	}

	// Составы -- отдельным ярусом: анонсы могли лечь без них.
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

/*
 * insert -- новый кусок в неизменяемую таблицу: копия с вставкой и подмена
 * указателя. Пересечение с уже лежащим -- противоречие между поколениями,
 * и старое побеждает: таблица одного поколения непротиворечива по
 * построению, а смена поколения её сбрасывает целиком.
 */
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

// reset -- новое поколение кодера: всё, что знали, устарело.
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

/* --- одиночный полёт --------------------------------------------------- */

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

/* --- кодер ---------------------------------------------------------------- */

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

	// В кэше диапазонов -- анонсы без составов: они общие и весят.
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

/*
 * evictNegLocked освобождает место в отрицательном кэше. Сначала выметается
 * протухшее -- по времени оно и так недействительно, но само из карты не
 * уходит и занимает место до самого потолка. Если этого мало (скан идёт
 * быстрее, чем срок), снимаем записи дальше, пока не останется negKeep от
 * потолка: без порядка, в порядке обхода карты. Порядок тут и не нужен --
 * все записи равноценны, а важно не обнулять кэш целиком: сброс на потолке
 * возвращает кодеру всю нагрузку разом.
 */
func (r *Resolver) evictNegLocked(now time.Time) {
	/*
	 * Протухшее -- всё: оно и так недействительно, проверку срока на чтении
	 * не проходит и занимает место просто так. Проход по карте здесь один и
	 * тот же, снимать половину смысла нет.
	 */
	for addr, until := range r.neg {
		if !now.Before(until) {
			delete(r.neg, addr)
		}
	}

	/*
	 * Если протухшего не хватило -- скан идёт быстрее срока -- снимаем живое
	 * до девяти десятых потолка. Без порядка: записи равноценны, важно лишь
	 * не обнулить кэш целиком.
	 */
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

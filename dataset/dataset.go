package dataset

import (
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/nats-io/nats.go"
)

const Version = 3

const (
	OpAdd    = "add"
	OpRemove = "remove"

	requestTimeout = 5 * time.Second
)

type Event struct {
	V      int      `json:"v"`
	Set    string   `json:"set"`
	Op     string   `json:"op"`
	Value  string   `json:"value,omitempty"`
	Values []string `json:"values,omitempty"`
	TTL    int      `json:"ttl,omitempty"`
	Origin string   `json:"origin"`
	Reason string   `json:"reason,omitempty"`
}

type Reply struct {
	OK    bool   `json:"ok"`
	Seq   uint64 `json:"seq,omitempty"`
	Epoch string `json:"epoch,omitempty"`
	Error string `json:"error,omitempty"`
	Limit int    `json:"limit,omitempty"`
}

type Rejected struct {
	Code  string
	Limit int
}

func (r *Rejected) Error() string {
	if r.Limit > 0 {
		return fmt.Sprintf("list rejected: %s (limit %d)", r.Code, r.Limit)
	}

	return "list rejected: " + r.Code
}

var ErrUnreachable = errors.New("keeper unreachable")

type Publisher struct {
	nc     *nats.Conn
	origin string
	log    *slog.Logger
}

func New(nc *nats.Conn, origin string) *Publisher {
	if origin == "" {
		origin = "unknown"
	}

	return &Publisher{nc: nc, origin: origin}
}

func NewBackground(nc *nats.Conn, origin string, log *slog.Logger) *Publisher {
	p := New(nc, origin)

	if log == nil {
		log = slog.Default()
	}

	p.log = log

	return p
}

func (p *Publisher) Add(name, value string, ttl time.Duration, reason string) error {
	if ttl <= 0 {
		return fmt.Errorf("dataset add without ttl")
	}

	return p.send(&Event{
		Op:     OpAdd,
		Set:    name,
		Value:  value,
		TTL:    int(ttl.Seconds()),
		Reason: reason,
	})
}

func (p *Publisher) AddMany(name string, values []string, ttl time.Duration, reason string) error {
	if ttl <= 0 {
		return fmt.Errorf("dataset add without ttl")
	}

	switch len(values) {
	case 0:
		return nil

	case 1:
		return p.Add(name, values[0], ttl, reason)
	}

	return p.send(&Event{
		Op:     OpAdd,
		Set:    name,
		Values: values,
		TTL:    int(ttl.Seconds()),
		Reason: reason,
	})
}

func (p *Publisher) Remove(name, value, reason string) error {
	return p.send(&Event{
		Op:     OpRemove,
		Set:    name,
		Value:  value,
		Reason: reason,
	})
}

func (ev *Event) check() error {
	if ev.Set == "" || (ev.Value == "" && len(ev.Values) == 0) {
		return fmt.Errorf("dataset event needs set and value")
	}

	return nil
}

func (ev *Event) first() string {
	if ev.Value != "" || len(ev.Values) == 0 {
		return ev.Value
	}

	return ev.Values[0]
}

func (p *Publisher) send(ev *Event) error {
	if p == nil || p.nc == nil {
		return nil
	}

	if err := ev.check(); err != nil {
		return err
	}

	ev.V = Version
	ev.Origin = p.origin

	body, err := json.Marshal(ev)
	if err != nil {
		return err
	}

	if p.log == nil {
		return p.request(ev, body)
	}

	go func() {
		err := p.request(ev, body)

		var rejected *Rejected

		switch {
		case err == nil:
		case errors.As(err, &rejected):
			p.log.Warn("list write rejected",
				"set", ev.Set, "value", ev.first(), "count", max(len(ev.Values), 1),
				"error", rejected.Code, "limit", rejected.Limit)
		default:
			p.log.Warn("list write failed: keeper unreachable",
				"set", ev.Set, "value", ev.first(), "count", max(len(ev.Values), 1),
				"error", err.Error())
		}
	}()

	return nil
}

func (p *Publisher) request(ev *Event, body []byte) error {
	msg, err := p.nc.Request("waf.sets."+ev.Set+".event", body, requestTimeout)
	if err != nil {
		return fmt.Errorf("%w: %s", ErrUnreachable, err.Error())
	}

	var reply Reply
	if err := json.Unmarshal(msg.Data, &reply); err != nil {
		return fmt.Errorf("keeper reply is not json: %w", err)
	}

	if !reply.OK {
		return &Rejected{Code: reply.Error, Limit: reply.Limit}
	}

	return nil
}

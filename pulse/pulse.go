/*
 * Присутствие на WAF_STATUS: кто, где, сколько работает. Не вердикт и не
 * healthcheck контейнера. Контроллер слушает WAF_STATUS.> и ставит degraded
 * по тишине.
 *
 * Кадр у каждого процесса свой -- у инспектора очередь и профили, у keeper
 * наборы, у агента Redis снимок хранилища, -- но шапка одна: Frame. Процесс
 * встраивает её в свою структуру, поля ложатся в тот же объект JSON, а
 * контроллер разбирает то, что знает по kind, и пропускает остальное.
 * Message -- кадр инспектора, собранный так же.
 */

package pulse

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/nats-io/nats.go"

	"github.com/exemt/placitum-shared/flow"
	"github.com/exemt/placitum-shared/host"
)

// Frame -- шапка кадра любого процесса контура.
type Frame struct {
	V        int                  `json:"v"`
	Kind     string               `json:"kind"`
	ID       string               `json:"id"`
	Name     string               `json:"name"`
	Hostname string               `json:"hostname"`
	Ready    bool                 `json:"ready"`
	At       string               `json:"at"`
	Host     host.Snapshot        `json:"host"`
	WindowS  int                  `json:"window_s,omitempty"`
	IO       map[string]flow.Flow `json:"io,omitempty"`
}

/*
 * NewFrame -- шапка с временем и снимком машины, снятыми здесь. io -- темп
 * каналов за окно flow.Window; процесс, у которого окно своё (агенты
 * хранилищ меряют его по снимку хранилища), кладёт IO и WindowS сам.
 */
func NewFrame(kind, id, name string, ready bool, io map[string]flow.Flow) Frame {
	f := Frame{
		V:        1,
		Kind:     kind,
		ID:       id,
		Name:     name,
		Hostname: host.Hostname(),
		Ready:    ready,
		At:       time.Now().UTC().Format(time.RFC3339Nano),
		Host:     host.Collect(),
	}
	if len(io) > 0 {
		f.WindowS = flow.Window
		f.IO = io
	}
	return f
}

// Work -- очередь инспектора.
type Work struct {
	Workers    int   `json:"workers,omitempty"`
	QueueDepth int   `json:"queue_depth,omitempty"`
	Queued     int   `json:"queued,omitempty"`
	Accepted   int64 `json:"accepted,omitempty"`
	Shed       int64 `json:"shed,omitempty"`
	Expired    int64 `json:"expired,omitempty"`
}

// Message -- кадр инспектора: шапка, адрес на шине, очередь, поколение.
type Message struct {
	Frame
	Subject    string   `json:"subject"`
	Queue      string   `json:"queue"`
	Work       *Work    `json:"work,omitempty"`
	ConfigHash string   `json:"config_hash,omitempty"`
	Rev        int      `json:"rev,omitempty"`
	Apply      string   `json:"apply,omitempty"`
	Profiles   []string `json:"profiles,omitempty"`
}

func NewID() string {
	var b [16]byte
	_, _ = rand.Read(b[:])
	return hex.EncodeToString(b[:])
}

// Subject -- адрес кадра инспектора.
func Subject(name, id string) string {
	return fmt.Sprintf("WAF_STATUS.inspector.%s.%s", token(name), token(id))
}

// ServiceSubject -- адрес кадра сервиса: keeper, geo, логгер, агент haproxy.
func ServiceSubject(name, id string) string {
	return fmt.Sprintf("WAF_STATUS.service.%s.%s", token(name), token(id))
}

// StoreSubject -- адрес кадра агента хранилища: kind -- redis или s3.
func StoreSubject(kind, id string) string {
	return fmt.Sprintf("WAF_STATUS.store.%s.%s", token(kind), token(id))
}

func Build(id, name, subject, queue string, work *Work, io map[string]flow.Flow) Message {
	return Message{
		Frame:   NewFrame("inspector", id, name, true, io),
		Subject: subject,
		Queue:   queue,
		Work:    work,
	}
}

func Publish(nc *nats.Conn, msg Message) error {
	return PublishFrame(nc, Subject(msg.Name, msg.ID), msg)
}

/*
 * PublishFrame — кадр с полями, которых нет у соседей: список живых наборов
 * у инспектора адреса, счётчики вердиктов у капчи, снимок хранилища у агента
 * Redis. Процесс встраивает Message (инспектор) или Frame (сервис) в свою
 * структуру, и её поля ложатся в тот же объект JSON:
 *
 *	type frame struct {
 *		pulse.Message
 *		Live []LiveSet `json:"live,omitempty"`
 *	}
 *
 *	pulse.PublishFrame(nc, pulse.Subject(name, id), frame{Message: m, Live: l})
 *
 * Общий кадр от этого не растёт чужими полями, а читатель — контроллер —
 * разбирает то, что знает, и пропускает остальное.
 */
func PublishFrame(nc *nats.Conn, subject string, frame any) error {
	body, err := json.Marshal(frame)
	if err != nil {
		return err
	}

	return nc.Publish(subject, body)
}

func token(s string) string {
	r := strings.NewReplacer(".", "_", ">", "_", "*", "_", " ", "_")
	return r.Replace(s)
}

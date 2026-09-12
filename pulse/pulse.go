/*
 * Присутствие на WAF_STATUS — та же шина, что у агента и воркера.
 * Не вердикт и не probe-healthcheck контейнера. Контроллер слушает
 * WAF_STATUS.> и ставит degraded по тишине.
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

type Work struct {
	Workers    int   `json:"workers,omitempty"`
	QueueDepth int   `json:"queue_depth,omitempty"`
	Queued     int   `json:"queued,omitempty"`
	Accepted   int64 `json:"accepted,omitempty"`
	Shed       int64 `json:"shed,omitempty"`
	Expired    int64 `json:"expired,omitempty"`
}

type Message struct {
	V          int                  `json:"v"`
	Kind       string               `json:"kind"`
	ID         string               `json:"id"`
	Name       string               `json:"name"`
	Subject    string               `json:"subject"`
	Queue      string               `json:"queue"`
	Hostname   string               `json:"hostname"`
	Ready      bool                 `json:"ready"`
	At         string               `json:"at"`
	Host       host.Snapshot        `json:"host"`
	Work       *Work                `json:"work,omitempty"`
	WindowS    int                  `json:"window_s,omitempty"`
	IO         map[string]flow.Flow `json:"io,omitempty"`
	ConfigHash string               `json:"config_hash,omitempty"`
	Rev        int                  `json:"rev,omitempty"`
	Apply      string               `json:"apply,omitempty"`
	Profiles   []string             `json:"profiles,omitempty"`
}

func NewID() string {
	var b [16]byte
	_, _ = rand.Read(b[:])
	return hex.EncodeToString(b[:])
}

func Subject(name, id string) string {
	return fmt.Sprintf("WAF_STATUS.inspector.%s.%s", token(name), token(id))
}

func Build(id, name, subject, queue string, work *Work, io map[string]flow.Flow) Message {
	msg := Message{
		V:        1,
		Kind:     "inspector",
		ID:       id,
		Name:     name,
		Subject:  subject,
		Queue:    queue,
		Hostname: host.Hostname(),
		Ready:    true,
		At:       time.Now().UTC().Format(time.RFC3339Nano),
		Host:     host.Collect(),
		Work:     work,
	}
	if len(io) > 0 {
		msg.WindowS = flow.Window
		msg.IO = io
	}
	return msg
}

func Publish(nc *nats.Conn, msg Message) error {
	return PublishFrame(nc, Subject(msg.Name, msg.ID), msg)
}

/*
 * PublishFrame — тот же кадр, но с полями, которых нет у соседей: список живых
 * наборов у инспектора адреса, счётчики вердиктов у капчи. Процесс встраивает
 * Message в свою структуру, и её поля ложатся в тот же объект JSON:
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

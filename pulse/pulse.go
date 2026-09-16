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

type Frame struct {
	V        int                  `json:"v"`
	Kind     string               `json:"kind"`
	ID       string               `json:"id"`
	Name     string               `json:"name"`
	Hostname string               `json:"hostname"`
	Version  string               `json:"version,omitempty"`
	Revision string               `json:"revision,omitempty"`
	Ready    bool                 `json:"ready"`
	At       string               `json:"at"`
	Host     host.Snapshot        `json:"host"`
	WindowS  int                  `json:"window_s,omitempty"`
	IO       map[string]flow.Flow `json:"io,omitempty"`
}

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

type Work struct {
	Workers    int   `json:"workers,omitempty"`
	QueueDepth int   `json:"queue_depth,omitempty"`
	Queued     int   `json:"queued,omitempty"`
	Accepted   int64 `json:"accepted,omitempty"`
	Shed       int64 `json:"shed,omitempty"`
	Expired    int64 `json:"expired,omitempty"`
}

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

func Subject(name, id string) string {
	return fmt.Sprintf("WAF_STATUS.inspector.%s.%s", token(name), token(id))
}

func ServiceSubject(name, id string) string {
	return fmt.Sprintf("WAF_STATUS.service.%s.%s", token(name), token(id))
}

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

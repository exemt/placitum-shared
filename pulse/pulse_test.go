package pulse

import (
	"encoding/json"
	"testing"
)

// Встроенная шапка ложится в тот же объект, что и поля процесса, а поле
// процесса с тем же именем перекрывает поле шапки -- на этом держится
// собственный work у сервисов.
func TestEmbeddedFrameFlattens(t *testing.T) {
	type work struct {
		Inserted int `json:"inserted"`
	}

	type frame struct {
		Frame
		Work work `json:"work"`
	}

	body, err := json.Marshal(frame{Frame: NewFrame("service", "id-1", "logger", true, nil), Work: work{Inserted: 7}})
	if err != nil {
		t.Fatal(err)
	}

	var got map[string]any
	if err := json.Unmarshal(body, &got); err != nil {
		t.Fatal(err)
	}

	if got["kind"] != "service" || got["name"] != "logger" || got["ready"] != true {
		t.Fatalf("шапка: %s", body)
	}

	if w, _ := got["work"].(map[string]any); w["inserted"] != 7.0 {
		t.Fatalf("work процесса: %s", body)
	}

	if _, ok := got["window_s"]; ok {
		t.Fatalf("окно без каналов: %s", body)
	}
}

func TestInspectorMessageKeepsShape(t *testing.T) {
	msg := Build("id-2", "ip", "waf.req.ip", "ip", &Work{Workers: 4}, nil)
	msg.ConfigHash = "sha256:abc"

	body, err := json.Marshal(msg)
	if err != nil {
		t.Fatal(err)
	}

	var got map[string]any
	if err := json.Unmarshal(body, &got); err != nil {
		t.Fatal(err)
	}

	for _, key := range []string{"v", "kind", "id", "name", "subject", "queue", "hostname", "ready", "at", "host", "work", "config_hash"} {
		if _, ok := got[key]; !ok {
			t.Fatalf("нет %s: %s", key, body)
		}
	}

	if got["kind"] != "inspector" || got["subject"] != "waf.req.ip" {
		t.Fatalf("кадр инспектора: %s", body)
	}
}

func TestSubjects(t *testing.T) {
	if Subject("ip", "a.b") != "WAF_STATUS.inspector.ip.a_b" ||
		ServiceSubject("keeper", "x") != "WAF_STATUS.service.keeper.x" ||
		StoreSubject("redis", "r1") != "WAF_STATUS.store.redis.r1" {
		t.Fatal("адреса кадров")
	}
}

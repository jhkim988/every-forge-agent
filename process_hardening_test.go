package main

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"reflect"
	"testing"
)

func TestProcessHardening_LsofSpacesInCommandAndUser(t *testing.T) {
	sample := `COMMAND             PID           USER   FD   TYPE             DEVICE SIZE/OFF NODE NAME
Code Helper       11111         jinhan   42u  IPv4 0x1111111111111111      0t0  TCP 127.0.0.1:51001 (LISTEN)
Docker Desktop    22222   john doe       18u  IPv6 0x2222222222222222      0t0  TCP [::1]:51002 (LISTEN)
normalproc        33333   domain user    19u  IPv4 0x3333333333333333      0t0  TCP *:51003 (LISTEN)
`
	portMap := make(map[string][]string)
	parseLsofOutput(sample, portMap)
	sortPortMap(portMap)

	if !reflect.DeepEqual(portMap["11111"], []string{"tcp/51001"}) {
		t.Errorf("PID 11111 got %v, want [tcp/51001]", portMap["11111"])
	}
	if !reflect.DeepEqual(portMap["22222"], []string{"tcp/51002"}) {
		t.Errorf("PID 22222 got %v, want [tcp/51002]", portMap["22222"])
	}
	if !reflect.DeepEqual(portMap["33333"], []string{"tcp/51003"}) {
		t.Errorf("PID 33333 got %v, want [tcp/51003]", portMap["33333"])
	}
}

func TestProcessHardening_WindowsTasklistCSVQuotedCommas(t *testing.T) {
	raw := `"my,custom,app.exe","4321","Console","1","256,120 K"` + "\r\n" +
		`"HostName","NotAPid","Console","1","10 K"` + "\r\n"
	items := parseProcessList(raw, "windows")
	if len(items) != 1 {
		t.Fatalf("expected 1 valid windows process, got %d (%+v)", len(items), items)
	}
	if items[0].Name != "my,custom,app.exe" || items[0].PID != "4321" || items[0].Memory != "256,120 K" {
		t.Errorf("unexpected parsed item: %+v", items[0])
	}
}

func TestProcessHardening_FractionalAndOverflowFloatPIDRejected(t *testing.T) {
	agent := NewAgentServer("tok", false)
	badPayloads := []string{
		`{"pid": 2.9}`,
		`{"pid": 1234.5}`,
		`{"pid": 1e20}`,
	}
	for _, body := range badPayloads {
		req := httptest.NewRequest(http.MethodPost, "/api/process/kill", bytes.NewBufferString(body))
		w := httptest.NewRecorder()
		agent.handleProcessKill(w, req)
		if w.Code != http.StatusBadRequest {
			t.Errorf("payload %s returned %d, want 400 Bad Request (body=%s)", body, w.Code, w.Body.String())
		}
	}
}

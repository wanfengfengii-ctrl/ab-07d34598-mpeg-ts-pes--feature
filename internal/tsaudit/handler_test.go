package tsaudit_test

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"mpegtsaudit/internal/tsaudit"
	"mpegtsaudit/internal/tsbuild"
)

func doAudit(t *testing.T, body []byte, query, ctype string) (int, map[string]any) {
	t.Helper()
	srv := httptest.NewServer(tsaudit.AuditHandler{})
	defer srv.Close()

	req, err := http.NewRequest(http.MethodPost, srv.URL+"/api/mpegts/audit?"+query, bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	if ctype != "" {
		req.Header.Set("Content-Type", ctype)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var decoded map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&decoded); err != nil {
		t.Fatalf("response is not JSON: %v", err)
	}
	return resp.StatusCode, decoded
}

func TestHTTPSuccess(t *testing.T) {
	status, body := doAudit(t, validFragment(), "maxPcrGapMs=1000", "application/octet-stream")
	if status != http.StatusOK {
		t.Fatalf("status=%d body=%v", status, body)
	}
	if body["ok"] != true {
		t.Fatalf("ok flag = %v", body["ok"])
	}
	rep := body["report"].(map[string]any)
	if rep["programNumber"].(float64) != 1 {
		t.Errorf("programNumber = %v", rep["programNumber"])
	}
}

func TestHTTPRuleFailureShape(t *testing.T) {
	d := validFragment()
	d[0] = 0x00 // bad sync
	status, body := doAudit(t, d, "maxPcrGapMs=1000", "application/octet-stream")
	if status != http.StatusUnprocessableEntity {
		t.Fatalf("status=%d", status)
	}
	if body["ok"] != false {
		t.Fatalf("ok must be false, got %v", body["ok"])
	}
	errObj := body["error"].(map[string]any)
	if errObj["code"] != tsaudit.ErrBadSyncByte {
		t.Errorf("code = %v", errObj["code"])
	}
	if _, ok := body["report"]; ok {
		t.Fatal("partial report must not be returned on failure")
	}
	if body["packet"].(float64) != 0 {
		t.Errorf("packet = %v", body["packet"])
	}
}

func TestHTTPBadParams(t *testing.T) {
	cases := []struct {
		name   string
		query  string
		status int
		code   string
	}{
		{"missing", "", http.StatusBadRequest, "TS_MISSING_MAX_PCR_GAP"},
		{"zero", "maxPcrGapMs=0", http.StatusBadRequest, "TS_INVALID_MAX_PCR_GAP"},
		{"huge", "maxPcrGapMs=99999", http.StatusBadRequest, "TS_INVALID_MAX_PCR_GAP"},
		{"nan", "maxPcrGapMs=abc", http.StatusBadRequest, "TS_INVALID_MAX_PCR_GAP"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			status, body := doAudit(t, validFragment(), tc.query, "application/octet-stream")
			if status != tc.status {
				t.Fatalf("status=%d body=%v", status, body)
			}
			if body["error"].(map[string]any)["code"] != tc.code {
				t.Fatalf("body=%v", body)
			}
		})
	}
}

func TestHTTPWrongContentType(t *testing.T) {
	status, _ := doAudit(t, validFragment(), "maxPcrGapMs=1000", "text/plain")
	if status != http.StatusUnsupportedMediaType {
		t.Fatalf("status=%d", status)
	}
}

func TestHTTPPESInvalidValue(t *testing.T) {
	for _, q := range []string{"pes=strict", "pes=Bounded"} {
		status, body := doAudit(t, validFragment(), "maxPcrGapMs=1000&"+q, "application/octet-stream")
		if status != http.StatusBadRequest {
			t.Fatalf("%s: status=%d body=%v", q, status, body)
		}
		if body["error"].(map[string]any)["code"] != tsaudit.ErrInvalidPES {
			t.Fatalf("%s: body=%v", q, body)
		}
	}
}

func TestHTTPPESBoundedSuccess(t *testing.T) {
	status, body := doAudit(t, boundedFragment(), "maxPcrGapMs=1000&pes=bounded", "application/octet-stream")
	if status != http.StatusOK {
		t.Fatalf("status=%d body=%v", status, body)
	}
	media := body["report"].(map[string]any)["media"].([]any)
	m0 := media[0].(map[string]any)
	if m0["pesCount"].(float64) != 1 || m0["pesBytes"].(float64) != 406 {
		t.Fatalf("video PES fields wrong: %v", m0)
	}
	m1 := media[1].(map[string]any)
	if m1["pesCount"].(float64) != 1 || m1["pesBytes"].(float64) != 206 {
		t.Fatalf("audio PES fields wrong: %v", m1)
	}
}

func TestHTTPPESOmittedKeepsBaseShape(t *testing.T) {
	status, body := doAudit(t, validFragment(), "maxPcrGapMs=1000", "application/octet-stream")
	if status != http.StatusOK {
		t.Fatalf("status=%d body=%v", status, body)
	}
	media := body["report"].(map[string]any)["media"].([]any)
	for _, m := range media {
		entry := m.(map[string]any)
		if _, ok := entry["pesCount"]; ok {
			t.Fatalf("pesCount must be absent without pes=bounded: %v", entry)
		}
		if _, ok := entry["pesBytes"]; ok {
			t.Fatalf("pesBytes must be absent without pes=bounded: %v", entry)
		}
	}
}

func TestHTTPPESBoundedRejectsTruncated(t *testing.T) {
	b := tsbuild.New()
	b.AddPAT()
	b.AddPMT()
	b.AddPCR(b.Opt.PCRPID, 0)
	b.AddPESStart(b.Opt.Media[0].PID, 0xE0, 400)
	status, body := doAudit(t, b.Bytes(), "maxPcrGapMs=1000&pes=bounded", "application/octet-stream")
	if status != http.StatusUnprocessableEntity {
		t.Fatalf("status=%d body=%v", status, body)
	}
	errObj := body["error"].(map[string]any)
	if errObj["code"] != tsaudit.ErrPESTruncated {
		t.Fatalf("code=%v", errObj["code"])
	}
	if body["packet"].(float64) != 3 || body["pid"].(float64) != 0x0101 {
		t.Fatalf("location wrong: %v", body)
	}
	if _, ok := body["report"]; ok {
		t.Fatal("partial report must not be returned on failure")
	}
}

func TestHTTPTooLarge(t *testing.T) {
	big := make([]byte, tsaudit.MaxBodyBytes+188)
	for i := range big {
		big[i] = 0xFF
	}
	big[0] = 0x47
	status, body := doAudit(t, big, "maxPcrGapMs=1000", "application/octet-stream")
	if status != http.StatusRequestEntityTooLarge {
		t.Fatalf("status=%d body=%v", status, body)
	}
	if body["error"].(map[string]any)["code"] != tsaudit.ErrBodyTooLarge {
		t.Fatalf("body=%v", body)
	}
}

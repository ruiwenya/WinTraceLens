package server

import (
	"archive/zip"
	"bytes"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func readEvidenceZIP(t *testing.T, data []byte) map[string][]byte {
	t.Helper()
	reader, err := zip.NewReader(bytes.NewReader(data), int64(len(data)))
	if err != nil {
		t.Fatal(err)
	}
	files := map[string][]byte{}
	for _, entry := range reader.File {
		if strings.Contains(entry.Name, "..") || strings.HasPrefix(entry.Name, "/") || strings.ContainsAny(entry.Name, `\:`) {
			t.Fatalf("unsafe name %s", entry.Name)
		}
		if _, ok := files[entry.Name]; ok {
			t.Fatalf("duplicate name %s", entry.Name)
		}
		file, err := entry.Open()
		if err != nil {
			t.Fatal(err)
		}
		content, err := io.ReadAll(file)
		file.Close()
		if err != nil {
			t.Fatal(err)
		}
		files[entry.Name] = content
	}
	return files
}

func TestEvidenceExportAuthenticatedEmptyAndNoAISecrets(t *testing.T) {
	s := New(Options{Version: "test"})
	routes := s.Routes()
	bootstrap := httptest.NewRecorder()
	routes.ServeHTTP(bootstrap, httptest.NewRequest(http.MethodGet, s.BootstrapURL("http://127.0.0.1/"), nil))
	cookie := bootstrap.Result().Cookies()[0]
	call := func(method, path string, authorized bool) *httptest.ResponseRecorder {
		r := httptest.NewRequest(method, "http://127.0.0.1"+path, nil)
		if authorized {
			r.AddCookie(cookie)
			r.Header.Set(tokenHeader, s.accessToken)
		}
		w := httptest.NewRecorder()
		routes.ServeHTTP(w, r)
		return w
	}
	if w := call(http.MethodPost, "/api/export/evidence", false); w.Code != http.StatusForbidden {
		t.Fatalf("unauthenticated export %d", w.Code)
	}
	if w := call(http.MethodGet, "/api/export/evidence", true); w.Code != http.StatusMethodNotAllowed {
		t.Fatalf("GET export %d", w.Code)
	}
	if w := call(http.MethodPost, "/api/export/evidence", true); w.Code != http.StatusConflict {
		t.Fatalf("empty export %d", w.Code)
	}
	s.aiSession.APIKeys = map[string]string{"deepseek": "do-not-export-this-key"}
	s.rememberEvidence("findings", nil, map[string]any{"items": []any{map[string]string{"name": "fixture"}}})
	w := call(http.MethodGet, "/api/export/evidence/status", true)
	if w.Code != 200 || strings.Contains(w.Body.String(), "fixture") {
		t.Fatalf("status not metadata only: %s", w.Body.String())
	}
	w = call(http.MethodPost, "/api/export/evidence", true)
	if w.Code != 200 || w.Header().Get("Content-Type") != "application/zip" {
		t.Fatalf("export %d: %s", w.Code, w.Body.String())
	}
	for name, data := range readEvidenceZIP(t, w.Body.Bytes()) {
		if strings.Contains(string(data), "do-not-export-this-key") {
			t.Fatalf("secret in %s", name)
		}
	}
	s.evidenceExportMu.Lock()
	w = call(http.MethodPost, "/api/export/evidence", true)
	s.evidenceExportMu.Unlock()
	if w.Code != http.StatusConflict {
		t.Fatal("parallel package generation allowed")
	}
}

func TestEvidenceExportSelectedSources(t *testing.T) {
	s := New(Options{Version: "test"})
	s.rememberEvidence("findings", nil, map[string]any{"items": []string{"selected-fixture"}})
	s.rememberEvidence("behavior", nil, map[string]any{"items": []string{"excluded-fixture"}})
	for _, test := range []struct {
		body string
		code int
	}{
		{`{"sources":[]}`, http.StatusBadRequest},
		{`{"sources":["unknown"]}`, http.StatusBadRequest},
		{`{"sources":["host"]}`, http.StatusConflict},
		{`{"sources":["findings"]}`, http.StatusOK},
	} {
		w := httptest.NewRecorder()
		r := httptest.NewRequest(http.MethodPost, "/api/export/evidence", strings.NewReader(test.body))
		s.handleEvidencePackage(w, r)
		if w.Code != test.code {
			t.Fatalf("%s: %d, %s", test.body, w.Code, w.Body.String())
		}
		if w.Code != http.StatusOK {
			continue
		}
		found := false
		for name, data := range readEvidenceZIP(t, w.Body.Bytes()) {
			if strings.Contains(string(data), "excluded-fixture") {
				t.Fatalf("excluded evidence present in %s", name)
			}
			found = found || strings.Contains(string(data), "selected-fixture")
		}
		if !found {
			t.Fatal("selected evidence missing")
		}
	}
}

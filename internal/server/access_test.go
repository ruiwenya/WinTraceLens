package server

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestRoutesRequireBootstrapCookieAndAPIHeader(t *testing.T) {
	srv := New(Options{Version: "test"})
	handler := srv.Routes()

	unauthorized := httptest.NewRecorder()
	handler.ServeHTTP(unauthorized, httptest.NewRequest(http.MethodGet, "http://127.0.0.1/", nil))
	if unauthorized.Code != http.StatusForbidden {
		t.Fatalf("unauthorized static request: got %d", unauthorized.Code)
	}

	bootstrap := httptest.NewRecorder()
	handler.ServeHTTP(bootstrap, httptest.NewRequest(http.MethodGet, srv.BootstrapURL("http://127.0.0.1/"), nil))
	if bootstrap.Code != http.StatusSeeOther {
		t.Fatalf("bootstrap: got %d", bootstrap.Code)
	}
	cookies := bootstrap.Result().Cookies()
	if len(cookies) != 1 || !cookies[0].HttpOnly {
		t.Fatalf("bootstrap cookie missing or not HttpOnly")
	}

	noHeader := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodGet, "http://127.0.0.1/api/about", nil)
	request.AddCookie(cookies[0])
	handler.ServeHTTP(noHeader, request)
	if noHeader.Code != http.StatusForbidden {
		t.Fatalf("API without token header: got %d", noHeader.Code)
	}

	authorized := httptest.NewRecorder()
	request = httptest.NewRequest(http.MethodGet, "http://127.0.0.1/api/about", nil)
	request.AddCookie(cookies[0])
	request.Header.Set(tokenHeader, srv.accessToken)
	request.Header.Set("Origin", "http://127.0.0.1")
	handler.ServeHTTP(authorized, request)
	if authorized.Code != http.StatusOK {
		t.Fatalf("authorized API request: got %d body=%s", authorized.Code, authorized.Body.String())
	}
}

func TestRoutesRejectNonLoopbackHostAndCrossSiteBrowserRequest(t *testing.T) {
	srv := New(Options{Version: "test"})
	handler := srv.Routes()

	nonLoopback := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodGet, srv.BootstrapURL("http://127.0.0.1/"), nil)
	request.Host = "attacker.example"
	handler.ServeHTTP(nonLoopback, request)
	if nonLoopback.Code != http.StatusForbidden {
		t.Fatalf("non-loopback Host: got %d", nonLoopback.Code)
	}

	bootstrap := httptest.NewRecorder()
	handler.ServeHTTP(bootstrap, httptest.NewRequest(http.MethodGet, srv.BootstrapURL("http://127.0.0.1/"), nil))
	cookie := bootstrap.Result().Cookies()[0]

	crossSite := httptest.NewRecorder()
	request = httptest.NewRequest(http.MethodGet, "http://127.0.0.1/api/about", nil)
	request.AddCookie(cookie)
	request.Header.Set(tokenHeader, srv.accessToken)
	request.Header.Set("Sec-Fetch-Site", "cross-site")
	handler.ServeHTTP(crossSite, request)
	if crossSite.Code != http.StatusForbidden {
		t.Fatalf("cross-site browser request: got %d", crossSite.Code)
	}
}

func TestAISessionDoesNotReturnAPIKeys(t *testing.T) {
	srv := New(Options{Version: "test"})
	handler := srv.Routes()
	bootstrap := httptest.NewRecorder()
	handler.ServeHTTP(bootstrap, httptest.NewRequest(http.MethodGet, srv.BootstrapURL("http://127.0.0.1/"), nil))
	cookie := bootstrap.Result().Cookies()[0]

	put := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodPut, "http://127.0.0.1/api/ai/session",
		strings.NewReader(`{"apiKeys":{"deepseek":"secret-value"}}`))
	request.AddCookie(cookie)
	request.Header.Set(tokenHeader, srv.accessToken)
	request.Header.Set("Content-Type", "application/json")
	handler.ServeHTTP(put, request)
	if put.Code != http.StatusOK {
		t.Fatalf("save session: got %d body=%s", put.Code, put.Body.String())
	}
	if strings.Contains(put.Body.String(), "secret-value") {
		t.Fatalf("PUT response exposed API key")
	}

	get := httptest.NewRecorder()
	request = httptest.NewRequest(http.MethodGet, "http://127.0.0.1/api/ai/session", nil)
	request.AddCookie(cookie)
	request.Header.Set(tokenHeader, srv.accessToken)
	handler.ServeHTTP(get, request)
	if get.Code != http.StatusOK {
		t.Fatalf("load session: got %d body=%s", get.Code, get.Body.String())
	}
	if strings.Contains(get.Body.String(), "secret-value") {
		t.Fatalf("GET response exposed API key")
	}
	var state struct {
		SavedAPIKeys map[string]bool `json:"savedApiKeys"`
	}
	if err := json.Unmarshal(get.Body.Bytes(), &state); err != nil {
		t.Fatal(err)
	}
	if !state.SavedAPIKeys["deepseek"] {
		t.Fatalf("saved API key marker missing")
	}
}

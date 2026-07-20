package server

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strings"
)

const (
	bootstrapQuery = "wtl_bootstrap"
	sessionCookie  = "WTL-Session"
	tokenHeader    = "X-WTL-Token"
)

func newAccessToken() string {
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		panic(fmt.Errorf("generate local API token: %w", err))
	}
	return base64.RawURLEncoding.EncodeToString(raw)
}

func (s *Server) BootstrapURL(base string) string {
	parsed, err := url.Parse(base)
	if err != nil {
		return base
	}
	query := parsed.Query()
	query.Set(bootstrapQuery, s.accessToken)
	parsed.RawQuery = query.Encode()
	return parsed.String()
}

func (s *Server) requireLocalSession(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		setSecurityHeaders(w)
		if !isLoopbackHost(r.Host) {
			http.Error(w, "loopback host required", http.StatusForbidden)
			return
		}
		if token := r.URL.Query().Get(bootstrapQuery); token != "" {
			if !secureEqual(token, s.accessToken) {
				http.Error(w, "invalid bootstrap token", http.StatusForbidden)
				return
			}
			http.SetCookie(w, &http.Cookie{
				Name:     sessionCookie,
				Value:    s.accessToken,
				Path:     "/",
				HttpOnly: true,
				SameSite: http.SameSiteStrictMode,
			})
			target := *r.URL
			query := target.Query()
			query.Del(bootstrapQuery)
			target.RawQuery = query.Encode()
			if target.Path == "" {
				target.Path = "/"
			}
			http.Redirect(w, r, target.String(), http.StatusSeeOther)
			return
		}

		cookie, err := r.Cookie(sessionCookie)
		if err != nil || !secureEqual(cookie.Value, s.accessToken) {
			http.Error(w, "local session required", http.StatusForbidden)
			return
		}
		if strings.HasPrefix(r.URL.Path, "/api/") {
			if !secureEqual(r.Header.Get(tokenHeader), s.accessToken) {
				http.Error(w, "local API token required", http.StatusForbidden)
				return
			}
			if !sameOriginRequest(r) {
				http.Error(w, "cross-origin request denied", http.StatusForbidden)
				return
			}
			w.Header().Set("Cache-Control", "no-store")
		}
		next.ServeHTTP(w, r)
	})
}

func (s *Server) handleAppJS(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	script, err := uiFiles.ReadFile("ui/app.js")
	if err != nil {
		http.Error(w, "app bootstrap unavailable", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/javascript; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	_, _ = fmt.Fprintf(w, "window.__WTL_API_TOKEN=%q;\n", s.accessToken)
	_, _ = w.Write(script)
}

func secureEqual(left, right string) bool {
	if len(left) != len(right) {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(left), []byte(right)) == 1
}

func sameOriginRequest(r *http.Request) bool {
	if strings.EqualFold(strings.TrimSpace(r.Header.Get("Sec-Fetch-Site")), "cross-site") {
		return false
	}
	origin := strings.TrimSpace(r.Header.Get("Origin"))
	// Non-browser clients may omit Origin; the session cookie and random API
	// token remain the authentication boundary for those requests.
	if origin == "" {
		return true
	}
	parsed, err := url.Parse(origin)
	if err != nil {
		return false
	}
	return (parsed.Scheme == "http" || parsed.Scheme == "https") &&
		strings.EqualFold(parsed.Host, r.Host)
}

func isLoopbackHost(value string) bool {
	host := strings.TrimSpace(value)
	if parsedHost, _, err := net.SplitHostPort(host); err == nil {
		host = parsedHost
	}
	host = strings.Trim(host, "[]")
	if strings.EqualFold(host, "localhost") {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

func setSecurityHeaders(w http.ResponseWriter) {
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Referrer-Policy", "no-referrer")
	w.Header().Set("Cross-Origin-Resource-Policy", "same-origin")
	w.Header().Set("X-Frame-Options", "DENY")
}

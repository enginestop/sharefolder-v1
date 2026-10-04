package app

import (
	"net/http"
	"sharefolder/internal/auth"
	"sharefolder/internal/web"
	"strings"
	"time"
)

func (a *App) web(r *Request) {
	if r.R.Method != "GET" && r.R.Method != "HEAD" {
		r.W.WriteHeader(405)
		return
	}
	if strings.HasPrefix(r.R.URL.Path, "/static/") {
		r.W.Header().Set("Cache-Control", "no-store")
		http.StripPrefix("/static/", http.FileServer(http.FS(web.Static()))).ServeHTTP(r.W, r.R)
		return
	}
	nonce := ""
	if r.R.URL.Path == "/login" {
		a.nonceMu.Lock()
		for key, expiry := range a.nonces {
			if !a.now().Before(expiry) {
				delete(a.nonces, key)
			}
		}
		for key, entry := range a.limits {
			if !a.now().Before(entry.Until) {
				delete(a.limits, key)
			}
		}
		if len(a.nonces) >= 10000 {
			a.nonceMu.Unlock()
			problem(r.W, r.ID, fail(429, "RATE_LIMITED"))
			return
		}
		nonce = auth.Token()
		a.nonces[nonce] = a.now().Add(10 * time.Minute)
		a.nonceMu.Unlock()
		http.SetCookie(r.W, &http.Cookie{Name: "rf_login_nonce", Value: nonce, Path: "/", MaxAge: 600, HttpOnly: true, Secure: a.Config.Env == "production", SameSite: http.SameSiteStrictMode})
	}
	r.W.Header().Set("Content-Type", "text/html; charset=utf-8")
	r.W.Header().Set("Cache-Control", "no-store")
	r.W.Write([]byte(strings.ReplaceAll(web.Shell(), "{{NONCE}}", nonce)))
}

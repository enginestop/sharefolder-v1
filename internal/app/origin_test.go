package app

import (
	"bytes"
	"net/http/httptest"
	"regexp"
	"testing"
)

func TestAdditionalOriginIsBoundToRequestHost(t *testing.T) {
	a := testApp(t)
	request := func(method, target, origin string, body []byte, nonce string, forwarded string) *httptest.ResponseRecorder {
		r := httptest.NewRequest(method, target, bytes.NewReader(body))
		if body != nil {
			r.Header.Set("Content-Type", "application/json")
		}
		if origin != "" {
			r.Header.Set("Origin", origin)
		}
		if nonce != "" {
			r.Header.Set("Cookie", "rf_login_nonce="+nonce)
			r.Header.Set("X-Login-Nonce", nonce)
		}
		if forwarded != "" {
			r.Header.Set("X-Forwarded-Host", forwarded)
		}
		w := httptest.NewRecorder()
		a.ServeHTTP(w, r)
		return w
	}
	base := "https://sf.cloudserver.my.id"
	login := request("GET", base+"/login", "", nil, "", "")
	if login.Code != 200 {
		t.Fatalf("tunnel login page: %d %s", login.Code, login.Body.String())
	}
	nonceMatch := regexp.MustCompile(`name="login-nonce" content="([^"]+)"`).FindStringSubmatch(login.Body.String())
	if len(nonceMatch) != 2 {
		t.Fatal("login nonce missing")
	}
	nonce := nonceMatch[1]
	credentials := []byte(`{"username":"admin","password":"LocalOnly-Admin!2026"}`)
	parse(t, request("POST", base+"/api/v1/session", a.Config.Origin, credentials, nonce, ""), 403)
	parse(t, request("POST", "https://localhost/api/v1/session", base, credentials, nonce, "sf.cloudserver.my.id"), 400)
	parse(t, request("POST", "https://evil.example/api/v1/session", base, credentials, nonce, ""), 403)
	response := request("POST", base+"/api/v1/session", base, credentials, nonce, "")
	parse(t, response, 200)
	if len(response.Result().Cookies()) == 0 {
		t.Fatal("session cookie missing")
	}
	if primary := request("GET", a.Config.Origin+"/login", "", nil, "", ""); primary.Code != 200 {
		t.Fatalf("LAN origin stopped working: %d", primary.Code)
	}
	second := "https://files.example.net"
	changed := request("GET", second+"/login", "", nil, "", "")
	if changed.Code != 200 {
		t.Fatalf("new domain requires configuration: %d", changed.Code)
	}
	changedNonce := regexp.MustCompile(`name="login-nonce" content="([^"]+)"`).FindStringSubmatch(changed.Body.String())[1]
	parse(t, request("POST", second+"/api/v1/session", second, credentials, changedNonce, ""), 200)
}

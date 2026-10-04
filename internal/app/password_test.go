package app

import (
	"regexp"
	"sharefolder/internal/db"
	"strings"
	"testing"
)

func TestUnrestrictedPasswordResetAndLogin(t *testing.T) {
	a := testApp(t)
	admin := loginClient(t, a, "admin")
	for _, password := range []string{"", "1", " ", strings.Repeat("x", 256)} {
		parse(t, admin.request("POST", "/api/v1/admin/users/"+fixtureID("2")+"/reset-password", M{"temporary_password": password}, map[string]string{"Idempotency-Key": db.ID()}), 204)
		c := &client{app: a, t: t}
		page := c.request("GET", "/login", nil, nil)
		nonce := regexp.MustCompile(`name="login-nonce" content="([^"]+)"`).FindStringSubmatch(page.Body.String())[1]
		c.cookie = "rf_login_nonce=" + nonce
		response := c.request("POST", "/api/v1/session", M{"username": "pegawai-a", "password": password}, map[string]string{"X-Login-Nonce": nonce})
		result := parse(t, response, 200)
		if result["user"].(map[string]any)["must_change_password"].(bool) {
			t.Fatal("reset unexpectedly requires password change")
		}
		c.csrf = result["csrf_token"].(string)
		for _, cookie := range response.Result().Cookies() {
			if cookie.Name == "rf_session" {
				c.cookie = cookie.Name + "=" + cookie.Value
			}
		}
		parse(t, c.request("GET", "/api/v1/workspaces", nil, nil), 200)
		createFolderTest(t, c, fixtureID("201"), fixtureID("101"), db.ID())
	}
}

func TestStartupClearsLegacyPasswordRequirement(t *testing.T) {
	a := testApp(t)
	c := loginClient(t, a, "pegawai-a")
	before, e := getUser(a.DB.Read, fixtureID("2"))
	if e != nil {
		t.Fatal(e)
	}
	if _, e = a.DB.Write.Exec("UPDATE users SET must_change_password=1 WHERE id=?", before.ID); e != nil {
		t.Fatal(e)
	}
	if _, e = a.DB.Write.Exec("UPDATE sessions SET password_change_only=1 WHERE user_id=?", before.ID); e != nil {
		t.Fatal(e)
	}
	if e = a.Start(); e != nil {
		t.Fatal(e)
	}
	defer a.Close()
	after, e := getUser(a.DB.Read, before.ID)
	if e != nil {
		t.Fatal(e)
	}
	if after.MustChange || after.Hash != before.Hash || after.Revision != before.Revision+1 {
		t.Fatal("legacy account conversion failed")
	}
	var flags int
	if e = a.DB.Read.QueryRow("SELECT count(*) FROM sessions WHERE password_change_only=1").Scan(&flags); e != nil || flags != 0 {
		t.Fatal("legacy session conversion failed")
	}
	parse(t, c.request("GET", "/api/v1/workspaces", nil, nil), 200)
	createFolderTest(t, c, fixtureID("201"), fixtureID("101"), "After upgrade")
	if e = a.clearPasswordChangeRequirements(); e != nil {
		t.Fatal(e)
	}
	again, e := getUser(a.DB.Read, before.ID)
	if e != nil || again.Revision != after.Revision {
		t.Fatal("conversion is not idempotent")
	}
}

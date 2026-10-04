package app

import (
	"context"
	"database/sql"
	"errors"
	"sharefolder/internal/auth"
	"sharefolder/internal/db"
	"strings"
	"time"
	"unicode/utf8"
)

func (a *App) session(r *Request) error {
	c, e := r.R.Cookie("rf_session")
	if e != nil {
		return fail(401, "AUTH_REQUIRED")
	}
	r.Token = auth.Digest(c.Value)
	var uid string
	var expiry, last int64
	e = a.DB.Read.QueryRow("SELECT user_id,csrf_token,expires_at,last_seen_at FROM sessions WHERE token_hash=?", r.Token).Scan(&uid, &r.CSRF, &expiry, &last)
	if e != nil || a.now().UnixMilli() >= expiry || a.now().Sub(time.UnixMilli(last)) >= 30*time.Minute {
		return fail(401, "AUTH_REQUIRED")
	}
	r.User, e = getUser(a.DB.Read, uid)
	if e != nil || r.User.Status != "active" {
		return fail(401, "AUTH_REQUIRED")
	}
	if a.now().Sub(time.UnixMilli(last)) >= time.Minute {
		_, e = a.DB.Write.Exec("UPDATE sessions SET last_seen_at=? WHERE token_hash=?", a.now().UnixMilli(), r.Token)
	}
	return e
}
func (a *App) login(r *Request) {
	b, e := readJSON(r.W, r.R)
	if e == nil {
		e = fields(b, "username password", "username password")
	}
	if e != nil {
		problem(r.W, r.ID, e)
		return
	}
	v, e := stringsFields(b, "username", "password")
	if e != nil {
		problem(r.W, r.ID, e)
		return
	}
	username := strings.ToLower(v[0])
	password := v[1]
	nonce, e := r.R.Cookie("rf_login_nonce")
	a.nonceMu.Lock()
	valid := false
	if e == nil {
		expiry, ok := a.nonces[nonce.Value]
		valid = ok && a.now().Before(expiry) && secureEqual(nonce.Value, r.R.Header.Get("X-Login-Nonce"))
		if valid {
			delete(a.nonces, nonce.Value)
		}
	}
	limited := false
	for _, key := range []string{"u:" + username, "i:" + r.IP} {
		entry := a.limits[key]
		if entry != nil && a.now().Before(entry.Until) {
			limit := 10
			if strings.HasPrefix(key, "i:") {
				limit = 100
			}
			if entry.Count >= limit {
				limited = true
			}
		}
	}
	a.nonceMu.Unlock()
	if !valid {
		problem(r.W, r.ID, fail(403, "CSRF_INVALID"))
		return
	}
	if limited {
		problem(r.W, r.ID, fail(429, "RATE_LIMITED"))
		return
	}
	select {
	case a.logins <- struct{}{}:
		defer func() { <-a.logins }()
	default:
		problem(r.W, r.ID, fail(429, "RATE_LIMITED"))
		return
	}
	var u User
	e = a.DB.Read.QueryRow("SELECT "+userCols+" FROM users WHERE username=?", username).Scan(&u.ID, &u.Username, &u.DisplayName, &u.Hash, &u.Role, &u.Status, &u.MustChange, &u.Revision, &u.Created)
	hash := u.Hash
	if e != nil {
		hash = "$argon2id$v=19$m=65536,t=3,p=2$AAAAAAAAAAAAAAAAAAAAAA$AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
	}
	hashContext, cancelHash := context.WithTimeout(r.R.Context(), 30*time.Second)
	correct, hashErr := auth.CheckContext(hashContext, password, hash)
	cancelHash()
	if hashErr != nil {
		problem(r.W, r.ID, fail(429, "RATE_LIMITED"))
		return
	}
	if !correct || e != nil || u.Status != "active" {
		a.nonceMu.Lock()
		for _, key := range []string{"u:" + username, "i:" + r.IP} {
			entry := a.limits[key]
			if entry == nil || !a.now().Before(entry.Until) {
				entry = &rate{Until: a.now().Add(15 * time.Minute)}
				a.limits[key] = entry
			}
			entry.Count++
		}
		a.nonceMu.Unlock()
		if u.ID != "" {
			r.User = u
		}
		if e = a.audit(a.DB.Write, r, "auth.login", "user", u.ID, "denied", false, nil); e != nil {
			problem(r.W, r.ID, e)
		} else {
			problem(r.W, r.ID, fail(401, "LOGIN_FAILED"))
		}
		return
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	tx, e := a.DB.Write.Begin()
	if e != nil {
		problem(r.W, r.ID, e)
		return
	}
	defer tx.Rollback()
	fresh, e := getUser(tx, u.ID)
	if e != nil || fresh.Hash != u.Hash || fresh.Status != "active" {
		problem(r.W, r.ID, fail(401, "LOGIN_FAILED"))
		return
	}
	r.User = fresh
	token, csrf := auth.Token(), auth.Token()
	_, e = tx.Exec("INSERT INTO sessions VALUES(?,?,?,?,?,?,?)", auth.Digest(token), u.ID, csrf, a.now().UnixMilli(), a.now().UnixMilli(), a.now().Add(12*time.Hour).UnixMilli(), false)
	if e == nil {
		e = a.audit(tx, r, "auth.login", "user", u.ID, "success", false, nil)
	}
	if e == nil {
		e = tx.Commit()
	}
	if e != nil {
		problem(r.W, r.ID, e)
		return
	}
	a.nonceMu.Lock()
	delete(a.limits, "u:"+username)
	a.nonceMu.Unlock()
	a.cookie(r.W, "rf_session", token, 43200)
	respond(r.W, 200, M{"user": u.JSON(), "csrf_token": csrf})
}
func (a *App) authRoute(r *Request, path string) (Result, error) {
	if path == "session" && r.R.Method == "GET" {
		var expiry int64
		e := a.DB.Read.QueryRow("SELECT expires_at FROM sessions WHERE token_hash=?", r.Token).Scan(&expiry)
		return Result{200, M{"user": r.User.JSON(), "csrf_token": r.CSRF, "expires_at": stamp(expiry)}}, e
	}
	if path == "session" && r.R.Method == "DELETE" {
		out, e := a.mutate(r, false, func(q Query) error { return nil }, func(tx *sql.Tx) (Result, error) {
			_, e := tx.Exec("DELETE FROM sessions WHERE token_hash=?", r.Token)
			if e == nil {
				e = a.audit(tx, r, "auth.logout", "user", r.User.ID, "success", false, nil)
			}
			return Result{204, nil}, e
		})
		if e == nil {
			a.cookie(r.W, "rf_session", "", -1)
		}
		return out, e
	}
	if path == "session/password" && r.R.Method == "POST" {
		if e := fields(r.Body, "current_password new_password", "current_password new_password"); e != nil {
			return Result{}, e
		}
		v, e := stringsFields(r.Body, "current_password", "new_password")
		if e != nil {
			return Result{}, e
		}
		if !auth.Check(v[0], r.User.Hash) {
			return Result{}, fail(401, "LOGIN_FAILED")
		}
		hash, e := auth.Hash(v[1])
		if e != nil {
			return Result{}, e
		}
		oldHash := r.User.Hash
		out, e := a.mutate(r, false, func(q Query) error {
			if r.User.Hash != oldHash {
				return fail(401, "AUTH_REQUIRED")
			}
			return nil
		}, func(tx *sql.Tx) (Result, error) {
			_, e := tx.Exec("UPDATE users SET password_hash=?,must_change_password=0,revision=revision+1,updated_at=? WHERE id=?", hash, a.now().UnixMilli(), r.User.ID)
			if e == nil {
				_, e = tx.Exec("DELETE FROM sessions WHERE user_id=?", r.User.ID)
			}
			if e == nil {
				e = a.audit(tx, r, "auth.password_change", "user", r.User.ID, "success", false, nil)
			}
			return Result{204, nil}, e
		})
		if e == nil {
			a.cookie(r.W, "rf_session", "", -1)
		}
		return out, e
	}
	return Result{}, fail(404, "NOT_FOUND")
}
func (a *App) createWorkspace(tx *sql.Tx, id, root, kind, title, owner, group, member, creator string) error {
	_, key, e := name(title)
	if e != nil {
		return e
	}
	at := a.now().UnixMilli()
	if _, e = tx.Exec("INSERT INTO workspaces VALUES(?,?,?,?,?,?,?,1,?)", id, kind, title, nullable(owner), nullable(group), nullable(member), root, at); e != nil {
		return e
	}
	if _, e = tx.Exec("INSERT INTO nodes(id,workspace_id,parent_id,kind,name,name_key,revision,state,created_by,created_at,modified_at) VALUES(?,?,NULL,'folder',?,?,1,'ACTIVE',?,?,?)", root, id, title, key, creator, at, at); e != nil {
		return e
	}
	return addClosure(tx, root, "")
}
func (a *App) createUser(tx *sql.Tx, id, ws, root, username, display, role, hash string) error {
	if !usernamePattern.MatchString(username) || utf8.RuneCountInString(display) < 1 || utf8.RuneCountInString(display) > 100 || (role != "admin" && role != "employee") {
		return fail(422, "INVALID_FIELD")
	}
	at := a.now().UnixMilli()
	if _, e := tx.Exec("INSERT INTO users VALUES(?,?,?,?,?,'active',?,1,?,?)", id, username, display, hash, role, false, at, at); e != nil {
		return e
	}
	return a.createWorkspace(tx, ws, root, "personal", "File "+username, id, "", "", id)
}
func (a *App) Bootstrap(username, display, password string) error {
	hash, e := auth.Hash(password)
	if e != nil {
		return e
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	tx, e := a.DB.Write.Begin()
	if e != nil {
		return e
	}
	defer tx.Rollback()
	var count int
	if e = tx.QueryRow("SELECT count(*) FROM users WHERE role='admin'").Scan(&count); e != nil {
		return e
	}
	if count > 0 {
		return errors.New("admin already exists")
	}
	id, office, root := db.ID(), db.ID(), db.ID()
	if e = a.createUser(tx, id, db.ID(), db.ID(), username, display, "admin", hash); e != nil {
		return e
	}
	if e = a.createWorkspace(tx, office, root, "office", "Kantor", "", "", "viewer", id); e != nil {
		return e
	}
	if _, e = tx.Exec("INSERT INTO grants VALUES(?,'user',?,'editor',?,?)", root, id, a.now().UnixMilli(), id); e != nil {
		return e
	}
	if e = a.audit(tx, &Request{User: User{ID: id}, ID: db.ID()}, "user.create", "user", id, "success", false, nil); e != nil {
		return e
	}
	return tx.Commit()
}
func fixtureID(n string) string {
	return "00000000-0000-4000-8000-" + strings.Repeat("0", 12-len(n)) + n
}
func (a *App) Seed() error {
	if a.Config.Env == "production" {
		return errors.New("fixture prohibited in production")
	}
	tx, e := a.DB.Write.Begin()
	if e != nil {
		return e
	}
	defer tx.Rollback()
	var count int
	if e = tx.QueryRow("SELECT count(*) FROM users").Scan(&count); e != nil {
		return e
	}
	if count > 0 {
		var marker string
		if e = tx.QueryRow("SELECT value FROM app_meta WHERE key='fixture'").Scan(&marker); e != nil || marker != "office-demo" {
			return errors.New("foreign instance: seed refused")
		}
		return nil
	}
	adminHash, e := auth.Hash("LocalOnly-Admin!2026")
	if e != nil {
		return e
	}
	staffHash, e := auth.Hash("LocalOnly-Staff!2026")
	if e != nil {
		return e
	}
	for _, v := range [][6]string{{"1", "106", "206", "admin", "Administrator", "admin"}, {"2", "101", "201", "pegawai-a", "Pegawai A", "employee"}, {"3", "102", "202", "pegawai-b", "Pegawai B", "employee"}, {"4", "103", "203", "pegawai-c", "Pegawai C", "employee"}} {
		hash := staffHash
		if v[5] == "admin" {
			hash = adminHash
		}
		if e = a.createUser(tx, fixtureID(v[0]), fixtureID(v[1]), fixtureID(v[2]), v[3], v[4], v[5], hash); e != nil {
			return e
		}
	}
	at := a.now().UnixMilli()
	for _, v := range [][3]string{{"51", "Keuangan", "keuangan"}, {"52", "Umum", "umum"}} {
		if _, e = tx.Exec("INSERT INTO groups VALUES(?,?,?,1,?)", fixtureID(v[0]), v[1], v[2], at); e != nil {
			return e
		}
	}
	for _, v := range [][2]string{{"51", "2"}, {"51", "3"}, {"52", "4"}} {
		if _, e = tx.Exec("INSERT INTO group_members VALUES(?,?,?)", fixtureID(v[0]), fixtureID(v[1]), at); e != nil {
			return e
		}
	}
	if e = a.createWorkspace(tx, fixtureID("104"), fixtureID("204"), "office", "Kantor", "", "", "viewer", fixtureID("1")); e != nil {
		return e
	}
	if e = a.createWorkspace(tx, fixtureID("105"), fixtureID("205"), "team", "Keuangan", "", fixtureID("51"), "editor", fixtureID("1")); e != nil {
		return e
	}
	for _, root := range []string{"204", "205"} {
		if _, e = tx.Exec("INSERT INTO grants VALUES(?,'user',?,'editor',?,?)", fixtureID(root), fixtureID("1"), at, fixtureID("1")); e != nil {
			return e
		}
	}
	if _, e = tx.Exec("INSERT INTO app_meta VALUES('fixture','office-demo')"); e != nil {
		return e
	}
	return tx.Commit()
}

package app

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"sharefolder/internal/config"
	"sharefolder/internal/db"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

type App struct {
	Config                  config.Config
	DB                      *db.DB
	now                     func() time.Time
	mu                      sync.Mutex
	nonceMu                 sync.Mutex
	nonces                  map[string]time.Time
	limits                  map[string]*rate
	uploadLocks             sync.Map
	inflight                sync.Map
	chunks, streams, logins chan struct{}
	ready                   atomic.Bool
	queued                  atomic.Int64
	stop                    chan struct{}
	wg                      sync.WaitGroup
	Fault                   func(string) error
	Log                     io.Writer
	logMu                   sync.Mutex
}
type rate struct {
	Count int
	Until time.Time
}
type Request struct {
	W                   http.ResponseWriter
	R                   *http.Request
	User                User
	ID, IP, Token, CSRF string
	Body                M
}
type Result struct {
	Status int
	Body   any
}

func New(c config.Config, d *db.DB) *App {
	return &App{Config: c, DB: d, now: time.Now, nonces: map[string]time.Time{}, limits: map[string]*rate{}, chunks: make(chan struct{}, 4), streams: make(chan struct{}, 16), logins: make(chan struct{}, 52), stop: make(chan struct{})}
}
func (a *App) audit(q Query, r *Request, action, targetType, target, outcome string, override bool, bytesValue any) error {
	_, e := q.Exec("INSERT INTO audit_events(actor_id,action,target_type,target_id,at,request_id,outcome,admin_override,ip,detail_json) VALUES(?,?,?,?,?,?,?,?,?,?)", nullable(r.User.ID), action, targetType, nullable(target), a.now().UnixMilli(), r.ID, outcome, override, r.IP, string(marshal(M{"code": nil, "bytes": bytesValue})))
	if e != nil {
		return fail(503, "AUDIT_UNAVAILABLE")
	}
	return nil
}
func marshal(v any) []byte {
	b, e := json.Marshal(v)
	if e != nil {
		panic(e)
	}
	return b
}
func respond(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	if m, ok := v.(M); ok {
		if rev, ok := m["revision"].(int64); ok {
			w.Header().Set("ETag", fmt.Sprintf(`"r%d"`, rev))
		}
	}
	w.WriteHeader(status)
	if v != nil && status != 204 {
		w.Write(marshal(v))
	}
}
func problem(w http.ResponseWriter, id string, e error) {
	e = dbProblem(e)
	var p *Problem
	if !errors.As(e, &p) {
		p = &Problem{503, "STORAGE_UNAVAILABLE", ""}
	}
	if p.Status == 429 {
		w.Header().Set("Retry-After", "2")
	}
	if p.Code == "REQUEST_IN_PROGRESS" {
		w.Header().Set("Retry-After", "1")
	}
	respond(w, p.Status, M{"error": M{"code": p.Code, "message": message(p.Code), "field": nullable(p.Field), "request_id": id}})
}
func message(code string) string {
	messages := map[string]string{"LOGIN_FAILED": "Nama pengguna atau kata sandi salah.", "AUTH_REQUIRED": "Silakan masuk kembali.", "FORBIDDEN": "Anda tidak memiliki izin untuk tindakan ini.", "NOT_FOUND": "Item tidak tersedia.", "NAME_CONFLICT": "Nama sudah digunakan.", "REVISION_MISMATCH": "Item telah berubah. Muat ulang sebelum mencoba lagi.", "INSUFFICIENT_STORAGE": "Ruang penyimpanan tidak mencukupi.", "INVALID_NAME": "Nama tidak valid.", "CSRF_INVALID": "Permintaan tidak valid. Muat ulang halaman.", "LAST_ADMIN": "Minimal satu administrator aktif harus tersedia.", "AUDIT_UNAVAILABLE": "Pencatatan aktivitas tidak tersedia. Coba lagi nanti."}
	if s := messages[code]; s != "" {
		return s
	}
	return "Permintaan tidak dapat diproses (" + code + ")."
}
func (a *App) ServeHTTP(w http.ResponseWriter, h *http.Request) {
	r := &Request{W: w, R: h, ID: db.ID()}
	if a.Log != nil {
		logged := &responseLog{ResponseWriter: w}
		w = logged
		r.W = w
		defer a.logRequest(logged, r.ID, time.Now())
	}
	r.IP, _, _ = net.SplitHostPort(h.RemoteAddr)
	w.Header().Set("X-Request-ID", r.ID)
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Referrer-Policy", "no-referrer")
	w.Header().Set("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
	w.Header().Set("Content-Security-Policy", "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' blob:; font-src 'self' blob:; worker-src 'self'; connect-src 'self'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'")
	if a.Config.Env == "production" {
		w.Header().Set("Strict-Transport-Security", "max-age=31536000")
	}
	expectedOrigin := a.Config.OriginForHost(h.Host)
	if expectedOrigin == "" {
		problem(w, r.ID, fail(400, "MALFORMED_REQUEST"))
		return
	}
	if h.URL.Path == "/health/live" && (h.Method == "GET" || h.Method == "HEAD") {
		respond(w, 200, M{"status": "ok"})
		return
	}
	if h.URL.Path == "/health/ready" && (h.Method == "GET" || h.Method == "HEAD") {
		if a.ready.Load() && a.health() == nil {
			respond(w, 200, M{"status": "ready"})
		} else {
			respond(w, 503, M{"status": "not_ready"})
		}
		return
	}
	if !strings.HasPrefix(h.URL.Path, "/api/v1/") {
		a.web(r)
		return
	}
	if h.Method != "GET" && h.Method != "HEAD" && h.Header.Get("Origin") != expectedOrigin {
		problem(w, r.ID, fail(403, "CSRF_INVALID"))
		return
	}
	if h.URL.Path == "/api/v1/session" && h.Method == "POST" {
		a.login(r)
		return
	}
	e := a.session(r)
	if e != nil {
		if h.URL.Path == "/api/v1/session" && h.Method == "DELETE" {
			a.cookie(w, "rf_session", "", -1)
			w.WriteHeader(204)
			return
		}
		problem(w, r.ID, e)
		return
	}
	if h.Method != "GET" && h.Method != "HEAD" && !secureEqual(h.Header.Get("X-CSRF-Token"), r.CSRF) {
		problem(w, r.ID, fail(403, "CSRF_INVALID"))
		return
	}
	if h.Method != "GET" && h.Method != "HEAD" && !(h.Method == "PATCH" && strings.HasPrefix(h.URL.Path, "/api/v1/uploads/")) && h.Method != "DELETE" {
		r.Body, e = readJSON(w, h)
		if e != nil {
			problem(w, r.ID, e)
			return
		}
	}
	result, e := a.route(r)
	if e != nil {
		if action, targetType, target := deniedAction(r); action != "" {
			a.mu.Lock()
			ae := a.audit(a.DB.Write, r, action, targetType, target, "denied", false, nil)
			a.mu.Unlock()
			if ae != nil {
				e = ae
			}
		}
		problem(w, r.ID, e)
		return
	}
	if result.Status != 0 {
		respond(w, result.Status, result.Body)
	}
}
func readJSON(w http.ResponseWriter, r *http.Request) (M, error) {
	if strings.Split(r.Header.Get("Content-Type"), ";")[0] != "application/json" {
		return nil, fail(415, "UNSUPPORTED_MEDIA")
	}
	raw, e := io.ReadAll(http.MaxBytesReader(w, r.Body, 65536))
	if e != nil {
		return nil, fail(413, "JSON_TOO_LARGE")
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.UseNumber()
	if e = uniqueJSON(d); e != nil {
		return nil, e
	}
	if _, e = d.Token(); e != io.EOF {
		return nil, fail(400, "MALFORMED_REQUEST")
	}
	var body M
	d = json.NewDecoder(bytes.NewReader(raw))
	d.UseNumber()
	if e = d.Decode(&body); e != nil || body == nil {
		return nil, fail(400, "MALFORMED_REQUEST")
	}
	return body, nil
}
func uniqueJSON(d *json.Decoder) error {
	t, e := d.Token()
	if e != nil {
		return fail(400, "MALFORMED_REQUEST")
	}
	if delim, ok := t.(json.Delim); ok {
		switch delim {
		case '{':
			seen := map[string]bool{}
			for d.More() {
				k, e := d.Token()
				if e != nil {
					return fail(400, "MALFORMED_REQUEST")
				}
				s, ok := k.(string)
				if !ok {
					return fail(400, "MALFORMED_REQUEST")
				}
				if seen[s] {
					return fail(422, "INVALID_FIELD")
				}
				seen[s] = true
				if e = uniqueJSON(d); e != nil {
					return e
				}
			}
		case '[':
			for d.More() {
				if e = uniqueJSON(d); e != nil {
					return e
				}
			}
		default:
			return fail(400, "MALFORMED_REQUEST")
		}
		if _, e = d.Token(); e != nil {
			return fail(400, "MALFORMED_REQUEST")
		}
	}
	return nil
}
func fields(b M, allowed, required string) error {
	set := map[string]bool{}
	for _, s := range strings.Fields(allowed) {
		set[s] = true
	}
	for k, v := range b {
		if !set[k] {
			return &Problem{422, "UNKNOWN_FIELD", k}
		}
		if v == nil {
			return &Problem{422, "INVALID_FIELD", k}
		}
	}
	for _, k := range strings.Fields(required) {
		if _, ok := b[k]; !ok {
			return &Problem{422, "INVALID_FIELD", k}
		}
	}
	return nil
}
func textField(b M, k string) (string, error) {
	v, ok := b[k].(string)
	if !ok {
		return "", &Problem{422, "INVALID_FIELD", k}
	}
	return v, nil
}
func stringsFields(b M, keys ...string) ([]string, error) {
	out := []string{}
	for _, k := range keys {
		s, e := textField(b, k)
		if e != nil {
			return nil, e
		}
		out = append(out, s)
	}
	return out, nil
}
func (a *App) mutate(r *Request, keyRequired bool, check func(Query) error, fn func(*sql.Tx) (Result, error)) (out Result, err error) {
	if keyRequired {
		key := r.R.Header.Get("Idempotency-Key")
		if e := validID(key); e != nil {
			return out, e
		}
		scope := r.User.ID + " " + r.R.Method + " " + r.R.URL.Path + " " + key
		if _, busy := a.inflight.LoadOrStore(scope, true); busy {
			return out, fail(409, "REQUEST_IN_PROGRESS")
		}
		defer a.inflight.Delete(scope)
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	tx, e := a.DB.Write.BeginTx(r.R.Context(), nil)
	if e != nil {
		return out, e
	}
	defer tx.Rollback()
	fresh, e := getUser(tx, r.User.ID)
	if e != nil || fresh.Status != "active" {
		return out, fail(401, "AUTH_REQUIRED")
	}
	r.User = fresh
	var sessionCount int
	if e = tx.QueryRow("SELECT count(*) FROM sessions WHERE token_hash=? AND user_id=? AND expires_at>? AND last_seen_at>?", r.Token, r.User.ID, a.now().UnixMilli(), a.now().Add(-30*time.Minute).UnixMilli()).Scan(&sessionCount); e != nil {
		return out, e
	}
	if sessionCount != 1 {
		return out, fail(401, "AUTH_REQUIRED")
	}
	if e = check(tx); e != nil {
		return out, e
	}
	key := r.R.Header.Get("Idempotency-Key")
	digest := ""
	if keyRequired {
		if e = validID(key); e != nil {
			return out, fail(422, "INVALID_FIELD")
		}
		h := hmac.New(sha256.New, a.DB.Key)
		h.Write(marshal(r.Body))
		digest = hex.EncodeToString(h.Sum(nil))
		var oldHash, body string
		var status int
		e = tx.QueryRow("SELECT request_hash,response_status,response_json FROM idempotency WHERE actor_id=? AND method=? AND path=? AND key=? AND expires_at>?", r.User.ID, r.R.Method, r.R.URL.Path, key, a.now().UnixMilli()).Scan(&oldHash, &status, &body)
		if e == nil {
			if oldHash != digest {
				return out, fail(409, "IDEMPOTENCY_CONFLICT")
			}
			return Result{status, json.RawMessage(body)}, nil
		}
		if !errors.Is(e, sql.ErrNoRows) {
			return out, e
		}
	}
	out, e = fn(tx)
	if e != nil {
		return out, e
	}
	if keyRequired {
		_, e = tx.Exec("INSERT INTO idempotency VALUES(?,?,?,?,?,'DONE',?,?,?,?) ON CONFLICT(actor_id,method,path,key) DO UPDATE SET request_hash=excluded.request_hash,state='DONE',response_status=excluded.response_status,response_json=excluded.response_json,created_at=excluded.created_at,expires_at=excluded.expires_at", r.User.ID, r.R.Method, r.R.URL.Path, key, digest, out.Status, string(marshal(out.Body)), a.now().UnixMilli(), a.now().Add(24*time.Hour).UnixMilli())
		if e != nil {
			return out, e
		}
	}
	e = tx.Commit()
	return out, e
}
func secureEqual(a, b string) bool { return a != "" && hmac.Equal([]byte(a), []byte(b)) }
func (a *App) cookie(w http.ResponseWriter, name, value string, maxAge int) {
	http.SetCookie(w, &http.Cookie{Name: name, Value: value, Path: "/", HttpOnly: true, Secure: a.Config.Env == "production", SameSite: http.SameSiteLaxMode, MaxAge: maxAge})
}
func (a *App) Close() { a.ready.Store(false); close(a.stop); a.wg.Wait() }
func permit(ctx context.Context, ch chan struct{}) error {
	timer := time.NewTimer(2 * time.Second)
	defer timer.Stop()
	select {
	case ch <- struct{}{}:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return fail(429, "TRANSFER_BUSY")
	}
}

func (a *App) acquireTransfer(ctx context.Context, ch chan struct{}) error {
	a.queued.Add(1)
	defer a.queued.Add(-1)
	return permit(ctx, ch)
}

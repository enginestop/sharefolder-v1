package app

import (
	"bytes"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"regexp"
	"sharefolder/internal/config"
	"sharefolder/internal/db"
	"strings"
	"testing"
	"time"
)

type client struct {
	app          *App
	t            *testing.T
	cookie, csrf string
}

func testApp(t *testing.T) *App {
	t.Helper()
	root := t.TempDir()
	c := config.Config{Env: "test", Listen: "127.0.0.1:18080", Origin: "http://127.0.0.1:18080", Metadata: filepath.Join(root, "state"), Data: filepath.Join(root, "data")}
	d, e := db.Open(c, true)
	if e != nil {
		t.Fatal(e)
	}
	if e = d.Migrate(); e != nil {
		t.Fatal(e)
	}
	a := New(c, d)
	if e = a.Seed(); e != nil {
		t.Fatal(e)
	}
	t.Cleanup(d.Close)
	return a
}
func (c *client) request(method, path string, body any, headers map[string]string) *httptest.ResponseRecorder {
	c.t.Helper()
	var raw []byte
	switch v := body.(type) {
	case []byte:
		raw = v
	case nil:
	default:
		raw = marshal(body)
	}
	r := httptest.NewRequest(method, c.app.Config.Origin+path, bytes.NewReader(raw))
	r.RemoteAddr = "127.0.0.1:1234"
	r.Header.Set("Origin", c.app.Config.Origin)
	r.Header.Set("Content-Type", "application/json")
	if c.cookie != "" {
		r.Header.Set("Cookie", c.cookie)
	}
	if c.csrf != "" {
		r.Header.Set("X-CSRF-Token", c.csrf)
	}
	for k, v := range headers {
		r.Header.Set(k, v)
	}
	w := httptest.NewRecorder()
	c.app.ServeHTTP(w, r)
	return w
}
func parse(t *testing.T, w *httptest.ResponseRecorder, status int) M {
	t.Helper()
	if w.Code != status {
		t.Fatalf("status=%d expected=%d body=%s", w.Code, status, w.Body.String())
	}
	var v M
	if w.Body.Len() > 0 {
		if e := json.Unmarshal(w.Body.Bytes(), &v); e != nil {
			t.Fatal(e)
		}
	}
	return v
}
func loginClient(t *testing.T, a *App, username string) *client {
	t.Helper()
	c := &client{app: a, t: t}
	w := c.request("GET", "/login", nil, nil)
	nonce := regexp.MustCompile(`name="login-nonce" content="([^"]+)"`).FindStringSubmatch(w.Body.String())[1]
	c.cookie = "rf_login_nonce=" + nonce
	password := "LocalOnly-Staff!2026"
	if username == "admin" {
		password = "LocalOnly-Admin!2026"
	}
	w = c.request("POST", "/api/v1/session", M{"username": username, "password": password}, map[string]string{"X-Login-Nonce": nonce})
	v := parse(t, w, 200)
	c.csrf = v["csrf_token"].(string)
	for _, cookie := range w.Result().Cookies() {
		if cookie.Name == "rf_session" {
			c.cookie = cookie.Name + "=" + cookie.Value
		}
	}
	return c
}
func rev(v M) string { return fmt.Sprintf(`"r%.0f"`, v["revision"].(float64)) }
func createFolderTest(t *testing.T, c *client, parent, workspace, title string) M {
	t.Helper()
	return parse(t, c.request("POST", "/api/v1/folders", M{"parent_id": parent, "workspace_id": workspace, "name": title}, map[string]string{"Idempotency-Key": db.ID()}), 201)
}
func uploadTest(t *testing.T, c *client, parent, workspace, title string, data []byte) M {
	t.Helper()
	u := parse(t, c.request("POST", "/api/v1/uploads", M{"parent_id": parent, "workspace_id": workspace, "name": title, "size_bytes": str(int64(len(data))), "last_modified_ms": 0}, map[string]string{"Idempotency-Key": db.ID()}), 201)
	id := u["id"].(string)
	for offset := 0; offset < len(data); {
		end := min(offset+int(chunkSize), len(data))
		chunk := data[offset:end]
		hash := sha256.Sum256(chunk)
		parse(t, c.request("PATCH", "/api/v1/uploads/"+id, chunk, map[string]string{"Content-Type": "application/offset+octet-stream", "Upload-Offset": fmt.Sprint(offset), "Upload-Checksum": "sha256 " + hex.EncodeToString(hash[:])}), 200)
		offset = end
	}
	status := parse(t, c.request("GET", "/api/v1/uploads/"+id, nil, nil), 200)
	u = status["upload"].(map[string]any)
	parse(t, c.request("POST", "/api/v1/uploads/"+id+"/complete", M{"manifest_sha256": u["manifest_sha256"]}, map[string]string{"Idempotency-Key": db.ID()}), 202)
	if e := c.app.RunJobs(); e != nil {
		t.Fatal(e)
	}
	status = parse(t, c.request("GET", "/api/v1/uploads/"+id, nil, nil), 200)
	u = status["upload"].(map[string]any)
	if u["state"] != "COMPLETE" {
		t.Fatalf("upload not complete: %v", u)
	}
	return parse(t, c.request("GET", "/api/v1/nodes/"+u["node_id"].(string), nil, nil), 200)
}
func TestJourneySecurityAndDurability(t *testing.T) {
	a := testApp(t)
	admin := loginClient(t, a, "admin")
	A := loginClient(t, a, "pegawai-a")
	B := loginClient(t, a, "pegawai-b")
	C := loginClient(t, a, "pegawai-c")
	root, ws := fixtureID("201"), fixtureID("101")
	t.Run("migrations_lock_fixture", func(t *testing.T) {
		if e := a.DB.Migrate(); e != nil {
			t.Fatal(e)
		}
		if e := a.Seed(); e != nil {
			t.Fatal(e)
		}
		if e := a.DB.Verify(); e != nil {
			t.Fatal(e)
		}
		if second, e := db.Open(a.Config, false); e == nil {
			second.Close()
			t.Fatal("second writer accepted")
		}
		_, e := a.DB.Write.Exec("UPDATE schema_migrations SET sha256='bad'")
		if e != nil {
			t.Fatal(e)
		}
		if e = a.DB.CheckSchema(); e == nil {
			t.Fatal("schema drift accepted")
		}
		_, e = a.DB.Write.Exec("UPDATE schema_migrations SET sha256=?", schemaHash(t, a))
		if e != nil {
			t.Fatal(e)
		}
	})
	t.Run("csrf_json_names_idempotency", func(t *testing.T) {
		body := M{"parent_id": root, "workspace_id": ws, "name": "Documents"}
		key := db.ID()
		headers := map[string]string{"Idempotency-Key": key}
		v := parse(t, A.request("POST", "/api/v1/folders", body, headers), 201)
		replay := parse(t, A.request("POST", "/api/v1/folders", body, headers), 201)
		if v["id"] != replay["id"] {
			t.Fatal("duplicate replay")
		}
		body["name"] = "Different"
		parse(t, A.request("POST", "/api/v1/folders", body, headers), 409)
		headers["X-CSRF-Token"] = "wrong"
		parse(t, A.request("POST", "/api/v1/folders", body, headers), 403)
		for _, name := range []string{"../bad", "CON.txt", "NUL", "ends.", "ends ", "bad<name", "bad\\name"} {
			body["name"] = name
			parse(t, A.request("POST", "/api/v1/folders", body, map[string]string{"Idempotency-Key": db.ID()}), 422)
		}
		parse(t, A.request("POST", "/api/v1/folders", []byte(`{"name":"x","name":"y"}`), nil), 422)
		parse(t, A.request("POST", "/api/v1/folders", M{"other": 1}, nil), 422)
	})
	file := uploadTest(t, A, root, ws, "agenda.txt", []byte("rapat\n"))
	id := file["id"].(string)
	t.Run("sharing_admin_read_ranges_revocation", func(t *testing.T) {
		parse(t, B.request("GET", "/api/v1/nodes/"+id, nil, nil), 404)
		file = parse(t, A.request("PUT", "/api/v1/nodes/"+id+"/grants/user/"+fixtureID("3"), M{"permission": "viewer"}, map[string]string{"If-Match": rev(file)}), 200)
		bv := parse(t, B.request("GET", "/api/v1/nodes/"+id, nil, nil), 200)
		if len(bv["ancestors"].([]any)) != 0 {
			t.Fatal("private ancestor leaked")
		}
		parse(t, B.request("PATCH", "/api/v1/nodes/"+id, M{"name": "changed"}, map[string]string{"If-Match": rev(file)}), 403)
		parse(t, C.request("GET", "/api/v1/nodes/"+id+"/content", nil, map[string]string{"Range": "bytes=0-1"}), 404)
		w := B.request("GET", "/api/v1/nodes/"+id+"/content", nil, map[string]string{"Range": "bytes=0-1"})
		if w.Code != 206 || w.Body.String() != "ra" {
			t.Fatalf("range: %d %s", w.Code, w.Body.String())
		}
		if w = B.request("GET", "/api/v1/nodes/"+id+"/content", nil, map[string]string{"Range": "bytes=99-100"}); w.Code != 416 {
			t.Fatal("EOF range accepted")
		}
		parse(t, B.request("GET", "/api/v1/nodes/"+id+"/content", nil, map[string]string{"Range": "bytes=0-1,3-4"}), 416)
		av := parse(t, admin.request("GET", "/api/v1/nodes/"+id, nil, nil), 200)
		if av["admin_read_override"] != true || av["can_write"] != false {
			t.Fatal("admin read override incorrect")
		}
		parse(t, admin.request("PATCH", "/api/v1/nodes/"+id, M{"name": "admin overwrite"}, map[string]string{"If-Match": rev(file)}), 403)
		parse(t, A.request("DELETE", "/api/v1/nodes/"+id+"/grants/user/"+fixtureID("3"), nil, map[string]string{"If-Match": rev(file)}), 204)
		parse(t, B.request("GET", "/api/v1/nodes/"+id+"/content", nil, nil), 404)
	})
	t.Run("tree_etag_cycles_trash_restore", func(t *testing.T) {
		folder := createFolderTest(t, A, root, ws, "Folder")
		child := createFolderTest(t, A, folder["id"].(string), ws, "Child")
		parse(t, A.request("PATCH", "/api/v1/nodes/"+folder["id"].(string), M{"parent_id": child["id"]}, map[string]string{"If-Match": rev(folder)}), 409)
		old := rev(folder)
		folder = parse(t, A.request("PATCH", "/api/v1/nodes/"+folder["id"].(string), M{"name": "Renamed"}, map[string]string{"If-Match": old}), 200)
		parse(t, A.request("PATCH", "/api/v1/nodes/"+folder["id"].(string), M{"name": "Stale"}, map[string]string{"If-Match": old}), 412)
		parse(t, A.request("PATCH", "/api/v1/nodes/"+folder["id"].(string), M{"name": "No header"}, nil), 428)
		folder = parse(t, A.request("POST", "/api/v1/nodes/"+folder["id"].(string)+"/trash", M{}, map[string]string{"If-Match": rev(folder), "Idempotency-Key": db.ID()}), 200)
		parse(t, A.request("GET", "/api/v1/nodes/"+child["id"].(string), nil, nil), 404)
		folder = parse(t, A.request("POST", "/api/v1/nodes/"+folder["id"].(string)+"/restore", M{}, map[string]string{"If-Match": rev(folder), "Idempotency-Key": db.ID()}), 200)
		parse(t, A.request("GET", "/api/v1/nodes/"+child["id"].(string), nil, nil), 200)
	})
	t.Run("audit_fail_closed", func(t *testing.T) {
		_, e := a.DB.Write.Exec("CREATE TRIGGER fail_audit BEFORE INSERT ON audit_events BEGIN SELECT RAISE(ABORT,'test audit unavailable'); END")
		if e != nil {
			t.Fatal(e)
		}
		parse(t, A.request("GET", "/api/v1/nodes/"+id+"/content", nil, nil), 503)
		parse(t, A.request("POST", "/api/v1/folders", M{"workspace_id": ws, "parent_id": root, "name": "must rollback"}, map[string]string{"Idempotency-Key": db.ID()}), 503)
		_, e = a.DB.Write.Exec("DROP TRIGGER fail_audit")
		if e != nil {
			t.Fatal(e)
		}
		var count int
		a.DB.Read.QueryRow("SELECT count(*) FROM nodes WHERE name='must rollback'").Scan(&count)
		if count != 0 {
			t.Fatal("mutation survived failed audit")
		}
	})
	t.Run("last_admin_reset_revocation", func(t *testing.T) {
		users := parse(t, admin.request("GET", "/api/v1/admin/users", nil, nil), 200)
		var self M
		for _, v := range users["items"].([]any) {
			u := v.(map[string]any)
			if u["username"] == "admin" {
				self = u
			}
		}
		parse(t, admin.request("PATCH", "/api/v1/admin/users/"+fixtureID("1"), M{"status": "disabled"}, map[string]string{"If-Match": rev(self)}), 409)
		parse(t, A.request("GET", "/api/v1/admin/users", nil, nil), 403)
		parse(t, admin.request("POST", "/api/v1/admin/users/"+fixtureID("4")+"/reset-password", M{"temporary_password": "Replacement!2026"}, map[string]string{"Idempotency-Key": db.ID()}), 204)
		parse(t, C.request("GET", "/api/v1/session", nil, nil), 401)
	})
	if e := a.DB.Verify(); e != nil {
		t.Fatal(e)
	}
	if e := a.VerifyStorage(); e != nil {
		t.Fatal(e)
	}
}
func schemaHash(t *testing.T, a *App) string {
	t.Helper()
	b, e := os.ReadFile(filepath.Join("..", "db", "migrations", "001_initial.sql"))
	if e != nil {
		t.Fatal(e)
	}
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:])
}
func TestUploadRecoveryAndExpiry(t *testing.T) {
	a := testApp(t)
	c := loginClient(t, a, "pegawai-a")
	root, ws := fixtureID("201"), fixtureID("101")
	u := parse(t, c.request("POST", "/api/v1/uploads", M{"workspace_id": ws, "parent_id": root, "name": "recover.bin", "size_bytes": "6", "last_modified_ms": 0}, map[string]string{"Idempotency-Key": db.ID()}), 201)
	id := u["id"].(string)
	data := []byte("abcdef")
	h := sha256.Sum256(data)
	headers := map[string]string{"Content-Type": "application/offset+octet-stream", "Upload-Offset": "0", "Upload-Checksum": strings.Repeat("0", 64)}
	parse(t, c.request("PATCH", "/api/v1/uploads/"+id, data, headers), 422)
	status := parse(t, c.request("GET", "/api/v1/uploads/"+id, nil, nil), 200)
	if status["upload"].(map[string]any)["offset_bytes"] != "0" {
		t.Fatal("corrupt chunk acknowledged")
	}
	headers["Upload-Checksum"] = hex.EncodeToString(h[:])
	a.Fault = func(point string) error {
		if point == "chunk_synced" {
			return fmt.Errorf("crash boundary")
		}
		return nil
	}
	parse(t, c.request("PATCH", "/api/v1/uploads/"+id, data, headers), 503)
	a.Fault = nil
	if e := a.Reconcile(); e != nil {
		t.Fatal(e)
	}
	path, _ := a.filePath("staging", id)
	info, _ := os.Stat(path)
	if info.Size() != 0 {
		t.Fatal("unacknowledged bytes not truncated")
	}
	parse(t, c.request("PATCH", "/api/v1/uploads/"+id, data, headers), 200)
	status = parse(t, c.request("GET", "/api/v1/uploads/"+id+"?include_chunks=true", nil, nil), 200)
	manifest := status["upload"].(map[string]any)["manifest_sha256"]
	parse(t, c.request("POST", "/api/v1/uploads/"+id+"/complete", M{"manifest_sha256": manifest}, map[string]string{"Idempotency-Key": db.ID()}), 202)
	a.Fault = func(point string) error {
		if point == "commit_renamed" {
			return fmt.Errorf("crash after rename")
		}
		return nil
	}
	a.RunJobs()
	var active int
	a.DB.Read.QueryRow("SELECT count(*) FROM nodes WHERE name='recover.bin'").Scan(&active)
	if active != 0 {
		t.Fatal("partial commit visible")
	}
	a.Fault = nil
	a.DB.Write.Exec("UPDATE fs_intents SET state='RUNNING'")
	if e := a.Reconcile(); e != nil {
		t.Fatal(e)
	}
	status = parse(t, c.request("GET", "/api/v1/uploads/"+id, nil, nil), 200)
	completed := status["upload"].(map[string]any)
	if completed["state"] != "COMPLETE" {
		t.Fatalf("not recovered: %v", completed)
	}
	n := parse(t, c.request("GET", "/api/v1/nodes/"+completed["node_id"].(string), nil, nil), 200)
	n = parse(t, c.request("POST", "/api/v1/nodes/"+n["id"].(string)+"/trash", M{}, map[string]string{"If-Match": rev(n), "Idempotency-Key": db.ID()}), 200)
	a.DB.Write.Exec("UPDATE nodes SET deleted_at=? WHERE id=?", time.Now().Add(-30*24*time.Hour).UnixMilli(), n["id"])
	parse(t, c.request("POST", "/api/v1/nodes/"+n["id"].(string)+"/restore", M{}, map[string]string{"If-Match": rev(n), "Idempotency-Key": db.ID()}), 410)
	if e := a.Maintain(); e != nil {
		t.Fatal(e)
	}
	if e := a.RunJobs(); e != nil {
		t.Fatal(e)
	}
	parse(t, c.request("GET", "/api/v1/nodes/"+n["id"].(string), nil, nil), 404)
	uploadTest(t, c, root, ws, "empty.txt", nil)
	parse(t, c.request("POST", "/api/v1/uploads", M{"workspace_id": ws, "parent_id": root, "name": "huge", "size_bytes": "9223372036854775807", "last_modified_ms": 0}, map[string]string{"Idempotency-Key": db.ID()}), 507)
	parse(t, c.request("POST", "/api/v1/uploads", M{"workspace_id": ws, "parent_id": root, "name": "overflow", "size_bytes": "9223372036854775808", "last_modified_ms": 0}, map[string]string{"Idempotency-Key": db.ID()}), 422)
}

var _ = http.MethodGet
var _ = sql.ErrNoRows

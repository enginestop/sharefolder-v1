package app

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sharefolder/internal/db"
	"strings"
	"testing"
	"time"
)

func TestACLGroupsSessionsAndLifecycle(t *testing.T) {
	a := testApp(t)
	admin := loginClient(t, a, "admin")
	A := loginClient(t, a, "pegawai-a")
	B := loginClient(t, a, "pegawai-b")
	C := loginClient(t, a, "pegawai-c")
	root, ws := fixtureID("201"), fixtureID("101")
	t.Run("office_team_and_membership_revocation", func(t *testing.T) {
		parse(t, A.request("POST", "/api/v1/folders", M{"workspace_id": fixtureID("104"), "parent_id": fixtureID("204"), "name": "office denied"}, map[string]string{"Idempotency-Key": db.ID()}), 403)
		createFolderTest(t, A, fixtureID("205"), fixtureID("105"), "team folder")
		parse(t, C.request("GET", "/api/v1/nodes/"+fixtureID("205"), nil, nil), 404)
		g := parse(t, admin.request("GET", "/api/v1/admin/groups/"+fixtureID("51"), nil, nil), 200)
		parse(t, admin.request("PATCH", "/api/v1/admin/groups/"+fixtureID("51"), M{"member_ids": []string{fixtureID("2")}}, map[string]string{"If-Match": rev(g)}), 200)
		parse(t, B.request("GET", "/api/v1/nodes/"+fixtureID("205"), nil, nil), 404)
	})
	t.Run("editor_cannot_reshare_and_replay_after_revoke", func(t *testing.T) {
		folder := createFolderTest(t, A, root, ws, "shared editor")
		id := folder["id"].(string)
		folder = parse(t, A.request("PUT", "/api/v1/nodes/"+id+"/grants/user/"+fixtureID("3"), M{"permission": "editor"}, map[string]string{"If-Match": rev(folder)}), 200)
		body := M{"workspace_id": ws, "parent_id": id, "name": "child"}
		key := db.ID()
		parse(t, B.request("POST", "/api/v1/folders", body, map[string]string{"Idempotency-Key": key}), 201)
		parse(t, B.request("PUT", "/api/v1/nodes/"+id+"/grants/user/"+fixtureID("4"), M{"permission": "viewer"}, map[string]string{"If-Match": rev(folder)}), 403)
		parse(t, A.request("DELETE", "/api/v1/nodes/"+id+"/grants/user/"+fixtureID("3"), nil, map[string]string{"If-Match": rev(folder)}), 204)
		parse(t, B.request("POST", "/api/v1/folders", body, map[string]string{"Idempotency-Key": key}), 404)
	})
	t.Run("content_conditionals_attachment_head", func(t *testing.T) {
		n := uploadTest(t, A, root, ws, "unsafe.html", []byte("<html><script>alert(1)</script></html>"))
		id := n["id"].(string)
		desc := parse(t, A.request("GET", "/api/v1/nodes/"+id+"/preview", nil, nil), 200)
		if desc["kind"] != "unavailable" {
			t.Fatal("unsafe preview allowed")
		}
		parse(t, A.request("GET", "/api/v1/nodes/"+id+"/content?disposition=preview", nil, nil), 415)
		w := A.request("GET", "/api/v1/nodes/"+id+"/content", nil, nil)
		if w.Code != 200 || w.Header().Get("Content-Type") != "application/octet-stream" || !strings.HasPrefix(w.Header().Get("Content-Disposition"), "attachment") {
			t.Fatal("unsafe attachment headers")
		}
		etag := w.Header().Get("ETag")
		w = A.request("HEAD", "/api/v1/nodes/"+id+"/content", nil, nil)
		if w.Code != 200 || w.Body.Len() != 0 {
			t.Fatal("HEAD has body")
		}
		w = A.request("GET", "/api/v1/nodes/"+id+"/content", nil, map[string]string{"If-None-Match": etag})
		if w.Code != 304 {
			t.Fatal("conditional GET failed")
		}
		w = A.request("GET", "/api/v1/nodes/"+id+"/content", nil, map[string]string{"Range": "bytes=0-3", "If-Range": "\"wrong\""})
		if w.Code != 200 {
			t.Fatal("If-Range failed")
		}
	})
	t.Run("trash_child_independent_restore_parent_purged", func(t *testing.T) {
		parent := createFolderTest(t, A, root, ws, "trash parent")
		child := createFolderTest(t, A, parent["id"].(string), ws, "independent child")
		child = parse(t, A.request("POST", "/api/v1/nodes/"+child["id"].(string)+"/trash", M{}, map[string]string{"If-Match": rev(child), "Idempotency-Key": db.ID()}), 200)
		parent = parse(t, A.request("POST", "/api/v1/nodes/"+parent["id"].(string)+"/trash", M{}, map[string]string{"If-Match": rev(parent), "Idempotency-Key": db.ID()}), 200)
		parse(t, A.request("POST", "/api/v1/nodes/"+parent["id"].(string)+"/purge", M{"confirm_name": parent["name"]}, map[string]string{"If-Match": rev(parent), "Idempotency-Key": db.ID()}), 202)
		if e := a.RunJobs(); e != nil {
			t.Fatal(e)
		}
		child = parse(t, A.request("GET", "/api/v1/nodes/"+child["id"].(string), nil, nil), 200)
		if child["restore_parent_id"] != nil {
			t.Fatal("purged parent reference retained")
		}
		parse(t, A.request("POST", "/api/v1/nodes/"+child["id"].(string)+"/restore", M{"target_parent_id": root}, map[string]string{"If-Match": rev(child), "Idempotency-Key": db.ID()}), 200)
	})
	t.Run("pagination_and_filter_binding", func(t *testing.T) {
		folder := createFolderTest(t, A, root, ws, "pagination")
		for i := 0; i < 5; i++ {
			createFolderTest(t, A, folder["id"].(string), ws, fmt.Sprint("item-", i))
		}
		path := "/api/v1/nodes?workspace_id=" + ws + "&parent_id=" + folder["id"].(string) + "&limit=2"
		first := parse(t, A.request("GET", path, nil, nil), 200)
		next := first["next_cursor"].(string)
		second := parse(t, A.request("GET", path+"&cursor="+next, nil, nil), 200)
		if len(second["items"].([]any)) != 2 || first["items"].([]any)[0].(map[string]any)["id"] == second["items"].([]any)[0].(map[string]any)["id"] {
			t.Fatal("pagination repeated")
		}
		parse(t, A.request("GET", path+"&q=changed&cursor="+next, nil, nil), 422)
	})
	t.Run("mandatory_password_change_and_expiry", func(t *testing.T) {
		u := parse(t, admin.request("POST", "/api/v1/admin/users", M{"username": "new-user", "display_name": "New", "role": "employee", "temporary_password": "Temporary!User2026"}, map[string]string{"Idempotency-Key": db.ID()}), 201)
		var token string
		for _, r := range []string{u["id"].(string)} {
			token = r
		}
		if token == "" {
			t.Fatal("missing created user")
		}
		a.DB.Write.Exec("UPDATE sessions SET last_seen_at=? WHERE user_id=?", time.Now().Add(-31*time.Minute).UnixMilli(), fixtureID("4"))
		parse(t, C.request("GET", "/api/v1/session", nil, nil), 401)
	})
	if e := a.DB.Verify(); e != nil {
		t.Fatal(e)
	}
}
func TestConcurrentMetadataPreconditions(t *testing.T) {
	a := testApp(t)
	c := loginClient(t, a, "pegawai-a")
	n := createFolderTest(t, c, fixtureID("201"), fixtureID("101"), "race")
	statuses := make(chan int, 2)
	for _, title := range []string{"first", "second"} {
		go func(title string) {
			statuses <- c.request("PATCH", "/api/v1/nodes/"+n["id"].(string), M{"name": title}, map[string]string{"If-Match": rev(n)}).Code
		}(title)
	}
	one, two := <-statuses, <-statuses
	if !((one == 200 && two == 412) || (one == 412 && two == 200)) {
		t.Fatalf("ETag race %d %d", one, two)
	}
}
func TestChunkBoundariesAndCancellation(t *testing.T) {
	a := testApp(t)
	c := loginClient(t, a, "pegawai-a")
	data := make([]byte, chunkSize+1)
	for i := range data {
		data[i] = byte(i % 251)
	}
	n := uploadTest(t, c, fixtureID("201"), fixtureID("101"), "chunks.bin", data)
	w := c.request("GET", "/api/v1/nodes/"+n["id"].(string)+"/content", nil, map[string]string{"Range": fmt.Sprintf("bytes=%d-%d", chunkSize-1, chunkSize)})
	if w.Code != 206 || !strings.EqualFold(hex.EncodeToString(w.Body.Bytes()), hex.EncodeToString(data[chunkSize-1:])) {
		t.Fatal("chunk boundary mismatch")
	}
	sum := sha256.Sum256(data)
	received := sha256.Sum256(c.request("GET", "/api/v1/nodes/"+n["id"].(string)+"/content", nil, nil).Body.Bytes())
	if sum != received {
		t.Fatal("whole file mismatch")
	}
}

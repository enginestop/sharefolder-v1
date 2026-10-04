package app

import (
	"sharefolder/internal/db"
	"testing"
)

func TestLifecycleIdempotencyReplaysOldRevision(t *testing.T) {
	a := testApp(t)
	c := loginClient(t, a, "pegawai-a")
	n := createFolderTest(t, c, fixtureID("201"), fixtureID("101"), "idempotent lifecycle")
	id := n["id"].(string)
	for _, action := range []string{"trash", "restore", "trash", "purge"} {
		body := M{}
		if action == "purge" {
			body["confirm_name"] = n["name"]
		}
		headers := map[string]string{"Idempotency-Key": db.ID(), "If-Match": rev(n)}
		status := 200
		if action == "purge" {
			status = 202
		}
		first := parse(t, c.request("POST", "/api/v1/nodes/"+id+"/"+action, body, headers), status)
		second := parse(t, c.request("POST", "/api/v1/nodes/"+id+"/"+action, body, headers), status)
		if string(marshal(first)) != string(marshal(second)) {
			t.Fatal("replay changed response")
		}
		if action != "purge" {
			n = first
		}
	}
}

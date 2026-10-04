package db

import (
	"os"
	"path/filepath"
	"sharefolder/internal/config"
	"testing"
)

func TestDataRootBinding(t *testing.T) {
	root := t.TempDir()
	c := config.Config{Env: "test", Listen: "127.0.0.1:8080", Origin: "http://127.0.0.1:8080", Metadata: filepath.Join(root, "state"), Data: filepath.Join(root, "data")}
	d, e := Open(c, true)
	if e != nil {
		t.Fatal(e)
	}
	if e = d.Migrate(); e != nil {
		t.Fatal(e)
	}
	d.Close()
	wrong := c
	wrong.Data = filepath.Join(root, "wrong-data")
	for _, p := range []string{"blobs", "staging"} {
		if e = os.MkdirAll(filepath.Join(wrong.Data, p), 0700); e != nil {
			t.Fatal(e)
		}
	}
	if bad, e := Open(wrong, false); e == nil {
		bad.Close()
		t.Fatal("accepted unrelated data root")
	}
	if e = Doctor(wrong); e == nil {
		t.Fatal("doctor accepted unrelated data root")
	}
	d, e = Open(c, false)
	if e != nil {
		t.Fatal(e)
	}
	d.Close()
	marker := filepath.Join(c.Data, ".sharefolder-instance")
	if e = os.WriteFile(marker, []byte(ID()+"\n"), 0600); e != nil {
		t.Fatal(e)
	}
	if bad, e := Open(c, false); e == nil {
		bad.Close()
		t.Fatal("accepted foreign marker")
	}
}

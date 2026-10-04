package db

import (
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"sharefolder/internal/config"
	"sharefolder/internal/platform"
)

func Doctor(c config.Config) error {
	if e := c.Validate(); e != nil {
		return e
	}
	for _, p := range []string{c.Metadata, c.Data, filepath.Join(c.Data, "blobs"), filepath.Join(c.Data, "staging")} {
		if e := config.SafePath(p); e != nil {
			return e
		}
		if _, e := os.Stat(p); e != nil {
			return e
		}
		if c.Env == "production" {
			if e := platform.Private(p); e != nil {
				return e
			}
		}
	}
	same, e := platform.SameFS(filepath.Join(c.Data, "blobs"), filepath.Join(c.Data, "staging"))
	if e != nil {
		return e
	}
	if !same {
		return fmt.Errorf("data paths cross filesystem")
	}
	_, free, e := platform.Disk(c.Data)
	if e != nil {
		return e
	}
	if free < 5*1024*1024*1024 {
		return fmt.Errorf("data reserve below 5 GiB")
	}
	_, free, e = platform.Disk(c.Metadata)
	if e != nil {
		return e
	}
	if free < 2*1024*1024*1024 {
		return fmt.Errorf("metadata reserve below 2 GiB")
	}
	if c.Env == "production" {
		if runtime.GOOS != "linux" || runtime.GOARCH != "amd64" {
			return fmt.Errorf("production requires linux/amd64")
		}
		if e = platform.Private(c.Key); e != nil {
			return e
		}
	}
	path := filepath.Join(c.Metadata, "metadata.db")
	if _, e = os.Stat(path); os.IsNotExist(e) {
		return nil
	} else if e != nil {
		return e
	}
	key, e := os.ReadFile(filepath.Join(c.Metadata, "keys", "idempotency.key"))
	if e != nil || len(key) != 32 {
		return fmt.Errorf("invalid instance key")
	}
	uri := url.URL{Scheme: "file", Path: filepath.ToSlash(path)}
	if runtime.GOOS == "windows" {
		uri.Path = "/" + uri.Path
	}
	q, e := sql.Open("sqlite", uri.String()+"?mode=ro&_pragma=query_only(1)")
	if e != nil {
		return e
	}
	defer q.Close()
	var version int
	var hash string
	if e = q.QueryRow("SELECT version,sha256 FROM schema_migrations ORDER BY version DESC LIMIT 1").Scan(&version, &hash); e != nil {
		return e
	}
	expected := sha256.Sum256([]byte(migration))
	if version != 1 || hash != hex.EncodeToString(expected[:]) {
		return fmt.Errorf("unsupported schema/checksum")
	}
	if e = (&DB{Read: q, DataRoot: c.Data}).checkBinding(false); e != nil {
		return e
	}
	if c.Env == "production" {
		var count int
		if e = q.QueryRow("SELECT count(*) FROM app_meta WHERE key='fixture'").Scan(&count); e != nil {
			return e
		}
		if count > 0 {
			return fmt.Errorf("fixture database refused")
		}
	}
	return nil
}

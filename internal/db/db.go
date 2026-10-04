package db

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	_ "embed"
	"encoding/hex"
	"fmt"
	_ "modernc.org/sqlite"
	"os"
	"path/filepath"
	"sharefolder/internal/config"
	"sharefolder/internal/platform"
	"time"
)

//go:embed migrations/001_initial.sql
var migration string

type DB struct {
	Write, Read *sql.DB
	lock        *os.File
	Key         []byte
	DataRoot    string
}

func ID() string {
	b := make([]byte, 16)
	if _, e := rand.Read(b); e != nil {
		panic(e)
	}
	b[6] = (b[6] & 15) | 64
	b[8] = (b[8] & 63) | 128
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[:4], b[4:6], b[6:8], b[8:10], b[10:])
}
func Open(c config.Config, init bool) (d *DB, err error) {
	if err = c.Validate(); err != nil {
		return nil, err
	}
	if init {
		for _, p := range []string{c.Metadata, filepath.Join(c.Metadata, "keys"), c.Data, filepath.Join(c.Data, "blobs"), filepath.Join(c.Data, "staging")} {
			if err = os.MkdirAll(p, 0700); err != nil {
				return nil, err
			}
		}
	}
	for _, p := range []string{c.Metadata, c.Data, filepath.Join(c.Data, "blobs"), filepath.Join(c.Data, "staging")} {
		if err = config.SafePath(p); err != nil {
			return nil, err
		}
		if _, err = os.Stat(p); err != nil {
			return nil, err
		}
		if c.Env == "production" {
			if err = platform.Private(p); err != nil {
				return nil, err
			}
		}
	}
	same, e := platform.SameFS(filepath.Join(c.Data, "blobs"), filepath.Join(c.Data, "staging"))
	if e != nil || !same {
		return nil, fmt.Errorf("staging and blobs must share filesystem")
	}
	d = &DB{DataRoot: c.Data}
	opened := d
	defer func() {
		if err != nil {
			opened.Close()
		}
	}()
	d.lock, err = os.OpenFile(filepath.Join(c.Metadata, "metadata.db.app.lock"), os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		return nil, err
	}
	if err = platform.Lock(d.lock); err != nil {
		return nil, fmt.Errorf("instance already locked: %w", err)
	}
	path := filepath.Join(c.Metadata, "metadata.db")
	_, existsErr := os.Stat(path)
	keyPath := filepath.Join(c.Metadata, "keys", "idempotency.key")
	d.Key, err = os.ReadFile(keyPath)
	if os.IsNotExist(err) && init && os.IsNotExist(existsErr) {
		key := make([]byte, 32)
		if _, err = rand.Read(key); err != nil {
			return nil, err
		}
		var f *os.File
		f, err = os.OpenFile(keyPath, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
		if err != nil {
			return nil, err
		}
		_, err = f.Write(key)
		if err == nil {
			err = f.Sync()
		}
		f.Close()
		if err != nil {
			return nil, err
		}
		d.Key = key
		err = platform.SyncDir(filepath.Dir(keyPath))
	}
	if err != nil {
		return nil, fmt.Errorf("instance key unavailable: %w", err)
	}
	if len(d.Key) != 32 {
		return nil, fmt.Errorf("invalid instance key")
	}
	if c.Env == "production" {
		if err = platform.Private(keyPath); err != nil {
			return nil, err
		}
	}
	if !init && existsErr != nil {
		return nil, fmt.Errorf("database must be migrated first")
	}
	dsn := filepath.ToSlash(path) + "?_pragma=foreign_keys(1)&_pragma=busy_timeout(5000)&_pragma=synchronous(FULL)"
	d.Write, err = sql.Open("sqlite", dsn)
	if err != nil {
		return nil, err
	}
	d.Write.SetMaxOpenConns(1)
	var mode string
	if err = d.Write.QueryRow("PRAGMA journal_mode=WAL").Scan(&mode); err != nil || mode != "wal" {
		return nil, fmt.Errorf("WAL unavailable: %v", err)
	}
	d.Read, err = sql.Open("sqlite", dsn+"&_pragma=query_only(1)")
	if err != nil {
		return nil, err
	}
	d.Read.SetMaxOpenConns(4)
	if !init {
		if err = d.CheckSchema(); err != nil {
			return nil, err
		}
		if err = d.checkBinding(false); err != nil {
			return nil, err
		}
	}
	return d, nil
}
func (d *DB) Close() {
	if d == nil {
		return
	}
	if d.Read != nil {
		d.Read.Close()
	}
	if d.Write != nil {
		d.Write.Close()
	}
	if d.lock != nil {
		d.lock.Close()
	}
}
func (d *DB) Migrate() error {
	var count int
	if e := d.Write.QueryRow("SELECT count(*) FROM sqlite_master WHERE type='table' AND name='schema_migrations'").Scan(&count); e != nil {
		return e
	}
	if count > 0 {
		if e := d.CheckSchema(); e != nil {
			return e
		}
		return d.checkBinding(true)
	}
	tx, e := d.Write.BeginTx(context.Background(), nil)
	if e != nil {
		return e
	}
	defer tx.Rollback()
	if _, e = tx.Exec(migration); e != nil {
		return e
	}
	sum := sha256.Sum256([]byte(migration))
	if _, e = tx.Exec("INSERT INTO schema_migrations VALUES(1,?,?)", hex.EncodeToString(sum[:]), time.Now().UnixMilli()); e != nil {
		return e
	}
	if _, e = tx.Exec("INSERT INTO app_meta VALUES('instance_id',?)", ID()); e != nil {
		return e
	}
	if _, e = tx.Exec("INSERT INTO app_meta VALUES('data_root',?)", d.DataRoot); e != nil {
		return e
	}
	if e = tx.Commit(); e != nil {
		return e
	}
	return d.checkBinding(true)
}

// A persistent marker prevents accidentally serving a database with another data root.
// Only an empty, newly migrated instance can complete an interrupted marker creation.
func (d *DB) checkBinding(initialize bool) error {
	var id, root string
	if e := d.Read.QueryRow("SELECT value FROM app_meta WHERE key='instance_id'").Scan(&id); e != nil {
		return e
	}
	if e := d.Read.QueryRow("SELECT value FROM app_meta WHERE key='data_root'").Scan(&root); e != nil || root != d.DataRoot {
		return fmt.Errorf("database/data root binding mismatch")
	}
	path := filepath.Join(root, ".sharefolder-instance")
	if e := config.SafePath(path); e != nil {
		return e
	}
	marker, e := os.ReadFile(path)
	if os.IsNotExist(e) && initialize {
		var count int
		if e = d.Read.QueryRow("SELECT (SELECT count(*) FROM users)+(SELECT count(*) FROM nodes)+(SELECT count(*) FROM uploads)").Scan(&count); e != nil {
			return e
		}
		if count != 0 {
			return fmt.Errorf("data marker missing from populated instance")
		}
		f, e := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
		if e != nil {
			return e
		}
		_, e = f.WriteString(id + "\n")
		if e == nil {
			e = f.Sync()
		}
		closeErr := f.Close()
		if e != nil {
			return e
		}
		if closeErr != nil {
			return closeErr
		}
		return platform.SyncDir(root)
	}
	if e != nil || string(marker) != id+"\n" {
		return fmt.Errorf("data marker missing or belongs to another instance")
	}
	return nil
}
func (d *DB) CheckSchema() error {
	var version int
	var hash string
	e := d.Read.QueryRow("SELECT version,sha256 FROM schema_migrations ORDER BY version DESC LIMIT 1").Scan(&version, &hash)
	sum := sha256.Sum256([]byte(migration))
	if e != nil || version != 1 || hash != hex.EncodeToString(sum[:]) {
		return fmt.Errorf("schema version/checksum mismatch")
	}
	return nil
}
func (d *DB) Verify() error {
	if e := d.CheckSchema(); e != nil {
		return e
	}
	var integrity string
	if e := d.Read.QueryRow("PRAGMA integrity_check").Scan(&integrity); e != nil {
		return e
	}
	if integrity != "ok" {
		return fmt.Errorf("integrity check failed")
	}
	rows, e := d.Read.Query("PRAGMA foreign_key_check")
	if e != nil {
		return e
	}
	defer rows.Close()
	if rows.Next() {
		return fmt.Errorf("foreign key check failed")
	}
	var invalid int
	e = d.Read.QueryRow("SELECT count(*) FROM workspaces w LEFT JOIN nodes n ON n.id=w.root_id WHERE n.id IS NULL OR n.workspace_id<>w.id OR n.parent_id IS NOT NULL").Scan(&invalid)
	if e != nil {
		return e
	}
	if invalid > 0 {
		return fmt.Errorf("invalid workspace roots")
	}
	return nil
}

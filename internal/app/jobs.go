package app

import (
	"database/sql"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"sharefolder/internal/db"
	"sharefolder/internal/platform"
	"time"
)

func (a *App) intent(q Query, kind, id string) error {
	at := a.now().UnixMilli()
	_, e := q.Exec("INSERT INTO fs_intents VALUES(?,?,?,'PENDING',0,?,NULL,?,?) ON CONFLICT(kind,subject_id) DO UPDATE SET state=CASE WHEN fs_intents.state='DONE' THEN 'PENDING' ELSE fs_intents.state END", db.ID(), kind, id, at, at, at)
	return e
}
func (a *App) health() error {
	if e := a.DB.Read.Ping(); e != nil {
		return e
	}
	f, e := os.CreateTemp(a.Config.Data, ".health-")
	if e != nil {
		return e
	}
	p := f.Name()
	e = f.Close()
	os.Remove(p)
	if e != nil {
		return e
	}
	tx, e := a.DB.Write.Begin()
	if e != nil {
		return e
	}
	defer tx.Rollback()
	_, e = tx.Exec("UPDATE app_meta SET value=value WHERE key='instance_id'")
	return e
}
func (a *App) Start() error {
	if a.Config.Env == "production" {
		var count int
		if e := a.DB.Read.QueryRow("SELECT count(*) FROM app_meta WHERE key='fixture'").Scan(&count); e != nil {
			return e
		}
		if count > 0 {
			return fmt.Errorf("production refuses fixture database")
		}
	}
	if e := a.clearPasswordChangeRequirements(); e != nil {
		return e
	}
	if e := a.Reconcile(); e != nil {
		return e
	}
	if e := a.health(); e != nil {
		return e
	}
	a.ready.Store(true)
	a.wg.Add(1)
	go func() {
		defer a.wg.Done()
		tick := time.NewTicker(time.Second)
		defer tick.Stop()
		maintenance := a.now()
		for {
			select {
			case <-a.stop:
				return
			case <-tick.C:
				if a.now().Sub(maintenance) >= time.Minute {
					a.Maintain()
					maintenance = a.now()
				}
				a.RunJobs()
			}
		}
	}()
	return nil
}
func (a *App) Reconcile() error {
	a.mu.Lock()
	_, e := a.DB.Write.Exec("UPDATE fs_intents SET state='PENDING',next_attempt_at=? WHERE state IN ('RUNNING','FAILED')", a.now().UnixMilli())
	a.mu.Unlock()
	if e != nil {
		return e
	}
	rows, e := a.DB.Read.Query("SELECT " + uploadCols + " FROM uploads WHERE state='OPEN'")
	if e != nil {
		return e
	}
	uploads := []Upload{}
	for rows.Next() {
		u, e := scanUpload(rows)
		if e != nil {
			rows.Close()
			return e
		}
		uploads = append(uploads, u)
	}
	rows.Close()
	for _, u := range uploads {
		p, e := a.filePath("staging", u.Staging)
		if e != nil {
			return e
		}
		f, e := os.OpenFile(p, os.O_RDWR, 0600)
		if e != nil {
			return e
		}
		info, e := f.Stat()
		if e == nil && info.Size() < u.Offset {
			e = fmt.Errorf("staging shorter than acknowledged offset")
		}
		if e == nil {
			e = f.Truncate(u.Offset)
		}
		if e == nil {
			e = f.Sync()
		}
		f.Close()
		if e != nil {
			return e
		}
	}
	if e = a.Maintain(); e != nil {
		return e
	}
	return a.RunJobs()
}
func (a *App) Maintain() error {
	a.mu.Lock()
	defer a.mu.Unlock()
	tx, e := a.DB.Write.Begin()
	if e != nil {
		return e
	}
	defer tx.Rollback()
	now := a.now().UnixMilli()
	rows, e := tx.Query("SELECT id FROM uploads WHERE state='OPEN' AND expires_at<=?", now)
	if e != nil {
		return e
	}
	ids := []string{}
	for rows.Next() {
		var id string
		if e = rows.Scan(&id); e != nil {
			rows.Close()
			return e
		}
		ids = append(ids, id)
	}
	rows.Close()
	for _, id := range ids {
		if _, e = tx.Exec("UPDATE uploads SET state='EXPIRED',last_activity_at=? WHERE id=?", now, id); e != nil {
			return e
		}
		if e = a.intent(tx, "CLEAN_UPLOAD", id); e != nil {
			return e
		}
	}
	rows, e = tx.Query("SELECT id FROM nodes WHERE state='TRASHED' AND deleted_at<=?", a.now().Add(-30*24*time.Hour).UnixMilli())
	if e != nil {
		return e
	}
	ids = nil
	for rows.Next() {
		var id string
		if e = rows.Scan(&id); e != nil {
			rows.Close()
			return e
		}
		ids = append(ids, id)
	}
	rows.Close()
	for _, id := range ids {
		if _, e = tx.Exec("UPDATE nodes SET state='PURGING',revision=revision+1 WHERE id=?", id); e != nil {
			return e
		}
		if e = a.intent(tx, "PURGE_SUBTREE", id); e != nil {
			return e
		}
	}
	for _, query := range []string{"DELETE FROM idempotency WHERE expires_at<=?", "DELETE FROM sessions WHERE expires_at<=?"} {
		if _, e = tx.Exec(query, now); e != nil {
			return e
		}
	}
	if _, e = tx.Exec("DELETE FROM audit_events WHERE id IN (SELECT id FROM audit_events WHERE at<? LIMIT 500)", a.now().Add(-180*24*time.Hour).UnixMilli()); e != nil {
		return e
	}
	if _, e = tx.Exec("DELETE FROM uploads WHERE id IN (SELECT id FROM uploads WHERE state NOT IN ('OPEN','COMMITTING') AND last_activity_at<? AND NOT EXISTS(SELECT 1 FROM fs_intents f WHERE f.subject_id=uploads.id AND f.state<>'DONE') LIMIT 100)", a.now().Add(-24*time.Hour).UnixMilli()); e != nil {
		return e
	}
	if _, e = tx.Exec("DELETE FROM fs_intents WHERE state='DONE' AND updated_at<?", a.now().Add(-24*time.Hour).UnixMilli()); e != nil {
		return e
	}
	return tx.Commit()
}
func (a *App) RunJobs() error {
	rows, e := a.DB.Read.Query("SELECT id,kind,subject_id,attempts FROM fs_intents WHERE state='PENDING' AND next_attempt_at<=? ORDER BY created_at LIMIT 100", a.now().UnixMilli())
	if e != nil {
		return e
	}
	type job struct {
		id, kind, subject string
		attempt           int
	}
	jobs := []job{}
	for rows.Next() {
		var j job
		if e = rows.Scan(&j.id, &j.kind, &j.subject, &j.attempt); e != nil {
			rows.Close()
			return e
		}
		jobs = append(jobs, j)
	}
	rows.Close()
	for _, j := range jobs {
		switch j.kind {
		case "COMMIT_UPLOAD":
			e = a.commit(j.subject)
		case "CLEAN_UPLOAD":
			e = a.cleanUpload(j.subject)
		case "PURGE_SUBTREE":
			e = a.purge(j.subject)
		}
		a.mu.Lock()
		if e == nil {
			_, e = a.DB.Write.Exec("UPDATE fs_intents SET state='DONE',updated_at=?,last_error=NULL WHERE id=?", a.now().UnixMilli(), j.id)
		} else {
			delay := []time.Duration{time.Minute, 5 * time.Minute, 15 * time.Minute, time.Hour, 6 * time.Hour}
			state := "PENDING"
			if j.attempt >= len(delay) {
				state = "FAILED"
			}
			_, e = a.DB.Write.Exec("UPDATE fs_intents SET state=?,attempts=attempts+1,next_attempt_at=?,last_error='STORAGE_UNAVAILABLE',updated_at=? WHERE id=?", state, a.now().Add(delay[min(j.attempt, len(delay)-1)]).UnixMilli(), a.now().UnixMilli(), j.id)
		}
		a.mu.Unlock()
		if e != nil {
			return e
		}
	}
	return nil
}
func (a *App) commit(id string) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	u, e := scanUpload(a.DB.Read.QueryRow("SELECT "+uploadCols+" FROM uploads WHERE id=?", id))
	if errors.Is(e, sql.ErrNoRows) {
		return nil
	}
	if e != nil {
		return e
	}
	if u.State != "COMMITTING" {
		return nil
	}
	user, e := getUser(a.DB.Read, u.User)
	if e != nil {
		return e
	}
	_, permissionErr := a.folder(a.DB.Read, user, u.Parent, u.Workspace)
	if user.Status != "active" {
		permissionErr = fail(403, "FORBIDDEN")
	}
	if permissionErr == nil {
		permissionErr = availableName(a.DB.Read, u.Parent, u.NameKey, u.Reserved)
	}
	if permissionErr != nil {
		tx, e := a.DB.Write.Begin()
		if e != nil {
			return e
		}
		defer tx.Rollback()
		if _, e = tx.Exec("UPDATE uploads SET state='FAILED',error_code='FORBIDDEN',last_activity_at=? WHERE id=?", a.now().UnixMilli(), id); e != nil {
			return e
		}
		if e = a.intent(tx, "CLEAN_UPLOAD", id); e != nil {
			return e
		}
		return tx.Commit()
	}
	source, e := a.filePath("staging", u.Staging)
	if e != nil {
		return e
	}
	dest, e := a.filePath("blobs", u.Reserved)
	if e != nil {
		return e
	}
	s, sourceErr := os.Stat(source)
	d, destErr := os.Stat(dest)
	if sourceErr == nil && destErr == nil {
		return fail(503, "STORAGE_CONFLICT")
	}
	if sourceErr != nil && !os.IsNotExist(sourceErr) {
		return sourceErr
	}
	if destErr != nil && !os.IsNotExist(destErr) {
		return destErr
	}
	if sourceErr != nil && destErr != nil {
		return fail(503, "STORAGE_UNAVAILABLE")
	}
	if sourceErr == nil {
		if s.Size() != u.Size {
			return fail(503, "STORAGE_CONFLICT")
		}
		f, e := os.OpenFile(source, os.O_RDWR, 0600)
		if e != nil {
			return e
		}
		e = f.Sync()
		f.Close()
		if e != nil {
			return e
		}
		if e = os.MkdirAll(filepath.Dir(dest), 0700); e != nil {
			return e
		}
		if e = platform.SyncDir(filepath.Join(a.Config.Data, "blobs")); e != nil {
			return e
		}
		if e = a.boundary("commit_before_rename"); e != nil {
			return e
		}
		if e = os.Rename(source, dest); e != nil {
			return e
		}
		if e = platform.SyncDir(filepath.Dir(dest)); e != nil {
			return e
		}
		if e = platform.SyncDir(filepath.Dir(source)); e != nil {
			return e
		}
		if e = a.boundary("commit_renamed"); e != nil {
			return e
		}
	} else if d.Size() != u.Size {
		return fail(503, "STORAGE_CONFLICT")
	}
	f, e := os.Open(dest)
	if e != nil {
		return e
	}
	head := make([]byte, 512)
	n, _ := f.Read(head)
	f.Close()
	mime := http.DetectContentType(head[:n])
	tx, e := a.DB.Write.Begin()
	if e != nil {
		return e
	}
	defer tx.Rollback()
	at := a.now().UnixMilli()
	_, e = tx.Exec("INSERT INTO nodes(id,workspace_id,parent_id,kind,name,name_key,size_bytes,mime_type,manifest_sha256,blob_key,revision,state,created_by,created_at,modified_at) VALUES(?,?,?,'file',?,?,?,?,?,?,1,'ACTIVE',?,?,?)", u.Reserved, u.Workspace, u.Parent, u.Name, u.NameKey, u.Size, mime, u.Manifest.String, u.Reserved, u.User, at, at)
	if e != nil {
		return e
	}
	if e = addClosure(tx, u.Reserved, u.Parent); e != nil {
		return e
	}
	if _, e = tx.Exec("UPDATE uploads SET state='COMPLETE',node_id=?,last_activity_at=? WHERE id=?", u.Reserved, at, id); e != nil {
		return e
	}
	r := &Request{User: user, ID: db.ID(), IP: ""}
	if e = a.audit(tx, r, "upload.complete", "node", u.Reserved, "success", false, str(u.Size)); e != nil {
		return e
	}
	if e = a.boundary("commit_before_database"); e != nil {
		return e
	}
	return tx.Commit()
}
func removeFile(path string) error {
	e := os.Remove(path)
	if os.IsNotExist(e) {
		return nil
	}
	if e != nil {
		return e
	}
	return platform.SyncDir(filepath.Dir(path))
}
func (a *App) cleanUpload(id string) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	u, e := scanUpload(a.DB.Read.QueryRow("SELECT "+uploadCols+" FROM uploads WHERE id=?", id))
	if errors.Is(e, sql.ErrNoRows) {
		return nil
	}
	if e != nil {
		return e
	}
	if u.State == "COMPLETE" || u.State == "OPEN" || u.State == "COMMITTING" {
		return nil
	}
	for _, pair := range [][2]string{{"staging", u.Staging}, {"blobs", u.Reserved}} {
		var count int
		if pair[0] == "blobs" {
			if e = a.DB.Read.QueryRow("SELECT count(*) FROM nodes WHERE blob_key=?", u.Reserved).Scan(&count); e != nil {
				return e
			}
			if count > 0 {
				continue
			}
		}
		path, e := a.filePath(pair[0], pair[1])
		if e != nil {
			return e
		}
		if e = removeFile(path); e != nil {
			return e
		}
	}
	return nil
}
func (a *App) purge(id string) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	n, e := node(a.DB.Read, id)
	if errors.Is(e, sql.ErrNoRows) {
		return nil
	}
	if p, ok := e.(*Problem); ok && p.Status == 404 {
		return nil
	}
	if e != nil {
		return e
	}
	if n.State != "PURGING" {
		return nil
	}
	rows, e := a.DB.Read.Query("SELECT n.id,n.blob_key FROM nodes n JOIN node_closure c ON c.descendant_id=n.id WHERE c.ancestor_id=? ORDER BY c.depth DESC", id)
	if e != nil {
		return e
	}
	ids := []string{}
	blobs := []string{}
	for rows.Next() {
		var nid string
		var blob sql.NullString
		if e = rows.Scan(&nid, &blob); e != nil {
			rows.Close()
			return e
		}
		ids = append(ids, nid)
		if blob.Valid {
			blobs = append(blobs, blob.String)
		}
	}
	rows.Close()
	for _, blob := range blobs {
		p, e := a.filePath("blobs", blob)
		if e != nil {
			return e
		}
		if e = removeFile(p); e != nil {
			return e
		}
		if e = a.boundary("purge_unlinked"); e != nil {
			return e
		}
	}
	tx, e := a.DB.Write.Begin()
	if e != nil {
		return e
	}
	defer tx.Rollback()
	for _, nid := range ids {
		rows, e := tx.Query("SELECT staging_key,reserved_node_id FROM uploads WHERE parent_id=?", nid)
		if e != nil {
			return e
		}
		pairs := [][2]string{}
		for rows.Next() {
			var x, y string
			if e = rows.Scan(&x, &y); e != nil {
				rows.Close()
				return e
			}
			pairs = append(pairs, [2]string{x, y})
		}
		rows.Close()
		for _, pair := range pairs {
			p, e := a.filePath("staging", pair[0])
			if e != nil {
				return e
			}
			if e = removeFile(p); e != nil {
				return e
			}
		}
		if _, e = tx.Exec("DELETE FROM uploads WHERE parent_id=?", nid); e != nil {
			return e
		}
		if _, e = tx.Exec("DELETE FROM nodes WHERE id=?", nid); e != nil {
			return e
		}
	}
	r := &Request{ID: db.ID()}
	if e = a.audit(tx, r, "maintenance.purge", "node", id, "success", false, nil); e != nil {
		return e
	}
	return tx.Commit()
}

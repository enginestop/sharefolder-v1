package app

import (
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"sharefolder/internal/config"
	"sharefolder/internal/db"
	"sharefolder/internal/platform"
	"strconv"
	"strings"
	"sync"
	"time"
)

const chunkSize int64 = 8388608

type Upload struct {
	ID, User, Workspace, Parent, Name, NameKey, State, Reserved, Staging string
	Node, Manifest, Error                                                sql.NullString
	Size, Offset, LastModified, Created, Activity, Expires               int64
}

const uploadCols = "id,user_id,workspace_id,parent_id,name,name_key,size_bytes,offset_bytes,last_modified_ms,state,reserved_node_id,node_id,staging_key,manifest_sha256,created_at,last_activity_at,expires_at,error_code"

func scanUpload(s scanner) (u Upload, e error) {
	e = s.Scan(&u.ID, &u.User, &u.Workspace, &u.Parent, &u.Name, &u.NameKey, &u.Size, &u.Offset, &u.LastModified, &u.State, &u.Reserved, &u.Node, &u.Staging, &u.Manifest, &u.Created, &u.Activity, &u.Expires, &u.Error)
	return
}
func (u Upload) JSON() M {
	return M{"id": u.ID, "workspace_id": u.Workspace, "parent_id": u.Parent, "node_id": nullable(u.Node.String), "name": u.Name, "size_bytes": str(u.Size), "offset_bytes": str(u.Offset), "chunk_bytes": chunkSize, "state": u.State, "manifest_sha256": nullable(u.Manifest.String), "created_at": stamp(u.Created), "last_activity_at": stamp(u.Activity), "expires_at": stamp(u.Expires), "error_code": nullable(u.Error.String)}
}
func (a *App) getUpload(q Query, r *Request, id string, write bool) (Upload, error) {
	if e := validID(id); e != nil {
		return Upload{}, e
	}
	u, e := scanUpload(q.QueryRow("SELECT "+uploadCols+" FROM uploads WHERE id=? AND user_id=?", id, r.User.ID))
	if errors.Is(e, sql.ErrNoRows) {
		return u, fail(404, "NOT_FOUND")
	}
	if e != nil {
		return u, e
	}
	if u.State == "EXPIRED" || (u.State == "OPEN" && a.now().UnixMilli() >= u.Expires) {
		return u, fail(410, "UPLOAD_EXPIRED")
	}
	if write {
		if _, e = a.folder(q, r.User, u.Parent, u.Workspace); e != nil {
			return u, e
		}
	}
	return u, nil
}
func (a *App) filePath(kind, id string) (string, error) {
	if e := validID(id); e != nil {
		return "", e
	}
	p := filepath.Join(a.Config.Data, kind, id)
	if kind == "blobs" {
		p = filepath.Join(a.Config.Data, kind, id[:2], id)
	}
	if kind != "blobs" && kind != "staging" {
		return "", fail(503, "STORAGE_UNAVAILABLE")
	}
	return p, config.SafePath(p)
}
func (a *App) uploadRoute(r *Request, s []string) (Result, error) {
	if len(s) == 0 {
		switch r.R.Method {
		case "POST":
			return a.createUpload(r)
		case "GET":
			rows, e := a.DB.Read.Query("SELECT "+uploadCols+" FROM uploads WHERE user_id=? AND (state IN ('OPEN','COMMITTING') OR last_activity_at>?) ORDER BY created_at DESC,id", r.User.ID, a.now().Add(-24*time.Hour).UnixMilli())
			if e != nil {
				return Result{}, e
			}
			defer rows.Close()
			out := []M{}
			for rows.Next() {
				u, e := scanUpload(rows)
				if e != nil {
					return Result{}, e
				}
				out = append(out, u.JSON())
			}
			return paginate(r, out)
		}
	}
	if len(s) == 1 {
		switch r.R.Method {
		case "GET":
			return a.uploadStatus(r, s[0])
		case "PATCH":
			return a.chunk(r, s[0])
		case "DELETE":
			return a.cancelUpload(r, s[0])
		}
	}
	if len(s) == 2 && s[1] == "complete" && r.R.Method == "POST" {
		return a.completeUpload(r, s[0])
	}
	return Result{}, fail(404, "NOT_FOUND")
}
func (a *App) createUpload(r *Request) (Result, error) {
	if e := fields(r.Body, "workspace_id parent_id name size_bytes last_modified_ms", "workspace_id parent_id name size_bytes last_modified_ms"); e != nil {
		return Result{}, e
	}
	v, e := stringsFields(r.Body, "workspace_id", "parent_id", "name", "size_bytes")
	if e != nil {
		return Result{}, e
	}
	title, key, e := name(v[2])
	if e != nil {
		return Result{}, e
	}
	bytes, e := size(v[3])
	if e != nil {
		return Result{}, e
	}
	number, ok := r.Body["last_modified_ms"].(json.Number)
	if !ok {
		return Result{}, fail(422, "INVALID_FIELD")
	}
	modified, e := strconv.ParseInt(string(number), 10, 64)
	if e != nil || modified < 0 {
		return Result{}, fail(422, "INVALID_FIELD")
	}
	return a.mutate(r, true, func(q Query) error { _, e := a.folder(q, r.User, v[1], v[0]); return e }, func(tx *sql.Tx) (Result, error) {
		if e := availableName(tx, v[1], key, ""); e != nil {
			return Result{}, e
		}
		_, free, e := platform.Disk(a.Config.Data)
		if e != nil {
			return Result{}, e
		}
		_, metaFree, e := platform.Disk(a.Config.Metadata)
		if e != nil {
			return Result{}, e
		}
		var reserved int64
		var count, mine int
		if e = tx.QueryRow("SELECT COALESCE(sum(size_bytes-offset_bytes),0),count(*),COALESCE(sum(CASE WHEN user_id=? THEN 1 ELSE 0 END),0) FROM uploads WHERE state IN ('OPEN','COMMITTING')", r.User.ID).Scan(&reserved, &count, &mine); e != nil {
			return Result{}, e
		}
		if count >= 100 || mine >= 2 {
			return Result{}, fail(429, "TRANSFER_BUSY")
		}
		if free-reserved-5*1024*1024*1024 < bytes || metaFree < 2*1024*1024*1024 {
			return Result{}, fail(507, "INSUFFICIENT_STORAGE")
		}
		id, nodeID := db.ID(), db.ID()
		path, e := a.filePath("staging", id)
		if e != nil {
			return Result{}, e
		}
		file, e := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_RDWR, 0600)
		if e != nil {
			return Result{}, e
		}
		e = file.Sync()
		file.Close()
		if e != nil {
			return Result{}, e
		}
		if e = platform.SyncDir(filepath.Dir(path)); e != nil {
			return Result{}, e
		}
		at := a.now().UnixMilli()
		var manifest any
		if bytes == 0 {
			sum := sha256.Sum256(nil)
			manifest = hex.EncodeToString(sum[:])
		}
		_, e = tx.Exec("INSERT INTO uploads VALUES(?,?,?,?,?,?,?,0,?,'OPEN',?,NULL,?,?, ?,?,?,NULL)", id, r.User.ID, v[0], v[1], title, key, bytes, modified, nodeID, id, manifest, at, at, a.now().Add(24*time.Hour).UnixMilli())
		if e != nil {
			return Result{}, e
		}
		if e = a.audit(tx, r, "upload.create", "upload", id, "success", false, nil); e != nil {
			return Result{}, e
		}
		u, e := a.getUpload(tx, r, id, false)
		return Result{201, u.JSON()}, e
	})
}
func (a *App) uploadStatus(r *Request, id string) (Result, error) {
	u, e := a.getUpload(a.DB.Read, r, id, false)
	if e != nil {
		return Result{}, e
	}
	chunks := []M{}
	var next any
	if r.R.URL.Query().Get("include_chunks") == "true" {
		limit := 200
		if raw := r.R.URL.Query().Get("chunk_limit"); raw != "" {
			limit, e = strconv.Atoi(raw)
			if e != nil || limit < 1 || limit > 1000 {
				return Result{}, fail(422, "INVALID_FIELD")
			}
		}
		offset := int64(0)
		if raw := r.R.URL.Query().Get("chunk_cursor"); raw != "" {
			offset, e = size(raw)
			if e != nil {
				return Result{}, e
			}
		}
		rows, e := a.DB.Read.Query("SELECT offset_bytes,size_bytes,sha256 FROM upload_chunks WHERE upload_id=? AND offset_bytes>=? ORDER BY offset_bytes LIMIT ?", id, offset, limit+1)
		if e != nil {
			return Result{}, e
		}
		defer rows.Close()
		for rows.Next() {
			var off, sz int64
			var hash string
			if e = rows.Scan(&off, &sz, &hash); e != nil {
				return Result{}, e
			}
			if len(chunks) == limit {
				next = str(off)
				break
			}
			chunks = append(chunks, M{"offset_bytes": str(off), "size_bytes": str(sz), "sha256": hash})
		}
	}
	return Result{200, M{"upload": u.JSON(), "chunks": chunks, "next_chunk_cursor": next}}, nil
}
func (a *App) chunk(r *Request, id string) (Result, error) {
	if e := validID(id); e != nil {
		return Result{}, e
	}
	if strings.Split(r.R.Header.Get("Content-Type"), ";")[0] != "application/offset+octet-stream" {
		return Result{}, fail(415, "UNSUPPORTED_MEDIA")
	}
	offset, e := size(r.R.Header.Get("Upload-Offset"))
	if e != nil {
		return Result{}, e
	}
	hash := strings.TrimPrefix(r.R.Header.Get("Upload-Checksum"), "sha256 ")
	decoded, e := hex.DecodeString(hash)
	if e != nil || len(decoded) != 32 || strings.ToLower(hash) != hash {
		return Result{}, fail(422, "INVALID_FIELD")
	}
	if r.R.ContentLength > chunkSize {
		return Result{}, fail(413, "CHUNK_TOO_LARGE")
	}
	if r.R.ContentLength < 1 {
		return Result{}, fail(422, "INVALID_FIELD")
	}
	if e = a.acquireTransfer(r.R.Context(), a.chunks); e != nil {
		return Result{}, e
	}
	defer func() { <-a.chunks }()
	value, _ := a.uploadLocks.LoadOrStore(id, &sync.Mutex{})
	lock := value.(*sync.Mutex)
	lock.Lock()
	defer lock.Unlock()
	u, e := a.getUpload(a.DB.Read, r, id, true)
	if e != nil {
		return Result{}, e
	}
	if u.State != "OPEN" {
		return Result{}, fail(409, "UPLOAD_COMPLETE")
	}
	if offset != u.Offset {
		r.W.Header().Set("Upload-Offset", str(u.Offset))
		return Result{}, fail(409, "OFFSET_MISMATCH")
	}
	expected := min(chunkSize, u.Size-u.Offset)
	if r.R.ContentLength != expected {
		return Result{}, fail(422, "INVALID_FIELD")
	}
	_, free, e := platform.Disk(a.Config.Data)
	if e != nil {
		return Result{}, e
	}
	if free-5*1024*1024*1024 < expected {
		return Result{}, fail(507, "INSUFFICIENT_STORAGE")
	}
	path, e := a.filePath("staging", u.Staging)
	if e != nil {
		return Result{}, e
	}
	f, e := os.OpenFile(path, os.O_RDWR, 0600)
	if e != nil {
		return Result{}, e
	}
	defer f.Close()
	info, e := f.Stat()
	if e != nil {
		return Result{}, e
	}
	if info.Size() < u.Offset {
		return Result{}, fail(503, "STORAGE_CONFLICT")
	}
	if e = f.Truncate(u.Offset); e != nil {
		return Result{}, e
	}
	if _, e = f.Seek(u.Offset, io.SeekStart); e != nil {
		return Result{}, e
	}
	http.NewResponseController(r.W).SetReadDeadline(a.now().Add(120 * time.Second))
	defer http.NewResponseController(r.W).SetReadDeadline(time.Time{})
	h := sha256.New()
	written, e := io.CopyBuffer(io.MultiWriter(f, h), io.LimitReader(r.R.Body, expected+1), make([]byte, 256*1024))
	rollback := func() { f.Truncate(u.Offset); f.Sync() }
	if e != nil || written != expected {
		rollback()
		return Result{}, fail(422, "INCOMPLETE_UPLOAD")
	}
	if hex.EncodeToString(h.Sum(nil)) != hash {
		rollback()
		return Result{}, fail(422, "HASH_MISMATCH")
	}
	if e = f.Sync(); e != nil {
		rollback()
		return Result{}, e
	}
	if e = a.boundary("chunk_synced"); e != nil {
		return Result{}, e
	}
	out, e := a.mutate(r, false, func(q Query) error {
		fresh, e := a.getUpload(q, r, id, true)
		if e != nil {
			return e
		}
		if fresh.State != "OPEN" || fresh.Offset != offset {
			return fail(409, "OFFSET_MISMATCH")
		}
		return nil
	}, func(tx *sql.Tx) (Result, error) {
		_, e := tx.Exec("INSERT INTO upload_chunks VALUES(?,?,?,?)", id, offset, written, hash)
		if e != nil {
			return Result{}, e
		}
		var manifest any
		if offset+written == u.Size {
			manifest, e = uploadManifest(tx, id, u.Size)
			if e != nil {
				return Result{}, e
			}
		}
		_, e = tx.Exec("UPDATE uploads SET offset_bytes=?,manifest_sha256=?,last_activity_at=?,expires_at=? WHERE id=?", offset+written, manifest, a.now().UnixMilli(), a.now().Add(24*time.Hour).UnixMilli(), id)
		return Result{200, M{"offset_bytes": str(offset + written)}}, e
	})
	if e != nil {
		rollback()
	}
	return out, e
}
func uploadManifest(q Query, id string, total int64) (string, error) {
	rows, e := q.Query("SELECT offset_bytes,size_bytes,sha256 FROM upload_chunks WHERE upload_id=? ORDER BY offset_bytes", id)
	if e != nil {
		return "", e
	}
	defer rows.Close()
	h := sha256.New()
	offset := int64(0)
	for rows.Next() {
		var off, sz int64
		var hash string
		if e = rows.Scan(&off, &sz, &hash); e != nil {
			return "", e
		}
		if off != offset || sz != min(chunkSize, total-offset) {
			return "", fail(422, "INVALID_MANIFEST")
		}
		raw, e := hex.DecodeString(hash)
		if e != nil || len(raw) != 32 {
			return "", fail(422, "INVALID_MANIFEST")
		}
		h.Write(raw)
		offset += sz
	}
	if offset != total {
		return "", fail(422, "INCOMPLETE_UPLOAD")
	}
	return hex.EncodeToString(h.Sum(nil)), rows.Err()
}
func (a *App) completeUpload(r *Request, id string) (Result, error) {
	if e := fields(r.Body, "manifest_sha256", "manifest_sha256"); e != nil {
		return Result{}, e
	}
	hash, e := textField(r.Body, "manifest_sha256")
	if e != nil {
		return Result{}, e
	}
	return a.mutate(r, true, func(q Query) error { _, e := a.getUpload(q, r, id, true); return e }, func(tx *sql.Tx) (Result, error) {
		u, e := a.getUpload(tx, r, id, true)
		if e != nil {
			return Result{}, e
		}
		if u.State == "COMPLETE" {
			return Result{200, u.JSON()}, nil
		}
		if u.State == "COMMITTING" {
			return Result{202, u.JSON()}, nil
		}
		if u.State != "OPEN" {
			return Result{}, fail(410, "UPLOAD_EXPIRED")
		}
		if u.Size != u.Offset {
			return Result{}, fail(422, "INCOMPLETE_UPLOAD")
		}
		manifest, e := uploadManifest(tx, id, u.Size)
		if e != nil {
			return Result{}, e
		}
		if hash != manifest {
			return Result{}, fail(422, "INVALID_MANIFEST")
		}
		if _, e = tx.Exec("UPDATE uploads SET state='COMMITTING' WHERE id=?", id); e != nil {
			return Result{}, e
		}
		if e = a.intent(tx, "COMMIT_UPLOAD", id); e != nil {
			return Result{}, e
		}
		u.State = "COMMITTING"
		return Result{202, u.JSON()}, nil
	})
}
func (a *App) cancelUpload(r *Request, id string) (Result, error) {
	return a.mutate(r, false, func(q Query) error { _, e := a.getUpload(q, r, id, false); return e }, func(tx *sql.Tx) (Result, error) {
		u, e := a.getUpload(tx, r, id, false)
		if e != nil {
			return Result{}, e
		}
		if u.State == "COMPLETE" {
			return Result{}, fail(409, "UPLOAD_COMPLETE")
		}
		if _, e = tx.Exec("UPDATE uploads SET state='CANCELLED',last_activity_at=? WHERE id=?", a.now().UnixMilli(), id); e != nil {
			return Result{}, e
		}
		if e = a.intent(tx, "CLEAN_UPLOAD", id); e != nil {
			return Result{}, e
		}
		if e = a.audit(tx, r, "upload.cancel", "upload", id, "success", false, nil); e != nil {
			return Result{}, e
		}
		return Result{204, nil}, nil
	})
}
func (a *App) boundary(point string) error {
	if a.Fault != nil && a.Config.Env != "production" {
		return a.Fault(point)
	}
	return nil
}
func rawJSON(s string) json.RawMessage { return json.RawMessage(s) }

var _ = fmt.Sprint

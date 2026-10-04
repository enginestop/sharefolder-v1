package app

import (
	_ "golang.org/x/image/webp"
	"image"
	_ "image/gif"
	_ "image/jpeg"
	_ "image/png"
	"io"
	"mime"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"
)

func previewKind(m string) string {
	switch m {
	case "application/pdf":
		return "pdf"
	case "image/png", "image/jpeg", "image/gif", "image/webp":
		return "image"
	}
	return "unavailable"
}
func (a *App) preview(n Node) (M, error) {
	kind := previewKind(n.Mime.String)
	var url, reason, width, height any
	if kind == "unavailable" {
		reason = "UNSUPPORTED_PREVIEW"
	} else {
		url = "/api/v1/nodes/" + n.ID + "/content?disposition=preview"
	}
	if kind == "image" {
		if n.Size.Int64 > 50*1024*1024 {
			kind = "unavailable"
			reason = "PREVIEW_TOO_LARGE"
			url = nil
		} else {
			path, e := a.filePath("blobs", n.Blob.String)
			if e != nil {
				return nil, e
			}
			f, e := os.Open(path)
			if e != nil {
				return nil, e
			}
			cfg, _, e := image.DecodeConfig(io.LimitReader(f, 1024*1024))
			f.Close()
			if e != nil || int64(cfg.Width)*int64(cfg.Height) > 40000000 || cfg.Width < 1 || cfg.Height < 1 {
				kind = "unavailable"
				reason = "PREVIEW_UNAVAILABLE"
				url = nil
			} else {
				width = cfg.Width
				height = cfg.Height
			}
		}
	}
	return M{"node_id": n.ID, "kind": kind, "content_url": url, "reason": reason, "mime_type": n.Mime.String, "width": width, "height": height, "size_bytes": str(n.Size.Int64)}, nil
}

type idleWriter struct{ http.ResponseWriter }

func (w idleWriter) Write(b []byte) (int, error) {
	http.NewResponseController(w.ResponseWriter).SetWriteDeadline(time.Now().Add(120 * time.Second))
	return w.ResponseWriter.Write(b)
}
func (a *App) content(r *Request, id, mode string) (Result, error) {
	n, p, e := a.requireNode(a.DB.Read, r.User, id, "read")
	if e != nil {
		return Result{}, e
	}
	if n.Kind != "file" {
		return Result{}, fail(422, "INVALID_FIELD")
	}
	if n.State != "ACTIVE" {
		return Result{}, fail(404, "NOT_FOUND")
	}
	if mode == "preview" {
		v, e := a.preview(n)
		if e != nil {
			return Result{}, e
		}
		if p.Override {
			if e = a.audit(a.DB.Write, r, "admin.node_read", "node", id, "success", true, nil); e != nil {
				return Result{}, e
			}
		}
		return Result{200, v}, nil
	}
	disposition := r.R.URL.Query().Get("disposition")
	if disposition == "" {
		disposition = "attachment"
	}
	if disposition != "attachment" && disposition != "preview" {
		return Result{}, fail(422, "INVALID_FIELD")
	}
	if disposition == "preview" {
		v, e := a.preview(n)
		if e != nil {
			return Result{}, e
		}
		if v["kind"] == "unavailable" {
			return Result{}, fail(415, "UNSUPPORTED_MEDIA")
		}
	}
	if strings.Contains(r.R.Header.Get("Range"), ",") {
		r.W.Header().Set("Content-Range", "bytes */"+str(n.Size.Int64))
		return Result{}, fail(416, "RANGE_NOT_SATISFIABLE")
	}
	if e = a.acquireTransfer(r.R.Context(), a.streams); e != nil {
		return Result{}, e
	}
	defer func() { <-a.streams }()
	path, e := a.filePath("blobs", n.Blob.String)
	if e != nil {
		return Result{}, e
	}
	f, e := os.Open(path)
	if e != nil {
		return Result{}, e
	}
	defer f.Close()
	info, e := f.Stat()
	if e != nil || info.Size() != n.Size.Int64 {
		return Result{}, fail(503, "STORAGE_UNAVAILABLE")
	}
	if r.R.Method == "GET" || p.Override {
		action := "file.download"
		if disposition == "preview" {
			action = "file.preview"
		}
		if e = a.audit(a.DB.Write, r, action, "node", id, "success", p.Override, str(plannedBytes(r.R, n.Size.Int64))); e != nil {
			return Result{}, e
		}
	}
	mimeType := n.Mime.String
	if previewKind(mimeType) == "unavailable" {
		mimeType = "application/octet-stream"
	}
	disp := "attachment"
	if disposition == "preview" {
		disp = "inline"
	}
	r.W.Header().Set("Content-Disposition", mime.FormatMediaType(disp, map[string]string{"filename": n.Name}))
	r.W.Header().Set("Content-Type", mimeType)
	r.W.Header().Set("Cache-Control", "private, no-store")
	r.W.Header().Set("ETag", `"`+n.Manifest.String+`"`)
	defer http.NewResponseController(r.W).SetWriteDeadline(time.Time{})
	http.ServeContent(idleWriter{r.W}, r.R, n.Name, time.UnixMilli(n.Modified), f)
	return Result{}, nil
}

func plannedBytes(r *http.Request, size int64) int64 {
	if r.Method == "HEAD" {
		return 0
	}
	value := r.Header.Get("Range")
	if value == "" || r.Header.Get("If-Range") != "" {
		return size
	}
	if !strings.HasPrefix(value, "bytes=") {
		return 0
	}
	start, end, ok := strings.Cut(strings.TrimPrefix(value, "bytes="), "-")
	if !ok {
		return 0
	}
	if start == "" {
		n, e := strconv.ParseInt(end, 10, 64)
		if e != nil || n < 0 {
			return 0
		}
		return min(n, size)
	}
	lo, e := strconv.ParseInt(start, 10, 64)
	if e != nil || lo < 0 || lo >= size {
		return 0
	}
	hi := size - 1
	if end != "" {
		hi, e = strconv.ParseInt(end, 10, 64)
		if e != nil || hi < lo {
			return 0
		}
	}
	return min(hi, size-1) - lo + 1
}

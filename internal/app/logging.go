package app

import (
	"net/http"
	"time"
)

type responseLog struct {
	http.ResponseWriter
	status int
	bytes  int64
}

func (w *responseLog) Unwrap() http.ResponseWriter { return w.ResponseWriter }
func (w *responseLog) WriteHeader(status int) {
	if w.status == 0 {
		w.status = status
	}
	w.ResponseWriter.WriteHeader(status)
}
func (w *responseLog) Write(b []byte) (int, error) {
	if w.status == 0 {
		w.status = 200
	}
	n, e := w.ResponseWriter.Write(b)
	w.bytes += int64(n)
	return n, e
}
func (a *App) logRequest(w *responseLog, id string, start time.Time) {
	if a.Log == nil {
		return
	}
	status := w.status
	if status == 0 {
		status = 200
	}
	entry := M{"time": time.Now().UTC().Format(time.RFC3339Nano), "level": "info", "event": "http_request", "request_id": id, "status": status, "duration_ms": time.Since(start).Milliseconds(), "bytes": str(w.bytes)}
	b := append(marshal(entry), '\n')
	a.logMu.Lock()
	defer a.logMu.Unlock()
	a.Log.Write(b)
}

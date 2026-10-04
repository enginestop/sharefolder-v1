package app

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"net/url"
	"strconv"
	"strings"
)

func (a *App) route(r *Request) (Result, error) {
	p := strings.TrimPrefix(r.R.URL.Path, "/api/v1/")
	s := strings.Split(p, "/")
	method := r.R.Method
	if s[0] == "session" {
		return a.authRoute(r, p)
	}
	if s[0] == "admin" {
		if e := requireAdmin(r.User); e != nil {
			return Result{}, e
		}
		return a.adminRoute(r, s[1:])
	}
	if p == "principals" && method == "GET" {
		return a.principals(r)
	}
	if p == "workspaces" && method == "GET" {
		return a.workspaces(r)
	}
	if (p == "nodes" || p == "search" || p == "trash") && method == "GET" {
		return a.listNodesPaged(r, p)
	}
	if p == "folders" && method == "POST" {
		return a.createFolder(r)
	}
	if s[0] == "nodes" && len(s) >= 2 {
		if len(s) == 2 && method == "GET" {
			return a.nodeDetail(r, s[1])
		}
		if len(s) == 2 && method == "PATCH" {
			return a.updateNode(r, s[1])
		}
		if len(s) == 3 && (s[2] == "content" || s[2] == "preview") && (method == "GET" || method == "HEAD") {
			return a.content(r, s[1], s[2])
		}
		if len(s) >= 3 && s[2] == "grants" {
			return a.grants(r, s[1], s[3:])
		}
		if len(s) == 3 && method == "POST" && (s[2] == "trash" || s[2] == "restore" || s[2] == "purge") {
			return a.trashAction(r, s[1], s[2])
		}
	}
	if s[0] == "uploads" {
		return a.uploadRoute(r, s[1:])
	}
	return Result{}, fail(404, "NOT_FOUND")
}

type cursor struct {
	Filter string `json:"f"`
	Offset int    `json:"o"`
}

func paginate(r *Request, items []M) (Result, error) {
	limit := 50
	var e error
	if s := r.R.URL.Query().Get("limit"); s != "" {
		limit, e = strconv.Atoi(s)
		if e != nil || limit < 1 || limit > 200 {
			return Result{}, fail(422, "INVALID_FIELD")
		}
	}
	q := r.R.URL.Query()
	q.Del("cursor")
	hash := sha256.Sum256([]byte(r.R.URL.Path + "?" + q.Encode()))
	filter := hex.EncodeToString(hash[:])
	offset := 0
	if raw := r.R.URL.Query().Get("cursor"); raw != "" {
		if len(raw) > 2048 {
			return Result{}, fail(422, "INVALID_FIELD")
		}
		data, e := base64.RawURLEncoding.DecodeString(raw)
		if e != nil {
			return Result{}, fail(422, "INVALID_FIELD")
		}
		var c cursor
		if e = json.Unmarshal(data, &c); e != nil || c.Filter != filter || c.Offset < 0 {
			return Result{}, fail(422, "INVALID_FIELD")
		}
		offset = c.Offset
	}
	if offset > len(items) {
		offset = len(items)
	}
	end := offset + limit
	var next any
	if end < len(items) {
		next = base64.RawURLEncoding.EncodeToString(marshal(cursor{filter, end}))
	} else {
		end = len(items)
	}
	return Result{200, M{"items": items[offset:end], "next_cursor": next}}, nil
}
func queryScope(r *Request) error {
	s := r.R.URL.Query().Get("scope")
	if s != "" && s != "mine" && s != "all" {
		return fail(422, "INVALID_FIELD")
	}
	if s == "all" {
		return requireAdmin(r.User)
	}
	return nil
}
func queryText(q url.Values, key string, max int) (string, error) {
	s := q.Get(key)
	if len([]rune(s)) > max {
		return "", fail(422, "INVALID_FIELD")
	}
	return s, nil
}

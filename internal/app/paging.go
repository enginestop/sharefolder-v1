package app

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"golang.org/x/text/cases"
	"strconv"
	"strings"
	"time"
)

type nodeCursor struct {
	Filter string `json:"filter"`
	ID     string `json:"id"`
	Kind   int    `json:"kind"`
	Name   string `json:"name"`
	Time   int64  `json:"time"`
}

func (a *App) listNodesPaged(r *Request, mode string) (Result, error) {
	if e := queryScope(r); e != nil {
		return Result{}, e
	}
	params := r.R.URL.Query()
	ws, parent, sortOrder := params.Get("workspace_id"), params.Get("parent_id"), params.Get("sort")
	if sortOrder != "" && sortOrder != "name" && sortOrder != "modified_desc" {
		return Result{}, fail(422, "INVALID_FIELD")
	}
	if ws != "" {
		if e := validID(ws); e != nil {
			return Result{}, e
		}
	}
	search, e := queryText(params, "q", 100)
	if e != nil {
		return Result{}, e
	}
	search = cases.Fold().String(search)
	shared := mode == "search" && params.Get("mode") == "shared"
	if mode == "search" {
		if m := params.Get("mode"); m != "" && m != "search" && m != "shared" {
			return Result{}, fail(422, "INVALID_FIELD")
		}
		if !shared && search == "" {
			return Result{}, fail(422, "INVALID_FIELD")
		}
	}
	if mode == "nodes" {
		if ws == "" {
			return Result{}, fail(422, "INVALID_FIELD")
		}
		n, _, e := a.requireNode(a.DB.Read, r.User, parent, "read")
		if e != nil {
			return Result{}, e
		}
		if n.Workspace != ws || n.Kind != "folder" || n.State != "ACTIVE" {
			return Result{}, fail(404, "NOT_FOUND")
		}
	}
	limit := 50
	if raw := params.Get("limit"); raw != "" {
		limit, e = strconv.Atoi(raw)
		if e != nil || limit < 1 || limit > 200 {
			return Result{}, fail(422, "INVALID_FIELD")
		}
	}
	rawCursor := params.Get("cursor")
	params.Del("cursor")
	hash := sha256.Sum256([]byte(r.R.URL.Path + "?" + params.Encode()))
	filter := hex.EncodeToString(hash[:])
	var after *nodeCursor
	if rawCursor != "" {
		if len(rawCursor) > 2048 {
			return Result{}, fail(422, "INVALID_FIELD")
		}
		raw, e := base64.RawURLEncoding.DecodeString(rawCursor)
		if e != nil {
			return Result{}, fail(422, "INVALID_FIELD")
		}
		var c nodeCursor
		if e = json.Unmarshal(raw, &c); e != nil || c.Filter != filter || validID(c.ID) != nil || c.Kind < 0 || c.Kind > 1 || len(c.Name) > 1024 {
			return Result{}, fail(422, "INVALID_FIELD")
		}
		after = &c
	}
	base := "SELECT " + nodeCols + " FROM nodes WHERE 1=1"
	args := []any{}
	if ws != "" {
		base += " AND workspace_id=?"
		args = append(args, ws)
	}
	if mode == "nodes" {
		base += " AND parent_id=? AND state='ACTIVE'"
		args = append(args, parent)
	} else if mode == "trash" {
		base += " AND state='TRASHED' AND deleted_at>?"
		args = append(args, a.now().Add(-30*24*time.Hour).UnixMilli())
	} else {
		base += " AND state='ACTIVE' AND parent_id IS NOT NULL"
	}
	if search != "" {
		base += " AND instr(name_key,?)>0"
		args = append(args, search)
	}
	if shared {
		base += ` AND EXISTS(SELECT 1 FROM grants g WHERE g.node_id=nodes.id AND ((g.principal_type='user' AND g.principal_id=?) OR (g.principal_type='group' AND g.principal_id IN(SELECT group_id FROM group_members WHERE user_id=?))))`
		args = append(args, r.User.ID, r.User.ID)
	}
	timeColumn := ""
	if sortOrder == "modified_desc" {
		timeColumn = "modified_at"
	}
	if mode == "trash" {
		timeColumn = "deleted_at"
	}
	kindExpr := "CASE kind WHEN 'folder' THEN 0 ELSE 1 END"
	order := kindExpr + ",name_key,id"
	if timeColumn != "" {
		order = timeColumn + " DESC,id"
	}
	items := []M{}
	var lastAccepted *nodeCursor
	override := false
	var next any
	for {
		query := base
		batchArgs := append([]any{}, args...)
		if after != nil {
			if timeColumn != "" {
				query += " AND (" + timeColumn + "<? OR (" + timeColumn + "=? AND id>?))"
				batchArgs = append(batchArgs, after.Time, after.Time, after.ID)
			} else {
				query += " AND ((" + kindExpr + ")>? OR ((" + kindExpr + ")=? AND (name_key>? OR (name_key=? AND id>?))))"
				batchArgs = append(batchArgs, after.Kind, after.Kind, after.Name, after.Name, after.ID)
			}
		}
		query += " ORDER BY " + order + " LIMIT 256"
		rows, e := a.DB.Read.Query(query, batchArgs...)
		if e != nil {
			return Result{}, e
		}
		batch := []Node{}
		for rows.Next() {
			n, e := scanNode(rows)
			if e != nil {
				rows.Close()
				return Result{}, e
			}
			batch = append(batch, n)
		}
		if e = rows.Err(); e != nil {
			rows.Close()
			return Result{}, e
		}
		rows.Close()
		if len(batch) == 0 {
			break
		}
		for _, n := range batch {
			c := &nodeCursor{Filter: filter, ID: n.ID, Name: n.NameKey, Time: n.Modified}
			if n.Kind != "folder" {
				c.Kind = 1
			}
			if mode == "trash" {
				c.Time = n.Deleted.Int64
			}
			after = c
			p, e := a.rights(a.DB.Read, r.User, n)
			if e != nil {
				return Result{}, e
			}
			if !p.Read {
				continue
			}
			if shared {
				w, e := workspace(a.DB.Read, n.Workspace)
				if e != nil {
					return Result{}, e
				}
				if w.Owner.String == r.User.ID {
					continue
				}
				pn, e := node(a.DB.Read, n.Parent.String)
				if e == nil {
					pp, e := a.rights(a.DB.Read, r.User, pn)
					if e != nil {
						return Result{}, e
					}
					if pp.Read && !pp.Override {
						continue
					}
				}
			}
			if len(items) == limit {
				next = base64.RawURLEncoding.EncodeToString(marshal(lastAccepted))
				break
			}
			items = append(items, n.JSON(p))
			lastAccepted = c
			override = override || p.Override
		}
		if next != nil || len(batch) < 256 {
			break
		}
	}
	if override || params.Get("scope") == "all" {
		if e = a.audit(a.DB.Write, r, "admin.files_list", "workspace", ws, "success", override, nil); e != nil {
			return Result{}, e
		}
	}
	return Result{200, M{"items": items, "next_cursor": next}}, nil
}

var _ = strings.Compare

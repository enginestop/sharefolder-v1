package app

import (
	"database/sql"
	"sharefolder/internal/db"
)

func (a *App) nodeDetail(r *Request, id string) (Result, error) {
	n, p, e := a.requireNode(a.DB.Read, r.User, id, "read")
	if e != nil {
		return Result{}, e
	}
	if p.Override {
		if e = a.audit(a.DB.Write, r, "admin.node_read", "node", id, "success", true, nil); e != nil {
			return Result{}, e
		}
	}
	v, e := a.detail(a.DB.Read, r.User, n, p)
	return Result{200, v}, e
}
func (a *App) createFolder(r *Request) (Result, error) {
	if e := fields(r.Body, "workspace_id parent_id name", "workspace_id parent_id name"); e != nil {
		return Result{}, e
	}
	v, e := stringsFields(r.Body, "workspace_id", "parent_id", "name")
	if e != nil {
		return Result{}, e
	}
	title, key, e := name(v[2])
	if e != nil {
		return Result{}, e
	}
	return a.mutate(r, true, func(q Query) error { _, e := a.folder(q, r.User, v[1], v[0]); return e }, func(tx *sql.Tx) (Result, error) {
		if e := availableName(tx, v[1], key, ""); e != nil {
			return Result{}, e
		}
		id := db.ID()
		at := a.now().UnixMilli()
		_, e := tx.Exec("INSERT INTO nodes(id,workspace_id,parent_id,kind,name,name_key,revision,state,created_by,created_at,modified_at) VALUES(?,?,?,'folder',?,?,1,'ACTIVE',?,?,?)", id, v[0], v[1], title, key, r.User.ID, at, at)
		if e != nil {
			return Result{}, e
		}
		if e = addClosure(tx, id, v[1]); e != nil {
			return Result{}, e
		}
		if e = a.audit(tx, r, "node.create", "node", id, "success", false, nil); e != nil {
			return Result{}, e
		}
		n, p, e := a.requireNode(tx, r.User, id, "read")
		return Result{201, n.JSON(p)}, e
	})
}
func (a *App) updateNode(r *Request, id string) (Result, error) {
	if e := fields(r.Body, "name parent_id", ""); e != nil {
		return Result{}, e
	}
	if len(r.Body) == 0 {
		return Result{}, fail(422, "INVALID_FIELD")
	}
	return a.mutate(r, false, func(q Query) error {
		n, _, e := a.requireNode(q, r.User, id, "write")
		if e != nil {
			return e
		}
		if !n.Parent.Valid {
			return fail(403, "FORBIDDEN")
		}
		return nil
	}, func(tx *sql.Tx) (Result, error) {
		n, _, e := a.requireNode(tx, r.User, id, "write")
		if e != nil {
			return Result{}, e
		}
		if e = revision(r.R.Header.Get("If-Match"), n.Revision); e != nil {
			return Result{}, e
		}
		parent := n.Parent.String
		title, key := n.Name, n.NameKey
		action := "node.rename"
		if _, ok := r.Body["name"]; ok {
			s, e := textField(r.Body, "name")
			if e != nil {
				return Result{}, e
			}
			title, key, e = name(s)
			if e != nil {
				return Result{}, e
			}
		}
		if _, ok := r.Body["parent_id"]; ok {
			parent, e = textField(r.Body, "parent_id")
			if e != nil {
				return Result{}, e
			}
			if _, e = a.folder(tx, r.User, parent, n.Workspace); e != nil {
				return Result{}, e
			}
			var count int
			if e = tx.QueryRow("SELECT count(*) FROM node_closure WHERE ancestor_id=? AND descendant_id=?", id, parent).Scan(&count); e != nil {
				return Result{}, e
			}
			if count > 0 {
				return Result{}, fail(409, "CYCLE")
			}
			action = "node.move"
		}
		if e = availableName(tx, parent, key, id); e != nil {
			return Result{}, e
		}
		if parent != n.Parent.String {
			if e = moveClosure(tx, id, parent); e != nil {
				return Result{}, e
			}
		}
		_, e = tx.Exec("UPDATE nodes SET name=?,name_key=?,parent_id=?,revision=revision+1,modified_at=? WHERE id=?", title, key, parent, a.now().UnixMilli(), id)
		if e != nil {
			return Result{}, e
		}
		if e = a.audit(tx, r, action, "node", id, "success", false, nil); e != nil {
			return Result{}, e
		}
		n, p, e := a.requireNode(tx, r.User, id, "read")
		return Result{200, n.JSON(p)}, e
	})
}
func (a *App) grants(r *Request, id string, tail []string) (Result, error) {
	if len(tail) == 0 && r.R.Method == "GET" {
		n, _, e := a.requireNode(a.DB.Read, r.User, id, "share")
		if e != nil {
			return Result{}, e
		}
		d, i, e := grantJSON(a.DB.Read, id)
		r.W.Header().Set("ETag", revisionValue(n.Revision))
		return Result{200, M{"direct": d, "inherited": i}}, e
	}
	if len(tail) != 2 || (r.R.Method != "PUT" && r.R.Method != "DELETE") {
		return Result{}, fail(404, "NOT_FOUND")
	}
	permission := ""
	if r.R.Method == "PUT" {
		if e := fields(r.Body, "permission", "permission"); e != nil {
			return Result{}, e
		}
		var e error
		permission, e = textField(r.Body, "permission")
		if e != nil {
			return Result{}, e
		}
		if permission != "viewer" && permission != "editor" {
			return Result{}, fail(422, "INVALID_FIELD")
		}
	}
	return a.mutate(r, false, func(q Query) error { _, _, e := a.requireNode(q, r.User, id, "share"); return e }, func(tx *sql.Tx) (Result, error) {
		n, p, e := a.requireNode(tx, r.User, id, "share")
		if e != nil {
			return Result{}, e
		}
		if e = revision(r.R.Header.Get("If-Match"), n.Revision); e != nil {
			return Result{}, e
		}
		if e = principal(tx, tail[0], tail[1]); e != nil {
			return Result{}, e
		}
		w, e := workspace(tx, n.Workspace)
		if e != nil {
			return Result{}, e
		}
		if tail[0] == "user" && tail[1] == w.Owner.String {
			return Result{}, fail(422, "INVALID_FIELD")
		}
		action := "grant.upsert"
		if r.R.Method == "DELETE" {
			result, e := tx.Exec("DELETE FROM grants WHERE node_id=? AND principal_type=? AND principal_id=?", id, tail[0], tail[1])
			if e != nil {
				return Result{}, e
			}
			count, _ := result.RowsAffected()
			if count == 0 {
				var inherited int
				e = tx.QueryRow("SELECT count(*) FROM grants g JOIN node_closure c ON c.ancestor_id=g.node_id WHERE c.descendant_id=? AND c.depth>0 AND g.principal_type=? AND g.principal_id=?", id, tail[0], tail[1]).Scan(&inherited)
				if e != nil {
					return Result{}, e
				}
				if inherited > 0 {
					return Result{}, fail(403, "INHERITED_GRANT")
				}
				return Result{204, nil}, nil
			}
			action = "grant.delete"
		} else {
			_, e = tx.Exec("INSERT INTO grants VALUES(?,?,?,?,?,?) ON CONFLICT(node_id,principal_type,principal_id) DO UPDATE SET permission=excluded.permission", id, tail[0], tail[1], permission, a.now().UnixMilli(), r.User.ID)
			if e != nil {
				return Result{}, e
			}
		}
		if _, e = tx.Exec("UPDATE nodes SET revision=revision+1 WHERE id=?", id); e != nil {
			return Result{}, e
		}
		if e = a.audit(tx, r, action, "node", id, "success", false, nil); e != nil {
			return Result{}, e
		}
		if r.R.Method == "DELETE" {
			return Result{204, nil}, nil
		}
		n, e = node(tx, id)
		if e != nil {
			return Result{}, e
		}
		body, e := a.detail(tx, r.User, n, p)
		return Result{200, body}, e
	})
}

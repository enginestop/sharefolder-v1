package app

import (
	"database/sql"
	"time"
)

func (a *App) trashAction(r *Request, id, action string) (Result, error) {
	allowed, required := "", ""
	if action == "restore" {
		allowed = "target_parent_id"
	}
	if action == "purge" {
		allowed = "confirm_name"
		required = allowed
	}
	if e := fields(r.Body, allowed, required); e != nil {
		return Result{}, e
	}
	permission := action
	if action == "trash" {
		permission = "write"
	}
	check := func(q Query) error {
		n, e := node(q, id)
		if e != nil {
			return e
		}
		if e == nil && n.State == "TRASHED" && n.Deleted.Valid && a.now().Sub(time.UnixMilli(n.Deleted.Int64)) >= 30*24*time.Hour {
			return fail(410, "TRASH_EXPIRED")
		}
		var replay int
		if e = q.QueryRow("SELECT count(*) FROM idempotency WHERE actor_id=? AND method=? AND path=? AND key=? AND expires_at>?", r.User.ID, r.R.Method, r.R.URL.Path, r.R.Header.Get("Idempotency-Key"), a.now().UnixMilli()).Scan(&replay); e != nil {
			return e
		}
		if replay > 0 {
			w, e := workspace(q, n.Workspace)
			if e != nil {
				return e
			}
			if w.Owner.String == r.User.ID || (r.User.Role == "admin" && w.Kind != "personal") {
				return nil
			}
			p, e := a.rights(q, r.User, n)
			if e != nil {
				return e
			}
			if (action == "trash" && p.Restore) || (action == "restore" && p.Write) || (action == "purge" && p.Purge) {
				return nil
			}
			return fail(403, "FORBIDDEN")
		}
		_, _, e = a.requireNode(q, r.User, id, permission)
		return e
	}
	return a.mutate(r, true, check, func(tx *sql.Tx) (Result, error) {
		n, p, e := a.requireNode(tx, r.User, id, permission)
		if e != nil {
			return Result{}, e
		}
		if e = revision(r.R.Header.Get("If-Match"), n.Revision); e != nil {
			return Result{}, e
		}
		now := a.now().UnixMilli()
		if action == "trash" {
			if !n.Parent.Valid {
				return Result{}, fail(403, "FORBIDDEN")
			}
			if n.State != "ACTIVE" {
				return Result{}, fail(409, "ALREADY_TRASHED")
			}
			if e = a.cancelSubtree(tx, id); e != nil {
				return Result{}, e
			}
			if e = moveClosure(tx, id, ""); e != nil {
				return Result{}, e
			}
			_, e = tx.Exec("UPDATE nodes SET parent_id=NULL,restore_parent_id=?,state='TRASHED',deleted_at=?,deleted_by=?,revision=revision+1,modified_at=? WHERE id=?", n.Parent.String, now, r.User.ID, now, id)
		} else {
			if n.State != "TRASHED" {
				return Result{}, fail(422, "INVALID_FIELD")
			}
			if action == "restore" {
				parent := n.RestoreParent.String
				if _, ok := r.Body["target_parent_id"]; ok {
					parent, e = textField(r.Body, "target_parent_id")
					if e != nil {
						return Result{}, e
					}
				}
				if parent == "" {
					return Result{}, fail(422, "INVALID_FIELD")
				}
				pn, e := node(tx, parent)
				if e != nil {
					return Result{}, e
				}
				if pn.Workspace != n.Workspace {
					return Result{}, fail(422, "CROSS_WORKSPACE_MOVE")
				}
				pp, e := a.rights(tx, r.User, pn)
				if e != nil {
					return Result{}, e
				}
				w, e := workspace(tx, n.Workspace)
				if e != nil {
					return Result{}, e
				}
				manager := r.User.Role == "admin" && w.Kind != "personal"
				if pn.Kind != "folder" || pn.State != "ACTIVE" || (!pp.Write && !manager) {
					return Result{}, fail(403, "FORBIDDEN")
				}
				if e = availableName(tx, parent, n.NameKey, id); e != nil {
					return Result{}, e
				}
				if e = moveClosure(tx, id, parent); e != nil {
					return Result{}, e
				}
				_, e = tx.Exec("UPDATE nodes SET parent_id=?,restore_parent_id=NULL,state='ACTIVE',deleted_at=NULL,deleted_by=NULL,revision=revision+1,modified_at=? WHERE id=?", parent, now, id)
			} else {
				confirm, e := textField(r.Body, "confirm_name")
				if e != nil {
					return Result{}, e
				}
				if confirm != n.Name {
					return Result{}, fail(422, "INVALID_FIELD")
				}
				if e = a.intent(tx, "PURGE_SUBTREE", id); e != nil {
					return Result{}, e
				}
				_, e = tx.Exec("UPDATE nodes SET state='PURGING',revision=revision+1 WHERE id=?", id)
			}
		}
		if e != nil {
			return Result{}, e
		}
		if e = a.audit(tx, r, "node."+action, "node", id, "success", false, nil); e != nil {
			return Result{}, e
		}
		if action == "purge" {
			return Result{202, M{"node_id": id, "state": "PURGING"}}, nil
		}
		n, e = node(tx, id)
		if e != nil {
			return Result{}, e
		}
		p, e = a.rights(tx, r.User, n)
		return Result{200, n.JSON(p)}, e
	})
}
func (a *App) cancelSubtree(q Query, id string) error {
	rows, e := q.Query("SELECT id FROM uploads WHERE parent_id IN (SELECT descendant_id FROM node_closure WHERE ancestor_id=?) AND state IN ('OPEN','COMMITTING')", id)
	if e != nil {
		return e
	}
	ids := []string{}
	for rows.Next() {
		var uid string
		if e = rows.Scan(&uid); e != nil {
			rows.Close()
			return e
		}
		ids = append(ids, uid)
	}
	rows.Close()
	for _, uid := range ids {
		if _, e = q.Exec("UPDATE uploads SET state='CANCELLED',last_activity_at=? WHERE id=?", a.now().UnixMilli(), uid); e != nil {
			return e
		}
		if e = a.intent(q, "CLEAN_UPLOAD", uid); e != nil {
			return e
		}
	}
	return nil
}

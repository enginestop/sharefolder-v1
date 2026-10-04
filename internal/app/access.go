package app

import (
	"database/sql"
	"time"
)

func (a *App) rights(q Query, u User, n Node) (p Rights, e error) {
	w, e := workspace(q, n.Workspace)
	if e != nil {
		return p, e
	}
	var inactive int
	if e = q.QueryRow("SELECT count(*) FROM node_closure c JOIN nodes n ON n.id=c.ancestor_id WHERE c.descendant_id=? AND n.state<>'ACTIVE' AND n.id<>?", n.ID, n.ID).Scan(&inactive); e != nil {
		return p, e
	}
	if inactive > 0 || n.State == "PURGING" {
		return p, nil
	}
	owner := w.Owner.String == u.ID
	manager := u.Role == "admin" && w.Kind != "personal"
	p.Share = owner || manager
	p.Read = owner
	p.Write = owner
	if n.State == "ACTIVE" {
		if w.Kind == "office" {
			p.Read = true
		}
		if w.Kind == "team" {
			var member int
			e = q.QueryRow("SELECT count(*) FROM group_members WHERE group_id=? AND user_id=?", w.Group.String, u.ID).Scan(&member)
			if e != nil {
				return p, e
			}
			if member > 0 {
				p.Read = true
				p.Write = w.Member.String == "editor"
			}
		}
	}
	var level int
	e = q.QueryRow(`SELECT COALESCE(MAX(CASE g.permission WHEN 'editor' THEN 2 ELSE 1 END),0) FROM grants g JOIN node_closure c ON c.ancestor_id=g.node_id WHERE c.descendant_id=? AND ((g.principal_type='user' AND g.principal_id=?) OR (g.principal_type='group' AND g.principal_id IN (SELECT group_id FROM group_members WHERE user_id=?)))`, n.ID, u.ID, u.ID).Scan(&level)
	if e != nil {
		return p, e
	}
	p.Read = p.Read || level > 0
	p.Write = p.Write || level == 2
	if n.State == "TRASHED" {
		if n.Deleted.Valid && a.now().Sub(time.UnixMilli(n.Deleted.Int64)) >= 30*24*time.Hour {
			return Rights{}, nil
		}
		parentWrite := false
		if n.RestoreParent.Valid {
			parent, err := node(q, n.RestoreParent.String)
			if err == nil && parent.State == "ACTIVE" {
				pp, err := a.rights(q, u, parent)
				if err != nil {
					return p, err
				}
				p.Read = p.Read || pp.Read
				parentWrite = pp.Write
			}
		}
		p.Restore = owner || manager || (n.DeletedBy.String == u.ID && parentWrite)
		p.Purge = p.Restore
		p.Read = p.Read || p.Restore
		p.Write = false
		p.Share = false
	}
	if u.Role == "admin" && !p.Read {
		p.Read = true
		p.Override = true
	}
	return p, nil
}
func (a *App) requireNode(q Query, u User, id, permission string) (Node, Rights, error) {
	if e := validID(id); e != nil {
		return Node{}, Rights{}, e
	}
	n, e := node(q, id)
	if e != nil {
		return n, Rights{}, e
	}
	p, e := a.rights(q, u, n)
	if e != nil {
		return n, p, e
	}
	if !p.Read {
		return n, p, fail(404, "NOT_FOUND")
	}
	ok := permission == "read" || (permission == "write" && p.Write) || (permission == "share" && p.Share) || (permission == "restore" && p.Restore) || (permission == "purge" && p.Purge)
	if !ok {
		return n, p, fail(403, "FORBIDDEN")
	}
	return n, p, nil
}
func (a *App) folder(q Query, u User, id, ws string) (Node, error) {
	n, _, e := a.requireNode(q, u, id, "write")
	if e != nil {
		return n, e
	}
	if n.State != "ACTIVE" || n.Kind != "folder" {
		return n, fail(422, "INVALID_FIELD")
	}
	if n.Workspace != ws {
		return n, fail(422, "CROSS_WORKSPACE_MOVE")
	}
	return n, nil
}
func addClosure(q Query, id, parent string) error {
	if _, e := q.Exec("INSERT INTO node_closure VALUES(?,?,0)", id, id); e != nil {
		return e
	}
	if parent != "" {
		_, e := q.Exec("INSERT INTO node_closure SELECT ancestor_id,?,depth+1 FROM node_closure WHERE descendant_id=?", id, parent)
		return e
	}
	return nil
}
func moveClosure(q Query, id, parent string) error {
	_, e := q.Exec(`DELETE FROM node_closure WHERE descendant_id IN (SELECT descendant_id FROM node_closure WHERE ancestor_id=?) AND ancestor_id NOT IN (SELECT descendant_id FROM node_closure WHERE ancestor_id=?)`, id, id)
	if e != nil {
		return e
	}
	if parent != "" {
		_, e = q.Exec(`INSERT INTO node_closure SELECT super.ancestor_id,sub.descendant_id,super.depth+sub.depth+1 FROM node_closure super CROSS JOIN node_closure sub WHERE super.descendant_id=? AND sub.ancestor_id=?`, parent, id)
	}
	return e
}
func availableName(q Query, parent, key, except string) error {
	var count int
	e := q.QueryRow("SELECT (SELECT count(*) FROM nodes WHERE parent_id=? AND name_key=? AND state='ACTIVE' AND id<>?)+(SELECT count(*) FROM uploads WHERE parent_id=? AND name_key=? AND state IN ('OPEN','COMMITTING') AND reserved_node_id<>?)", parent, key, except, parent, key, except).Scan(&count)
	if e != nil {
		return e
	}
	if count > 0 {
		return fail(409, "NAME_CONFLICT")
	}
	return nil
}
func grantJSON(q Query, id string) ([]M, []M, error) {
	direct, inherited := []M{}, []M{}
	rows, e := q.Query(`SELECT g.node_id,g.principal_type,g.principal_id,g.permission,g.created_at FROM grants g JOIN node_closure c ON c.ancestor_id=g.node_id WHERE c.descendant_id=? ORDER BY c.depth,g.principal_type,g.principal_id`, id)
	if e != nil {
		return nil, nil, e
	}
	defer rows.Close()
	for rows.Next() {
		var source, t, p, perm string
		var at int64
		if e = rows.Scan(&source, &t, &p, &perm, &at); e != nil {
			return nil, nil, e
		}
		g := M{"principal_type": t, "principal_id": p, "permission": perm, "created_at": stamp(at)}
		if source == id {
			direct = append(direct, g)
		} else {
			inherited = append(inherited, M{"source_node_id": source, "grant": g})
		}
	}
	return direct, inherited, rows.Err()
}
func (a *App) detail(q Query, u User, n Node, p Rights) (M, error) {
	v := n.JSON(p)
	ancestors := []M{}
	rows, e := q.Query("SELECT ancestor_id FROM node_closure WHERE descendant_id=? AND depth>0 ORDER BY depth DESC", n.ID)
	if e != nil {
		return nil, e
	}
	ids := []string{}
	for rows.Next() {
		var id string
		if e = rows.Scan(&id); e != nil {
			rows.Close()
			return nil, e
		}
		ids = append(ids, id)
	}
	rows.Close()
	for _, id := range ids {
		an, e := node(q, id)
		if e != nil {
			return nil, e
		}
		ap, e := a.rights(q, u, an)
		if e != nil {
			return nil, e
		}
		if ap.Read {
			ancestors = append(ancestors, M{"id": id, "name": an.Name})
		}
	}
	v["ancestors"] = ancestors
	v["grants_direct"] = []M{}
	v["grants_inherited"] = []M{}
	if p.Share {
		d, i, e := grantJSON(q, n.ID)
		if e != nil {
			return nil, e
		}
		v["grants_direct"] = d
		v["grants_inherited"] = i
	}
	return v, nil
}
func requireAdmin(u User) error {
	if u.Role != "admin" {
		return fail(403, "FORBIDDEN")
	}
	return nil
}
func principal(q Query, t, id string) error {
	if e := validID(id); e != nil {
		return e
	}
	var count int
	var e error
	if t == "user" {
		e = q.QueryRow("SELECT count(*) FROM users WHERE id=? AND status='active'", id).Scan(&count)
	} else if t == "group" {
		e = q.QueryRow("SELECT count(*) FROM groups WHERE id=?", id).Scan(&count)
	} else {
		return fail(422, "INVALID_FIELD")
	}
	if e != nil {
		return e
	}
	if count == 0 {
		return fail(422, "INVALID_FIELD")
	}
	return nil
}

var _ = sql.ErrNoRows

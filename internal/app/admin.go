package app

import (
	"database/sql"
	"fmt"
	"sharefolder/internal/auth"
	"sharefolder/internal/db"
	"sharefolder/internal/platform"
	"strings"
	"time"
	"unicode/utf8"
)

func revisionValue(n int64) string { return fmt.Sprintf(`"r%d"`, n) }
func (a *App) workspaceJSON(q Query, u User, w Workspace) (M, error) {
	n, e := node(q, w.Root.String)
	if e != nil {
		return nil, e
	}
	p, e := a.rights(q, u, n)
	if e != nil {
		return nil, e
	}
	permission := "viewer"
	if p.Write {
		permission = "editor"
	}
	if w.Owner.String == u.ID {
		permission = "owner"
	}
	return M{"id": w.ID, "root_id": w.Root.String, "kind": w.Kind, "name": w.Name, "owner_user_id": nullable(w.Owner.String), "group_id": nullable(w.Group.String), "member_permission": nullable(w.Member.String), "revision": w.Revision, "effective_permission": permission, "admin_read_override": p.Override}, nil
}
func (a *App) workspaces(r *Request) (Result, error) {
	if e := queryScope(r); e != nil {
		return Result{}, e
	}
	rows, e := a.DB.Read.Query("SELECT id FROM workspaces ORDER BY kind,name,id")
	if e != nil {
		return Result{}, e
	}
	ids := []string{}
	for rows.Next() {
		var id string
		if e = rows.Scan(&id); e != nil {
			rows.Close()
			return Result{}, e
		}
		ids = append(ids, id)
	}
	rows.Close()
	out := []M{}
	override := false
	for _, id := range ids {
		w, e := workspace(a.DB.Read, id)
		if e != nil {
			return Result{}, e
		}
		n, e := node(a.DB.Read, w.Root.String)
		if e != nil {
			return Result{}, e
		}
		p, e := a.rights(a.DB.Read, r.User, n)
		if e != nil {
			return Result{}, e
		}
		if !p.Read || (p.Override && r.R.URL.Query().Get("scope") != "all") {
			continue
		}
		v, e := a.workspaceJSON(a.DB.Read, r.User, w)
		if e != nil {
			return Result{}, e
		}
		out = append(out, v)
		override = override || p.Override
	}
	if r.R.URL.Query().Get("scope") == "all" {
		if e = a.audit(a.DB.Write, r, "admin.files_list", "workspace", "", "success", override, nil); e != nil {
			return Result{}, e
		}
	}
	return paginate(r, out)
}
func (a *App) principals(r *Request) (Result, error) {
	q, e := queryText(r.R.URL.Query(), "q", 100)
	if e != nil {
		return Result{}, e
	}
	kind := r.R.URL.Query().Get("kind")
	if kind != "" && kind != "all" && kind != "user" && kind != "group" {
		return Result{}, fail(422, "INVALID_FIELD")
	}
	items := []M{}
	for _, t := range []string{"user", "group"} {
		if kind != "" && kind != "all" && kind != t {
			continue
		}
		query := "SELECT id,display_name FROM users WHERE status='active' ORDER BY display_name,id"
		if t == "group" {
			query = "SELECT id,name FROM groups ORDER BY name,id"
		}
		rows, e := a.DB.Read.Query(query)
		if e != nil {
			return Result{}, e
		}
		for rows.Next() {
			var id, label string
			if e = rows.Scan(&id, &label); e != nil {
				rows.Close()
				return Result{}, e
			}
			if strings.Contains(strings.ToLower(label), strings.ToLower(q)) {
				items = append(items, M{"id": id, "type": t, "display_name": label})
			}
		}
		rows.Close()
	}
	return paginate(r, items)
}
func (a *App) adminRoute(r *Request, s []string) (Result, error) {
	if len(s) == 0 {
		return Result{}, fail(404, "NOT_FOUND")
	}
	if len(s) == 1 && s[0] == "test-instance" && r.R.Method == "GET" && a.Config.Env == "test" {
		var fixture string
		if e := a.DB.Read.QueryRow("SELECT value FROM app_meta WHERE key='fixture'").Scan(&fixture); e != nil {
			return Result{}, e
		}
		return Result{200, M{"fixture": fixture, "instance_id": a.Config.TestID}}, nil
	}
	if len(s) == 2 && s[0] == "groups" && r.R.Method == "GET" {
		v, e := groupJSON(a.DB.Read, s[1], true)
		return Result{200, v}, e
	}
	if len(s) == 1 && r.R.Method == "GET" {
		switch s[0] {
		case "users":
			return a.listUsers(r)
		case "groups":
			return a.listGroups(r)
		case "capacity":
			return a.capacity()
		case "audit":
			return a.listAudit(r)
		}
	}
	if s[0] == "users" {
		return a.userMutation(r, s[1:])
	}
	if s[0] == "groups" {
		return a.groupMutation(r, s[1:])
	}
	if s[0] == "workspaces" {
		return a.workspaceMutation(r, s[1:])
	}
	return Result{}, fail(404, "NOT_FOUND")
}
func (a *App) listUsers(r *Request) (Result, error) {
	q, e := queryText(r.R.URL.Query(), "q", 100)
	if e != nil {
		return Result{}, e
	}
	status := r.R.URL.Query().Get("status")
	if status != "" && status != "active" && status != "disabled" {
		return Result{}, fail(422, "INVALID_FIELD")
	}
	rows, e := a.DB.Read.Query("SELECT " + userCols + " FROM users ORDER BY username,id")
	if e != nil {
		return Result{}, e
	}
	defer rows.Close()
	out := []M{}
	for rows.Next() {
		var u User
		if e = rows.Scan(&u.ID, &u.Username, &u.DisplayName, &u.Hash, &u.Role, &u.Status, &u.MustChange, &u.Revision, &u.Created); e != nil {
			return Result{}, e
		}
		if status != "" && u.Status != status {
			continue
		}
		if !strings.Contains(strings.ToLower(u.Username+" "+u.DisplayName), strings.ToLower(q)) {
			continue
		}
		out = append(out, u.JSON())
	}
	return paginate(r, out)
}
func (a *App) userMutation(r *Request, s []string) (Result, error) {
	create := len(s) == 0 && r.R.Method == "POST"
	reset := len(s) == 2 && s[1] == "reset-password" && r.R.Method == "POST"
	update := len(s) == 1 && r.R.Method == "PATCH"
	if !create && !reset && !update {
		return Result{}, fail(404, "NOT_FOUND")
	}
	allowed, required := "display_name role status", ""
	if create {
		allowed = "username display_name role temporary_password"
		required = allowed
	}
	if reset {
		allowed = "temporary_password"
		required = allowed
	}
	if e := fields(r.Body, allowed, required); e != nil {
		return Result{}, e
	}
	if len(r.Body) == 0 {
		return Result{}, fail(422, "INVALID_FIELD")
	}
	hash := ""
	if create || reset {
		password, e := textField(r.Body, "temporary_password")
		if e != nil {
			return Result{}, e
		}
		hash, e = auth.Hash(password)
		if e != nil {
			return Result{}, e
		}
	}
	return a.mutate(r, create || reset, func(q Query) error { return requireAdmin(r.User) }, func(tx *sql.Tx) (Result, error) {
		id := db.ID()
		action := "user.create"
		if create {
			v, e := stringsFields(r.Body, "username", "display_name", "role")
			if e != nil {
				return Result{}, e
			}
			if e = a.createUser(tx, id, db.ID(), db.ID(), v[0], v[1], v[2], hash); e != nil {
				return Result{}, e
			}
		} else {
			id = s[0]
			if e := validID(id); e != nil {
				return Result{}, e
			}
			u, e := getUser(tx, id)
			if e != nil {
				return Result{}, fail(404, "NOT_FOUND")
			}
			if reset {
				_, e = tx.Exec("UPDATE users SET password_hash=?,must_change_password=0,revision=revision+1,updated_at=? WHERE id=?", hash, a.now().UnixMilli(), id)
				action = "user.reset_password"
			} else {
				if e = revision(r.R.Header.Get("If-Match"), u.Revision); e != nil {
					return Result{}, e
				}
				display, role, status := u.DisplayName, u.Role, u.Status
				for k, v := range r.Body {
					s, ok := v.(string)
					if !ok {
						return Result{}, fail(422, "INVALID_FIELD")
					}
					switch k {
					case "display_name":
						display = s
					case "role":
						role = s
					case "status":
						status = s
					}
				}
				if utf8.RuneCountInString(display) < 1 || utf8.RuneCountInString(display) > 100 || (role != "admin" && role != "employee") || (status != "active" && status != "disabled") {
					return Result{}, fail(422, "INVALID_FIELD")
				}
				if u.Role == "admin" && u.Status == "active" && (role != "admin" || status != "active") {
					var count int
					if e = tx.QueryRow("SELECT count(*) FROM users WHERE role='admin' AND status='active'").Scan(&count); e != nil {
						return Result{}, e
					}
					if count <= 1 {
						return Result{}, fail(409, "LAST_ADMIN")
					}
				}
				_, e = tx.Exec("UPDATE users SET display_name=?,role=?,status=?,revision=revision+1,updated_at=? WHERE id=?", display, role, status, a.now().UnixMilli(), id)
				action = "user.update"
				if role == u.Role && status == u.Status {
					if e != nil {
						return Result{}, e
					}
					if e = a.audit(tx, r, action, "user", id, "success", false, nil); e != nil {
						return Result{}, e
					}
					u, e = getUser(tx, id)
					return Result{200, u.JSON()}, e
				}
			}
			if e != nil {
				return Result{}, e
			}
			if _, e = tx.Exec("DELETE FROM sessions WHERE user_id=?", id); e != nil {
				return Result{}, e
			}
		}
		if e := a.audit(tx, r, action, "user", id, "success", false, nil); e != nil {
			return Result{}, e
		}
		if reset {
			return Result{204, nil}, nil
		}
		u, e := getUser(tx, id)
		status := 200
		if create {
			status = 201
		}
		return Result{status, u.JSON()}, e
	})
}
func groupJSON(q Query, id string, detail bool) (M, error) {
	var title string
	var revision int64
	e := q.QueryRow("SELECT name,revision FROM groups WHERE id=?", id).Scan(&title, &revision)
	if e != nil {
		return nil, fail(404, "NOT_FOUND")
	}
	rows, e := q.Query("SELECT user_id FROM group_members WHERE group_id=? ORDER BY user_id", id)
	if e != nil {
		return nil, e
	}
	defer rows.Close()
	ids := []string{}
	for rows.Next() {
		var user string
		if e = rows.Scan(&user); e != nil {
			return nil, e
		}
		ids = append(ids, user)
	}
	v := M{"id": id, "name": title, "revision": revision}
	if detail {
		v["member_ids"] = ids
	} else {
		v["member_count"] = len(ids)
	}
	return v, nil
}
func (a *App) listGroups(r *Request) (Result, error) {
	rows, e := a.DB.Read.Query("SELECT id FROM groups ORDER BY name_key,id")
	if e != nil {
		return Result{}, e
	}
	ids := []string{}
	for rows.Next() {
		var id string
		if e = rows.Scan(&id); e != nil {
			rows.Close()
			return Result{}, e
		}
		ids = append(ids, id)
	}
	rows.Close()
	out := []M{}
	for _, id := range ids {
		v, e := groupJSON(a.DB.Read, id, false)
		if e != nil {
			return Result{}, e
		}
		out = append(out, v)
	}
	return paginate(r, out)
}
func (a *App) groupMutation(r *Request, s []string) (Result, error) {
	create := len(s) == 0 && r.R.Method == "POST"
	if !create && (len(s) != 1 || r.R.Method != "PATCH") {
		return Result{}, fail(404, "NOT_FOUND")
	}
	required := ""
	if create {
		required = "name member_ids"
	}
	if e := fields(r.Body, "name member_ids", required); e != nil {
		return Result{}, e
	}
	if len(r.Body) == 0 {
		return Result{}, fail(422, "INVALID_FIELD")
	}
	return a.mutate(r, create, func(q Query) error { return requireAdmin(r.User) }, func(tx *sql.Tx) (Result, error) {
		id := db.ID()
		title, key := "", ""
		var e error
		if _, ok := r.Body["name"]; ok {
			title, e = textField(r.Body, "name")
			if e != nil {
				return Result{}, e
			}
			title, key, e = name(title)
			if e != nil || utf8.RuneCountInString(title) > 100 {
				return Result{}, fail(422, "INVALID_NAME")
			}
		}
		if create {
			_, e = tx.Exec("INSERT INTO groups VALUES(?,?,?,1,?)", id, title, key, a.now().UnixMilli())
		} else {
			id = s[0]
			v, e := groupJSON(tx, id, false)
			if e != nil {
				return Result{}, e
			}
			if e = revision(r.R.Header.Get("If-Match"), v["revision"].(int64)); e != nil {
				return Result{}, e
			}
			if title != "" {
				_, e = tx.Exec("UPDATE groups SET name=?,name_key=?,revision=revision+1 WHERE id=?", title, key, id)
			} else {
				_, e = tx.Exec("UPDATE groups SET revision=revision+1 WHERE id=?", id)
			}
			if e != nil {
				return Result{}, e
			}
		}
		if e != nil {
			return Result{}, e
		}
		if v, ok := r.Body["member_ids"]; ok {
			ids, ok := v.([]any)
			if !ok || len(ids) > 1000 {
				return Result{}, fail(422, "INVALID_FIELD")
			}
			if _, e = tx.Exec("DELETE FROM group_members WHERE group_id=?", id); e != nil {
				return Result{}, e
			}
			seen := map[string]bool{}
			for _, v := range ids {
				uid, ok := v.(string)
				if !ok || seen[uid] {
					return Result{}, fail(422, "INVALID_FIELD")
				}
				seen[uid] = true
				if e = principal(tx, "user", uid); e != nil {
					return Result{}, e
				}
				if _, e = tx.Exec("INSERT INTO group_members VALUES(?,?,?)", id, uid, a.now().UnixMilli()); e != nil {
					return Result{}, e
				}
			}
		}
		action, status := "group.update", 200
		if create {
			action = "group.create"
			status = 201
		}
		if e = a.audit(tx, r, action, "group", id, "success", false, nil); e != nil {
			return Result{}, e
		}
		v, e := groupJSON(tx, id, true)
		return Result{status, v}, e
	})
}
func (a *App) workspaceMutation(r *Request, s []string) (Result, error) {
	create := len(s) == 0 && r.R.Method == "POST"
	if !create && (len(s) != 1 || r.R.Method != "PATCH") {
		return Result{}, fail(404, "NOT_FOUND")
	}
	allowed, required := "name member_permission", ""
	if create {
		allowed = "kind name group_id member_permission"
		required = allowed
	}
	if e := fields(r.Body, allowed, required); e != nil {
		return Result{}, e
	}
	if len(r.Body) == 0 {
		return Result{}, fail(422, "INVALID_FIELD")
	}
	return a.mutate(r, create, func(q Query) error { return requireAdmin(r.User) }, func(tx *sql.Tx) (Result, error) {
		id, root := db.ID(), db.ID()
		title, member := "", ""
		var e error
		if _, ok := r.Body["name"]; ok {
			title, e = textField(r.Body, "name")
			if e != nil {
				return Result{}, e
			}
			title, _, e = name(title)
			if e != nil || utf8.RuneCountInString(title) > 100 {
				return Result{}, fail(422, "INVALID_NAME")
			}
		}
		if _, ok := r.Body["member_permission"]; ok {
			member, e = textField(r.Body, "member_permission")
			if e != nil || (member != "viewer" && member != "editor") {
				return Result{}, fail(422, "INVALID_FIELD")
			}
		}
		if create {
			v, e := stringsFields(r.Body, "kind", "group_id")
			if e != nil {
				return Result{}, e
			}
			if v[0] != "team" {
				return Result{}, fail(422, "INVALID_FIELD")
			}
			if e = principal(tx, "group", v[1]); e != nil {
				return Result{}, e
			}
			if e = a.createWorkspace(tx, id, root, "team", title, "", v[1], member, r.User.ID); e != nil {
				return Result{}, e
			}
			_, e = tx.Exec("INSERT INTO grants VALUES(?,'user',?,'editor',?,?)", root, r.User.ID, a.now().UnixMilli(), r.User.ID)
			if e != nil {
				return Result{}, e
			}
		} else {
			id = s[0]
			w, e := workspace(tx, id)
			if e != nil {
				return Result{}, fail(404, "NOT_FOUND")
			}
			if w.Kind == "personal" {
				return Result{}, fail(403, "FORBIDDEN")
			}
			if e = revision(r.R.Header.Get("If-Match"), w.Revision); e != nil {
				return Result{}, e
			}
			if title == "" {
				title = w.Name
			}
			if member == "" {
				member = w.Member.String
			}
			if w.Kind == "office" && member != "viewer" {
				return Result{}, fail(422, "INVALID_FIELD")
			}
			if _, e = tx.Exec("UPDATE workspaces SET name=?,member_permission=?,revision=revision+1 WHERE id=?", title, member, id); e != nil {
				return Result{}, e
			}
			_, key, _ := name(title)
			if _, e = tx.Exec("UPDATE nodes SET name=?,name_key=?,revision=revision+1 WHERE id=?", title, key, w.Root.String); e != nil {
				return Result{}, e
			}
		}
		action, status := "workspace.update", 200
		if create {
			action = "workspace.create"
			status = 201
		}
		if e = a.audit(tx, r, action, "workspace", id, "success", false, nil); e != nil {
			return Result{}, e
		}
		w, e := workspace(tx, id)
		if e != nil {
			return Result{}, e
		}
		v, e := a.workspaceJSON(tx, r.User, w)
		return Result{status, v}, e
	})
}
func (a *App) capacity() (Result, error) {
	total, free, e := platform.Disk(a.Config.Data)
	if e != nil {
		return Result{}, e
	}
	var reserved int64
	var active, pending, failed int
	if e = a.DB.Read.QueryRow("SELECT COALESCE(sum(size_bytes-offset_bytes),0),count(*) FROM uploads WHERE state IN ('OPEN','COMMITTING')").Scan(&reserved, &active); e != nil {
		return Result{}, e
	}
	if e = a.DB.Read.QueryRow("SELECT count(*) FROM fs_intents WHERE state IN ('PENDING','RUNNING')").Scan(&pending); e != nil {
		return Result{}, e
	}
	if e = a.DB.Read.QueryRow("SELECT count(*) FROM fs_intents WHERE state='FAILED'").Scan(&failed); e != nil {
		return Result{}, e
	}
	usable := free - reserved - 5*1024*1024*1024
	if usable < 0 {
		usable = 0
	}
	return Result{200, M{"total_bytes": str(total), "free_bytes": str(free), "reserved_bytes": str(reserved), "usable_bytes": str(usable), "active_uploads": active, "queued_transfers": a.queued.Load(), "pending_jobs": pending, "failed_jobs": failed, "backup_enabled": false, "audit_retention_days": 180, "trash_retention_days": 30}}, nil
}
func (a *App) listAudit(r *Request) (Result, error) {
	q := r.R.URL.Query()
	from, to := a.now().Add(-7*24*time.Hour), a.now()
	var e error
	if q.Get("from") != "" {
		from, e = time.Parse(time.RFC3339, q.Get("from"))
		if e != nil {
			return Result{}, fail(422, "INVALID_FIELD")
		}
	}
	if q.Get("to") != "" {
		to, e = time.Parse(time.RFC3339, q.Get("to"))
		if e != nil {
			return Result{}, fail(422, "INVALID_FIELD")
		}
	}
	if to.Before(from) || to.Sub(from) > 180*24*time.Hour {
		return Result{}, fail(422, "INVALID_FIELD")
	}
	if e = a.audit(a.DB.Write, r, "audit.read", "audit", "", "success", false, nil); e != nil {
		return Result{}, e
	}
	query := "SELECT id,actor_id,action,target_type,target_id,at,request_id,outcome,admin_override,ip,detail_json FROM audit_events WHERE at>=? AND at<=?"
	args := []any{from.UnixMilli(), to.UnixMilli()}
	for _, key := range []string{"actor_id", "action"} {
		if v := q.Get(key); v != "" {
			query += " AND " + key + "=?"
			args = append(args, v)
		}
	}
	query += " ORDER BY at DESC,id DESC"
	rows, e := a.DB.Read.Query(query, args...)
	if e != nil {
		return Result{}, e
	}
	defer rows.Close()
	out := []M{}
	for rows.Next() {
		var id, at int64
		var actor, target sql.NullString
		var action, typ, request, outcome, ip, detail string
		var override bool
		if e = rows.Scan(&id, &actor, &action, &typ, &target, &at, &request, &outcome, &override, &ip, &detail); e != nil {
			return Result{}, e
		}
		out = append(out, M{"id": str(id), "actor_id": nullable(actor.String), "action": action, "target_type": typ, "target_id": nullable(target.String), "at": stamp(at), "request_id": request, "outcome": outcome, "admin_override": override, "ip": ip, "detail": rawJSON(detail)})
	}
	return paginate(r, out)
}

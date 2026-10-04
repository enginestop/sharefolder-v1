package app

import (
	"database/sql"
	"errors"
	"fmt"
	"golang.org/x/text/cases"
	"golang.org/x/text/unicode/norm"
	"regexp"
	"strconv"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"
)

type M = map[string]any
type Problem struct {
	Status      int
	Code, Field string
}

func (e *Problem) Error() string         { return e.Code }
func fail(status int, code string) error { return &Problem{status, code, ""} }

var uuidPattern = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`)
var decimalPattern = regexp.MustCompile(`^(0|[1-9][0-9]*)$`)
var usernamePattern = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{2,63}$`)

func validID(s string) error {
	if !uuidPattern.MatchString(s) {
		return fail(422, "INVALID_FIELD")
	}
	return nil
}
func size(s string) (int64, error) {
	if !decimalPattern.MatchString(s) {
		return 0, fail(422, "INVALID_FIELD")
	}
	n, e := strconv.ParseInt(s, 10, 64)
	if e != nil {
		return 0, fail(422, "SIZE_UNREPRESENTABLE")
	}
	return n, nil
}
func name(s string) (string, string, error) {
	s = norm.NFC.String(s)
	bad := s == "" || len(s) > 255 || s == "." || s == ".." || !utf8.ValidString(s) || strings.TrimRight(s, " .") != s
	for _, r := range s {
		if unicode.IsControl(r) || strings.ContainsRune(`/\<>:"|?*`, r) {
			bad = true
		}
	}
	base := strings.ToUpper(strings.Split(s, ".")[0])
	if base == "CON" || base == "PRN" || base == "AUX" || base == "NUL" || (len(base) == 4 && (strings.HasPrefix(base, "COM") || strings.HasPrefix(base, "LPT")) && base[3] >= '1' && base[3] <= '9') {
		bad = true
	}
	if bad {
		return "", "", &Problem{422, "INVALID_NAME", "name"}
	}
	return s, cases.Fold().String(s), nil
}
func nullable(s string) any {
	if s == "" {
		return nil
	}
	return s
}
func stamp(n int64) string { return time.UnixMilli(n).UTC().Format(time.RFC3339Nano) }
func nullStamp(n sql.NullInt64) any {
	if !n.Valid {
		return nil
	}
	return stamp(n.Int64)
}
func str(n int64) string { return strconv.FormatInt(n, 10) }

type Query interface {
	Exec(string, ...any) (sql.Result, error)
	Query(string, ...any) (*sql.Rows, error)
	QueryRow(string, ...any) *sql.Row
}
type User struct {
	ID, Username, DisplayName, Hash, Role, Status string
	MustChange                                    bool
	Revision, Created                             int64
}

func (u User) JSON() M {
	return M{"id": u.ID, "username": u.Username, "display_name": u.DisplayName, "role": u.Role, "status": u.Status, "must_change_password": false, "revision": u.Revision, "created_at": stamp(u.Created)}
}

const userCols = "id,username,display_name,password_hash,role,status,must_change_password,revision,created_at"

func getUser(q Query, id string) (u User, e error) {
	e = q.QueryRow("SELECT "+userCols+" FROM users WHERE id=?", id).Scan(&u.ID, &u.Username, &u.DisplayName, &u.Hash, &u.Role, &u.Status, &u.MustChange, &u.Revision, &u.Created)
	return
}

type Workspace struct {
	ID, Kind, Name             string
	Owner, Group, Member, Root sql.NullString
	Revision, Created          int64
}

func workspace(q Query, id string) (w Workspace, e error) {
	e = q.QueryRow("SELECT id,kind,name,owner_user_id,group_id,member_permission,root_id,revision,created_at FROM workspaces WHERE id=?", id).Scan(&w.ID, &w.Kind, &w.Name, &w.Owner, &w.Group, &w.Member, &w.Root, &w.Revision, &w.Created)
	return
}

type Node struct {
	ID, Workspace, Kind, Name, NameKey, State, Creator     string
	Parent, Mime, Manifest, Blob, DeletedBy, RestoreParent sql.NullString
	Size, Deleted                                          sql.NullInt64
	Revision, Created, Modified                            int64
}

const nodeCols = "id,workspace_id,parent_id,kind,name,name_key,size_bytes,mime_type,manifest_sha256,blob_key,revision,state,created_by,created_at,modified_at,deleted_at,deleted_by,restore_parent_id"

type scanner interface{ Scan(...any) error }

func scanNode(s scanner) (n Node, e error) {
	e = s.Scan(&n.ID, &n.Workspace, &n.Parent, &n.Kind, &n.Name, &n.NameKey, &n.Size, &n.Mime, &n.Manifest, &n.Blob, &n.Revision, &n.State, &n.Creator, &n.Created, &n.Modified, &n.Deleted, &n.DeletedBy, &n.RestoreParent)
	return
}
func node(q Query, id string) (Node, error) {
	n, e := scanNode(q.QueryRow("SELECT "+nodeCols+" FROM nodes WHERE id=?", id))
	if errors.Is(e, sql.ErrNoRows) {
		e = fail(404, "NOT_FOUND")
	}
	return n, e
}

type Rights struct{ Read, Write, Share, Restore, Purge, Override bool }

func (n Node) JSON(p Rights) M {
	var sz any
	if n.Size.Valid {
		sz = str(n.Size.Int64)
	}
	return M{"id": n.ID, "workspace_id": n.Workspace, "parent_id": nullable(n.Parent.String), "kind": n.Kind, "name": n.Name, "size_bytes": sz, "mime_type": nullable(n.Mime.String), "manifest_sha256": nullable(n.Manifest.String), "revision": n.Revision, "state": n.State, "created_by": n.Creator, "created_at": stamp(n.Created), "modified_at": stamp(n.Modified), "deleted_at": nullStamp(n.Deleted), "deleted_by": nullable(n.DeletedBy.String), "restore_parent_id": nullable(n.RestoreParent.String), "can_read": p.Read, "can_write": p.Write, "can_share": p.Share, "can_restore": p.Restore, "can_purge": p.Purge, "admin_read_override": p.Override}
}
func revision(header string, n int64) error {
	if header == "" {
		return fail(428, "PRECONDITION_REQUIRED")
	}
	if header != fmt.Sprintf(`"r%d"`, n) {
		return fail(412, "REVISION_MISMATCH")
	}
	return nil
}
func dbProblem(e error) error {
	if e == nil {
		return nil
	}
	var p *Problem
	if errors.As(e, &p) {
		return e
	}
	s := e.Error()
	if strings.Contains(s, "UNIQUE constraint") {
		return fail(409, "NAME_CONFLICT")
	}
	if strings.Contains(s, "database is locked") {
		return fail(503, "DATABASE_BUSY")
	}
	return fail(503, "STORAGE_UNAVAILABLE")
}

package app

import "strings"

// Map denied operations to the same audit vocabulary as successful operations.
// Only syntactically valid input IDs are retained; no resource lookup is needed.
func deniedAction(r *Request) (action, targetType, target string) {
	p := strings.Split(strings.TrimPrefix(r.R.URL.Path, "/api/v1/"), "/")
	if len(p) == 0 {
		return
	}
	switch p[0] {
	case "nodes":
		targetType = "node"
		if len(p) == 1 {
			action = "node.create"
		} else if len(p) > 2 {
			switch p[2] {
			case "content":
				action = "file.download"
				if r.R.URL.Query().Get("disposition") == "preview" {
					action = "file.preview"
				}
			case "preview":
				action = "file.preview"
			case "rename", "move", "trash", "restore", "purge":
				action = "node." + p[2]
			case "grants":
				action = "grant.upsert"
				if r.R.Method == "DELETE" {
					action = "grant.delete"
				}
			}
		}
	case "uploads":
		targetType = "upload"
		if len(p) == 1 {
			action = "upload.create"
		} else if len(p) > 2 && p[2] == "complete" {
			action = "upload.complete"
		} else if r.R.Method == "DELETE" {
			action = "upload.cancel"
		}
	case "admin":
		if len(p) > 1 {
			singular := map[string]string{"users": "user", "groups": "group", "workspaces": "workspace"}[p[1]]
			if singular != "" {
				targetType = singular
				action = singular + ".update"
				if len(p) == 2 && r.R.Method == "POST" {
					action = singular + ".create"
				}
				if len(p) > 3 && p[3] == "reset-password" {
					action = "user.reset_password"
				}
				if len(p) > 2 && validID(p[2]) == nil {
					target = p[2]
				}
			}
		}
	}
	if target == "" && len(p) > 1 && validID(p[1]) == nil {
		target = p[1]
	}
	if (r.R.Method == "GET" || r.R.Method == "HEAD") && action != "file.download" && action != "file.preview" {
		return "", "", ""
	}
	return
}

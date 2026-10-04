package app

// Retain legacy columns for database/API compatibility, but clear the old
// restriction before accepting traffic. Existing passwords and sessions survive.
func (a *App) clearPasswordChangeRequirements() error {
	tx, e := a.DB.Write.Begin()
	if e != nil {
		return e
	}
	defer tx.Rollback()
	if _, e = tx.Exec("UPDATE users SET must_change_password=0,revision=revision+1,updated_at=? WHERE must_change_password=1", a.now().UnixMilli()); e != nil {
		return e
	}
	if _, e = tx.Exec("UPDATE sessions SET password_change_only=0 WHERE password_change_only=1"); e != nil {
		return e
	}
	return tx.Commit()
}

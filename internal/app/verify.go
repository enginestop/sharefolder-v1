package app

import (
	"os"
)

func (a *App) VerifyStorage() error {
	rows, e := a.DB.Read.Query("SELECT blob_key,size_bytes FROM nodes WHERE kind='file' AND state<>'PURGING'")
	if e != nil {
		return e
	}
	defer rows.Close()
	for rows.Next() {
		var id string
		var size int64
		if e = rows.Scan(&id, &size); e != nil {
			return e
		}
		path, e := a.filePath("blobs", id)
		if e != nil {
			return e
		}
		info, e := os.Stat(path)
		if e != nil {
			return e
		}
		if info.Size() != size {
			return fail(503, "STORAGE_CONFLICT")
		}
	}
	return rows.Err()
}

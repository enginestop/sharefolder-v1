package web

import (
	"embed"
	"io/fs"
)

//go:embed templates/* static/*
var files embed.FS

func Static() fs.FS {
	f, e := fs.Sub(files, "static")
	if e != nil {
		panic(e)
	}
	return f
}
func Shell() string {
	b, e := files.ReadFile("templates/shell.html")
	if e != nil {
		panic(e)
	}
	return string(b)
}

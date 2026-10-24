//go:build noui

package server

import (
	"embed"
	"io/fs"
)

//go:embed all:headlessdist
var headlessDist embed.FS

var webDistFS = func() fs.FS {
	files, err := fs.Sub(headlessDist, "headlessdist")
	if err != nil {
		panic(err)
	}
	return files
}()

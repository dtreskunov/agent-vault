//go:build !noui

package server

import "embed"

//go:embed all:webdist
var webDistFS embed.FS

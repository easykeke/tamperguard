// Package webui embeds the admin console so the control plane ships as a
// single binary with no external asset files and no build step.
package webui

import (
	"embed"
	"io/fs"
)

//go:embed index.html app.js style.css
var files embed.FS

// FS returns the embedded admin console.
func FS() fs.FS { return files }

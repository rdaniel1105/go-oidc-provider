package handler

import (
	"embed"
	"fmt"
	"html/template"
	"time"
)

// nowUTC returns the current wall-clock time in UTC. Centralizing it lets
// tests swap the clock if a deterministic timestamp ever becomes useful;
// for now it is just a thin wrapper around time.Now.
func nowUTC() time.Time { return time.Now().UTC() }

//go:embed templates/*.html
var templatesFS embed.FS

// templates is the parsed template set, loaded once at process start. All
// templates ship from internal/api/handler/templates and are referenced by
// filename without the directory prefix (e.g. "login.html").
var templates = mustParseTemplates()

func mustParseTemplates() *template.Template {
	t, err := template.ParseFS(templatesFS, "templates/*.html")
	if err != nil {
		panic(fmt.Sprintf("handler: parse templates: %v", err))
	}
	return t
}

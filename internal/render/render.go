package render

import (
	"bytes"
	"fmt"
	"html/template"
	"net/http"

	"github.com/sglmr/csvdiff/assets"
	"github.com/sglmr/csvdiff/internal/funcs"
)

// Page renders a template page with the provided data and HTTP status code.
// It's a convenience wrapper around PageWithHeaders with no additional headers.
func Page(w http.ResponseWriter, status int, data any, pagePath string) error {
	return PageWithHeaders(w, status, data, nil, pagePath)
}

// PageWithHeaders renders a template page with the provided data, HTTP status code,
// and custom HTTP headers. This function combines the base template, partials, and named page templates.
func PageWithHeaders(w http.ResponseWriter, status int, data any, headers http.Header, pageName string) error {
	// Define templates to be included for this page render
	patterns := []string{"base.tmpl", "partials/*.tmpl", fmt.Sprintf("pages/%s", pageName)}

	// Render the base template with the specified patterns
	return NamedTemplateWithHeaders(w, status, data, headers, "base", patterns...)
}

// NamedTemplate renders a specific named template with the provided data and HTTP status code.
// It's a convenience wrapper around NamedTemplateWithHeaders with no additional headers.
func NamedTemplate(w http.ResponseWriter, status int, data any, templateName string, patterns ...string) error {
	return NamedTemplateWithHeaders(w, status, data, nil, templateName, patterns...)
}

// NamedTemplateWithHeaders renders a specific named template with the provided data,
// HTTP status code, and custom HTTP headers.
func NamedTemplateWithHeaders(w http.ResponseWriter, status int, data any, headers http.Header, templateName string, patterns ...string) error {
	// Prepend "templates/" to all patterns to make them relative to the root
	for i := range patterns {
		patterns[i] = "templates/" + patterns[i]
	}

	// Create a new template with custom functions and parse all template files
	// from the embedded filesystem
	ts, err := template.New("").Funcs(funcs.TemplateFuncs).ParseFS(assets.EmbeddedFiles, patterns...)
	if err != nil {
		return fmt.Errorf("template.New: %w", err)
	}

	// Create a buffer to store the rendered template output
	buf := new(bytes.Buffer)

	// Execute the specified template with the provided data
	err = ts.ExecuteTemplate(buf, templateName, data)
	if err != nil {
		return fmt.Errorf("ExecuteTemplate: %w", err)
	}

	// Set any provided custom HTTP headers
	for key, value := range headers {
		w.Header()[key] = value
	}

	// Set the HTTP status code
	w.WriteHeader(status)
	buf.WriteTo(w)

	// Write the rendered template to the HTTP response
	return nil
}

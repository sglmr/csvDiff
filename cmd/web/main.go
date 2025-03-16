package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"runtime/debug"
	"strings"
	"sync"
	"syscall"
	"time"
	"unicode/utf8"

	"github.com/sglmr/csvdiff/assets"
	"github.com/sglmr/csvdiff/internal/render"
	"github.com/sglmr/csvdiff/internal/vcs"
)

//=============================================================================
// Top level application functions
//=============================================================================

func main() {
	// Get the background context to pass through the application
	ctx := context.Background()

	// Run the application
	if err := RunApp(ctx, os.Stdout, os.Args, os.Getenv); err != nil {
		fmt.Fprintf(os.Stderr, "%s\n", err)
		os.Exit(1)
		return
	}
}

// NewServer is a constructor that takes in all dependencies as arguments
func NewServer(logger *slog.Logger, devMode bool) http.Handler {
	// Create a serve mux
	logger.Debug("creating server")
	mux := http.NewServeMux()

	// Register the home handler for the root route
	httpHandler := AddRoutes(mux, logger, devMode)

	return httpHandler
}

func RunApp(
	ctx context.Context,
	w io.Writer,
	args []string,
	getenv func(string) string,
) error {
	ctx, cancel := signal.NotifyContext(ctx, os.Interrupt, syscall.SIGINT, syscall.SIGTERM)
	defer cancel()

	// Create a waitgroup with 1 item for handling shutdown
	wg := sync.WaitGroup{}
	wg.Add(1)

	// New Flag set
	fs := flag.NewFlagSet(args[0], flag.ExitOnError)

	host := fs.String("host", "0.0.0.0", "Server host")
	port := fs.String("port", "", "Server port")
	devMode := fs.Bool("dev", false, "Development mode. Displays stack trace & more verbose logging")

	// Parse the flags
	err := fs.Parse(args[1:])
	if err != nil {
		return fmt.Errorf("error parsing flags: %w", err)
	}

	// Get port from environment
	if *port == "" {
		*port = os.Getenv("PORT")
	}
	if *port == "" {
		*port = "8000"
	}

	// Create a new logger
	logLevel := &slog.LevelVar{}
	logLevel.Set(slog.LevelInfo)
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{
		Level: logLevel,
	}))

	switch {
	case *devMode:
		// Change log level to debug
		logLevel.Set(slog.LevelDebug)

	default:
		// Change log level to warn
		logLevel.Set(slog.LevelWarn)
	}

	// Set up router
	srv := NewServer(logger, *devMode)

	// Configure an http server
	httpServer := &http.Server{
		Addr:         net.JoinHostPort(*host, *port),
		Handler:      srv,
		ErrorLog:     slog.NewLogLogger(logger.Handler(), slog.LevelWarn),
		IdleTimeout:  time.Minute,
		ReadTimeout:  5 * time.Second,
		WriteTimeout: 10 * time.Second,
	}

	// This pattern is starts a server background while the main program continues with other tasks.
	// The main program can later stop the server using httpServer.Shutdown().
	go func() {
		logger.Info("application running (press ctrl+C to quit)", "address", fmt.Sprintf("http://%s", httpServer.Addr))

		// httpServer.ListenAndServe() begins listening for HTTP requests
		// This method blocks (runs forever) until the server is shut down
		if err := httpServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			// Print an error if any error other than http.ErrServerclosed shows up
			logger.Error("listen and serve error", "error", err)
			// Send SIGTERM to self to shutdown the application
			p, _ := os.FindProcess(os.Getpid())
			p.Signal(syscall.SIGTERM)
		}
	}()

	// Start a goroutine to handle server shutdown
	go func() {
		// The waitgroup counter will decrement and signal complete at
		// the end of this function
		defer wg.Done()

		// This blocks the goroutine until the ctx context is cancelled
		<-ctx.Done()
		logger.Info("waiting for application to shutdown")

		// Create an empty context for the shutdown process with a 10 second timer
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()

		// Initiate a graceful shutdown of the server and handle any errors
		if err := httpServer.Shutdown(shutdownCtx); err != nil {
			logger.Error("error shutting down http server: %s\n", "error", err)
		}
	}()
	// Makes the goroutine wait until shutdown starts
	wg.Wait()
	logger.Info("application shutdown complete")
	return nil
}

//=============================================================================
// Helper functions
//=============================================================================

// AddRoutes adds all the routes to the mux
func AddRoutes(mux *http.ServeMux, logger *slog.Logger, devMode bool) http.Handler {
	// Set up file server for embedded static files
	// fileserver := http.FileServer(http.FS(assets.EmbeddedFiles))
	fileServer := http.FileServer(http.FS(staticFileSystem{assets.EmbeddedFiles}))
	mux.Handle("GET /static/", CacheControlMW("31536000")(fileServer))

	mux.Handle("GET /", home(logger, devMode))
	mux.Handle("POST /", home(logger, devMode))

	mux.Handle("GET /health/", health())

	// Add recoverPanic middleware
	handler := RecoverPanicMW(mux, logger, devMode)
	handler = SecureHeadersMW(handler)
	handler = LogRequestMW(logger)(handler)

	// Return the handler
	return handler
}

// ServerError handles server error http responses.
func ServerError(w http.ResponseWriter, r *http.Request, err error, logger *slog.Logger, showTrace bool) {
	// TODO: find some way of reporting the server error
	// app.reportServerError(r, err)

	message := "The server encountered a problem and could not process your request"

	// Display the stack trace on the web page if env is development is on
	if showTrace {
		body := fmt.Sprintf("%s\n\n%s", err, string(debug.Stack()))
		http.Error(w, body, http.StatusInternalServerError)
		return
	}
	logger.Error("server error", "status", http.StatusInternalServerError, "error", err)

	http.Error(w, message, http.StatusInternalServerError)
}

// NotFound handles not found http responses.
func NotFound(w http.ResponseWriter, r *http.Request) {
	message := "The requested resource could not be found"
	http.Error(w, message, http.StatusNotFound)
}

// BadRequest hadles bad request http responses.
func BadRequest(w http.ResponseWriter, r *http.Request, err error) {
	http.Error(w, err.Error(), http.StatusBadRequest)
}

//=============================================================================
// Routes/Views/HTTP handlers
//=============================================================================

// home handles the root route
func home(logger *slog.Logger, showTrace bool) http.HandlerFunc {
	type Form struct {
		Validator
	}

	return func(w http.ResponseWriter, r *http.Request) {
		// Redirect non-root paths to root
		// TODO: write a test for this someday
		if r.URL.Path != "/" {
			NotFound(w, r)
			return
		}

		data := newTemplateData(r)
		form := Form{}

		if r.Method == http.MethodPost {
			// Maximum upload size of 10 MB
			err := r.ParseMultipartForm(10 << 20)
			if err != nil {
				form.AddError("Form", "Could not process the files provided.")
			}

			// Get the Key field
			key := r.Form.Get("key")
			form.Check(MinRunes(key, 1), "Key", "Key is a required field")
			form.Check(MaxRunes(key, 200), "key", "Key must be less than 200 characters")

			// Get File1
			file1, handler1, err := r.FormFile("file1")
			if err != nil {
				form.AddError("File1", "Could not process file 1.")
			}
			// Validate File1 is a CSV file
			if filepath.Ext(handler1.Filename) != ".csv" {
				form.AddError("File1", "This file must be a CSV file ending in '.csv'")
			}

			// Get File2
			file2, handler2, err := r.FormFile("file2")
			if err != nil {
				form.AddError("File2", "Could not process file 2.")
			}
			// Validate File2 is a CSV file
			if filepath.Ext(handler2.Filename) != ".csv" {
				form.AddError("File2", "This file must be a CSV file ending in '.csv'")
			}

			if form.Valid() {
				// Try to diff the files
				mismatches, err := findMismatches(logger, file1, file2, key, handler1.Filename, handler2.Filename)
				if err != nil {
					ServerError(w, r, err, logger, showTrace)
					return
				}

				// Set headers
				w.Header().Set("Content-Type", "text/csv")
				w.Header().Set("Content-Disposition", `attachment; filename="mismatches.csv"`)
				w.Header().Set("Content-Length", fmt.Sprintf("%d", len(mismatches)))

				// Write the mismatch data to the response
				if _, err := w.Write(mismatches); err != nil {
					ServerError(w, r, err, logger, showTrace)
					return
				}

				// Return to avoid writing anything else in the response
				return
			}

		}

		// Render the home page with the csv file form
		data["Form"] = form
		err := render.Page(w, http.StatusOK, data, "home.tmpl")
		if err != nil {
			ServerError(w, r, err, logger, showTrace)
			return
		}
	}
}

// health handles a healthcheck response "OK"
func health() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		fmt.Fprintln(w, "status: OK")
		fmt.Fprintln(w, "ver: ", vcs.Version())
	}
}

//=============================================================================
// Validation helpers
//=============================================================================

// newTemplateData constructs a map of data to pass into templates
func newTemplateData(r *http.Request) map[string]any {
	return map[string]any{
		"Version": vcs.Version(),
	}
}

//=============================================================================
// Middleware functions
//=============================================================================

// staticFileSystem is a custom type that embeds the standard http.FileSystem for serving static files
type staticFileSystem struct {
	fs fs.FS
}

// Open is a method on the staticFileSystem to only serve files in the
// static embedded file folder without directory listings
func (sfs staticFileSystem) Open(path string) (fs.File, error) {
	// If the file isn't in the /static directory, don't return it
	if !strings.HasPrefix(path, "static") {
		return nil, fs.ErrNotExist
	}

	// Try to open the file
	f, err := sfs.fs.Open(path)
	if err != nil {
		return nil, err
	}

	// os.Stat to determine if the path is a file or directory
	s, err := f.Stat()
	if err != nil {
		return nil, err
	}

	// If the file is a directory, check for an index.html file
	if s.IsDir() {
		index := filepath.Join(path, "index.html")
		if _, err := sfs.fs.Open(index); err != nil {
			closeErr := f.Close()
			if closeErr != nil {
				return nil, closeErr
			}
			return nil, err
		}
	}

	return f, nil
}

// CacheControlMW sets the Cache-Control header
func CacheControlMW(age string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Cache-Control", fmt.Sprintf("public, max-age=%s", age))
			next.ServeHTTP(w, r)
		})
	}
}

// RecoverPanicMW recovers from panics to avoid crashing the whole server
func RecoverPanicMW(next http.Handler, logger *slog.Logger, showTrace bool) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			err := recover()
			if err != nil {
				ServerError(w, r, fmt.Errorf("%s", err), logger, showTrace)
			}
		}()

		next.ServeHTTP(w, r)
	})
}

// SecureHeadersMW sets security headers for the whole application
func SecureHeadersMW(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Referrer-Policy", "origin-when-cross-origin")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "deny")
		w.Header().Set("X-XSS-Protection", "0")

		next.ServeHTTP(w, r)
	})
}

// LogRequestMW logs the http request
func LogRequestMW(logger *slog.Logger) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			var (
				ip     = r.RemoteAddr
				proto  = r.Proto
				method = r.Method
				uri    = r.URL.RequestURI()
			)
			logger.Info("request", "ip", ip, "proto", proto, "method", method, "uri", uri)
			next.ServeHTTP(w, r)
		})
	}
}

//=============================================================================
// Validator (validation) functions
//=============================================================================

// Validator is a type with helper functions for Validation
type Validator struct {
	Errors map[string]string
}

// Valid returns 'true' when there are no errors in the map
func (v Validator) Valid() bool {
	return !v.HasErrors()
}

// HasErrors returns 'true' when there are errors in the map
func (v Validator) HasErrors() bool {
	return len(v.Errors) != 0
}

// AddError adds a message for a given key to the map of errors.
func (v *Validator) AddError(key, message string) {
	if v.Errors == nil {
		v.Errors = map[string]string{}
	}

	if _, exists := v.Errors[key]; !exists {
		v.Errors[key] = message
	}
}

// Check will add an error message to the specified key if ok is 'false'.
func (v *Validator) Check(ok bool, key, message string) {
	if !ok {
		v.AddError(key, message)
	}
}

// -------------- Validation checks functions --------------------

// NotBlank returns true when a string is not empty.
func NotBlank(value string) bool {
	return strings.TrimSpace(value) != ""
}

// MinRunes returns true when the string is longer than n runes.
func MinRunes(value string, n int) bool {
	return utf8.RuneCountInString(value) >= n
}

// MaxRunes returns true when the string is <= n runes.
func MaxRunes(value string, n int) bool {
	return utf8.RuneCountInString(value) <= n
}

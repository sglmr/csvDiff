package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"path/filepath"
	"reflect"
	"regexp"
	"runtime"
	"runtime/debug"
	"strings"
	"sync"
	"syscall"
	"time"
	"unicode/utf8"

	"github.com/alexedwards/scs/v2"
	"github.com/justinas/nosurf"
	"github.com/sglmr/gowebstart/assets"
	"github.com/sglmr/gowebstart/internal/email"
	"github.com/sglmr/gowebstart/internal/render"
	"github.com/sglmr/gowebstart/internal/vcs"
	"golang.org/x/crypto/bcrypt"
	"golang.org/x/exp/constraints"
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
func NewServer(
	logger *slog.Logger,
	devMode bool,
	mailer email.MailerInterface,
	username, password string,
	wg *sync.WaitGroup,
	sessionManager *scs.SessionManager,
) http.Handler {
	// Create a serve mux
	logger.Debug("creating server")
	mux := http.NewServeMux()

	// Register the home handler for the root route
	httpHandler := AddRoutes(mux, logger, devMode, mailer, username, password, wg, sessionManager)

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
	username := fs.String("username", "admin", "Username basic auth")
	password := fs.String("password", `$2a$10$yIdGuTfOlZEA00kpreh2yuTihYQs9WAjeoIu/81AMWTVt9.Ocef5O`, "Password for basic auth ('password' by default)")
	smtpHost := fs.String("smtp-host", "", "Email smtp host")
	smtpPort := fs.Int("smtp-port", 25, "Email smtp port")
	smtpUsername := fs.String("smtp-username", "", "Email smtp username")
	smtpPassword := fs.String("smtp-password", "", "Email smtp password")
	smtpFrom := fs.String("smtp-from", "Eample Name <no-reply@example.com>", "Email smtp Sender")

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

	// Create a mailer for sending emails
	var mailer email.MailerInterface
	switch {
	case *devMode:
		// Change log level to debug
		logLevel.Set(slog.LevelDebug)

		// Configure email to send to log
		mailer = email.NewLogMailer(logger)
	default:
		// Configure a mailer to send real emails
		mailer, err = email.NewMailer(*smtpHost, *smtpPort, *smtpUsername, *smtpPassword, *smtpFrom)
		if err != nil {
			logger.Error("smtp configuration error", "error", err)
			return fmt.Errorf("smtp mailer setup failed: %w", err)
		}
	}

	// Session manager configuration
	sessionManager := scs.New()
	sessionManager.Lifetime = 24 * time.Hour

	// Set up router
	srv := NewServer(logger, *devMode, mailer, *username, *password, &wg, sessionManager)

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

// BackgroundTask executes a function in a background goroutine with proper error handling.
func BackgroundTask(wg *sync.WaitGroup, logger *slog.Logger, fn func() error) {
	// Increment waitgroup to track whether this background task is complete or not
	wg.Add(1)

	// Launch a goroutine to run the task in
	go func() {
		// decrement the waitgroup after the task completes
		defer wg.Done()

		// Get the name of the function
		funcName := runtime.FuncForPC(reflect.ValueOf(fn).Pointer()).Name()

		// Recover any panics in the task function so that
		// a panic doesn't kill the whole application
		defer func() {
			err := recover()
			if err != nil {
				logger.Error("task", "name", funcName, "error", fmt.Errorf("%s", err))
			}
		}()

		// Execute the provided function, logging any errors
		err := fn()
		if err != nil {
			logger.Error("task", "name", funcName, "error", err)
		}
	}()
}

//=============================================================================
// Helper functions
//=============================================================================

// AddRoutes adds all the routes to the mux
func AddRoutes(
	mux *http.ServeMux,
	logger *slog.Logger,
	devMode bool,
	mailer email.MailerInterface,
	username, password string,
	wg *sync.WaitGroup,
	sessionManager *scs.SessionManager,
) http.Handler {
	// Set up file server for embedded static files
	// fileserver := http.FileServer(http.FS(assets.EmbeddedFiles))
	fileServer := http.FileServer(http.FS(staticFileSystem{assets.EmbeddedFiles}))
	mux.Handle("GET /static/", CacheControlMW("31536000")(fileServer))

	mux.Handle("GET /", home(logger, devMode, sessionManager))
	// TODO: Figure out how to wrap this with nosurf
	c := contact(logger, devMode, wg, mailer, sessionManager)
	mux.Handle("GET /contact/", CsrfMW(c))
	mux.Handle("POST /contact/", CsrfMW(c))
	mux.Handle("GET /health/", health())
	mux.Handle("GET /send-mail", sendEmail(mailer, logger, wg))

	mux.Handle("GET /protected/", BasicAuthMW(username, password, logger, devMode)(protected()))

	// Add recoverPanic middleware
	handler := RecoverPanicMW(mux, logger, devMode)
	handler = SecureHeadersMW(handler)
	handler = LogRequestMW(logger)(handler)
	handler = sessionManager.LoadAndSave(handler)

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
func home(
	logger *slog.Logger,
	showTrace bool,
	sessionManager *scs.SessionManager,
) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Redirect non-root paths to root
		// TODO: write a test for this someday
		if r.URL.Path != "/" {
			NotFound(w, r)
			return
		}
		putFlashMessage(r, LevelSuccess, "Welcome!", sessionManager)
		putFlashMessage(r, LevelSuccess, "You made it!", sessionManager)

		data := newTemplateData(r, sessionManager)

		if err := render.Page(w, http.StatusOK, data, "home.tmpl"); err != nil {
			ServerError(w, r, err, logger, showTrace)
			return
		}
	}
}

// contact handles rendering a contact page
func contact(
	logger *slog.Logger,
	showTrace bool,
	wg *sync.WaitGroup,
	mailer email.MailerInterface,
	sessionManager *scs.SessionManager,
) http.HandlerFunc {
	type contactForm struct {
		Name    string
		Email   string
		Message string
		Validator
	}
	return func(w http.ResponseWriter, r *http.Request) {
		data := newTemplateData(r, sessionManager)
		data["Form"] = contactForm{}

		if r.Method == http.MethodPost {
			if err := r.ParseForm(); err != nil {
				BadRequest(w, r, err)
				return
			}

			form := contactForm{}

			// Populate the form data
			form.Name = r.FormValue("name")
			form.Email = r.FormValue("email")
			form.Message = r.FormValue("message")

			// Validate the form
			form.Check(NotBlank(form.Name), "Name", "Name is required.")
			form.Check(MaxRunes(form.Name, 100), "Name", "Name must be less than 100 characters.")

			form.Check(NotBlank(form.Email), "Email", "Email is required.")
			form.Check(IsEmail(form.Email), "Email", "Email must be a valid email address.")

			form.Check(NotBlank(form.Message), "Message", "Message is required.")
			form.Check(MaxRunes(form.Message, 1000), "Message", "Message must be less than 1,000 characters.")

			if form.Valid() {
				// Email the form message
				BackgroundTask(wg, logger, func() error {
					return mailer.Send("Recipient <recipient@example.com>", "Reply-To <reply-to@example.com>", form, "example.tmpl")
				})
				// Render the contact success page
				err := render.Page(w, http.StatusFound, data, "contact-success.tmpl")
				if err != nil {
					ServerError(w, r, err, logger, showTrace)
					return
				}
				return
			}

			// Update the template data form so the page errors will render
			data["Form"] = form

		}

		// Render the contact.tmpl page
		err := render.Page(w, http.StatusOK, data, "contact.tmpl")
		if err != nil {
			ServerError(w, r, err, logger, showTrace)
			return
		}
	}
}

// sendEmail sends out a background email task
func sendEmail(mailer email.MailerInterface, logger *slog.Logger, wg *sync.WaitGroup) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		fmt.Fprint(w, "Email queued")
		emailData := map[string]any{
			"Name": "Person",
		}
		BackgroundTask(
			wg, logger,
			func() error {
				return mailer.Send("Recipient <recipient@example.com>", "Reply-To <reply-to@example.com>", emailData, "example.tmpl")
			})
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

// protected handles a page protected by basic authentication.
func protected() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		fmt.Fprint(w, "You're visiting a protected page!")
	}
}

//=============================================================================
// Validation helpers
//=============================================================================

// newTemplateData constructs a map of data to pass into templates
func newTemplateData(r *http.Request, sessionManager *scs.SessionManager) map[string]any {
	messages, ok := sessionManager.Pop(r.Context(), "messages").([]FlashMessage)
	if !ok {
		messages = []FlashMessage{}
	}

	return map[string]any{
		"CSRFToken": nosurf.Token(r),
		"Messages":  messages,
		"Version":   vcs.Version(),
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

// CsrfMW protects specific routes against CSRF.
func CsrfMW(next http.Handler) http.Handler {
	csrfHandler := nosurf.New(next)
	csrfHandler.SetBaseCookie(http.Cookie{
		HttpOnly: true,
		Path:     "/",
		Secure:   true,
	})
	return csrfHandler
}

// BasicAuthMW restricts routes for basic authentication
func BasicAuthMW(username, passwordHash string, logger *slog.Logger, showTrace bool) func(http.Handler) http.Handler {
	authError := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("WWW-Authenticate", `Basic realm="restricted", charset="UTF-8"`)

		message := "You must be authenticated to access this resource"
		http.Error(w, message, http.StatusUnauthorized)
	})

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Get basic auth credentials from the request
			requestUser, requestPass, ok := r.BasicAuth()
			if !ok {
				authError(w, r)
				return
			}

			// Check if the username matches the request
			if username != requestUser {
				authError(w, r)
				return
			}

			// Hash and compare the passwords
			err := bcrypt.CompareHashAndPassword([]byte(passwordHash), []byte(requestPass))
			switch {
			case errors.Is(err, bcrypt.ErrMismatchedHashAndPassword):
				authError(w, r)
				return
			case err != nil:
				ServerError(w, r, err, logger, showTrace)
				return
			}

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

var RgxEmail = regexp.MustCompile("^[a-zA-Z0-9.!#$%&'*+/=?^_`{|}~-]+@[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$")

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

// Between returns true when the value is between (inclusive) two values.
func Between[T constraints.Ordered](value, min, max T) bool {
	return value >= min && value <= max
}

// Matches returns true when the string matches a given regular expression.
func Matches(value string, rx *regexp.Regexp) bool {
	return rx.MatchString(value)
}

// In returns true when a value is in the safe list of values.
func In[T comparable](value T, safelist ...T) bool {
	for i := range safelist {
		if value == safelist[i] {
			return true
		}
	}
	return false
}

// AllIn returns true if all the values are in the safelist of values.
func AllIn[T comparable](values []T, safelist ...T) bool {
	for i := range values {
		if !In(values[i], safelist...) {
			return false
		}
	}
	return true
}

// NotIn returns true when the value is not in the blocklist of values.
func NotIn[T comparable](value T, blocklist ...T) bool {
	for i := range blocklist {
		if value == blocklist[i] {
			return false
		}
	}
	return true
}

// NoDuplicates returns true when there are no duplicates in the values
func NoDuplicates[T comparable](values []T) bool {
	uniqueValues := make(map[T]bool)

	for _, value := range values {
		uniqueValues[value] = true
	}

	return len(values) == len(uniqueValues)
}

// IsEmail returns true when the string value passes an email regular expression pattern.
func IsEmail(value string) bool {
	if len(value) > 254 {
		return false
	}

	return RgxEmail.MatchString(value)
}

// IsURL returns true if the value is a valid URL
func IsURL(value string) bool {
	u, err := url.ParseRequestURI(value)
	if err != nil {
		return false
	}

	return u.Scheme != "" && u.Host != ""
}

//=============================================================================
// Flash Message functions
//=============================================================================

type contextKey string

const flashMessageKey = "messages"

type FlashMessageLevel string

const (
	// Different FlashMessageLevel types
	LevelSuccess FlashMessageLevel = "success"
	LevelError   FlashMessageLevel = "error"
	LevelWarning FlashMessageLevel = "warning"
	LevelInfo    FlashMessageLevel = "info"
)

type FlashMessage struct {
	Level   FlashMessageLevel
	Message string
}

// putFlashMessage adds a flash message into the session manager
func putFlashMessage(r *http.Request, level FlashMessageLevel, message string, sessionManager *scs.SessionManager) {
	newMessage := FlashMessage{
		Level:   level,
		Message: message,
	}

	// Create a new flashMessageKey context key if one doesn't exist and add the message
	messages, ok := sessionManager.Get(r.Context(), flashMessageKey).([]FlashMessage)
	if !ok {
		sessionManager.Put(r.Context(), flashMessageKey, []FlashMessage{newMessage})
		return
	}

	// Add a flash message to an existing flashMessageKey context key
	messages = append(messages, newMessage)
	sessionManager.Put(r.Context(), flashMessageKey, messages)
}

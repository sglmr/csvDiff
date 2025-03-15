# Go Start

A lightweight, feature-rich Go web application template with built-in security features, session management, email functionality, and more.

This project template aims to reduce third party dependencies wherever possible. Most of the "code" for the project is in a single `cmd/web/main.go` file. Because (A) it's easier to give AI project context when most of the project is in a single file and (B) it's a simple starter template with minimal assumptions about how a project might evovle over time.

This project does not currently include any configuration for a database.

This project aims to avoid using receiver methods on handlers and other project functions. An application struct hanging off of every method is convenient and makes for pretty code, but there are also some negatives:

- Surprise dependency issues during testing
- Non-implicit dependencies
- More restrictive coupling of project components and structure

This project assumes you will be running it behind a reverse proxy service that handles HTTPS and certificates for you.

## Features

- **Complete Web Server**: HTTP server with graceful shutdown
- **Middleware Stack**:
  - Panic recovery
  - Secure headers
  - Request logging
  - CSRF protection
  - Basic authentication
  - Static asset caching
  - Session management
- **Email Support**: Send emails with configurable SMTP
- **Form Validation**: Comprehensive validation helpers
- **Flash Messages**: Session-based notifications system
- **Templating**: HTML template rendering with data context
- **Static File Serving**: Embedded static file handling
- **Development Mode**: Enhanced debugging with stack traces and additional logging.

## Getting Started

### Prerequisites

- Go 1.22 or higher
- [Task](https://taskfile.dev/) for project management commands.

### Installation

1. Clone the repository:

```bash
git clone https://github.com/sglmr/gowebstart.git
cd gowebstart
```

2. Replace "gowebstart" with your new project name.

3. Build the project:

```bash
task build
```

### Running the Server

Basic usage:

```bash
# Run the app
task run

# Run the app with live reload
task run:live
```

This will start the server on the default address `0.0.0.0:8000`.

### Command-Line Options

| Flag | Description | Default |
|------|-------------|---------|
| `-host` | Server host | `0.0.0.0` |
| `-port` | Server port | `8000` or `PORT` env variable |
| `-dev` | Development mode | `false` |
| `-username` | Basic auth admin username | `admin` |
| `-password` | Basic auth admin password | `password` (hashed) |
| `-smtp-host` | SMTP server host | `` |
| `-smtp-port` | SMTP server port | `25` |
| `-smtp-username` | SMTP username | `` |
| `-smtp-password` | SMTP password | `` |
| `-smtp-from` | Email sender | `Example Name <no-reply@example.com>` |

Example with custom options:

```bash
./gowebstart -port=3000 -dev -smtp-host=smtp.example.com -smtp-port=587 -smtp-username=user -smtp-password=pass
```

## SMTP Emails

The application includes methods for sending SMTP Emails. Email templates are configuratble in the `assets/emails` directory.

```go
err = mailer.Send(recipient string, replyTo string, data any, templates ...string)
```

## Background Tasks

The application includes a system for running asynchornous tasks using the `BackgroundTask` function.

```go
BackgroundTask(wg *sync.WaitGroup, logger *slog.Logger, fn func() error)
```

Background task system features:

- **Panic Recovery**: Tasks are isolated so panics don't crash the server
- **Logging**: Automatic error logging with the function name
- **WaitGroup Integration**: Proper shutdown handling with sync.WaitGroup
- **Graceful Shutdown**: Tasks tracked during server shutdown

Example usage:

```go
// Send an email in the background
BackgroundTask(
    wg, logger, 
    func() error {
        return mailer.Send("recipient@example.com", "reply-to@example.com", emailData, "email-template.tmpl")
    })

// Continue processing the request without waiting
```

This pattern is useful for operations like:

- Sending emails
- Processing uploaded files
- Running reports
- Performing database maintenance
- Any long-running task that shouldn't block the request handler

## Architecture

### Application Structure

- `assets/`: Folder for all project embedded files
  - `emails/`: Email templates
  - `static/`: Static files like CSS, Javascript, etc
  - `templates/`: Templates to render to HTML pages for the application
    - `pages/`: Main web page content to load, like "home.tmpl" or "about.tmpl"
    - `partials/`: Page partials, like a nav bar, footer, etc
    - `base.tmpl`: Base template for all pages and partials
- `cmd/`
  - `web/`
    - `main.go`: Entry point and server configuration
- `internal/`:
  - `asserts/`: Testing assert functions
  - `email/`: SMTP email functionality
  - `funcs/`: Template functions
  - `render/`: Template rendering helpers
  - `vcs/`: Version information

### Middleware

The application uses a composable middleware pattern:

```go
handler = RecoverPanicMW(mux, logger, devMode)
handler = SecureHeadersMW(handler)
handler = LogRequestMW(logger)(handler)
handler = sessionManager.LoadAndSave(handler)
```

### Using Basic Authentication

The project contains a `BasicAuthMW` middleware that you can use to protect the application, or specific routes with HTTP basic authentication.

You can try this out by visiting the [https://localhost:8000/protected/](https://localhost:8000/protected/) endpoint in any web browser and entering the default user name and password:

```
User name: admin
Password:  password
```

You can change the user name and password by setting the `--username` command-line flag and `--password` command-line flag. For example:

```sh
go run ./cmd/web -username='alice' --password='$2a$10$xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx'
```

Note: You will probably need to wrap the username and password in `'` quotes to prevent your shell interpreting dollar and slash symbols as special characters.

The value for the `-password` command-line flag should be a bcrypt hash of the password, not the plaintext password itself. An easy way to generate the bcrypt hash for a password is to use the `gophers.dev/cmds/bcrypt-tool` package like so:

```sh
go run gophers.dev/cmds/bcrypt-tool@latest hash 'your_pa55word'
```

There is also a helper "app" you can run in `cmd/hash/main.go` that prompts for and generates a password.

```sh
go run ./cmd/hash

   Enter password: 
Re-enter password:
    Password hash: $2a$10$xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
```

If you want to change the default values for username and password you can do so by editing the default command-line flag values in the `cmd/web/main.go` file.

## Request Handlers

Request handlers follow a standardized pattern:

```go
func handlerName(dependencies...) http.HandlerFunc {
    // Handler specific type, constant, or variable definitions
    return func(w http.ResponseWriter, r *http.Request) {
        // Handler logic
    }
}
```

### Background Tasks

Tasks like sending emails are handled in the background:

```go
BackgroundTask(wg, logger, func() error {
    return mailer.Send(...)
})
```

## Form Validation

The application includes a comprehensive validation system with the `Validator` struct.

```go
type Validator struct {
    Errors map[string]string
}
```

`Validator` includes methods for managing errors and validation. For Example:


```go
// Example ContactForm validation with Validator

type contactForm struct {
    Name    string
    Message string
    Validator
}

form := contactForm{}
form.Check(IsEmail(form.Email), "Email", "Email must be a valid email address.")
form.Check(NotBlank(form.Message), "Message", "Message is required.")

if form.HasErrors() { 
    // Do something with errors
}
// Do something with no errors
```

Available validators:
- `NotBlank`: Ensures string is not empty
- `MinRunes`/`MaxRunes`: Length validation
- `Between`: Range validation
- `Matches`: Regex validation
- `In`/`NotIn`: Value presence validation
- `NoDuplicates`: Uniqueness validation
- `IsEmail`: Email validation
- `IsURL`: URL validation

## Flash Messages

The application supports various flash message types. Flash messages are formatted and rendered in the `assets/templates/partials/flashMessages.tmpl` template.

```go
putFlashMessage(r, LevelSuccess, "Welcome!", sessionManager)
```

Message levels:
- `LevelSuccess`
- `LevelError`
- `LevelWarning`
- `LevelInfo`

## Customization

### Adding New Routes and Middleware

Add new routes and middleware in the `AddRoutes` function. This project takes advantage of the [Go 1.22 Routing Enhancements](https://go.dev/blog/routing-enhancements).

```go
func AddRoutes(mux *http.ServeMux, ...) http.Handler {
    // Existing routes...
    
    // Add your new route
    mux.Handle("GET /your-path", yourHandler(dependencies...))
    
    // Middleware...
    handler := middleware1(mux)
    handler = middleware2(handler)

    return handler
}
```

### Rendering pages from templates

Templates are rendered using the `render.Page` function. Template pages live in the `assets/templates/pages` directory.

A `newTemplateData` function prefills a map with commony used template data

```go
data := newTemplateData(r, sessionManager)
err := render.Page(w, http.StatusOK, data, "your-template.tmpl")
```

Template functions are managed in the `internal/funcs` package.

## License

[MIT License](LICENSE)

## External Dependencies

- github.com/alexedwards/scs/v2
- github.com/justinas/nosurf
- github.com/wneessen/go-mail
package email

import (
	"bytes"
	"log/slog"
	"testing"

	"github.com/sglmr/gowebstart/internal/assert"
)

func TestLogMailer_Send(t *testing.T) {
	// Create a buffer to capture log output
	var logBuffer bytes.Buffer

	// Create a test logger that writes to our buffer
	logger := slog.New(slog.NewTextHandler(&logBuffer, &slog.HandlerOptions{
		Level: slog.LevelInfo,
	}))

	// Create the LogMailer with our test logger
	logMailer := NewLogMailer(logger)

	// Test data
	recipient := "test@example.com"
	replyTo := "reply@example.com"
	testData := map[string]string{"name": "Test User", "message": "Hello World"}
	patterns := []string{"welcome.tmpl", "notification.tmpl"}

	// Call the Send method
	err := logMailer.Send(recipient, replyTo, testData, patterns...)

	// Assert no error was returned
	assert.NoError(t, err)

	// Assert the log StringContains the expected information
	logOutput := logBuffer.String()
	assert.StringContains(t, logOutput, "send email")
	assert.StringContains(t, logOutput, "recipient=test@example.com")
	assert.StringContains(t, logOutput, "name")
	assert.StringContains(t, logOutput, "Test User")
	assert.StringContains(t, logOutput, "message")
	assert.StringContains(t, logOutput, "Hello World")
	assert.StringContains(t, logOutput, "welcome.tmpl")
	assert.StringContains(t, logOutput, "notification.tmpl")
}

// TestLogMailerImplementsInterface ensures that LogMailer correctly implements MailerInterface
func TestLogMailerImplementsInterface(t *testing.T) {
	t.Parallel()
	// This is a compile time check that LogMailer implements the MailerInterface
	var _ MailerInterface = (*LogMailer)(nil)
}

// TestMailerImplementsInterface ensures that Mailer correctly implements MailerInterface
func TestMailerImplementsInterface(t *testing.T) {
	t.Parallel()
	var _ MailerInterface = (*Mailer)(nil)
}

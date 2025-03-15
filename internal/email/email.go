package email

import (
	"bytes"
	"log/slog"
	"time"

	"github.com/sglmr/gowebstart/assets"
	"github.com/sglmr/gowebstart/internal/funcs"

	"github.com/wneessen/go-mail"

	htmlTemplate "html/template"
	textTemplate "text/template"
)

const defaultTimeout = 10 * time.Second

// MailerInterface enables exchanging between a Mailer and LogMailer.
type MailerInterface interface {
	Send(recipient string, replyTo string, data any, templates ...string) error
}

// Mailer that sends SMTP emails
type Mailer struct {
	client *mail.Client
	from   string
}

// NewMailer initializes a new Mailer client for sending emails
func NewMailer(host string, port int, username, password, from string) (*Mailer, error) {
	client, err := mail.NewClient(host, mail.WithTimeout(defaultTimeout), mail.WithSMTPAuth(mail.SMTPAuthLogin), mail.WithPort(port), mail.WithUsername(username), mail.WithPassword(password))
	if err != nil {
		return nil, err
	}

	mailer := &Mailer{
		client: client,
		from:   from,
	}

	return mailer, nil
}

// Send an email to a recipient with data for a specified template name (patterns)
func (m *Mailer) Send(recipient string, replyTo string, data any, templates ...string) error {
	// Create a slice from the patterns argument
	for i := range templates {
		templates[i] = "emails/" + templates[i]
	}

	// Initialize a new mail message
	msg := mail.NewMsg()

	err := msg.To(recipient)
	if err != nil {
		return err
	}

	err = msg.ReplyTo(replyTo)
	if err != nil {
		return err
	}

	err = msg.From(m.from)
	if err != nil {
		return err
	}

	ts, err := textTemplate.New("").Funcs(funcs.TemplateFuncs).ParseFS(assets.EmbeddedFiles, templates...)
	if err != nil {
		return err
	}

	subject := new(bytes.Buffer)
	err = ts.ExecuteTemplate(subject, "subject", data)
	if err != nil {
		return err
	}

	msg.Subject(subject.String())

	plainBody := new(bytes.Buffer)
	err = ts.ExecuteTemplate(plainBody, "plainBody", data)
	if err != nil {
		return err
	}

	msg.SetBodyString(mail.TypeTextPlain, plainBody.String())

	if ts.Lookup("htmlBody") != nil {
		ts, err := htmlTemplate.New("").Funcs(funcs.TemplateFuncs).ParseFS(assets.EmbeddedFiles, templates...)
		if err != nil {
			return err
		}

		htmlBody := new(bytes.Buffer)
		err = ts.ExecuteTemplate(htmlBody, "htmlBody", data)
		if err != nil {
			return err
		}

		msg.AddAlternativeString(mail.TypeTextHTML, htmlBody.String())
	}

	for i := 1; i <= 3; i++ {
		err = m.client.DialAndSend(msg)

		if nil == err {
			return nil
		}

		if i != 3 {
			time.Sleep(2 * time.Second)
		}
	}

	return err
}

// LogMailer object for logging emails instead of sending them
type LogMailer struct {
	log *slog.Logger
}

// NewLogMailer creates a new logMailer object for logging emails instead of sending them
func NewLogMailer(l *slog.Logger) *LogMailer {
	return &LogMailer{
		log: l,
	}
}

// Send method takes the recipient email, template file name, and any dynamic data for the templates
// as an any parameter.
func (m *LogMailer) Send(recipient string, replyTo string, data any, templates ...string) error {
	m.log.Info("send email", "recipient", recipient, "replyTo", replyTo, "templates", templates, "data", data)
	return nil
}

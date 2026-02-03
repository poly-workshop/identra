package mail

import "github.com/poly-workshop/identra/internal/infrastructure/notification/smtp"

// Sender defines the interface for sending emails.
type Sender interface {
	SendEmail(msg smtp.Message) error
}

// NewSMTPSender creates a new SMTP-based mail sender.
func NewSMTPSender(cfg smtp.Config) Sender {
	return smtp.NewMailer(cfg)
}

// NewSenderFromConfig creates a mail sender based on configuration.
func NewSenderFromConfig(cfg smtp.Config) Sender {
	return smtp.NewMailer(cfg)
}

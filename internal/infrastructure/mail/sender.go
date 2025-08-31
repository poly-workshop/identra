package mail

import smtpmailer "github.com/poly-workshop/go-webmods/smtpmailer"

// Sender defines the interface for sending emails.
type Sender interface {
	SendEmail(msg smtpmailer.Message) error
}

// NewSMTPSender creates a new SMTP-based mail sender.
func NewSMTPSender(cfg smtpmailer.Config) Sender {
	return smtpmailer.NewMailer(cfg)
}

// NewSenderFromConfig creates a mail sender based on configuration.
func NewSenderFromConfig(cfg smtpmailer.Config) Sender {
	return smtpmailer.NewMailer(cfg)
}

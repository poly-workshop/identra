package app

import (
	"strings"

	"github.com/slhmy/identra/internal/identra"
	"github.com/slhmy/identra/internal/mail/smtp"
)

func buildMailer(cfg smtp.Config) identra.EmailSender {
	if strings.TrimSpace(cfg.Host) == "" {
		return nil
	}
	return smtpMailerAdapter{sender: smtp.NewMailer(cfg)}
}

type smtpMailerAdapter struct {
	sender *smtp.Mailer
}

func (a smtpMailerAdapter) SendEmail(message identra.EmailMessage) error {
	return a.sender.SendEmail(smtp.Message{
		ToEmails: message.ToEmails,
		Subject:  message.Subject,
		Body:     message.Body,
		IsHTML:   message.IsHTML,
	})
}

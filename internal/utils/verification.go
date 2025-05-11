package utils

import (
	"context"
	"fmt"
	"time"

	"cloud.google.com/go/firestore"
	"github.com/lijuuu/AuthenticationServiceMachineTest/config"
	resend "github.com/resendlabs/resend-go"
	"github.com/twilio/twilio-go"
	twilioApi "github.com/twilio/twilio-go/rest/api/v2010"
)

// SendVerification sends an OTP via email or SMS using configuration from Config
func SendVerification(ctx context.Context, firestoreClient *firestore.Client, cfg *config.Config, uid, recipient, verificationType, otp string, expiresAt time.Time) error {
	switch verificationType {
	case "email_verification", "password_reset":
		return sendEmailVerification(cfg, recipient, otp, verificationType)
	case "phone_verification":
		return sendPhoneVerification(cfg, recipient, otp)
	default:
		return fmt.Errorf("unsupported verification type: %s", verificationType)
	}
}

// sendEmailVerification sends an OTP via email using Resend.com
func sendEmailVerification(cfg *config.Config, email, otp, verificationType string) error {
	if cfg.Resend.APIKey == "" {
		return fmt.Errorf("resend API key not set in configuration")
	}

	client := resend.NewClient(cfg.Resend.APIKey)

	subject := "Verify Your Email"
	body := fmt.Sprintf("Your OTP is %s. It expires in 15 minutes.", otp)
	if verificationType == "password_reset" {
		subject = "Reset Your Password"
		body = fmt.Sprintf("Your password reset OTP is %s. It expires in 15 minutes.", otp)
	}

	params := &resend.SendEmailRequest{
		From:    cfg.Resend.From,
		To:      []string{email},
		Subject: subject,
		Html:    fmt.Sprintf("<p>%s</p>", body),
	}

	_, err := client.Emails.Send(params)
	if err != nil {
		return fmt.Errorf("failed to send email: %v", err)
	}

	return nil
}

// sendPhoneVerification sends an OTP via SMS using Twilio
func sendPhoneVerification(cfg *config.Config, phone, otp string) error {
	if cfg.Twilio.AccountSID == "" || cfg.Twilio.AuthToken == "" || cfg.Twilio.PhoneNumber == "" {
		return fmt.Errorf("twilio credentials not set in configuration")
	}

	client := twilio.NewRestClientWithParams(twilio.ClientParams{
		Username: cfg.Twilio.AccountSID,
		Password: cfg.Twilio.AuthToken,
	})

	params := &twilioApi.CreateMessageParams{}
	params.SetTo(phone)
	params.SetFrom(cfg.Twilio.PhoneNumber)
	params.SetBody(fmt.Sprintf("Your verification OTP is %s. It expires in 15 minutes.", otp))

	_, err := client.Api.CreateMessage(params)
	if err != nil {
		return fmt.Errorf("failed to send SMS: %v", err)
	}

	return nil
}

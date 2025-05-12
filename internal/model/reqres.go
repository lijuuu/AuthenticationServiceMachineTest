package model

import (
	"fmt"
	"time"

	"github.com/go-playground/validator/v10"
)

// ValidateRequest validates any request struct using go-playground/validator
func ValidateRequest(req interface{}) error {
	validate := validator.New()
	err := validate.Struct(req)
	if err != nil {
		if _, ok := err.(*validator.InvalidValidationError); ok {
			return fmt.Errorf("validation error: %v", err)
		}
		var errors []string
		for _, err := range err.(validator.ValidationErrors) {
			errors = append(errors, fmt.Sprintf("field %s: %s", err.Field(), err.Tag()))
		}
		return fmt.Errorf("validation failed: %s", errors)
	}
	return nil
}

type ErrorResponse struct {
	Status  string `json:"status"`
	Message string `json:"message"`
	Code    int    `json:"code"`
}

// SignupRequest - Structure for the user signup request
type SignupRequest struct {
	Email string `json:"email,omitempty" validate:"omitempty,email|required_without=Phone"`
	Phone string `json:"phone,omitempty" validate:"omitempty,e164|required_without=Email"`

	Password   string `json:"password" validate:"required,min=8,containsany=abcdefghijklmnopqrstuvwxyz,containsany=0123456789"`
	Username   string `json:"username" validate:"required,min=3"`
	FirstName  string `json:"first_name" validate:"omitempty"`
	SecondName string `json:"second_name" validate:"omitempty"`
}

// LoginRequest - Structure for the user login request
type LoginRequest struct {
	Credential    string `json:"credential" validate:"required"`
	Password      string `json:"password" validate:"required"`
	TwoFactorCode string `json:"two_factor_code" validate:"omitempty"`
}

// GuestLoginRequest - Structure for the guest login/signup request
type GuestLoginRequest struct {
	Username string `json:"username" validate:"required,min=3"`
}

// VerifyCredentialsRequest - Structure to verify credentials
type VerifyCredentialsRequest struct {
	Credential string `json:"credential" validate:"required"`
	OTP        string `json:"otp" validate:"required"`
}

// ForgotPasswordRequest - Structure for forgot password request
type ForgotPasswordRequest struct {
	Email string `json:"email" validate:"required,email"`
}

// ResetPasswordRequest - Structure for reset password request
type ResetPasswordRequest struct {
	Email    string `json:"email" validate:"required,email"`
	OTP      string `json:"otp" validate:"required,len=6"`
	Password string `json:"password" validate:"required,min=8,containsany=abcdefghijklmnopqrstuvwxyz,containsany=0123456789"`
}

// ChangeLoginRequest - Structure for changing login credentials
type ChangeLoginRequest struct {
	UID      string `json:"uid"`
	Password string `json:"password" validate:"required,min=8,containsany=abcdefghijklmnopqrstuvwxyz,containsany=0123456789"`
	NewEmail string `json:"new_email" validate:"email"`
}

// Enable2FARequest - Structure to enable 2FA request
type Enable2FARequest struct {
	UID string `json:"uid"`
}

// AddAltCredentialRequest - Structure for adding alternative credentials
type AddAltCredentialRequest struct {
	UID        string `json:"uid"`
	Credential string `json:"credential" validate:"required"`
}

// ChangePasswordRequest - Structure for the change password request
type ChangePasswordRequest struct {
	OldPassword string `json:"old_password" validate:"required"`
	NewPassword string `json:"new_password" validate:"required,min=8,containsany=abcdefghijklmnopqrstuvwxyz,containsany=0123456789"`
}

// VerifyEmailRequest - Structure for email verification request
type VerifyEmailRequest struct {
	Email string `json:"email" validate:"required,email"`
	OTP   string `json:"otp" validate:"required,len=6"`
}

// VerifyPhoneRequest - Structure for phone verification request
type VerifyPhoneRequest struct {
	Phone string `json:"phone" validate:"required,e164"`
	OTP   string `json:"otp" validate:"required,len=6"`
}

// ResendVerificationRequest - Structure for resending email/phone verification
type ResendVerificationRequest struct {
	Email string `json:"email,omitempty" validate:"omitempty,email|required_without=Phone"`
	Phone string `json:"phone,omitempty" validate:"omitempty,e164|required_without=Email"`
}

// Verify2FARequest - Structure for verifying 2FA code
type Verify2FARequest struct {
	UID           string `json:"uid"`
	TwoFactorCode string `json:"two_factor_code" validate:"required,len=6"`
}

// RefreshTokenRequest - Structure for refreshing access token
type RefreshTokenRequest struct {
	RefreshToken string `json:"refresh_token" validate:"required"`
}

// UpdateProfileRequest - Structure for updating user profile
type UpdateProfileRequest struct {
	Username        *string `json:"username" validate:"omitempty,min=3"`
	Bio             *string `json:"bio" validate:"omitempty,max=160"`
	ImageURL        *string `json:"image_url" validate:"omitempty,url"`
	FirstName       *string `json:"first_name" validate:"omitempty"`
	SecondName      *string `json:"second_name" validate:"omitempty"`
	CountryOfOrigin *string `json:"country_of_origin" validate:"omitempty"`
	Address         *string `json:"address" validate:"omitempty"`
}

// SuccessResponse - Generic success response
type SuccessResponse struct {
	Status  string                 `json:"status"`
	Message string                 `json:"message"`
	Payload map[string]interface{} `json:"payload"`
}

// TokenResponse - Response for token-based operations
type TokenResponse struct {
	Status  string `json:"status"`
	Message string `json:"message"`
	Token   string `json:"token"`
}

// ResendVerificationResponse - Response for resend verification
type ResendVerificationResponse struct {
	Status  string            `json:"status"`
	Message string            `json:"message"`
	Payload map[string]string `json:"payload"`
}

// ProfileResponse - Response for profile retrieval
type ProfileResponse struct {
	Status  string `json:"status"`
	Message string `json:"message"`
	Payload struct {
		UID                  string    `json:"uid"`
		Email                string    `json:"email"`
		Phone                string    `json:"phone"`
		IsPhoneVerified      bool      `json:"is_phone_verified"`
		IsEmailVerified      bool      `json:"is_email_verified"`
		IsGuestUser          bool      `json:"is_guest_user"`
		Joint                []any     `json:"joint"`
		IsBillableUser       bool      `json:"is_billable_user"`
		Is2FNeeded           bool      `json:"is_2f_needed"`
		FirstName            string    `json:"first_name"`
		SecondName           string    `json:"second_name"`
		UserCreatedDate      time.Time `json:"user_created_date"`
		UserLastLoginDetails time.Time `json:"user_last_login_details"`
		CountryOfOrigin      string    `json:"country_of_origin"`
		Address              string    `json:"address"`
		Username             string    `json:"username"`
		CreatedAt            time.Time `json:"created_at"`
		Bio                  string    `json:"bio"`
	} `json:"payload"`
}

// TwoFAStatusResponse - Response for 2FA status
type TwoFAStatusResponse struct {
	Status  string `json:"status"`
	Message string `json:"message"`
	Payload struct {
		Enabled bool `json:"enabled"`
	} `json:"payload"`
}

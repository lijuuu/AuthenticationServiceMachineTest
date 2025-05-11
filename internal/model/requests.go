package model

import (
	"fmt"

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

// SignupRequest - Structure for the user signup request
type SignupRequest struct {
	Email    string `json:"email" validate:"required_without=Phone,email"`
	Phone    string `json:"phone" validate:"required_without=Email,e164"`
	Password string `json:"password" validate:"required,min=8"`
	Username string `json:"username" validate:"required,min=3"`
}

// LoginRequest - Structure for the user login request
type LoginRequest struct {
	Credential string `json:"credential" validate:"required"`
	Password   string `json:"password" validate:"required"`
}

// GuestLoginRequest - Structure for the guest login/signup request
type GuestLoginRequest struct {
	Username string `json:"username" validate:"required,min=3"`
}

// VerifyCredentialsRequest - Structure to verify credentials
type VerifyCredentialsRequest struct {
	Credential string `json:"credential" validate:"required"`
	Password   string `json:"password" validate:"required"`
}

// ForgotPasswordRequest - Structure for forgot password request
type ForgotPasswordRequest struct {
	Email string `json:"email" validate:"required,email"`
}

// ResetPasswordRequest - Structure for reset password request
type ResetPasswordRequest struct {
	Email    string `json:"email" validate:"required,email"`
	OTP      string `json:"otp" validate:"required,len=6"`
	Password string `json:"password" validate:"required,min=8"`
}

// ChangeLoginRequest - Structure for changing login credentials
type ChangeLoginRequest struct {
	OldCredential string `json:"old_credential" validate:"required"`
	NewEmail      string `json:"new_email" validate:"required_without=NewPhone,email"`
	NewPhone      string `json:"new_phone" validate:"required_without=NewEmail,e164"`
	NewPassword   string `json:"new_password" validate:"required,min=8"`
}

// Enable2FARequest - Structure to enable 2FA request
type Enable2FARequest struct {
	Email string `json:"email" validate:"required,email"`
}

// AddAltCredentialRequest - Structure for adding alternative credentials
type AddAltCredentialRequest struct {
	UID        string `json:"uid" validate:"required"`
	Credential string `json:"credential" validate:"required"`
}

// ChangePasswordRequest - Structure for the change password request
type ChangePasswordRequest struct {
	OldPassword string `json:"old_password" validate:"required"`
	NewPassword string `json:"new_password" validate:"required,min=8"`
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
	Email string `json:"email" validate:"required_without=Phone,email"`
	Phone string `json:"phone" validate:"required_without=Email,e164"`
}

// Verify2FARequest - Structure for verifying 2FA code
type Verify2FARequest struct {
	Email string `json:"email" validate:"required,email"`
	Code  string `json:"code" validate:"required,len=6"`
}

// RefreshTokenRequest - Structure for refreshing access token
type RefreshTokenRequest struct {
	RefreshToken string `json:"refresh_token" validate:"required"`
}

// UpdateProfileRequest - Structure for updating user profile
type UpdateProfileRequest struct {
	Username string `json:"username" validate:"omitempty,min=3"`
	Bio      string `json:"bio" validate:"omitempty,max=160"`
	ImageURL string `json:"image_url" validate:"omitempty,url"`
}

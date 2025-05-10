package model

// SignupRequest - Structure for the user signup request
type SignupRequest struct {
	Email    string `json:"email" binding:"required,email"`
	Password string `json:"password" binding:"required,min=8"`
	Username string `json:"username" binding:"required"`
}

// LoginRequest - Structure for the user login request
type LoginRequest struct {
	Email    string `json:"email" binding:"required,email"`
	Password string `json:"password" binding:"required"`
}

// GuestLoginRequest - Structure for the guest login/signup request
type GuestLoginRequest struct {
	Username string `json:"username" binding:"required"`
}

// VerifyCredentialsRequest - Structure to verify credentials (email, password)
type VerifyCredentialsRequest struct {
	Email    string `json:"email" binding:"required,email"`
	Password string `json:"password" binding:"required"`
}

// ForgotPasswordRequest - Structure for forgot password request
type ForgotPasswordRequest struct {
	Email string `json:"email" binding:"required,email"`
}

// ResetPasswordRequest - Structure for reset password request
type ResetPasswordRequest struct {
	Token    string `json:"token" binding:"required"`
	Password string `json:"password" binding:"required,min=8"`
}

// ChangeLoginRequest - Structure for changing login credentials
type ChangeLoginRequest struct {
	OldEmail    string `json:"old_email" binding:"required,email"`
	NewEmail    string `json:"new_email" binding:"required,email"`
	NewPassword string `json:"new_password" binding:"required,min=8"`
}

// Enable2FARequest - Structure to enable 2FA request
type Enable2FARequest struct {
	Email string `json:"email" binding:"required,email"`
}

// AddAltCredentialRequest - Structure for adding alternative credentials (email/phone)
type AddAltCredentialRequest struct {
	Credential string `json:"credential" binding:"required"`
}

// ChangePasswordRequest - Structure for the change password request
type ChangePasswordRequest struct {
	OldPassword string `json:"old_password" binding:"required"`
	NewPassword string `json:"new_password" binding:"required,min=8"`
}

// VerifyEmailRequest - Structure for email verification request
type VerifyEmailRequest struct {
	Email string `json:"email" binding:"required,email"`
}

// VerifyPhoneRequest - Structure for phone verification request
type VerifyPhoneRequest struct {
	Phone string `json:"phone" binding:"required"`
}

// ResendVerificationRequest - Structure for resending email/phone verification
type ResendVerificationRequest struct {
	Email string `json:"email" binding:"required,email"`
	Phone string `json:"phone" binding:"required"`
}

// Verify2FARequest - Structure for verifying 2FA code
type Verify2FARequest struct {
	Email string `json:"email" binding:"required,email"`
	Code  string `json:"code" binding:"required,len=6"`
}

// RefreshTokenRequest - Structure for refreshing access token
type RefreshTokenRequest struct {
	RefreshToken string `json:"refresh_token" binding:"required"`
}

// UpdateProfileRequest - Structure for updating user profile
type UpdateProfileRequest struct {
	Username string `json:"username" binding:"omitempty,min=3"`
	Bio      string `json:"bio" binding:"omitempty,max=160"`
	ImageURL string `json:"image_url" binding:"omitempty,url"`
}

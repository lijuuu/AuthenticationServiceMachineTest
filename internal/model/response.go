package model

// SuccessResponse - Standard success response format
type SuccessResponse struct {
	Status  string      `json:"status"`
	Message string      `json:"message"`
	Payload interface{} `json:"payload,omitempty"`
}

// ErrorResponse - Standard error response format
type ErrorResponse struct {
	Status  string `json:"status"`
	Message string `json:"message"`
	Code    int    `json:"code"`
}

// TokenResponse - Response format for token-related endpoints
type TokenResponse struct {
	Status  string `json:"status"`
	Message string `json:"message"`
	Token   string `json:"token"`
}

// ProfileResponse - Response for fetching user profile
type ProfileResponse struct {
	Status  string `json:"status"`
	Message string `json:"message"`
	Payload struct {
		Username      string `json:"username"`
		Email         string `json:"email"`
		Phone         string `json:"phone"`
		CreatedAt     string `json:"created_at"`
		Bio           string `json:"bio"`
		ImageURL      string `json:"image_url"`
		EmailVerified bool   `json:"email_verified"`
		PhoneVerified bool   `json:"phone_verified"`
	} `json:"payload"`
}

// TwoFAStatusResponse - Response format for 2FA status
type TwoFAStatusResponse struct {
	Status  string `json:"status"`
	Message string `json:"message"`
	Payload struct {
		Enabled bool `json:"enabled"`
	} `json:"payload"`
}

// ResendVerificationResponse - Response for resending verification
type ResendVerificationResponse struct {
	Status  string      `json:"status"`
	Message string      `json:"message"`
	Payload interface{} `json:"payload,omitempty"`
}
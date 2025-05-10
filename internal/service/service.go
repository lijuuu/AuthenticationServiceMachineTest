package services

import (
	"context"
	"strings"

	"github.com/lijuuu/AuthenticationServiceMachineTest/internal/model"
	"github.com/lijuuu/AuthenticationServiceMachineTest/internal/repository"
)

// AuthService defines the interface for authentication service methods
type AuthService interface {
	Signup(req model.SignupRequest) (model.SuccessResponse, *model.ErrorResponse)
	Login(req model.LoginRequest) (model.TokenResponse, *model.ErrorResponse)
	GuestLogin(req model.GuestLoginRequest) (model.TokenResponse, *model.ErrorResponse)
	VerifyCredentials(req model.VerifyCredentialsRequest) (model.SuccessResponse, *model.ErrorResponse)
	ForgotPassword(req model.ForgotPasswordRequest) (model.SuccessResponse, *model.ErrorResponse)
	ResetPassword(req model.ResetPasswordRequest) (model.SuccessResponse, *model.ErrorResponse)
	ChangeLogin(req model.ChangeLoginRequest) (model.SuccessResponse, *model.ErrorResponse)
	Enable2FA(req model.Enable2FARequest) (model.SuccessResponse, *model.ErrorResponse)
	AddAltCredential(req model.AddAltCredentialRequest) (model.SuccessResponse, *model.ErrorResponse)
	GetProfile(uid string) (model.ProfileResponse, *model.ErrorResponse)
	Logout() (model.SuccessResponse, *model.ErrorResponse)
	RefreshToken(req model.RefreshTokenRequest) (model.TokenResponse, *model.ErrorResponse)
	VerifyToken(token string) (model.SuccessResponse, *model.ErrorResponse)
	UpdateProfile(uid string, req model.UpdateProfileRequest) (model.SuccessResponse, *model.ErrorResponse)
	DeleteAccount(uid string) (model.SuccessResponse, *model.ErrorResponse)
	ChangePassword(uid string, req model.ChangePasswordRequest) (model.SuccessResponse, *model.ErrorResponse)
	VerifyEmail(req model.VerifyEmailRequest) (model.SuccessResponse, *model.ErrorResponse)
	VerifyPhone(req model.VerifyPhoneRequest) (model.SuccessResponse, *model.ErrorResponse)
	ResendVerification(req model.ResendVerificationRequest) (model.ResendVerificationResponse, *model.ErrorResponse)
	Verify2FA(req model.Verify2FARequest) (model.SuccessResponse, *model.ErrorResponse)
	Disable2FA(uid string) (model.SuccessResponse, *model.ErrorResponse)
	Get2FAStatus(uid string) (model.TwoFAStatusResponse, *model.ErrorResponse)
}

// authService implements the AuthService interface
type authService struct {
	repo *repository.FirebaseRepository
	ctx  context.Context
}

// NewAuthService creates a new authService instance
func NewAuthService(ctx context.Context, repo *repository.FirebaseRepository) AuthService {
	return &authService{
		repo: repo,
		ctx:  ctx,
	}
}

// MockVerifyOTP is a mock function for OTP verification
func MockVerifyOTP(code string) bool {
	// For testing, assume "123456" is the valid OTP
	return code == "123456"
}

// Signup handles user registration
func (s *authService) Signup(req model.SignupRequest) (model.SuccessResponse, *model.ErrorResponse) {
	// Validation is handled by binding tags, but add additional checks if needed
	if len(req.Username) < 3 {
		return model.SuccessResponse{}, &model.ErrorResponse{
			Status:  "error",
			Message: "Username must be at least 3 characters",
			Code:    400,
		}
	}

	resp, err := s.repo.Signup(req)
	if err != nil {
		return model.SuccessResponse{}, err
	}

	return resp, nil
}

// Login handles user login
func (s *authService) Login(req model.LoginRequest) (model.TokenResponse, *model.ErrorResponse) {
	resp, err := s.repo.Login(req)
	if err != nil {
		return model.TokenResponse{}, err
	}

	return resp, nil
}

// GuestLogin creates a guest user
func (s *authService) GuestLogin(req model.GuestLoginRequest) (model.TokenResponse, *model.ErrorResponse) {
	if len(req.Username) < 3 {
		return model.TokenResponse{}, &model.ErrorResponse{
			Status:  "error",
			Message: "Username must be at least 3 characters",
			Code:    400,
		}
	}

	resp, err := s.repo.GuestLogin(req)
	if err != nil {
		return model.TokenResponse{}, err
	}

	return resp, nil
}

// VerifyCredentials verifies user credentials
func (s *authService) VerifyCredentials(req model.VerifyCredentialsRequest) (model.SuccessResponse, *model.ErrorResponse) {
	resp, err := s.repo.VerifyCredentials(req)
	if err != nil {
		return model.SuccessResponse{}, err
	}

	return resp, nil
}

// ForgotPassword initiates password reset
func (s *authService) ForgotPassword(req model.ForgotPasswordRequest) (model.SuccessResponse, *model.ErrorResponse) {
	resp, err := s.repo.ForgotPassword(req)
	if err != nil {
		return model.SuccessResponse{}, err
	}

	return resp, nil
}

// ResetPassword resets the user's password
func (s *authService) ResetPassword(req model.ResetPasswordRequest) (model.SuccessResponse, *model.ErrorResponse) {
	resp, err := s.repo.ResetPassword(req)
	if err != nil {
		return model.SuccessResponse{}, err
	}

	return resp, nil
}

// ChangeLogin updates the user's email
func (s *authService) ChangeLogin(req model.ChangeLoginRequest) (model.SuccessResponse, *model.ErrorResponse) {
	if req.OldEmail == req.NewEmail {
		return model.SuccessResponse{}, &model.ErrorResponse{
			Status:  "error",
			Message: "New email must be different from old email",
			Code:    400,
		}
	}

	resp, err := s.repo.ChangeLogin(req)
	if err != nil {
		return model.SuccessResponse{}, err
	}

	return resp, nil
}

// Enable2FA enables two-factor authentication
func (s *authService) Enable2FA(req model.Enable2FARequest) (model.SuccessResponse, *model.ErrorResponse) {
	resp, err := s.repo.Enable2FA(req)
	if err != nil {
		return model.SuccessResponse{}, err
	}

	return resp, nil
}

// AddAltCredential adds an alternate credential
func (s *authService) AddAltCredential(req model.AddAltCredentialRequest) (model.SuccessResponse, *model.ErrorResponse) {
	// Basic validation for credential (email or phone)
	if !strings.Contains(req.Credential, "@") && !strings.HasPrefix(req.Credential, "+") {
		return model.SuccessResponse{}, &model.ErrorResponse{
			Status:  "error",
			Message: "Credential must be a valid email or phone number",
			Code:    400,
		}
	}

	resp, err := s.repo.AddAltCredential(req)
	if err != nil {
		return model.SuccessResponse{}, err
	}

	return resp, nil
}

// GetProfile retrieves the user's profile
func (s *authService) GetProfile(uid string) (model.ProfileResponse, *model.ErrorResponse) {
	if uid == "" {
		return model.ProfileResponse{}, &model.ErrorResponse{
			Status:  "error",
			Message: "UID is required",
			Code:    400,
		}
	}

	resp, err := s.repo.GetProfile(uid)
	if err != nil {
		return model.ProfileResponse{}, err
	}

	return resp, nil
}

// Logout logs out the user
func (s *authService) Logout() (model.SuccessResponse, *model.ErrorResponse) {
	resp, err := s.repo.Logout()
	if err != nil {
		return model.SuccessResponse{}, err
	}

	return resp, nil
}

// RefreshToken refreshes the user's token
func (s *authService) RefreshToken(req model.RefreshTokenRequest) (model.TokenResponse, *model.ErrorResponse) {
	resp, err := s.repo.RefreshToken(req)
	if err != nil {
		return model.TokenResponse{}, err
	}

	return resp, nil
}

// VerifyToken verifies a token
func (s *authService) VerifyToken(token string) (model.SuccessResponse, *model.ErrorResponse) {
	resp, err := s.repo.VerifyToken(token)
	if err != nil {
		return model.SuccessResponse{}, err
	}

	return resp, nil
}

// UpdateProfile updates the user's profile
func (s *authService) UpdateProfile(uid string, req model.UpdateProfileRequest) (model.SuccessResponse, *model.ErrorResponse) {
	if uid == "" {
		return model.SuccessResponse{}, &model.ErrorResponse{
			Status:  "error",
			Message: "UID is required",
			Code:    400,
		}
	}

	resp, err := s.repo.UpdateProfile(uid, req)
	if err != nil {
		return model.SuccessResponse{}, err
	}

	return resp, nil
}

// DeleteAccount deletes the user's account
func (s *authService) DeleteAccount(uid string) (model.SuccessResponse, *model.ErrorResponse) {
	if uid == "" {
		return model.SuccessResponse{}, &model.ErrorResponse{
			Status:  "error",
			Message: "UID is required",
			Code:    400,
		}
	}

	resp, err := s.repo.DeleteAccount(uid)
	if err != nil {
		return model.SuccessResponse{}, err
	}

	return resp, nil
}

// ChangePassword changes the user's password
func (s *authService) ChangePassword(uid string, req model.ChangePasswordRequest) (model.SuccessResponse, *model.ErrorResponse) {
	if uid == "" {
		return model.SuccessResponse{}, &model.ErrorResponse{
			Status:  "error",
			Message: "UID is required",
			Code:    400,
		}
	}

	resp, err := s.repo.ChangePassword(uid, req)
	if err != nil {
		return model.SuccessResponse{}, err
	}

	return resp, nil
}

// VerifyEmail verifies the user's email
func (s *authService) VerifyEmail(req model.VerifyEmailRequest) (model.SuccessResponse, *model.ErrorResponse) {
	resp, err := s.repo.VerifyEmail(req)
	if err != nil {
		return model.SuccessResponse{}, err
	}

	return resp, nil
}

// VerifyPhone verifies the user's phone number
func (s *authService) VerifyPhone(req model.VerifyPhoneRequest) (model.SuccessResponse, *model.ErrorResponse) {
	resp, err := s.repo.VerifyPhone(req)
	if err != nil {
		return model.SuccessResponse{}, err
	}

	return resp, nil
}

// ResendVerification resends verification email or phone code
func (s *authService) ResendVerification(req model.ResendVerificationRequest) (model.ResendVerificationResponse, *model.ErrorResponse) {
	if req.Email == "" && req.Phone == "" {
		return model.ResendVerificationResponse{}, &model.ErrorResponse{
			Status:  "error",
			Message: "Email or phone is required",
			Code:    400,
		}
	}

	resp, err := s.repo.ResendVerification(req)
	if err != nil {
		return model.ResendVerificationResponse{}, err
	}

	return resp, nil
}

// Verify2FA verifies the2FA code
func (s *authService) Verify2FA(req model.Verify2FARequest) (model.SuccessResponse, *model.ErrorResponse) {
	// Use mock OTP verification
	if !MockVerifyOTP(req.Code) {
		return model.SuccessResponse{}, &model.ErrorResponse{
			Status:  "error",
			Message: "Invalid 2FA code",
			Code:    401,
		}
	}

	resp, err := s.repo.Verify2FA(req)
	if err != nil {
		return model.SuccessResponse{}, err
	}

	return resp, nil
}

// Disable2FA disables two-factor authentication
func (s *authService) Disable2FA(uid string) (model.SuccessResponse, *model.ErrorResponse) {
	if uid == "" {
		return model.SuccessResponse{}, &model.ErrorResponse{
			Status:  "error",
			Message: "UID is required",
			Code:    400,
		}
	}

	resp, err := s.repo.Disable2FA(uid)
	if err != nil {
		return model.SuccessResponse{}, err
	}

	return resp, nil
}

// Get2FAStatus retrieves the 2FA status
func (s *authService) Get2FAStatus(uid string) (model.TwoFAStatusResponse, *model.ErrorResponse) {
	if uid == "" {
		return model.TwoFAStatusResponse{}, &model.ErrorResponse{
			Status:  "error",
			Message: "UID is required",
			Code:    400,
		}
	}

	resp, err := s.repo.Get2FAStatus(uid)
	if err != nil {
		return model.TwoFAStatusResponse{}, err
	}

	return resp, nil
}

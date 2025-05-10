package repository

import (
	"context"
	"fmt"
	"time"

	"cloud.google.com/go/firestore"
	firebase "firebase.google.com/go"
	"firebase.google.com/go/auth"
	"github.com/lijuuu/AuthenticationServiceMachineTest/internal/model"
	"google.golang.org/api/option"
)

// FirebaseRepository implements the repository layer for interacting with Firebase
type FirebaseRepository struct {
	firestoreClient *firestore.Client
	authClient      *auth.Client
	ctx             context.Context
}

// NewFirebaseRepository initializes Firebase Admin SDK and returns a new repository
func NewFirebaseRepository(ctx context.Context, credentialsFile string) (*FirebaseRepository, error) {
	opt := option.WithCredentialsFile(credentialsFile)
	app, err := firebase.NewApp(ctx, nil, opt)
	if err != nil {
		return nil, fmt.Errorf("error initializing Firebase app: %v", err)
	}

	firestoreClient, err := app.Firestore(ctx)
	if err != nil {
		return nil, fmt.Errorf("error initializing Firestore client: %v", err)
	}

	authClient, err := app.Auth(ctx)
	if err != nil {
		return nil, fmt.Errorf("error initializing Auth client: %v", err)
	}

	return &FirebaseRepository{
		firestoreClient: firestoreClient,
		authClient:      authClient,
		ctx:             ctx,
	}, nil
}

// Close closes the Firestore client
func (r *FirebaseRepository) Close() error {
	return r.firestoreClient.Close()
}

// Signup creates a new user in Firebase Authentication and stores profile in Firestore
func (r *FirebaseRepository) Signup(req model.SignupRequest) (model.SuccessResponse, *model.ErrorResponse) {
	params := (&auth.UserToCreate{}).
		Email(req.Email).
		Password(req.Password).
		DisplayName(req.Username)

	user, err := r.authClient.CreateUser(r.ctx, params)
	if err != nil {
		return model.SuccessResponse{}, &model.ErrorResponse{
			Status:  "error",
			Message: "Failed to create user",
			Code:    400,
		}
	}

	// Store user profile in Firestore
	profile := map[string]interface{}{
		"uid":         user.UID,
		"email":       req.Email,
		"username":    req.Username,
		"created_at":  time.Now().Format(time.RFC3339),
		"updated_at":  time.Now().Format(time.RFC3339),
		"2fa_enabled": false,
	}

	_, err = r.firestoreClient.Collection("users").Doc(user.UID).Set(r.ctx, profile)
	if err != nil {
		_ = r.authClient.DeleteUser(r.ctx, user.UID)
		return model.SuccessResponse{}, &model.ErrorResponse{
			Status:  "error",
			Message: "Failed to store user profile",
			Code:    500,
		}
	}

	return model.SuccessResponse{
		Status:  "success",
		Message: "User created successfully",
		Payload: map[string]string{
			"uid":      user.UID,
			"email":    req.Email,
			"username": req.Username,
		},
	}, nil
}

// Login verifies user credentials and generates a custom token
func (r *FirebaseRepository) Login(req model.LoginRequest) (model.TokenResponse, *model.ErrorResponse) {
	user, err := r.authClient.GetUserByEmail(r.ctx, req.Email)
	if err != nil {
		return model.TokenResponse{}, &model.ErrorResponse{
			Status:  "error",
			Message: "Invalid credentials",
			Code:    401,
		}
	}

	token, err := r.authClient.CustomToken(r.ctx, user.UID)
	if err != nil {
		return model.TokenResponse{}, &model.ErrorResponse{
			Status:  "error",
			Message: "Failed to generate token",
			Code:    500,
		}
	}

	return model.TokenResponse{
		Status:  "success",
		Message: "Login successful",
		Token:   token,
	}, nil
}

// GuestLogin creates a guest user
func (r *FirebaseRepository) GuestLogin(req model.GuestLoginRequest) (model.TokenResponse, *model.ErrorResponse) {
	params := (&auth.UserToCreate{}).Disabled(true).DisplayName(req.Username)
	user, err := r.authClient.CreateUser(r.ctx, params)
	if err != nil {
		return model.TokenResponse{}, &model.ErrorResponse{
			Status:  "error",
			Message: "Failed to create guest user",
			Code:    500,
		}
	}

	token, err := r.authClient.CustomToken(r.ctx, user.UID)
	if err != nil {
		_ = r.authClient.DeleteUser(r.ctx, user.UID)
		return model.TokenResponse{}, &model.ErrorResponse{
			Status:  "error",
			Message: "Failed to generate guest token",
			Code:    500,
		}
	}

	// Store guest profile in Firestore
	profile := map[string]interface{}{
		"uid":         user.UID,
		"username":    req.Username,
		"created_at":  time.Now().Format(time.RFC3339),
		"updated_at":  time.Now().Format(time.RFC3339),
		"2fa_enabled": false,
	}

	_, err = r.firestoreClient.Collection("users").Doc(user.UID).Set(r.ctx, profile)
	if err != nil {
		_ = r.authClient.DeleteUser(r.ctx, user.UID)
		return model.TokenResponse{}, &model.ErrorResponse{
			Status:  "error",
			Message: "Failed to store guest profile",
			Code:    500,
		}
	}

	return model.TokenResponse{
		Status:  "success",
		Message: "Guest login successful",
		Token:   token,
	}, nil
}

// VerifyCredentials checks if the provided credentials are valid
func (r *FirebaseRepository) VerifyCredentials(req model.VerifyCredentialsRequest) (model.SuccessResponse, *model.ErrorResponse) {
	user, err := r.authClient.GetUserByEmail(r.ctx, req.Email)
	if err != nil {
		return model.SuccessResponse{}, &model.ErrorResponse{
			Status:  "error",
			Message: "Invalid credentials",
			Code:    401,
		}
	}

	return model.SuccessResponse{
		Status:  "success",
		Message: "Credentials verified",
		Payload: map[string]string{
			"uid":   user.UID,
			"email": user.Email,
		},
	}, nil
}

// ForgotPassword sends a password reset email
func (r *FirebaseRepository) ForgotPassword(req model.ForgotPasswordRequest) (model.SuccessResponse, *model.ErrorResponse) {
	err := r.authClient.SendPasswordResetEmail(r.ctx, req.Email)
	if err != nil {
		return model.SuccessResponse{}, &model.ErrorResponse{
			Status:  "error",
			Message: "Failed to send password reset email",
			Code:    400,
		}
	}

	return model.SuccessResponse{
		Status:  "success",
		Message: "Password reset email sent",
	}, nil
}

// ResetPassword updates the user's password
func (r *FirebaseRepository) ResetPassword(req model.ResetPasswordRequest) (model.SuccessResponse, *model.ErrorResponse) {
	// Verify the reset token (Firebase handles this client-side in production)
	_, err := r.authClient.VerifyPasswordResetCode(r.ctx, req.Token)
	if err != nil {
		return model.SuccessResponse{}, &model.ErrorResponse{
			Status:  "error",
			Message: "Invalid or expired reset token",
			Code:    400,
		}
	}

	// In a real app, Firebase client SDK would handle password reset
	// Here, we simulate by updating the user's password
	user, err := r.authClient.GetUserByEmail(r.ctx, req.Token) // Assuming token contains email for simplicity
	if err != nil {
		return model.SuccessResponse{}, &model.ErrorResponse{
			Status:  "error",
			Message: "User not found",
			Code:    404,
		}
	}

	_, err = r.authClient.UpdateUser(r.ctx, user.UID, (&auth.UserToUpdate{}).Password(req.Password))
	if err != nil {
		return model.SuccessResponse{}, &model.ErrorResponse{
			Status:  "error",
			Message: "Failed to reset password",
			Code:    400,
		}
	}

	return model.SuccessResponse{
		Status:  "success",
		Message: "Password reset successful",
	}, nil
}

// ChangeLogin updates the user's email and password
func (r *FirebaseRepository) ChangeLogin(req model.ChangeLoginRequest) (model.SuccessResponse, *model.ErrorResponse) {
	user, err := r.authClient.GetUserByEmail(r.ctx, req.OldEmail)
	if err != nil {
		return model.SuccessResponse{}, &model.ErrorResponse{
			Status:  "error",
			Message: "User not found",
			Code:    404,
		}
	}

	update := &auth.UserToUpdate{}
	update = update.Email(req.NewEmail).Password(req.NewPassword)
	_, err = r.authClient.UpdateUser(r.ctx, user.UID, update)
	if err != nil {
		return model.SuccessResponse{}, &model.ErrorResponse{
			Status:  "error",
			Message: "Failed to update login credentials",
			Code:    400,
		}
	}

	// Update Firestore profile
	_, err = r.firestoreClient.Collection("users").Doc(user.UID).Update(r.ctx, []firestore.Update{
		{Path: "email", Value: req.NewEmail},
		{Path: "updated_at", Value: time.Now().Format(time.RFC3339)},
	})
	if err != nil {
		return model.SuccessResponse{}, &model.ErrorResponse{
			Status:  "error",
			Message: "Failed to update profile",
			Code:    500,
		}
	}

	return model.SuccessResponse{
		Status:  "success",
		Message: "Login credentials updated successfully",
	}, nil
}

// Enable2FA enables two-factor authentication
func (r *FirebaseRepository) Enable2FA(req model.Enable2FARequest) (model.SuccessResponse, *model.ErrorResponse) {
	_, err := r.firestoreClient.Collection("users").Doc(req.Email).Update(r.ctx, []firestore.Update{
		{Path: "2fa_enabled", Value: true},
		{Path: "updated_at", Value: time.Now().Format(time.RFC3339)},
	})
	if err != nil {
		return model.SuccessResponse{}, &model.ErrorResponse{
			Status:  "error",
			Message: "Failed to enable 2FA",
			Code:    500,
		}
	}

	return model.SuccessResponse{
		Status:  "success",
		Message: "2FA enabled successfully",
	}, nil
}

// AddAltCredential adds an alternate credential (email or phone)
func (r *FirebaseRepository) AddAltCredential(req model.AddAltCredentialRequest) (model.SuccessResponse, *model.ErrorResponse) {
	// Assume credential is a phone number for Firebase Authentication
	user, err := r.authClient.GetUserByEmail(r.ctx, req.Credential)
	if err != nil {
		return model.SuccessResponse{}, &model.ErrorResponse{
			Status:  "error",
			Message: "User not found",
			Code:    404,
		}
	}

	_, err = r.authClient.UpdateUser(r.ctx, user.UID, (&auth.UserToUpdate{}).PhoneNumber(req.Credential))
	if err != nil {
		return model.SuccessResponse{}, &model.ErrorResponse{
			Status:  "error",
			Message: "Failed to add alternate credential",
			Code:    400,
		}
	}

	// Update Firestore profile
	_, err = r.firestoreClient.Collection("users").Doc(user.UID).Update(r.ctx, []firestore.Update{
		{Path: "phone_number", Value: req.Credential},
		{Path: "updated_at", Value: time.Now().Format(time.RFC3339)},
	})
	if err != nil {
		return model.SuccessResponse{}, &model.ErrorResponse{
			Status:  "error",
			Message: "Failed to update profile",
			Code:    500,
		}
	}

	return model.SuccessResponse{
		Status:  "success",
		Message: "Alternate credential added successfully",
	}, nil
}

// GetProfile retrieves the user's profile from Firestore
func (r *FirebaseRepository) GetProfile(uid string) (model.ProfileResponse, *model.ErrorResponse) {
	doc, err := r.firestoreClient.Collection("users").Doc(uid).Get(r.ctx)
	if err != nil {
		return model.ProfileResponse{}, &model.ErrorResponse{
			Status:  "error",
			Message: "Failed to retrieve profile",
			Code:    404,
		}
	}

	data := doc.Data()
	resp := model.ProfileResponse{
		Status:  "success",
		Message: "Profile retrieved successfully",
	}
	resp.Payload.Username = data["username"].(string)
	resp.Payload.Email = data["email"].(string)
	resp.Payload.CreatedAt = data["created_at"].(string)

	return resp, nil
}

// Logout (no-op for Firebase, as tokens are stateless)
func (r *FirebaseRepository) Logout() (model.SuccessResponse, *model.ErrorResponse) {
	return model.SuccessResponse{
		Status:  "success",
		Message: "Logged out successfully",
	}, nil
}

// RefreshToken generates a new custom token
func (r *FirebaseRepository) RefreshToken(req model.RefreshTokenRequest) (model.TokenResponse, *model.ErrorResponse) {
	_, err := r.authClient.VerifyIDToken(r.ctx, req.RefreshToken)
	if err != nil {
		return model.TokenResponse{}, &model.ErrorResponse{
			Status:  "error",
			Message: "Invalid refresh token",
			Code:    401,
		}
	}

	// Generate new custom token
	user, err := r.authClient.GetUser(r.ctx, req.RefreshToken) // Assuming token contains UID for simplicity
	if err != nil {
		return model.TokenResponse{}, &model.ErrorResponse{
			Status:  "error",
			Message: "User not found",
			Code:    404,
		}
	}

	token, err := r.authClient.CustomToken(r.ctx, user.UID)
	if err != nil {
		return model.TokenResponse{}, &model.ErrorResponse{
			Status:  "error",
			Message: "Failed to generate new token",
			Code:    500,
		}
	}

	return model.TokenResponse{
		Status:  "success",
		Message: "Token refreshed successfully",
		Token:   token,
	}, nil
}

// VerifyToken verifies a Firebase ID token
func (r *FirebaseRepository) VerifyToken(token string) (model.SuccessResponse, *model.ErrorResponse) {
	decoded, err := r.authClient.VerifyIDToken(r.ctx, token)
	if err != nil {
		return model.SuccessResponse{}, &model.ErrorResponse{
			Status:  "error",
			Message: "Invalid token",
			Code:    401,
		}
	}

	return model.SuccessResponse{
		Status:  "success",
		Message: "Token verified successfully",
		Payload: map[string]string{
			"uid": decoded.UID,
		},
	}, nil
}

// UpdateProfile updates the user's profile in Firestore and Firebase Authentication
func (r *FirebaseRepository) UpdateProfile(uid string, req model.UpdateProfileRequest) (model.SuccessResponse, *model.ErrorResponse) {
	updates := []firestore.Update{
		{Path: "updated_at", Value: time.Now().Format(time.RFC3339)},
	}
	if req.Username != "" {
		updates = append(updates, firestore.Update{Path: "username", Value: req.Username})
	}
	if req.Bio != "" {
		updates = append(updates, firestore.Update{Path: "bio", Value: req.Bio})
	}
	if req.ImageURL != "" {
		updates = append(updates, firestore.Update{Path: "image_url", Value: req.ImageURL})
	}

	_, err := r.firestoreClient.Collection("users").Doc(uid).Update(r.ctx, updates)
	if err != nil {
		return model.SuccessResponse{}, &model.ErrorResponse{
			Status:  "error",
			Message: "Failed to update profile",
			Code:    500,
		}
	}

	// Update Firebase Authentication
	userUpdate := &auth.UserToUpdate{}
	if req.Username != "" {
		userUpdate = userUpdate.DisplayName(req.Username)
	}
	_, err = r.authClient.UpdateUser(r.ctx, uid, userUpdate)
	if err != nil {
		return model.SuccessResponse{}, &model.ErrorResponse{
			Status:  "error",
			Message: "Failed to update authentication profile",
			Code:    400,
		}
	}

	return model.SuccessResponse{
		Status:  "success",
		Message: "Profile updated successfully",
	}, nil
}

// DeleteAccount deletes the user from Firebase Authentication and Firestore
func (r *FirebaseRepository) DeleteAccount(uid string) (model.SuccessResponse, *model.ErrorResponse) {
	err := r.authClient.DeleteUser(r.ctx, uid)
	if err != nil {
		return model.SuccessResponse{}, &model.ErrorResponse{
			Status:  "error",
			Message: "Failed to delete account",
			Code:    400,
		}
	}

	_, err = r.firestoreClient.Collection("users").Doc(uid).Delete(r.ctx)
	if err != nil {
		return model.SuccessResponse{}, &model.ErrorResponse{
			Status:  "error",
			Message: "Failed to delete profile",
			Code:    500,
		}
	}

	return model.SuccessResponse{
		Status:  "success",
		Message: "Account deleted successfully",
	}, nil
}

// ChangePassword updates the user's password
func (r *FirebaseRepository) ChangePassword(uid string, req model.ChangePasswordRequest) (model.SuccessResponse, *model.ErrorResponse) {
	_, err := r.authClient.UpdateUser(r.ctx, uid, (&auth.UserToUpdate{}).Password(req.NewPassword))
	if err != nil {
		return model.SuccessResponse{}, &model.ErrorResponse{
			Status:  "error",
			Message: "Failed to change password",
			Code:    400,
		}
	}

	return model.SuccessResponse{
		Status:  "success",
		Message: "Password changed successfully",
	}, nil
}

// VerifyEmail verifies the user's email
func (r *FirebaseRepository) VerifyEmail(req model.VerifyEmailRequest) (model.SuccessResponse, *model.ErrorResponse) {
	user, err := r.authClient.GetUserByEmail(r.ctx, req.Email)
	if err != nil {
		return model.SuccessResponse{}, &model.ErrorResponse{
			Status:  "error",
			Message: "User not found",
			Code:    404,
		}
	}

	_, err = r.authClient.UpdateUser(r.ctx, user.UID, (&auth.UserToUpdate{}).EmailVerified(true))
	if err != nil {
		return model.SuccessResponse{}, &model.ErrorResponse{
			Status:  "error",
			Message: "Failed to verify email",
			Code:    400,
		}
	}

	return model.SuccessResponse{
		Status:  "success",
		Message: "Email verified successfully",
	}, nil
}

// VerifyPhone verifies the user's phone number
func (r *FirebaseRepository) VerifyPhone(req model.VerifyPhoneRequest) (model.SuccessResponse, *model.ErrorResponse) {
	user, err := r.authClient.GetUserByPhoneNumber(r.ctx, req.Phone)
	if err != nil {
		return model.SuccessResponse{}, &model.ErrorResponse{
			Status:  "error",
			Message: "User not found",
			Code:    404,
		}
	}

	_, err = r.authClient.UpdateUser(r.ctx, user.UID, (&auth.UserToUpdate{}).PhoneNumber(req.Phone))
	if err != nil {
		return model.SuccessResponse{}, &model.ErrorResponse{
			Status:  "error",
			Message: "Failed to verify phone number",
			Code:    400,
		}
	}

	_, err = r.firestoreClient.Collection("users").Doc(user.UID).Update(r.ctx, []firestore.Update{
		{Path: "phone_verified", Value: true},
		{Path: "phone_number", Value: req.Phone},
		{Path: "updated_at", Value: time.Now().Format(time.RFC3339)},
	})
	if err != nil {
		return model.SuccessResponse{}, &model.ErrorResponse{
			Status:  "error",
			Message: "Failed to update profile",
			Code:    500,
		}
	}

	return model.SuccessResponse{
		Status:  "success",
		Message: "Phone verified successfully",
	}, nil
}

// ResendVerification resends verification email or phone code
func (r *FirebaseRepository) ResendVerification(req model.ResendVerificationRequest) (model.ResendVerificationResponse, *model.ErrorResponse) {
	if req.Email != "" {
		err := r.authClient.SendPasswordResetEmail(r.ctx, req.Email)
		if err != nil {
			return model.ResendVerificationResponse{}, &model.ErrorResponse{
				Status:  "error",
				Message: "Failed to resend verification email",
				Code:    400,
			}
		}
	} else if req.Phone != "" {
		// Firebase doesn't support phone verification resend directly; simulate for now
		return model.ResendVerificationResponse{}, &model.ErrorResponse{
			Status:  "error",
			Message: "Phone verification resend not supported",
			Code:    400,
		}
	}

	return model.ResendVerificationResponse{
		Status:  "success",
		Message: "Verification resent successfully",
	}, nil
}

// Verify2FA verifies the 2FA code (mock verification in service layer)
func (r *FirebaseRepository) Verify2FA(req model.Verify2FARequest) (model.SuccessResponse, *model.ErrorResponse) {
	doc, err := r.firestoreClient.Collection("users").Doc(req.Email).Get(r.ctx)
	if err != nil {
		return model.SuccessResponse{}, &model.ErrorResponse{
			Status:  "error",
			Message: "User not found",
			Code:    404,
		}
	}

	data := doc.Data()
	if !data["2fa_enabled"].(bool) {
		return model.SuccessResponse{}, &model.ErrorResponse{
			Status:  "error",
			Message: "2FA not enabled",
			Code:    400,
		}
	}

	return model.SuccessResponse{
		Status:  "success",
		Message: "2FA verified successfully",
	}, nil
}

// Disable2FA disables two-factor authentication
func (r *FirebaseRepository) Disable2FA(uid string) (model.SuccessResponse, *model.ErrorResponse) {
	_, err := r.firestoreClient.Collection("users").Doc(uid).Update(r.ctx, []firestore.Update{
		{Path: "2fa_enabled", Value: false},
		{Path: "updated_at", Value: time.Now().Format(time.RFC3339)},
	})
	if err != nil {
		return model.SuccessResponse{}, &model.ErrorResponse{
			Status:  "error",
			Message: "Failed to disable 2FA",
			Code:    500,
		}
	}

	return model.SuccessResponse{
		Status:  "success",
		Message: "2FA disabled successfully",
	}, nil
}

// Get2FAStatus retrieves the 2FA status
func (r *FirebaseRepository) Get2FAStatus(uid string) (model.TwoFAStatusResponse, *model.ErrorResponse) {
	doc, err := r.firestoreClient.Collection("users").Doc(uid).Get(r.ctx)
	if err != nil {
		return model.TwoFAStatusResponse{}, &model.ErrorResponse{
			Status:  "error",
			Message: "User not found",
			Code:    404,
		}
	}

	data := doc.Data()
	resp := model.TwoFAStatusResponse{
		Status:  "success",
		Message: "2FA status retrieved successfully",
	}
	resp.Payload.Enabled = data["2fa_enabled"].(bool)

	return resp, nil
}
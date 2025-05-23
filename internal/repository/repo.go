package repository

import (
	"context"
	"fmt"
	"log"
	"math/rand"
	"strings"
	"time"

	"cloud.google.com/go/firestore"
	"firebase.google.com/go/auth"
	"golang.org/x/crypto/bcrypt"

	"github.com/lijuuu/AuthenticationServiceMachineTest/config"
	firebaseclient "github.com/lijuuu/AuthenticationServiceMachineTest/internal/firebase"
	"github.com/lijuuu/AuthenticationServiceMachineTest/internal/middleware"
	"github.com/lijuuu/AuthenticationServiceMachineTest/internal/model"
	"github.com/lijuuu/AuthenticationServiceMachineTest/internal/utils"

	"github.com/pquerna/otp"
	"github.com/pquerna/otp/totp"
)

// FirebaseRepository implements the repository layer for interacting with Firebase
type FirebaseRepository struct {
	firestoreClient *firestore.Client
	authClient      *auth.Client
	ctx             context.Context
	cfg             *config.Config
}

// NewFirebaseRepository initializes Firebase Admin SDK and returns a new repository
func NewFirebaseRepository(ctx context.Context, cfg *config.Config, clients *firebaseclient.FirebaseClients) (*FirebaseRepository, error) {
	return &FirebaseRepository{
		firestoreClient: clients.FirestoreClient,
		authClient:      clients.AuthClient,
		ctx:             ctx,
		cfg:             cfg,
	}, nil
}

// Close closes the Firestore client
func (r *FirebaseRepository) Close() error {
	return r.firestoreClient.Close()
}

// AuthClient returns the Firebase auth client
func (r *FirebaseRepository) AuthClient() *auth.Client {
	return r.authClient
}

// generateOTP creates a 6-digit OTP
func generateOTP() string {
	rand.Seed(time.Now().UnixNano())
	return fmt.Sprintf("%06d", rand.Intn(1000000))
}

// Signup creates a new user in Firebase Authentication and stores profile in Firestore
func (r *FirebaseRepository) Signup(req model.SignupRequest) (model.SuccessResponse, *model.ErrorResponse) {
	// Check for existing email or phone
	if req.Email != "" {
		_, err := r.authClient.GetUserByEmail(r.ctx, req.Email)
		if err == nil {
			return model.SuccessResponse{}, &model.ErrorResponse{
				Status:  "error",
				Message: "Email already in use",
				Code:    400,
			}
		}
	}
	if req.Phone != "" {
		_, err := r.authClient.GetUserByPhoneNumber(r.ctx, req.Phone)
		if err == nil {
			return model.SuccessResponse{}, &model.ErrorResponse{
				Status:  "error",
				Message: "Phone number already in use",
				Code:    400,
			}
		}
	}

	if req.Username != "" {
		// assuming "users" collection with field "username"
		query := r.firestoreClient.Collection("users").Where("username", "==", req.Username).Limit(1)
		docs, err := query.Documents(r.ctx).GetAll()
		if err != nil {
			return model.SuccessResponse{}, &model.ErrorResponse{
				Status:  "error",
				Message: "Internal server error",
				Code:    500,
			}
		}
		if len(docs) > 0 {
			return model.SuccessResponse{}, &model.ErrorResponse{
				Status:  "error",
				Message: "Username already in use",
				Code:    400,
			}
		}
	}

	// Hash password with bcrypt
	hashedPassword := req.Password
	if req.Password != "" {
		hash, err := bcrypt.GenerateFromPassword([]byte(req.Password), bcrypt.DefaultCost)
		if err != nil {
			return model.SuccessResponse{}, &model.ErrorResponse{
				Status:  "error",
				Message: "Failed to hash password: " + err.Error(),
				Code:    500,
			}
		}
		hashedPassword = string(hash)
	}

	params := &auth.UserToCreate{}
	params = params.Password(hashedPassword).DisplayName(req.Username)

	if req.Phone != "" {
		params = params.PhoneNumber(req.Phone)
	}

	if req.Email != "" {
		params = params.Email(req.Email)
	}

	user, err := r.authClient.CreateUser(r.ctx, params)
	if err != nil {
		return model.SuccessResponse{}, &model.ErrorResponse{
			Status:  "error",
			Message: "Failed to create user: " + err.Error(),
			Code:    400,
		}
	}

	// Store user profile in Firestore with all required fields
	currentTime := time.Now().UTC()
	joint := []string{"Capcons"}
	isBillable := req.Password != "" && contains(joint, "Capcons")

	profile := map[string]any{
		"uid":                        user.UID,
		"email":                      req.Email,
		"phone":                      req.Phone,
		"is_phone_verified":          false,
		"is_email_verified":          false,
		"is_guest_user":              false,
		"password":                   hashedPassword,
		"joint":                      joint,
		"is_billable_user":           isBillable,
		"is_2f_needed":               false,
		"first_name":                 req.FirstName,
		"second_name":                req.SecondName,
		"user_created_date":          currentTime,
		"user_last_login_details":    currentTime,
		"country_of_origin":          "",
		"address":                    "",
		"username":                   req.Username,
		"created_at":                 currentTime,
		"updated_at":                 currentTime,
		"totp_secret":                "",
		"bio":                        "",
		"image_url":                  "",
		"email_verification_pending": false,
		"phone_verification_pending": false,
		"password_reset_pending":     false,
	}

	_, err = r.firestoreClient.Collection("users").Doc(user.UID).Set(r.ctx, profile)
	if err != nil {
		_ = r.authClient.DeleteUser(r.ctx, user.UID)
		return model.SuccessResponse{}, &model.ErrorResponse{
			Status:  "error",
			Message: "Failed to store user profile: " + err.Error(),
			Code:    500,
		}
	}

	// Send verification OTP if email or phone provided
	if req.Email != "" {
		_, errResp := r.SendEmailVerification(req.Email)
		if errResp != nil {
			return model.SuccessResponse{}, errResp
		}
	} else if req.Phone != "" {
		_, errResp := r.SendPhoneVerification(req.Phone)
		if errResp != nil {
			return model.SuccessResponse{}, errResp
		}
	}

	return model.SuccessResponse{
		Status:  "success",
		Message: "User created successfully",
		Payload: map[string]interface{}{
			"uid":         user.UID,
			"email":       req.Email,
			"phone":       req.Phone,
			"username":    req.Username,
			"first_name":  req.FirstName,
			"second_name": req.SecondName,
		},
	}, nil
}

// Login verifies user credentials and TOTP code (if 2FA is enabled) and generates a custom token
func (r *FirebaseRepository) Login(req model.LoginRequest) (model.TokenResponse, *model.ErrorResponse) {
	var user *auth.UserRecord
	var err error

	// Check if credential is an email or phone
	if strings.Contains(req.Credential, "@") {
		user, err = r.authClient.GetUserByEmail(r.ctx, req.Credential)
	} else {
		user, err = r.authClient.GetUserByPhoneNumber(r.ctx, req.Credential)
	}
	if err != nil {
		return model.TokenResponse{}, &model.ErrorResponse{
			Status:  "error",
			Message: "Invalid credentials",
			Code:    401,
		}
	}

	// Verify password
	doc, err := r.firestoreClient.Collection("users").Doc(user.UID).Get(r.ctx)
	if err != nil {
		return model.TokenResponse{}, &model.ErrorResponse{
			Status:  "error",
			Message: "Failed to retrieve profile: " + err.Error(),
			Code:    500,
		}
	}
	data := doc.Data()
	storedPassword, ok := data["password"].(string)
	if !ok || storedPassword == "" {
		return model.TokenResponse{}, &model.ErrorResponse{
			Status:  "error",
			Message: "No password set for this user",
			Code:    401,
		}
	}
	if err := bcrypt.CompareHashAndPassword([]byte(storedPassword), []byte(req.Password)); err != nil {
		return model.TokenResponse{}, &model.ErrorResponse{
			Status:  "error",
			Message: "Invalid password",
			Code:    401,
		}
	}

	// Check 2FA if enabled
	if twoFAEnabled, ok := data["is_2fa_needed"].(bool); ok && twoFAEnabled {
		totpSecret, ok := data["totp_secret"].(string)
		if !ok || totpSecret == "" {
			return model.TokenResponse{}, &model.ErrorResponse{
				Status:  "error",
				Message: "2FA is enabled but TOTP secret is missing",
				Code:    500,
			}
		}
		if req.TwoFactorCode == "" {
			return model.TokenResponse{}, &model.ErrorResponse{
				Status:  "error",
				Message: "TOTP code is required for 2FA",
				Code:    401,
			}
		}
		valid, err := totp.ValidateCustom(req.TwoFactorCode, totpSecret, time.Now(), totp.ValidateOpts{
			Period:    30,
			Skew:      0, //dont
			Digits:    otp.DigitsSix,
			Algorithm: otp.AlgorithmSHA1,
		})
		if err != nil || !valid {
			return model.TokenResponse{}, &model.ErrorResponse{
				Status:  "error",
				Message: "Invalid TOTP code",
				Code:    401,
			}
		}

	}

	// Update last login details
	_, err = r.firestoreClient.Collection("users").Doc(user.UID).Update(r.ctx, []firestore.Update{
		{Path: "user_last_login_details", Value: time.Now().UTC()},
		{Path: "updated_at", Value: time.Now().UTC()},
	})
	if err != nil {
		return model.TokenResponse{}, &model.ErrorResponse{
			Status:  "error",
			Message: "Failed to update login details: " + err.Error(),
			Code:    500,
		}
	}

	token := middleware.GenerateJWT(context.Background(), user.UID, r.cfg.JWTSecret)

	return model.TokenResponse{
		Status:  "success",
		Message: "Login successful",
		Token:   token,
	}, nil
}

// GuestLogin creates a guest user
func (r *FirebaseRepository) GuestLogin(req model.GuestLoginRequest) (model.TokenResponse, *model.ErrorResponse) {
	if req.Username != "" {
		// assuming "users" collection with field "username"
		query := r.firestoreClient.Collection("users").Where("username", "==", req.Username).Limit(1)
		docs, err := query.Documents(r.ctx).GetAll()
		if err != nil {
			return model.TokenResponse{}, &model.ErrorResponse{
				Status:  "error",
				Message: "Internal server error",
				Code:    500,
			}
		}
		if len(docs) > 0 {
			return model.TokenResponse{}, &model.ErrorResponse{
				Status:  "error",
				Message: "Username already in use",
				Code:    400,
			}
		}
	} else {
		return model.TokenResponse{}, &model.ErrorResponse{
			Status:  "error",
			Message: "Username not provided",
			Code:    400,
		}
	}
	params := (&auth.UserToCreate{}).
		DisplayName(req.Username)

	user, err := r.authClient.CreateUser(r.ctx, params)
	if err != nil {
		return model.TokenResponse{}, &model.ErrorResponse{
			Status:  "error",
			Message: "Failed to create guest user: " + err.Error(),
			Code:    500,
		}
	}

	token := middleware.GenerateJWT(context.Background(), user.UID, r.cfg.JWTSecret)

	// Store guest profile in Firestore
	currentTime := time.Now().UTC()
	profile := map[string]interface{}{
		"uid":                        user.UID,
		"email":                      "",
		"phone":                      "",
		"is_phone_verified":          false,
		"is_email_verified":          false,
		"is_guest_user":              true,
		"password":                   "",
		"joint":                      []any{"Capcons"},
		"is_billable_user":           false,
		"is_2f_needed":               false,
		"first_name":                 "",
		"second_name":                "",
		"user_created_date":          currentTime,
		"user_last_login_details":    currentTime,
		"country_of_origin":          "",
		"address":                    "",
		"username":                   req.Username,
		"created_at":                 currentTime,
		"updated_at":                 currentTime,
		"is_2fa_needed":              false,
		"totp_secret":                "",
		"bio":                        "",
		"image_url":                  "",
		"email_verification_pending": false,
		"phone_verification_pending": false,
		"password_reset_pending":     false,
	}

	_, err = r.firestoreClient.Collection("users").Doc(user.UID).Set(r.ctx, profile)
	if err != nil {
		_ = r.authClient.DeleteUser(r.ctx, user.UID)
		return model.TokenResponse{}, &model.ErrorResponse{
			Status:  "error",
			Message: "Failed to store guest profile: " + err.Error(),
			Code:    500,
		}
	}

	return model.TokenResponse{
		Status:  "success",
		Message: "Guest login successful",
		Token:   token,
	}, nil
}

// VerifyCredentials checks if the provided credential and OTP are valid
func (r *FirebaseRepository) VerifyCredentials(req model.VerifyCredentialsRequest) (model.SuccessResponse, *model.ErrorResponse) {
	var user *auth.UserRecord
	var err error
	var otpType, identifierField, identifier string

	// Determine if credential is an email or phone
	if strings.Contains(req.Credential, "@") {
		user, err = r.authClient.GetUserByEmail(r.ctx, req.Credential)
		otpType = "email_verification"
		identifierField = "email"
		identifier = req.Credential
	} else {
		user, err = r.authClient.GetUserByPhoneNumber(r.ctx, req.Credential)
		otpType = "phone_verification"
		identifierField = "phone"
		identifier = req.Credential
	}
	if err != nil {
		return model.SuccessResponse{}, &model.ErrorResponse{
			Status:  "error",
			Message: "Invalid credential: User not found",
			Code:    404,
		}
	}

	// Check for a valid OTP in the otps collection
	query := r.firestoreClient.Collection("otps").
		Where(identifierField, "==", identifier).
		Where("type", "==", otpType).
		Where("otp", "==", req.OTP).
		Limit(1)
	docs, err := query.Documents(r.ctx).GetAll()
	if err != nil {
		return model.SuccessResponse{}, &model.ErrorResponse{
			Status:  "error",
			Message: "Failed to verify OTP: " + err.Error(),
			Code:    500,
		}
	}
	if len(docs) == 0 {
		return model.SuccessResponse{}, &model.ErrorResponse{
			Status:  "error",
			Message: "Invalid OTP",
			Code:    400,
		}
	}

	// Verify OTP expiration
	otpData := docs[0].Data()
	expiresAt, ok := otpData["expires_at"].(time.Time)
	if !ok || expiresAt.Before(time.Now().UTC()) {
		return model.SuccessResponse{}, &model.ErrorResponse{
			Status:  "error",
			Message: "OTP has expired",
			Code:    400,
		}
	}

	// OTP is valid; optionally update verification status
	updates := []firestore.Update{
		{Path: "updated_at", Value: time.Now().UTC()},
	}
	if otpType == "email_verification" {
		if user.EmailVerified {
			return model.SuccessResponse{}, &model.ErrorResponse{
				Status:  "error",
				Message: "Email is already verified",
				Code:    400,
			}
		}
		// Update Firebase Authentication
		_, err = r.authClient.UpdateUser(r.ctx, user.UID, (&auth.UserToUpdate{}).EmailVerified(true))
		if err != nil {
			return model.SuccessResponse{}, &model.ErrorResponse{
				Status:  "error",
				Message: "Failed to update email verification status: " + err.Error(),
				Code:    500,
			}
		}
		updates = append(updates, []firestore.Update{
			{Path: "is_email_verified", Value: true},
			{Path: "email_verification_pending", Value: false},
		}...)
	} else if otpType == "phone_verification" {
		doc, err := r.firestoreClient.Collection("users").Doc(user.UID).Get(r.ctx)
		if err != nil {
			return model.SuccessResponse{}, &model.ErrorResponse{
				Status:  "error",
				Message: "Failed to retrieve profile: " + err.Error(),
				Code:    500,
			}
		}
		if isVerified, ok := doc.Data()["is_phone_verified"].(bool); ok && isVerified {
			return model.SuccessResponse{}, &model.ErrorResponse{
				Status:  "error",
				Message: "Phone is already verified",
				Code:    400,
			}
		}
		updates = append(updates, []firestore.Update{
			{Path: "is_phone_verified", Value: true},
			{Path: "phone_verification_pending", Value: false},
		}...)
	}

	// Update Firestore profile
	_, err = r.firestoreClient.Collection("users").Doc(user.UID).Update(r.ctx, updates)
	if err != nil {
		return model.SuccessResponse{}, &model.ErrorResponse{
			Status:  "error",
			Message: "Failed to update profile: " + err.Error(),
			Code:    500,
		}
	}

	// Delete the used OTP
	_, err = r.firestoreClient.Collection("otps").Doc(docs[0].Ref.ID).Delete(r.ctx)
	if err != nil {
		// Log the error but don't fail the request
		log.Printf("Failed to delete OTP document %s: %v", docs[0].Ref.ID, err)
	}

	return model.SuccessResponse{
		Status:  "success",
		Message: "Credentials verified successfully",
		Payload: map[string]interface{}{
			"uid": user.UID,
		},
	}, nil
}

// ForgotPassword initiates a password reset by generating an OTP
func (r *FirebaseRepository) ForgotPassword(req model.ForgotPasswordRequest) (model.SuccessResponse, *model.ErrorResponse) {
	return r.SendPasswordResetEmail(req)
}

// ResetPassword updates the user's password using an OTP
func (r *FirebaseRepository) ResetPassword(req model.ResetPasswordRequest) (model.SuccessResponse, *model.ErrorResponse) {
	// Find the OTP in the otps collection
	query := r.firestoreClient.Collection("otps").
		Where("email", "==", req.Email).
		Where("type", "==", "password_reset").
		Where("otp", "==", req.OTP).
		Limit(1)
	docs, err := query.Documents(r.ctx).GetAll()
	if err != nil || len(docs) == 0 {
		return model.SuccessResponse{}, &model.ErrorResponse{
			Status:  "error",
			Message: "Invalid or expired OTP",
			Code:    400,
		}
	}

	otpData := docs[0].Data()
	expiresAt, ok := otpData["expires_at"].(time.Time)
	if !ok || expiresAt.Before(time.Now()) {
		return model.SuccessResponse{}, &model.ErrorResponse{
			Status:  "error",
			Message: "OTP has expired",
			Code:    400,
		}
	}

	uid, ok := otpData["uid"].(string)
	if !ok {
		return model.SuccessResponse{}, &model.ErrorResponse{
			Status:  "error",
			Message: "Invalid OTP data",
			Code:    400,
		}
	}

	// Hash new password
	hash, err := bcrypt.GenerateFromPassword([]byte(req.Password), bcrypt.DefaultCost)
	if err != nil {
		return model.SuccessResponse{}, &model.ErrorResponse{
			Status:  "error",
			Message: "Failed to hash password: " + err.Error(),
			Code:    500,
		}
	}
	hashedPassword := string(hash)

	// Update the user's password
	_, err = r.authClient.UpdateUser(r.ctx, uid, (&auth.UserToUpdate{}).Password(hashedPassword))
	if err != nil {
		return model.SuccessResponse{}, &model.ErrorResponse{
			Status:  "error",
			Message: "Failed to reset password: " + err.Error(),
			Code:    400,
		}
	}

	// Update Firestore profile
	_, err = r.firestoreClient.Collection("users").Doc(uid).Update(r.ctx, []firestore.Update{
		{Path: "password", Value: hashedPassword},
		{Path: "password_reset_pending", Value: false},
		{Path: "updated_at", Value: time.Now().UTC()},
	})
	if err != nil {
		return model.SuccessResponse{}, &model.ErrorResponse{
			Status:  "error",
			Message: " MOBILE_NUMBER_ALREADY_EXISTSFailed to update profile: " + err.Error(),
			Code:    500,
		}
	}

	// Delete the used OTP
	_, err = r.firestoreClient.Collection("otps").Doc(docs[0].Ref.ID).Delete(r.ctx)
	if err != nil {
		fmt.Printf("Failed to delete OTP: %v\n", err)
	}

	return model.SuccessResponse{
		Status:  "success",
		Message: "Password reset successful",
	}, nil
}

// ChangeLogin updates a user's email after verifying the password
func (r *FirebaseRepository) ChangeLogin(req model.ChangeLoginRequest) (model.SuccessResponse, *model.ErrorResponse) {
	// Get user by UID
	user, err := r.authClient.GetUser(r.ctx, req.UID)
	if err != nil {
		return model.SuccessResponse{}, &model.ErrorResponse{
			Status:  "error",
			Message: "User not found",
			Code:    404,
		}
	}

	// Get Firestore document
	docRef := r.firestoreClient.Collection("users").Doc(user.UID)
	doc, err := docRef.Get(r.ctx)
	if err != nil {
		return model.SuccessResponse{}, &model.ErrorResponse{
			Status:  "error",
			Message: "Failed to fetch user document: " + err.Error(),
			Code:    500,
		}
	}

	// Check password
	storedHash, ok := doc.Data()["password"].(string)
	if !ok || storedHash == "" {
		return model.SuccessResponse{}, &model.ErrorResponse{
			Status:  "error",
			Message: "No password set for this user",
			Code:    401,
		}
	}
	if err := bcrypt.CompareHashAndPassword([]byte(storedHash), []byte(req.Password)); err != nil {
		return model.SuccessResponse{}, &model.ErrorResponse{
			Status:  "error",
			Message: "Invalid password",
			Code:    401,
		}
	}

	// Check if new email already exists
	if req.NewEmail != "" {
		_, err := r.authClient.GetUserByEmail(r.ctx, req.NewEmail)
		if err == nil {
			return model.SuccessResponse{}, &model.ErrorResponse{
				Status:  "error",
				Message: "Email already in use",
				Code:    400,
			}
		}
	}

	// Update Firebase Authentication with new email and unverified status
	update := (&auth.UserToUpdate{}).Email(req.NewEmail).EmailVerified(false)
	_, err = r.authClient.UpdateUser(r.ctx, req.UID, update)
	if err != nil {
		return model.SuccessResponse{}, &model.ErrorResponse{
			Status:  "error",
			Message: "Failed to update authentication: " + err.Error(),
			Code:    400,
		}
	}

	// Update Firestore in a transaction
	err = r.firestoreClient.RunTransaction(r.ctx, func(ctx context.Context, tx *firestore.Transaction) error {
		return tx.Update(docRef, []firestore.Update{
			{Path: "email", Value: req.NewEmail},
			{Path: "is_email_verified", Value: false},
			{Path: "email_verification_pending", Value: true},
			{Path: "updated_at", Value: time.Now().UTC()},
		})
	})
	if err != nil {
		// Attempt to revert Firebase Authentication update
		_, revertErr := r.authClient.UpdateUser(r.ctx, req.UID, (&auth.UserToUpdate{}).Email(user.Email).EmailVerified(user.EmailVerified))
		if revertErr != nil {
			log.Printf("Failed to revert auth email update for UID %s: %v", req.UID, revertErr)
		}
		return model.SuccessResponse{}, &model.ErrorResponse{
			Status:  "error",
			Message: "Failed to update Firestore: " + err.Error(),
			Code:    500,
		}
	}

	// Send verification email
	_, errResp := r.SendEmailVerification(req.NewEmail)
	if errResp != nil {
		// Log the error but don't fail, as the email update was successful
		log.Printf("Failed to send verification email for %s: %v", req.NewEmail, errResp.Message)
		return model.SuccessResponse{
			Status:  "success",
			Message: "Email updated successfully, but failed to send verification email",
		}, nil
	}

	return model.SuccessResponse{
		Status:  "success",
		Message: "Email updated and verification email sent",
	}, nil
}

// Enable2FA enables two-factor authentication with TOTP
func (r *FirebaseRepository) Enable2FA(req model.Enable2FARequest) (model.SuccessResponse, *model.ErrorResponse) {
	user, err := r.authClient.GetUser(r.ctx, req.UID)
	if err != nil {
		return model.SuccessResponse{}, &model.ErrorResponse{
			Status:  "error",
			Message: "User not found",
			Code:    404,
		}
	}

	// Check if 2FA is already enabled
	doc, err := r.firestoreClient.Collection("users").Doc(user.UID).Get(r.ctx)
	if err != nil {
		return model.SuccessResponse{}, &model.ErrorResponse{
			Status:  "error",
			Message: "Failed to retrieve profile: " + err.Error(),
			Code:    500,
		}
	}
	data := doc.Data()
	is2FA := false
	if val, ok := data["is_2fa_needed"]; ok {
		if b, ok := val.(bool); ok {
			is2FA = b
		}
	}

	if is2FA {
		return model.SuccessResponse{}, &model.ErrorResponse{
			Status:  "error",
			Message: "2FA is already enabled",
			Code:    400,
		}
	}

	// Generate TOTP secret
	key, err := totp.Generate(totp.GenerateOpts{
		Issuer:      "AuthenticationServiceMachineTest",
		AccountName: req.UID,
		Period:      30,
	})

	if err != nil {
		return model.SuccessResponse{}, &model.ErrorResponse{
			Status:  "error",
			Message: "Failed to generate TOTP secret: " + err.Error(),
			Code:    500,
		}
	}

	// Store TOTP secret and enable 2FA in Firestore
	_, err = r.firestoreClient.Collection("users").Doc(user.UID).Update(r.ctx, []firestore.Update{
		{Path: "is_2fa_needed", Value: true},
		{Path: "totp_secret", Value: key.Secret()},
		{Path: "updated_at", Value: time.Now().UTC()},
	})
	if err != nil {
		return model.SuccessResponse{}, &model.ErrorResponse{
			Status:  "error",
			Message: "Failed to enable 2FA: " + err.Error(),
			Code:    500,
		}
	}

	return model.SuccessResponse{
		Status:  "success",
		Message: "2FA enabled successfully",
		Payload: map[string]any{
			"totp_secret": key.Secret(),
			"totp_url":    key.URL(),
		},
	}, nil
}

// AddAltCredential adds an alternate email or phone credential
func (r *FirebaseRepository) AddAltCredential(req model.AddAltCredentialRequest) (model.SuccessResponse, *model.ErrorResponse) {
	user, err := r.authClient.GetUser(r.ctx, req.UID)
	if err != nil {
		return model.SuccessResponse{}, &model.ErrorResponse{
			Status:  "error",
			Message: "User not found",
			Code:    404,
		}
	}

	// Check if credential already in use
	if strings.Contains(req.Credential, "@") {
		_, err := r.authClient.GetUserByEmail(r.ctx, req.Credential)
		if err == nil {
			return model.SuccessResponse{}, &model.ErrorResponse{
				Status:  "error",
				Message: "Email already in use",
				Code:    400,
			}
		}
	} else {
		_, err := r.authClient.GetUserByPhoneNumber(r.ctx, req.Credential)
		if err == nil {
			return model.SuccessResponse{}, &model.ErrorResponse{
				Status:  "error",
				Message: "Phone number already in use",
				Code:    400,
			}
		}
	}

	update := &auth.UserToUpdate{}
	updates := []firestore.Update{
		{Path: "updated_at", Value: time.Now().UTC()},
	}

	if strings.Contains(req.Credential, "@") {
		update = update.Email(req.Credential)
		updates = append(updates, firestore.Update{Path: "email", Value: req.Credential})
		updates = append(updates, firestore.Update{Path: "is_email_verified", Value: false})
	} else {
		update = update.PhoneNumber(req.Credential)
		updates = append(updates, firestore.Update{Path: "phone", Value: req.Credential})
		updates = append(updates, firestore.Update{Path: "is_phone_verified", Value: false})
	}

	// Update Firebase Authentication
	_, err = r.authClient.UpdateUser(r.ctx, user.UID, update)
	if err != nil {
		return model.SuccessResponse{}, &model.ErrorResponse{
			Status:  "error",
			Message: "Failed to add alternate credential: " + err.Error(),
			Code:    400,
		}
	}

	// Update Firestore profile
	_, err = r.firestoreClient.Collection("users").Doc(user.UID).Update(r.ctx, updates)
	if err != nil {
		return model.SuccessResponse{}, &model.ErrorResponse{
			Status:  "error",
			Message: "Failed to update profile: " + err.Error(),
			Code:    500,
		}
	}

	// Send verification for new credential
	if strings.Contains(req.Credential, "@") {
		_, errResp := r.SendEmailVerification(req.Credential)
		if errResp != nil {
			return model.SuccessResponse{}, errResp
		}
	} else {
		_, errResp := r.SendPhoneVerification(req.Credential)
		if errResp != nil {
			return model.SuccessResponse{}, errResp
		}
	}

	return model.SuccessResponse{
		Status:  "success",
		Message: "Alternate credential added successfully",
	}, nil
}

// GetProfile retrieves the user's profile from Firestore
func (r *FirebaseRepository) GetProfile(uid string) (model.ProfileResponse, *model.ErrorResponse) {
	if uid == "" {
		return model.ProfileResponse{}, &model.ErrorResponse{
			Status:  "error",
			Message: "UID is required",
			Code:    400,
		}
	}

	doc, err := r.firestoreClient.Collection("users").Doc(uid).Get(r.ctx)
	if err != nil {
		return model.ProfileResponse{}, &model.ErrorResponse{
			Status:  "error",
			Message: "Failed to retrieve profile: " + err.Error(),
			Code:    404,
		}
	}

	data := doc.Data()
	resp := model.ProfileResponse{
		Status:  "success",
		Message: "Profile retrieved successfully",
	}
	resp.Payload.UID = data["uid"].(string)
	resp.Payload.Email = data["email"].(string)
	resp.Payload.Phone = data["phone"].(string)
	resp.Payload.IsPhoneVerified = data["is_phone_verified"].(bool)
	resp.Payload.IsEmailVerified = data["is_email_verified"].(bool)
	resp.Payload.IsGuestUser = data["is_guest_user"].(bool)
	resp.Payload.Joint = data["joint"].([]any)
	resp.Payload.IsBillableUser = data["is_billable_user"].(bool)
	resp.Payload.Is2FNeeded = data["is_2f_needed"].(bool)
	resp.Payload.FirstName = data["first_name"].(string)
	resp.Payload.SecondName = data["second_name"].(string)
	resp.Payload.UserCreatedDate = data["user_created_date"].(time.Time)
	resp.Payload.UserLastLoginDetails = data["user_last_login_details"].(time.Time)
	resp.Payload.CountryOfOrigin = data["country_of_origin"].(string)
	resp.Payload.Address = data["address"].(string)
	resp.Payload.Username = data["username"].(string)
	resp.Payload.CreatedAt = data["created_at"].(time.Time)
	resp.Payload.Bio = data["bio"].(string)

	return resp, nil
}

// Logout (no-op for Firebase, as tokens are stateless)
func (r *FirebaseRepository) Logout() (model.SuccessResponse, *model.ErrorResponse) {
	return model.SuccessResponse{
		Status:  "success",
		Message: "Logged out successfully",
	}, nil
}

// VerifyToken verifies a Firebase ID token
func (r *FirebaseRepository) VerifyToken(token string) (model.SuccessResponse, *model.ErrorResponse) {
	if token == "" {
		return model.SuccessResponse{}, &model.ErrorResponse{
			Status:  "error",
			Message: "Token is required",
			Code:    400,
		}
	}

	decoded, err := r.authClient.VerifyIDToken(r.ctx, token)
	if err != nil {
		return model.SuccessResponse{}, &model.ErrorResponse{
			Status:  "error",
			Message: "Invalid token: " + err.Error(),
			Code:    401,
		}
	}

	return model.SuccessResponse{
		Status:  "success",
		Message: "Token verified successfully",
		Payload: map[string]any{
			"uid": decoded.UID,
		},
	}, nil
}

// UpdateProfile updates the user's profile in Firestore and Firebase Authentication
func (r *FirebaseRepository) UpdateProfile(uid string, req model.UpdateProfileRequest) (model.SuccessResponse, *model.ErrorResponse) {
	if uid == "" {
		return model.SuccessResponse{}, &model.ErrorResponse{
			Status:  "error",
			Message: "UID is required",
			Code:    400,
		}
	}

	updates := []firestore.Update{
		{Path: "updated_at", Value: time.Now().UTC()},
	}
	if *req.Username != "" {
		updates = append(updates, firestore.Update{Path: "username", Value: req.Username})
	}
	if *req.Bio != "" {
		updates = append(updates, firestore.Update{Path: "bio", Value: req.Bio})
	}

	// Allow updating optional fields
	if req.FirstName != nil {
		updates = append(updates, firestore.Update{Path: "first_name", Value: *req.FirstName})
	}
	if req.SecondName != nil {
		updates = append(updates, firestore.Update{Path: "second_name", Value: *req.SecondName})
	}
	if req.CountryOfOrigin != nil {
		updates = append(updates, firestore.Update{Path: "country_of_origin", Value: *req.CountryOfOrigin})
	}
	if req.Address != nil {
		updates = append(updates, firestore.Update{Path: "address", Value: *req.Address})
	}

	_, err := r.firestoreClient.Collection("users").Doc(uid).Update(r.ctx, updates)
	if err != nil {
		return model.SuccessResponse{}, &model.ErrorResponse{
			Status:  "error",
			Message: "Failed to update profile: " + err.Error(),
			Code:    500,
		}
	}

	// Update Firebase Authentication
	userUpdate := &auth.UserToUpdate{}
	if *req.Username != "" {
		userUpdate = userUpdate.DisplayName(*req.Username)
	}
	_, err = r.authClient.UpdateUser(r.ctx, uid, userUpdate)
	if err != nil {
		return model.SuccessResponse{}, &model.ErrorResponse{
			Status:  "error",
			Message: "Failed to update authentication profile: " + err.Error(),
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
	if uid == "" {
		return model.SuccessResponse{}, &model.ErrorResponse{
			Status:  "error",
			Message: "UID is required",
			Code:    400,
		}
	}

	err := r.authClient.DeleteUser(r.ctx, uid)
	if err != nil {
		return model.SuccessResponse{}, &model.ErrorResponse{
			Status:  "error",
			Message: "Failed to delete account: " + err.Error(),
			Code:    400,
		}
	}

	_, err = r.firestoreClient.Collection("users").Doc(uid).Delete(r.ctx)
	if err != nil {
		return model.SuccessResponse{}, &model.ErrorResponse{
			Status:  "error",
			Message: "Failed to delete profile: " + err.Error(),
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
	if uid == "" {
		return model.SuccessResponse{}, &model.ErrorResponse{
			Status:  "error",
			Message: "UID is required",
			Code:    400,
		}
	}

	// Verify old password
	doc, err := r.firestoreClient.Collection("users").Doc(uid).Get(r.ctx)
	if err != nil {
		return model.SuccessResponse{}, &model.ErrorResponse{
			Status:  "error",
			Message: "Failed to retrieve profile: " + err.Error(),
			Code:    500,
		}
	}
	data := doc.Data()
	storedPassword, ok := data["password"].(string)
	if !ok || storedPassword == "" {
		return model.SuccessResponse{}, &model.ErrorResponse{
			Status:  "error",
			Message: "No password set for this user",
			Code:    401,
		}
	}
	if err := bcrypt.CompareHashAndPassword([]byte(storedPassword), []byte(req.OldPassword)); err != nil {
		return model.SuccessResponse{}, &model.ErrorResponse{
			Status:  "error",
			Message: "Invalid old password",
			Code:    401,
		}
	}

	// Hash new password
	hash, err := bcrypt.GenerateFromPassword([]byte(req.NewPassword), bcrypt.DefaultCost)
	if err != nil {
		return model.SuccessResponse{}, &model.ErrorResponse{
			Status:  "error",
			Message: "Failed to hash password: " + err.Error(),
			Code:    500,
		}
	}
	hashedPassword := string(hash)

	// Update password
	_, err = r.authClient.UpdateUser(r.ctx, uid, (&auth.UserToUpdate{}).Password(hashedPassword))
	if err != nil {
		return model.SuccessResponse{}, &model.ErrorResponse{
			Status:  "error",
			Message: "Failed to change password: " + err.Error(),
			Code:    400,
		}
	}

	// Update Firestore profile
	_, err = r.firestoreClient.Collection("users").Doc(uid).Update(r.ctx, []firestore.Update{
		{Path: "password", Value: hashedPassword},
		{Path: "updated_at", Value: time.Now().UTC()},
	})
	if err != nil {
		return model.SuccessResponse{}, &model.ErrorResponse{
			Status:  "error",
			Message: "Failed to update profile: " + err.Error(),
			Code:    500,
		}
	}

	return model.SuccessResponse{
		Status:  "success",
		Message: "Password changed successfully",
	}, nil
}

// ResendVerification generates and stores an OTP for email or phone verification
func (r *FirebaseRepository) ResendVerification(req model.ResendVerificationRequest) (model.ResendVerificationResponse, *model.ErrorResponse) {
	var user *auth.UserRecord
	var err error
	var verificationType, recipient, field string

	if req.Email != "" {
		user, err = r.authClient.GetUserByEmail(r.ctx, req.Email)
		verificationType = "email_verification"
		recipient = req.Email
		field = "email"
	} else if req.Phone != "" {
		user, err = r.authClient.GetUserByPhoneNumber(r.ctx, req.Phone)
		verificationType = "phone_verification"
		recipient = req.Phone
		field = "phone"
	} else {
		return model.ResendVerificationResponse{}, &model.ErrorResponse{
			Status:  "error",
			Message: "Email or phone required",
			Code:    400,
		}
	}

	if err != nil {
		return model.ResendVerificationResponse{}, &model.ErrorResponse{
			Status:  "error",
			Message: "User not found",
			Code:    404,
		}
	}

	// Check if already verified
	if field == "email" && user.EmailVerified {
		return model.ResendVerificationResponse{}, &model.ErrorResponse{
			Status:  "error",
			Message: "Email is already verified",
			Code:    400,
		}
	}
	if field == "phone" {
		doc, err := r.firestoreClient.Collection("users").Doc(user.UID).Get(r.ctx)
		if err != nil {
			return model.ResendVerificationResponse{}, &model.ErrorResponse{
				Status:  "error",
				Message: "Failed to retrieve profile: " + err.Error(),
				Code:    404,
			}
		}
		if isVerified, ok := doc.Data()["is_phone_verified"].(bool); ok && isVerified {
			return model.ResendVerificationResponse{}, &model.ErrorResponse{
				Status:  "error",
				Message: "Phone is already verified",
				Code:    400,
			}
		}
	}

	// Check for existing non-expired OTP
	query := r.firestoreClient.Collection("otps").
		Where("uid", "==", user.UID).
		Where("type", "==", verificationType).
		Where("expires_at", ">", time.Now().UTC())
	docs, err := query.Documents(r.ctx).GetAll()
	if err != nil {
		return model.ResendVerificationResponse{}, &model.ErrorResponse{
			Status:  "error",
			Message: "Failed to check existing OTPs: " + err.Error(),
			Code:    500,
		}
	}

	if len(docs) > 0 {
		// Found a non-expired OTP; do not send a new one
		otpData := docs[0].Data()
		expiresAt, ok := otpData["expires_at"].(time.Time)
		if !ok {
			return model.ResendVerificationResponse{}, &model.ErrorResponse{
				Status:  "error",
				Message: "Invalid OTP expiration data",
				Code:    500,
			}
		}
		// Calculate time remaining until expiry
		timeUntilExpiry := expiresAt.Sub(time.Now().UTC()).Round(time.Second)
		return model.ResendVerificationResponse{}, &model.ErrorResponse{
			Status:  "error",
			Message: fmt.Sprintf("An OTP is already active. Please wait %s before requesting a new one.", timeUntilExpiry),
			Code:    429, // Too Many Requests
		}
	}

	// Generate new OTP and set expiry
	otp := generateOTP()
	createdAt := time.Now()
	expiresAt := createdAt.Add(15 * time.Minute)

	// Store OTP in Firestore otps collection
	otpDoc := map[string]interface{}{
		"otp":        otp,
		"type":       verificationType,
		"uid":        user.UID,
		"email":      req.Email,
		"phone":      req.Phone,
		"created_at": createdAt.UTC(),
		"expires_at": expiresAt,
	}
	_, err = r.firestoreClient.Collection("otps").Doc(fmt.Sprintf("%s-%s-%s", user.UID, verificationType, createdAt.UTC())).Set(r.ctx, otpDoc)
	if err != nil {
		return model.ResendVerificationResponse{}, &model.ErrorResponse{
			Status:  "error",
			Message: "Failed to store OTP: " + err.Error(),
			Code:    500,
		}
	}

	// Update Firestore to mark verification as pending
	updateField := "email_verification_pending"
	if field == "phone" {
		updateField = "phone_verification_pending"
	}
	_, err = r.firestoreClient.Collection("users").Doc(user.UID).Update(r.ctx, []firestore.Update{
		{Path: updateField, Value: true},
		{Path: "updated_at", Value: time.Now().UTC()},
	})
	if err != nil {
		return model.ResendVerificationResponse{}, &model.ErrorResponse{
			Status:  "error",
			Message: "Failed to update profile: " + err.Error(),
			Code:    500,
		}
	}

	// Call utils to send OTP
	err = utils.SendVerification(r.ctx, r.firestoreClient, r.cfg, user.UID, recipient, verificationType, otp, expiresAt)
	if err != nil {
		return model.ResendVerificationResponse{}, &model.ErrorResponse{
			Status:  "error",
			Message: fmt.Sprintf("Failed to send %s verification: %v", field, err),
			Code:    400,
		}
	}

	return model.ResendVerificationResponse{
		Status:  "success",
		Message: fmt.Sprintf("%s verification OTP sent successfully", strings.Title(field)),
		Payload: map[string]string{
			"type": field,
		},
	}, nil
}

// Verify2FA verifies the TOTP code
func (r *FirebaseRepository) Verify2FA(req model.Verify2FARequest) (model.SuccessResponse, *model.ErrorResponse) {
	user, err := r.authClient.GetUser(r.ctx, req.UID)
	if err != nil {
		return model.SuccessResponse{}, &model.ErrorResponse{
			Status:  "error",
			Message: "User not found",
			Code:    404,
		}
	}

	doc, err := r.firestoreClient.Collection("users").Doc(user.UID).Get(r.ctx)
	if err != nil {
		return model.SuccessResponse{}, &model.ErrorResponse{
			Status:  "error",
			Message: "Failed to retrieve profile: " + err.Error(),
			Code:    404,
		}
	}

	data := doc.Data()
	if !data["is_2fa_needed"].(bool) {
		return model.SuccessResponse{}, &model.ErrorResponse{
			Status:  "error",
			Message: "2FA not enabled",
			Code:    400,
		}
	}

	totpSecret, ok := data["totp_secret"].(string)
	if !ok || totpSecret == "" {
		return model.SuccessResponse{}, &model.ErrorResponse{
			Status:  "error",
			Message: "TOTP secret not found",
			Code:    400,
		}
	}

	// Validate TOTP code
	valid := totp.Validate(req.TwoFactorCode, totpSecret)
	if !valid {
		return model.SuccessResponse{}, &model.ErrorResponse{
			Status:  "error",
			Message: "Invalid TOTP code",
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
	if uid == "" {
		return model.SuccessResponse{}, &model.ErrorResponse{
			Status:  "error",
			Message: "UID is required",
			Code:    400,
		}
	}

	_, err := r.firestoreClient.Collection("users").Doc(uid).Update(r.ctx, []firestore.Update{
		{Path: "is_2fa_needed", Value: false},
		{Path: "totp_secret", Value: ""},
		{Path: "updated_at", Value: time.Now().UTC()},
	})
	if err != nil {
		return model.SuccessResponse{}, &model.ErrorResponse{
			Status:  "error",
			Message: "Failed to disable 2FA: " + err.Error(),
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
	if uid == "" {
		return model.TwoFAStatusResponse{}, &model.ErrorResponse{
			Status:  "error",
			Message: "UID is required",
			Code:    400,
		}
	}

	doc, err := r.firestoreClient.Collection("users").Doc(uid).Get(r.ctx)
	if err != nil {
		return model.TwoFAStatusResponse{}, &model.ErrorResponse{
			Status:  "error",
			Message: "User not found: " + err.Error(),
			Code:    404,
		}
	}

	data := doc.Data()
	resp := model.TwoFAStatusResponse{
		Status:  "success",
		Message: "2FA status retrieved successfully",
		Payload: struct {
			Enabled bool `json:"enabled"`
		}{
			Enabled: data["is_2fa_needed"].(bool),
		},
	}

	return resp, nil
}

// SendPasswordResetEmail generates and stores an OTP for password reset
func (r *FirebaseRepository) SendPasswordResetEmail(req model.ForgotPasswordRequest) (model.SuccessResponse, *model.ErrorResponse) {
	user, err := r.authClient.GetUserByEmail(r.ctx, req.Email)
	if err != nil {
		return model.SuccessResponse{}, &model.ErrorResponse{
			Status:  "error",
			Message: "User not found",
			Code:    404,
		}
	}

	// Generate OTP and set expiry
	otp := generateOTP()
	createdAt := time.Now()
	expiresAt := createdAt.Add(15 * time.Minute)

	// Store OTP in Firestore otps collection
	otpDoc := map[string]interface{}{
		"otp":        otp,
		"type":       "password_reset",
		"uid":        user.UID,
		"email":      req.Email,
		"phone":      "",
		"created_at": createdAt.UTC(),
		"expires_at": expiresAt,
	}
	_, err = r.firestoreClient.Collection("otps").Doc(fmt.Sprintf("%s-%s-%s", user.UID, "password_reset", createdAt.UTC())).Set(r.ctx, otpDoc)
	if err != nil {
		return model.SuccessResponse{}, &model.ErrorResponse{
			Status:  "error",
			Message: "Failed to store OTP: " + err.Error(),
			Code:    500,
		}
	}

	// Update Firestore to mark password reset as pending
	_, err = r.firestoreClient.Collection("users").Doc(user.UID).Update(r.ctx, []firestore.Update{
		{Path: "password_reset_pending", Value: true},
		{Path: "updated_at", Value: time.Now().UTC()},
	})
	if err != nil {
		return model.SuccessResponse{}, &model.ErrorResponse{
			Status:  "error",
			Message: "Failed to update profile: " + err.Error(),
			Code:    500,
		}
	}

	// Call utils to send OTP via email
	err = utils.SendVerification(r.ctx, r.firestoreClient, r.cfg, user.UID, req.Email, "password_reset", otp, expiresAt)
	if err != nil {
		return model.SuccessResponse{}, &model.ErrorResponse{
			Status:  "error",
			Message: "Failed to send password reset email: " + err.Error(),
			Code:    400,
		}
	}

	return model.SuccessResponse{
		Status:  "success",
		Message: "Password reset OTP sent successfully",
		Payload: map[string]any{
			"email": req.Email,
		},
	}, nil
}

// SendPhoneVerification generates and stores an OTP for phone verification
func (r *FirebaseRepository) SendPhoneVerification(phone string) (model.SuccessResponse, *model.ErrorResponse) {
	user, err := r.authClient.GetUserByPhoneNumber(r.ctx, phone)
	if err != nil {
		return model.SuccessResponse{}, &model.ErrorResponse{
			Status:  "error",
			Message: "User not found",
			Code:    404,
		}
	}

	// Check if phone is already verified
	doc, err := r.firestoreClient.Collection("users").Doc(user.UID).Get(r.ctx)
	if err != nil {
		return model.SuccessResponse{}, &model.ErrorResponse{
			Status:  "error",
			Message: "Failed to retrieve profile: " + err.Error(),
			Code:    404,
		}
	}
	if doc.Data()["is_phone_verified"].(bool) {
		return model.SuccessResponse{}, &model.ErrorResponse{
			Status:  "error",
			Message: "Phone is already verified",
			Code:    400,
		}
	}

	// Generate OTP and set expiry
	otp := generateOTP()
	createdAt := time.Now()
	expiresAt := createdAt.Add(15 * time.Minute)

	// Store OTP in Firestore otps collection
	otpDoc := map[string]interface{}{
		"otp":        otp,
		"type":       "phone_verification",
		"uid":        user.UID,
		"email":      "",
		"phone":      phone,
		"created_at": createdAt.UTC(),
		"expires_at": expiresAt,
	}
	_, err = r.firestoreClient.Collection("otps").Doc(fmt.Sprintf("%s-%s-%s", user.UID, "phone_verification", createdAt.UTC())).Set(r.ctx, otpDoc)
	if err != nil {
		return model.SuccessResponse{}, &model.ErrorResponse{
			Status:  "error",
			Message: "Failed to store OTP: " + err.Error(),
			Code:    500,
		}
	}

	// Update Firestore to mark phone verification as pending
	_, err = r.firestoreClient.Collection("users").Doc(user.UID).Update(r.ctx, []firestore.Update{
		{Path: "phone_verification_pending", Value: true},
		{Path: "updated_at", Value: time.Now().UTC()},
	})
	if err != nil {
		return model.SuccessResponse{}, &model.ErrorResponse{
			Status:  "error",
			Message: "Failed to update profile: " + err.Error(),
			Code:    500,
		}
	}

	// Call utils to send OTP via SMS
	err = utils.SendVerification(r.ctx, r.firestoreClient, r.cfg, user.UID, phone, "phone_verification", otp, expiresAt)
	if err != nil {
		return model.SuccessResponse{}, &model.ErrorResponse{
			Status:  "error",
			Message: "Failed to send phone verification: " + err.Error(),
			Code:    400,
		}
	}

	return model.SuccessResponse{
		Status:  "success",
		Message: "Phone verification OTP sent successfully",
		Payload: map[string]any{
			"phone": phone,
		},
	}, nil
}

// SendEmailVerification generates and stores an OTP for email verification
func (r *FirebaseRepository) SendEmailVerification(email string) (model.SuccessResponse, *model.ErrorResponse) {
	user, err := r.authClient.GetUserByEmail(r.ctx, email)
	if err != nil {
		return model.SuccessResponse{}, &model.ErrorResponse{
			Status:  "error",
			Message: "User not found",
			Code:    404,
		}
	}

	// Check if email is already verified
	if user.EmailVerified {
		return model.SuccessResponse{}, &model.ErrorResponse{
			Status:  "error",
			Message: "Email is already verified",
			Code:    400,
		}
	}

	// Generate OTP and set expiry
	otp := generateOTP()
	createdAt := time.Now()
	expiresAt := createdAt.Add(15 * time.Minute)

	// Store OTP in Firestore otps collection
	otpDoc := map[string]interface{}{
		"otp":        otp,
		"type":       "email_verification",
		"uid":        user.UID,
		"email":      email,
		"phone":      "",
		"created_at": createdAt.UTC(),
		"expires_at": expiresAt,
	}
	_, err = r.firestoreClient.Collection("otps").Doc(fmt.Sprintf("%s-%s-%s", user.UID, "email_verification", createdAt.UTC())).Set(r.ctx, otpDoc)
	if err != nil {
		return model.SuccessResponse{}, &model.ErrorResponse{
			Status:  "error",
			Message: "Failed to store OTP: " + err.Error(),
			Code:    500,
		}
	}

	// Update Firestore to mark email verification as pending
	_, err = r.firestoreClient.Collection("users").Doc(user.UID).Update(r.ctx, []firestore.Update{
		{Path: "email_verification_pending", Value: true},
		{Path: "updated_at", Value: time.Now().UTC()},
	})
	if err != nil {
		return model.SuccessResponse{}, &model.ErrorResponse{
			Status:  "error",
			Message: "Failed to update profile: " + err.Error(),
			Code:    500,
		}
	}

	// Call utils to send OTP via email
	err = utils.SendVerification(r.ctx, r.firestoreClient, r.cfg, user.UID, email, "email_verification", otp, expiresAt)
	if err != nil {
		return model.SuccessResponse{}, &model.ErrorResponse{
			Status:  "error",
			Message: "Failed to send email verification: " + err.Error(),
			Code:    400,
		}
	}

	return model.SuccessResponse{
		Status:  "success",
		Message: "Email verification OTP sent successfully",
		Payload: map[string]any{
			"email": email,
		},
	}, nil
}

// contains checks if a string slice contains a specific value
func contains(slice []string, value string) bool {
	for _, item := range slice {
		if item == value {
			return true
		}
	}
	return false
}

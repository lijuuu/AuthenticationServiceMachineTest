package api

import (
	"github.com/gin-gonic/gin"
)

func RegisterAuthRoutes(r *gin.Engine) {
	auth := r.Group("/api/v1/auth")
	{
		auth.POST("/signup", SignupHandler)
		auth.POST("/login", LoginHandler)
		auth.POST("/guest", GuestLoginHandler)
		auth.POST("/verify", VerifyCredentialsHandler)
		auth.POST("/forgot-password", ForgotPasswordHandler)
		auth.POST("/reset-password", ResetPasswordHandler)
		auth.POST("/change-login", ChangeLoginHandler)
		auth.POST("/2fa", Enable2FAHandler)
		auth.POST("/add-credential", AddAltCredentialHandler)
		auth.GET("/profile", GetProfileHandler)

		// Auth & Session Management
		auth.POST("/logout", LogoutHandler)              // Logout user
		auth.POST("/token/refresh", RefreshTokenHandler) // Refresh token
		auth.GET("/verify-token", VerifyTokenHandler)    // Verify if token is valid

		// User Account Management
		auth.PUT("/profile", UpdateProfileHandler)           // Update user profile
		auth.DELETE("/account", DeleteAccountHandler)        // Soft Delete account
		auth.POST("/change-password", ChangePasswordHandler) // Change password

		// Contact & Credential Management
		auth.POST("/verify-email", VerifyEmailHandler)               // Send email verification
		auth.POST("/verify-phone", VerifyPhoneHandler)               // Send phone verification
		auth.POST("/resend-verification", ResendVerificationHandler) // Resend email/phone verification

		// 2FA Management
		auth.POST("/2fa/verify", Verify2FAHandler)     // Verify 2FA during login
		auth.DELETE("/2fa/disable", Disable2FAHandler) // Disable 2FA
		auth.GET("/2fa/status", Get2FAStatusHandler)   // Get 2FA status
	}
}

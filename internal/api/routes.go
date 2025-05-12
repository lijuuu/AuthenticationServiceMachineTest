package api

import (
	"context"

	"firebase.google.com/go/auth"
	"github.com/gin-gonic/gin"
	"github.com/lijuuu/AuthenticationServiceMachineTest/config"
	"github.com/lijuuu/AuthenticationServiceMachineTest/internal/middleware"
)

// RegisterAuthRoutes sets up authentication-related routes with middleware
func RegisterAuthRoutes(r *gin.Engine, handler *Handler, authClient *auth.Client, ctx context.Context, cfg config.Config) {

	r.GET("/health", func(ctx *gin.Context) {
		ctx.JSON(200, map[string]any{
			"success": true,
		})
	})

	auth := r.Group("/api/v1/auth")
	{
		// Public routes (no authentication required)
		auth.POST("/signup", handler.SignupHandler)
		auth.POST("/login", handler.LoginHandler)
		auth.POST("/guest", handler.GuestLoginHandler)
		auth.POST("/verify", handler.VerifyCredentialsHandler)
		auth.POST("/forgot-password", handler.ForgotPasswordHandler)
		auth.POST("/reset-password", handler.ResetPasswordHandler)
		auth.POST("/resend-verification", handler.ResendVerificationHandler)

		// Protected routes (require valid Firebase ID token)
		protected := auth.Group("/")
		protected.Use(middleware.AuthMiddleware(cfg.JWTSecret))
		{
			// Authentication & Session Management
			protected.GET("/verify-token", handler.VerifyTokenHandler)

			// User Account Management
			protected.GET("/profile", handler.GetProfileHandler)
			protected.PUT("/profile", handler.UpdateProfileHandler)
			protected.DELETE("/account", handler.DeleteAccountHandler)
			protected.POST("/change-password", handler.ChangePasswordHandler)
			protected.POST("/change-login", handler.ChangeLoginHandler)

			// Contact & Credential Management
			protected.POST("/add-credential", handler.AddAltCredentialHandler)

			// 2FA Management
			protected.POST("/2fa", handler.Enable2FAHandler)
			protected.POST("/2fa/verify", handler.Verify2FAHandler)
			protected.DELETE("/2fa/disable", handler.Disable2FAHandler)
			protected.GET("/2fa/status", handler.Get2FAStatusHandler)
		}
	}
}

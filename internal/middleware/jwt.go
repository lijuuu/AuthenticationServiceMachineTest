package middleware

import (
	"context"
	"net/http"
	"strings"

	"firebase.google.com/go/auth"
	"github.com/gin-gonic/gin"
	"github.com/lijuuu/AuthenticationServiceMachineTest/internal/model"
)

// AuthMiddleware creates a Gin middleware to verify Firebase ID tokens
func AuthMiddleware(authClient *auth.Client, ctx context.Context) gin.HandlerFunc {
	return func(c *gin.Context) {
		// Get the Authorization header
		authHeader := c.GetHeader("Authorization")
		if authHeader == "" {
			c.JSON(http.StatusUnauthorized, model.ErrorResponse{
				Status:  "error",
				Message: "Authorization header is missing",
				Code:    http.StatusUnauthorized,
			})
			c.Abort()
			return
		}

		// Expect header format: "Bearer <ID_TOKEN>"
		parts := strings.Split(authHeader, " ")
		if len(parts) != 2 || strings.ToLower(parts[0]) != "bearer" {
			c.JSON(http.StatusUnauthorized, model.ErrorResponse{
				Status:  "error",
				Message: "Invalid Authorization header format. Expected: Bearer <token>",
				Code:    http.StatusUnauthorized,
			})
			c.Abort()
			return
		}

		idToken := parts[1]

		// Verify the ID token using Firebase Admin SDK
		token, err := authClient.VerifyIDToken(ctx, idToken)
		if err != nil {
			c.JSON(http.StatusUnauthorized, model.ErrorResponse{
				Status:  "error",
				Message: "Invalid or expired token: " + err.Error(),
				Code:    http.StatusUnauthorized,
			})
			c.Abort()
			return
		}

		// Store the UID in the Gin context for downstream handlers
		c.Set("uid", token.UID)

		// Continue to the next handler
		c.Next()
	}
}

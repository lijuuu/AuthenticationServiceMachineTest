package middleware

import (
	"context"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt"
	"github.com/lijuuu/AuthenticationServiceMachineTest/internal/model"
)

// AuthMiddleware creates a Gin middleware to verify Firebase ID tokens
func AuthMiddleware(jwtSecret string) gin.HandlerFunc {
	return func(c *gin.Context) {
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

		tokenStr := parts[1]
		secret := []byte(jwtSecret)

		token, err := jwt.Parse(tokenStr, func(t *jwt.Token) (interface{}, error) {
			// validate signing method
			if _, ok := t.Method.(*jwt.SigningMethodHMAC); !ok {
				return nil, jwt.ErrSignatureInvalid
			}
			return secret, nil
		})

		if err != nil || !token.Valid {
			c.JSON(http.StatusUnauthorized, model.ErrorResponse{
				Status:  "error",
				Message: "Invalid or expired JWT: " + err.Error(),
				Code:    http.StatusUnauthorized,
			})
			c.Abort()
			return
		}

		claims, ok := token.Claims.(jwt.MapClaims)
		if !ok || claims["sub"] == nil {
			c.JSON(http.StatusUnauthorized, model.ErrorResponse{
				Status:  "error",
				Message: "Invalid JWT claims",
				Code:    http.StatusUnauthorized,
			})
			c.Abort()
			return
		}

		uid := claims["sub"].(string)
		c.Set("uid", uid)
		c.Next()
	}
}

func GenerateJWT(ctx context.Context, uid, jwtsecret string) string {
	secret := []byte(jwtsecret)

	//define claims
	claims := jwt.MapClaims{
		"sub": uid,                                   // subject = user id
		"exp": time.Now().Add(24 * time.Hour).Unix(), // expires in 24h
		"iat": time.Now().Unix(),                     // issued at
	}

	//create token
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)

	//sign the token
	signedToken, err := token.SignedString(secret)
	if err != nil {
		log.Printf("failed to sign JWT: %v", err)
		return ""
	}

	return signedToken
}

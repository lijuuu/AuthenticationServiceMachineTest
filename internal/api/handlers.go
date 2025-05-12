package api

import (
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/lijuuu/AuthenticationServiceMachineTest/internal/model"
	services "github.com/lijuuu/AuthenticationServiceMachineTest/internal/service"
)

// Handler holds the AuthService dependency
type Handler struct {
	Auth services.AuthService
}

// NewHandler creates a new Handler instance
func NewHandler(auth services.AuthService) *Handler {
	return &Handler{Auth: auth}
}

// SignupHandler handles user signup requests
func (h *Handler) SignupHandler(c *gin.Context) {
	var req model.SignupRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, model.ErrorResponse{
			Status:  "error",
			Message: "Invalid request body",
			Code:    http.StatusBadRequest,
		})
		return
	}

	if err := model.ValidateRequest(req); err != nil {
		c.JSON(http.StatusBadRequest, model.ErrorResponse{
			Status:  "error",
			Message: "Invalid request body " + err.Error(),
			Code:    http.StatusBadRequest,
		})
		return
	}

	req.Phone = strings.ReplaceAll(req.Phone, " ", "")

	resp, err := h.Auth.Signup(req)
	if err != nil {
		c.JSON(err.Code, err)
		return
	}

	c.JSON(http.StatusOK, resp)
}

// LoginHandler handles user login requests
func (h *Handler) LoginHandler(c *gin.Context) {
	var req model.LoginRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, model.ErrorResponse{
			Status:  "error",
			Message: "Invalid request body",
			Code:    http.StatusBadRequest,
		})
		return
	}

	if err := model.ValidateRequest(req); err != nil {
		c.JSON(http.StatusBadRequest, model.ErrorResponse{
			Status:  "error",
			Message: "Invalid request body " + err.Error(),
			Code:    http.StatusBadRequest,
		})
		return
	}

	resp, err := h.Auth.Login(req)
	if err != nil {
		c.JSON(err.Code, err)
		return
	}

	c.JSON(http.StatusOK, resp)
}

// GuestLoginHandler handles guest login requests
func (h *Handler) GuestLoginHandler(c *gin.Context) {

	var req model.GuestLoginRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, model.ErrorResponse{
			Status:  "error",
			Message: "Invalid request body",
			Code:    http.StatusBadRequest,
		})
		return
	}

	resp, err := h.Auth.GuestLogin(req)
	if err != nil {
		c.JSON(err.Code, err)
		return
	}

	c.JSON(http.StatusOK, resp)
}

// VerifyCredentialsHandler handles credential verification requests
func (h *Handler) VerifyCredentialsHandler(c *gin.Context) {
	var req model.VerifyCredentialsRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, model.ErrorResponse{
			Status:  "error",
			Message: "Invalid request body",
			Code:    http.StatusBadRequest,
		})
		return
	}

	if err := model.ValidateRequest(req); err != nil {
		c.JSON(http.StatusBadRequest, model.ErrorResponse{
			Status:  "error",
			Message: "Invalid request body " + err.Error(),
			Code:    http.StatusBadRequest,
		})
		return
	}

	resp, err := h.Auth.VerifyCredentials(req)
	if err != nil {
		c.JSON(err.Code, err)
		return
	}

	c.JSON(http.StatusOK, resp)
}

// ForgotPasswordHandler handles password reset initiation requests
func (h *Handler) ForgotPasswordHandler(c *gin.Context) {
	var req model.ForgotPasswordRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, model.ErrorResponse{
			Status:  "error",
			Message: "Invalid request body",
			Code:    http.StatusBadRequest,
		})
		return
	}

	if err := model.ValidateRequest(req); err != nil {
		c.JSON(http.StatusBadRequest, model.ErrorResponse{
			Status:  "error",
			Message: "Invalid request body " + err.Error(),
			Code:    http.StatusBadRequest,
		})
		return
	}

	resp, err := h.Auth.ForgotPassword(req)
	if err != nil {
		c.JSON(err.Code, err)
		return
	}

	c.JSON(http.StatusOK, resp)
}

// ResetPasswordHandler handles password reset requests
func (h *Handler) ResetPasswordHandler(c *gin.Context) {
	var req model.ResetPasswordRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, model.ErrorResponse{
			Status:  "error",
			Message: "Invalid request body",
			Code:    http.StatusBadRequest,
		})
		return
	}
	if err := model.ValidateRequest(req); err != nil {
		c.JSON(http.StatusBadRequest, model.ErrorResponse{
			Status:  "error",
			Message: "Invalid request body " + err.Error(),
			Code:    http.StatusBadRequest,
		})
		return
	}

	resp, err := h.Auth.ResetPassword(req)
	if err != nil {
		c.JSON(err.Code, err)
		return
	}

	c.JSON(http.StatusOK, resp)
}

// ChangeLoginHandler handles login credential change requests
func (h *Handler) ChangeLoginHandler(c *gin.Context) {
	var req model.ChangeLoginRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, model.ErrorResponse{
			Status:  "error",
			Message: "Invalid request body",
			Code:    http.StatusBadRequest,
		})
		return
	}

	if err := model.ValidateRequest(req); err != nil {
		c.JSON(http.StatusBadRequest, model.ErrorResponse{
			Status:  "error",
			Message: "Invalid request body " + err.Error(),
			Code:    http.StatusBadRequest,
		})
		return
	}

	resp, err := h.Auth.ChangeLogin(req)
	if err != nil {
		c.JSON(err.Code, err)
		return
	}

	c.JSON(http.StatusOK, resp)
}

// Enable2FAHandler handles 2FA enablement requests
func (h *Handler) Enable2FAHandler(c *gin.Context) {
	var req model.Enable2FARequest

	req.UID = c.MustGet("uid").(string)
	if err := model.ValidateRequest(req); err != nil {
		c.JSON(http.StatusBadRequest, model.ErrorResponse{
			Status:  "error",
			Message: "Invalid request body " + err.Error(),
			Code:    http.StatusBadRequest,
		})
		return
	}

	resp, err := h.Auth.Enable2FA(req)
	if err != nil {
		c.JSON(err.Code, err)
		return
	}

	c.JSON(http.StatusOK, resp)
}

// AddAltCredentialHandler handles adding alternate credential requests
func (h *Handler) AddAltCredentialHandler(c *gin.Context) {
	var req model.AddAltCredentialRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, model.ErrorResponse{
			Status:  "error",
			Message: "Invalid request body",
			Code:    http.StatusBadRequest,
		})
		return
	}

	req.UID = c.MustGet("uid").(string)

	if err := model.ValidateRequest(req); err != nil {
		c.JSON(http.StatusBadRequest, model.ErrorResponse{
			Status:  "error",
			Message: "Invalid request body " + err.Error(),
			Code:    http.StatusBadRequest,
		})
		return
	}

	resp, err := h.Auth.AddAltCredential(req)
	if err != nil {
		c.JSON(err.Code, err)
		return
	}

	c.JSON(http.StatusOK, resp)
}

// GetProfileHandler handles profile retrieval requests
func (h *Handler) GetProfileHandler(c *gin.Context) {
	uid := c.MustGet("uid").(string)

	resp, err := h.Auth.GetProfile(uid)
	if err != nil {
		c.JSON(err.Code, err)
		return
	}

	c.JSON(http.StatusOK, resp)
}

// LogoutHandler handles logout requests
func (h *Handler) LogoutHandler(c *gin.Context) {
	resp, err := h.Auth.Logout()
	if err != nil {
		c.JSON(err.Code, err)
		return
	}

	c.JSON(http.StatusOK, resp)
}

// VerifyTokenHandler handles token verification requests
func (h *Handler) VerifyTokenHandler(c *gin.Context) {

	uid := c.MustGet("uid")

	c.JSON(http.StatusOK, model.SuccessResponse{
		Status:  "success",
		Message: "Token verified successfully",
		Payload: map[string]any{
			"uid": uid,
		},
	})
}

// UpdateProfileHandler handles profile update requests
func (h *Handler) UpdateProfileHandler(c *gin.Context) {
	var req model.UpdateProfileRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, model.ErrorResponse{
			Status:  "error",
			Message: "Invalid request body",
			Code:    http.StatusBadRequest,
		})
		return
	}

	if err := model.ValidateRequest(req); err != nil {
		c.JSON(http.StatusBadRequest, model.ErrorResponse{
			Status:  "error",
			Message: "Invalid request body " + err.Error(),
			Code:    http.StatusBadRequest,
		})
		return
	}

	uid := c.MustGet("uid").(string)

	resp, err := h.Auth.UpdateProfile(uid, req)
	if err != nil {
		c.JSON(err.Code, err)
		return
	}

	c.JSON(http.StatusOK, resp)
}

// DeleteAccountHandler handles account deletion requests
func (h *Handler) DeleteAccountHandler(c *gin.Context) {
	uid := c.MustGet("uid").(string)

	resp, err := h.Auth.DeleteAccount(uid)
	if err != nil {
		c.JSON(err.Code, err)
		return
	}

	c.JSON(http.StatusOK, resp)
}

// ChangePasswordHandler handles password change requests
func (h *Handler) ChangePasswordHandler(c *gin.Context) {
	var req model.ChangePasswordRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, model.ErrorResponse{
			Status:  "error",
			Message: "Invalid request body",
			Code:    http.StatusBadRequest,
		})
		return
	}

	if err := model.ValidateRequest(req); err != nil {
		c.JSON(http.StatusBadRequest, model.ErrorResponse{
			Status:  "error",
			Message: "Invalid request body " + err.Error(),
			Code:    http.StatusBadRequest,
		})
		return
	}

	uid := c.MustGet("uid").(string)

	resp, err := h.Auth.ChangePassword(uid, req)
	if err != nil {
		c.JSON(err.Code, err)
		return
	}

	c.JSON(http.StatusOK, resp)
}

// VerifyEmailHandler handles email verification requests
func (h *Handler) VerifyEmailHandler(c *gin.Context) {
	var req model.VerifyEmailRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, model.ErrorResponse{
			Status:  "error",
			Message: "Invalid request body",
			Code:    http.StatusBadRequest,
		})
		return
	}

	if err := model.ValidateRequest(req); err != nil {
		c.JSON(http.StatusBadRequest, model.ErrorResponse{
			Status:  "error",
			Message: "Invalid request body " + err.Error(),
			Code:    http.StatusBadRequest,
		})
		return
	}

	resp, err := h.Auth.VerifyEmail(req)
	if err != nil {
		c.JSON(err.Code, err)
		return
	}

	c.JSON(http.StatusOK, resp)
}

// VerifyPhoneHandler handles phone verification requests
func (h *Handler) VerifyPhoneHandler(c *gin.Context) {
	var req model.VerifyPhoneRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, model.ErrorResponse{
			Status:  "error",
			Message: "Invalid request body",
			Code:    http.StatusBadRequest,
		})
		return
	}

	if err := model.ValidateRequest(req); err != nil {
		c.JSON(http.StatusBadRequest, model.ErrorResponse{
			Status:  "error",
			Message: "Invalid request body " + err.Error(),
			Code:    http.StatusBadRequest,
		})
		return
	}

	resp, err := h.Auth.VerifyPhone(req)
	if err != nil {
		c.JSON(err.Code, err)
		return
	}

	c.JSON(http.StatusOK, resp)
}

// ResendVerificationHandler handles resending verification requests
func (h *Handler) ResendVerificationHandler(c *gin.Context) {
	var req model.ResendVerificationRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, model.ErrorResponse{
			Status:  "error",
			Message: "Invalid request body",
			Code:    http.StatusBadRequest,
		})
		return
	}

	if err := model.ValidateRequest(req); err != nil {
		c.JSON(http.StatusBadRequest, model.ErrorResponse{
			Status:  "error",
			Message: "Invalid request body " + err.Error(),
			Code:    http.StatusBadRequest,
		})
		return
	}

	resp, err := h.Auth.ResendVerification(req)
	if err != nil {
		c.JSON(err.Code, err)
		return
	}

	c.JSON(http.StatusOK, resp)
}

// Verify2FAHandler handles 2FA verification requests
func (h *Handler) Verify2FAHandler(c *gin.Context) {
	var req model.Verify2FARequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, model.ErrorResponse{
			Status:  "error",
			Message: "Invalid request body",
			Code:    http.StatusBadRequest,
		})
		return
	}

	req.UID = c.MustGet("uid").(string)

	if err := model.ValidateRequest(req); err != nil {
		c.JSON(http.StatusBadRequest, model.ErrorResponse{
			Status:  "error",
			Message: "Invalid request body " + err.Error(),
			Code:    http.StatusBadRequest,
		})
		return
	}

	resp, err := h.Auth.Verify2FA(req)
	if err != nil {
		c.JSON(err.Code, err)
		return
	}

	c.JSON(http.StatusOK, resp)
}

// Disable2FAHandler handles disabling 2FA requests
func (h *Handler) Disable2FAHandler(c *gin.Context) {
	uid := c.MustGet("uid").(string)

	resp, err := h.Auth.Disable2FA(uid)
	if err != nil {
		c.JSON(err.Code, err)
		return
	}

	c.JSON(http.StatusOK, resp)
}

// Get2FAStatusHandler handles retrieving 2FA status requests
func (h *Handler) Get2FAStatusHandler(c *gin.Context) {
	uid := c.MustGet("uid").(string)

	resp, err := h.Auth.Get2FAStatus(uid)
	if err != nil {
		c.JSON(err.Code, err)
		return
	}

	c.JSON(http.StatusOK, resp)
}

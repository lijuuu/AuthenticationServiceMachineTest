package api

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/lijuuu/AuthenticationServiceMachineTest/internal/model"
	"github.com/lijuuu/AuthenticationServiceMachineTest/internal/service"
)

type Handler struct {
	Auth services.services
}

func NewHandler(auth services.services) *Handler {
	return &Handler{Auth: auth}
}

func SignupHandler(c *gin.Context) {
	var req model.SignupRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, model.ErrorResponse{
			Status:  "error",
			Message: "Invalid request body",
			Code:    http.StatusBadRequest,
		})
		return
	}

	resp, err := services.SignUp(req)
	if err != nil {
		c.JSON(err.Code, err)
		return
	}

	c.JSON(http.StatusOK, resp)
}

func LoginHandler(c *gin.Context) {
	var req model.LoginRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, model.ErrorResponse{
			Status:  "error",
			Message: "Invalid request body",
			Code:    http.StatusBadRequest,
		})
		return
	}

	resp, err := services.Login(req)
	if err != nil {
		c.JSON(err.Code, err)
		return
	}

	c.JSON(http.StatusOK, resp)
}

func GuestLoginHandler(c *gin.Context) {
	resp, err := services.GuestLogin()
	if err != nil {
		c.JSON(err.Code, err)
		return
	}

	c.JSON(http.StatusOK, resp)
}

func VerifyCredentialsHandler(c *gin.Context) {
	var req model.VerifyCredentialsRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, model.ErrorResponse{
			Status:  "error",
			Message: "Invalid request body",
			Code:    http.StatusBadRequest,
		})
		return
	}

	resp, err := services.VerifyCredentials(req)
	if err != nil {
		c.JSON(err.Code, err)
		return
	}

	c.JSON(http.StatusOK, resp)
}

func ForgotPasswordHandler(c *gin.Context) {
	var req model.ForgotPasswordRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, model.ErrorResponse{
			Status:  "error",
			Message: "Invalid request body",
			Code:    http.StatusBadRequest,
		})
		return
	}

	resp, err := services.ForgotPassword(req)
	if err != nil {
		c.JSON(err.Code, err)
		return
	}

	c.JSON(http.StatusOK, resp)
}

func ResetPasswordHandler(c *gin.Context) {
	var req model.ResetPasswordRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, model.ErrorResponse{
			Status:  "error",
			Message: "Invalid request body",
			Code:    http.StatusBadRequest,
		})
		return
	}

	resp, err := services.ResetPassword(req)
	if err != nil {
		c.JSON(err.Code, err)
		return
	}

	c.JSON(http.StatusOK, resp)
}

func ChangeLoginHandler(c *gin.Context) {
	var req model.ChangeLoginRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, model.ErrorResponse{
			Status:  "error",
			Message: "Invalid request body",
			Code:    http.StatusBadRequest,
		})
		return
	}

	resp, err := services.ChangeLogin(req)
	if err != nil {
		c.JSON(err.Code, err)
		return
	}

	c.JSON(http.StatusOK, resp)
}

func Enable2FAHandler(c *gin.Context) {
	var req model.Enable2FARequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, model.ErrorResponse{
			Status:  "error",
			Message: "Invalid request body",
			Code:    http.StatusBadRequest,
		})
		return
	}

	resp, err := services.Enable2FA(req)
	if err != nil {
		c.JSON(err.Code, err)
		return
	}

	c.JSON(http.StatusOK, resp)
}

func AddAltCredentialHandler(c *gin.Context) {
	var req model.AddAltCredentialRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, model.ErrorResponse{
			Status:  "error",
			Message: "Invalid request body",
			Code:    http.StatusBadRequest,
		})
		return
	}

	resp, err := services.AddAltCredential(req)
	if err != nil {
		c.JSON(err.Code, err)
		return
	}

	c.JSON(http.StatusOK, resp)
}

func GetProfileHandler(c *gin.Context) {
	uid := c.MustGet("uid").(string)

	resp, err := services.GetProfile(uid)
	if err != nil {
		c.JSON(err.Code, err)
		return
	}

	c.JSON(http.StatusOK, resp)
}

func LogoutHandler(c *gin.Context) {
	resp, err := services.Logout()
	if err != nil {
		c.JSON(err.Code, err)
		return
	}

	c.JSON(http.StatusOK, resp)
}

func RefreshTokenHandler(c *gin.Context) {
	var req model.RefreshTokenRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, model.ErrorResponse{
			Status:  "error",
			Message: "Invalid request body",
			Code:    http.StatusBadRequest,
		})
		return
	}

	resp, err := services.RefreshToken(req)
	if err != nil {
		c.JSON(err.Code, err)
		return
	}

	c.JSON(http.StatusOK, resp)
}

func VerifyTokenHandler(c *gin.Context) {
	token := c.Query("token")
	if token == "" {
		c.JSON(http.StatusBadRequest, model.ErrorResponse{
			Status:  "error",
			Message: "Token is required",
			Code:    http.StatusBadRequest,
		})
		return
	}

	resp, err := services.VerifyToken(token)
	if err != nil {
		c.JSON(err.Code, err)
		return
	}

	c.JSON(http.StatusOK, resp)
}

func UpdateProfileHandler(c *gin.Context) {
	var req model.UpdateProfileRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, model.ErrorResponse{
			Status:  "error",
			Message: "Invalid request body",
			Code:    http.StatusBadRequest,
		})
		return
	}

	uid := c.MustGet("uid").(string)

	resp, err := services.UpdateProfile(uid, req)
	if err != nil {
		c.JSON(err.Code, err)
		return
	}

	c.JSON(http.StatusOK, resp)
}

func DeleteAccountHandler(c *gin.Context) {
	uid := c.MustGet("uid").(string)

	resp, err := services.DeleteAccount(uid)
	if err != nil {
		c.JSON(err.Code, err)
		return
	}

	c.JSON(http.StatusOK, resp)
}

func ChangePasswordHandler(c *gin.Context) {
	var req model.ChangePasswordRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, model.ErrorResponse{
			Status:  "error",
			Message: "Invalid request body",
			Code:    http.StatusBadRequest,
		})
		return
	}

	uid := c.MustGet("uid").(string)

	resp, err := services.ChangePassword(uid, req)
	if err != nil {
		c.JSON(err.Code, err)
		return
	}

	c.JSON(http.StatusOK, resp)
}

func VerifyEmailHandler(c *gin.Context) {
	var req model.VerifyEmailRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, model.ErrorResponse{
			Status:  "error",
			Message: "Invalid request body",
			Code:    http.StatusBadRequest,
		})
		return
	}

	resp, err := services.VerifyEmail(req)
	if err != nil {
		c.JSON(err.Code, err)
		return
	}

	c.JSON(http.StatusOK, resp)
}

func VerifyPhoneHandler(c *gin.Context) {
	var req model.VerifyPhoneRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, model.ErrorResponse{
			Status:  "error",
			Message: "Invalid request body",
			Code:    http.StatusBadRequest,
		})
		return
	}

	resp, err := services.VerifyPhone(req)
	if err != nil {
		c.JSON(err.Code, err)
		return
	}

	c.JSON(http.StatusOK, resp)
}

func ResendVerificationHandler(c *gin.Context) {
	var req model.ResendVerificationRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, model.ErrorResponse{
			Status:  "error",
			Message: "Invalid request body",
			Code:    http.StatusBadRequest,
		})
		return
	}

	resp, err := services.ResendVerification(req)
	if err != nil {
		c.JSON(err.Code, err)
		return
	}

	c.JSON(http.StatusOK, resp)
}

func Verify2FAHandler(c *gin.Context) {
	var req model.Verify2FARequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, model.ErrorResponse{
			Status:  "error",
			Message: "Invalid request body",
			Code:    http.StatusBadRequest,
		})
		return
	}

	resp, err := services.Verify2FA(req)
	if err != nil {
		c.JSON(err.Code, err)
		return
	}

	c.JSON(http.StatusOK, resp)
}

func Disable2FAHandler(c *gin.Context) {
	uid := c.MustGet("uid").(string)

	resp, err := services.Disable2FA(uid)
	if err != nil {
		c.JSON(err.Code, err)
		return
	}

	c.JSON(http.StatusOK, resp)
}

func Get2FAStatusHandler(c *gin.Context) {
	uid := c.MustGet("uid").(string)

	resp, err := services.Get2FAStatus(uid)
	if err != nil {
		c.JSON(err.Code, err)
		return
	}

	c.JSON(http.StatusOK, resp)
}

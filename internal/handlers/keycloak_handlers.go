package handlers

import (
	"errors"
	"github.com/gin-gonic/gin"
	"github.com/sirupsen/logrus"
	"keycloak-token-proxy/config"
	"keycloak-token-proxy/internal/dto"
	"keycloak-token-proxy/pkg/keycloak"
	"net/http"
)

// KeycloakHandlers provides methods to handle Keycloak token exchange, refresh, and logout requests.
type KeycloakHandlers interface {
	ExchangeToken(c *gin.Context)
	RefreshToken(c *gin.Context)
	Logout(c *gin.Context)
}

type keycloakHandlers struct {
	keycloakClient keycloak.KeycloakClient
	securityConfig config.SecurityConfig
}

func NewKeycloakHandlers(keycloakClient keycloak.KeycloakClient, securityConfig config.SecurityConfig) KeycloakHandlers {
	return &keycloakHandlers{
		keycloakClient: keycloakClient,
		securityConfig: securityConfig,
	}
}

// ExchangeToken Identity Broker Login Flow 에서 나온 외부 Idp 토큰을 Keycloak Access Token 으로 교환하는 핸들러.
// 이때 refresh token을 쿠키에 저장.
func (k *keycloakHandlers) ExchangeToken(c *gin.Context) {
	var req dto.TokenExchangeReq

	if err := c.ShouldBindJSON(&req); err != nil {
		logrus.Debug(err)
		resp := dto.TokenExchangeRes{
			AccessToken: "",
			ExpiresIn:   -1,
			Result:      false,
			Message:     err.Error(),
		}
		c.JSON(http.StatusBadRequest, resp)
		return
	}

	exchangeRes, err := k.keycloakClient.ExchangeToken(&req)
	if err != nil {
		logrus.Debug(err)
		var ke *keycloak.KeycloakBadPermission
		if errors.As(err, &ke) {
			resp := dto.TokenExchangeRes{
				AccessToken: "",
				ExpiresIn:   -1,
				Result:      false,
				Message:     "Your token is not valid token",
			}
			c.JSON(http.StatusForbidden, resp)
			return
		} else {
			resp := dto.TokenExchangeRes{
				AccessToken: "",
				ExpiresIn:   -1,
				Result:      false,
				Message:     "Unknown error",
			}
			c.JSON(http.StatusInternalServerError, resp)
			return
		}
	}

	resp := dto.TokenExchangeRes{
		AccessToken: exchangeRes.AccessToken,
		ExpiresIn:   exchangeRes.ExpiresIn,
		Result:      true,
		Message:     "OK",
	}

	c.SetCookie(
		k.securityConfig.RefreshCookieName,
		exchangeRes.RefreshToken,
		k.securityConfig.RefreshMaxAge,
		k.securityConfig.RefreshAllowPath,
		k.securityConfig.RefreshDomain,
		true,
		true,
	)

	c.JSON(http.StatusOK, resp)
}

// RefreshToken 기존에 저장된 refresh token을 이용하여 새로운 access token을 발급받는 핸들러.
// 이때 기존 refresh token을 함께 갱신.
func (k *keycloakHandlers) RefreshToken(c *gin.Context) {
	refreshToken, err := c.Cookie(k.securityConfig.RefreshCookieName)
	if err != nil {
		resp := dto.TokenExchangeRes{
			AccessToken: "",
			ExpiresIn:   -1,
			Result:      false,
			Message:     "Cannot found Refresh Token",
		}
		c.JSON(http.StatusForbidden, resp)
		return
	}

	exchangeRes, err := k.keycloakClient.RefreshAccessToken(refreshToken)
	if err != nil {
		logrus.Debug(err)
		var ke *keycloak.KeycloakBadPermission
		if errors.As(err, &ke) {
			resp := dto.TokenExchangeRes{
				AccessToken: "",
				ExpiresIn:   -1,
				Result:      false,
				Message:     "Your token is not valid token",
			}
			c.JSON(http.StatusForbidden, resp)
			return
		} else {
			resp := dto.TokenExchangeRes{
				AccessToken: "",
				ExpiresIn:   -1,
				Result:      false,
				Message:     "Unknown error",
			}
			c.JSON(http.StatusInternalServerError, resp)
			return
		}
	}

	resp := dto.TokenExchangeRes{
		AccessToken: exchangeRes.AccessToken,
		ExpiresIn:   exchangeRes.ExpiresIn,
		Result:      true,
		Message:     "OK",
	}

	// Refresh token 갱신
	//c.SetSameSite(http.SameSiteNoneMode)
	//c.SetCookie(
	//	k.securityConfig.RefreshCookieName,
	//	exchangeRes.RefreshToken,
	//	k.securityConfig.RefreshMaxAge,
	//	k.securityConfig.RefreshAllowPath,
	//	k.securityConfig.RefreshDomain,
	//	true,
	//	true,
	//)
	http.SetCookie(c.Writer, &http.Cookie{
		Name:     k.securityConfig.RefreshCookieName,
		Value:    exchangeRes.RefreshToken,
		Path:     k.securityConfig.RefreshAllowPath,
		Domain:   k.securityConfig.RefreshDomain,
		MaxAge:   k.securityConfig.RefreshMaxAge,
		Secure:   true,
		HttpOnly: true,
		SameSite: http.SameSiteNoneMode,
	})
	c.JSON(http.StatusOK, resp)
}

// Logout 로그아웃 핸들러. refresh token을 쿠키에서 삭제하고 Keycloak에서 로그아웃 처리.
func (k *keycloakHandlers) Logout(c *gin.Context) {
	refreshToken, err := c.Cookie(k.securityConfig.RefreshCookieName)
	if err != nil {
		resp := dto.TokenExchangeRes{
			AccessToken: "",
			ExpiresIn:   -1,
			Result:      false,
			Message:     "Cannot found Refresh Token",
		}
		c.JSON(http.StatusForbidden, resp)
		return
	}

	err = k.keycloakClient.Logout(refreshToken)
	if err != nil {
		logrus.Debug(err)
		var ke *keycloak.KeycloakBadPermission
		if errors.As(err, &ke) {
			resp := dto.TokenExchangeRes{
				AccessToken: "",
				ExpiresIn:   -1,
				Result:      false,
				Message:     "Your token is not valid token",
			}
			c.JSON(http.StatusForbidden, resp)
			return
		} else {
			resp := dto.TokenExchangeRes{
				AccessToken: "",
				ExpiresIn:   -1,
				Result:      false,
				Message:     "Unknown error",
			}
			c.JSON(http.StatusInternalServerError, resp)
			return
		}
	}

	c.SetCookie(
		k.securityConfig.RefreshCookieName,
		refreshToken,
		-1,
		k.securityConfig.RefreshAllowPath,
		k.securityConfig.RefreshDomain,
		true,
		true,
	)

}

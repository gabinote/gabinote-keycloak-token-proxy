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

package keycloak

import (
	"bytes"
	"fmt"
	"github.com/goccy/go-json"
	"github.com/sirupsen/logrus"
	"io"
	"keycloak-token-proxy/config"
	"keycloak-token-proxy/internal/dto"
	"net/http"
	"net/url"
	"strings"
	"time"
)

type KeycloakClient interface {
	ExchangeToken(req *dto.TokenExchangeReq) (*KeycloakTokenExchangeRes, error)
	RefreshAccessToken(refreshToken string) (*KeycloakAccessTokenResponse, error)
	Logout(refreshToken string) error
}

type keycloakClient struct {
	config *config.KeycloakConfig
	client *http.Client
}

func NewKeycloakAuth(cfg *config.KeycloakConfig) KeycloakClient {
	return &keycloakClient{
		config: cfg,
		client: &http.Client{
			Timeout: time.Duration(30) * time.Second,
		},
	}
}

func (k *keycloakClient) ExchangeToken(data *dto.TokenExchangeReq) (*KeycloakTokenExchangeRes, error) {
	tokenUrl := fmt.Sprintf("%s/realms/%s/protocol/openid-connect/token", k.config.URL, k.config.Realm)

	form := url.Values{}
	form.Set("grant_type", "authorization_code")
	form.Set("client_id", k.config.ClientID)
	form.Set("code", data.ExchangeToken)
	form.Set("redirect_uri", data.RedirectionUrl)
	form.Set("code_verifier", data.CodeVerifier)

	req, err := http.NewRequest("POST", tokenUrl, bytes.NewBufferString(form.Encode()))
	if err != nil {
		return nil, &KeycloakHttpClientError{Message: err.Error()}
	}

	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := k.client.Do(req)
	if err != nil {
		return nil, &KeycloakHttpClientError{Message: err.Error()}
	}
	defer resp.Body.Close()

	logrus.Debug("token exchange resp %s", resp.Status)

	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		if resp.StatusCode == http.StatusInternalServerError {
			return nil, &KeycloakHttpClientError{Message: "Internal server error"}
		}

		if resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden {
			return nil, &KeycloakBadPermission{Message: string(body)}
		} else {
			return nil, &KeycloakHttpClientError{Message: fmt.Sprintf("KeycloakHttpClientError : %s", resp.Status)}
		}
	}

	var tokenResp KeycloakTokenExchangeRes
	if err := json.Unmarshal(body, &tokenResp); err != nil {
		return nil, &KeycloakHttpClientError{Message: "token body parse fail"}
	}

	return &tokenResp, nil
}

func (k *keycloakClient) RefreshAccessToken(refreshToken string) (*KeycloakAccessTokenResponse, error) {
	tokenUrl := fmt.Sprintf("%s/realms/%s/protocol/openid-connect/token", k.config.URL, k.config.Realm)

	form := url.Values{}
	form.Set("grant_type", "refresh_token")
	form.Set("client_id", k.config.ClientID)
	form.Set("refresh_token", refreshToken)

	req, err := http.NewRequest("POST", tokenUrl, bytes.NewBufferString(form.Encode()))
	if err != nil {
		return nil, &KeycloakHttpClientError{Message: err.Error()}
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := k.client.Do(req)
	if err != nil {
		return nil, &KeycloakHttpClientError{Message: err.Error()}
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		if resp.StatusCode == http.StatusInternalServerError {
			return nil, &KeycloakHttpClientError{Message: "Internal server error"}
		}

		if resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden {
			return nil, &KeycloakBadPermission{Message: string(body)}
		} else {
			return nil, &KeycloakHttpClientError{Message: fmt.Sprintf("KeycloakHttpClientError : %s", resp.Status)}
		}
	}

	var tokenResp KeycloakAccessTokenResponse
	if err := json.Unmarshal(body, &tokenResp); err != nil {
		return nil, &KeycloakHttpClientError{Message: "token body parse fail"}
	}

	return &tokenResp, nil
}

func (k *keycloakClient) Logout(refreshToken string) error {
	logoutUrl := fmt.Sprintf("%s/realms/%s/protocol/openid-connect/logout", k.config.URL, k.config.Realm)

	form := url.Values{}
	form.Set("client_id", k.config.ClientID)
	form.Set("client_secret", k.config.ClientSecret)
	form.Set("refresh_token", refreshToken)

	req, err := http.NewRequest("POST", logoutUrl, strings.NewReader(form.Encode()))
	if err != nil {
		return &KeycloakHttpClientError{Message: err.Error()}
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := k.client.Do(req)
	if err != nil {
		return &KeycloakHttpClientError{Message: err.Error()}
	}
	defer resp.Body.Close()

	// Keycloak 로그아웃은 204 No Content 또는 200 OK 를 반환합니다.
	if resp.StatusCode != http.StatusNoContent && resp.StatusCode != http.StatusOK {
		if resp.StatusCode != http.StatusOK {
			if resp.StatusCode == http.StatusInternalServerError {
				return &KeycloakHttpClientError{Message: "Internal server error"}
			}
			if resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden {
				return &KeycloakBadPermission{Message: "refresh token is not valid"}
			} else {
				return &KeycloakHttpClientError{Message: fmt.Sprintf("KeycloakHttpClientError : %s", resp.Status)}
			}
		}
	}
	return nil
}

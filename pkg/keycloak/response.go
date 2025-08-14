package keycloak

// KeycloakTokenExchangeRes Keycloak 에서 Idp 토큰 교환을 요청한 후 응답으로 받는 구조체.
type KeycloakTokenExchangeRes struct {
	AccessToken      string `json:"access_token"`
	ExpiresIn        int64  `json:"expires_in"`
	RefreshToken     string `json:"refresh_token,omitempty"`
	RefreshExpiresIn int    `json:"refresh_expires_in,omitempty"`
	TokenType        string `json:"token_type"`
	NotBeforePolicy  int    `json:"not-before-policy,omitempty"`
	Scope            string `json:"scope,omitempty"`
}

// KeycloakAccessTokenResponse Keycloak 에서 Access Token 갱신을 요청한 후 응답으로 받는 구조체.
type KeycloakAccessTokenResponse struct {
	AccessToken      string `json:"access_token"`
	RefreshToken     string `json:"refresh_token,omitempty"`
	ExpiresIn        int64  `json:"expires_in"`
	RefreshExpiresIn int    `json:"refresh_expires_in,omitempty"`
	TokenType        string `json:"token_type"`
	Scope            string `json:"scope,omitempty"`
}

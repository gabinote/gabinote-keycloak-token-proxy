package dto

// TokenExchangeReq represents Token Exchange request structure.
type TokenExchangeReq struct {
	ExchangeToken  string `json:"exchange_token" binding:"required"`      // Identity Broker Login Flow 에서 나온 Idp 토큰
	CodeVerifier   string `json:"code_verifier" binding:"required"`       // 클라이언트에서 제공한 pkce
	RedirectionUrl string `json:"redirection_url" binding:"required,url"` // 클라이언트에서 제공한 리다이렉션 URL
}

// TokenExchangeRes represents Token Exchange response structure.
type TokenExchangeRes struct {
	Result      bool   `json:"result"`
	Message     string `json:"message"`
	AccessToken string `json:"access_token"` // Keycloak에서 발급한 Access Token. refresh token은 제공하지 않음.
	ExpiresIn   int64  `json:"expires_in"`
}

package dto

type TokenExchangeReq struct {
	ExchangeToken  string `json:"exchange_token" binding:"required"`
	CodeVerifier   string `json:"code_verifier" binding:"required"`
	RedirectionUrl string `json:"redirection_url" binding:"required,url"`
}
type TokenExchangeRes struct {
	Result      bool   `json:"result"`
	Message     string `json:"message"`
	AccessToken string `json:"access_token"`
	ExpiresIn   int64  `json:"expires_in"`
}

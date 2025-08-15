package dto

// TokenRefreshRes represents the structure of a token refresh request.
type TokenRefreshRes struct {
	Result      bool   `json:"result"`
	Message     string `json:"message"`
	AccessToken string `json:"access_token"`
	ExpiresIn   int64  `json:"expires_in"`
}

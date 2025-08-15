package keycloak

import "fmt"

// KeycloakHttpClientError 인증 처리중 Keycloak HTTP 클라이언트에서 발생하는 에러. 즉 서버 내부 오류를 나타낸다.
type KeycloakHttpClientError struct {
	Message string
}

func (e *KeycloakHttpClientError) Error() string {
	return fmt.Sprintf("KeycloakHttpClientError : %s", e.Message)
}

// KeycloakBadPermission 인증 처리중 잘못된 권한이 있는 경우 발생하는 에러.
type KeycloakBadPermission struct {
	Message string
}

func (e *KeycloakBadPermission) Error() string {
	return fmt.Sprintf("KeycloakBadPermission : %s", e.Message)
}

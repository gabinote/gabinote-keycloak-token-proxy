package keycloak

import "fmt"

type KeycloakHttpClientError struct {
	Message string
}

func (e *KeycloakHttpClientError) Error() string {
	return fmt.Sprintf("KeycloakHttpClientError : %s", e.Message)
}

type KeycloakBadPermission struct {
	Message string
}

func (e *KeycloakBadPermission) Error() string {
	return fmt.Sprintf("KeycloakBadPermission : %s", e.Message)
}

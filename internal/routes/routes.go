package routes

import (
	"github.com/gin-gonic/gin"
	cors "github.com/rs/cors/wrapper/gin"
	"keycloak-token-proxy/internal/handlers"
)

// Router defines the interface for setting up routes and middleware in the application.
type Router interface {
	setupMiddleware()
	setupRoutes()
	GetEngine() *gin.Engine
}

type router struct {
	engine          *gin.Engine
	errorHandlers   handlers.ErrorHandlers
	healthHandlers  handlers.HealthHandlers
	keycloakHandler handlers.KeycloakHandlers
}

func NewRouter(
	errorHandlers handlers.ErrorHandlers,
	healthHandlers handlers.HealthHandlers,
	keycloakHandler handlers.KeycloakHandlers,
) Router {
	router := &router{
		engine:          gin.New(),
		errorHandlers:   errorHandlers,
		healthHandlers:  healthHandlers,
		keycloakHandler: keycloakHandler,
	}
	router.setupMiddleware()
	router.setupRoutes()

	return router
}

func (r *router) setupMiddleware() {
	// 로깅 미들웨어
	r.engine.Use(gin.Logger())
	r.engine.Use(gin.Recovery())

	// CORS 미들웨어
	corsConfig := cors.Default()
	r.engine.Use(corsConfig)
}

func (r *router) setupRoutes() {
	// 헬스체크 엔드포인트
	r.engine.GET("/health", r.healthHandlers.HealthCheck)

	// keycloak 엔드포인트
	r.engine.POST("/keycloak/exchange", r.keycloakHandler.ExchangeToken)
	r.engine.POST("/keycloak/refresh", r.keycloakHandler.RefreshToken)
	r.engine.DELETE("/keycloak/logout", r.keycloakHandler.Logout)

	// 404 핸들러
	r.engine.NoRoute(r.errorHandlers.NotFound)
	r.engine.NoMethod(r.errorHandlers.MethodNotAllowed)
}

func (r *router) GetEngine() *gin.Engine {
	return r.engine
}

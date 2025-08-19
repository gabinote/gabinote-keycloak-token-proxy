package main

import (
	"context"
	"errors"
	"fmt"
	"github.com/gin-gonic/gin"
	"keycloak-token-proxy/pkg/keycloak"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"keycloak-token-proxy/config"
	"keycloak-token-proxy/internal/handlers"
	"keycloak-token-proxy/internal/routes"

	"github.com/sirupsen/logrus"
)

func main() {
	// 설정 로드
	if err := config.LoadConfig(); err != nil {
		logrus.Fatalf("Config Load Failed : %v", err)
	}

	// 로그 설정
	logrus.SetFormatter(&logrus.JSONFormatter{})

	if config.AppConfig.Server.LoggingLevel == "debug" {
		logrus.SetLevel(logrus.DebugLevel)
	} else if config.AppConfig.Server.LoggingLevel == "error" {
		logrus.SetLevel(logrus.ErrorLevel)
	} else {
		logrus.SetLevel(logrus.InfoLevel)
	}

	if config.AppConfig.Server.ReleaseMode {
		gin.SetMode(gin.ReleaseMode)
	}

	logrus.Info("Keycloak Proxy Server Start")
	logrus.Info("Use Keycloak : " + config.AppConfig.Keycloak.URL)
	// Keycloak 인증 클라이언트 생성
	keycloakAuth := keycloak.NewKeycloakAuth(&config.AppConfig.Keycloak)

	// 핸들러 생성
	healthHandlers := handlers.NewHealthHandlers()
	errorHandlers := handlers.NewErrorHandlers()
	keyCloakHandlers := handlers.NewKeycloakHandlers(keycloakAuth, config.AppConfig.Security)

	// 라우터 생성
	router := routes.NewRouter(
		errorHandlers,
		healthHandlers,
		keyCloakHandlers,
	)

	// HTTP 서버 생성
	server := &http.Server{
		Addr:    fmt.Sprintf("%s:%d", config.AppConfig.Server.Host, config.AppConfig.Server.Port),
		Handler: router.GetEngine(),
	}

	// 서버 시작
	go func() {
		logrus.Infof("Server running on %s", server.Addr)
		if err := server.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			logrus.Fatalf("Server start failed: %v", err)
		}
	}()

	// 종료 신호 대기
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit

	logrus.Info("Shutting down server...")

	// 정상 종료를 위한 컨텍스트
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	if err := server.Shutdown(ctx); err != nil {
		logrus.Fatalf("Server forced to shutdown: %v", err)
	}

	logrus.Info("Server exited gracefully")
}

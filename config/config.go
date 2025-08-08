package config

import (
	"errors"
	"fmt"
	"github.com/sirupsen/logrus"
	"github.com/spf13/viper"
)

type Config struct {
	Server   ServerConfig   `mapstructure:"server"`
	Keycloak KeycloakConfig `mapstructure:"keycloak"`
	Security SecurityConfig `mapstructure:"security"`
}

type ServerConfig struct {
	Port int    `mapstructure:"port"`
	Host string `mapstructure:"host"`
}

type KeycloakConfig struct {
	URL          string `mapstructure:"url"`
	Realm        string `mapstructure:"realm"`
	ClientID     string `mapstructure:"client_id"`
	ClientSecret string `mapstructure:"client_secret"`
}

type SecurityConfig struct {
	RefreshMaxAge     int    `mapstructure:"refresh_max_age"`
	RefreshAllowPath  string `mapstructure:"refresh_allow_path"`
	RefreshDomain     string `mapstructure:"refresh_allow_domain"`
	RefreshCookieName string `mapstructure:"refresh_cookie_name"`
	CorsAllowedOrigin string `mapstructure:"cors_allowed_origin"`
}

var AppConfig *Config

func LoadConfig() error {
	viper.SetConfigName("config")
	viper.SetConfigType("yaml")
	viper.AddConfigPath(".")
	viper.AddConfigPath("./config")

	// 기본값 설정
	setDefaults()

	if err := viper.ReadInConfig(); err != nil {
		var configFileNotFoundError viper.ConfigFileNotFoundError
		if errors.As(err, &configFileNotFoundError) {
			logrus.Fatalf("Config file not found: %v", err)
		}
	}

	AppConfig = &Config{}
	if err := viper.Unmarshal(AppConfig); err != nil {
		return fmt.Errorf("unmarshal config: %v", err)
	}

	return nil
}

func setDefaults() {
	// 서버 기본값
	viper.SetDefault("server.port", 8080)
	viper.SetDefault("server.host", "0.0.0.0")

	// Keycloak 기본값
	viper.SetDefault("keycloak.url", "http://localhost:8080")
	viper.SetDefault("keycloak.realm", "master")
	viper.SetDefault("keycloak.client_id", "proxy-client")

	// Security 기본 값
	viper.SetDefault("security.refresh_max_age", 3600)
	viper.SetDefault("security.refresh_allow_path", "/keycloak/refresh")
	viper.SetDefault("security.refresh_allow_domain", "localhost")
	viper.SetDefault("security.refresh_cookie_name", "gabienote-refresh")
}

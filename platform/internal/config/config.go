// Package config loads platform configuration from the environment.
package config

import (
	"fmt"
	"os"
)

type Config struct {
	DatabaseURL       string
	JWTSecret         string
	Port              string
	CORSAllowedOrigin string
}

func Load() (Config, error) {
	cfg := Config{
		DatabaseURL:       os.Getenv("DATABASE_URL"),
		JWTSecret:         os.Getenv("JWT_SECRET"),
		Port:              getEnvDefault("PLATFORM_PORT", "8080"),
		CORSAllowedOrigin: getEnvDefault("CORS_ALLOWED_ORIGIN", "http://localhost:5173"),
	}

	if cfg.DatabaseURL == "" {
		return cfg, fmt.Errorf("DATABASE_URL is required")
	}
	if cfg.JWTSecret == "" || len(cfg.JWTSecret) < 16 {
		return cfg, fmt.Errorf("JWT_SECRET is required and must be at least 16 characters")
	}

	return cfg, nil
}

func getEnvDefault(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

package handlers

import (
	"github.com/gin-gonic/gin"
	"net/http"
	"time"
)

// HealthHandlers provides methods to handle health check requests.
type HealthHandlers interface {
	HealthCheck(c *gin.Context)
}

type healthHandlers struct {
}

func NewHealthHandlers() HealthHandlers {
	return &healthHandlers{}
}

func (h *healthHandlers) HealthCheck(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{
		"status":    "healthy",
		"timestamp": time.Now().Format(time.RFC3339),
	})
}

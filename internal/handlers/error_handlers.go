package handlers

import (
	"github.com/gin-gonic/gin"
	"net/http"
)

type ErrorHandlers interface {
	NotFound(c *gin.Context)
	MethodNotAllowed(c *gin.Context)
}

type errorHandlers struct {
}

func NewErrorHandlers() ErrorHandlers {
	return &errorHandlers{}
}

func (h *errorHandlers) NotFound(c *gin.Context) {
	c.JSON(http.StatusNotFound, gin.H{
		"error": "요청한 리소스를 찾을 수 없습니다",
		"path":  c.Request.URL.Path,
	})
}

func (h *errorHandlers) MethodNotAllowed(c *gin.Context) {
	c.JSON(http.StatusMethodNotAllowed, gin.H{
		"error":  "허용되지 않는 HTTP 메서드입니다",
		"method": c.Request.Method,
		"path":   c.Request.URL.Path,
	})
}

// Package response provides standardized JSON response helpers for the API.
package response

import (
	"net/http"

	"github.com/gin-gonic/gin"
)

// OK sends a 200 JSON response with the given data.
func OK(c *gin.Context, data any) {
	c.JSON(http.StatusOK, data)
}

// Created sends a 201 JSON response.
func Created(c *gin.Context, data any) {
	c.JSON(http.StatusCreated, data)
}

// NoContent sends a 204 response.
func NoContent(c *gin.Context) {
	c.Status(http.StatusNoContent)
}

// Error sends a JSON error response with the given HTTP status.
func Error(c *gin.Context, status int, msg string) {
	c.JSON(status, gin.H{"error": msg})
}

// BadRequest sends a 400 error.
func BadRequest(c *gin.Context, msg string) {
	Error(c, http.StatusBadRequest, msg)
}

// Unauthorized sends a 401 error.
func Unauthorized(c *gin.Context, msg string) {
	Error(c, http.StatusUnauthorized, msg)
}

// Forbidden sends a 403 error.
func Forbidden(c *gin.Context, msg string) {
	Error(c, http.StatusForbidden, msg)
}

// NotFound sends a 404 error.
func NotFound(c *gin.Context, msg string) {
	Error(c, http.StatusNotFound, msg)
}

// InternalError sends a 500 error.
func InternalError(c *gin.Context, msg string) {
	Error(c, http.StatusInternalServerError, msg)
}

// Paginated wraps list results with pagination metadata.
func Paginated(c *gin.Context, data any, total, limit, offset int) {
	c.JSON(http.StatusOK, gin.H{
		"data":     data,
		"total":    total,
		"limit":    limit,
		"offset":   offset,
		"has_more": offset+limit < total,
	})
}

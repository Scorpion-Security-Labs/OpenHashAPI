// Package middleware contains server-side middleware for HTTP requests
//
// Middleware is applied at three locations:
//   - On all server routes
//   - On public and private routes
//   - On particular REST endpoints
//
// The authorization model is designed to allow more granular control over
// endpoints which is then enforced by middleware and authentication
package middleware

import (
	"fmt"
	"log"
	"net/http"
	"ohaserver/internal/auth"
	"os"
	"path/filepath"
	"time"

	"github.com/gin-gonic/gin"
)

// AuthenticationCheckMiddleware verifies authentication of a request and if the
// authentication token is valid the request is allowed otherwise return an
// unauthorized response
//
// Args:
//
//	None
//
// Returns:
//
//	(gin.HandlerFunc): gin.Handler object
func AuthenticationCheckMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		err := auth.ValidateToken(c)
		if err != nil {
			c.AbortWithStatus(http.StatusUnauthorized)
			return
		}
		c.Next()
	}
}

// OpenRegistrationMiddleware controls access to the registration process
//
// If open registration is set to false then registration will be closed and
// the server will respond with a forbidden status code
//
// Args:
//
//	openRegistration (bool): controls allowance of registration requests
//
// Returns:
//
//	(gin.HandlerFunc): gin.Handler object
func OpenRegistrationMiddleware(openRegistration bool) gin.HandlerFunc {
	return func(c *gin.Context) {
		if !openRegistration {
			c.AbortWithStatus(http.StatusForbidden)
			return
		}
		c.Next()
	}
}

// LoggerMiddleware controls logging incoming requests
//
// By default all requests are logged to /var/www/OpenHashAPI/OpenHashAPI.log and the logfile
// is reset at 5 GB
//
// Args:
//
//	c (gin.Context): The Gin context object
//
// Returns:
//
//	(gin.HandlerFunc): gin.Handler object
func LoggerMiddleware(c *gin.Context) {
	startTime := time.Now()
	c.Next()
	endTime := time.Now()
	latency := endTime.Sub(startTime)

	logPath := filepath.Join("/var/www/OpenHashAPI/logs", "OpenHashAPI-Endpoint.log")
	f, err := os.OpenFile(logPath, os.O_RDWR|os.O_CREATE|os.O_APPEND, 0664)
	if err != nil {
		fmt.Println(err)
		return
	}
	defer f.Close()

	fileInfo, err := f.Stat()
	if err != nil {
		fmt.Println(err)
		return
	}
	if fileInfo.Size() > 512*1024*1024*1024 {
		err = f.Truncate(0)
		if err != nil {
			fmt.Println(err)
			return
		}
		_, err = f.Seek(0, 0)
		if err != nil {
			fmt.Println(err)
			return
		}
	}

	logger := log.New(f, "", 0)
	logger.Printf("[OHA] %v | %3d | %13v | %15s | %-7s %s\n",
		endTime.Format("2006/01/02 - 15:04:05"),
		c.Writer.Status(),
		latency,
		c.ClientIP(),
		c.Request.Method,
		c.Request.URL.Path,
	)
}

// CanSearchMiddleware controls access to search the database via API
//
// This middleware checks for authentication and then verifies the
// authentication token claims for access
//
// Args:
//
//	None
//
// Returns:
//
//	(gin.HandlerFunc): gin.Handler object
func CanSearchMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		claims, err := auth.ExtractClaimsFromContext(c)
		if err != nil {
			c.AbortWithStatus(http.StatusForbidden)
			return
		}
		canSearch, ok := claims["canSearch"].(bool)
		if !ok || !canSearch {
			c.AbortWithStatus(http.StatusForbidden)
			return
		}
		c.Next()
	}
}

// CanUploadMiddleware controls access to upload data to the database via API
//
// This middleware checks for authentication and then verifies the
// authentication token claims for access
//
// Args:
//
//	None
//
// Returns:
//
//	(gin.HandlerFunc): gin.Handler object
func CanUploadMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		claims, err := auth.ExtractClaimsFromContext(c)
		if err != nil {
			c.AbortWithStatus(http.StatusForbidden)
			return
		}
		canUpload, ok := claims["canUpload"].(bool)
		if !ok || !canUpload {
			c.AbortWithStatus(http.StatusForbidden)
			return
		}
		c.Next()
	}
}

// CanManageMiddleware controls access to manage other users permissions via
// the API
//
// This middleware checks for authentication and then verifies the
// authentication token claims for access
//
// Args:
//
//	None
//
// Returns:
//
//	(gin.HandlerFunc): gin.Handler object
func CanManageMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		claims, err := auth.ExtractClaimsFromContext(c)
		if err != nil {
			c.AbortWithStatus(http.StatusForbidden)
			return
		}
		canManage, ok := claims["canManage"].(bool)
		if !ok || !canManage {
			c.AbortWithStatus(http.StatusForbidden)
			return
		}
		c.Next()
	}
}

// CanListUserListsMiddleware controls access to list all user lists via the API
//
// This middleware checks for authentication and then verifies the
// authentication token claims for access
//
// Args:
//
// allowUserLists (bool): controls allowance of user list requests
//
// Returns:
// (gin.HandlerFunc): gin.Handler object
func CanListUserListsMiddleware(allowUserLists bool) gin.HandlerFunc {
	return func(c *gin.Context) {
		if !allowUserLists {
			c.AbortWithStatus(http.StatusForbidden)
			return
		}
		claims, err := auth.ExtractClaimsFromContext(c)
		if err != nil {
			c.AbortWithStatus(http.StatusForbidden)
			return
		}
		canList, ok := claims["canViewUserLists"].(bool)
		if !ok || !canList {
			c.AbortWithStatus(http.StatusForbidden)
			return
		}
		c.Next()
	}
}

// CanEditUserListsMiddleware controls access to edit user lists via the API
//
// This middleware checks for authentication and then verifies the
// authentication token claims for access
//
// Args:
//
// allowUserLists (bool): controls allowance of user list requests
//
// Returns:
// (gin.HandlerFunc): gin.Handler object
func CanEditUserListsMiddleware(allowUserLists bool) gin.HandlerFunc {
	return func(c *gin.Context) {
		if !allowUserLists {
			c.AbortWithStatus(http.StatusForbidden)
			return
		}
		claims, err := auth.ExtractClaimsFromContext(c)
		if err != nil {
			c.AbortWithStatus(http.StatusForbidden)
			return
		}
		canEdit, ok := claims["canEditUserLists"].(bool)
		if !ok || !canEdit {
			c.AbortWithStatus(http.StatusForbidden)
			return
		}
		c.Next()
	}
}

// MaxSizeAllowed limits the max request size to prevent errors
//
// Args:
//
//	None
//
// Returns:
//
//	(gin.HandlerFunc): gin.Handler object
func MaxSizeAllowed(n int) gin.HandlerFunc {
	return func(c *gin.Context) {
		// Convert n from gigabytes to bytes
		nBytes := int64(n) * 1024 * 1024 * 1024
		c.Request.Body = http.MaxBytesReader(c.Writer, c.Request.Body, nBytes)
		c.Next()
	}
}

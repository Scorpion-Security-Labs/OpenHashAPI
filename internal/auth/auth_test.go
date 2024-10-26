// Package auth controls REST routes related to authentication or authorization
//
// Note: For unit tests packages that required access to the backend database
// were not replicated
//
// In auth_test.go functions that required a valid JWT were not replicated
//
// The package structure is broken into three components:
// auth.go which contains the functions and structs for the routes
// auth_controller.go which contains the route handlers
// auth_test.go which contains unit tests
package auth

import (
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v4"
	"golang.org/x/crypto/bcrypt"
)

func TestValidateTokenClaims(t *testing.T) {
	// Test that ValidateTokenClaims returns an error if the "authorized" claim is not true
	claims := jwt.MapClaims{
		"authorized": false,
	}
	err := ValidateTokenClaims(claims)
	if err == nil {
		t.Error("Expected ValidateTokenClaims to return an error if the 'authorized' claim is not true")
	}

	// Test that ValidateTokenClaims returns an error if the "exp" claim is a string and the token has expired
	claims = jwt.MapClaims{
		"authorized": true,
		"exp":        strconv.FormatInt(time.Now().Add(-time.Hour).Unix(), 10),
	}
	err = ValidateTokenClaims(claims)
	if err == nil {
		t.Error("Expected ValidateTokenClaims to return an error if the 'exp' claim is a string and the token has expired")
	}

	// Test that ValidateTokenClaims returns an error if the "exp" claim is an int64 and the token has expired
	claims = jwt.MapClaims{
		"authorized": true,
		"exp":        time.Now().Add(-time.Hour).Unix(),
	}
	err = ValidateTokenClaims(claims)
	if err == nil {
		t.Error("Expected ValidateTokenClaims to return an error if the 'exp' claim is an int64 and the token has expired")
	}

	// Test that ValidateTokenClaims returns an error if any of the required claims are missing
	requiredClaims := []string{"canLogin", "canSearch", "canUpload", "canManage"}
	for _, claim := range requiredClaims {
		claims = jwt.MapClaims{
			"authorized": true,
			"exp":        time.Now().Add(time.Hour).Unix(),
		}
		err = ValidateTokenClaims(claims)
		if err == nil {
			t.Errorf("Expected ValidateTokenClaims to return an error if the '%s' claim is missing", claim)
		}
	}

	// Test that ValidateTokenClaims returns nil for valid claims
	claims = jwt.MapClaims{
		"authorized":       true,
		"exp":              time.Now().Add(time.Hour).Unix(),
		"canLogin":         true,
		"canSearch":        true,
		"canUpload":        true,
		"canManage":        true,
		"canViewUserLists": true,
		"canEditUserLists": true,
	}
	err = ValidateTokenClaims(claims)
	if err != nil {
		t.Errorf("Expected ValidateTokenClaims to return nil for valid claims, got %v", err)
	}
}

func TestExtractToken(t *testing.T) {
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)

	// Initialize the c.Request field
	c.Request, _ = http.NewRequest("GET", "/", nil)

	// Set the Authorization header
	tokenString := "test_token"
	c.Request.Header.Set("Authorization", "Bearer "+tokenString)

	// Call the ExtractToken function
	token, err := ExtractToken(c)
	if err != nil {
		t.Fatal(err)
	}

	// Check that ExtractToken returns the expected token
	if token != tokenString {
		t.Errorf("Expected ExtractToken to return %q, got %q", tokenString, token)
	}
}

func TestVerifyPassword(t *testing.T) {
	// Hash a test password
	password := "password123"
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		t.Fatal(err)
	}

	// Test that VerifyPassword returns true for the correct password
	if !VerifyPassword([]byte(password), []byte(hashedPassword)) {
		t.Error("Expected VerifyPassword to return true for the correct password")
	}

	// Test that VerifyPassword returns false for an incorrect password
	if VerifyPassword([]byte("incorrect"), []byte(hashedPassword)) {
		t.Error("Expected VerifyPassword to return false for an incorrect password")
	}
}

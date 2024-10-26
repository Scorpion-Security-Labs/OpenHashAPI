// Package auth controls REST routes related to authentication or authorization
//
// The package structure is broken into three components:
// auth.go which contains the functions and structs for the routes
// auth_controller.go which contains the route handlers
// auth_test.go which contains unit tests
package auth

import (
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"html"
	"net/http"
	"ohaserver/internal/config"
	"ohaserver/internal/models"
	"regexp"
	"strings"

	"github.com/gin-gonic/gin"
	"golang.org/x/crypto/bcrypt"
)

// RegistrationHandler is the endpoint handler for /api/register
//
// The endpoint expects an unauthorized POST request and returns a JSON
// showing success or error
//
// This endpoint is unauthorized but affected by middleware that restricts
// access based on the server configuration.
//
// The expected JSON object has two properties, username and password:
//
//	username (string): The username of the user
//	password (string): The password of the user
//
// Args:
//
//	c (gin.Context): The Gin context object
//
// Returns:
//
//	None
func RegistrationHandler(c *gin.Context) {
	var input CredentialInput

	if err := c.ShouldBindJSON(&input); err != nil {
		config.LogError("RegistrationHandler: Invalid JSON provided", err)
		customErr := models.ErrorStruct{Error: err.Error(), Message: "Invalid JSON provided", Context: "RegistrationHandler"}
		c.JSON(http.StatusBadRequest, customErr)
		return
	}

	upper := regexp.MustCompile(`[A-Z]`)
	lower := regexp.MustCompile(`[a-z]`)
	number := regexp.MustCompile(`[0-9]`)
	special := regexp.MustCompile(`[^a-zA-Z0-9\s]`)
	if len(input.Password) < 12 || !(upper.MatchString(input.Password) && lower.MatchString(input.Password) && special.MatchString(input.Password) && number.MatchString(input.Password)) || !regexp.MustCompile(`^[a-zA-Z0-9!@#$%^&*()_+=. -]*$`).MatchString(input.Password) {
		customErr := models.ErrorStruct{Error: "password must be at least 12 characters long and contain only letters, numbers, and the following special characters: !@#$%^&*()_+", Message: "Invalid password provided", Context: "RegistrationHandler"}
		c.JSON(http.StatusBadRequest, customErr)
		return
	}

	input.Username = html.EscapeString(strings.TrimSpace(input.Username))

	if models.ValidateUsernameInput(input.Username) == false {
		customErr := models.ErrorStruct{Error: "username contains invalid characters", Message: "Invalid username provided", Context: "RegistrationHandler"}
		c.JSON(http.StatusBadRequest, customErr)
		return
	}

	err := RegisterNewUser(input.Username, input.Password)
	if err != nil {
		customErr := models.ErrorStruct{Error: err.Error(), Message: "Failed to register new user", Context: "RegistrationHandler"}
		c.JSON(http.StatusBadRequest, customErr)
		return
	}

	c.JSON(http.StatusOK, "Success!")
}

// LoginHandler is the endpoint handler for /api/login
//
// The endpoint expects an unauthorized POST request and returns JSON with
// a valid JWT if successful
//
// The expected JSON object has two properties, username and password:
//
//	username (string): The username of the user
//	password (string): The password of the user
//
// Args:
//
//	c (gin.Context): The Gin context object
//
// Returns:
//
//	None
func LoginHandler(c *gin.Context) {

	var input CredentialInput

	if err := c.ShouldBindJSON(&input); err != nil {
		config.LogError("LoginHandler: Invalid JSON provided", err)
		customErr := models.ErrorStruct{Error: err.Error(), Message: "Invalid JSON provided", Context: "LoginHandler"}
		c.JSON(http.StatusBadRequest, customErr)
		return
	}

	u := User{}

	u.Username = input.Username
	u.Password = input.Password

	token, err := AuthenticationCheck(u.Username, u.Password)

	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			config.LogError("LoginHandler: Invalid username or password", err)
			customErr := models.ErrorStruct{Error: "invalid username or password", Message: "Invalid username or password", Context: "LoginHandler"}
			c.JSON(http.StatusBadRequest, customErr)
			return
		} else if err == bcrypt.ErrMismatchedHashAndPassword {
			config.LogError("LoginHandler: Invalid username or password", err)
			customErr := models.ErrorStruct{Error: "invalid username or password", Message: "Invalid username or password", Context: "LoginHandler"}
			c.JSON(http.StatusBadRequest, customErr)
			return
		} else if err.Error() == "User is not allowed to login" {
			config.LogError("LoginHandler: User is not allowed to login", err)
			customErr := models.ErrorStruct{Error: "user is not allowed to login", Message: "User is not allowed to login", Context: "LoginHandler"}
			c.JSON(http.StatusForbidden, customErr)
			return
		}
		config.LogError("LoginHandler: Something went wrong", err)
		customErr := models.ErrorStruct{Error: err.Error(), Message: "Something went wrong", Context: "LoginHandler"}
		c.JSON(http.StatusInternalServerError, customErr)
		return
	}

	jwtParts := strings.Split(token, ".")[:2]
	partsStr := strings.Join(jwtParts, ".")
	config.LogEvent(fmt.Sprintf("LoginHandler: User %s logged in", u.Username), partsStr)
	c.JSON(http.StatusOK, gin.H{"token": token})

}

// ManageUserHandler is the endpoint handler for /api/manage
//
// The endpoint expects an authorized POST request and returns a JSON
// confirming if the request was successful
//
// The expected JSON object has the following properties:
//
//	userID (int): The target users ID value
//	canLogin (bool): Whether the user can log in
//	canSearch (bool): Whether the user can search
//	canUpload (bool): Whether the user can upload
//	canManage (bool): Whether the user can manage other users
//	canViewUserLists (bool): Whether the user can view user lists
//	canEditUserLists (bool): Whether the user can edit user lists
//
// Args:
//
//	c (gin.Context): The Gin context object
//
// Returns:
//
//	None
func ManageUserHandler(c *gin.Context) {
	permissionsJSON, err := c.GetRawData()
	if err != nil {
		config.LogError("ManageUserHandler: Invalid JSON provided", err)
		customErr := models.ErrorStruct{Error: err.Error(), Message: "Invalid JSON provided", Context: "ManageUserHandler"}
		c.JSON(http.StatusBadRequest, customErr)
		return
	}

	var permissions map[string]interface{}
	err = json.Unmarshal(permissionsJSON, &permissions)
	if err != nil {
		config.LogError("ManageUserHandler: Invalid JSON provided", err)
		customErr := models.ErrorStruct{Error: err.Error(), Message: "Invalid JSON provided", Context: "ManageUserHandler"}
		c.JSON(http.StatusBadRequest, customErr)
		return
	}

	userID, ok := permissions["userID"].(float64)
	if !ok {
		config.LogError("ManageUserHandler: Invalid userID value", err)
		customErr := models.ErrorStruct{Error: "invalid userID value", Message: "Invalid userID value", Context: "ManageUserHandler"}
		c.JSON(http.StatusBadRequest, customErr)
		return
	}

	err = UpdateUserPermissions(uint(userID), permissionsJSON)
	if err != nil {
		config.LogError("ManageUserHandler: Failed to update user permissions", err)
		customErr := models.ErrorStruct{Error: err.Error(), Message: "Failed to update user permissions", Context: "ManageUserHandler"}
		c.JSON(http.StatusInternalServerError, customErr)
		return
	}

	c.JSON(http.StatusOK, gin.H{"success": true})
}

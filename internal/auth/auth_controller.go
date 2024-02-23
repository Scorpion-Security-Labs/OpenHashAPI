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
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	upper := regexp.MustCompile(`[A-Z]`)
	lower := regexp.MustCompile(`[a-z]`)
	number := regexp.MustCompile(`[0-9]`)
	special := regexp.MustCompile(`[^a-zA-Z0-9\s]`)
	if len(input.Password) < 12 || !(upper.MatchString(input.Password) && lower.MatchString(input.Password) && special.MatchString(input.Password) && number.MatchString(input.Password)) || !regexp.MustCompile(`^[a-zA-Z0-9!@#$%^&*()_+=. -]*$`).MatchString(input.Password) {
		c.JSON(http.StatusBadRequest, gin.H{"error": "password must be at least 12 characters long and contain only letters, numbers, and the following special characters: !@#$%^&*()_+"})
		return
	}

	input.Username = html.EscapeString(strings.TrimSpace(input.Username))

	if models.ValidateUsernameInput(input.Username) == false {
		c.JSON(http.StatusBadRequest, gin.H{"error": "username contains invalid characters."})
		return
	}

	err := RegisterNewUser(input.Username, input.Password)
	if err != nil {
		config.LogError("RegistrationHandler: Failed to register new user", err)
		c.JSON(http.StatusBadRequest, gin.H{"error": err})
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
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	u := User{}

	u.Username = input.Username
	u.Password = input.Password

	token, err := AuthenticationCheck(u.Username, u.Password)

	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			config.LogError("LoginHandler: Invalid username or password", err)
			c.JSON(http.StatusBadRequest, gin.H{"error": "invalid username or password"})
			return
		} else if err == bcrypt.ErrMismatchedHashAndPassword {
			config.LogError("LoginHandler: Invalid username or password", err)
			c.JSON(http.StatusBadRequest, gin.H{"error": "invalid username or password"})
			return
		} else if err.Error() == "User is not allowed to login" {
			config.LogError("LoginHandler: User is not allowed to login", err)
			c.JSON(http.StatusForbidden, gin.H{"error": "user is not allowed to login"})
			return
		}
		config.LogError("LoginHandler: Something went wrong", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "something went wrong"})
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
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid JSON provided"})
		return
	}

	var permissions map[string]interface{}
	err = json.Unmarshal(permissionsJSON, &permissions)
	if err != nil {
		config.LogError("ManageUserHandler: Invalid JSON provided", err)
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid JSON provided"})
		return
	}

	userID, ok := permissions["userID"].(float64)
	if !ok {
		config.LogError("ManageUserHandler: Invalid userID value", err)
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid userID value"})
		return
	}

	err = UpdateUserPermissions(uint(userID), permissionsJSON)
	if err != nil {
		config.LogError("ManageUserHandler: Failed to update user permissions", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to update user permissions"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"success": true})
}

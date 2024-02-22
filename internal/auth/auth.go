// Package auth controls REST routes related to authentication or authorization
//
// The package structure is broken into three components:
// auth.go which contains the functions and structs for the routes
// auth_controller.go which contains the route handlers
// auth_test.go which contains unit tests
package auth

import (
	"crypto/hmac"
	"crypto/sha256"
	"crypto/sha512"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"ohaserver/internal/config"
	"ohaserver/internal/models"
	"os"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/go-sql-driver/mysql"
	"github.com/golang-jwt/jwt/v4"
	"golang.org/x/crypto/bcrypt"
)

// CredentialInput is a struct used to hold user provided credential input
//
// The struct has two fields, Username and Password:
//
//	Username: The username of the user
//	Password: The password of the user
type CredentialInput struct {
	Username string `json:"username" binding:"required"`
	Password string `json:"password" binding:"required"`
}

// User is a struct used to hold user data
//
// The struct contains the following fields:
//
//	ID: The ID of the user
//	Username: The username of the user
//	Password: The password of the user
//	CanLogin: Whether the user can log in
//	CanSearch: Whether the user can search
//	CanUpload: Whether the user can upload
//	CanManage: Whether the user can manage other users
//	CanViewUserLists: Whether the user can view and download user lists
//	CanEditUserLists: Whether the user can edit and upload to user list
type User struct {
	ID               uint   `json:"id"`
	Username         string `json:"username"`
	Password         string `json:"password"`
	CanLogin         bool   `json:"can_login"`
	CanSearch        bool   `json:"can_search"`
	CanUpload        bool   `json:"can_upload"`
	CanManage        bool   `json:"can_manage"`
	CanViewUserLists bool   `json:"can_view_user_lists"`
	CanEditUserLists bool   `json:"can_edit_user_lists"`
}

// MySQLAuthenticate authorizes a connection to the backend DB
//
// Args:
//
//	None
//
// Returns:
//
//	db (*sql.DB): The database connection
//	err (error): Error data
func MySQLAuthenticate() (*sql.DB, error) {
	var db *sql.DB
	var err error
	serverConfig := config.ServerConfig

	mysqlConfig := mysql.Config{
		User:                 serverConfig.DatabaseUser,
		Passwd:               serverConfig.DatabasePwd,
		Net:                  "tcp",
		Addr:                 "127.0.0.1:3306",
		DBName:               "OpenHashAPI",
		AllowNativePasswords: true,
	}

	db, err = sql.Open("mysql", mysqlConfig.FormatDSN())
	if err != nil {
		return nil, err
	}

	db.SetMaxIdleConns(serverConfig.DatabaseIdleConnections)
	db.SetConnMaxLifetime(time.Hour)

	err = db.Ping()
	if err != nil {
		return nil, err
	}

	return db, nil

}

// GenerateToken will create a valid JWT using the provided claims
//
// Args:
//
//	userID (uint): The ID of the user
//	canLogin (bool): Whether the user can log in
//	canSearch (bool): Whether the user can search
//	canUpload (bool): Whether the user can upload
//	canManage (bool): Whether the user can manage other users
//	canViewUserLists (bool): Whether the user can view and download user lists
//	canEditUserLists (bool): Whether the user can edit and upload to user list
//
// Returns:
//
//	tokenString (string): The created JWT token
//	err (error): Error data
func GenerateToken(userID uint, canLogin bool, canSearch bool, canUpload bool, canManage bool, canViewUserLists bool, canEditUserLists bool) (string, error) {

	if !canLogin {
		return "", errors.New("User is not allowed to login")
	}

	serverConfig := config.ServerConfig
	pemEncodedPrivateKey, err := LoadPemEncodedKeyFromFile(serverConfig.ServerJWTPrivatePEMfilePath)
	if err != nil {
		return "", err
	}

	secretKey, err := jwt.ParseRSAPrivateKeyFromPEM(pemEncodedPrivateKey)
	if err != nil {
		return "", err
	}

	tokenLifespan := serverConfig.ServerJWTTimeToLive

	claims := jwt.MapClaims{}
	claims["authorized"] = true
	claims["userID"] = userID
	claims["canLogin"] = canLogin
	claims["canSearch"] = canSearch
	claims["canUpload"] = canUpload
	claims["canManage"] = canManage
	claims["canViewUserLists"] = canViewUserLists
	claims["canEditUserLists"] = canEditUserLists
	claims["exp"] = time.Now().Add(time.Minute * time.Duration(tokenLifespan)).Unix()

	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	tokenString, err := token.SignedString(secretKey)

	if err != nil {
		return "", err
	}

	err = ValidateTokenClaims(claims)
	if err != nil {
		return "", err
	}

	return tokenString, nil

}

// ValidateTokenClaims will validate the claims made by a JWT
//
// Args:
//
//	claims (jwt.MapClaims): The claims to be validated
//
// Return:
//
//	err (error): Error data
func ValidateTokenClaims(claims jwt.MapClaims) error {
	if claims["authorized"] != true {
		return errors.New("Unauthorized")
	}

	expirationTimeStr, ok := claims["exp"].(string)
	if ok {
		expirationTimeInt, err := strconv.ParseInt(expirationTimeStr, 10, 64)
		if err != nil {
			return err
		}

		if time.Now().Unix() > expirationTimeInt {
			return errors.New("Token has expired")
		}

	} else {
		expirationTime, ok := claims["exp"].(int64)
		if ok {
			if time.Now().Unix() > expirationTime {
				return errors.New("Token has expired")
			}
		}
	}

	_, ok = claims["canLogin"].(bool)
	if !ok {
		return errors.New("Invalid canLogin value")
	}

	_, ok = claims["canSearch"].(bool)
	if !ok {
		return errors.New("Invalid canSearch value")
	}

	_, ok = claims["canUpload"].(bool)
	if !ok {
		return errors.New("Invalid canUpload value")
	}

	_, ok = claims["canManage"].(bool)
	if !ok {
		return errors.New("Invalid canManage value")
	}

	_, ok = claims["canViewUserLists"].(bool)
	if !ok {
		return errors.New("Invalid canViewUserLists value")
	}

	_, ok = claims["canEditUserLists"].(bool)
	if !ok {
		return errors.New("Invalid canEditUserLists value")
	}

	return nil
}

// ValidateToken will validate JWT claims through gin.Context
//
// Args:
//
//	c (gin.Context): The Gin context object
//
// Returns:
//
//	err (error): Error data
func ValidateToken(c *gin.Context) error {
	serverConfig := config.ServerConfig
	pemEncodedPrivateKey, err := LoadPemEncodedKeyFromFile(serverConfig.ServerJWTPublicPEMfilePath)
	if err != nil {
		return err
	}

	secretKey, err := jwt.ParseRSAPublicKeyFromPEM(pemEncodedPrivateKey)
	if err != nil {
		return err
	}

	tokenString, err := ExtractToken(c)
	if err != nil {
		return err
	}

	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		if token.Method.Alg() != "RS256" {
			return nil, fmt.Errorf("Unexpected signing method: %v", token.Header["alg"])
		}
		return secretKey, nil
	})
	if err != nil {
		return err
	}

	claims := token.Claims.(jwt.MapClaims)
	err = ValidateTokenClaims(claims)
	if err != nil {
		return err
	}

	return nil
}

// ExtractToken will parse the JWT from the Authorization HTTP header
// or the auth_cookie HTTP cookie
//
// Args:
//
//	c (gin.Context): The Gin context object
//
// Returns:
//
//	token (string): The parsed JWT token
//	error (err): Error data
func ExtractToken(c *gin.Context) (string, error) {
	const bearerTokenPrefix = "Bearer "
	authorizationHeader := c.Request.Header.Get("Authorization")
	authCookie, _ := c.Request.Cookie("auth_token")

	if authorizationHeader == "" && authCookie == nil {
		return "", errors.New("Authorization header is missing")
	} else if authCookie != nil {
		if models.ValidateJWTCharacters(authCookie.Value) {
			authorizationHeader = fmt.Sprintf("Bearer %s", authCookie.Value)
		} else {
			return "", errors.New("Authorization header is missing")
		}
	}

	if !strings.HasPrefix(authorizationHeader, bearerTokenPrefix) {
		return "", errors.New("Authorization header must start with 'Bearer '")
	}

	token := strings.TrimPrefix(authorizationHeader, bearerTokenPrefix)

	return token, nil
}

// ExtractClaimsFromContext extracts the JWT claims from the gin.Context
//
// Args:
//
//	c (gin.Context): The Gin context object
//
// Returns:
//
//	claims (jwt.MapClaims): The JWT claims
//	err (error): Error data
func ExtractClaimsFromContext(c *gin.Context) (jwt.MapClaims, error) {
	serverConfig := config.ServerConfig
	pemEncodedPrivateKey, err := LoadPemEncodedKeyFromFile(serverConfig.ServerJWTPublicPEMfilePath)
	if err != nil {
		return nil, err
	}

	secretKey, err := jwt.ParseRSAPublicKeyFromPEM(pemEncodedPrivateKey)
	if err != nil {
		return nil, err
	}

	tokenString, err := ExtractToken(c)
	if err != nil {
		return nil, err
	}

	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		if token.Method.Alg() != "RS256" {
			return nil, fmt.Errorf("Unexpected signing method: %v", token.Header["alg"])
		}
		return secretKey, nil
	})

	if err != nil {
		return nil, err
	}

	claims := token.Claims.(jwt.MapClaims)

	return claims, nil
}

// LoadPemEncodedKeyFromFile will load a public/private PEM-encoded key file
// from the file system
//
// Args:
//
//	filename (string): The full path to the file
//
// Return:
//
//	pemEncodedPrivateKey([]byte): Byte slice of the PEM key file
//	err (error): Error data
func LoadPemEncodedKeyFromFile(filename string) ([]byte, error) {
	pemEncodedPrivateKey, err := os.ReadFile(filename)
	if err != nil {
		return nil, err
	}

	return pemEncodedPrivateKey, nil
}

// AuthenticationCheck validates the provided credentials and returns a valid
// authentication token if correct
//
// Args:
//
//	username (string): The username of the user
//	password (string): The password of the user
//
// Returns:
//
//	token (string): The generated authentication token
//	err (error): Error data
func AuthenticationCheck(username string, password string) (string, error) {

	var err error
	serverConfig := config.ServerConfig

	u := User{}
	db, err := MySQLAuthenticate()
	if err != nil {
		return "", err
	}
	defer db.Close()

	rows, err := db.Query("SELECT * FROM Users WHERE username = ?", username)

	if err != nil {
		return "", err
	}

	defer rows.Close()

	for rows.Next() {
		err = rows.Scan(&u.ID, &u.Username, &u.Password, &u.CanLogin, &u.CanSearch, &u.CanUpload, &u.CanManage, &u.CanViewUserLists, &u.CanEditUserLists)
	}
	err = rows.Err()

	if err != nil {
		return "", err
	}

	salt := []byte(u.Username)
	pepper := []byte(serverConfig.AuthenticationPepper)
	givenPass := fmt.Sprintf("%s%s", password, salt)
	passwordBytes := []byte(givenPass)

	// Pre-hash
	preHash := hmac.New(sha512.New, salt)
	preHash.Write(passwordBytes)
	preHashString := base64.StdEncoding.EncodeToString(preHash.Sum(nil))

	// Hash
	preHashPasswordWithPepper := append([]byte(preHashString), pepper...)
	hashedPassword := sha256.Sum256([]byte(preHashPasswordWithPepper))

	// Compare to bcrypt
	auth := VerifyPassword(hashedPassword[:], []byte(u.Password))
	if auth == false {
		return "", errors.New("Invalid Credentials")
	}

	token, err := GenerateToken(u.ID, u.CanLogin, u.CanSearch, u.CanUpload, u.CanManage, u.CanViewUserLists, u.CanEditUserLists)

	if err != nil {
		return "", err
	}

	return token, nil
}

// VerifyPassword compares the hash and password values for validation
//
// Args:
//
//	password ([]byte): The provided user password
//	hashedPassword ([]byte): The hash value to compare against
//
// Returns:
//
//	(bool): If err = nil
func VerifyPassword(password []byte, hashedPassword []byte) bool {
	err := bcrypt.CompareHashAndPassword(hashedPassword, password)
	return err == nil
}

// RegisterNewUser registers a new user account for the API
//
//	NOTE: By default new users are not allowed to manage others
//
// Args:
//
//	username (string): The username to register
//	password (string): The password to register
//
// Returns:
//
//	err (error): Error data
func RegisterNewUser(username string, password string) error {

	serverConfig := config.ServerConfig

	db, err := MySQLAuthenticate()
	if err != nil {
		return fmt.Errorf("something went wrong")
	}
	defer db.Close()

	salt := []byte(username)
	pepper := []byte(serverConfig.AuthenticationPepper)
	cost := 13
	givenPass := fmt.Sprintf("%s%s", password, salt)
	passwordBytes := []byte(givenPass)

	// Pre-hash
	preHash := hmac.New(sha512.New, salt)
	preHash.Write(passwordBytes)
	preHashString := base64.StdEncoding.EncodeToString(preHash.Sum(nil))

	// Hash
	preHashPasswordWithPepper := append([]byte(preHashString), pepper...)
	hashedPassword := sha256.Sum256([]byte(preHashPasswordWithPepper))
	bcryptHash, err := bcrypt.GenerateFromPassword(hashedPassword[:], cost)
	if err != nil {
		return fmt.Errorf("hashing password failed")
	}

	password = string(bcryptHash)

	res, err := db.Query("INSERT INTO Users (username, password, can_login, can_search, can_upload, can_manage, can_view_private, can_edit_private) VALUES (?, ?, ?, ?, ?, ?, ?, ?)", username, password, true, true, true, false, false, false)
	defer res.Close()

	if err != nil {
		re := regexp.MustCompile("Duplicate entry")
		if re.MatchString(err.Error()) {
			return fmt.Errorf("username already exists")
		}
		return fmt.Errorf("something went wrong")
	}
	return nil
}

// UpdateUserPermissions updates the permission matrix for a user
//
// Args:
//
//	userID (uint): The ID of the user
//	permissionsJSON ([]byte) Byte slice of the new JSON permissions
//
// Returns:
//
//	err (error): Error data
func UpdateUserPermissions(userID uint, permissionsJSON []byte) error {
	db, err := MySQLAuthenticate()
	if err != nil {
		return err
	}
	defer db.Close()

	var permissions map[string]interface{}
	err = json.Unmarshal(permissionsJSON, &permissions)
	if err != nil {
		return err
	}

	userIDStr := fmt.Sprintf("%v", userID)
	if models.ValidateIntInput(userIDStr) == false {
		return errors.New("Missing or invalid userID field")
	}

	canLogin, ok := permissions["canLogin"]
	if !ok || models.ValidateBoolInput(fmt.Sprintf("%v", canLogin)) == false {
		return errors.New("Missing or invalid canLogin field")
	}

	canSearch, ok := permissions["canSearch"]
	if !ok || models.ValidateBoolInput(fmt.Sprintf("%v", canSearch)) == false {
		return errors.New("Missing or invalid canSearch field")
	}

	canUpload, ok := permissions["canUpload"]
	if !ok || models.ValidateBoolInput(fmt.Sprintf("%v", canUpload)) == false {
		return errors.New("Missing or invalid canUpload field")
	}

	canManage, ok := permissions["canManage"]
	if !ok || models.ValidateBoolInput(fmt.Sprintf("%v", canManage)) == false {
		return errors.New("Missing or invalid canManage field")
	}

	canViewPrivateLists, ok := permissions["canViewUserLists"]
	if !ok || models.ValidateBoolInput(fmt.Sprintf("%v", canViewPrivateLists)) == false {
		return errors.New("Missing or invalid canViewUserLists field")
	}

	canEditPrivateLists, ok := permissions["canEditUserLists"]
	if !ok || models.ValidateBoolInput(fmt.Sprintf("%v", canEditPrivateLists)) == false {
		return errors.New("Missing or invalid canEditUserLists field")
	}

	_, err = db.Exec(`UPDATE Users SET can_login = ?, can_search = ?, can_upload = ?, can_manage = ?, can_view_private = ?, can_edit_private = ? WHERE id = ?`,
		canLogin, canSearch, canUpload, canManage, canViewPrivateLists, canEditPrivateLists, userID)
	if err != nil {
		return err
	}

	// Log the event
	config.LogError(fmt.Sprintf("UpdateUserPermissions: User %d permissions have been updated", userID), fmt.Errorf("can_login %s, can_search %s, can_upload %s, can_manage:%s, can_view_private:%s, can_edit_private:%s", canLogin, canSearch, canUpload, canManage, canViewPrivateLists, canEditPrivateLists))
	return nil
}

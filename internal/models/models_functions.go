// Package models contains object definitions and validation functions
//
// The package structure is broken into three components:
// models_structs.go which contains all the structs
// models_functions.go which contains all of the functions
// models_test.go which contains all of the unit tests
package models

import (
	"fmt"
	"reflect"
	"regexp"
)

// ValidateConfigFile validates a server configuration JSON file after loading
// it into a Configuration object
//
//	If the quality filter regex is found to be invalid a default regex is set
//	to allow all values through
//
// Args:
//
//	config (Configuration): The loaded configuration settings
//
// Return:
//
//	config (Configuration): The loaded configuration settings
//	err (error): Error data
func ValidateConfigFile(config Configuration) (Configuration, error) {
	// Validate the database user
	if !ValidateUsernameInput(config.DatabaseUser) {
		return config, fmt.Errorf("Invalid database user. Expected a string with at most 32 alphanumeric characters. Got: %s", config.DatabaseUser)
	}
	// Validate the database password
	upper := regexp.MustCompile(`[A-Z]`)
	lower := regexp.MustCompile(`[a-z]`)
	number := regexp.MustCompile(`[0-9]`)
	special := regexp.MustCompile(`[^a-zA-Z0-9\s]`)

	if len(config.DatabasePwd) < 12 || !(upper.MatchString(config.DatabasePwd) && lower.MatchString(config.DatabasePwd) && special.MatchString(config.DatabasePwd) && number.MatchString(config.DatabasePwd)) {
		return config, fmt.Errorf("Invalid password. Passwords must be at least 12 characters long and contain a mix of uppercase, lowercase letters, and at least one digit and one special character")
	}
	// Validate the authentication pepper
	if len(config.AuthenticationPepper) < 8 || !regexp.MustCompile(`^[a-zA-Z0-9!@#$%^&*()_+]{12,}$`).MatchString(config.AuthenticationPepper) {
		return config, fmt.Errorf("Invalid authentication pepper. Pepper must be at least 8 characters long and contain a mix of uppercase, lowercase letters, and at least one digit and one special character")
	}
	// Validate the number of idle database connections
	if config.DatabaseIdleConnections < 0 || config.DatabaseIdleConnections > 1000 {
		return config, fmt.Errorf("Invalid number of idle database connections. Expected a value between 0 and 1000. Got: %d", config.ServerPort)
	}
	// Validate the server port
	if config.ServerPort < 0 || config.ServerPort > 65535 {
		return config, fmt.Errorf("Invalid server port. Expected a value between 0 and 65535. Got: %d", config.ServerPort)
	}
	// Validate the JWT TTL
	if config.ServerJWTTimeToLive < 5 || config.ServerJWTTimeToLive > 90 {
		return config, fmt.Errorf("Invalid JWT TTL. Expected a value between 5 and 90. Got: %d", config.ServerJWTTimeToLive)
	}
	// Validate the server GB max upload size
	if config.ServerGBMaxUploadSize < 0 {
		return config, fmt.Errorf("Invalid server GB max upload size. Expected a positive value. Got: %d", config.ServerGBMaxUploadSize)
	}
	// Validate the rehash algorithm
	if config.RehashAlgorithm != 0 && config.RehashAlgorithm != 100 && config.RehashAlgorithm != 1000 {
		return config, fmt.Errorf("Invalid rehash algorithm. Expected a value of 0, 100, or 1000. Got: %d", config.RehashAlgorithm)
	}
	// Validate the open registration field
	if reflect.TypeOf(config.OpenRegistration).Kind() != reflect.Bool {
		return config, fmt.Errorf("Invalid open registration value. Expected a boolean value. Got: %v", config.OpenRegistration)
	}
	// Validate the rehash uploads field
	if reflect.TypeOf(config.RehashUploads).Kind() != reflect.Bool {
		return config, fmt.Errorf("Invalid rehash uploads value. Expected a boolean value. Got: %v", config.RehashUploads)
	}
	// Validate the quality filter field
	if reflect.TypeOf(config.QualityFilter).Kind() != reflect.Bool {
		return config, fmt.Errorf("Invalid quality filter value. Expected a boolean value. Got: %v", config.QualityFilter)
	}
	// Validate the quality filter regex field
	if config.QualityFilterRegex == "" {
		config.QualityFilterRegex = "^default.{1000}$"
	}

	_, err := regexp.Compile(config.QualityFilterRegex)
	if err != nil {
		config.QualityFilterRegex = "^default.{1000}$"
	}
	// Validate the self heal database field
	if reflect.TypeOf(config.SelfHealDB).Kind() != reflect.Bool {
		return config, fmt.Errorf("Invalid self heal database value. Expected a boolean value. Got: %v", config.SelfHealDB)
	}
	// Validate the number of database chunks for self heal
	if config.SelfHealDBChunks < 0 || config.SelfHealDBChunks > 100000 {
		return config, fmt.Errorf("Invalid number of self heal database chunks. Expected a value between 0 and 100000. Got: %d", config.ServerPort)
	}
	// Validate the number of database workers for self heal
	if config.SelfHealDBWorkers < 0 || config.SelfHealDBWorkers > 10000 {
		return config, fmt.Errorf("Invalid number of self heal database chunks. Expected a value between 0 and 10000. Got: %d", config.ServerPort)
	}

	// Validate the allow private lists field
	if reflect.TypeOf(config.AllowPrivateLists).Kind() != reflect.Bool {
		return config, fmt.Errorf("Invalid allow private list value. Expected a boolean value. Got: %v", config.AllowPrivateLists)
	}

	// Validate the path fields
	pathFields := []string{
		config.ServerTLSCertfilePath,
		config.ServerTLSKeyfilePath,
		config.ServerJWTPublicPEMfilePath,
		config.ServerJWTPrivatePEMfilePath,
	}
	for _, path := range pathFields {
		if !regexp.MustCompile(`^[a-zA-Z0-9\.\-_\/]+$`).MatchString(path) {
			return config, fmt.Errorf("Invalid path. Got: %s", path)
		}
	}

	return config, nil
}

// ValidateIntInput checks input for only valid numerical values
//
// Args:
//
//	s (string): string to be validated
//
// Returns:
//
//	(bool): Returns true if it matches and false if it did not
func ValidateIntInput(s string) bool {
	var validateInput = regexp.MustCompile(`^[0-9]+$`).MatchString
	if validateInput(s) == false {
		return false
	}
	return true
}

// ValidateUsernameInput checks input for only valid alphanumerical values
//
// Args:
//
//	s (string): string to be validated
//
// Returns:
//
//	(bool): Returns true if it matches and false if it did not
func ValidateUsernameInput(s string) bool {
	var validateInput = regexp.MustCompile(`^[a-zA-Z0-9]+$`).MatchString
	if len(s) > 32 {
		return false
	}
	if validateInput(s) == false {
		return false
	}
	return true
}

// ValidateJWTCharacters checks the JWT token for valid characters.
//
// Args:
//
//	jwtToken (string): The JWT token to validate.
//
// Returns:
//
//	bool: True if the token is valid, False otherwise.
func ValidateJWTCharacters(jwtToken string) bool {
	return bool(regexp.MustCompile(`^[a-zA-Z0-9-_]+={0,2}\.[a-zA-Z0-9-_]+={0,2}\.[a-zA-Z0-9-_]+={0,2}$`).MatchString(jwtToken))
}

// ValidateBoolInput checks input for only valid boolean values
//
// Args:
// s (string): string to be validated
//
// Returns:
// (bool): Returns true if it matches and false if it did not
func ValidateBoolInput(s string) bool {
	if s == "true" {
		return true
	}
	return false
}

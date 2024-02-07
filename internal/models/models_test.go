// Package models contains object definitions and validation functions
//
// The package structure is broken into three components:
// models_structs.go which contains all the structs
// models_functions.go which contains all of the functions
// models_test.go which contains all of the unit tests
package models

import (
	"regexp"
	"testing"
)

func TestValidateConfigFile(t *testing.T) {
	config := Configuration{
		DatabaseUser:                "testUser",
		DatabasePwd:                 "testPassword",
		AuthenticationPepper:        "0H4St4ticP3pp3r",
		DatabaseIdleConnections:     100,
		ServerPort:                  8080,
		ServerTLSCertfilePath:       "server.crt",
		ServerTLSKeyfilePath:        "server.key",
		ServerJWTPublicPEMfilePath:  "jwt.pub",
		ServerJWTPrivatePEMfilePath: "jwt.priv",
		ServerJWTTimeToLive:         30,
		ServerGBMaxUploadSize:       10,
		OpenRegistration:            true,
		RehashUploads:               true,
		RehashAlgorithm:             0,
		QualityFilter:               true,
		QualityFilterRegex:          "default.{1000}$",
		SelfHealDB:                  true,
		SelfHealDBChunks:            100,
		SelfHealDBWorkers:           10,
	}

	_, err := ValidateConfigFile(config)
	if err != nil {
		t.Errorf("error validating config file: %v", err)
	}

	config.DatabaseUser = "invalid_user"
	_, err = ValidateConfigFile(config)
	if err == nil {
		t.Errorf("expected error validating invalid database user, got nil")
	}

	config.DatabasePwd = "invalid_password"
	_, err = ValidateConfigFile(config)
	if err == nil {
		t.Errorf("expected error validating invalid database password, got nil")
	}

	config.DatabaseIdleConnections = -1
	_, err = ValidateConfigFile(config)
	if err == nil {
		t.Errorf("expected error validating invalid database idle connections, got nil")
	}

	config.ServerPort = -1
	_, err = ValidateConfigFile(config)
	if err == nil {
		t.Errorf("expected error validating invalid server port, got nil")
	}

	config.ServerJWTTimeToLive = -1
	_, err = ValidateConfigFile(config)
	if err == nil {
		t.Errorf("expected error validating invalid JWT TTL, got nil")
	}

	config.ServerGBMaxUploadSize = -1
	_, err = ValidateConfigFile(config)
	if err == nil {
		t.Errorf("expected error validating invalid server GB max upload size, got nil")
	}

	config.RehashAlgorithm = 1001
	_, err = ValidateConfigFile(config)
	if err == nil {
		t.Errorf("expected error validating invalid rehash algorithm, got nil")
	}

	config.OpenRegistration = false
	_, err = ValidateConfigFile(config)
	if err == nil {
		t.Errorf("expected error validating invalid open registration, got nil")
	}

	config.RehashUploads = false
	_, err = ValidateConfigFile(config)
	if err == nil {
		t.Errorf("expected error validating invalid rehash uploads, got nil")
	}

	config.QualityFilter = false
	_, err = ValidateConfigFile(config)
	if err == nil {
		t.Errorf("expected error validating invalid quality filter, got nil")
	}

	config.QualityFilterRegex = ""
	_, err = ValidateConfigFile(config)
	if err == nil {
		t.Errorf("expected error validating empty quality filter regex, got nil")
	}

	config.QualityFilterRegex = "^default.{1000}$"
	_, err = regexp.Compile(config.QualityFilterRegex)
	if err != nil {
		t.Errorf("expected error validating invalid quality filter regex, got nil")
	}

	config.SelfHealDB = false
	_, err = ValidateConfigFile(config)
	if err == nil {
		t.Errorf("expected error validating invalid self heal database, got nil")
	}

	config.SelfHealDBChunks = -1
	_, err = ValidateConfigFile(config)
	if err == nil {
		t.Errorf("expected error validating invalid number of self heal database chunks, got nil")
	}

	config.SelfHealDBWorkers = -1
	_, err = ValidateConfigFile(config)
	if err == nil {
		t.Errorf("expected error validating invalid number of self heal database workers, got nil")
	}

	pathFields := []string{
		config.ServerTLSCertfilePath,
		config.ServerTLSKeyfilePath,
		config.ServerJWTPublicPEMfilePath,
		config.ServerJWTPrivatePEMfilePath,
	}
	for _, path := range pathFields {
		if !regexp.MustCompile(`^[a-zA-Z0-9\.\-_\/]+$`).MatchString(path) {
			t.Errorf("Invalid path. Got: %s", path)
		}
	}
}

func TestValidateIntInput(t *testing.T) {
	validInputs := []string{"123", "0", "1", "999999999"}
	for _, input := range validInputs {
		if !ValidateIntInput(input) {
			t.Errorf("Expected input '%s' to be valid", input)
		}
	}

	invalidInputs := []string{"test", "123a", "1.23", "-1", "+1"}
	for _, input := range invalidInputs {
		if ValidateIntInput(input) {
			t.Errorf("Expected input '%s' to be invalid", input)
		}
	}
}

func TestValidateUsernameInput(t *testing.T) {
	validInputs := []string{"testuser", "TestUser123", "TESTUSER"}
	for _, input := range validInputs {
		if !ValidateUsernameInput(input) {
			t.Errorf("Expected input '%s' to be valid", input)
		}
	}

	invalidInputs := []string{"test user", "Test@User", "Test.User", "Test-User", "Test_User", "TestUser123456789012345678901234567890123"}
	for _, input := range invalidInputs {
		if ValidateUsernameInput(input) {
			t.Errorf("Expected input '%s' to be invalid", input)
		}
	}
}

// Package models contains object definitions and validation functions
//
// The package structure is broken into three components:
// models_structs.go which contains all the structs
// models_functions.go which contains all of the functions
// models_test.go which contains all of the unit tests
package models

//
// Structs
//

// Configuration is a struct used to load JSON config files
//
// The struct contains the following fields:
//
//	DatabaseUser: The username of the database user
//	DatabasePwd: The password of the database user
//	AuthenticationPepper: The pepper value used in authentication
//	DatabaseIdleConnections: The number of idle database connections allowed
//	ServerPort: The port the server will host on
//	ServerTLSCertfilePath: Local path to the cert file for TLS
//	ServerTLSKeyfilePath: Local path to the key file for TLS
//	ServerJWTPublicPEMfilePath: Local path to the public PEM file for auth
//	ServerJWTPrivatePEMfilePath: Local path to the private PEM file for auth
//	ServerJWTTimeToLive: The JWT auth token TTL value
//	ServerGBMaxUploadSize: Max POST request size in GB
//	OpenRegistration: If users are allowed to self register accounts
//	RehashUploads: If uploads should be rehashed into another algorithm
//	RehashAlgorithm: Algorithm to use are 0, 100, 1000
//	QualityFilter: If uploads should be filtered before adding to database
//	QualityFilterRegex: Regex to match bad items to
//	SelfHealDB: If the database should validate hashes in the background
//	SelfHealDBChunks: Number of chunks the database is broken into for the
//	worker pool
//	SelfHealDBWorkers: Number of workers to spawn for the validation process
//	GenerateWordlist: If the server should start a process to make a wordlist
//	GenerateRules: If the server should start a process to make a rule list
//	GenerateMasks: If the server should start a process to make a mask list
//	AllowPrivateLists: If the server should allow private lists
type Configuration struct {
	DatabaseUser                string `json:"database-user"`
	DatabasePwd                 string `json:"database-pwd"`
	AuthenticationPepper        string `json:"auth-pepper"`
	DatabaseIdleConnections     int    `json:"database-idle-connections"`
	ServerPort                  int    `json:"server-port"`
	ServerTLSCertfilePath       string `json:"server-tls-certfile-path"`
	ServerTLSKeyfilePath        string `json:"server-tls-keyfile-path"`
	ServerJWTPublicPEMfilePath  string `json:"server-jwt-public-pemfile-path"`
	ServerJWTPrivatePEMfilePath string `json:"server-jwt-private-pemfile-path"`
	ServerJWTTimeToLive         int    `json:"server-jwt-ttl"`
	ServerGBMaxUploadSize       int    `json:"server-gb-max-upload-size"`
	OpenRegistration            bool   `json:"open-registration"`
	RehashUploads               bool   `json:"rehash-uploads"`
	RehashAlgorithm             int    `json:"rehash-algorithm"`
	QualityFilter               bool   `json:"quality-filter"`
	QualityFilterRegex          string `json:"quality-filter-regex"`
	SelfHealDB                  bool   `json:"self-heal-database"`
	SelfHealDBChunks            int    `json:"self-heal-database-chunks"`
	SelfHealDBWorkers           int    `json:"self-heal-database-workers"`
	GenerateWordlist            bool   `json:"generate-wordlist"`
	GenerateRules               bool   `json:"generate-rules"`
	GenerateMasks               bool   `json:"generate-masks"`
	AllowPrivateLists           bool   `json:"allow-private-lists"`
}

// HashSearchStruct is a struct used for searching the database
//
// The struct has one field, data:
//
//	Data: Array of either HASH and/or PLAIN to search the database for
type HashSearchStruct struct {
	Data []string `json:"data"`
}

// HashUploadStruct is a struct used to upload data to the database
//
// The struct has two fields, Algorithm and HashPlain:
//
//	Algorithm: The algorithm of the HASH value
//	HashPlain: Array in HASH:PLAIN or HASH:SALT:PLAIN format
type HashUploadStruct struct {
	Algorithm string   `json:"algorithm"`
	HashPlain []string `json:"hash-plain"`
}

// HashStruct is a struct used to hold individual hash data
//
// The struct has the following fields:
//
//	Algorithm: The algorithm of the HASH value
//	Hash: The HASH value
//	Plaintext: The PLAINTEXT value
//	Validated: If the HASH has been validated
type HashStruct struct {
	Algorithm string `json:"algorithm"`
	Hash      string `json:"hash"`
	Plaintext string `json:"plaintext"`
	Validated string `json:"validated"`
}

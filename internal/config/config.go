// Package config controls server-side configuration
//
// The validation and definition of the configuration file is done within
// models and config is used to store logic related to server-side components
//
// The package structure is broken into two components:
// config.go which contains the functions
// config_test.go which contains the unit tests
package config

import (
	"bytes"
	"crypto/md5"
	"crypto/sha1"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	mathrand "math/rand"
	"ohaserver/internal/models"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
	stdunicode "unicode"
	"unicode/utf8"

	"golang.org/x/crypto/md4"
	"golang.org/x/text/encoding/unicode"
	"golang.org/x/text/transform"
)

// ServerConfig is the global variable that holds the loaded config
var ServerConfig models.Configuration

// SelfValidationResult is a struct used to hold output from the self
// validation feature to print to console
//
// The struct contains the following fields:
//
//	Hash: The hash value
//	Plaintext: The plaintext value
//	Err: Error found in validation
type SelfValidationResult struct {
	Hash      string
	Plaintext string
	Err       error
}

// LoadConfig loads the JSON configuration from a file path
//
// Args:
//
//	directory (string): The directory of the configuration file
//
// Returns:
//
//	conf (models.Configuration): Configuration struct containing loaded data
func LoadConfig(directory string) models.Configuration {

	_, err := os.Stat(directory)
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}

	fileContent, err := os.Open(directory)
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}

	defer fileContent.Close()
	byteResult, err := io.ReadAll(fileContent)
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}

	var conf models.Configuration
	err = json.Unmarshal([]byte(byteResult), &conf)
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}

	conf, err = models.ValidateConfigFile(conf)
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}

	return conf
}

// DehexPlaintext decodes plaintext from $HEX[...] format
//
// Args:
//
//	s (string): The string to be dehexed
//
// Returns:
//
//	decoded (string): The decoded hex string
//	err (error): Error data
func DehexPlaintext(s string) (string, error) {
	s = strings.TrimPrefix(s, "$HEX[")
	s = strings.TrimSuffix(s, "]")
	decoded, err := hex.DecodeString(s)
	if err != nil {
		fullErr := fmt.Errorf("error decoding hex string: %s", s)
		return string(decoded), fullErr
	}

	if bytes.HasPrefix([]byte(s), []byte("$HEX")) || bytes.HasPrefix([]byte(s), []byte("HEX")) {
		return string(decoded), fmt.Errorf("error hex string is not valid: %s", s)
	}

	return string(decoded), err
}

// RehashMD5 rehashes a string into a MD5 hash
//
// Args:
//
//	s (string): The string to be hashed
//
// Returns:
//
//	md5sum (string): The MD5 hash
func RehashMD5(s string) string {
	hash := md5.New()
	hash.Write([]byte(s))
	md5sum := hex.EncodeToString(hash.Sum(nil))
	return md5sum
}

// RehashSHA1 rehashes a string into a SHA1 hash
//
// Args:
//
//	s (string): The string to be hashed
//
// Returns:
//
//	sha1sum (string): The SHA1 hash
func RehashSHA1(s string) string {
	hash := sha1.New()
	hash.Write([]byte(s))
	sha1sum := hex.EncodeToString(hash.Sum(nil))
	return sha1sum
}

// RehashNTLM rehashes a string into a NTLM hash
//
// Args:
//
//	s (string): The string to be hashed
//
// Returns:
//
//	ntlmsum (string): The NTLM hash
func RehashNTLM(s string) string {
	hash := md4.New()
	encoder := unicode.UTF16(unicode.LittleEndian, unicode.IgnoreBOM).NewEncoder()
	reader := transform.NewReader(bytes.NewReader([]byte(s)), encoder)
	transformedInput, _ := io.ReadAll(reader)
	hash.Write(transformedInput)
	ntlmsum := hex.EncodeToString(hash.Sum(nil))
	return ntlmsum
}

// TestPlainQuality is used by the quality filter to remove items based on
// regex
//
// Args:
//
//	s (str): The string to be evaluated
//
// Return
//
//	(bool): Returns true if it did not match and false if it did
func TestPlainQuality(s string) bool {
	var validateInput = regexp.MustCompile(ServerConfig.QualityFilterRegex).MatchString
	if validateInput(s) == false {
		return true
	}
	return false
}

// TestHexInput is used by the rehashing feature to identify plaintext in the
// $HEX[...] format
//
// Args:
//
//	s (str): The string to be evaluated
//
// Returns:
//
//	(bool): Returns true if it matches and false if it did not
func TestHexInput(s string) bool {
	var validateInput = regexp.MustCompile(`^\$HEX\[[a-zA-Z0-9]*\]$`).MatchString
	if validateInput(s) == false {
		return false
	}
	return true
}

// ParseHashAndPlaintext separates HASH:PLAIN and HASH:SALT:PLAIN
//
// Args:
//
//	s (interface{}): HASH:PLAIN or HASH:SALT:PLAIN data
//
// Returns:
//
//	cipher (string): HASH or HASH:SALT value result
//	plain (string): PLAIN value result
//	err (error): Error data
func ParseHashAndPlaintext(s interface{}) (string, string, error) {
	var splitPlain = regexp.MustCompile("([^:]*):(.*):(.*)")
	var cipher string
	var plain string

	sp := fmt.Sprintf("%v", s)
	foundItem := splitPlain.FindAllStringSubmatch(sp, 2)

	if len(foundItem) != 0 {
		if len(foundItem[0]) == 4 {
			cipher = foundItem[0][1] + ":" + foundItem[0][2]
			plain = foundItem[0][3]
		}
	} else {
		splitPlain = regexp.MustCompile("([^:]*):(.*)")
		foundItem = splitPlain.FindAllStringSubmatch(sp, -1)
		if len(foundItem) == 0 {
			return "", "", fmt.Errorf("error parsing hash from plaintext: %s", sp)
		}
		cipher = foundItem[0][1]
		plain = foundItem[0][2]
	}

	return cipher, plain, nil
}

// RehashUpload rehashes an upload into one of three algorithms:
//   - 0 (MD5)
//   - 100 (SHA1)
//   - 1000 (NTLM)
//
// Args:
//
//	hashes ([]string): Slice of HASH:PLAIN strings to be rehashed
//	algo (string): The new algorithm to use based on numerical value
//
// Returns:
//
//	uploadStruct ([]interface{}): Slice of HASH:PLAIN strings in the new
//	algorithm
//	err (err): Error data
func RehashUpload(hashes []string, algo string) ([]interface{}, error) {
	uploadStruct := make([]interface{}, len(hashes))
	err := error(nil)
	for i, h := range hashes {
		ciphertext, plaintext, err := ParseHashAndPlaintext(h)
		if err != nil {
			return nil, err
		}
		// dehex when needed
		if TestHexInput(plaintext) == true {
			dehexPlaintext, err := DehexPlaintext(plaintext)
			if err != nil {
				continue
			}
			switch algo {
			case "0":
				ciphertext = RehashMD5(dehexPlaintext)
			case "100":
				ciphertext = RehashSHA1(dehexPlaintext)
			case "1000":
				ciphertext = RehashNTLM(dehexPlaintext)
			}
		} else {
			switch algo {
			case "0":
				ciphertext = RehashMD5(plaintext)
			case "100":
				ciphertext = RehashSHA1(plaintext)
			case "1000":
				ciphertext = RehashNTLM(plaintext)
			}
		}
		cp := fmt.Sprintf("%s:%s", ciphertext, plaintext)
		uploadStruct[i] = cp
	}
	return uploadStruct, err
}

// ValidateDatabaseHashes is used to self heal the database entries async while
// the API is operational
//
// The self heal feature will split the database into chunks then assign
// a worker pool to go through and validate hash entries for quality and
// accuracy
//
// Removed items are printed to the console and the Rehash algorithm is used
// for verification
//
// Args:
//
//	db (*sql.DB): The database connection
//	chunkSize (int): Number of chunks to split the database into
//	numWorkers (int): Number of workers to go through the chunks
//	algo (int): Algorithm used to verify
//
// Returns:
//
//	None
func ValidateDatabaseHashes(db *sql.DB, chunkSize int, numWorkers int, algo int) {
	message := fmt.Sprintf("Background validation | Algorithm %d | Number of Chunks: %d | Number of Workers: %d", algo, chunkSize, numWorkers)
	ConsoleLogger(message)

	// Get the total number of database items
	var totalRows int64
	err := db.QueryRow("SELECT COUNT(*) FROM Hashes").Scan(&totalRows)
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
	var totalValidatedRows int64
	err = db.QueryRow("SELECT COUNT(*) FROM Hashes WHERE validated = 1").Scan(&totalValidatedRows)
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
	percentageDone := float64(totalValidatedRows) / float64(totalRows) * 100
	ConsoleLogger(fmt.Sprintf("Current validation status: %d/%d results validated (%.1f%%)", totalValidatedRows, totalRows, percentageDone))

	// Split the database into chunks
	numChunks := (totalRows + int64(chunkSize) - 1) / int64(chunkSize)
	chunks := make(chan int, numChunks)
	for i := 0; i < int(totalRows); i += chunkSize {
		chunks <- i
	}
	close(chunks)

	var hash models.HashStruct
	var wg sync.WaitGroup
	wg.Add(numWorkers)
	results := make(chan SelfValidationResult)

	// Create a mutex to synchronize access to shared data
	var mu sync.Mutex

	for i := 0; i < numWorkers; i++ {
		go func() {
			defer wg.Done()

			for range chunks {

				mu.Lock()

				rows, err := db.Query("SELECT * FROM Hashes WHERE validated = false LIMIT ?", chunkSize)
				if err != nil {
					fmt.Println(err)
					os.Exit(1)
				}
				defer rows.Close()

				// Process the chunk
				for rows.Next() {
					err := rows.Scan(&hash.Algorithm, &hash.Hash, &hash.Plaintext, &hash.Validated)
					if err != nil {
						fmt.Println(err)
						os.Exit(1)
					}

					errInvalid := ValidateHashItem(hash, strconv.Itoa(algo))
					if errInvalid != nil {
						// Attempt to delete items
						maxRetries := 18
						for j := 0; j < maxRetries; j++ {
							err = deleteItem(db, hash)
							if err != nil {
								if strings.Contains(err.Error(), "try restarting transaction") {
									// wait for a short time before retrying
									time.Sleep(time.Duration(3) * time.Second)
									continue
								}
								// wait for a long time before retrying
								time.Sleep(time.Duration(300) * time.Second)
								continue
							}
							break
						}
						if err != nil {
							fmt.Println("Failed to delete database item:", err)
							os.Exit(1)
						}
					}

					_, err = db.Exec("UPDATE Hashes SET validated = true WHERE algorithm = ? AND hash = ? AND plaintext = ?", hash.Algorithm, hash.Hash, hash.Plaintext)
					if err != nil {
						fmt.Println(err)
						os.Exit(1)
					}

					results <- SelfValidationResult{Hash: hash.Hash, Plaintext: hash.Plaintext, Err: errInvalid}
				}
				mu.Unlock()
			}
		}()
	}

	// Process the validation results
	go func() {
		count := int64(0)
		threshold := totalRows / 100
		if threshold < 1 {
			threshold = 1
		}
		for result := range results {
			if result.Err != nil {
				message := fmt.Sprintf("Deleted %s:%s | %v", result.Hash, result.Plaintext, result.Err)
				ConsoleLogger(message)
			} else {
				count++
				if (count+totalValidatedRows)%threshold == 0 {
					percentageDone := float64(count+totalValidatedRows) / float64(totalRows) * 100
					statusDone := count + totalValidatedRows
					ConsoleLogger(fmt.Sprintf("Validation status: %d/%d results validated (%.1f%%) | Validated this session: %d", statusDone, totalRows, percentageDone, count))
				}
			}
		}
	}()

	wg.Wait()
	close(results)

	// Check if the database is validated
	err = db.QueryRow("SELECT COUNT(*) FROM Hashes WHERE validated = 1").Scan(&totalValidatedRows)
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}

	if totalValidatedRows != totalRows {
		ValidateDatabaseHashes(db, chunkSize, numWorkers, algo)
	}
}

// ValidateHashItem is used to verify a HASH:PLAIN is correct and does not
// match the quality filter
//
// Args:
//
//	hash (HashStruct): The HASH:PLAIN object struct
//	algo (string): The hashing algorithm to check
//
// Returns:
//
//	(error): Error on why it failed validation
func ValidateHashItem(hash models.HashStruct, algo string) error {
	var ciphertext string

	// dehex when needed
	if TestHexInput(hash.Plaintext) == true {
		dehexPlaintext, err := DehexPlaintext(hash.Plaintext)
		if err != nil {
			return fmt.Errorf("dehex error: %s", hash)
		}
		if ServerConfig.QualityFilter {
			if !TestPlainQuality(dehexPlaintext) {
				return fmt.Errorf("dehexed plaintext caught by filter")
			}
		}
		switch algo {
		case "0":
			ciphertext = RehashMD5(dehexPlaintext)
		case "100":
			ciphertext = RehashSHA1(dehexPlaintext)
		case "1000":
			ciphertext = RehashNTLM(dehexPlaintext)
		}
	} else {
		if ServerConfig.QualityFilter {
			if !TestPlainQuality(hash.Plaintext) {
				return fmt.Errorf("plaintext caught by filter")
			}
		}
		switch algo {
		case "0":
			ciphertext = RehashMD5(hash.Plaintext)
		case "100":
			ciphertext = RehashSHA1(hash.Plaintext)
		case "1000":
			ciphertext = RehashNTLM(hash.Plaintext)
		}
	}

	if ciphertext != hash.Hash {
		return fmt.Errorf("hashes do not match: %s (rehashed) != %s (provided)", ciphertext, hash.Hash)
	}
	return nil
}

// deleteItem is used to delete a HASH object from the database
//
// Args:
//
//	db (*sql.DB): The database connection
//	hash (HashStruct): The HASH:PLAIN object struct
//
// Returns:
//
//	(error): Error data
func deleteItem(db *sql.DB, hash models.HashStruct) error {
	_, err := db.Exec("DELETE FROM Hashes WHERE algorithm = ? AND hash = ? AND plaintext = ?", hash.Algorithm, hash.Hash, hash.Plaintext)
	if err != nil {
		return fmt.Errorf("failed to delete item: %v", err)
	}

	return nil
}

// ConsoleLogger is used to log server-side messages to the console these
// items are also logged to a file
//
// Args:
//
//	s (string): string to be logged
//
// Returns:
//
//	None
func ConsoleLogger(s string) {
	// Get the request information
	timestamp := time.Now()

	// Print the request information
	LogEvent("ConsoleLogger", s)
	fmt.Printf("[OHA] %s | %s\n",
		timestamp.Format("2006/01/02 - 15:04:05"),
		s)
}

// GenerateWordlistFile is used to generate a wordlist file to the local
// file system for download by the API
//
// items less than 4 length are removed
// items with less than 3 unique characters are removed
// all items are saved in lowercase
// all non-alpha characters are removed
//
// Args:
//
//	db (*sql.DB): The database connection
//
// Returns:
//
//	None
func GenerateWordlistFile(db *sql.DB) {
	message := fmt.Sprintf("Starting background wordlist generation...")
	ConsoleLogger(message)
	start := time.Now()

	rows, err := db.Query("SELECT plaintext FROM Hashes")
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
	defer rows.Close()

	entries := make(map[string]int)
	re := regexp.MustCompile("[^a-zA-Z]+")
	keepRe := regexp.MustCompile("[aeiouxyzAEIOUXYZ]")
	for rows.Next() {
		var entry string
		if err := rows.Scan(&entry); err != nil {
			fmt.Println(err)
			os.Exit(1)
		}

		// dehex when needed
		if TestHexInput(entry) == true {
			entry, err = DehexPlaintext(entry)
			if err != nil {
				continue
			}
		}

		entry = re.ReplaceAllString(entry, "")
		if len(entry) >= 4 && len(keepRe.FindAllString(entry, 1)) >= 1 {
			if hasUniqueChars(entry) {
				lowerEntry := strings.ToLower(entry)
				entries[lowerEntry]++
			}
		}
	}
	if err := rows.Err(); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}

	type kv struct {
		Key   string
		Value int
	}

	var sortedEntries []kv
	for k, v := range entries {
		if v >= 1 {
			sortedEntries = append(sortedEntries, kv{k, v})
		}
	}

	sort.Slice(sortedEntries, func(i, j int) bool {
		return sortedEntries[i].Value > sortedEntries[j].Value
	})

	var result []string
	for _, kv := range sortedEntries {
		result = append(result, kv.Key)
	}

	if err := os.WriteFile("/var/www/OpenHashAPI/wordlist.txt", []byte(strings.Join(result, "\n")), 0644); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
	elapsed := time.Since(start)
	message = fmt.Sprintf("Completed background wordlist generation in %s", elapsed)
	ConsoleLogger(message)
}

// GenerateRulesFile is used to generate a rule file to the local
// file system for download by the API
//
// Args:
//
//	db (*sql.DB): The database connection
//
// Returns:
//
//	None
func GenerateRulesFile(db *sql.DB) {
	message := fmt.Sprintf("Starting background rules generation...")
	ConsoleLogger(message)
	start := time.Now()

	// Create rules
	var prefixEntry string
	var appendEntry string
	var comboAppendEntry string
	var comboPrefixEntry string
	var comboAppendPrefixEntry string
	var comboAppendTogglePrefixEntry string
	var insertEntry string

	rows, err := db.Query("SELECT plaintext FROM Hashes")
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
	defer rows.Close()

	outputRules := make(map[string]int)

	for rows.Next() {
		var entry string
		if err := rows.Scan(&entry); err != nil {
			fmt.Println(err)
			os.Exit(1)
		}

		// dehex when needed
		if TestHexInput(entry) == true {
			entry, err = DehexPlaintext(entry)
			if err != nil {
				fmt.Println(err)
				os.Exit(1)
			}
		}

		// get only alpha chars to test len
		re := regexp.MustCompile(`[^a-zA-Z]`)
		alphaEntry := re.ReplaceAllString(entry, "")

		if len(alphaEntry) >= 4 {
			// get remaining chars
			re = regexp.MustCompile(`[a-zA-Z]`)
			nonAlphaEntry := re.ReplaceAllString(entry, "")

			// get prefix rules

			// Get upper to upper case word transitions
			prefixRegexCase1 := regexp.MustCompile(`[A-Z].*[A-Z]`)
			prefixRegexFetch1 := regexp.MustCompile(`^([A-Z][a-z]+)`)

			// Get word to divider transitions
			prefixRegexCase2 := regexp.MustCompile(`^[a-zA-Z]+[@.\-_!+&][a-zA-Z]+$`)
			prefixRegexFetch2 := regexp.MustCompile(`[a-zA-Z]+[@.\-_!+&]`)

			if prefixRegexCase1.MatchString(entry) {
				prefixEntry = prefixRegexFetch1.FindString(entry)
			} else if prefixRegexCase2.MatchString(entry) {
				prefixEntry = prefixRegexFetch2.FindString(entry)
			} else {
				prefixEntry = ""
			}

			// get toggle rules
			toggledEntry := StringToToggle(alphaEntry, 0)

			if len(prefixEntry) >= 3 {
				prefixEntry = strings.ToLower(prefixEntry)
				prefixEntry = CharToRule(ReverseString(prefixEntry), "^")
			} else {
				prefixEntry = ""
			}

			appendEntry = CharToRule(nonAlphaEntry, "$")

			if len(appendEntry) > 1 && len(toggledEntry) > 1 {
				comboAppendEntry = fmt.Sprintf("%s %s", toggledEntry, appendEntry)
			}
			if len(prefixEntry) > 1 && len(toggledEntry) > 1 {
				comboPrefixEntry = fmt.Sprintf("%s %s", prefixEntry, toggledEntry)
			}
			if len(prefixEntry) > 1 && len(appendEntry) > 1 {
				// here we are trying to fix parsing where an append and prefix
				// rule might have the same special character and gets added
				// twice.
				if len(toggledEntry) > 1 && appendEntry[1] != prefixEntry[1] {
					comboAppendTogglePrefixEntry = fmt.Sprintf("%s %s %s", prefixEntry, toggledEntry, appendEntry)
				} else if len(appendEntry) > 1 && appendEntry[1] != prefixEntry[1] {
					comboAppendPrefixEntry = fmt.Sprintf("%s %s", prefixEntry, appendEntry)
				}
			}

		} else {
			continue
		}

		// ensure formatting
		values := []string{prefixEntry, appendEntry, comboAppendEntry, comboPrefixEntry, comboAppendPrefixEntry, comboAppendTogglePrefixEntry, insertEntry}

		for _, rule := range values {
			rule = strings.TrimSpace(rule)

			if !CheckASCIIString(rule) {
				rule = ConvertCharacterMultiByteString(rule)
			}

			if strings.HasSuffix(rule, " $") {
				rule += " :"
			}

			if strings.HasSuffix(rule, " ^") {
				rule += " :"
			}
			if rule != "" && len(rule) <= 93 && len(rule) >= 2 {
				doubleSpacesRegex := regexp.MustCompile(`\s+`)
				rule = doubleSpacesRegex.ReplaceAllString(rule, " ")
				outputRules[rule]++
			}
		}

	}

	type kv struct {
		Key   string
		Value int
	}

	var sortedEntries []kv
	for k, v := range outputRules {
		sortedEntries = append(sortedEntries, kv{k, v})
	}

	sort.Slice(sortedEntries, func(i, j int) bool {
		return sortedEntries[i].Value > sortedEntries[j].Value
	})

	var result []string
	for _, kv := range sortedEntries {
		result = append(result, kv.Key)
	}

	if err := os.WriteFile("/var/www/OpenHashAPI/rules.txt", []byte(strings.Join(result, "\n")), 0644); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}

	elapsed := time.Since(start)
	message = fmt.Sprintf("Completed background rules generation in %s", elapsed)
	ConsoleLogger(message)
}

// StringToToggle converts a string to a toggle rule by looking for upper case
// characters
//
// Args:
//
//	str (string): String to read for toggle creation
//	index (int): Index to start the new rule at
//
// Returns:
//
//	result (string): Output rule
func StringToToggle(str string, index int) string {
	var result strings.Builder
	for i, r := range str {
		if stdunicode.IsUpper(r) {
			if i+index < 10 {
				result.WriteString(fmt.Sprintf("%s%d ", "T", i+index))
			} else if i+index-10 < 26 {
				result.WriteString(fmt.Sprintf("%s%c ", "T", 'A'+i+index-10))
			}
		}
	}
	return strings.TrimSpace(result.String())
}

// CharToRule converts a string into a rule by appending a rule character in
// front of each character in a string
//
// Args:
//
//	str (string): String to convert
//	rule (string): Rule character to append in front of each character
//
// Returns:
//
//	(string): Valid rule
func CharToRule(str string, rule string) string {
	return rule + strings.Join(strings.Split(str, ""), " "+rule)
}

// CheckASCIIString is used to identify multibyte characters within strings
//
// Args:
//
//	str (string): String to check
//
// Returns:
//
//	(bool): Returns true if only contains ascii and false if it does not
func CheckASCIIString(str string) bool {
	if utf8.RuneCountInString(str) != len(str) {
		return false
	}
	return true
}

// ConvertCharacterMultiByteString converts non-ascii characters to a valid
// format used by the CharToRule function to convert rules that included
// multibyte characters
//
// Args:
//
//	str (string): Rule string to convert
//
// Return:
//
//	returnStr (string): Converted rule
func ConvertCharacterMultiByteString(str string) string {
	returnStr := ""
	deletedChar := ``
	for i, r := range str {
		if r > 127 {
			if i > 0 {
				deletedChar = string(returnStr[len(returnStr)-1])
				returnStr = returnStr[:len(returnStr)-1]
			}
			byteArr := []byte(string(r))
			if deletedChar == "^" {
				for j := len(byteArr) - 1; j >= 0; j-- {
					b := byteArr[j]
					if j == 0 {
						returnStr += fmt.Sprintf("%s\\x%X", deletedChar, b)
					} else {
						returnStr += fmt.Sprintf("%s\\x%X ", deletedChar, b)
					}
				}
			} else {
				for j, b := range byteArr {
					if j == len(byteArr)-1 {
						returnStr += fmt.Sprintf("%s\\x%X", deletedChar, b)
					} else {
						returnStr += fmt.Sprintf("%s\\x%X ", deletedChar, b)
					}
				}
			}
		} else {
			returnStr += fmt.Sprintf("%c", r)
		}
	}
	return returnStr
}

// GenerateMasksFile is used to generate a mask file to the local
// file system for download by the API
//
//	The process is:
//	 - Get plains that contain three or greater complexity
//	 - Convert to a mask
//	 - Convert multibyte characters in masks
//
// Args:
//
//	db (*sql.DB): The database connection
//
// Returns:
//
//	None
func GenerateMasksFile(db *sql.DB) {
	message := fmt.Sprintf("Starting background masks generation...")
	ConsoleLogger(message)
	start := time.Now()

	rows, err := db.Query("SELECT plaintext FROM Hashes")
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
	defer rows.Close()

	masks := make(map[string]int)
	replacements := ConstructReplacements("ulds")
	letterCheck := regexp.MustCompile(`[a-zA-Z]`)
	numberCheck := regexp.MustCompile(`[0-9]`)
	specialCheck := regexp.MustCompile(`[^a-zA-Z0-9\s]`)

	for rows.Next() {
		var entry string
		if err := rows.Scan(&entry); err != nil {
			fmt.Println(err)
			os.Exit(1)
		}

		// dehex when needed
		if TestHexInput(entry) == true {
			entry, err = DehexPlaintext(entry)
			if err != nil {
				fmt.Println(err)
				os.Exit(1)
			}
		}
		if letterCheck.MatchString(entry) && specialCheck.MatchString(entry) && numberCheck.MatchString(entry) {
			mask := MakeMask(entry, replacements)

			var IsMask = regexp.MustCompile(`^[uldsb?]+$`).MatchString
			if IsMask(mask) == false {
				if CheckASCIIString(mask) == false {
					mask = ConvertMaskMultiByteString(mask)
				} else {
					continue
				}
			}

			masks[mask]++
		}
	}
	if err := rows.Err(); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}

	type kv struct {
		Key   string
		Value int
	}

	var sortedEntries []kv
	for k, v := range masks {
		sortedEntries = append(sortedEntries, kv{k, v})
	}

	sort.Slice(sortedEntries, func(i, j int) bool {
		return sortedEntries[i].Value > sortedEntries[j].Value
	})

	var result []string
	for _, kv := range sortedEntries {
		result = append(result, kv.Key)
	}

	if err := os.WriteFile("/var/www/OpenHashAPI/masks.txt", []byte(strings.Join(result, "\n")), 0644); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}

	elapsed := time.Since(start)
	message = fmt.Sprintf("Completed background masks generation in %s", elapsed)
	ConsoleLogger(message)
}

// MakeMask is used to create masks of plaintext
//
// Args:
//
//	str (string): The string to convert
//	replacements ([]string): Array of character replacements
//
// Returns:
//
//	(string): Mask string
func MakeMask(str string, replacements []string) string {
	return strings.NewReplacer(replacements...).Replace(str)
}

// ConvertMaskMultiByteString converts non-ascii characters to a valid format
// by replacing multibyte characters with a placeholder
//
// Args:
//
//	str (string): The string to convert
//
// Returns:
//
//	returnStr (string): The converted string
func ConvertMaskMultiByteString(str string) string {
	returnStr := ""
	for _, r := range str {
		if r > 127 {
			byteArr := []byte(string(r))
			for j := range byteArr {
				if j == len(byteArr)-1 {
					returnStr += fmt.Sprintf("?b")
				} else {
					returnStr += fmt.Sprintf("?b")
				}
			}
		} else {
			returnStr += fmt.Sprintf("%c", r)
		}
	}
	return returnStr
}

// ConstructReplacements create an array mapping which characters to replace
//
// Args:
//
//	str (string): The string containing what characters to convert "u", "l",
//	"d", "s"
//
// Returns:
//
//	args ([]string}: String slice containing replacements
func ConstructReplacements(str string) []string {
	var lowerArgs, upperArgs, digitArgs, args []string
	for c := 'a'; c <= 'z'; c++ {
		lowerArgs = append(lowerArgs, string(c), "?l")
	}
	for c := 'A'; c <= 'Z'; c++ {
		upperArgs = append(upperArgs, string(c), "?u")
	}
	for c := '0'; c <= '9'; c++ {
		digitArgs = append(digitArgs, string(c), "?d")
	}
	specialChars := " !\"#$%&\\()*+,-./:;<=>?@[\\]^_`{|}~'"
	specialArgs := make([]string, len(specialChars)*2)
	for i, c := range specialChars {
		specialArgs[i*2] = string(c)
		specialArgs[i*2+1] = "?s"
	}

	if strings.Contains(str, "l") {
		args = append(args, lowerArgs...)
	}

	if strings.Contains(str, "u") {
		args = append(args, upperArgs...)
	}

	if strings.Contains(str, "d") {
		args = append(args, digitArgs...)
	}

	if strings.Contains(str, "s") {
		args = append(args, specialArgs...)
	}

	return args
}

// ReverseString reverses a string and returns it
//
// Args:
//
//	s (string): String to reverse
//
// Returns:
//
//	(string): The reversed string
func ReverseString(s string) string {
	runes := []rune(s)
	for i, j := 0, len(runes)-1; i < j; i, j = i+1, j-1 {
		runes[i], runes[j] = runes[j], runes[i]
	}
	return string(runes)
}

// CharToIteratingRule converts a string to a rule by its characters but
// increments along with each character
//
// Args:
//
//	str (string): Input string to transform
//	rule (string): Rule to insert per length
//	index (int): Index to start at
//
// Returns:
//
//	(string): Transformed string
func CharToIteratingRule(str string, rule string, index int) string {
	var result strings.Builder
	for i, r := range str {
		if i+index < 10 {
			result.WriteString(fmt.Sprintf("%s%d%c ", rule, i+index, r))
		} else {
			result.WriteString(fmt.Sprintf("%s%c%c ", rule, 'A'+i+index-10, r))
		}
	}
	return strings.TrimSpace(result.String())
}

// LogError is used to log errors to a file
//
// Args:
//
//	funcName (string): Function name
//	printErr (error): Error data
//
//	Returns:
//		None
func LogError(funcName string, printErr error) {
	startTime := time.Now()

	logPath := filepath.Join("/var/www/OpenHashAPI/logs", "OpenHashAPI-Error.log")
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
	endTime := time.Now()
	latency := endTime.Sub(startTime)
	logger.Printf("[OHA] %v | %13v | Error: %s (%s)\n",
		endTime.Format("2006/01/02 - 15:04:05"),
		latency,
		printErr.Error(),
		funcName,
	)
}

// LogEvent is used to log events to a file
//
// Args:
//
//	funcName (string): Function name
//	printEvent (string): Event data
//
//	Returns:
//		None
func LogEvent(funcName string, printEvent string) {
	startTime := time.Now()

	logPath := filepath.Join("/var/www/OpenHashAPI/logs", "OpenHashAPI-Event.log")
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

	// set limit to 5gb
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
	endTime := time.Now()
	latency := endTime.Sub(startTime)
	logger.Printf("[OHA] %v | %13v | Event: %s (%s)\n",
		endTime.Format("2006/01/02 - 15:04:05"),
		latency,
		printEvent,
		funcName,
	)
}

// GenerateInsecureUniqueID is used to generate a unique ID for a request
// This is used for file creation. This is not cryptographically secure.
//
// Args:
//
//	None
//
// Returns:
//
//	(string): Unique ID
//	(error): Error data
func GenerateInsecureUniqueID() (string, error) {
	mathrand.New(mathrand.NewSource(time.Now().UnixNano()))
	charset := "abcdefghijklmnopqrstuvwxyz" +
		"ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"

	b := make([]byte, 8)
	for i := range b {
		b[i] = charset[mathrand.Intn(len(charset))]
	}
	return string(b), nil
}

// containsSubstring is used to check if a string contains any of the
// substrings in a slice
//
// Args:
//
//	word (string): The string to check
//	substrings ([]string): The substrings to check for
//
// Returns:
//
//	(bool): Returns true if it contains any of the substrings and false if it
func containsSubstring(word string, substrings []string) bool {
	for _, substring := range substrings {
		if strings.Contains(word, substring) {
			return true
		}
	}
	return false
}

// hasUniqueChars is used to check if a string has more than 3 unique characters
// This is used to filter out passwords that are not complex enough to be
// useful
//
// Args:
//
//	str (string): The string to check
//
// Returns:
//
//	(bool): Returns true if it has more than 3 unique characters and
//	false if it does not
func hasUniqueChars(str string) bool {
	counts := [128]bool{}
	uniqueCharCount := 0
	for i := 0; i < len(str); i++ {
		char := str[i]
		if char >= 'A' && char <= 'Z' || char >= 'a' && char <= 'z' {
			if !counts[char] {
				uniqueCharCount++
				if uniqueCharCount > 3 {
					return true
				}
			}
			counts[char] = true
		}
	}
	return false
}

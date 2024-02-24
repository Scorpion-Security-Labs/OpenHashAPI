// Package api controls REST routes not related to authentication or
// authorization
package api

import (
	"bufio"
	"fmt"
	"io"
	"net/http"
	"ohaserver/internal/auth"
	"ohaserver/internal/config"
	"ohaserver/internal/models"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
)

// HealthHandler is the endpoint handler for /api/health
//
// The endpoint expects an authorized GET request and returns metadata about
// the server configuration and status
//
// Args:
//
//	c (gin.Context): The Gin context object
//
// Returns:
//
//	None
func HealthHandler(c *gin.Context) {
	serverConfig := config.ServerConfig
	db, err := auth.MySQLAuthenticate()
	if err != nil {
		customErr := models.ErrorStruct{Error: err.Error(), Message: "Database authentication failed", Context: "HealthHandler"}
		c.JSON(http.StatusInternalServerError, customErr)
		return
	}
	defer db.Close()
	stats := db.Stats()

	metrics := struct {
		MaxGBrequestSize   int    `json:"max-gb-request-size"`
		OpenRegistration   bool   `json:"open-registration"`
		RehashUploads      bool   `json:"rehash-uploads"`
		RehashAlgo         int    `json:"rehash-algo"`
		QualityFilter      bool   `json:"quality-filter"`
		QualityFilterRegex string `json:"quality-filter-regex"`
		SelfHealDB         bool   `json:"self-heal-database"`
		SelfHealDBChunks   int    `json:"self-heal-database-chunks"`
		SelfHealDBWorkers  int    `json:"self-heal-database-workers"`
		MaxOpenConnections int    `json:"max-open-connections"`
		OpenConnections    int    `json:"open-connections"`
		InUseConnections   int    `json:"in-use-connections"`
		IdleConnections    int    `json:"idle-connections"`
	}{
		MaxGBrequestSize:   serverConfig.ServerGBMaxUploadSize,
		OpenRegistration:   serverConfig.OpenRegistration,
		RehashUploads:      serverConfig.RehashUploads,
		RehashAlgo:         serverConfig.RehashAlgorithm,
		QualityFilter:      serverConfig.QualityFilter,
		QualityFilterRegex: serverConfig.QualityFilterRegex,
		SelfHealDB:         serverConfig.SelfHealDB,
		SelfHealDBChunks:   serverConfig.SelfHealDBChunks,
		SelfHealDBWorkers:  serverConfig.SelfHealDBWorkers,
		MaxOpenConnections: stats.MaxOpenConnections,
		OpenConnections:    stats.OpenConnections,
		InUseConnections:   stats.InUse,
		IdleConnections:    stats.Idle,
	}

	c.JSON(http.StatusOK, metrics)
}

// SearchHandler is the endpoint handler for /api/search
//
// The endpoint expects an authorized POST request with a JSON body and returns
// any found HASH and/or PLAINS from the database that match
//
// The expected JSON object has a single property, data:
//
//	data (string): An array of strings with either HASH or PLAIN values
//
// Args:
//
//	c (gin.Context): The Gin context object
//
// Returns:
//
//	None
func SearchHandler(c *gin.Context) {
	var hashes models.HashSearchStruct
	var hash models.HashStruct
	var outarray []models.HashStruct
	db, err := auth.MySQLAuthenticate()
	if err != nil {
		customErr := models.ErrorStruct{Error: err.Error(), Message: "Database authentication failed", Context: "SearchHandler"}
		c.JSON(http.StatusInternalServerError, customErr)
		return
	}
	defer db.Close()

	if err := c.BindJSON(&hashes); err != nil {
		customErr := models.ErrorStruct{Error: err.Error(), Message: "Error binding JSON", Context: "SearchHandler"}
		c.JSON(http.StatusBadRequest, customErr)
		return
	}

	stmt, err := db.Prepare("SELECT * FROM Hashes WHERE hash IN (?" + strings.Repeat(",?", len(hashes.Data)-1) + ") OR plaintext IN (?" + strings.Repeat(",?", len(hashes.Data)-1) + ")")
	if err != nil {
		config.LogError("SearchHandler: error preparing statement", err)
		customErr := models.ErrorStruct{Error: err.Error(), Message: "Error preparing statement", Context: "SearchHandler"}
		c.JSON(http.StatusInternalServerError, customErr)
		return
	}
	defer stmt.Close()

	args := make([]interface{}, len(hashes.Data)*2)
	for i, v := range hashes.Data {
		args[i] = v
		args[i+len(hashes.Data)] = v
	}
	rows, err := stmt.Query(args...)
	if err != nil {
		config.LogError("SearchHandler: error querying database", err)
		customErr := models.ErrorStruct{Error: err.Error(), Message: "Error querying database", Context: "SearchHandler"}
		c.JSON(http.StatusInternalServerError, customErr)
		return
	}
	defer rows.Close()

	for rows.Next() {
		err = rows.Scan(&hash.Algorithm, &hash.Hash, &hash.Plaintext, &hash.Validated)
		if err != nil {
			config.LogError("SearchHandler: error scanning rows", err)
			customErr := models.ErrorStruct{Error: err.Error(), Message: "Error scanning rows", Context: "SearchHandler"}
			c.JSON(http.StatusInternalServerError, customErr)
			return
		}
		outarray = append(outarray, hash)
	}

	c.JSON(http.StatusOK, gin.H{"found": outarray})
}

// SubmitHashHandler is the endpoint handler for /api/submit
//
// The endpoint expects an authorized POST request with a JSON body and returns
// a JSON containing the hashing algorithm, total hashes submitted, number of
// filtered hashes, and number of new plaintexts from the submission.
//
// The expected JSON object has two properties, algorithm and hash-plain:
//
//	algorithm (string): property that specifies the hashing algorithm used
//	hash-plain (string): array of strings in HASH:PLAIN or HASH:SALT:PLAIN
//	format
//
// Args:
//
//	c (gin.Context): The Gin context object
//
// Returns:
//
//	None
func SubmitHashHandler(c *gin.Context) {
	var originalHashesLen int
	var hashes models.HashUploadStruct
	var newhashes []interface{}
	serverConfig := config.ServerConfig
	db, err := auth.MySQLAuthenticate()
	if err != nil {
		customErr := models.ErrorStruct{Error: err.Error(), Message: "Database authentication failed", Context: "SubmitHashHandler"}
		c.JSON(http.StatusInternalServerError, customErr)
		return
	}
	defer db.Close()

	if err := c.BindJSON(&hashes); err != nil {
		config.LogError("SubmitHashHandler: error binding JSON", err)
		customErr := models.ErrorStruct{Error: err.Error(), Message: "Error binding JSON", Context: "SubmitHashHandler"}
		c.JSON(http.StatusBadRequest, customErr)
		return
	}

	if models.ValidateIntInput(hashes.Algorithm) == false {
		customErr := models.ErrorStruct{Error: "Invalid algorithm selected", Message: "Invalid algorithm selected", Context: "SubmitHashHandler"}
		c.JSON(http.StatusBadRequest, customErr)
		return
	}

	originalHashesLen = len(hashes.HashPlain)
	errorCount := 0

	// if rehashing
	if serverConfig.RehashUploads {
		if hashes.Algorithm != "0" && serverConfig.RehashAlgorithm == 0 {
			hashes.Algorithm = "0"
			newhashes, err = config.RehashUpload(hashes.HashPlain, "0")
			if err != nil {
				config.LogError("SubmitHashHandler: error rehashing hashes", err)
				customErr := models.ErrorStruct{Error: err.Error(), Message: "Error rehashing hashes", Context: "SubmitHashHandler"}
				c.JSON(http.StatusInternalServerError, customErr)
				return
			}
		} else if hashes.Algorithm != "100" && serverConfig.RehashAlgorithm == 100 {
			hashes.Algorithm = "100"
			newhashes, err = config.RehashUpload(hashes.HashPlain, "100")
			if err != nil {
				config.LogError("SubmitHashHandler: error rehashing hashes", err)
				customErr := models.ErrorStruct{Error: err.Error(), Message: "Error rehashing hashes", Context: "SubmitHashHandler"}
				c.JSON(http.StatusInternalServerError, customErr)
				return
			}
		} else if hashes.Algorithm != "1000" && serverConfig.RehashAlgorithm == 1000 {
			hashes.Algorithm = "1000"
			newhashes, err = config.RehashUpload(hashes.HashPlain, "1000")
			if err != nil {
				config.LogError("SubmitHashHandler: error rehashing hashes", err)
				customErr := models.ErrorStruct{Error: err.Error(), Message: "Error rehashing hashes", Context: "SubmitHashHandler"}
				c.JSON(http.StatusInternalServerError, customErr)
				return
			}
		} else {
			for _, h := range hashes.HashPlain {
				newhashes = append(newhashes, h)
			}
		}
	} else {
		for _, h := range hashes.HashPlain {
			newhashes = append(newhashes, h)
		}
	}

	// if filtering
	if serverConfig.QualityFilter {
		filteredNewhashes := []interface{}{}
		for _, row := range newhashes {
			_, plaintext, err := config.ParseHashAndPlaintext(row)
			if err != nil {
				config.LogError("SubmitHashHandler: error parsing hash and plaintext", err)
				errorCount++
				continue
			}

			// dehex when needed
			if config.TestHexInput(plaintext) == true {
				plaintext, err = config.DehexPlaintext(plaintext)
				if err != nil {
					config.LogError("SubmitHashHandler: error dehexing plaintext", err)
					errorCount++
					continue
				}
			}

			if config.TestPlainQuality(plaintext) {
				filteredNewhashes = append(filteredNewhashes, row)
			}
		}
		newhashes = filteredNewhashes
	}

	if len(newhashes) <= 0 {
		customErr := models.ErrorStruct{Error: "No valid hashes received", Message: "No valid hashes received. Please check the filter if enabled.", Context: "SubmitHashHandler"}
		c.JSON(http.StatusOK, customErr)
		return
	}

	var parsedhashes []interface{}
	for _, row := range newhashes {
		hash, plain, err := config.ParseHashAndPlaintext(row)
		if err != nil {
			config.LogError("SubmitHashHandler: error parsing hash and plaintext", err)
			errorCount++
			continue
		}
		parsedhashes = append(parsedhashes, hashes.Algorithm, hash, plain)
	}

	batchSize := 10000

	totalRowsAffected := int64(0)
	for i := 0; i < len(parsedhashes); i += 3 * batchSize {
		end := i + 3*batchSize
		if end > len(parsedhashes) {
			end = len(parsedhashes)
		}
		batch := parsedhashes[i:end]

		str := "INSERT IGNORE INTO Hashes (algorithm, hash, plaintext) VALUES "
		for i := 0; i < len(batch); i += 3 {
			str += "(?, ?, ?),"
		}
		str = strings.TrimSuffix(str, ",")

		statement, err := db.Prepare(str)
		if err != nil {
			config.LogError("SubmitHashHandler: error preparing statement", err)
			customErr := models.ErrorStruct{Error: err.Error(), Message: "Error preparing statement", Context: "SubmitHashHandler"}
			c.JSON(http.StatusInternalServerError, customErr)
			return
		}
		defer statement.Close()

		result, err := statement.Exec(batch...)
		if err != nil {
			config.LogError("SubmitHashHandler: error executing statement", err)
			customErr := models.ErrorStruct{Error: err.Error(), Message: "Error executing statement", Context: "SubmitHashHandler"}
			c.JSON(http.StatusInternalServerError, customErr)
			return
		}

		rowsAffected, err := result.RowsAffected()
		if err != nil {
			config.LogError("SubmitHashHandler: error getting rows affected", err)
			customErr := models.ErrorStruct{Error: err.Error(), Message: "Error getting rows affected", Context: "SubmitHashHandler"}
			c.JSON(http.StatusInternalServerError, customErr)
			return
		}

		totalRowsAffected += rowsAffected
	}

	config.LogEvent(fmt.Sprintf("SubmitHashHandler: processed %d [%s] hashes", originalHashesLen, hashes.Algorithm), fmt.Sprintf("New hashes added: %d", totalRowsAffected))
	c.JSON(http.StatusOK, gin.H{"Algorithm": hashes.Algorithm, "Total": originalHashesLen, "Filtered": originalHashesLen - len(newhashes), "New": totalRowsAffected, "Errors": errorCount})
}

// DownloadFileHandler is the endpoint handler for /api/download/FILE/NUMBER
//
// The endpoint expects an authorized GET request with FILE being "wordlist",
// "rules", or "masks" and the NUMBER being a valid integer value
//
// responses include the top NUMBER of items from the FILE
//
// requests can include a query string parameter of "offset" (int) that will offset
// the starting point of the file read by that many lines
//
// Args:
//
//	c (gin.Context): The Gin context object
//
// Returns:
//
//	None
func DownloadFileHandler(c *gin.Context) {
	n := c.Param("n")
	offset := c.Query("offset")
	contains := c.Query("contains")
	prepends := c.Query("prepend")
	appends := c.Query("append")
	toggles := c.Query("toggle")
	var offsetInt int
	var prependBool bool
	var appendBool bool
	var toggleBool bool

	if models.ValidateIntInput(offset) == false {
		offsetInt = 0
	}

	if models.ValidateBoolInput(prepends) == true {
		prependBool = true
	}

	if models.ValidateBoolInput(appends) == true {
		appendBool = true
	}

	if models.ValidateBoolInput(toggles) == true {
		toggleBool = true
	}

	if !regexp.MustCompile(`^[a-zA-Z0-9!@#$%^&*()_+=. -]*$`).MatchString(contains) {
		customErr := models.ErrorStruct{Error: "Invalid value provided for contains", Message: fmt.Sprintf("Invalid value provided for contains: %q", contains), Context: "DownloadFileHandler"}
		c.JSON(http.StatusBadRequest, customErr)
		return
	}

	offsetInt, err := strconv.Atoi(offset)
	if err != nil {
		offsetInt = 0
	}
	filename := c.Param("filename")

	if filename != "wordlist" && filename != "rules" && filename != "masks" {
		customErr := models.ErrorStruct{Error: "Invalid value provided for filename", Message: fmt.Sprintf("Invalid value provided for filename: %q", filename), Context: "DownloadFileHandler"}
		c.JSON(http.StatusBadRequest, customErr)
		return
	} else if filename == "wordlist" {
		filename = "/var/www/OpenHashAPI/wordlist.txt"
	} else if filename == "rules" {
		filename = "/var/www/OpenHashAPI/rules.txt"
	} else if filename == "masks" {
		filename = "/var/www/OpenHashAPI/masks.txt"
	}

	if models.ValidateIntInput(n) == false {
		customErr := models.ErrorStruct{Error: "Invalid value provided for n", Message: fmt.Sprintf("Invalid value provided for number of entries: %q", n), Context: "DownloadFileHandler"}
		c.JSON(http.StatusBadRequest, customErr)
		return
	}

	lines, err := strconv.Atoi(n)
	if err != nil {
		customErr := models.ErrorStruct{Error: err.Error(), Message: "Error converting number of entries to integer", Context: "DownloadFileHandler"}
		c.JSON(http.StatusBadRequest, customErr)
		return
	}

	file, err := os.Open(filepath.Clean(filename))
	if err != nil {
		customErr := models.ErrorStruct{Error: err.Error(), Message: "Error opening file", Context: "DownloadFileHandler"}
		c.JSON(http.StatusInternalServerError, customErr)
		return
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	var sb strings.Builder
	lineCount := 0
	for scanner.Scan() {
		if lineCount >= offsetInt {

			if contains != "" && !strings.Contains(scanner.Text(), contains) {
				continue
			}

			if prepends != "" {

				prependRegex := `\^[a-zA-Z0-9!@#$%^&*()_+=.-] |\^[a-zA-Z0-9!@#$%^&*()_+=.-]$`
				if prependBool {
					if !regexp.MustCompile(prependRegex).MatchString(scanner.Text()) {
						continue
					}
				} else {
					if regexp.MustCompile(prependRegex).MatchString(scanner.Text()) {
						continue
					}
				}
			}

			if appends != "" {

				appendRegex := `\$[a-zA-Z0-9!@#$%^&*()_+=.-] |\$[a-zA-Z0-9!@#$%^&*()_+=.-]$`
				if appendBool {
					if !regexp.MustCompile(appendRegex).MatchString(scanner.Text()) {
						continue
					}
				} else {
					if regexp.MustCompile(appendRegex).MatchString(scanner.Text()) {
						continue
					}
				}
			}

			if toggles != "" {

				toggleRegex := `T[0-9A-Z] |T[0-9A-Z]$`
				if toggleBool {
					if !regexp.MustCompile(toggleRegex).MatchString(scanner.Text()) {
						continue
					}
				} else {
					if regexp.MustCompile(toggleRegex).MatchString(scanner.Text()) {
						continue
					}
				}
			}

			sb.WriteString(scanner.Text() + "\n")
			lines--
			if lines == 0 {
				break
			}

			lineCount++

		} else if contains == "" || prepends != "" || appends != "" || toggles != "" || strings.Contains(scanner.Text(), contains) {
			lineCount++
		}
	}

	if err := scanner.Err(); err != nil {
		config.LogError("DownloadFileHandler: error reading file", err)
		customErr := models.ErrorStruct{Error: err.Error(), Message: "Error reading file", Context: "DownloadFileHandler"}
		c.JSON(http.StatusInternalServerError, customErr)
		return
	}

	c.Writer.Header().Add("Content-Disposition", "attachment; filename="+filename)
	c.Writer.Header().Add("Content-Type", "application/octet-stream")
	c.String(http.StatusOK, sb.String())
}

// StatusHandler is the endpoint handler for /api/status
//
// The endpoint expects an unauthorized GET request and returns the status of
// the downloadable files on the server
//
// Args:
//
//	c (gin.Context): The Gin context object
//
// Returns:
//
//	None
func StatusHandler(c *gin.Context) {
	type Response struct {
		Masks    bool `json:"masks"`
		Wordlist bool `json:"wordlist"`
		Rules    bool `json:"rules"`
	}
	var res Response

	if _, err := os.Stat("/var/www/OpenHashAPI/masks.txt"); err == nil {
		res.Masks = true
	}
	if _, err := os.Stat("/var/www/OpenHashAPI/wordlist.txt"); err == nil {
		res.Wordlist = true
	}
	if _, err := os.Stat("/var/www/OpenHashAPI/rules.txt"); err == nil {
		res.Rules = true
	}

	c.JSON(http.StatusOK, res)
}

// ViewListHandler is the endpoint handler for GET /api/list and /api/list/ID
//
// The endpoint expects an authorized GET request and returns a list of all
// lists available to the user. If an ID is provided, the endpoint returns the
// list with that ID
//
// Args:
//
// c (gin.Context): The Gin context object
//
// Returns:
//
// None
func ViewListHandler(c *gin.Context) {
	listName := c.Param("listname")
	if !regexp.MustCompile(`^[a-zA-Z0-9!@#$%^&*()_+=.-]*$`).MatchString(listName) {
		customErr := models.ErrorStruct{Error: "Invalid value provided for listName", Message: fmt.Sprintf("Invalid value provided for listName: %q", listName), Context: "ViewListHandler"}
		c.JSON(http.StatusBadRequest, customErr)
		return
	}

	if listName == "" {
		// list all files in /var/www/OpenHashAPI/lists
		dir := "/var/www/OpenHashAPI/lists"
		files := make([]map[string]interface{}, 0)
		err := filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
			if err != nil {
				return err
			}
			if !info.IsDir() {
				file := map[string]interface{}{
					"name":          strings.TrimSuffix(filepath.Base(path), filepath.Ext(filepath.Base(path))),
					"size":          info.Size(),
					"creation_time": info.ModTime().Format(time.RFC3339),
				}
				files = append(files, file)
			}
			return nil
		})
		if err != nil {
			customErr := models.ErrorStruct{Error: err.Error(), Message: "Error walking the path", Context: "ViewListHandler"}
			c.JSON(http.StatusInternalServerError, customErr)
			return
		}
		c.JSON(http.StatusOK, gin.H{
			"files": files,
		})
	} else {
		// return the file contents of /var/www/OpenHashAPI/lists/listName
		file, err := os.Open(filepath.Clean(fmt.Sprintf("%s/%s.%s", "/var/www/OpenHashAPI/lists", listName, "txt")))
		if err != nil {
			customErr := models.ErrorStruct{Error: err.Error(), Message: "Error opening file", Context: "ViewListHandler"}
			c.JSON(http.StatusBadRequest, customErr)
			return
		}
		defer file.Close()

		scanner := bufio.NewScanner(file)
		var sb strings.Builder
		for scanner.Scan() {
			sb.WriteString(scanner.Text() + "\n")
		}

		if err := scanner.Err(); err != nil {
			customErr := models.ErrorStruct{Error: err.Error(), Message: "Error reading file", Context: "ViewListHandler"}
			c.JSON(http.StatusInternalServerError, customErr)
			return
		}

		c.Writer.Header().Add("Content-Disposition", "attachment; filename="+listName)
		c.Writer.Header().Add("Content-Type", "application/octet-stream")
		c.String(http.StatusOK, sb.String())
	}
}

// EditListHandler is the endpoint handler for POST /api/list and /api/list/ID
//
// The endpoint expects an authorized POST request and creates a new list or
// edits an existing list with the provided ID. If editing, the orginal list is
// modified with new founds.
//
// Args:
//
// c (gin.Context): The Gin context object
//
// Returns:
//
// # None
func EditListHandler(c *gin.Context) {
	listName := c.Param("listname")
	userInputListName := c.Query("name")

	if !regexp.MustCompile(`^[a-zA-Z0-9!@#$%^&*()_+=.-]*$`).MatchString(listName) {
		customErr := models.ErrorStruct{Error: "Invalid value provided for listName", Message: fmt.Sprintf("Invalid value provided for listName: %q", listName), Context: "EditListHandler"}
		c.JSON(http.StatusBadRequest, customErr)
		return
	}

	if listName == "" {
		body := c.Request.Body
		data, err := io.ReadAll(body)
		if err != nil {
			customErr := models.ErrorStruct{Error: err.Error(), Message: "Error reading request body", Context: "EditListHandler"}
			c.JSON(http.StatusBadRequest, customErr)
			return
		}

		// Use a unique ID for the filename
		uniqueID, err := config.GenerateInsecureUniqueID()
		if err != nil {
			customErr := models.ErrorStruct{Error: err.Error(), Message: "Error generating unique ID", Context: "EditListHandler"}
			c.JSON(http.StatusInternalServerError, customErr)
			return
		}

		// Check if the query parameter is set
		// If so, use that as the filename instead of the unique ID
		if userInputListName != "" {
			if models.ValidateUsernameInput(userInputListName) == false {
				customErr := models.ErrorStruct{Error: "Invalid value provided for name", Message: fmt.Sprintf("Invalid value provided for name: %q", userInputListName), Context: "EditListHandler"}
				c.JSON(http.StatusBadRequest, customErr)
				return
			}
			uniqueID = userInputListName
		}

		// Check if the file already exists
		if _, err := os.Stat(fmt.Sprintf("%s/%s.%s", "/var/www/OpenHashAPI/lists", uniqueID, "txt")); err == nil {
			customErr := models.ErrorStruct{Error: "File already exists", Message: fmt.Sprintf("File already exists: %q", uniqueID), Context: "EditListHandler"}
			c.JSON(http.StatusBadRequest, customErr)
			return
		}

		// Write the file
		filename := fmt.Sprintf("%s/%s.%s", "/var/www/OpenHashAPI/lists", uniqueID, "txt")
		err = os.WriteFile(filename, data, 0664)
		if err != nil {
			customErr := models.ErrorStruct{Error: err.Error(), Message: "Error writing file", Context: "EditListHandler"}
			c.JSON(http.StatusInternalServerError, customErr)
			return
		}

		c.JSON(http.StatusOK, gin.H{
			"filename": strings.TrimSuffix(filepath.Base(filename), filepath.Ext(filepath.Base(filename))),
		})
	} else {
		// edit the file contents of /var/www/OpenHashAPI/lists/listName
		// any matching hashes are added with the format HASH:PLAIN
		// non-matching hashes are ignored
		// WARNING: no validation is done on the algorithmic values of the HASH:PLAIN
		if listName == "" {
			customErr := models.ErrorStruct{Error: "Missing listname parameter", Message: "Missing listname parameter", Context: "EditListHandler"}
			c.JSON(http.StatusBadRequest, customErr)
			return
		}

		body := c.Request.Body
		data, err := io.ReadAll(body)
		if err != nil {
			customErr := models.ErrorStruct{Error: err.Error(), Message: "Error reading request body", Context: "EditListHandler"}
			c.JSON(http.StatusBadRequest, customErr)
			return
		}

		// Read the existing file
		existingData, err := os.ReadFile(fmt.Sprintf("%s/%s.%s", "/var/www/OpenHashAPI/lists", listName, "txt"))
		if err != nil {
			customErr := models.ErrorStruct{Error: err.Error(), Message: "Error reading existing file", Context: "EditListHandler"}
			c.JSON(http.StatusInternalServerError, customErr)
			return
		}

		// Compare the new data with the existing data
		newData := string(data)
		existingLines := strings.Split(string(existingData), "\n")
		newLines := strings.Split(newData, "\n")

		// Create a map to hold the final lines and lefts
		finalLines := make(map[string]string)
		leftLines := make(map[string]string)

		// Add existing lines to the map
		for _, line := range existingLines {
			if strings.Contains(line, ":") && line != "" {
				cipher, plain, err := config.ParseHashAndPlaintext(line)
				if err != nil {
					c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
					return
				}
				finalLines[cipher] = fmt.Sprintf("%s:%s", cipher, plain)
			} else {
				leftLines[line] = line
			}
		}

		// Add new lines to the map
		for _, line := range newLines {
			if strings.Contains(line, ":") && line != "" {
				cipher, plain, err := config.ParseHashAndPlaintext(line)
				if err != nil {
					customErr := models.ErrorStruct{Error: err.Error(), Message: "Error parsing hash and plaintext", Context: "EditListHandler"}
					c.JSON(http.StatusInternalServerError, customErr)
					return
				}

				// Check if the cipher already exists in the map if not ignore
				if _, ok := leftLines[cipher]; ok {
					finalLines[cipher] = fmt.Sprintf("%s:%s", cipher, plain)
					delete(leftLines, cipher)
				}

			}
		}

		// Add the left lines to the final lines
		for _, line := range leftLines {
			finalLines[line] = line
		}

		// Convert the map back to a slice
		updatedLines := make([]string, 0, len(finalLines))
		for _, line := range finalLines {
			updatedLines = append(updatedLines, line)
		}

		// Write the updated data back to the file
		err = os.WriteFile(fmt.Sprintf("%s/%s.%s", "/var/www/OpenHashAPI/lists", listName, "txt"), []byte(strings.Join(updatedLines, "\n")), 0664)
		if err != nil {
			customErr := models.ErrorStruct{Error: err.Error(), Message: "Error writing file", Context: "EditListHandler"}
			c.JSON(http.StatusInternalServerError, customErr)
			return
		}

		c.JSON(http.StatusOK, gin.H{"status": "file updated"})

	}
}

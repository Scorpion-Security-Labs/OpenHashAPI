// Package main controls launching the server and its components
//
// The configuration for the server is done by a JSON configuration file given
// in the Dockerfile. All API routes are hosted on /api/* and some require more
// granular permissions to access.
package main

import (
	"fmt"
	"net/http"
	"ohaserver/internal/api"
	"ohaserver/internal/auth"
	"ohaserver/internal/config"
	"ohaserver/internal/middleware"
	"os"

	"github.com/gin-gonic/gin"
)

var err error

func init() {
	// NOTE: This is hard coded from the Dockerfile
	config.ServerConfig = config.LoadConfig("/etc/config.json")
}

func main() {
	// DATABASE
	db, err := auth.MySQLAuthenticate()
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}

	// SERVER
	serverConfig := config.ServerConfig
	ginServer := gin.Default()
	ginServer.Static("/static", "/var/www/OpenHashAPI/static")
	ginServer.LoadHTMLGlob("/var/www/OpenHashAPI/templates/*")
	ginServer.SetTrustedProxies([]string{""})

	// SELF VALIDATION
	if serverConfig.SelfHealDB && serverConfig.RehashUploads {
		go config.ValidateDatabaseHashes(db, serverConfig.SelfHealDBChunks, serverConfig.SelfHealDBWorkers, serverConfig.RehashAlgorithm)
	}

	// GENERATE FILES
	tasks := make(chan func(), 2)
	go func() {
		for task := range tasks {
			task()
		}
	}()

	if serverConfig.GenerateWordlist {
		tasks <- func() { config.GenerateWordlistFile(db) }
	}
	if serverConfig.GenerateRules {
		tasks <- func() { config.GenerateRulesFile(db) }
	}
	if serverConfig.GenerateMasks {
		tasks <- func() { config.GenerateMasksFile(db) }
	}

	close(tasks)

	// MIDDLEWARE
	ginServer.Use(middleware.MaxSizeAllowed(serverConfig.ServerGBMaxUploadSize))
	ginServer.Use(middleware.LoggerMiddleware)

	// AUTHORIZATION LEVELS
	frontendPublic := ginServer.Group("/")
	frontendPrivate := ginServer.Group("/")
	frontendPrivate.Use(middleware.AuthenticationCheckMiddleware())

	public := ginServer.Group("/api")
	private := ginServer.Group("/api")
	private.Use(middleware.AuthenticationCheckMiddleware())

	// FRONTEND ROUTES
	frontendPublic.GET("/login", func(c *gin.Context) {
		c.HTML(http.StatusOK, "login.html", gin.H{})
	})
	frontendPrivate.GET("/home", func(c *gin.Context) {
		c.HTML(http.StatusOK, "home.html", gin.H{})
	})

	// API ROUTES
	public.GET("/status", api.StatusHandler)
	public.POST("/login", auth.LoginHandler)
	public.POST("/register", middleware.OpenRegistrationMiddleware(serverConfig.OpenRegistration), auth.RegistrationHandler)

	// PRIVATE ROUTES
	private.GET("/health", api.HealthHandler)
	private.GET("/download/:filename/:n", api.DownloadFileHandler)
	private.GET("/manage/refresh/:filename", middleware.CanManageMiddleware(), api.ManageRefreshFilesHandler)
	private.POST("/search", middleware.CanSearchMiddleware(), api.SearchHandler)
	private.POST("/found", middleware.CanUploadMiddleware(), api.SubmitHashHandler)
	private.POST("/manage", middleware.CanManageMiddleware(), auth.ManageUserHandler)

	// PRIVATE LIST ROUTES
	private.GET("/lists", middleware.CanListUserListsMiddleware(serverConfig.AllowUserLists), api.ViewListHandler)
	private.GET("/lists/:listname", middleware.CanListUserListsMiddleware(serverConfig.AllowUserLists), api.ViewListHandler)
	private.POST("/lists", middleware.CanEditUserListsMiddleware(serverConfig.AllowUserLists), api.EditListHandler)
	private.POST("/lists/:listname", middleware.CanEditUserListsMiddleware(serverConfig.AllowUserLists), api.EditListHandler)

	// REDIRECT ROUTE
	ginServer.NoRoute(func(c *gin.Context) {
		c.Redirect(http.StatusFound, "/login")
	})

	// SERVER START
	ginServer.RunTLS(fmt.Sprintf(":%d", serverConfig.ServerPort), serverConfig.ServerTLSCertfilePath, serverConfig.ServerTLSKeyfilePath)
}

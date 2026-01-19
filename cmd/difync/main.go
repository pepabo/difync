// Package main is the entry point for the difync CLI application
package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"time"

	"github.com/joho/godotenv"
	"github.com/pepabo/difync/internal/syncer"
)

// getEnvWithDefault gets environment variable or returns default if not set
func getEnvWithDefault(key, defaultValue string) string {
	value := os.Getenv(key)
	if value == "" {
		return defaultValue
	}
	return value
}

// Command-line flags
var (
	difyBaseURL = flag.String("base-url", "", "Dify API base URL (overrides env: DIFY_BASE_URL)")
	dslDir      = flag.String("dsl-dir", "", "Directory containing DSL files (overrides env: DSL_DIRECTORY, default: dsl)")
	appMapFile  = flag.String("app-map", "", "Path to app mapping file (overrides env: APP_MAP_FILE, default: app_map.json)")
	dryRun      = flag.Bool("dry-run", false, "Perform a dry run without making any changes")
	verbose     = flag.Bool("verbose", false, "Enable verbose output")
)

// For testing purposes, we make createSyncer a variable so it can be replaced in tests
var createSyncer = func(config syncer.Config) syncer.Syncer {
	return syncer.NewSyncer(config)
}

// For testing purposes
var osExit = os.Exit

// loadConfigAndValidate loads configuration from flags and environment variables
// and validates the configuration
func loadConfigAndValidate() (*syncer.Config, error) {
	// Get values from environment if not set via flags
	baseURL := *difyBaseURL
	if baseURL == "" {
		baseURL = os.Getenv("DIFY_BASE_URL")
	}

	// Email and password are only retrieved from environment variables
	email := os.Getenv("DIFY_EMAIL")
	password := os.Getenv("DIFY_PASSWORD")

	// Get DSL directory from flags or environment with default
	dslDirectory := *dslDir
	if dslDirectory == "" {
		dslDirectory = getEnvWithDefault("DSL_DIRECTORY", "dsl")
	}

	// Get app map file from flags or environment with default
	appMap := *appMapFile
	if appMap == "" {
		appMap = getEnvWithDefault("APP_MAP_FILE", "app_map.json")
	}

	// Validate required parameters
	if baseURL == "" {
		return nil, fmt.Errorf("dify base URL is required. Set with --base-url or DIFY_BASE_URL env var")
	}

	if email == "" {
		return nil, fmt.Errorf("dify email is required. Set with DIFY_EMAIL env var")
	}

	if password == "" {
		return nil, fmt.Errorf("dify password is required. Set with DIFY_PASSWORD env var")
	}

	// Resolve DSL directory path
	dslDirPath, err := filepath.Abs(dslDirectory)
	if err != nil {
		return nil, fmt.Errorf("failed to resolve DSL directory path: %w", err)
	}

	// Resolve app map file path
	appMapPath, err := filepath.Abs(appMap)
	if err != nil {
		return nil, fmt.Errorf("failed to resolve app map file path: %w", err)
	}

	// Create syncer config
	config := &syncer.Config{
		DifyBaseURL:  baseURL,
		DifyEmail:    email,
		DifyPassword: password,
		DSLDirectory: dslDirPath,
		AppMapFile:   appMapPath,
		DryRun:       *dryRun,
		Verbose:      *verbose,
	}

	return config, nil
}

// printInfo prints information about the sync operation
func printInfo(config *syncer.Config) {
	fmt.Println("Difync - Dify.AI DSL Synchronizer")
	fmt.Println("----------------------------")
	fmt.Printf("DSL Directory: %s\n", config.DSLDirectory)
	fmt.Printf("App Map File: %s\n", config.AppMapFile)
	if config.DryRun {
		fmt.Println("Mode: DRY RUN (no changes will be made)")
	} else {
		fmt.Println("Mode: Download")
	}
	fmt.Println()
}

// printStats prints statistics about the sync operation
func printStats(stats *syncer.SyncStats, duration time.Duration) {
	fmt.Println("\nSync Summary:")
	fmt.Printf("Total apps: %d\n", stats.Total)
	fmt.Printf("Downloads: %d\n", stats.Downloads)
	fmt.Printf("Added: %d\n", stats.Added)
	fmt.Printf("No action (in sync): %d\n", stats.NoAction)
	fmt.Printf("Errors: %d\n", stats.Errors)
	fmt.Printf("Duration: %v\n", duration)
}

// runInit initializes the app map file
func runInit(config *syncer.Config) (int, error) {
	// Validate config
	if config == nil {
		return 1, fmt.Errorf("configuration is nil")
	}

	fmt.Println("Difync - Dify.AI DSL Synchronizer")
	fmt.Println("----------------------------")
	fmt.Println("Initializing app map file...")

	syncr := createSyncer(*config)

	// Type assertion using duck typing to check for InitializeAppMap method
	// Use reflection to check if the object has the InitializeAppMap method
	initMethod := reflect.ValueOf(syncr).MethodByName("InitializeAppMap")
	if !initMethod.IsValid() {
		return 1, fmt.Errorf("failed to convert syncer to DefaultSyncer")
	}

	// Call the InitializeAppMap method
	results := initMethod.Call([]reflect.Value{})
	if len(results) != 2 {
		return 1, fmt.Errorf("unexpected return values from InitializeAppMap")
	}

	// Check for error
	errVal := results[1].Interface()
	if errVal != nil {
		return 1, fmt.Errorf("initialization failed: %v", errVal)
	}

	// Get app map
	appMapVal := results[0].Interface()
	appMap, ok := appMapVal.(*syncer.AppMap)
	if !ok {
		return 1, fmt.Errorf("unexpected return type from InitializeAppMap")
	}

	fmt.Printf("Successfully initialized app map file with %d applications\n", len(appMap.Apps))
	fmt.Printf("App map file created at: %s\n", config.AppMapFile)
	fmt.Printf("DSL files downloaded to: %s\n", config.DSLDirectory)
	return 0, nil
}

// runSync runs the sync operation
func runSync(config *syncer.Config) (int, error) {
	// Validate config
	if config == nil {
		return 1, fmt.Errorf("configuration is nil")
	}

	// Create syncer
	syncr := createSyncer(*config)

	// Print info
	printInfo(config)

	// Start sync
	fmt.Println("Starting sync...")
	startTime := time.Now()

	stats, err := syncr.SyncAll()
	if err != nil {
		// Display initialization errors more clearly
		errMsg := err.Error()
		appMapNotFoundErr := fmt.Sprintf("app map file not found at %s", config.AppMapFile)

		if strings.Contains(errMsg, appMapNotFoundErr) {
			return 1, fmt.Errorf("\nerror: App map file not found.\n\nPlease run initialization first:\n\ndifync init\n\nThen you can run the sync command")
		}

		return 1, fmt.Errorf("error during sync: %w", err)
	}

	// Print summary
	duration := time.Since(startTime)
	printStats(stats, duration)

	// Return non-zero status code if there were errors
	if stats.Errors > 0 {
		return 1, nil
	}

	return 0, nil
}

func main() {
	// Load .env file if it exists
	_ = godotenv.Load()

	flag.Parse()

	// Check for subcommands
	args := flag.Args()
	subCommand := ""
	if len(args) > 0 {
		subCommand = args[0]
	}

	// Load and validate configuration
	config, err := loadConfigAndValidate()
	if err != nil {
		fmt.Printf("Error: %v\n", err)
		osExit(1)
	}

	var exitCode int

	// Branch processing according to subcommand
	switch subCommand {
	case "init":
		// Initialization command
		exitCode, err = runInit(config)
	default:
		// Normal sync command
		exitCode, err = runSync(config)
	}

	if err != nil {
		fmt.Printf("Error: %v\n", err)
		osExit(1)
	}

	osExit(exitCode)
}

// Package main is the entry point for the difync CLI application
package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"
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
	difyBaseURL    = flag.String("base-url", "", "Dify API base URL (overrides env: DIFY_BASE_URL)")
	dslDir         = flag.String("dsl-dir", "", "Directory containing DSL files (overrides env: DSL_DIRECTORY, default: dsl)")
	appMapFile     = flag.String("app-map", "", "Path to app mapping file (overrides env: APP_MAP_FILE, default: app_map.json)")
	dryRun         = flag.Bool("dry-run", false, "Perform a dry run without making any changes")
	forceDirection = flag.String("force", "", "Force sync direction: 'upload', 'download', or empty for bidirectional")
	verbose        = flag.Bool("verbose", false, "Enable verbose output")
)

// For testing purposes, we make createSyncer a variable so it can be replaced in tests
var createSyncer = func(config syncer.Config) syncer.Syncer {
	return syncer.NewSyncer(config)
}

// loadConfigAndValidate loads configuration from flags and environment variables
// and validates the configuration
func loadConfigAndValidate() (*syncer.Config, error) {
	// Get values from environment if not set via flags
	baseURL := *difyBaseURL
	if baseURL == "" {
		baseURL = os.Getenv("DIFY_BASE_URL")
	}

	// メールとパスワードは環境変数からのみ取得
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

	// Validate force direction if provided
	if *forceDirection != "" && *forceDirection != "upload" && *forceDirection != "download" {
		return nil, fmt.Errorf("invalid force direction '%s'. Must be 'upload', 'download', or empty", *forceDirection)
	}

	// Create syncer config
	config := &syncer.Config{
		DifyBaseURL:    baseURL,
		DifyEmail:      email,
		DifyPassword:   password,
		DSLDirectory:   dslDirPath,
		AppMapFile:     appMapPath,
		DryRun:         *dryRun,
		ForceDirection: *forceDirection,
		Verbose:        *verbose,
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
	} else if config.ForceDirection != "" {
		fmt.Printf("Mode: Force %s\n", config.ForceDirection)
	} else {
		fmt.Println("Mode: Bidirectional sync")
	}
	fmt.Println()
}

// printStats prints statistics about the sync operation
func printStats(stats *syncer.SyncStats, duration time.Duration) {
	fmt.Println("\nSync Summary:")
	fmt.Printf("Total apps: %d\n", stats.Total)
	fmt.Printf("Uploads: %d\n", stats.Uploads)
	fmt.Printf("Downloads: %d\n", stats.Downloads)
	fmt.Printf("No action (in sync): %d\n", stats.NoAction)
	fmt.Printf("Errors: %d\n", stats.Errors)
	fmt.Printf("Duration: %v\n", duration)
}

// runSync runs the sync operation
func runSync(config *syncer.Config) (int, error) {
	// Create syncer
	syncr := createSyncer(*config)

	// Print info
	printInfo(config)

	// Start sync
	fmt.Println("Starting sync...")
	startTime := time.Now()

	stats, err := syncr.SyncAll()
	if err != nil {
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

	// Load and validate configuration
	config, err := loadConfigAndValidate()
	if err != nil {
		fmt.Printf("Error: %v\n", err)
		os.Exit(1)
	}

	// Run sync
	exitCode, err := runSync(config)
	if err != nil {
		fmt.Printf("Error: %v\n", err)
		os.Exit(1)
	}

	os.Exit(exitCode)
}

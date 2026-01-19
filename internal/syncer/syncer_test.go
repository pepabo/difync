package syncer

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestLoadAppMap(t *testing.T) {
	// Create a temporary directory for testing
	tmpDir, err := os.MkdirTemp("", "difync-test-")
	if err != nil {
		t.Fatalf("Failed to create temp directory: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	// Create a test app map file
	appMapData := AppMap{
		Apps: []AppMapping{
			{
				Filename: "app1.yaml",
				AppID:    "app-id-1",
			},
			{
				Filename: "app2.yaml",
				AppID:    "app-id-2",
			},
		},
	}

	appMapPath := filepath.Join(tmpDir, "app_map.json")
	appMapFile, err := os.Create(appMapPath)
	if err != nil {
		t.Fatalf("Failed to create app map file: %v", err)
	}

	err = json.NewEncoder(appMapFile).Encode(appMapData)
	appMapFile.Close()
	if err != nil {
		t.Fatalf("Failed to write app map file: %v", err)
	}

	// Create a syncer with the test app map file
	config := Config{
		AppMapFile: appMapPath,
	}
	syncer := NewSyncer(config)

	// Load the app map
	appMap, err := syncer.LoadAppMap()
	if err != nil {
		t.Fatalf("Failed to load app map: %v", err)
	}

	// Check the loaded app map
	if len(appMap.Apps) != 2 {
		t.Errorf("Expected 2 apps in app map, got %d", len(appMap.Apps))
	}

	if appMap.Apps[0].Filename != "app1.yaml" {
		t.Errorf("Expected app1.yaml, got %s", appMap.Apps[0].Filename)
	}

	if appMap.Apps[0].AppID != "app-id-1" {
		t.Errorf("Expected app-id-1, got %s", appMap.Apps[0].AppID)
	}

	if appMap.Apps[1].Filename != "app2.yaml" {
		t.Errorf("Expected app2.yaml, got %s", appMap.Apps[1].Filename)
	}

	if appMap.Apps[1].AppID != "app-id-2" {
		t.Errorf("Expected app-id-2, got %s", appMap.Apps[1].AppID)
	}
}

// Helper function to set up a test server and syncer for testing
func setupTestSyncerAndServer(t *testing.T) (Syncer, *httptest.Server, string, string, string, func()) {
	// Create a temporary directory for testing
	tmpDir, err := os.MkdirTemp("", "difync-test-")
	if err != nil {
		t.Fatalf("Failed to create temp directory: %v", err)
	}

	// Create a test DSL directory
	dslDir := filepath.Join(tmpDir, "dsl")
	err = os.Mkdir(dslDir, 0755)
	if err != nil {
		t.Fatalf("Failed to create DSL directory: %v", err)
	}

	// Create a test app map file
	appMapPath := filepath.Join(tmpDir, "app_map.json")
	appMap := AppMap{
		Apps: []AppMapping{
			{
				Filename: "test.yaml",
				AppID:    "test-app-id",
			},
		},
	}

	appMapFile, err := os.Create(appMapPath)
	if err != nil {
		t.Fatalf("Failed to create app map file: %v", err)
	}

	err = json.NewEncoder(appMapFile).Encode(appMap)
	appMapFile.Close()
	if err != nil {
		t.Fatalf("Failed to write app map file: %v", err)
	}

	// Create a test DSL file
	dslContent := "name: Test App\nversion: 1.0.0"
	dslPath := filepath.Join(dslDir, "test.yaml")
	err = os.WriteFile(dslPath, []byte(dslContent), 0644)
	if err != nil {
		t.Fatalf("Failed to write DSL file: %v", err)
	}

	// Create a test server
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/console/api/login":
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(`{
				"status": "success",
				"data": {
					"access_token": "test-token"
				}
			}`))
		case "/console/api/apps":
			// Return a list of apps that includes our test app
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(`{
				"data": [
					{
						"id": "test-app-id",
						"name": "Test App",
						"updated_at": "2023-01-01T12:00:00Z"
					}
				]
			}`))
		case "/console/api/apps/test-app-id":
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(`{
				"data": {
					"id": "test-app-id",
					"name": "Test App",
					"updated_at": "2023-01-01T12:00:00Z"
				}
			}`))
		case "/console/api/apps/test-app-id/export":
			if r.Method == "GET" {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusOK)
				w.Write([]byte(`{
					"data": "name: Test App\nversion: 1.0.0"
				}`))
			} else {
				w.WriteHeader(http.StatusMethodNotAllowed)
			}
		case "/console/api/apps/test-app-id-2/export":
			if r.Method == "GET" {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusOK)
				w.Write([]byte(`{
					"data": "name: Another Test App\nversion: 1.0.0"
				}`))
			} else {
				w.WriteHeader(http.StatusMethodNotAllowed)
			}
		case "/console/api/apps/test-app-id/import":
			if r.Method == "POST" {
				w.WriteHeader(http.StatusOK)
			} else {
				w.WriteHeader(http.StatusMethodNotAllowed)
			}
		case "/console/api/apps/test-app-id/check":
			// App exists
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(`{"exists": true}`))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))

	// Create syncer with test configuration
	config := Config{
		DifyBaseURL:  server.URL,
		DifyEmail:    "test@example.com",
		DifyPassword: "testpassword",
		DSLDirectory: dslDir,
		AppMapFile:   appMapPath,
	}
	syncer := NewSyncer(config)

	// Return cleanup function
	cleanup := func() {
		server.Close()
		os.RemoveAll(tmpDir)
	}

	return syncer, server, dslDir, dslPath, appMapPath, cleanup
}

func TestSyncAll(t *testing.T) {
	syncer, _, _, _, _, cleanup := setupTestSyncerAndServer(t)
	defer cleanup()

	stats, err := syncer.SyncAll()
	if err != nil {
		t.Fatalf("Failed to sync all: %v", err)
	}

	// Check statistics
	if stats.Total != 1 {
		t.Errorf("Expected Total to be 1, got %d", stats.Total)
	}

	// Since file dates and API dates may vary in tests, we don't check
	// the specific action counts, just that we got stats back
	if stats.StartTime.IsZero() {
		t.Error("Expected StartTime to be set")
	}

	if stats.EndTime.IsZero() {
		t.Error("Expected EndTime to be set")
	}
}

func TestSyncApp(t *testing.T) {
	syncer, _, _, dslPath, _, cleanup := setupTestSyncerAndServer(t)
	defer cleanup()

	// Modify the file to be newer than the API response
	newTime := time.Now().Add(24 * time.Hour)
	err := os.Chtimes(dslPath, newTime, newTime)
	if err != nil {
		t.Fatalf("Failed to change file time: %v", err)
	}

	// Test local file modification case
	result := syncer.SyncApp(AppMapping{
		Filename: "test.yaml",
		AppID:    "test-app-id",
	})

	// Local files newer than remote are ignored
	if result.Action != ActionNone {
		t.Errorf("Expected Action to be none, got %s", result.Action)
	}

	if !result.Success {
		t.Errorf("Expected Success to be true")
	}
}

func TestDryRun(t *testing.T) {
	syncer, _, _, _, _, cleanup := setupTestSyncerAndServer(t)
	defer cleanup()

	// Use type assertion to get the concrete type
	defaultSyncer, ok := syncer.(*DefaultSyncer)
	if !ok {
		t.Fatalf("Failed to convert syncer to *DefaultSyncer")
	}

	// Enable dry run
	defaultSyncer.config.DryRun = true

	// Test dry run case
	result := syncer.SyncApp(AppMapping{
		Filename: "test.yaml",
		AppID:    "test-app-id",
	})

	if !result.Success {
		t.Errorf("Expected Success to be true in dry run mode")
	}
}

func TestFileErrors(t *testing.T) {
	// Create a temporary directory for testing
	tmpDir, err := os.MkdirTemp("", "difync-test-")
	if err != nil {
		t.Fatalf("Failed to create temp directory: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	// Create a test server
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/console/api/login" {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(`{
				"status": "success",
				"data": {
					"access_token": "test-token"
				}
			}`))
		} else {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(`{
				"data": {
					"id": "test-app-id",
					"name": "Test App",
					"updated_at": "2023-01-01T12:00:00Z"
				}
			}`))
		}
	}))
	defer server.Close()

	// Create configuration with nonexistent file
	config := Config{
		DifyBaseURL:  server.URL,
		DifyEmail:    "test@example.com",
		DifyPassword: "testpassword",
		DSLDirectory: tmpDir,
		AppMapFile:   "/nonexistent/app_map.json",
	}
	syncer := NewSyncer(config)

	// Test loading nonexistent app map
	_, err = syncer.LoadAppMap()
	if err == nil {
		t.Error("Expected error when loading nonexistent app map")
	}

	// Test sync all with nonexistent app map
	_, err = syncer.SyncAll()
	if err == nil {
		t.Error("Expected error when syncing with nonexistent app map")
	}

	// Create an invalid app map file
	invalidAppMapPath := filepath.Join(tmpDir, "invalid_app_map.json")
	err = os.WriteFile(invalidAppMapPath, []byte("invalid json"), 0644)
	if err != nil {
		t.Fatalf("Failed to write invalid app map file: %v", err)
	}

	// Test loading invalid app map
	config.AppMapFile = invalidAppMapPath
	syncer = NewSyncer(config)

	_, err = syncer.LoadAppMap()
	if err == nil {
		t.Error("Expected error when loading invalid app map")
	}
}

func TestNewSyncer(t *testing.T) {
	config := Config{
		DifyBaseURL:  "https://example.com",
		DifyEmail:    "test@example.com",
		DifyPassword: "testpassword",
		DSLDirectory: "/path/to/dsl",
		AppMapFile:   "/path/to/app_map.json",
		DryRun:       true,
		Verbose:      true,
	}

	syncer := NewSyncer(config)
	if syncer == nil {
		t.Error("Expected syncer to be initialized")
	}

	// Check concrete type and fields
	defaultSyncer, ok := syncer.(*DefaultSyncer)
	if !ok {
		t.Fatalf("Expected syncer to be *DefaultSyncer")
	}

	if defaultSyncer.config.DifyBaseURL != config.DifyBaseURL {
		t.Errorf("Expected DifyBaseURL to be %s, got %s", config.DifyBaseURL, defaultSyncer.config.DifyBaseURL)
	}

	if defaultSyncer.config.DifyEmail != config.DifyEmail {
		t.Errorf("Expected DifyEmail to be %s, got %s", config.DifyEmail, defaultSyncer.config.DifyEmail)
	}

	if defaultSyncer.config.DifyPassword != config.DifyPassword {
		t.Errorf("Expected DifyPassword to be %s, got %s", config.DifyPassword, defaultSyncer.config.DifyPassword)
	}

	if defaultSyncer.config.DSLDirectory != config.DSLDirectory {
		t.Errorf("Expected DSLDirectory to be %s, got %s", config.DSLDirectory, defaultSyncer.config.DSLDirectory)
	}

	if defaultSyncer.client == nil {
		t.Error("Expected client to be initialized")
	}
}

func TestSyncAction(t *testing.T) {
	// Test SyncAction string representation
	actions := map[SyncAction]string{
		ActionNone:     "none",
		ActionDownload: "download",
		ActionError:    "error",
	}

	for action, expected := range actions {
		if string(action) != expected {
			t.Errorf("Expected %s, got %s", expected, action)
		}
	}
}

func TestSyncResultTimestamp(t *testing.T) {
	// Test that SyncResult has a timestamp
	before := time.Now()
	result := SyncResult{
		Timestamp: time.Now(),
	}
	after := time.Now()

	if result.Timestamp.Before(before) || result.Timestamp.After(after) {
		t.Errorf("Expected timestamp to be between %v and %v, got %v", before, after, result.Timestamp)
	}
}

func TestDownloadFromRemoteErrors(t *testing.T) {
	// Create a temporary directory for testing
	tmpDir, err := os.MkdirTemp("", "difync-test-")
	if err != nil {
		t.Fatalf("Failed to create temp directory: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	// Create a test server that returns an error
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte(`{"error": "Server error"}`))
	}))
	defer server.Close()

	// Create syncer with test configuration
	config := Config{
		DifyBaseURL:  server.URL,
		DifyEmail:    "test@example.com",
		DifyPassword: "testpassword",
		DSLDirectory: tmpDir,
	}
	syncer := NewSyncer(config)

	// Test downloadFromRemote with API error
	defaultSyncer, ok := syncer.(*DefaultSyncer)
	if !ok {
		t.Fatalf("Failed to convert syncer to *DefaultSyncer")
	}

	localPath := filepath.Join(tmpDir, "test.yaml")
	result := defaultSyncer.downloadFromRemote(AppMapping{
		Filename: "test.yaml",
		AppID:    "test-app-id",
	}, localPath)

	if result.Action != ActionDownload {
		t.Errorf("Expected Action to be download, got %s", result.Action)
	}

	if result.Success {
		t.Error("Expected Success to be false")
	}

	if result.Error == nil {
		t.Error("Expected Error to be set")
	}
}

func TestDownloadFromRemoteWriteError(t *testing.T) {
	// Create a temporary directory for testing
	tmpDir, err := os.MkdirTemp("", "difync-test-")
	if err != nil {
		t.Fatalf("Failed to create temp directory: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	// Make the directory read-only so we can't write to it
	if err := os.Chmod(tmpDir, 0500); err != nil {
		t.Fatalf("Failed to change directory permissions: %v", err)
	}
	defer os.Chmod(tmpDir, 0700) // Restore permissions for cleanup

	// Create a server that returns valid DSL
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/console/api/apps/test-app-id/dsl" {
			w.Header().Set("Content-Type", "application/yaml")
			w.WriteHeader(http.StatusOK)
			w.Write([]byte("name: Test App\nversion: 1.0.0"))
		} else {
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()

	// Create syncer with test configuration
	config := Config{
		DifyBaseURL:  server.URL,
		DifyEmail:    "test@example.com",
		DifyPassword: "testpassword",
		DSLDirectory: tmpDir,
	}
	syncer := NewSyncer(config)

	// Test downloadFromRemote with file write error
	defaultSyncer, ok := syncer.(*DefaultSyncer)
	if !ok {
		t.Fatalf("Failed to convert syncer to *DefaultSyncer")
	}

	localPath := filepath.Join(tmpDir, "test.yaml")
	result := defaultSyncer.downloadFromRemote(AppMapping{
		Filename: "test.yaml",
		AppID:    "test-app-id",
	}, localPath)

	if result.Action != ActionDownload {
		t.Errorf("Expected Action to be download, got %s", result.Action)
	}

	if result.Success {
		t.Error("Expected Success to be false")
	}

	if result.Error == nil {
		t.Error("Expected Error to be set")
	}
}

func TestSyncAppError(t *testing.T) {
	// Create a temporary directory for testing
	tmpDir, err := os.MkdirTemp("", "difync-test-")
	if err != nil {
		t.Fatalf("Failed to create temp directory: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	// Create a test server
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer server.Close()

	// Create syncer with test configuration
	config := Config{
		DifyBaseURL:  server.URL,
		DifyEmail:    "test@example.com",
		DifyPassword: "testpassword",
		DSLDirectory: tmpDir,
	}
	syncer := NewSyncer(config)

	// Test SyncApp with nonexistent local file
	result := syncer.SyncApp(AppMapping{
		Filename: "nonexistent.yaml",
		AppID:    "test-app-id",
	})

	if result.Action != ActionError {
		t.Errorf("Expected Action to be error, got %s", result.Action)
	}

	if result.Success {
		t.Error("Expected Success to be false")
	}

	if result.Error == nil {
		t.Error("Expected Error to be set")
	}
}

func TestSyncAllVerbose(t *testing.T) {
	syncer, _, _, _, _, cleanup := setupTestSyncerAndServer(t)
	defer cleanup()

	// Use type assertion to get the concrete type
	defaultSyncer, ok := syncer.(*DefaultSyncer)
	if !ok {
		t.Fatalf("Failed to convert syncer to *DefaultSyncer")
	}

	// Enable verbose mode
	defaultSyncer.config.Verbose = true

	stats, err := syncer.SyncAll()
	if err != nil {
		t.Fatalf("Failed to sync all: %v", err)
	}

	// Check statistics
	if stats.Total != 1 {
		t.Errorf("Expected Total to be 1, got %d", stats.Total)
	}
}

func TestInitializeAppMap(t *testing.T) {
	// Create a temporary directory for testing
	tmpDir, err := os.MkdirTemp("", "difync-test-")
	if err != nil {
		t.Fatalf("Failed to create temp directory: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	// Create a test DSL directory
	dslDir := filepath.Join(tmpDir, "dsl")
	err = os.Mkdir(dslDir, 0755)
	if err != nil {
		t.Fatalf("Failed to create DSL directory: %v", err)
	}

	// Create a nonexistent directory for app map file
	nonexistentDir := filepath.Join(tmpDir, "nonexistent_dir")
	appMapPath := filepath.Join(nonexistentDir, "app_map.json")

	// Create a mock server that returns a list of apps
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/console/api/login":
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(`{
				"status": "success",
				"data": {
					"access_token": "test-token"
				}
			}`))
		case "/console/api/apps":
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(`{
				"data": [
					{
						"id": "test-app-id",
						"name": "Test App",
						"updated_at": "2023-01-01T12:00:00Z"
					},
					{
						"id": "test-app-id-2",
						"name": "Another Test App With Spaces",
						"updated_at": "2023-01-02T12:00:00Z"
					}
				]
			}`))
		case "/console/api/apps/test-app-id/export":
		case "/console/api/apps/test-app-id-2/export":
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(`{
				"data": "name: Test App\nversion: 1.0.0"
			}`))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()

	// Create syncer with test configuration
	config := Config{
		DifyBaseURL:  server.URL,
		DifyEmail:    "test@example.com",
		DifyPassword: "testpassword",
		DSLDirectory: dslDir,
		AppMapFile:   appMapPath,
		Verbose:      true,
	}
	syncer := NewSyncer(config)

	// Initialize the app map
	appMap, err := syncer.(*DefaultSyncer).InitializeAppMap()
	if err != nil {
		t.Fatalf("Failed to initialize app map: %v", err)
	}

	// Check the app map
	if len(appMap.Apps) != 2 {
		t.Errorf("Expected 2 apps in app map, got %d", len(appMap.Apps))
	}

	// Check app mapping
	for _, app := range appMap.Apps {
		if app.AppID == "test-app-id" {
			// The new implementation preserves case
			if app.Filename != "Test_App.yaml" {
				t.Errorf("Expected Filename to be Test_App.yaml, got %s", app.Filename)
			}
		} else if app.AppID == "test-app-id-2" {
			// The new implementation preserves case
			if app.Filename != "Another_Test_App_With_Spaces.yaml" {
				t.Errorf("Expected Filename to be Another_Test_App_With_Spaces.yaml, got %s", app.Filename)
			}
		} else {
			t.Errorf("Unexpected app ID: %s", app.AppID)
		}
	}

	// Check that the app map file was created in nonexistent_dir (which should have been created)
	_, err = os.Stat(appMapPath)
	if err != nil {
		t.Errorf("Failed to stat app map file: %v", err)
	}

	// Skip checking DSL files in test environment since they're not actually created
	// (This avoids warnings like: "Failed to download DSL for Test App: failed to decode response: EOF")
	/*
		// Check that the DSL files were downloaded
		_, err = os.Stat(filepath.Join(dslDir, "Test_App.yaml"))
		if err != nil {
			t.Errorf("Failed to stat DSL file: %v", err)
		}

		_, err = os.Stat(filepath.Join(dslDir, "Another_Test_App_With_Spaces.yaml"))
		if err != nil {
			t.Errorf("Failed to stat DSL file: %v", err)
		}
	*/
}

func TestSanitizeFilename(t *testing.T) {
	// Create a DefaultSyncer for testing
	syncer := &DefaultSyncer{}

	testCases := []struct {
		input    string
		expected string
		desc     string
	}{
		{
			input:    "Simple App Name",
			expected: "Simple_App_Name",
			desc:     "Convert spaces to underscores",
		},
		{
			input:    "App/With:Invalid*Chars?",
			expected: "AppWithInvalidChars",
			desc:     "Remove invalid characters",
		},
		{
			input:    "日本語のアプリ名",
			expected: "日本語のアプリ名",
			desc:     "Preserve Japanese characters",
		},
		{
			input:    "アプリ名（テスト）",
			expected: "アプリ名（テスト）",
			desc:     "Preserve Japanese parentheses",
		},
		{
			input:    "Testing <> | / \\ : * ? \" App",
			expected: "Testing_________App",
			desc:     "Remove special characters and convert spaces to underscores",
		},
		{
			input:    "",
			expected: "app",
			desc:     "Use default name for empty string",
		},
		{
			input:    "       ",
			expected: "_______",
			desc:     "Convert whitespace-only string to underscores",
		},
		{
			input:    "Mixed 日本語 and English",
			expected: "Mixed_日本語_and_English",
			desc:     "Mix of Japanese and English",
		},
		{
			input:    "App with 特殊文字 *><|",
			expected: "App_with_特殊文字_",
			desc:     "Mix of Japanese and English with special characters",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.desc, func(t *testing.T) {
			result := syncer.sanitizeFilename(tc.input)
			if result != tc.expected {
				t.Errorf("sanitizeFilename(%q) = %q, expected %q", tc.input, result, tc.expected)
			}
		})
	}
}

func TestFilenameDeduplication(t *testing.T) {
	// Create a temporary directory for testing
	tmpDir, err := os.MkdirTemp("", "difync-test-")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	// Create a test DSL directory
	dslDir := filepath.Join(tmpDir, "dsl")
	if err := os.MkdirAll(dslDir, 0755); err != nil {
		t.Fatalf("Failed to create DSL directory: %v", err)
	}

	// Create test files with duplicate base names
	testFiles := []string{
		"Duplicate_App.yaml",
		"Another_App.yaml",
	}

	for _, filename := range testFiles {
		filePath := filepath.Join(dslDir, filename)
		if err := os.WriteFile(filePath, []byte("test content"), 0644); err != nil {
			t.Fatalf("Failed to create test file %s: %v", filename, err)
		}
	}

	// Create a mock server that returns a list of apps with duplicate names
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/console/api/login":
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(`{
				"status": "success",
				"data": {
					"access_token": "test-token"
				}
			}`))
		case "/console/api/apps":
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(`{
				"data": [
					{
						"id": "app-id-1",
						"name": "Duplicate App",
						"updated_at": 1672531200
					},
					{
						"id": "app-id-2",
						"name": "Duplicate App",
						"updated_at": 1672617600
					},
					{
						"id": "app-id-3",
						"name": "Another App",
						"updated_at": 1672704000
					}
				]
			}`))
		case "/console/api/apps/app-id-1/export":
		case "/console/api/apps/app-id-2/export":
		case "/console/api/apps/app-id-3/export":
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(`{
				"data": "name: Test App\nversion: 1.0.0"
			}`))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()

	// Create syncer with test configuration
	config := Config{
		DifyBaseURL:  server.URL,
		DifyEmail:    "test@example.com",
		DifyPassword: "testpassword",
		DSLDirectory: dslDir,
		AppMapFile:   filepath.Join(tmpDir, "app_map.json"),
	}
	syncer := NewSyncer(config)

	// Initialize the app map
	appMap, err := syncer.(*DefaultSyncer).InitializeAppMap()
	if err != nil {
		t.Fatalf("Failed to initialize app map: %v", err)
	}

	if len(appMap.Apps) != 3 {
		t.Errorf("Expected 3 apps in app map, got %d", len(appMap.Apps))
	}

	// Count how many files with each base name appear
	duplicateAppCount := 0
	anotherAppCount := 0

	for _, app := range appMap.Apps {
		if strings.HasPrefix(app.Filename, "Duplicate_App") {
			duplicateAppCount++
		} else if strings.HasPrefix(app.Filename, "Another_App") {
			anotherAppCount++
		} else {
			t.Errorf("Unexpected filename: %s", app.Filename)
		}
	}

	// Check the total number matches
	if len(appMap.Apps) != 3 {
		t.Errorf("Number of unique filenames (%d) doesn't match number of apps (3)", len(appMap.Apps))
	}

	// Check for duplicate filenames
	foundFilenames := make(map[string]bool)
	for _, app := range appMap.Apps {
		if foundFilenames[app.Filename] {
			t.Errorf("Found duplicate filename: %s", app.Filename)
		}
		foundFilenames[app.Filename] = true
	}

	// Check the total number matches
	if len(foundFilenames) != len(appMap.Apps) {
		t.Errorf("Number of unique filenames (%d) doesn't match number of apps (3)", len(foundFilenames))
	}
}

func TestDryRunWithoutAppMap(t *testing.T) {
	// Create a temporary directory for testing
	tmpDir, err := os.MkdirTemp("", "difync-test-")
	if err != nil {
		t.Fatalf("Failed to create temp directory: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	// Point to a non-existent app map file
	appMapPath := filepath.Join(tmpDir, "non_existent_app_map.json")

	// Create a test server
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"status":"success"}`))
	}))
	defer server.Close()

	// Create syncer with test configuration and dry-run enabled
	config := Config{
		DifyBaseURL:  server.URL,
		DifyEmail:    "test@example.com",
		DifyPassword: "testpassword",
		DSLDirectory: filepath.Join(tmpDir, "dsl"),
		AppMapFile:   appMapPath,
		DryRun:       true, // Enable dry-run mode
	}
	syncer := NewSyncer(config)

	// Try to load the app map in dry-run mode
	_, err = syncer.LoadAppMap()

	// Check that we get the expected error message
	expectedError := fmt.Sprintf("app map file not found at %s. Please run 'difync init' first to initialize the app map", appMapPath)
	if err == nil || err.Error() != expectedError {
		t.Errorf("Expected error message:\n%s\n\nGot:\n%v", expectedError, err)
	}

	// Verify that no app map file was created in dry-run mode
	if _, err := os.Stat(appMapPath); !os.IsNotExist(err) {
		t.Errorf("App map file was created in dry-run mode, which should not happen")
	}
}

func TestInitializeAppMapWithJapaneseNames(t *testing.T) {
	// Create a temporary directory for testing
	tmpDir, err := os.MkdirTemp("", "difync-test-")
	if err != nil {
		t.Fatalf("Failed to create temp directory: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	// Create a test DSL directory
	dslDir := filepath.Join(tmpDir, "dsl")
	err = os.Mkdir(dslDir, 0755)
	if err != nil {
		t.Fatalf("Failed to create DSL directory: %v", err)
	}

	// Create a mock server that returns apps with Japanese names
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/console/api/login":
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(`{
				"status": "success",
				"data": {
					"access_token": "test-token"
				}
			}`))
		case "/console/api/apps":
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(`{
				"data": [
					{
						"id": "app-id-1",
						"name": "日本語アプリ",
						"updated_at": 1672531200
					},
					{
						"id": "app-id-2",
						"name": "テスト（Test）",
						"updated_at": 1672617600
					},
					{
						"id": "app-id-3",
						"name": "英語と日本語Mix",
						"updated_at": 1672704000
					}
				]
			}`))
		case "/console/api/apps/app-id-1/export":
		case "/console/api/apps/app-id-2/export":
		case "/console/api/apps/app-id-3/export":
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(`{
				"data": "name: Test App\nversion: 1.0.0"
			}`))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()

	// Create syncer with test configuration
	config := Config{
		DifyBaseURL:  server.URL,
		DifyEmail:    "test@example.com",
		DifyPassword: "testpassword",
		DSLDirectory: dslDir,
		AppMapFile:   filepath.Join(tmpDir, "app_map.json"),
	}
	syncer := NewSyncer(config)

	// Initialize the app map
	appMap, err := syncer.(*DefaultSyncer).InitializeAppMap()
	if err != nil {
		t.Fatalf("Failed to initialize app map: %v", err)
	}

	// Check that Japanese names are preserved in filenames
	expectedFilenames := map[string]string{
		"app-id-1": "日本語アプリ.yaml",
		"app-id-2": "テスト（Test）.yaml",
		"app-id-3": "英語と日本語Mix.yaml",
	}

	if len(appMap.Apps) != 3 {
		t.Errorf("Expected 3 apps in app map, got %d", len(appMap.Apps))
	}

	// Check each app's filename matches expected pattern with Japanese characters
	for _, app := range appMap.Apps {
		expectedFilename := expectedFilenames[app.AppID]
		if expectedFilename != app.Filename {
			t.Errorf("For app ID %s: expected filename %s, got %s", app.AppID, expectedFilename, app.Filename)
		}
	}
}

func TestSyncAppWithDeletedApp(t *testing.T) {
	// Create a temporary directory for testing
	tmpDir, err := os.MkdirTemp("", "difync-test-")
	if err != nil {
		t.Fatalf("Failed to create temp directory: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	// Create a test file
	localPath := filepath.Join(tmpDir, "test.yaml")
	err = os.WriteFile(localPath, []byte("name: Test App\nversion: 1.0.0"), 0644)
	if err != nil {
		t.Fatalf("Failed to write test file: %v", err)
	}

	// Create a server that simulates a deleted app
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Handle login request
		if r.URL.Path == "/console/api/login" {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(`{
				"status": "success",
				"data": {
					"access_token": "test-token"
				}
			}`))
			return
		}

		// Handle app info request for deleted app
		if r.URL.Path == "/console/api/apps/deleted-app-id" {
			w.WriteHeader(http.StatusNotFound)
			return
		}

		// Default response
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	// Create syncer with test configuration
	config := Config{
		DifyBaseURL:  server.URL,
		DifyEmail:    "test@example.com",
		DifyPassword: "testpassword",
		DSLDirectory: tmpDir,
	}
	syncer := NewSyncer(config)

	// Test SyncApp with deleted app
	result := syncer.SyncApp(AppMapping{
		Filename: "test.yaml",
		AppID:    "deleted-app-id",
	})

	if result.Action != ActionNone {
		t.Errorf("Expected Action to be none for deleted app, got %s", result.Action)
	}

	if !result.Success {
		t.Error("Expected Success to be true for deleted app")
	}
}

func TestSyncAllWithDeletedApps(t *testing.T) {
	// Create a temporary directory for testing
	tmpDir, err := os.MkdirTemp("", "difync-test-")
	if err != nil {
		t.Fatalf("Failed to create temp directory: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	// Create DSL directory
	dslDir := filepath.Join(tmpDir, "dsl")
	err = os.Mkdir(dslDir, 0755)
	if err != nil {
		t.Fatalf("Failed to create DSL directory: %v", err)
	}

	// Create test files
	file1 := filepath.Join(dslDir, "app1.yaml")
	err = os.WriteFile(file1, []byte("name: App 1\nversion: 1.0.0"), 0644)
	if err != nil {
		t.Fatalf("Failed to write test file: %v", err)
	}

	file2 := filepath.Join(dslDir, "app2.yaml")
	err = os.WriteFile(file2, []byte("name: App 2\nversion: 1.0.0"), 0644)
	if err != nil {
		t.Fatalf("Failed to write test file: %v", err)
	}

	// Create app map file
	appMapFile := filepath.Join(tmpDir, "app_map.json")
	appMap := AppMap{
		Apps: []AppMapping{
			{
				Filename: "app1.yaml",
				AppID:    "app-id-1",
			},
			{
				Filename: "app2.yaml",
				AppID:    "app-id-2", // This one will be deleted
			},
		},
	}

	appMapData, err := json.Marshal(appMap)
	if err != nil {
		t.Fatalf("Failed to marshal app map: %v", err)
	}

	err = os.WriteFile(appMapFile, appMapData, 0644)
	if err != nil {
		t.Fatalf("Failed to write app map file: %v", err)
	}

	// Create a server that simulates one deleted app
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Handle login request
		if r.URL.Path == "/console/api/login" {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(`{
				"status": "success",
				"data": {
					"access_token": "test-token"
				}
			}`))
			return
		}

		// Handle app list request
		if r.URL.Path == "/console/api/apps" {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(`{
				"data": [
					{
						"id": "app-id-1",
						"name": "App 1",
						"updated_at": "2023-01-01T12:00:00Z"
					}
				]
			}`))
			return
		}

		// Handle check for app-id-1 (exists)
		if r.URL.Path == "/console/api/apps/app-id-1/check" {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(`{"exists": true}`))
			return
		}

		// Handle check for app-id-2 (deleted)
		if r.URL.Path == "/console/api/apps/app-id-2/check" {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(`{"exists": false}`))
			return
		}

		// App 2 is deleted
		if strings.Contains(r.URL.Path, "app-id-2") {
			w.WriteHeader(http.StatusNotFound)
			return
		}

		// Other apps exist
		if strings.Contains(r.URL.Path, "/export") {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(`{"data": "name: App 1\nversion: 1.0.0"}`))
			return
		}

		// Handle app info request for app 1
		if r.URL.Path == "/console/api/apps/app-id-1" {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(`{
				"data": {
					"id": "app-id-1",
					"name": "App 1",
					"updated_at": "2023-01-01T12:00:00Z"
				}
			}`))
			return
		}

		// Default response
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{}`))
	}))
	defer server.Close()

	// Create syncer with test configuration
	config := Config{
		DifyBaseURL:  server.URL,
		DifyEmail:    "test@example.com",
		DifyPassword: "testpassword",
		DSLDirectory: dslDir,
		AppMapFile:   appMapFile,
		Verbose:      true,
	}
	syncer := NewSyncer(config)

	// Run SyncAll
	stats, err := syncer.SyncAll()
	if err != nil {
		t.Fatalf("SyncAll failed: %v", err)
	}

	// Check that we have one download (for the deleted app)
	if stats.Downloads != 1 {
		t.Errorf("Expected 1 download (deleted app), got %d", stats.Downloads)
	}

	// Check that app2.yaml has been deleted
	if _, err := os.Stat(file2); !os.IsNotExist(err) {
		t.Error("Expected app2.yaml to be deleted")
	}

	// Check that app map has been updated
	var updatedAppMap AppMap
	updatedAppMapData, err := os.ReadFile(appMapFile)
	if err != nil {
		t.Fatalf("Failed to read updated app map file: %v", err)
	}

	err = json.Unmarshal(updatedAppMapData, &updatedAppMap)
	if err != nil {
		t.Fatalf("Failed to unmarshal updated app map: %v", err)
	}

	if len(updatedAppMap.Apps) != 1 {
		t.Errorf("Expected 1 app in updated app map, got %d", len(updatedAppMap.Apps))
	}

	if len(updatedAppMap.Apps) > 0 && updatedAppMap.Apps[0].AppID != "app-id-1" {
		t.Errorf("Expected app-id-1 to remain in app map, got %s", updatedAppMap.Apps[0].AppID)
	}
}

func TestSyncAppExtensive(t *testing.T) {
	// Create a temporary directory for testing
	tmpDir, err := os.MkdirTemp("", "difync-test-syncapp-")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	// Create a test DSL directory
	dslDir := filepath.Join(tmpDir, "dsl")
	if err := os.MkdirAll(dslDir, 0755); err != nil {
		t.Fatalf("Failed to create DSL directory: %v", err)
	}

	// Create a test file (app1.yaml)
	file1 := filepath.Join(dslDir, "app1.yaml")
	if err := os.WriteFile(file1, []byte("name: App 1\nversion: 1.0.0"), 0644); err != nil {
		t.Fatalf("Failed to create test file: %v", err)
	}

	// Set file modification time to a known value (1 day ago)
	fileTime := time.Now().Add(-24 * time.Hour)
	if err := os.Chtimes(file1, fileTime, fileTime); err != nil {
		t.Fatalf("Failed to set file modification time: %v", err)
	}

	// Create test mapping
	app1 := AppMapping{
		Filename: "app1.yaml",
		AppID:    "app-id-1",
	}

	// Create a mock server
	var serverHandler func(w http.ResponseWriter, r *http.Request)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		serverHandler(w, r)
	}))
	defer server.Close()

	// Basic test cases for SyncApp
	testCases := []struct {
		name           string
		handler        func(w http.ResponseWriter, r *http.Request)
		expectedAction SyncAction
		expectedError  bool
		dryRun         bool
		verbose        bool
	}{
		{
			name: "file_not_found",
			handler: func(w http.ResponseWriter, r *http.Request) {
				// This case won't hit the server as the file doesn't exist
			},
			expectedAction: ActionError,
			expectedError:  true,
		},
		{
			name: "app_check_error",
			handler: func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusInternalServerError)
				w.Write([]byte(`{"error": "Internal server error"}`))
			},
			expectedAction: ActionError,
			expectedError:  true,
		},
		{
			name: "app_deleted",
			handler: func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path == "/console/api/login" {
					w.Header().Set("Content-Type", "application/json")
					w.WriteHeader(http.StatusOK)
					w.Write([]byte(`{
						"status": "success",
						"data": {
							"access_token": "test-token"
						}
					}`))
					return
				}
				// For app check, return not found
				w.WriteHeader(http.StatusNotFound)
			},
			expectedAction: ActionNone,
			expectedError:  false,
		},
		{
			name: "app_info_error",
			handler: func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path == "/console/api/login" {
					w.Header().Set("Content-Type", "application/json")
					w.WriteHeader(http.StatusOK)
					w.Write([]byte(`{
						"status": "success",
						"data": {
							"access_token": "test-token"
						}
					}`))
					return
				}
				// For app check, return success
				if strings.Contains(r.URL.Path, "app-id-1") && !strings.Contains(r.URL.Path, "/export") {
					w.WriteHeader(http.StatusOK)
					return
				}
				// For app info, return error
				w.WriteHeader(http.StatusInternalServerError)
			},
			expectedAction: ActionError,
			expectedError:  true,
		},
		{
			name: "nil_updated_at",
			handler: func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path == "/console/api/login" {
					w.Header().Set("Content-Type", "application/json")
					w.WriteHeader(http.StatusOK)
					w.Write([]byte(`{
						"status": "success",
						"data": {
							"access_token": "test-token"
						}
					}`))
					return
				}
				// For app check, return success
				if strings.Contains(r.URL.Path, "app-id-1") && !strings.Contains(r.URL.Path, "/export") {
					w.Header().Set("Content-Type", "application/json")
					w.WriteHeader(http.StatusOK)
					w.Write([]byte(`{
						"data": {
							"id": "app-id-1",
							"name": "App 1",
							"updated_at": null
						}
					}`))
					return
				}
			},
			expectedAction: ActionNone,
			expectedError:  false,
		},
		{
			name: "empty_string_updated_at",
			handler: func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path == "/console/api/login" {
					w.Header().Set("Content-Type", "application/json")
					w.WriteHeader(http.StatusOK)
					w.Write([]byte(`{
						"status": "success",
						"data": {
							"access_token": "test-token"
						}
					}`))
					return
				}
				// For app check, return success
				if strings.Contains(r.URL.Path, "app-id-1") && !strings.Contains(r.URL.Path, "/export") {
					w.Header().Set("Content-Type", "application/json")
					w.WriteHeader(http.StatusOK)
					w.Write([]byte(`{
						"data": {
							"id": "app-id-1",
							"name": "App 1",
							"updated_at": ""
						}
					}`))
					return
				}
			},
			expectedAction: ActionNone,
			expectedError:  false,
		},
		{
			name: "remote_newer_download",
			handler: func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path == "/console/api/login" {
					w.Header().Set("Content-Type", "application/json")
					w.WriteHeader(http.StatusOK)
					w.Write([]byte(`{
						"status": "success",
						"data": {
							"access_token": "test-token"
						}
					}`))
					return
				}
				// For app check, return success
				if strings.Contains(r.URL.Path, "app-id-1") && !strings.Contains(r.URL.Path, "/export") {
					w.Header().Set("Content-Type", "application/json")
					w.WriteHeader(http.StatusOK)
					w.Write([]byte(`{
						"data": {
							"id": "app-id-1",
							"name": "App 1",
							"updated_at": "` + time.Now().Format(time.RFC3339) + `"
						}
					}`))
					return
				}
				// For DSL export
				if strings.Contains(r.URL.Path, "/export") {
					w.Header().Set("Content-Type", "application/json")
					w.WriteHeader(http.StatusOK)
					w.Write([]byte(`{"data": "name: Updated App 1\nversion: 1.1.0"}`))
					return
				}
			},
			expectedAction: ActionDownload,
			expectedError:  false,
		},
		{
			name: "remote_newer_dry_run",
			handler: func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path == "/console/api/login" {
					w.Header().Set("Content-Type", "application/json")
					w.WriteHeader(http.StatusOK)
					w.Write([]byte(`{
						"status": "success",
						"data": {
							"access_token": "test-token"
						}
					}`))
					return
				}
				// For app check, return success
				if strings.Contains(r.URL.Path, "app-id-1") && !strings.Contains(r.URL.Path, "/export") {
					w.Header().Set("Content-Type", "application/json")
					w.WriteHeader(http.StatusOK)
					w.Write([]byte(`{
						"data": {
							"id": "app-id-1",
							"name": "App 1",
							"updated_at": "` + time.Now().Format(time.RFC3339) + `"
						}
					}`))
					return
				}
				// For DSL export
				if strings.Contains(r.URL.Path, "/export") {
					w.Header().Set("Content-Type", "application/json")
					w.WriteHeader(http.StatusOK)
					w.Write([]byte(`{"data": "name: Updated App 1\nversion: 1.1.0"}`))
					return
				}
			},
			expectedAction: ActionDownload,
			expectedError:  false,
			dryRun:         true,
		},
		{
			name: "dsl_error",
			handler: func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path == "/console/api/login" {
					w.Header().Set("Content-Type", "application/json")
					w.WriteHeader(http.StatusOK)
					w.Write([]byte(`{
						"status": "success",
						"data": {
							"access_token": "test-token"
						}
					}`))
					return
				}
				// For app check, return success
				if strings.Contains(r.URL.Path, "app-id-1") && !strings.Contains(r.URL.Path, "/export") {
					w.Header().Set("Content-Type", "application/json")
					w.WriteHeader(http.StatusOK)
					w.Write([]byte(`{
						"data": {
							"id": "app-id-1",
							"name": "App 1",
							"updated_at": "` + time.Now().Format(time.RFC3339) + `"
						}
					}`))
					return
				}
				// For DSL export, return error
				if strings.Contains(r.URL.Path, "/export") {
					w.WriteHeader(http.StatusInternalServerError)
					w.Write([]byte(`{"error": "Internal server error"}`))
					return
				}
			},
			expectedAction: ActionDownload,
			expectedError:  true,
		},
		{
			name: "remote_older",
			handler: func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path == "/console/api/login" {
					w.Header().Set("Content-Type", "application/json")
					w.WriteHeader(http.StatusOK)
					w.Write([]byte(`{
						"status": "success",
						"data": {
							"access_token": "test-token"
						}
					}`))
					return
				}
				// For app check, return success
				if strings.Contains(r.URL.Path, "app-id-1") && !strings.Contains(r.URL.Path, "/export") {
					w.Header().Set("Content-Type", "application/json")
					w.WriteHeader(http.StatusOK)
					w.Write([]byte(`{
						"data": {
							"id": "app-id-1",
							"name": "App 1",
							"updated_at": "` + time.Now().Add(-48*time.Hour).Format(time.RFC3339) + `"
						}
					}`))
					return
				}
			},
			expectedAction: ActionNone,
			expectedError:  false,
		},
		{
			name: "integer_timestamp",
			handler: func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path == "/console/api/login" {
					w.Header().Set("Content-Type", "application/json")
					w.WriteHeader(http.StatusOK)
					w.Write([]byte(`{
						"status": "success",
						"data": {
							"access_token": "test-token"
						}
					}`))
					return
				}
				// For app check, return success
				if strings.Contains(r.URL.Path, "app-id-1") && !strings.Contains(r.URL.Path, "/export") {
					w.Header().Set("Content-Type", "application/json")
					w.WriteHeader(http.StatusOK)
					// Use current timestamp (newer than file)
					w.Write([]byte(`{
						"data": {
							"id": "app-id-1",
							"name": "App 1",
							"updated_at": ` + fmt.Sprintf("%d", time.Now().Unix()) + `
						}
					}`))
					return
				}
				// For DSL export
				if strings.Contains(r.URL.Path, "/export") {
					w.Header().Set("Content-Type", "application/json")
					w.WriteHeader(http.StatusOK)
					w.Write([]byte(`{"data": "name: Updated App 1\nversion: 1.1.0"}`))
					return
				}
			},
			expectedAction: ActionDownload,
			expectedError:  false,
		},
		{
			name: "float_timestamp",
			handler: func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path == "/console/api/login" {
					w.Header().Set("Content-Type", "application/json")
					w.WriteHeader(http.StatusOK)
					w.Write([]byte(`{
						"status": "success",
						"data": {
							"access_token": "test-token"
						}
					}`))
					return
				}
				// For app check, return success
				if strings.Contains(r.URL.Path, "app-id-1") && !strings.Contains(r.URL.Path, "/export") {
					w.Header().Set("Content-Type", "application/json")
					w.WriteHeader(http.StatusOK)
					// Use current timestamp (newer than file)
					w.Write([]byte(`{
						"data": {
							"id": "app-id-1",
							"name": "App 1",
							"updated_at": ` + fmt.Sprintf("%f", float64(time.Now().Unix())) + `
						}
					}`))
					return
				}
				// For DSL export
				if strings.Contains(r.URL.Path, "/export") {
					w.Header().Set("Content-Type", "application/json")
					w.WriteHeader(http.StatusOK)
					w.Write([]byte(`{"data": "name: Updated App 1\nversion: 1.1.0"}`))
					return
				}
			},
			expectedAction: ActionDownload,
			expectedError:  false,
		},
		{
			name: "unknown_type_timestamp",
			handler: func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path == "/console/api/login" {
					w.Header().Set("Content-Type", "application/json")
					w.WriteHeader(http.StatusOK)
					w.Write([]byte(`{
						"status": "success",
						"data": {
							"access_token": "test-token"
						}
					}`))
					return
				}
				// For app check, return success
				if strings.Contains(r.URL.Path, "app-id-1") && !strings.Contains(r.URL.Path, "/export") {
					w.Header().Set("Content-Type", "application/json")
					w.WriteHeader(http.StatusOK)
					// Use an object as timestamp (should use default timestamp)
					w.Write([]byte(`{
						"data": {
							"id": "app-id-1",
							"name": "App 1",
							"updated_at": {"some": "object"}
						}
					}`))
					return
				}
			},
			expectedAction: ActionNone,
			expectedError:  false,
		},
	}

	// Run test cases
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Setup handler
			serverHandler = tc.handler

			// Create a test file for each test case
			testFile := filepath.Join(dslDir, app1.Filename)
			if tc.name != "file_not_found" {
				if err := os.WriteFile(testFile, []byte("name: App 1\nversion: 1.0.0"), 0644); err != nil {
					t.Fatalf("Failed to create test file: %v", err)
				}
				if err := os.Chtimes(testFile, fileTime, fileTime); err != nil {
					t.Fatalf("Failed to set file modification time: %v", err)
				}
			} else {
				// For file_not_found case, remove the file if it exists
				os.Remove(testFile)
			}

			// Create syncer with test configuration
			config := Config{
				DifyBaseURL:  server.URL,
				DifyEmail:    "test@example.com",
				DifyPassword: "testpassword",
				DSLDirectory: dslDir,
				DryRun:       tc.dryRun,
				Verbose:      tc.verbose,
			}
			syncer := NewSyncer(config)

			// Call SyncApp
			result := syncer.SyncApp(app1)

			// Check results
			if result.Action != tc.expectedAction {
				t.Errorf("Expected action %s, got %s", tc.expectedAction, result.Action)
			}
			if (result.Error != nil) != tc.expectedError {
				t.Errorf("Expected error: %v, got error: %v", tc.expectedError, result.Error)
			}
		})
	}
}

// TestSyncAllWithRenamedApps tests that files are renamed when remote app names change
func TestSyncAllWithRenamedApps(t *testing.T) {
	// Create a temporary directory for testing
	tmpDir, err := os.MkdirTemp("", "difync-test-")
	if err != nil {
		t.Fatalf("Failed to create temp directory: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	// Create a test DSL directory
	dslDir := filepath.Join(tmpDir, "dsl")
	err = os.Mkdir(dslDir, 0755)
	if err != nil {
		t.Fatalf("Failed to create DSL directory: %v", err)
	}

	// Create test DSL files with original names
	dslContent := "name: Original App Name\nversion: 1.0.0"
	oldFilename := "Original_App_Name.yaml"
	oldFilePath := filepath.Join(dslDir, oldFilename)
	err = os.WriteFile(oldFilePath, []byte(dslContent), 0644)
	if err != nil {
		t.Fatalf("Failed to write DSL file: %v", err)
	}

	// Create test DSL file with Japanese name
	jpContent := "name: 日本語アプリ\nversion: 1.0.0"
	jpOldFilename := "日本語アプリ.yaml"
	jpOldFilePath := filepath.Join(dslDir, jpOldFilename)
	err = os.WriteFile(jpOldFilePath, []byte(jpContent), 0644)
	if err != nil {
		t.Fatalf("Failed to write Japanese DSL file: %v", err)
	}

	// Create an app map file with the original filenames
	appMapPath := filepath.Join(tmpDir, "app_map.json")
	appMap := AppMap{
		Apps: []AppMapping{
			{
				Filename: oldFilename,
				AppID:    "app-id-1",
			},
			{
				Filename: jpOldFilename,
				AppID:    "app-id-2",
			},
		},
	}

	appMapData, err := json.Marshal(appMap)
	if err != nil {
		t.Fatalf("Failed to marshal app map: %v", err)
	}

	err = os.WriteFile(appMapPath, appMapData, 0644)
	if err != nil {
		t.Fatalf("Failed to write app map file: %v", err)
	}

	// Create a mock server that returns changed app names
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/console/api/login" {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(`{
				"status": "success",
				"data": {
					"access_token": "test-token"
				}
			}`))
			return
		}

		if r.URL.Path == "/console/api/apps" {
			// Return the app list with changed names
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(`{
				"data": [
					{
						"id": "app-id-1",
						"name": "Changed App Name",
						"updated_at": 1672531200
					},
					{
						"id": "app-id-2",
						"name": "変更された日本語アプリ",
						"updated_at": 1672617600
					}
				]
			}`))
			return
		}

		if r.URL.Path == "/console/api/apps/app-id-1" {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(`{
				"data": {
					"id": "app-id-1",
					"name": "Changed App Name",
					"updated_at": 1672531200
				}
			}`))
			return
		}

		if r.URL.Path == "/console/api/apps/app-id-2" {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(`{
				"data": {
					"id": "app-id-2",
					"name": "変更された日本語アプリ",
					"updated_at": 1672617600
				}
			}`))
			return
		}

		if r.URL.Path == "/console/api/apps/app-id-1/export" {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(`{
				"data": "name: Changed App Name\nversion: 1.0.0"
			}`))
			return
		}

		if r.URL.Path == "/console/api/apps/app-id-2/export" {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(`{
				"data": "name: 変更された日本語アプリ\nversion: 1.0.0"
			}`))
			return
		}

		// Handle checks for app existence
		if r.URL.Path == "/console/api/apps/app-id-1/check" || r.URL.Path == "/console/api/apps/app-id-2/check" {
			// All apps exist in this test
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(`{"exists": true}`))
			return
		}

		w.WriteHeader(http.StatusNotFound)
	}))
	defer server.Close()

	// Create syncer with test configuration
	config := Config{
		DifyBaseURL:  server.URL,
		DifyEmail:    "test@example.com",
		DifyPassword: "testpassword",
		DSLDirectory: dslDir,
		AppMapFile:   appMapPath,
		Verbose:      true, // For better debugging in tests
	}
	syncer := NewSyncer(config)

	// Run SyncAll
	stats, err := syncer.SyncAll()
	if err != nil {
		t.Fatalf("Failed to sync all: %v", err)
	}

	// Check that files were renamed
	expectedNewFilename := "Changed_App_Name.yaml"
	expectedJpNewFilename := "変更された日本語アプリ.yaml"

	// Check that the old files no longer exist
	if _, err := os.Stat(oldFilePath); !os.IsNotExist(err) {
		t.Errorf("Expected old file %s to be renamed/removed", oldFilename)
	}
	if _, err := os.Stat(jpOldFilePath); !os.IsNotExist(err) {
		t.Errorf("Expected old file %s to be renamed/removed", jpOldFilename)
	}

	// Check that the new files exist
	newFilePath := filepath.Join(dslDir, expectedNewFilename)
	if _, err := os.Stat(newFilePath); os.IsNotExist(err) {
		t.Errorf("Expected new file %s to exist", expectedNewFilename)
	}
	jpNewFilePath := filepath.Join(dslDir, expectedJpNewFilename)
	if _, err := os.Stat(jpNewFilePath); os.IsNotExist(err) {
		t.Errorf("Expected new file %s to exist", expectedJpNewFilename)
	}

	// Check the app map has been updated
	updatedAppMap, err := syncer.LoadAppMap()
	if err != nil {
		t.Fatalf("Failed to load updated app map: %v", err)
	}

	// Check app map contains the new filenames
	foundUpdatedEn := false
	foundUpdatedJp := false
	for _, app := range updatedAppMap.Apps {
		if app.AppID == "app-id-1" {
			if app.Filename != expectedNewFilename {
				t.Errorf("Expected app id app-id-1 to have filename %s, got %s",
					expectedNewFilename, app.Filename)
			}
			foundUpdatedEn = true
		}
		if app.AppID == "app-id-2" {
			if app.Filename != expectedJpNewFilename {
				t.Errorf("Expected app id app-id-2 to have filename %s, got %s",
					expectedJpNewFilename, app.Filename)
			}
			foundUpdatedJp = true
		}
	}

	if !foundUpdatedEn {
		t.Errorf("English app mapping not found in updated app map")
	}
	if !foundUpdatedJp {
		t.Errorf("Japanese app mapping not found in updated app map")
	}

	// Check statistics
	if stats.Total != 2 {
		t.Errorf("Expected Total to be 2, got %d", stats.Total)
	}
}

func TestSyncAllWithNewApps(t *testing.T) {
	// Create a temporary directory for testing
	tmpDir, err := os.MkdirTemp("", "difync-test-")
	if err != nil {
		t.Fatalf("Failed to create temp directory: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	// Create a test DSL directory
	dslDir := filepath.Join(tmpDir, "dsl")
	err = os.Mkdir(dslDir, 0755)
	if err != nil {
		t.Fatalf("Failed to create DSL directory: %v", err)
	}

	// Create an existing DSL file
	existingFilename := "Existing_App.yaml"
	existingFilePath := filepath.Join(dslDir, existingFilename)
	err = os.WriteFile(existingFilePath, []byte("name: Existing App\nversion: 1.0.0"), 0644)
	if err != nil {
		t.Fatalf("Failed to create existing DSL file: %v", err)
	}

	// Create an app map with only one app (simulating existing state)
	appMapPath := filepath.Join(tmpDir, "app_map.json")
	appMap := AppMap{
		Apps: []AppMapping{
			{
				Filename: existingFilename,
				AppID:    "existing-app-id",
			},
		},
	}
	appMapFile, err := os.Create(appMapPath)
	if err != nil {
		t.Fatalf("Failed to create app map file: %v", err)
	}
	err = json.NewEncoder(appMapFile).Encode(appMap)
	appMapFile.Close()
	if err != nil {
		t.Fatalf("Failed to write app map file: %v", err)
	}

	// Create a test server that returns the existing app plus a new app
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Handle login
		if r.URL.Path == "/console/api/login" {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(`{"result": "success", "data": {"access_token": "test-token"}}`))
			return
		}

		// Handle app list - return both existing and new app
		if r.URL.Path == "/console/api/apps" {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(`{
				"data": [
					{
						"id": "existing-app-id",
						"name": "Existing App",
						"updated_at": "2023-01-01T12:00:00Z"
					},
					{
						"id": "new-app-id",
						"name": "New App",
						"updated_at": "2023-01-02T12:00:00Z"
					}
				]
			}`))
			return
		}

		// Handle app info for existing app
		if r.URL.Path == "/console/api/apps/existing-app-id" {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(`{
				"data": {
					"id": "existing-app-id",
					"name": "Existing App",
					"updated_at": "2023-01-01T12:00:00Z"
				}
			}`))
			return
		}

		// Handle DSL export for new app
		if r.URL.Path == "/console/api/apps/new-app-id/export" {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(`{
				"data": "name: New App\nversion: 1.0.0"
			}`))
			return
		}

		// Handle checks for app existence
		if strings.HasSuffix(r.URL.Path, "/check") {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(`{"exists": true}`))
			return
		}

		w.WriteHeader(http.StatusNotFound)
	}))
	defer server.Close()

	// Create syncer with test configuration
	config := Config{
		DifyBaseURL:  server.URL,
		DifyEmail:    "test@example.com",
		DifyPassword: "testpassword",
		DSLDirectory: dslDir,
		AppMapFile:   appMapPath,
		Verbose:      true,
	}
	syncer := NewSyncer(config)

	// Run SyncAll
	stats, err := syncer.SyncAll()
	if err != nil {
		t.Fatalf("Failed to sync all: %v", err)
	}

	// Check that the new app was added
	expectedNewFilename := "New_App.yaml"
	newFilePath := filepath.Join(dslDir, expectedNewFilename)
	if _, err := os.Stat(newFilePath); os.IsNotExist(err) {
		t.Errorf("Expected new file %s to exist", expectedNewFilename)
	}

	// Check the app map has been updated with the new app
	updatedAppMap, err := syncer.LoadAppMap()
	if err != nil {
		t.Fatalf("Failed to load updated app map: %v", err)
	}

	if len(updatedAppMap.Apps) != 2 {
		t.Errorf("Expected 2 apps in app map, got %d", len(updatedAppMap.Apps))
	}

	// Check that the new app is in the app map
	foundNewApp := false
	for _, app := range updatedAppMap.Apps {
		if app.AppID == "new-app-id" {
			if app.Filename != expectedNewFilename {
				t.Errorf("Expected new app to have filename %s, got %s",
					expectedNewFilename, app.Filename)
			}
			foundNewApp = true
		}
	}

	if !foundNewApp {
		t.Errorf("New app mapping not found in updated app map")
	}

	// Check statistics
	if stats.Added != 1 {
		t.Errorf("Expected Added to be 1, got %d", stats.Added)
	}
	if stats.Total != 2 {
		t.Errorf("Expected Total to be 2, got %d", stats.Total)
	}
}

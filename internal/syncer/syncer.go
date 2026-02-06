package syncer

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
	"unicode"

	"github.com/pepabo/difync/internal/api"
)

// Syncer defines the interface for syncing between local DSL files and Dify
type Syncer interface {
	LoadAppMap() (*AppMap, error)
	SyncAll() (*SyncStats, error)
	SyncApp(app AppMapping) SyncResult
}

// Config represents the configuration for the syncer
type Config struct {
	DifyBaseURL  string
	DifyEmail    string
	DifyPassword string
	DSLDirectory string
	AppMapFile   string
	DryRun       bool
	Verbose      bool
}

// DefaultSyncer handles the synchronization between local DSL files and Dify
type DefaultSyncer struct {
	config Config
	client *api.Client
}

// NewSyncer creates a new syncer with the given configuration
func NewSyncer(config Config) Syncer {
	client := api.NewClient(config.DifyBaseURL)
	client.Verbose = config.Verbose

	// Login to get token
	if err := client.Login(config.DifyEmail, config.DifyPassword); err != nil {
		// Log the error if login fails
		fmt.Printf("Failed to login to Dify API: %v\n", err)
	}

	return &DefaultSyncer{
		config: config,
		client: client,
	}
}

// LoadAppMap loads the app map from the app map file
func (s *DefaultSyncer) LoadAppMap() (*AppMap, error) {
	// Check if app map file exists
	_, err := os.Stat(s.config.AppMapFile)
	if os.IsNotExist(err) {
		// If the file doesn't exist, prompt for initialization regardless of dry-run mode
		return nil, fmt.Errorf("app map file not found at %s. Please run 'difync init' first to initialize the app map", s.config.AppMapFile)
	}

	file, err := os.Open(s.config.AppMapFile)
	if err != nil {
		return nil, fmt.Errorf("failed to open app map file: %w", err)
	}
	defer file.Close()

	var appMap AppMap
	if err := json.NewDecoder(file).Decode(&appMap); err != nil {
		return nil, fmt.Errorf("failed to decode app map: %w", err)
	}

	return &appMap, nil
}

// InitializeAppMap creates a new app map file by fetching app list from Dify API
func (s *DefaultSyncer) InitializeAppMap() (*AppMap, error) {
	// Fetch application list from API
	appList, err := s.client.GetAppList()
	if err != nil {
		return nil, fmt.Errorf("failed to get app list from API: %w", err)
	}

	if len(appList) == 0 {
		return nil, fmt.Errorf("no applications found in Dify account")
	}

	// Create DSL directory and its parent directories if they don't exist
	if err := os.MkdirAll(s.config.DSLDirectory, 0755); err != nil {
		return nil, fmt.Errorf("failed to create DSL directory: %w", err)
	}

	// Create app map directory and its parent directories if they don't exist
	appMapDir := filepath.Dir(s.config.AppMapFile)
	if err := os.MkdirAll(appMapDir, 0755); err != nil {
		return nil, fmt.Errorf("failed to create directory for app map file: %w", err)
	}

	// Create app map
	appMap := &AppMap{
		Apps: make([]AppMapping, 0, len(appList)),
	}

	// Map to track used filenames to avoid duplicates
	usedFilenames := make(map[string]bool)

	// For each app, add an entry to the app map
	for _, app := range appList {
		// Generate unique filename using shared helper
		filename := s.generateUniqueFilename(app.Name, usedFilenames)

		// Record the filename as used
		usedFilenames[filename] = true

		appMap.Apps = append(appMap.Apps, AppMapping{
			Filename: filename,
			AppID:    app.ID,
		})

		// Also download the DSL for this app if it doesn't exist yet
		localPath := filepath.Join(s.config.DSLDirectory, filename)
		if _, err := os.Stat(localPath); os.IsNotExist(err) {
			if s.config.Verbose {
				fmt.Printf("Downloading initial DSL for %s to %s\n", app.Name, localPath)
			}

			dsl, err := s.client.GetDSL(app.ID)
			if err != nil {
				fmt.Printf("Warning: Failed to download DSL for %s: %v\n", app.Name, err)
				continue
			}

			if !s.config.DryRun {
				if err := os.WriteFile(localPath, dsl, 0644); err != nil {
					fmt.Printf("Warning: Failed to write DSL file for %s: %v\n", app.Name, err)
				}
			}
		}
	}

	// Write the app map to file
	if !s.config.DryRun {
		file, err := os.Create(s.config.AppMapFile)
		if err != nil {
			return nil, fmt.Errorf("failed to create app map file: %w", err)
		}
		defer file.Close()

		encoder := json.NewEncoder(file)
		encoder.SetIndent("", "  ")
		if err := encoder.Encode(appMap); err != nil {
			return nil, fmt.Errorf("failed to write app map file: %w", err)
		}

		fmt.Printf("Created new app map file at %s with %d applications\n", s.config.AppMapFile, len(appMap.Apps))
	} else {
		fmt.Printf("Dry run: Would create app map file at %s with %d applications\n", s.config.AppMapFile, len(appMap.Apps))
	}

	return appMap, nil
}

// fileExists checks if a file exists
func (s *DefaultSyncer) fileExists(path string) bool {
	_, err := os.Stat(path)
	return !os.IsNotExist(err)
}

// generateUniqueFilename generates a unique filename for an app, avoiding duplicates
func (s *DefaultSyncer) generateUniqueFilename(appName string, usedFilenames map[string]bool) string {
	safeName := s.sanitizeFilename(appName)
	if s.config.Verbose {
		fmt.Printf("Debug - sanitizeFilename(%q) = %q\n", appName, safeName)
	}
	filename := safeName + ".yaml"

	// Check if file exists in filesystem or already used in map
	fileExists := s.fileExists(filepath.Join(s.config.DSLDirectory, filename))
	filenameUsed := usedFilenames[filename]

	counter := 1
	baseName := safeName

	// Loop until a unique filename is found
	for fileExists || filenameUsed {
		if s.config.Verbose {
			fmt.Printf("Debug - File exists or already used: %s, incrementing counter to %d\n", filename, counter)
		}
		filename = fmt.Sprintf("%s_%d.yaml", baseName, counter)
		fileExists = s.fileExists(filepath.Join(s.config.DSLDirectory, filename))
		filenameUsed = usedFilenames[filename]
		counter++
	}

	if s.config.Verbose {
		fmt.Printf("Debug - Final filename for app %q: %s\n", appName, filename)
	}
	return filename
}

// sanitizeFilename creates a safe filename from an app name
func (s *DefaultSyncer) sanitizeFilename(name string) string {
	// Result string
	var result strings.Builder

	// Replace characters not allowed in filenames
	// Characters invalid across Windows, macOS, Linux: / \ : * ? " < > |
	invalidChars := []rune{'/', '\\', ':', '*', '?', '"', '<', '>', '|'}

	// Convert spaces to underscores
	for _, r := range name {
		if unicode.IsSpace(r) {
			result.WriteRune('_')
		} else {
			// Check for invalid characters
			invalid := false
			for _, ic := range invalidChars {
				if r == ic {
					invalid = true
					break
				}
			}

			if !invalid {
				result.WriteRune(r)
			}
		}
	}

	// Use default name if result is empty
	if result.Len() == 0 {
		return "app"
	}

	return result.String()
}

// SyncAll synchronizes all apps in the app map
func (s *DefaultSyncer) SyncAll() (*SyncStats, error) {
	appMap, err := s.LoadAppMap()
	if err != nil {
		return nil, err
	}

	stats := &SyncStats{
		Total:     len(appMap.Apps),
		StartTime: time.Now(),
	}

	// Get current app list to compare names
	remoteAppList, err := s.client.GetAppList()
	if err != nil {
		return nil, fmt.Errorf("failed to get app list from API: %w", err)
	}

	// Create a map of app IDs to app info for quick lookup
	remoteApps := make(map[string]api.AppInfo)
	for _, app := range remoteAppList {
		remoteApps[app.ID] = app
	}

	// Track name changes for renaming files
	nameChanges := make(map[string]string) // old filename -> new filename
	renamedApps := []AppMapping{}          // Updated app mappings

	// Track used filenames for deduplication (initialized early for rename processing)
	usedFilenames := make(map[string]bool)
	for _, app := range appMap.Apps {
		usedFilenames[app.Filename] = true
	}

	// First, check for remote apps that have been deleted
	deletedApps := []AppMapping{}

	for _, app := range appMap.Apps {
		// Check if the app still exists in remote
		exists, err := s.client.DoesDSLExist(app.AppID)
		if err != nil {
			fmt.Printf("Warning: Failed to check if app %s exists: %v\n", app.AppID, err)
			continue
		}

		if !exists {
			// App has been deleted remotely
			deletedApps = append(deletedApps, app)
			if s.config.Verbose {
				fmt.Printf("App %s (ID: %s) has been deleted remotely\n", app.Filename, app.AppID)
			}

			// Delete local file if not in dry run mode
			if !s.config.DryRun {
				localPath := filepath.Join(s.config.DSLDirectory, app.Filename)
				if err := os.Remove(localPath); err != nil {
					fmt.Printf("Warning: Failed to delete local file %s: %v\n", localPath, err)
				} else if s.config.Verbose {
					fmt.Printf("Deleted local file %s\n", localPath)
				}
			}

			// Count as download since we're reflecting remote state
			stats.Downloads++

			// Remove the deleted app's filename from usedFilenames
			delete(usedFilenames, app.Filename)
			continue
		}

		// Check if app name has changed
		if remoteApp, ok := remoteApps[app.AppID]; ok {
			// Create a safe filename from the remote app name
			safeName := s.sanitizeFilename(remoteApp.Name)
			expectedFilename := safeName + ".yaml"

			// If the current filename doesn't match the expected one based on remote name
			if app.Filename != expectedFilename {
				if s.config.Verbose {
					fmt.Printf("App name changed for %s (ID: %s): %s -> %s\n",
						app.Filename, app.AppID, app.Filename, expectedFilename)
				}

				// Check if file exists in filesystem or is used by another app in app_map
				// Note: exclude self (app.Filename) from usedFilenames check since we're renaming it
				fileExists := s.fileExists(filepath.Join(s.config.DSLDirectory, expectedFilename))
				filenameUsedByOther := usedFilenames[expectedFilename] && expectedFilename != app.Filename
				counter := 1
				baseName := safeName

				// Loop until a unique filename is found (check both filesystem and app_map)
				for fileExists || filenameUsedByOther {
					expectedFilename = fmt.Sprintf("%s_%d.yaml", baseName, counter)
					fileExists = s.fileExists(filepath.Join(s.config.DSLDirectory, expectedFilename))
					filenameUsedByOther = usedFilenames[expectedFilename] && expectedFilename != app.Filename
					counter++
				}

				// Only rename if the expected filename is different from current
				if app.Filename != expectedFilename {
					if !s.config.DryRun {
						// Rename the file
						oldPath := filepath.Join(s.config.DSLDirectory, app.Filename)
						newPath := filepath.Join(s.config.DSLDirectory, expectedFilename)

						if err := os.Rename(oldPath, newPath); err != nil {
							fmt.Printf("Warning: Failed to rename file %s to %s: %v\n", oldPath, newPath, err)
						} else if s.config.Verbose {
							fmt.Printf("Renamed file from %s to %s\n", oldPath, newPath)
						}
					}

					// Record the name change
					nameChanges[app.Filename] = expectedFilename

					// Update usedFilenames: remove old, add new
					delete(usedFilenames, app.Filename)
					usedFilenames[expectedFilename] = true

					// Update the app mapping
					newMapping := AppMapping{
						Filename: expectedFilename,
						AppID:    app.AppID,
					}
					renamedApps = append(renamedApps, newMapping)

					// Don't process this app further in this iteration
					continue
				}
			}
		}

		// Process existing apps
		result := s.SyncApp(app)

		switch result.Action {
		case ActionDownload:
			stats.Downloads++
		case ActionNone:
			stats.NoAction++
		case ActionError:
			stats.Errors++
		}

		if s.config.Verbose {
			fmt.Printf("Synced %s (app_id: %s): %s\n", app.Filename, app.AppID, result.Action)
			if result.Error != nil {
				fmt.Printf("  Error: %v\n", result.Error)
			}
		}
	}

	// Detect and add new apps from remote
	existingAppIDs := make(map[string]bool)
	for _, app := range appMap.Apps {
		existingAppIDs[app.AppID] = true
	}

	// Note: usedFilenames is already initialized earlier and updated during delete/rename processing

	// Collect new app IDs and sort them for deterministic order
	var newAppIDs []string
	for appID := range remoteApps {
		if !existingAppIDs[appID] {
			newAppIDs = append(newAppIDs, appID)
		}
	}
	sort.Strings(newAppIDs)

	newApps := []AppMapping{}
	for _, appID := range newAppIDs {
		appInfo := remoteApps[appID]
		// New app found
		filename := s.generateUniqueFilename(appInfo.Name, usedFilenames)
		usedFilenames[filename] = true

		newApp := AppMapping{
			Filename: filename,
			AppID:    appID,
		}

		if s.config.Verbose {
			fmt.Printf("New app found: %s (ID: %s) -> %s\n", appInfo.Name, appID, filename)
		}

		// Download DSL for new app
		localPath := filepath.Join(s.config.DSLDirectory, filename)
		if s.config.DryRun {
			fmt.Printf("Dry run: Would download DSL for new app %s to %s\n", appInfo.Name, localPath)
			newApps = append(newApps, newApp)
			stats.Added++
			stats.Total++
			continue
		}

		dsl, err := s.client.GetDSL(appID)
		if err != nil {
			fmt.Printf("Warning: Failed to download DSL for new app %s: %v\n", appInfo.Name, err)
			stats.Errors++
			continue
		}

		if err := os.WriteFile(localPath, dsl, 0644); err != nil {
			fmt.Printf("Warning: Failed to write DSL file for new app %s: %v\n", appInfo.Name, err)
			stats.Errors++
			continue
		}

		if s.config.Verbose {
			fmt.Printf("Downloaded DSL for new app %s to %s\n", appInfo.Name, localPath)
		}

		// Only add to newApps after successful download and write
		newApps = append(newApps, newApp)
		stats.Added++
		stats.Total++
	}

	// Update app map if apps were deleted, renamed, or added
	if (len(deletedApps) > 0 || len(renamedApps) > 0 || len(newApps) > 0) && !s.config.DryRun {
		// Create new app map without deleted apps and with updated filenames
		updatedApps := make([]AppMapping, 0, len(appMap.Apps)-len(deletedApps))

		for _, app := range appMap.Apps {
			// Skip deleted apps
			isDeleted := false
			for _, deletedApp := range deletedApps {
				if app.AppID == deletedApp.AppID {
					isDeleted = true
					break
				}
			}
			if isDeleted {
				continue
			}

			// Check if this app was renamed
			isRenamed := false
			for _, renamedApp := range renamedApps {
				if app.AppID == renamedApp.AppID {
					// Add the renamed app
					updatedApps = append(updatedApps, renamedApp)
					isRenamed = true
					break
				}
			}

			// Add the unchanged app
			if !isRenamed {
				updatedApps = append(updatedApps, app)
			}
		}

		// Add new apps
		updatedApps = append(updatedApps, newApps...)

		// Save updated app map
		updatedAppMap := &AppMap{
			Apps: updatedApps,
		}

		file, err := os.Create(s.config.AppMapFile)
		if err != nil {
			return stats, fmt.Errorf("failed to update app map file: %w", err)
		}
		defer file.Close()

		encoder := json.NewEncoder(file)
		encoder.SetIndent("", "  ")
		if err := encoder.Encode(updatedAppMap); err != nil {
			return stats, fmt.Errorf("failed to write updated app map file: %w", err)
		}

		if s.config.Verbose {
			if len(deletedApps) > 0 {
				fmt.Printf("Removed %d deleted apps from app map\n", len(deletedApps))
			}
			if len(renamedApps) > 0 {
				fmt.Printf("Updated %d app names in app map\n", len(renamedApps))
			}
			if len(newApps) > 0 {
				fmt.Printf("Added %d new apps to app map\n", len(newApps))
			}
		}
	}

	stats.EndTime = time.Now()
	stats.Duration = stats.EndTime.Sub(stats.StartTime)

	return stats, nil
}

// SyncApp synchronizes a single app
func (s *DefaultSyncer) SyncApp(app AppMapping) SyncResult {
	result := SyncResult{
		Filename:  app.Filename,
		AppID:     app.AppID,
		Action:    ActionNone,
		Timestamp: time.Now(),
	}

	// Get local file modification time
	localPath := filepath.Join(s.config.DSLDirectory, app.Filename)
	localInfo, err := os.Stat(localPath)
	if err != nil {
		result.Action = ActionError
		result.Error = fmt.Errorf("failed to stat local file: %w", err)
		if s.config.Verbose {
			fmt.Printf("Error: %v\n", result.Error)
		}
		return result
	}
	localModTime := localInfo.ModTime()

	// Check if app still exists remotely
	exists, err := s.client.DoesDSLExist(app.AppID)
	if err != nil {
		result.Action = ActionError
		result.Error = fmt.Errorf("failed to check if app exists: %w", err)
		if s.config.Verbose {
			fmt.Printf("Error checking app %s (%s): %v\n", app.AppID, app.Filename, err)
		}
		return result
	}

	if !exists {
		// App has been deleted remotely
		if s.config.Verbose {
			fmt.Printf("App %s (ID: %s) no longer exists remotely\n", app.Filename, app.AppID)
		}

		// We'll handle the deletion in SyncAll
		result.Action = ActionNone
		result.Success = true
		return result
	}

	// Get remote app info
	appInfo, err := s.client.GetAppInfo(app.AppID)
	if err != nil {
		result.Action = ActionError
		result.Error = fmt.Errorf("failed to get app info: %w", err)
		if s.config.Verbose {
			fmt.Printf("Error accessing app %s (%s): %v\n", app.AppID, app.Filename, err)
		}
		return result
	}

	if s.config.Verbose {
		fmt.Printf("Debug - App Info for %s: %+v\n", app.AppID, appInfo)
	}

	// Convert interface{} updated_at to time.Time
	var remoteModTime time.Time
	var useLocalTime bool = false

	if appInfo.UpdatedAt == nil {
		// If UpdatedAt is nil, use a time in the past to ensure the local file is considered newer
		if s.config.Verbose {
			fmt.Printf("Debug - UpdatedAt is nil, using past timestamp to prioritize local file\n")
		}
		// Use Unix epoch start as the remote time (1970-01-01) to ensure local is newer
		remoteModTime = time.Unix(0, 0)
		useLocalTime = true
	} else {
		switch v := appInfo.UpdatedAt.(type) {
		case string:
			// For string type: parse the timestamp string
			if v != "" {
				// Try RFC3339 format (2023-01-02T15:04:05Z)
				parsedTime, err := time.Parse(time.RFC3339, v)
				if err == nil {
					remoteModTime = parsedTime
				} else {
					// Try other formats
					layouts := []string{
						"2006-01-02 15:04:05",
						"2006-01-02T15:04:05",
						"2006/01/02 15:04:05",
						time.RFC1123,
						time.RFC1123Z,
					}

					for _, layout := range layouts {
						parsedTime, err := time.Parse(layout, v)
						if err == nil {
							remoteModTime = parsedTime
							break
						}
					}
				}
			} else {
				// Empty string, treat as nil case
				if s.config.Verbose {
					fmt.Printf("Debug - UpdatedAt is empty string, using past timestamp to prioritize local file\n")
				}
				remoteModTime = time.Unix(0, 0)
				useLocalTime = true
			}
		case float64:
			// For numeric type: interpret as UNIX timestamp (seconds)
			remoteModTime = time.Unix(int64(v), 0)
			if s.config.Verbose {
				fmt.Printf("Debug - Converted float64 timestamp %v to time: %v\n", v, remoteModTime)
			}
		case int:
			// For integer type: interpret as UNIX timestamp (seconds)
			remoteModTime = time.Unix(int64(v), 0)
			if s.config.Verbose {
				fmt.Printf("Debug - Converted int timestamp %v to time: %v\n", v, remoteModTime)
			}
		case int64:
			// For 64-bit integer: interpret as UNIX timestamp
			remoteModTime = time.Unix(v, 0)
			if s.config.Verbose {
				fmt.Printf("Debug - Converted int64 timestamp %v to time: %v\n", v, remoteModTime)
			}
		case json.Number:
			// For json.Number type
			if i, err := v.Int64(); err == nil {
				remoteModTime = time.Unix(i, 0)
				if s.config.Verbose {
					fmt.Printf("Debug - Converted json.Number timestamp %v to time: %v\n", v, remoteModTime)
				}
			} else {
				// If conversion fails, treat as nil case
				if s.config.Verbose {
					fmt.Printf("Debug - Could not convert json.Number %v to timestamp, using past timestamp\n", v)
				}
				remoteModTime = time.Unix(0, 0)
				useLocalTime = true
			}
		default:
			if s.config.Verbose {
				fmt.Printf("Debug - Unknown type for UpdatedAt: %T value: %v, using past timestamp\n", appInfo.UpdatedAt, appInfo.UpdatedAt)
			}
			remoteModTime = time.Unix(0, 0)
			useLocalTime = true
		}
	}

	if s.config.Verbose {
		fmt.Printf("Debug - Local mod time: %v, Remote mod time: %v\n", localModTime, remoteModTime)
	}

	// If UpdatedAt was nil or couldn't be parsed, don't sync
	if useLocalTime {
		if s.config.Verbose {
			fmt.Printf("Debug - No valid remote timestamp found, skipping sync\n")
		}
		result.Action = ActionNone
		result.Success = true
		return result
	}

	// Only download if remote is newer
	if remoteModTime.After(localModTime) {
		return s.downloadFromRemote(app, localPath)
	}

	// Files are in sync
	result.Action = ActionNone
	result.Success = true
	return result
}

// downloadFromRemote downloads the DSL from Dify to the local file
func (s *DefaultSyncer) downloadFromRemote(app AppMapping, localPath string) SyncResult {
	result := SyncResult{
		Filename:  app.Filename,
		AppID:     app.AppID,
		Action:    ActionDownload,
		Timestamp: time.Now(),
	}

	// Get DSL from Dify
	dsl, err := s.client.GetDSL(app.AppID)
	if err != nil {
		result.Error = fmt.Errorf("failed to get DSL from Dify: %w", err)
		return result
	}

	// If dry run, just return success
	if s.config.DryRun {
		result.Success = true
		return result
	}

	// Write DSL to local file
	if err := os.WriteFile(localPath, dsl, 0644); err != nil {
		result.Error = fmt.Errorf("failed to write DSL to local file: %w", err)
		return result
	}

	result.Success = true
	return result
}

// Package syncer provides the core synchronization logic between local DSL files and Dify.AI
package syncer

import (
	"time"
)

// AppMap represents a mapping between local DSL files and Dify app IDs
type AppMap struct {
	Apps []AppMapping `json:"apps"`
}

// AppMapping represents a single mapping entry between a DSL file and a Dify app
type AppMapping struct {
	Filename string `json:"filename"`
	AppID    string `json:"app_id"`
}

// SyncResult represents the result of a sync operation for a single app
type SyncResult struct {
	Filename  string
	AppID     string
	Action    SyncAction
	Success   bool
	Error     error
	Timestamp time.Time
}

// SyncAction represents the action taken during sync
type SyncAction string

const (
	// ActionNone indicates no sync was needed (files already in sync)
	ActionNone SyncAction = "none"

	// ActionDownload indicates the Dify DSL was downloaded to local file
	ActionDownload SyncAction = "download"

	// ActionError indicates an error occurred during sync
	ActionError SyncAction = "error"
)

// SyncStats represents statistics about a sync operation
type SyncStats struct {
	Total     int
	Downloads int
	Added     int
	NoAction  int
	Errors    int
	StartTime time.Time
	EndTime   time.Time
	Duration  time.Duration
}

package app

import (
	"encoding/json"
	"os"
	"path/filepath"
	"time"
)

// Settings represents the configuration settings for the application.
type Settings struct {
	CreatedAt      string        `json:"createdAt"`
	CreatedByUser  string        `json:"createdByUser"`
	CreatedOnHost  string        `json:"createdOnHost"`
	CreatedVersion string        `json:"createdVersion"`
	Disabled       bool          `json:"disabled"`
	Scans          []ScanSetting `json:"scans"`
}

// ScanSetting represents the settings for a specific scan.
type ScanSetting struct {
	Disabled bool     `json:"disabled"`
	ScanTool string   `json:"scanTool"`
	ScanType string   `json:"scanType"`
	Ignore   []string `json:"ignore"`
	Severity string   `json:"severity"`
}

// LoadSettings loads Settings from a file.
func LoadSettings(path string) (*Settings, error) {
	settings := &Settings{}
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	if err := json.NewDecoder(file).Decode(settings); err != nil {
		return nil, err
	}
	return settings, nil
}

// NewSettings creates a new Settings object.
func NewSettings(createdByUser, createdOnHost, createdVersion string) *Settings {
	return &Settings{
		CreatedAt:      time.Now().Format(time.RFC3339),
		CreatedByUser:  createdByUser,
		CreatedOnHost:  createdOnHost,
		CreatedVersion: createdVersion,
		Scans: []ScanSetting{
			{
				ScanTool: "grype",
				ScanType: "files",
				Ignore:   make([]string, 0),
				Severity: "medium",
			},
			{
				ScanTool: "trivy",
				ScanType: "config",
				Ignore:   make([]string, 0),
				Severity: "medium",
			},
			{
				ScanTool: "trivy",
				ScanType: "files",
				Ignore:   make([]string, 0),
				Severity: "medium",
			},
			{
				ScanTool: "trufflehog",
				ScanType: "files",
				Ignore:   make([]string, 0),
				Severity: "medium",
			},
			{
				ScanTool: "grype",
				ScanType: "image",
				Ignore:   make([]string, 0),
				Severity: "medium",
			},
			{
				ScanTool: "trufflehog",
				ScanType: "image",
				Ignore:   make([]string, 0),
				Severity: "medium",
			},
		},
	}
}

// SaveSettings saves Settings to a file.
func SaveSettings(settings *Settings, path string) error {
	// Ensure the directory exists.
	if err := ensureDir(filepath.Dir(path)); err != nil {
		return err
	}

	// Open the file for writing.
	file, err := os.Create(path)
	if err != nil {
		return err
	}
	defer file.Close()

	// Write the settings to the file.
	encoder := json.NewEncoder(file)
	encoder.SetIndent("", "  ")
	return encoder.Encode(settings)
}

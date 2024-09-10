package app

import (
	"encoding/json"
	"os"
	"path/filepath"
	"time"
)

// ScanSettings represents the configuration settings for the application.
type ScanSettings struct {
	AppVersion string        `json:"appVersion"`
	InitTime   string        `json:"initTime"`
	Disabled   bool          `json:"disabled"`
	Scans      []ScanSetting `json:"scans"`
}

// ScanSetting represents the settings for a specific scan.
type ScanSetting struct {
	Disabled     bool     `json:"disabled"`
	ScanTool     string   `json:"scanTool"`
	ScanType     string   `json:"scanType"`
	IgnoreCVEs   []string `json:"ignoreCVEs"`
	IgnoreStates []string `json:"ignoreStates"`
	Severity     string   `json:"severity"`
}

// NewSettings creates a new ScanSettings object.
func NewSettings(appVersion, severity string, ignoreCVEs, ignoreStates []string) *ScanSettings {
	if ignoreCVEs == nil {
		ignoreCVEs = make([]string, 0)
	}
	if ignoreStates == nil {
		ignoreStates = make([]string, 0)
	}
	return &ScanSettings{
		AppVersion: appVersion,
		InitTime:   time.Now().Format(time.RFC3339),
		Disabled:   false,
		Scans: []ScanSetting{
			{
				ScanTool:     "grype",
				ScanType:     "files",
				Disabled:     false,
				IgnoreCVEs:   ignoreCVEs,
				IgnoreStates: ignoreStates,
				Severity:     severity,
			},
			{
				ScanTool:     "trivy",
				ScanType:     "config",
				Disabled:     false,
				IgnoreCVEs:   ignoreCVEs,
				IgnoreStates: ignoreStates,
				Severity:     severity,
			},
			{
				ScanTool:     "trivy",
				ScanType:     "files",
				Disabled:     false,
				IgnoreCVEs:   ignoreCVEs,
				IgnoreStates: ignoreStates,
				Severity:     severity,
			},
			{
				ScanTool:     "trufflehog",
				ScanType:     "files",
				Disabled:     false,
				IgnoreCVEs:   ignoreCVEs,
				IgnoreStates: ignoreStates,
				Severity:     severity,
			},
			{
				ScanTool:     "grype",
				ScanType:     "image",
				Disabled:     false,
				IgnoreCVEs:   ignoreCVEs,
				IgnoreStates: ignoreStates,
				Severity:     severity,
			},
			{
				ScanTool:     "trufflehog",
				ScanType:     "image",
				Disabled:     false,
				IgnoreCVEs:   ignoreCVEs,
				IgnoreStates: ignoreStates,
				Severity:     severity,
			},
		},
	}
}

// LoadSettings loads ScanSettings from a file.
func LoadSettings(path string) (*ScanSettings, error) {
	settings := &ScanSettings{}
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer func(file *os.File) {
		_ = file.Close()
	}(file)

	if err := json.NewDecoder(file).Decode(&settings); err != nil {
		return nil, err
	}
	return settings, nil
}

// SaveSettings saves ScanSettings to a file.
func SaveSettings(settings *ScanSettings, path string) error {
	// Ensure the directory exists.
	if err := ensureDir(filepath.Dir(path)); err != nil {
		return err
	}

	// Open the file for writing.
	file, err := os.Create(path)
	if err != nil {
		return err
	}
	defer func(file *os.File) {
		_ = file.Close()
	}(file)

	// Write the settings to the file.
	encoder := json.NewEncoder(file)
	encoder.SetIndent("", "  ")
	return encoder.Encode(settings)
}

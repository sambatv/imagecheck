package app

import (
	"encoding/json"
	"os"
	"path/filepath"
)

// ScansSettings represents the configuration settings for the application.
type ScansSettings struct {
	AppVersion string         `json:"appVersion"`
	Disabled   bool           `json:"disabled"`
	Scans      []ScanSettings `json:"scans"`
}

// ToJSON returns the JSON representation of a ScansSettings object.
func (s ScansSettings) ToJSON() (string, error) {
	data, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return "", err
	}
	return string(data), nil
}

// FindScanSetting finds a specific scan setting by scan tool and scan type.
func (s ScansSettings) FindScanSetting(scanTool, scanType string) ScanSettings {
	for _, setting := range s.Scans {
		if setting.ScanTool == scanTool && setting.ScanType == scanType {
			return setting
		}
	}
	return ScanSettings{}
}

// ScanSettings represents the settings for a specific scan, some of which are
// not persisted to disk in JSON format, but are set at runtime from the command
// line options.
type ScanSettings struct {
	ScanTool     string   `json:"scanTool"`
	ScanType     string   `json:"scanType"`
	Severity     string   `json:"severity"`
	Disabled     bool     `json:"disabled"`
	IgnoreCVEs   []string `json:"ignoreCVEs"`
	IgnoreStates []string `json:"ignoreStates"`
	DryRun       bool
	PipelineMode bool
	Verbose      bool
}

// NewScansSettings creates a new ScansSettings object.
func NewScansSettings(appVersion, severity string, ignoreCVEs, ignoreStates []string) *ScansSettings {
	if ignoreCVEs == nil {
		ignoreCVEs = make([]string, 0)
	}
	if ignoreStates == nil {
		ignoreStates = make([]string, 0)
	}
	return &ScansSettings{
		AppVersion: appVersion,
		Disabled:   false,
		Scans: []ScanSettings{
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

// LoadSettings loads ScansSettings from a file.
func LoadSettings(path string) (*ScansSettings, error) {
	settings := &ScansSettings{}
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

// SaveSettings saves ScansSettings to a file.
func SaveSettings(settings *ScansSettings, path string) error {
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

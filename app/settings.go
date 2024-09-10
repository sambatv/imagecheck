package app

import (
	"encoding/json"
	"os"
	"path/filepath"
)

// ScansSettings represents the configuration settings for the application,
// some of which are not persisted to disk in JSON format, but are set at
// runtime from the command line options.
type ScansSettings struct {
	AppVersion   string         `json:"appVersion"`
	Disabled     bool           `json:"disabled"`
	Severity     string         `json:"severity"`
	IgnoreCVEs   []string       `json:"ignoreCVEs"`
	IgnoreStates []string       `json:"ignoreStates"`
	Scans        []ScanSettings `json:"scans"`
	dryRun       bool
	verbose      bool
	pipelineMode bool
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
			setting.dryRun = s.dryRun
			setting.verbose = s.verbose
			setting.pipelineMode = s.pipelineMode
			setting.severity = s.Severity
			setting.ignoreCVEs = s.IgnoreCVEs
			setting.ignoreStates = s.IgnoreStates
			return setting
		}
	}
	return ScanSettings{}
}

// ScanSettings represents the settings for a specific scan, some of which are
// not persisted to disk in JSON format, but are set at runtime from the command
// line options.
type ScanSettings struct {
	ScanTool     string `json:"scanTool"`
	ScanType     string `json:"scanType"`
	Disabled     bool   `json:"disabled"`
	severity     string
	ignoreCVEs   []string
	ignoreStates []string
	dryRun       bool
	verbose      bool
	pipelineMode bool
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
		AppVersion:   appVersion,
		Disabled:     false,
		Severity:     severity,
		IgnoreCVEs:   ignoreCVEs,
		IgnoreStates: ignoreStates,
		Scans: []ScanSettings{
			{
				ScanTool: "grype",
				ScanType: "files",
				Disabled: false,
			},
			{
				ScanTool: "trivy",
				ScanType: "config",
				Disabled: false,
			},
			{
				ScanTool: "trivy",
				ScanType: "files",
				Disabled: false,
			},
			{
				ScanTool: "trufflehog",
				ScanType: "files",
				Disabled: false,
			},
			{
				ScanTool: "grype",
				ScanType: "image",
				Disabled: false,
			},
			{
				ScanTool: "trufflehog",
				ScanType: "image",
				Disabled: false,
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

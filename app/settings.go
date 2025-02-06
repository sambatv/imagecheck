package app

import (
	"encoding/json"
	"os"
	"path/filepath"
	"slices"
)

// ScansSettings represents the initial version of application scan settings.
// Some fields are not persisted to disk in JSON format, but are set at runtime
// from the command line options or their corresponding environment variables.
type ScansSettings struct {
	AppVersion      string          `json:"app_version"`
	Disabled        bool            `json:"disabled"`
	Severity        string          `json:"severity"`
	IgnoreFailures  bool            `json:"ignore_failures"`
	IgnoreIDs       []string        `json:"ignore_ids"`
	IgnoreFixStates []string        `json:"ignore_fix_states"`
	ScansSettings   []*ScanSettings `json:"scan_settings"`
	dryRun          bool
	verbose         bool
	pipelineMode    bool
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
func (s ScansSettings) FindScanSetting(scanTool, scanType string) *ScanSettings {
	for _, setting := range s.ScansSettings {
		if setting.ScanTool == scanTool && setting.ScanType == scanType {
			setting.dryRun = s.dryRun
			setting.verbose = s.verbose
			setting.pipelineMode = s.pipelineMode
			setting.severity = s.Severity
			setting.ignoreIDs = s.IgnoreIDs
			setting.ignoreFixStates = s.IgnoreFixStates
			return setting
		}
	}
	return nil
}

// ScanSettings represents the settings for a specific scan, some of which are
// not persisted to disk in JSON format, but are set at runtime from the command
// line options.
type ScanSettings struct {
	ScanTool        string `json:"scan_tool"`
	ScanType        string `json:"scan_type"`
	Disabled        bool   `json:"disabled"`
	dryRun          bool
	verbose         bool
	pipelineMode    bool
	severity        string
	ignoreFailures  bool
	ignoreIDs       []string
	ignoreFixStates []string
}

// IsIgnoredID tests if the CVE ID is ignored in settings.
func (s ScanSettings) IsIgnoredID(id string) bool {
	return slices.Contains(s.ignoreIDs, id)
}

// IsIgnoredFixState tests if the fix state is ignored in settings.
func (s ScanSettings) IsIgnoredFixState(state string) bool {
	return slices.Contains(s.ignoreFixStates, state)
}

// NewScansSettings creates a new ScansSettings object.
func NewScansSettings(appVersion, severity string, ignoreFailures bool, ignoreIDs, ignoreStates []string) *ScansSettings {
	if ignoreIDs == nil {
		ignoreIDs = make([]string, 0)
	}
	if ignoreStates == nil {
		ignoreStates = make([]string, 0)
	}
	return &ScansSettings{
		AppVersion:      appVersion,
		Disabled:        false,
		Severity:        severity,
		IgnoreFailures:  ignoreFailures,
		IgnoreIDs:       ignoreIDs,
		IgnoreFixStates: ignoreStates,
		ScansSettings: []*ScanSettings{
			{
				ScanTool: "grype",
				ScanType: "image",
				Disabled: false,
			},
			{
				ScanTool: "trivy",
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

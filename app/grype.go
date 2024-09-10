package app

import (
	"encoding/json"
	"fmt"
	"os/exec"
	"time"
)

// GrypeScanner is a struct that represents a grype scanner.
type GrypeScanner struct{}

// Version returns the version of the grype scanner application.
func (s GrypeScanner) Version() string {
	cmd := exec.Command("grype", "version", "--output", "json")
	output, err := cmd.Output()
	if err != nil {
		return ""
	}
	var data map[string]interface{}
	if err := json.Unmarshal(output, &data); err != nil {
		return ""
	}
	return data["version"].(string)
}

// Scan scans a target for a type of defect or vulnerability with grype.
func (s GrypeScanner) Scan(target string, settings ScanSettings) Scan {
	// Set output format to JSON in pipeline mode.
	var outputOpt string
	if settings.pipelineMode {
		outputOpt = "--output=json"
	}

	// Scan the appropriate scan command line.
	var cmdline string
	switch settings.ScanType {
	case "files":
		cmdline = fmt.Sprintf("grype %s --fail-on=%s dir:%s", outputOpt, settings.severity, target)
	case "image":
		cmdline = fmt.Sprintf("grype %s --fail-on=%s %s", outputOpt, settings.severity, target)
	default:
		return Scan{} // should never happen
	}
	return s.run(cmdline, target, settings)
}

func (s GrypeScanner) run(cmdline, target string, settings ScanSettings) Scan {
	// Execute the scanner command line and calculate the duration.
	beginTime := time.Now()
	exitCode, stdout, err := execScanner(cmdline, settings)
	durationSecs := time.Since(beginTime).Seconds()

	// Create a new scan object to return.
	scan := Scan{
		Settings:     settings,
		ScanTarget:   target,
		CommandLine:  cmdline,
		DurationSecs: durationSecs,
		ExitCode:     exitCode,
		stdout:       stdout,
	}

	// If there was an error or is a dry run, there's nothing more to do.
	if err != nil {
		scan.Error = err.Error()
		return scan
	}
	if settings.dryRun {
		return scan
	}

	// Otherwise, parse the JSON output to get the number of vulnerabilities.
	var data map[string]any
	if err := json.Unmarshal(stdout, &data); err != nil {
		scan.Error = err.Error()
		return scan
	}

	// Count the number of vulnerabilities in "matches" by severity.
	matches := data["matches"].([]interface{})
	for _, match := range matches {
		vulnerability, ok := match.(map[string]any)["vulnerability"].(map[string]any)
		if !ok {
			// No vulnerability found. Yay!
			continue
		}
		severity := vulnerability["severity"].(string)
		scan.Score(severity)
	}
	return scan
}

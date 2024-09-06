package app

import (
	"encoding/json"
	"fmt"
	"os/exec"
	"time"
)

// GrypeScanner is a struct that represents a grype scanner.
type GrypeScanner struct{}

// Name returns the name of the grype scanner application.
func (s GrypeScanner) Name() string {
	return "grype"
}

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
func (s GrypeScanner) Scan(scanType, scanTarget, severity string, ignore []string, dryRun, pipelineMode bool) Scan {
	// Set output format to JSON in pipeline mode.
	var outputOpt string
	if pipelineMode {
		outputOpt = "--output=json"
	}

	// Scan the appropriate scan command line.
	switch scanType {
	case "files":
		return s.run(fmt.Sprintf("grype %s --fail-on=%s dir:%s", outputOpt, severity, scanTarget), scanType, scanTarget, dryRun, pipelineMode)
	case "image":
		return s.run(fmt.Sprintf("grype %s --fail-on=%s %s", outputOpt, severity, scanTarget), scanType, scanTarget, dryRun, pipelineMode)
	default:
		return Scan{}
	}
}

func (s GrypeScanner) run(cmdline, scanType, scanTarget string, dryRun, pipelineMode bool) Scan {
	beginTime := time.Now()
	exitCode, stdout, err := execScanner(cmdline, dryRun, pipelineMode)
	durationSecs := time.Since(beginTime).Seconds()
	scan := Scan{
		ScanTool:     s.Name(),
		ScanType:     scanType,
		ScanTarget:   scanTarget,
		CommandLine:  cmdline,
		DurationSecs: durationSecs,
		ExitCode:     exitCode,
		stdout:       stdout,
		err:          err,
	}
	if err != nil {
		scan.Error = err.Error()
	}
	if dryRun {
		return scan
	}

	// Parse the JSON output to get the number of vulnerabilities.
	var data map[string]any
	if err := json.Unmarshal(stdout, &data); err != nil {
		return scan
	}

	// Count the number of vulnerabilities in "matches" by severity.
	matches := data["matches"].([]interface{})
	for _, match := range matches {
		vulnerability := match.(map[string]any)["vulnerability"].(map[string]any)
		severity := vulnerability["severity"].(string)
		scan.Score(severity)
	}
	return scan
}

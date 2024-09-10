package app

import (
	"encoding/json"
	"fmt"
	"os/exec"
	"time"
)

// TrivyScanner is a struct that represents a trivy scanner.
type TrivyScanner struct{}

// Version returns the version of the trivy scanner application.
func (s TrivyScanner) Version() string {
	cmd := exec.Command("trivy", "version", "--format", "json")
	output, err := cmd.Output()
	if err != nil {
		return ""
	}
	var data map[string]interface{}
	if err := json.Unmarshal(output, &data); err != nil {
		return ""
	}
	return data["Version"].(string)
}

// Scan scans a target for a type of defect or vulnerability with trivy.
func (s TrivyScanner) Scan(target string, settings ScanSettings) Scan {
	// Set output format to JSON in pipeline mode.
	var outputOpt string
	if settings.pipelineMode {
		outputOpt = "--format=json"
	}

	// Set the failure severity option.
	var severityOpt string
	switch settings.severity {
	case "critical":
		severityOpt = "--severity=CRITICAL"
	case "high":
		severityOpt = "--severity=CRITICAL,HIGH"
	case "medium":
		severityOpt = "--severity=CRITICAL,HIGH,MEDIUM"
	case "low":
		severityOpt = "--severity=CRITICAL,HIGH,MEDIUM,LOW"
	}

	// Scan the appropriate scan command line.
	var cmdline string
	switch settings.ScanType {
	case "config":
		cmdline = fmt.Sprintf("trivy config %s %s %s", severityOpt, outputOpt, target)
	case "files":
		cmdline = fmt.Sprintf("trivy filesystem %s %s %s", severityOpt, outputOpt, target)
	default:
		return Scan{} // should never happen
	}
	return s.run(cmdline, target, settings)
}

func (s TrivyScanner) run(cmdline, target string, settings ScanSettings) Scan {
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

	switch settings.ScanType {
	case "config":
		results := data["Results"].([]any)
		for _, result := range results {
			misconfigurations, ok := result.(map[string]any)["Misconfigurations"].([]any)
			if !ok {
				// No misconfigurations found. Yay!
				continue
			}
			for _, misconfiguration := range misconfigurations {
				severity := misconfiguration.(map[string]any)["Severity"].(string)
				scan.Score(severity)
			}
		}
	case "files":
		results := data["Results"].([]any)
		for _, result := range results {
			vulnerabilities, ok := result.(map[string]any)["Vulnerabilities"].([]any)
			if !ok {
				// No vulnerabilities found. Yay!
				continue
			}
			for _, vulnerability := range vulnerabilities {
				severity := vulnerability.(map[string]any)["Severity"].(string)
				scan.Score(severity)
			}
		}
	}
	return scan
}

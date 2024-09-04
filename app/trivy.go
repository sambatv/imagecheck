package app

import (
	"encoding/json"
	"fmt"
	"os/exec"
	"time"
)

// TrivyScanner is a struct that represents a trivy scanner.
type TrivyScanner struct{}

// Name returns the name of the trivy scanner application.
func (s TrivyScanner) Name() string {
	return "trivy"
}

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
func (s TrivyScanner) Scan(scanType, scanTarget, severity string, dryRun, pipelineMode bool) Scan {
	// Set output format to JSON in pipeline mode.
	var outputOpt string
	if pipelineMode {
		outputOpt = "--format=json"
	}

	// Set the failure severity option.
	var severityOpt string
	switch severity {
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
	switch scanType {
	case "config":
		return s.run(fmt.Sprintf("trivy config %s %s %s", severityOpt, outputOpt, scanTarget), scanType, scanTarget, dryRun, pipelineMode)
	case "files":
		return s.run(fmt.Sprintf("trivy filesystem %s %s %s", severityOpt, outputOpt, scanTarget), scanType, scanTarget, dryRun, pipelineMode)
	case "image":
		return s.run(fmt.Sprintf("trivy image %s %s %s", severityOpt, outputOpt, scanTarget), scanType, scanTarget, dryRun, pipelineMode)
	default:
		return Scan{}
	}
}

func (s TrivyScanner) run(cmdline, scanType, scanTarget string, dryRun, pipelineMode bool) Scan {
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

	switch scanType {
	case "config":
		results := data["Results"].([]any)
		for _, result := range results {
			misconfigurations := result.(map[string]any)["Misconfigurations"].([]any)
			for _, misconfiguration := range misconfigurations {
				severity := misconfiguration.(map[string]any)["Severity"].(string)
				scan.Score(severity)
			}
		}
	case "image":
		results := data["Results"].([]any)
		for _, result := range results {
			vulnerabilities := result.(map[string]any)["Vulnerabilities"].([]any)
			for _, vulnerability := range vulnerabilities {
				severity := vulnerability.(map[string]any)["Severity"].(string)
				scan.Score(severity)
			}
		}
	}
	return scan
}

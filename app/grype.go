package app

import (
	"encoding/json"
	"fmt"
	"os/exec"
	"strings"
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
func (s GrypeScanner) Scan(target string, settings *ScanSettings) *Scan {
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
		return &Scan{} // should never happen
	}
	return s.run(cmdline, target, settings)
}

func (s GrypeScanner) run(cmdline, target string, settings *ScanSettings) *Scan {
	// Execute the scanner command line and calculate the duration.
	beginTime := time.Now()
	exitCode, stdout, err := execScanner(cmdline, settings)
	durationSecs := time.Since(beginTime).Seconds()

	// Create a new scan object to return.
	scan := NewScan(settings, target, cmdline, durationSecs, exitCode, stdout)

	// If there was an error, is a dry run, or is in pipeline mode, there's nothing more to do.
	if err != nil {
		scan.Error = err.Error()
		return scan
	}
	if settings.dryRun {
		return scan
	}
	if !settings.pipelineMode {
		return scan
	}

	// Otherwise, parse the JSON output to get the number of vulnerabilities.
	var data map[string]any
	if err := json.Unmarshal(stdout, &data); err != nil {
		scan.Error = err.Error()
		return scan
	}

	// Count the number of vulnerabilities by severity.
	numFailures := 0
	matches := data["matches"].([]interface{})
	if settings.pipelineMode || settings.verbose {
		fmt.Printf("num vulnerabilities: %d\n", len(matches))
	}
	for i, match := range matches {
		i += 1
		vulnerability := match.(map[string]any)["vulnerability"].(map[string]any)

		// Score the vulnerability based on its severity.
		severity := vulnerability["severity"].(string)
		severity = strings.ToLower(severity)
		scan.Score(severity)

		// Test if vulnerability id is ignored.
		id := vulnerability["id"].(string)
		if settings.verbose || settings.pipelineMode {
			fmt.Printf("vulnerability %d: id=%s, severity=%s\n", i, id, severity)
		}
		if settings.IsIgnoredID(id) {
			scan.NumIgnored++
			if settings.verbose || settings.pipelineMode {
				fmt.Printf("vulnerability %d: ignoring id %s\n", i, id)
			}
			scan.Ok = true // ignored id does not fail the scan
			continue
		}

		// Test if vulnerability fix state is ignored.
		fix := vulnerability["fix"].(map[string]any)
		fixState := fix["state"].(string)
		fixState = strings.ToLower(fixState)
		if settings.IsIgnoredFixState(fixState) {
			scan.NumIgnored++
			if settings.verbose || settings.pipelineMode {
				fmt.Printf("vulnerability %d: ignoring fix state %s\n", i, fixState)
			}
			scan.Ok = true // ignored fix state does not fail the scan
			continue
		}

		// If not ignored, the scan is ok if the severity is below the failure threshold.
		if scan.Failed() {
			numFailures++
		}
	}
	scan.Ok = numFailures == 0
	return scan
}

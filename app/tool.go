package app

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"time"
)

// ScanTool defines behaviors for a scanner application used to scan a target for a type of defect or vulnerability.
type ScanTool interface {
	// Scan scans a target for a type of defect or vulnerability.
	Scan(target string, settings *ScanSettings) *Scan

	// Version returns the version of the scanner application.
	Version() string
}

func newScanTool(settings *ScanSettings) ScanTool {
	switch settings.ScanTool {
	case "grype":
		return &GrypeScanner{Settings: settings}
	case "trivy":
		return &TrivyScanner{Settings: settings}
	case "trufflehog":
		return &TrufflehogScanner{Settings: settings}
	default:
		return nil
	}
}

// execScanner executes a scan tool command line per its settings and returns its exit code, stdout and stderr.
func execScanner(cmdline, target string, settings *ScanSettings, wrapJsonItems bool) *Scan {
	if settings.dryRun {
		fmt.Println(cmdline)
		return nil
	}

	var (
		exitCode int
		stdout   []byte
		err      error
	)
	if settings.pipelineMode || settings.verbose {
		fmt.Printf("exec: %s\n", cmdline)
	}

	// Build command.
	parts := strings.Fields(cmdline)
	executable := parts[0]
	args := parts[1:]
	cmd := exec.Command(executable, args...)

	// If not in pipeline mode, print the command's stderr, typically progress info, to the console.
	if !settings.pipelineMode {
		cmd.Stderr = os.Stderr
	}

	// Execute command and ignore any exit errors.
	beginTime := time.Now()
	stdout, err = cmd.Output()
	durationSecs := time.Since(beginTime).Seconds()
	if err != nil {
		var exitErr *exec.ExitError
		if errors.As(err, &exitErr) {
			err = nil
			exitCode = exitErr.ExitCode()
		}
	}

	// If not in pipeline mode, print the command's stdout to the console.
	if !settings.pipelineMode {
		fmt.Println(string(stdout))
	}

	// If wrapping stdout JSON objects in array, do so.
	if wrapJsonItems {
		stdout = wrapJSONItems(stdout)
	}

	// Deserialize the scan results from the command's stdout.
	data := make(map[string]any)
	if err == nil {
		err = json.Unmarshal(stdout, &data)
	}

	// Finally, return the scan results.
	return NewScan(settings, target, cmdline, durationSecs, err, exitCode, stdout, data)
}

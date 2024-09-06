package app

import (
	"fmt"
	"os/exec"
	"strings"
	"time"
)

// TrufflehogScanner is a struct that represents a trufflehog scanner.
type TrufflehogScanner struct{}

// Name returns the name of the trufflehog scanner application.
func (s TrufflehogScanner) Name() string {
	return "trufflehog"
}

// Version returns the version of the trufflehog scanner application.
func (s TrufflehogScanner) Version() string {
	cmd := exec.Command("trufflehog", "--version")
	output, err := cmd.CombinedOutput()
	if err != nil {
		return ""
	}
	text := strings.TrimSpace(string(output))
	return strings.Split(text, " ")[1]
}

// Scan scans a target for a type of defect or vulnerability with trufflehog.
func (s TrufflehogScanner) Scan(scanType, scanTarget, severity string, ignore []string, dryRun, pipelineMode bool) Scan {
	// Set output format to JSON in pipeline mode.
	var outputOpt string
	if pipelineMode {
		outputOpt = "--json"
	}

	// Scan the appropriate scan command line.
	switch scanType {
	case "files":
		return s.run(fmt.Sprintf("trufflehog --fail %s filesystem %s", outputOpt, scanTarget), scanType, scanTarget, dryRun, pipelineMode)
	case "image":
		return s.run(fmt.Sprintf("trufflehog --fail %s docker --image=%s", outputOpt, scanTarget), scanType, scanTarget, dryRun, pipelineMode)
	default:
		return Scan{}
	}
}

func (s TrufflehogScanner) run(cmdline, scanType, scanTarget string, dryRun, pipelineMode bool) Scan {
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

	// TODO: Parse the output to get the number of vulnerabilities.
	return scan
}

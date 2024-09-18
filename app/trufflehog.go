package app

import (
	"encoding/json"
	"fmt"
	"os/exec"
	"strings"
	"time"
)

// TrufflehogScanner is a struct that represents a trufflehog scanner.
type TrufflehogScanner struct{}

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
func (s TrufflehogScanner) Scan(target string, settings *ScanSettings) *Scan {
	// Set output format to JSON in pipeline mode.
	var outputOpt string
	if settings.pipelineMode {
		outputOpt = "--json"
	} else {
		outputOpt = "--no-json"
	}

	// Scan the appropriate scan command line.
	var cmdline string
	switch settings.ScanType {
	case "files":
		cmdline = fmt.Sprintf("trufflehog --fail %s filesystem %s", outputOpt, target)
	case "image":
		cmdline = fmt.Sprintf("trufflehog --fail %s docker --image=%s", outputOpt, target)
	default:
		return &Scan{} // should never happen
	}
	return s.run(cmdline, target, settings)
}

func (s TrufflehogScanner) run(cmdline, target string, settings *ScanSettings) *Scan {
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

	// Otherwise, parse the JSON output to get the number of defects.
	scan.stdout = wrapJSONArray(scan.stdout)
	var data []any
	if err := json.Unmarshal(scan.stdout, &data); err != nil {
		scan.Error = err.Error()
		return scan
	}

	// Count the number of objects in output. With trufflehog, every object is a
	// vulnerability, which we will score as a critical vulnerability.
	scan.NumCritical = len(data)
	scan.Failed = scan.NumCritical > 0
	fmt.Printf("defects: %d found\n", scan.NumCritical)
	return scan
}

// wrapJSONArray wraps the given bytes in a JSON array.
// This is necessary because trufflehog outputs one JSON object per line with
// no comma delimiters between them, which is not a valid JSON doc.
func wrapJSONArray(bytes []byte) []byte {
	s := strings.TrimSpace(string(bytes))
	lines := strings.Split(s, "\n")
	if len(lines) == 0 {
		s = fmt.Sprintf("[%s]", s)
	} else {
		s = fmt.Sprintf("[%s]", strings.Join(lines, ","))
	}
	return []byte(s)
}

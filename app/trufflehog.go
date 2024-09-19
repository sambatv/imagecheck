package app

import (
	"fmt"
	"os/exec"
	"strings"
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
	// Execute the scanner command line.
	scan := execScanner(cmdline, target, settings, true)

	// If there was an error, is a dry run, or is in pipeline mode, there's nothing more to do.
	if scan.Error != "" {
		return scan
	}
	if settings.dryRun {
		return scan
	}
	if !settings.pipelineMode {
		return scan
	}

	// Count the number of objects in JSON data. With trufflehog, every result is
	// a potential vulnerability, which we will score as a critical defect if verified.
	results := scan.data["results"].([]any)
	if settings.verbose || settings.pipelineMode {
		fmt.Printf("results: %d found\n", len(results))
	}
	for i, result := range results {
		id := result.(map[string]any)["DetectorName"].(string)
		verified := result.(map[string]any)["Verified"].(bool)
		verifiedStr := "verified"
		if !verified {
			verifiedStr = "unverified"
		}
		if settings.verbose || settings.pipelineMode {
			fmt.Printf("result %d: %s %s\n", i, id, verifiedStr)
		}

		// Treat unverified results as unknown defects.
		severity := "unknown"
		if verified {
			severity = "critical"
		}

		scan.defects = append(scan.defects, Defect{
			ID:       id,
			Severity: severity,
		})

		if !verified && (settings.verbose || settings.pipelineMode) {
			fmt.Printf("ignored unverified result: %s\n", id)
		}
	}
	return scan
}

// wrapJSONItems wraps the given bytes in a JSON array in an enclosing object.
// This is necessary because trufflehog outputs one JSON object per line with
// no comma delimiters between them, which is not a valid JSON doc, and the
// common data deserialization in execScanner expects a JSON object.
func wrapJSONItems(bytes []byte) []byte {
	s := strings.TrimSpace(string(bytes))
	defects := strings.Split(s, "\n")
	if len(defects) > 0 {
		s = strings.Join(defects, ",\n    ")
	}
	const wrapFmt = `{
  "results": [
    %s
  ]
}`
	s = fmt.Sprintf(wrapFmt, s)
	return []byte(s)
}

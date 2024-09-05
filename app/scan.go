package app

import (
	"strings"
)

// Scan represents the results of a scan.
type Scan struct {
	ScanTool      string  `json:"scanTool"`
	ScanType      string  `json:"scanType"`
	ScanTarget    string  `json:"scanTarget"`
	CommandLine   string  `json:"commandLine"`
	DurationSecs  float64 `json:"durationSecs"`
	Error         string  `json:"error"`
	ExitCode      int     `json:"exitCode"`
	NumCritical   int     `json:"numCritical"`
	NumHigh       int     `json:"numHigh"`
	NumMedium     int     `json:"numMedium"`
	NumLow        int     `json:"numLow"`
	NumNegligible int     `json:"numNegligible"`
	NumUnknown    int     `json:"numUnknown"`
	err           error
	stdout        []byte
}

// Failed returns true if the scan failed severity threshold.
func (s *Scan) Failed(severity string) bool {
	switch severity {
	case "critical":
		return s.NumCritical > 0
	case "high":
		return s.NumHigh > 0 || s.NumCritical > 0
	case "medium":
		return s.NumMedium > 0 || s.NumHigh > 0 || s.NumCritical > 0
	case "low":
		return s.NumLow > 0 || s.NumMedium > 0 || s.NumHigh > 0 || s.NumCritical > 0
	default:
		return false
	}
}

// Score scores the scan based on the severity of the vulnerability.
func (s *Scan) Score(severity string) {
	severity = strings.ToLower(severity)
	switch severity {
	case "critical":
		s.NumCritical++
	case "high":
		s.NumHigh++
	case "medium":
		s.NumMedium++
	case "low":
		s.NumLow++
	case "negligible":
		s.NumNegligible++
	default:
		s.NumUnknown++
	}
}

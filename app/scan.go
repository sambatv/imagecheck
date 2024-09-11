package app

import "strings"

// Scan represents the results of a scan.
type Scan struct {
	Settings      *ScanSettings `json:"settings"`
	Target        string        `json:"target"`
	Cmdline       string        `json:"cmdline"`
	DurationSecs  float64       `json:"duration_secs"`
	Error         string        `json:"error"`
	ExitCode      int           `json:"exit_code"`
	Ok            bool          `json:"ok"`
	NumCritical   int           `json:"num_critical"`
	NumHigh       int           `json:"num_high"`
	NumMedium     int           `json:"num_medium"`
	NumLow        int           `json:"num_low"`
	NumNegligible int           `json:"num_negligible"`
	NumUnknown    int           `json:"num_known"`
	NumIgnored    int           `json:"num_ignored"`
	S3URL         string        `json:"s3_url"`
	stdout        []byte
}

// NewScan creates a new Scan object.
func NewScan(settings *ScanSettings, target, cmdline string, durationSecs float64, exitCode int, stdout []byte) *Scan {
	return &Scan{
		Settings:     settings,
		Target:       target,
		Cmdline:      cmdline,
		DurationSecs: durationSecs,
		ExitCode:     exitCode,
		stdout:       stdout,
	}
}

// Failed returns true if the scan failed severity threshold.
func (s *Scan) Failed() bool {
	var failed bool
	switch s.Settings.severity {
	case "critical":
		failed = (s.NumCritical) > 0
	case "high":
		failed = (s.NumHigh + s.NumCritical) > 0
	case "medium":
		failed = (s.NumMedium + s.NumHigh + s.NumCritical) > 0
	case "low":
		failed = (s.NumLow + s.NumMedium + s.NumHigh + s.NumCritical) > 0
	}
	return failed
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

// NumTotal returns the total number of vulnerabilities.
func (s *Scan) NumTotal() int {
	return s.NumCritical + s.NumHigh + s.NumMedium + s.NumLow + s.NumNegligible + s.NumUnknown
}

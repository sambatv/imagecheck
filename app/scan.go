package app

import (
	"fmt"
)

// Defect represents a defect found during a scan.
type Defect struct {
	ID       string `json:"id"`
	Severity string `json:"severity"`
	FixState string `json:"fix_state"`
}

// String returns a string representation of a Defect.
func (d Defect) String() string {
	return fmt.Sprintf("%s %s %s", d.ID, d.Severity, d.FixState)
}

// Scan represents the results of a scan.
type Scan struct {
	Settings      *ScanSettings `json:"settings"`
	Target        string        `json:"target"`
	Cmdline       string        `json:"cmdline"`
	DurationSecs  float64       `json:"duration_secs"`
	Error         string        `json:"error"`
	ExitCode      int           `json:"exit_code"`
	Failed        bool          `json:"failed"`
	NumCritical   int           `json:"num_critical"`
	NumHigh       int           `json:"num_high"`
	NumMedium     int           `json:"num_medium"`
	NumLow        int           `json:"num_low"`
	NumNegligible int           `json:"num_negligible"`
	NumUnknown    int           `json:"num_unknown"`
	NumTotal      int           `json:"num_total"`
	NumIgnored    int           `json:"num_ignored"`
	S3URL         string        `json:"s3_url"`
	stdout        []byte
	defects       []Defect
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
		defects:      make([]Defect, 0),
	}
}

// Score scores a Scan based on its defects.
func (s *Scan) Score() {
	// Set the total defects counter.
	s.NumTotal = len(s.defects)

	// Score each defect.
	for i, defect := range s.defects {
		// Print the defect if in verbose or pipeline mode.
		if s.Settings.verbose || s.Settings.pipelineMode {
			fmt.Printf("defect %d: %v\n", i, defect)
		}

		// Increment appropriate counters by severity.
		switch defect.Severity {
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

		// Increment total defects ignored counter if ignored and continue on to next scan.
		if s.Settings.IsIgnoredID(defect.ID) || s.Settings.IsIgnoredFixState(defect.FixState) {
			s.NumIgnored++
			if s.Settings.verbose {
				fmt.Printf("ignored %s check: defect %v\n", s.Settings.severity, defect)
			}
			continue
		}

		// Set the scan to failed if any defect exceeds severity in settings, excluding negligible or unknown.
		switch s.Settings.severity {
		case "critical":
			if defect.Severity == "critical" {
				if s.Settings.verbose {
					fmt.Printf("failed %s check: defect %v\n", s.Settings.severity, defect)
				}
				s.Failed = true
			}
		case "high":
			if defect.Severity == "critical" || defect.Severity == "high" {
				if s.Settings.verbose {
					fmt.Printf("failed %s check: defect %v\n", s.Settings.severity, defect)
				}
				s.Failed = true
			}
		case "medium":
			if defect.Severity == "critical" || defect.Severity == "high" || defect.Severity == "medium" {
				if s.Settings.verbose {
					fmt.Printf("failed %s check: defect %v\n", s.Settings.severity, defect)
				}
				s.Failed = true
			}
		case "low":
			if defect.Severity == "critical" || defect.Severity == "high" || defect.Severity == "medium" || defect.Severity == "low" {
				if s.Settings.verbose {
					fmt.Printf("failed %s check: defect %v\n", s.Settings.severity, defect)
				}
				s.Failed = true
			}
		default:
			if s.Settings.verbose {
				fmt.Printf("skipped %s check: defect %v\n", s.Settings.severity, defect)
			}
		}
	}
}

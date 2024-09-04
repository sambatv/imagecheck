package app

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strings"
)

// ScanRunnerConfig represents the configuration for a ScanRunner.
type ScanRunnerConfig struct {
	Severity        string
	IgnoreFixStates string
	PipelineMode    bool
	Verbose         bool
	DryRun          bool
}

// ScanRunner runs scans.
type ScanRunner struct {
	Config ScanRunnerConfig
}

// NewScanRunner creates a new configured ScanRunner.
func NewScanRunner(config ScanRunnerConfig) *ScanRunner {
	return &ScanRunner{Config: config}
}

// Scan runs the scans and returns their results.
func (r *ScanRunner) Scan(image string) []Scan {
	runScan := func(scanner, scanType, scanTarget string) Scan {
		return ScanTools[scanner].Scan(scanType, scanTarget, r.Config.Severity, r.Config.DryRun, r.Config.PipelineMode)
	}

	scans := make([]Scan, 0)
	scans = append(scans, runScan("grype", "files", currentDir))
	//scans = append(scans, runScan("trivy", "config", currentDir))
	//scans = append(scans, runScan("trivy", "files", currentDir))
	//scans = append(scans, runScan("trufflehog", "files", currentDir))
	if image != "" {
		scans = append(scans, runScan("grype", "image", image))
		//scans = append(scans, runScan("trivy", "image", image))
		//scans = append(scans, runScan("trufflehog", "image", image))
	}
	return scans
}

// ScanTool defines behaviors for a scanner application used to scan a target for a type of defect or vulnerability.
type ScanTool interface {
	// Scan scans a target for a type of defect or vulnerability.
	Scan(scanType, scanTarget, severity string, dryRun, pipelineMode bool) Scan

	// Name returns the name of the scanner application.
	Name() string

	// Version returns the version of the scanner application.
	Version() string
}

// ScanTools is a map of scanners by name.
var ScanTools = map[string]ScanTool{
	"grype":      &GrypeScanner{},
	"trivy":      &TrivyScanner{},
	"trufflehog": &TrufflehogScanner{},
}

// execScanner executes a scan tool command line and returns its exit code, stdout and stderr.
func execScanner(cmdline string, dryRun, pipelineMode bool) (int, []byte, error) {
	if dryRun {
		fmt.Println(cmdline)
		return 0, []byte{}, nil
	}

	var (
		exitCode int
		stdout   []byte
		err      error
	)
	if pipelineMode {
		fmt.Printf("\nrunning: %s\n", cmdline)
	}

	// Build command.
	parts := strings.Fields(cmdline)
	executable := parts[0]
	args := parts[1:]
	cmd := exec.Command(executable, args...)

	// If not in pipeline mode, print the command's stderr, typically progress info, to the console.
	if !pipelineMode {
		cmd.Stderr = os.Stderr
	}

	// Execute command and return its exit code, output, and any error.
	if stdout, err = cmd.Output(); err != nil {
		var exitErr *exec.ExitError
		if errors.As(err, &exitErr) {
			err = nil
			exitCode = exitErr.ExitCode()
		}
	}

	// If not in pipeline mode, print the command's stdout to the console.
	if !pipelineMode {
		fmt.Println(string(stdout))
	}
	return exitCode, stdout, err
}

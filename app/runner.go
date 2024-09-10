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
	DryRun       bool
	Verbose      bool
	PipelineMode bool
	Severity     string
	Ignore       []string
	Settings     *ScanSettings
}

// ScanRunner runs scans.
type ScanRunner struct {
	cfg ScanRunnerConfig
}

// NewScanRunner creates a new configured ScanRunner.
func NewScanRunner(config ScanRunnerConfig) *ScanRunner {
	return &ScanRunner{cfg: config}
}

// Scan runs the scans and returns their results.
func (r ScanRunner) Scan(image string) []Scan {
	runScan := func(scanTool, scanType, scanTarget string) Scan {
		return ScanTools[scanTool].Scan(scanType, scanTarget, r.cfg.Severity, r.cfg.Ignore, r.cfg.DryRun, r.cfg.PipelineMode)
	}

	scans := make([]Scan, 0)
	for _, setting := range r.cfg.Settings.Scans {
		if setting.Disabled {
			if r.cfg.Verbose {
				fmt.Printf("skipping disabled scan: %s %s\n", setting.ScanTool, setting.ScanType)
			}
			continue
		}
		if setting.ScanType == "image" && image == "" {
			if r.cfg.Verbose {
				fmt.Printf("skipping image scan with no image argument: %s %s\n", setting.ScanTool, setting.ScanType)
			}
			continue
		}
		scanTarget := currentDir
		if setting.ScanType == "image" {
			scanTarget = image
		}
		scans = append(scans, runScan(setting.ScanTool, setting.ScanType, scanTarget))
	}
	return scans
}

// ScanTool defines behaviors for a scanner application used to scan a target for a type of defect or vulnerability.
type ScanTool interface {
	// Scan scans a target for a type of defect or vulnerability.
	Scan(scanType, scanTarget, severity string, ignore []string, dryRun, pipelineMode bool) Scan

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
		fmt.Printf("running: %s\n", cmdline)
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

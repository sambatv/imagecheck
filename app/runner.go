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
	IgnoreCVEs   []string
	IgnoreStates []string
	Settings     ScansSettings
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
func (r ScanRunner) Scan(image string) []*Scan {
	runScan := func(scanTool, scanType, scanTarget string) *Scan {
		// Find the scan settings from those loaded from the settings file.
		scanSettings := r.cfg.Settings.FindScanSetting(scanTool, scanType)

		// Enrich the scan settings with the runtime configuration passed in from the command line.
		scanSettings.dryRun = r.cfg.DryRun
		scanSettings.pipelineMode = r.cfg.PipelineMode
		scanSettings.severity = r.cfg.Severity
		scanSettings.verbose = r.cfg.Verbose

		// Run the scan.
		return scanToolsRegistry[scanTool].Scan(scanTarget, scanSettings)
	}

	// Run scans based on scan settings.
	scans := make([]*Scan, 0)
	for _, setting := range r.cfg.Settings.ScanSettings {
		// Skip scan if disabled in settings.
		if setting.Disabled {
			if r.cfg.Verbose {
				fmt.Printf("skipping disabled scan: %s %s\n", setting.ScanTool, setting.ScanType)
			}
			continue
		}

		// Otherwise, determine the scan target.
		scanTarget := currentDir
		if setting.ScanType == "image" {
			scanTarget = image
		}

		// Then run the scan and append its result to the scan results being returned.
		scans = append(scans, runScan(setting.ScanTool, setting.ScanType, scanTarget))
	}
	return scans
}

// ScanTool defines behaviors for a scanner application used to scan a target for a type of defect or vulnerability.
type ScanTool interface {
	// Scan scans a target for a type of defect or vulnerability.
	Scan(target string, settings *ScanSettings) *Scan

	// Version returns the version of the scanner application.
	Version() string
}

// scanToolsRegistry is a registry of ScanTool objects mapped by name.
var scanToolsRegistry = map[string]ScanTool{
	"grype":      &GrypeScanner{},
	"trivy":      &TrivyScanner{},
	"trufflehog": &TrufflehogScanner{},
}

// execScanner executes a scan tool command line per its settings and returns its exit code, stdout and stderr.
func execScanner(cmdline string, settings *ScanSettings) (int, []byte, error) {
	if settings.dryRun {
		fmt.Println(cmdline)
		return 0, []byte{}, nil
	}

	var (
		exitCode int
		stdout   []byte
		err      error
	)
	if settings.pipelineMode || settings.verbose {
		fmt.Printf("running: %s\n", cmdline)
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

	// Execute command and return its exit code, output, and any error.
	if stdout, err = cmd.Output(); err != nil {
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
	return exitCode, stdout, err
}

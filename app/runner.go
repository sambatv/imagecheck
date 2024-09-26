package app

import (
	"fmt"
)

// ScanRunnerConfig represents the configuration for a ScanRunner.
type ScanRunnerConfig struct {
	DryRun       bool
	Verbose      bool
	PipelineMode bool
	Settings     *ScansSettings
}

// ScanRunner runs scans.
type ScanRunner struct {
	cfg       ScanRunnerConfig
	scanTools map[string]ScanTool
}

// NewScanRunner creates a new configured ScanRunner.
func NewScanRunner(cfg ScanRunnerConfig) *ScanRunner {
	// Build a registry of scan tools enabled in scans settings.
	scanTools := make(map[string]ScanTool)
	for _, scanSettings := range cfg.Settings.ScansSettings {
		// Skip scan tool if disabled in settings.
		if scanSettings.Disabled {
			continue
		}
		// Skip scan tool if previously added to the registry.
		if _, exists := scanTools[scanSettings.ScanTool]; exists {
			continue
		}

		// Enrich the scan settings with the runtime configuration passed in from the command line.
		scanSettings.dryRun = cfg.DryRun
		scanSettings.verbose = cfg.Verbose
		scanSettings.pipelineMode = cfg.PipelineMode
		scanSettings.severity = cfg.Settings.Severity
		scanSettings.ignoreFixStates = cfg.Settings.IgnoreFixStates
		scanSettings.ignoreIDs = cfg.Settings.IgnoreIDs
		// Add the new scan tool to the registry.
		scanTools[scanSettings.ScanTool] = newScanTool(scanSettings)
	}
	return &ScanRunner{
		cfg:       cfg,
		scanTools: scanTools,
	}
}

// Tools returns the enabled scan tools used by the runner.
func (r ScanRunner) Tools() map[string]ScanTool {
	return r.scanTools
}

// Scan runs the scans and returns their results.
func (r ScanRunner) Scan(image string) []*Scan {
	runScan := func(scanTool ScanTool, scanType, scanTarget string, scanSettings *ScanSettings) *Scan {
		scan := scanTool.Scan(scanTarget, scanSettings)
		scan.Score()
		return scan
	}

	// Run scans based on scan settings.
	scans := make([]*Scan, 0)
	for _, scanSetting := range r.cfg.Settings.ScansSettings {
		// Skip scan if disabled in settings.
		if scanSetting.Disabled {
			if r.cfg.Verbose || r.cfg.PipelineMode {
				fmt.Printf("skipping disabled scan: %s %s\n", scanSetting.ScanTool, scanSetting.ScanType)
			}
			continue
		}

		// Otherwise, determine the scan tool and target.
		scanTool := r.scanTools[scanSetting.ScanTool]
		scanTarget := currentDir
		if scanSetting.ScanType == "image" {
			scanTarget = image
		}

		// Then run the scan and append its result to the scan results being returned.
		scans = append(scans, runScan(scanTool, scanSetting.ScanType, scanTarget, scanSetting))
	}
	return scans
}

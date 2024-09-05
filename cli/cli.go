// Package cli provides the application command line interface.
package cli

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime/debug"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/fatih/color"
	"github.com/rodaine/table"
	"github.com/urfave/cli/v2"

	"github.com/sambatv/imagecheck/app"
)

// ----------------------------------------------------------------------------
// CLI application metadata
// ----------------------------------------------------------------------------

const usage = "Check image for defects and vulnerabilities"
const description = `This application checks a container image and all associated source code and
configuration artifacts for defects and vulnerabilities. It is intended to be
used in a CI/CD pipeline to ensure that images are safe to deploy, but is also
useful for scanning changes by developers during local development workflows.

This command runs a series of scans on the repository and optionally on a
container image. When run in a repository root directory with no arguments
it performs the following scans:
 
* a grype filesystem scan of the repository
* a trivy cfg scan of the repository, notably including the Dockerfile
* a trivy filesystem scan of the repository
* a trufflehog filesystem scan of the repository

If an optional image argument is provided it performs the following additional
scans on that image:

* a grype image scan of the image
* a trufflehog image scan of the image

Only a single image argument is allowed.

The --severity option specifies the severity level at which the application
should fail the scan.  The default severity level is "medium", which is an
ISO requirement for us. 

Valid --severity values include "critical", "high", "medium", and "low".

If the --dry-run option is provided, the scanner commands will not actually be
run, and will simply be displayed.

When run in pipeline mode with the --pipeline option, the scans output and
summaries are cached locally and written to an AWS S3 bucket. When running in
pipeline mode, provide the following additional options:

* --s3-bucket      The S3 bucket to upload scan results to
* --s3-key-prefix  The S3 key prefix to upload scan results to (optional, defaults to the application name)
* --git-repo       The Git repository id of the application being scanned
* --build-id       The Git repository pipeline build id of the application being scanned

When run in pipeline mode, the app requires AWS IAM permissions to upload scans
output and summaries to bucket configured for use.`

// ----------------------------------------------------------------------------
// CLI application "constants"
// ----------------------------------------------------------------------------

func init() {
	var err error
	if buildInfo, err = getBuildInfo(); err != nil {
		panic(err)
	}
}

var buildInfo BuildInfo

var defaultCacheDir = fmt.Sprintf("~/.cache/%s", app.Name)

const defaultSeverity = "medium"

var validSeverities = []string{"critical", "high", "medium", "low"}

var validIgnoreFixStates = []string{"fixed", "not-fixed", "wont-fix", "unknown"}

// ----------------------------------------------------------------------------
// CLI application flags
// ----------------------------------------------------------------------------

var cfg struct {
	DryRun          bool   `json:"dryRun"`
	Force           bool   `json:"force"`
	Verbose         bool   `json:"verbose"`
	Severity        string `json:"severity"`
	IgnoreFixStates string `json:"ignoreFixStates"`
	Pipeline        bool   `json:"pipeline"`
	GitRepo         string `json:"gitRepo"`
	BuildId         string `json:"buildId"`
	CacheDir        string `json:"cacheDir"`
	S3Bucket        string `json:"s3Bucket"`
	S3KeyPrefix     string `json:"s3KeyPrefix"`
}

var dryRunFlag = cli.BoolFlag{
	Name:        "dry-run",
	Usage:       "perform a dry run without actually running the scans",
	Destination: &cfg.DryRun,
	EnvVars:     []string{fmt.Sprintf("%s_DRYRUN", strings.ToUpper(app.Name))},
	Category:    "Scanning",
}
var forceFlag = cli.BoolFlag{
	Name:        "force",
	Aliases:     []string{"f"},
	Usage:       "force reporting action, if needed",
	Destination: &cfg.Force,
	EnvVars:     []string{fmt.Sprintf("%s_FORCE", strings.ToUpper(app.Name))},
	Category:    "Reporting",
}

var verboseFlag = cli.BoolFlag{
	Name:        "verbose",
	Aliases:     []string{"v"},
	Usage:       "show verbose output",
	Destination: &cfg.Verbose,
	EnvVars:     []string{fmt.Sprintf("%s_VERBOSE", strings.ToUpper(app.Name))},
	Category:    "Info",
}

var severityFlag = cli.StringFlag{
	Name:        "severity",
	Aliases:     []string{"s"},
	Usage:       "fail check if any defects or vulnerabilities meets or exceeds the specified severity",
	Value:       defaultSeverity,
	Destination: &cfg.Severity,
	EnvVars:     []string{fmt.Sprintf("%s_SEVERITY", strings.ToUpper(app.Name))},
	Category:    "Scanning",
}

var ignoreFixStatesFlag = cli.StringFlag{
	Name:        "ignore",
	Aliases:     []string{"i"},
	Destination: &cfg.IgnoreFixStates,
	Usage:       "ignore defects or vulnerabilities with any of the specified fix states",
	EnvVars:     []string{fmt.Sprintf("%s_IGNOREFIXSTATES", strings.ToUpper(app.Name))},
	Category:    "Scanning",
}

var pipelineFlag = cli.BoolFlag{
	Name:        "pipeline",
	Aliases:     []string{"p"},
	Usage:       "run in pipeline mode",
	Destination: &cfg.Pipeline,
	EnvVars:     []string{fmt.Sprintf("%s_PIPELINE", strings.ToUpper(app.Name))},
	Category:    "Reporting",
}

var gitRepoFlag = cli.StringFlag{
	Name:        "git-repo",
	Usage:       "id of git repository containing application being scanned",
	Destination: &cfg.GitRepo,
	EnvVars:     []string{fmt.Sprintf("%s_GITREPO", strings.ToUpper(app.Name))},
	Category:    "Reporting",
}

var buildIdFlag = cli.StringFlag{
	Name:        "build-id",
	Usage:       "build id of git repository pipeline of application being scanned",
	Destination: &cfg.BuildId,
	EnvVars:     []string{fmt.Sprintf("%s_BUILDID", strings.ToUpper(app.Name))},
	Category:    "Reporting",
}

var cacheDirFlag = cli.StringFlag{
	Name:        "cache-dir",
	Usage:       "cache directory for S3 uploads in pipeline mode",
	Destination: &cfg.CacheDir,
	Value:       defaultCacheDir,
	EnvVars:     []string{fmt.Sprintf("%s_CACHEDIR", strings.ToUpper(app.Name))},
	Category:    "Reporting",
}

var s3BucketFlag = cli.StringFlag{
	Name:        "s3-bucket",
	Usage:       "bucket to upload scan results to",
	Destination: &cfg.S3Bucket,
	EnvVars:     []string{fmt.Sprintf("%s_S3BUCKET", strings.ToUpper(app.Name))},
	Category:    "Reporting",
}

var s3KeyPrefixFlag = cli.StringFlag{
	Name:        "s3-key-prefix",
	Usage:       "key prefix to upload scan results to",
	Destination: &cfg.S3KeyPrefix,
	Value:       app.Name,
	EnvVars:     []string{fmt.Sprintf("%s_S3KEYPREFIX", strings.ToUpper(app.Name))},
	Category:    "Reporting",
}

var showConfig bool
var showConfigFlag = cli.BoolFlag{
	Name:        "config",
	Usage:       "show application configuration and exit",
	Destination: &showConfig,
	Category:    "Info",
	Hidden:      true,
}

var showBuildInfo bool
var showBuildInfoFlag = cli.BoolFlag{
	Name:        "buildinfo",
	Usage:       "show application build information and exit",
	Destination: &showBuildInfo,
	Category:    "Info",
	Hidden:      true,
}

var showScanners bool
var showScannersFlag = cli.BoolFlag{
	Name:        "scanners",
	Usage:       "show application scanners and exit",
	Destination: &showScanners,
	Category:    "Info",
	Hidden:      true,
}

var showVersion bool
var showVersionFlag = cli.BoolFlag{
	Name:        "version",
	Usage:       "show application version and exit",
	Destination: &showVersion,
	Category:    "Info",
	Hidden:      true,
}

// ----------------------------------------------------------------------------
// CLI application
// ----------------------------------------------------------------------------

// New creates a new cli application.
func New() *cli.App {
	return &cli.App{
		Name:                 app.Name,
		Usage:                usage,
		Description:          description,
		EnableBashCompletion: true,
		Flags: []cli.Flag{
			&dryRunFlag,
			&forceFlag,
			&verboseFlag,
			&severityFlag,
			&ignoreFixStatesFlag,
			&pipelineFlag,
			&gitRepoFlag,
			&buildIdFlag,
			&cacheDirFlag,
			&s3BucketFlag,
			&s3KeyPrefixFlag,
			&showBuildInfoFlag,
			&showConfigFlag,
			&showScannersFlag,
			&showVersionFlag,
		},
		Action: func(c *cli.Context) error {
			// Show the application build info, cfg, scanner tools, version as needed and exit.
			if showBuildInfo {
				tbl := getBuildInfoTable()
				tbl.Print()
				return nil
			}
			if showConfig {
				tbl := getConfigTable()
				tbl.Print()
				return nil
			}
			if showScanners {
				tbl := getScanToolsTable()
				tbl.Print()
				return nil
			}
			if showVersion {
				fmt.Println(app.Version)
				return nil
			}

			// Ensure a single argument is provided, at most, and set the image to that argument.
			if c.NArg() > 1 {
				return fmt.Errorf("too many image arguments")
			}
			var image string
			if c.NArg() == 1 {
				image = c.Args().First()
			}

			// Ensure that ignored fix states are valid.
			for _, ignoreFixState := range strings.Split(cfg.IgnoreFixStates, ",") {
				if ignoreFixState != "" && !isValidIgnoreFixState(ignoreFixState) {
					return fmt.Errorf("invalid ignore state: %s. Chose one of %s", ignoreFixState, strings.Join(validIgnoreFixStates, ", "))
				}
			}

			// Ensure that if --s3-bucket option is provided, so are --git-repo and --build-id options.
			if cfg.S3Bucket != "" && (cfg.GitRepo == "" || cfg.BuildId == "") {
				return fmt.Errorf("--git-repo and --build-id required in pipeline mode")
			}

			// Ensure that if we're running in pipeline mode, the repo is not in a dirty state (unless forced).
			if cfg.Pipeline && buildInfo.Dirty && !cfg.Force {
				return fmt.Errorf("dirty git repository not allowed in pipeline mode")
			}

			// Normalize the --severity option value to lowercase and ensure it's valid.
			cfg.Severity = strings.ToLower(cfg.Severity)
			if !isValidSeverity(cfg.Severity) {
				return fmt.Errorf("invalid severity: %s. Chose one of %s", cfg.Severity, strings.Join(validSeverities, ", "))
			}

			// Normalize the --cache-dir option to absolute path, expanding the home directory if necessary.
			if strings.HasPrefix(cfg.CacheDir, "~/") {
				homeDir, err := os.UserHomeDir()
				if err != nil {
					return err
				}
				cacheDir := strings.TrimPrefix(cfg.CacheDir, "~/")
				cfg.CacheDir = filepath.Join(homeDir, cacheDir)
			} else {
				cfg.CacheDir, _ = filepath.Abs(cfg.CacheDir)
			}

			// Ensure required scan tools are available in PATH.
			for name := range app.ScanTools {
				if path, _ := exec.LookPath(name); path == "" {
					return fmt.Errorf("missing scanner: %s", name)
				}
			}

			// Print application details if necessary.
			if cfg.Verbose || cfg.Pipeline {
				var pipelineMode string
				if cfg.Pipeline {
					pipelineMode = "(pipeline mode)"
				}
				fmt.Printf("%s %s %s\n\n", app.Name, app.Version, pipelineMode)

				fmt.Println("BUILD")
				tbl := getBuildInfoTable()
				tbl.Print()
				fmt.Println()

				fmt.Println("CONFIG")
				tbl = getConfigTable()
				tbl.Print()
				fmt.Println()

				fmt.Println("SCANNERS")
				tbl = getScanToolsTable()
				tbl.Print()
				fmt.Println()
			}

			// Get the start time timestamp, create a scan runner, and run the scans.
			if cfg.Verbose || cfg.Pipeline {
				fmt.Println("Running scans ...")
			}
			runner := app.NewScanRunner(app.ScanRunnerConfig{
				Severity:        cfg.Severity,
				IgnoreFixStates: cfg.IgnoreFixStates,
				PipelineMode:    cfg.Pipeline,
				Verbose:         cfg.Verbose,
				DryRun:          cfg.DryRun,
			})
			beginTime := time.Now()
			scans := runner.Scan(image)

			// We're done if we're not running in pipeline mode or if running in dry run mode.
			if !cfg.Pipeline || cfg.DryRun {
				return nil
			}

			// Otherwise, continue pipeline mode processing by printing a table of scan results.
			fmt.Println("\nRESULTS")
			tbl := getScansTable(scans)
			tbl.Print()
			fmt.Println()

			// Create a new scan reporter and report the scans.
			reporter := app.NewScanReporter(app.ScanReporterConfig{
				CacheDir:    cfg.CacheDir,
				Force:       cfg.Force,
				Verbose:     cfg.Verbose,
				GitRepo:     cfg.GitRepo,
				BuildId:     cfg.BuildId,
				S3Bucket:    cfg.S3Bucket,
				S3KeyPrefix: cfg.S3KeyPrefix,
			})
			if err := reporter.Report(scans, beginTime); err != nil {
				return err
			}

			// We're done, but first check to see if any defects or vulnerabilities
			// meet or exceed the severity specified in the fail flag.
			if checkFailed(scans, cfg.Severity) {
				return fmt.Errorf("%s severity %s threshold met or exceeded", app.Name, cfg.Severity)
			}
			fmt.Printf("\n%s succeeded.\n", app.Name)
			return nil
		},
	}
}

// ----------------------------------------------------------------------------
// Utility support
// ----------------------------------------------------------------------------

func checkFailed(scans []app.Scan, severity string) bool {
	for _, scan := range scans {
		if scan.Failed(severity) {
			return true
		}
	}
	return false
}

func isValidSeverity(severity string) bool {
	return slices.Contains(validSeverities, severity)
}

func isValidIgnoreFixState(ignoreState string) bool {
	return slices.Contains(validIgnoreFixStates, ignoreState)
}

// BuildInfo represents the build information for the application.
type BuildInfo struct {
	Version   string `json:"version"`
	Commit    string `json:"commit"`
	Dirty     bool   `json:"dirty"`
	Timestamp string `json:"timestamp"`
}

// getBuildInfo returns the build information for the application.
func getBuildInfo() (BuildInfo, error) {
	buildInfo := BuildInfo{Version: app.Version}
	if info, ok := debug.ReadBuildInfo(); ok {
		for _, setting := range info.Settings {
			switch setting.Key {
			case "vcs.modified":
				dirty, _ := strconv.ParseBool(setting.Value)
				buildInfo.Dirty = dirty
			case "vcs.revision":
				buildInfo.Commit = setting.Value
			case "vcs.time":
				buildInfo.Timestamp = setting.Value
			}
		}
		return buildInfo, nil
	}
	return buildInfo, fmt.Errorf("failed to read build information")
}

// ----------------------------------------------------------------------------
// Pretty tables support
// ----------------------------------------------------------------------------

var headerFmt = color.New(color.FgGreen, color.Underline).SprintfFunc()
var columnFmt = color.New(color.FgYellow).SprintfFunc()

func getBuildInfoTable() table.Table {
	tbl := table.New("Name", "Value")
	tbl.WithHeaderFormatter(headerFmt).WithFirstColumnFormatter(columnFmt)
	tbl.AddRow("Version", buildInfo.Version)
	tbl.AddRow("Commit", buildInfo.Commit)
	tbl.AddRow("Timestamp", buildInfo.Timestamp)
	tbl.AddRow("Dirty", buildInfo.Dirty)
	return tbl
}

func getConfigTable() table.Table {
	tbl := table.New("Name", "Value")
	tbl.WithHeaderFormatter(headerFmt).WithFirstColumnFormatter(columnFmt)
	tbl.AddRow("Dry Run", cfg.DryRun)
	tbl.AddRow("Force", cfg.Force)
	tbl.AddRow("Verbose", cfg.Verbose)
	tbl.AddRow("Severity", cfg.Severity)
	tbl.AddRow("Ignore Fix States", cfg.IgnoreFixStates)
	tbl.AddRow("Pipeline", cfg.Pipeline)
	tbl.AddRow("Git Repo", cfg.GitRepo)
	tbl.AddRow("Build Id", cfg.BuildId)
	tbl.AddRow("Cache Dir", cfg.CacheDir)
	tbl.AddRow("S3 Bucket", cfg.S3Bucket)
	tbl.AddRow("S3 Key Prefix", cfg.S3KeyPrefix)
	return tbl
}

func getScansTable(scans []app.Scan) table.Table {
	tbl := table.New("Scan Tool", "Scan Type", "Scan Target", "Exit", "Critical", "High", "Medium", "Low", "Negligible", "Unknown", "Error")
	tbl.WithHeaderFormatter(headerFmt).WithFirstColumnFormatter(columnFmt)
	for _, scan := range scans {
		tbl.AddRow(scan.ScanTool, scan.ScanType, scan.ScanTarget, scan.ExitCode, scan.NumCritical, scan.NumHigh, scan.NumMedium, scan.NumLow, scan.NumNegligible, scan.NumUnknown, scan.Error)
	}
	return tbl
}

func getScanToolsTable() table.Table {
	tbl := table.New("Name", "Version", "Path")
	tbl.WithHeaderFormatter(headerFmt).WithFirstColumnFormatter(columnFmt)
	for name, scanner := range app.ScanTools {
		version := scanner.Version()
		if version == "" {
			version = "not found"
		}
		path, _ := exec.LookPath(name)
		if path == "" {
			path = "not found"
		}
		tbl.AddRow(name, version, path)
	}
	return tbl
}

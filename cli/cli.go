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
* a trivy config scan of the repository, notably including the Dockerfile
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

var config struct {
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
	Usage:       "Perform a dry run without actually running the scans",
	Destination: &config.DryRun,
	EnvVars:     []string{fmt.Sprintf("%s_DRYRUN", strings.ToUpper(app.Name))},
	Category:    "Scanning",
}
var forceFlag = cli.BoolFlag{
	Name:        "force",
	Aliases:     []string{"f"},
	Usage:       "Force scan results caching and S3 uploading if artifacts already exists",
	Destination: &config.Force,
	EnvVars:     []string{fmt.Sprintf("%s_FORCE", strings.ToUpper(app.Name))},
	Category:    "Reporting",
}

var verboseFlag = cli.BoolFlag{
	Name:        "verbose",
	Aliases:     []string{"v"},
	Usage:       "Display verbose output",
	Destination: &config.Verbose,
	EnvVars:     []string{fmt.Sprintf("%s_VERBOSE", strings.ToUpper(app.Name))},
	Category:    "Miscellaneous",
}

var severityFlag = cli.StringFlag{
	Name:        "severity",
	Aliases:     []string{"s"},
	Usage:       "Fail check if any defects or vulnerabilities meets or exceeds the specified severity",
	Value:       defaultSeverity,
	Destination: &config.Severity,
	EnvVars:     []string{fmt.Sprintf("%s_SEVERITY", strings.ToUpper(app.Name))},
	Category:    "Scanning",
}

var ignoreFixStatesFlag = cli.StringFlag{
	Name:        "ignore",
	Aliases:     []string{"i"},
	Destination: &config.IgnoreFixStates,
	Usage:       "Ignore defects or vulnerabilities with any of the specified fix states",
	EnvVars:     []string{fmt.Sprintf("%s_IGNOREFIXSTATES", strings.ToUpper(app.Name))},
	Category:    "Scanning",
}

var pipelineFlag = cli.BoolFlag{
	Name:        "pipeline",
	Aliases:     []string{"p"},
	Usage:       "Run in pipeline mode",
	Destination: &config.Pipeline,
	EnvVars:     []string{fmt.Sprintf("%s_PIPELINE", strings.ToUpper(app.Name))},
	Category:    "Reporting",
}

var gitRepoFlag = cli.StringFlag{
	Name:        "git-repo",
	Usage:       "The git repository id containing the application being scanned",
	Destination: &config.GitRepo,
	EnvVars:     []string{fmt.Sprintf("%s_GITREPO", strings.ToUpper(app.Name))},
	Category:    "Reporting",
}

var buildIdFlag = cli.StringFlag{
	Name:        "build-id",
	Usage:       "The build id of the git repository pipeline of the application being scanned",
	Destination: &config.BuildId,
	EnvVars:     []string{fmt.Sprintf("%s_BUILDID", strings.ToUpper(app.Name))},
	Category:    "Reporting",
}

var cacheDirFlag = cli.StringFlag{
	Name:        "cache-dir",
	Usage:       "The cache directory for S3 uploads in pipeline mode",
	Destination: &config.CacheDir,
	Value:       defaultCacheDir,
	EnvVars:     []string{fmt.Sprintf("%s_CACHEDIR", strings.ToUpper(app.Name))},
	Category:    "Reporting",
}

var s3BucketFlag = cli.StringFlag{
	Name:        "s3-bucket",
	Usage:       "The S3 bucket to upload scan results to",
	Destination: &config.S3Bucket,
	EnvVars:     []string{fmt.Sprintf("%s_S3BUCKET", strings.ToUpper(app.Name))},
	Category:    "Reporting",
}

var s3KeyPrefixFlag = cli.StringFlag{
	Name:        "s3-key-prefix",
	Usage:       "The S3 key prefix to upload scan results to",
	Destination: &config.S3KeyPrefix,
	Value:       app.Name,
	EnvVars:     []string{fmt.Sprintf("%s_S3KEYPREFIX", strings.ToUpper(app.Name))},
	Category:    "Reporting",
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
		},
		Action: func(c *cli.Context) error {
			// Ensure a single argument is provided, at most, and set the image to that argument.
			if c.NArg() > 1 {
				return fmt.Errorf("too many image arguments")
			}
			var image string
			if c.NArg() == 1 {
				image = c.Args().First()
			}

			// Ensure that ignored fix states are valid.
			for _, ignoreFixState := range strings.Split(config.IgnoreFixStates, ",") {
				if ignoreFixState != "" && !isValidIgnoreFixState(ignoreFixState) {
					return fmt.Errorf("invalid ignore state: %s. Chose one of %s", ignoreFixState, strings.Join(validIgnoreFixStates, ", "))
				}
			}

			// Ensure that if --s3-bucket option is provided, so are --git-repo and --build-id options.
			if config.S3Bucket != "" && (config.GitRepo == "" || config.BuildId == "") {
				return fmt.Errorf("--git-repo and --build-id required in pipeline mode")
			}

			// Ensure that if we're running in pipeline mode, the repo is not in a dirty state (unless forced).
			if config.Pipeline && buildInfo.Dirty && !config.Force {
				return fmt.Errorf("dirty git repository not allowed in pipeline mode")
			}

			// Normalize the --severity option value to lowercase and ensure it's valid.
			config.Severity = strings.ToLower(config.Severity)
			if !isValidSeverity(config.Severity) {
				return fmt.Errorf("invalid severity: %s. Chose one of %s", config.Severity, strings.Join(validSeverities, ", "))
			}

			// Normalize the --cache-dir option to absolute path, expanding the home directory if necessary.
			if strings.HasPrefix(config.CacheDir, "~/") {
				homeDir, err := os.UserHomeDir()
				if err != nil {
					return err
				}
				cacheDir := strings.TrimPrefix(config.CacheDir, "~/")
				config.CacheDir = filepath.Join(homeDir, cacheDir)
			} else {
				config.CacheDir, _ = filepath.Abs(config.CacheDir)
			}

			// Ensure required scan tools are available in PATH.
			for name := range app.ScanTools {
				if path, _ := exec.LookPath(name); path == "" {
					return fmt.Errorf("missing scanner: %s", name)
				}
			}

			// Print application details if necessary.
			if config.Verbose || config.Pipeline {
				var pipelineMode string
				if config.Pipeline {
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
			if config.Verbose || config.Pipeline {
				fmt.Println("Running scans ...")
			}
			runner := app.NewScanRunner(app.ScanRunnerConfig{
				Severity:        config.Severity,
				IgnoreFixStates: config.IgnoreFixStates,
				PipelineMode:    config.Pipeline,
				Verbose:         config.Verbose,
				DryRun:          config.DryRun,
			})
			beginTime := time.Now()
			scans := runner.Scan(image)

			// We're done if we're not running in pipeline mode or if running in dry run mode.
			if !config.Pipeline || config.DryRun {
				return nil
			}

			// Otherwise, continue pipeline mode processing by printing a table of scan results.
			fmt.Println("\nRESULTS")
			tbl := getScansTable(scans)
			tbl.Print()
			fmt.Println()

			// Create a new scan reporter and report the scans.
			reporter := app.NewScanReporter(app.ScanReporterConfig{
				CacheDir:    config.CacheDir,
				Force:       config.Force,
				Verbose:     config.Verbose,
				GitRepo:     config.GitRepo,
				BuildId:     config.BuildId,
				S3Bucket:    config.S3Bucket,
				S3KeyPrefix: config.S3KeyPrefix,
			})
			if err := reporter.Report(scans, beginTime); err != nil {
				return err
			}

			// We're done, but first check to see if any defects or vulnerabilities
			// meet or exceed the severity specified in the fail flag.
			if checkFailed(scans, config.Severity) {
				return fmt.Errorf("%s severity %s threshold met or exceeded", app.Name, config.Severity)
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
	tbl.AddRow("Dry Run", config.DryRun)
	tbl.AddRow("Force", config.Force)
	tbl.AddRow("Verbose", config.Verbose)
	tbl.AddRow("Severity", config.Severity)
	tbl.AddRow("Ignore Fix States", config.IgnoreFixStates)
	tbl.AddRow("Pipeline", config.Pipeline)
	tbl.AddRow("Git Repo", config.GitRepo)
	tbl.AddRow("Build Id", config.BuildId)
	tbl.AddRow("Cache Dir", config.CacheDir)
	tbl.AddRow("S3 Bucket", config.S3Bucket)
	tbl.AddRow("S3 Key Prefix", config.S3KeyPrefix)
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

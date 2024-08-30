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
// CLI application docs
// ----------------------------------------------------------------------------

const scanCmdDocs = `This command checks a container image and all associated source code and
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

When run in pipeline mode, the scans output and summaries are written to an
AWS S3 bucket. To enable pipeline mode, provide the following options:

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
	if defaultCacheDir, err = homeDirPath(".cache", app.Name); err != nil {
		panic(err)
	}
}

var buildInfo BuildInfo

var defaultCacheDir string

const defaultSeverity = "medium"

var validSeverities = []string{"critical", "high", "medium", "low"}

var validIgnoreFixStates = []string{"fixed", "not-fixed", "wont-fix", "unknown"}

// ----------------------------------------------------------------------------
// CLI application flags
// ----------------------------------------------------------------------------

var force bool
var forceFlag = cli.BoolFlag{
	Name:        "force",
	Aliases:     []string{"f"},
	Usage:       "Force scan results caching and S3 uploading if artifacts already exists",
	Destination: &force,
	EnvVars:     []string{fmt.Sprintf("%s_FORCE", strings.ToUpper(app.Name))},
	Category:    "Miscellaneous",
}

var verbose bool
var verboseFlag = cli.BoolFlag{
	Name:        "verbose",
	Aliases:     []string{"v"},
	Usage:       "Display verbose output",
	Destination: &verbose,
	EnvVars:     []string{fmt.Sprintf("%s_VERBOSE", strings.ToUpper(app.Name))},
	Category:    "Miscellaneous",
}

var severity string
var severityFlag = cli.StringFlag{
	Name:        "severity",
	Aliases:     []string{"s"},
	Usage:       "Fail check if any defects or vulnerabilities meets or exceeds the specified severity",
	Value:       defaultSeverity,
	Destination: &severity,
	EnvVars:     []string{fmt.Sprintf("%s_SEVERITY", strings.ToUpper(app.Name))},
	Category:    "Scanning",
}

var ignoreFixStates string
var ignoreFixStatesFlag = cli.StringFlag{
	Name:        "ignore",
	Aliases:     []string{"i"},
	Destination: &ignoreFixStates,
	Usage:       "Ignore defects or vulnerabilities with any of the specified fix states",
	EnvVars:     []string{fmt.Sprintf("%s_IGNOREFIXSTATES", strings.ToUpper(app.Name))},
	Category:    "Scanning",
}

var pipeline bool
var pipelineFlag = cli.BoolFlag{
	Name:        "pipeline",
	Aliases:     []string{"p"},
	Usage:       "Run in pipeline mode",
	Destination: &pipeline,
	EnvVars:     []string{fmt.Sprintf("%s_PIPELINE", strings.ToUpper(app.Name))},
	Category:    "Reporting",
}

var gitRepo string
var gitRepoFlag = cli.StringFlag{
	Name:        "git-repo",
	Usage:       "The git repository id containing the application being scanned",
	Destination: &gitRepo,
	EnvVars:     []string{fmt.Sprintf("%s_GITREPO", strings.ToUpper(app.Name))},
	Category:    "Reporting",
}

var buildId string
var buildIdFlag = cli.StringFlag{
	Name:        "build-id",
	Usage:       "The build id of the git repository pipeline of the application being scanned",
	Destination: &buildId,
	EnvVars:     []string{fmt.Sprintf("%s_BUILDID", strings.ToUpper(app.Name))},
	Category:    "Reporting",
}

var cacheDir string
var cacheDirFlag = cli.StringFlag{
	Name:        "cache-dir",
	Aliases:     []string{"d"},
	Usage:       "The cache directory for S3 uploads in pipeline mode",
	Destination: &cacheDir,
	Value:       defaultCacheDir,
	EnvVars:     []string{fmt.Sprintf("%s_CACHEDIR", strings.ToUpper(app.Name))},
	Category:    "Reporting",
}

var s3Bucket string
var s3BucketFlag = cli.StringFlag{
	Name:        "s3-bucket",
	Usage:       "The S3 bucket to upload scan results to",
	Destination: &s3Bucket,
	EnvVars:     []string{fmt.Sprintf("%s_S3BUCKET", strings.ToUpper(app.Name))},
	Category:    "Reporting",
}

var s3KeyPrefix string
var s3KeyPrefixFlag = cli.StringFlag{
	Name:        "s3-key-prefix",
	Usage:       "The S3 key prefix to upload scan results to",
	Destination: &s3KeyPrefix,
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
		Usage:                "Check image for defects and vulnerabilities",
		EnableBashCompletion: true,
		Commands: []*cli.Command{
			{
				Name:        "scan",
				Usage:       "Runs scanners and reports on defects and vulnerabilities",
				Description: scanCmdDocs,
				Flags: []cli.Flag{
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
					// Ensure a single argument is provided, at most.
					if c.NArg() > 1 {
						return fmt.Errorf("too many image arguments")
					}
					// Set the image to that single argument, if provided.
					var image string
					if c.NArg() == 1 {
						image = c.Args().First()
					}

					// Ensure that ignored fix states are valid.
					for _, ignoreFixState := range strings.Split(ignoreFixStates, ",") {
						if ignoreFixState != "" && !isValidIgnoreFixState(ignoreFixState) {
							return fmt.Errorf("invalid ignore state: %s. Chose one of %s", ignoreFixState, strings.Join(validIgnoreFixStates, ", "))
						}
					}

					// Ensure that if --s3-bucket option is provided, so are --git-repo and --build-id options.
					if s3Bucket != "" && (gitRepo == "" || buildId == "") {
						return fmt.Errorf("--git-repo and --build-id required in pipeline mode")
					}

					// Ensure that if we're running in pipeline mode, the repo is not in a dirty state (unless forced).
					if pipeline && buildInfo.Dirty && !force {
						return fmt.Errorf("dirty git repository not allowed in pipeline mode")
					}

					// Normalize the severity flag value to lowercase and ensure it's valid.
					severity = strings.ToLower(severity)
					if !isValidSeverity(severity) {
						return fmt.Errorf("invalid severity: %s. Chose one of %s", severity, strings.Join(validSeverities, ", "))
					}

					// Print application identity if we're running in verbose or pipeline mode.
					if verbose || pipeline {
						var pipelineMode string
						if pipeline {
							pipelineMode = "(pipeline mode)"
						}
						fmt.Printf("%s %s %s\n\n", app.Name, app.Version, pipelineMode)
					}

					// Ensure required scan tools are available in PATH.
					for name := range app.ScanTools {
						if path, _ := exec.LookPath(name); path == "" {
							return fmt.Errorf("missing scanner: %s", name)
						}
					}

					// Print the scan tools details if we're running in verbose or pipeline mode.
					if verbose || pipeline {
						tbl := getScanToolsTable()
						tbl.Print()
						fmt.Println()
					}

					// Get the start time timestamp, create a scan runner, and run the scans.
					fmt.Println("Running scans ...")
					runner := app.NewScanRunner(app.ScanRunnerConfig{
						Severity:        severity,
						IgnoreFixStates: ignoreFixStates,
						PipelineMode:    pipeline,
						Verbose:         verbose,
					})
					beginTime := time.Now()
					scans := runner.Scan(image)
					//endTime := time.Now()

					// If we're not running in pipeline mode, we're done.
					if !pipeline {
						return nil
					}

					// Otherwise, continue pipeline mode processing by printing a table of scan results.
					tbl := getScansTable(scans)
					fmt.Println()
					tbl.Print()
					fmt.Println()

					// Create a new scan reporter and report the scans.
					reporter := app.NewScanReporter(app.ScanReporterConfig{
						CacheDir:    cacheDir,
						Force:       force,
						Verbose:     verbose,
						GitRepo:     gitRepo,
						BuildId:     buildId,
						S3Bucket:    s3Bucket,
						S3KeyPrefix: s3KeyPrefix,
					})
					fmt.Println("\nReporting scans...")
					if err := reporter.Report(scans, beginTime); err != nil {
						return err
					}

					// We're done, but first check to see if any defects or vulnerabilities
					// meet or exceed the severity specified in the fail flag.
					if scans.Failure(severity) {
						return fmt.Errorf("%s severity %s threshold met or exceeded", app.Name, severity)
					}
					fmt.Printf("\n%s succeeded.\n", app.Name)
					return nil
				},
			},
			{
				Name:  "buildinfo",
				Usage: "Shows build information",
				Action: func(_ *cli.Context) error {
					tbl := getBuildInfoTable()
					tbl.Print()
					return nil
				},
			},
			{
				Name:  "scantools",
				Usage: "Shows scan tools details",
				Action: func(_ *cli.Context) error {
					tbl := getScanToolsTable()
					tbl.Print()
					return nil
				},
			},
			{
				Name:  "version",
				Usage: "Shows version",
				Action: func(_ *cli.Context) error {
					fmt.Println(app.Version)
					return nil
				},
			},
		},
	}
}

// ----------------------------------------------------------------------------
// Utility support
// ----------------------------------------------------------------------------

func isValidSeverity(severity string) bool {
	return slices.Contains(validSeverities, severity)
}

func isValidIgnoreFixState(ignoreState string) bool {
	return slices.Contains(validIgnoreFixStates, ignoreState)
}

//func isPipelineMode() bool {
//	return s3Bucket != "" && gitRepo != "" && buildId != ""
//}

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

// homeDirPath returns the absolute path of the home directory with the provided path parts.
func homeDirPath(parts ...string) (string, error) {
	homeDir, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}

	homeDirPath := homeDir
	if len(parts) > 0 {
		homeDirPath = filepath.Join(append([]string{homeDir}, parts...)...)
	}
	return homeDirPath, nil
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

func getScansTable(scans app.Scans) table.Table {
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

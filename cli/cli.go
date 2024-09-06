// Package cli provides the application command line interface.
package cli

import (
	"fmt"
	"os/exec"
	"slices"
	"strings"
	"time"

	"github.com/fatih/color"
	"github.com/rodaine/table"
	"github.com/urfave/cli/v2"

	"github.com/sambatv/imagecheck/app"
	"github.com/sambatv/imagecheck/metadata"
)

// ----------------------------------------------------------------------------
// CLI application constants
// ----------------------------------------------------------------------------

const defaultCacheDir = "cache"

const defaultConfigFile = ".imagecheck.json"

const defaultSeverity = "medium"

var validSeverities = []string{"critical", "high", "medium", "low"}

var validIgnoreFixStates = []string{"fixed", "not-fixed", "wont-fix", "unknown"}

// ----------------------------------------------------------------------------
// CLI application flags
// ----------------------------------------------------------------------------

var configFile string
var configFileFlag = cli.StringFlag{
	Name:        "config-file",
	Usage:       "path to configuration file",
	Value:       defaultConfigFile,
	Destination: &configFile,
	EnvVars:     []string{fmt.Sprintf("%s_CONFIGFILE", strings.ToUpper(metadata.Name))},
	Category:    "Scanning",
}

var force bool
var forceFlag = cli.BoolFlag{
	Name:        "force",
	Usage:       "force the scan to run even if the git repository is dirty",
	Destination: &force,
	EnvVars:     []string{fmt.Sprintf("%s_FORCE", strings.ToUpper(metadata.Name))},
	Category:    "Scanning",
	Hidden:      true,
}

var dryRun bool
var dryRunFlag = cli.BoolFlag{
	Name:        "dry-run",
	Usage:       "perform a dry run without actually running the scans",
	Destination: &dryRun,
	EnvVars:     []string{fmt.Sprintf("%s_DRYRUN", strings.ToUpper(metadata.Name))},
	Category:    "Scanning",
}

var verbose bool
var verboseFlag = cli.BoolFlag{
	Name:        "verbose",
	Aliases:     []string{"v"},
	Usage:       "show verbose output",
	Destination: &verbose,
	EnvVars:     []string{fmt.Sprintf("%s_VERBOSE", strings.ToUpper(metadata.Name))},
	Category:    "Info",
}

var severity string
var severityFlag = cli.StringFlag{
	Name:        "severity",
	Aliases:     []string{"s"},
	Usage:       "fail check if any defects or vulnerabilities meets or exceeds the specified severity",
	Value:       defaultSeverity,
	Destination: &severity,
	EnvVars:     []string{fmt.Sprintf("%s_SEVERITY", strings.ToUpper(metadata.Name))},
	Category:    "Scanning",
}

var ignore string
var ignoreFlag = cli.StringFlag{
	Name:        "ignore",
	Aliases:     []string{"i"},
	Destination: &ignore,
	Usage:       "ignore defects or vulnerabilities with any of the specified fix states",
	EnvVars:     []string{fmt.Sprintf("%s_IGNOREFIXSTATES", strings.ToUpper(metadata.Name))},
	Category:    "Scanning",
}

var pipeline bool
var pipelineFlag = cli.BoolFlag{
	Name:        "pipeline",
	Aliases:     []string{"p"},
	Usage:       "run in pipeline mode",
	Destination: &pipeline,
	EnvVars:     []string{fmt.Sprintf("%s_PIPELINE", strings.ToUpper(metadata.Name))},
	Category:    "Reporting",
}

var gitRepo string
var gitRepoFlag = cli.StringFlag{
	Name:        "git-repo",
	Usage:       "id of git repository containing application being scanned",
	Destination: &gitRepo,
	EnvVars:     []string{fmt.Sprintf("%s_GITREPO", strings.ToUpper(metadata.Name))},
	Category:    "Reporting",
}

var buildId string
var buildIdFlag = cli.StringFlag{
	Name:        "build-id",
	Usage:       "build id of git repository pipeline of application being scanned",
	Destination: &buildId,
	EnvVars:     []string{fmt.Sprintf("%s_BUILDID", strings.ToUpper(metadata.Name))},
	Category:    "Reporting",
}

var cacheDir string
var cacheDirFlag = cli.StringFlag{
	Name:        "cache-dir",
	Usage:       "cache directory for S3 uploads in pipeline mode",
	Destination: &cacheDir,
	Value:       defaultCacheDir,
	EnvVars:     []string{fmt.Sprintf("%s_CACHEDIR", strings.ToUpper(metadata.Name))},
	Category:    "Reporting",
}

var s3Bucket string
var s3BucketFlag = cli.StringFlag{
	Name:        "s3-bucket",
	Usage:       "bucket to upload scan results to",
	Destination: &s3Bucket,
	EnvVars:     []string{fmt.Sprintf("%s_S3BUCKET", strings.ToUpper(metadata.Name))},
	Category:    "Reporting",
}

var s3KeyPrefix string
var s3KeyPrefixFlag = cli.StringFlag{
	Name:        "s3-key-prefix",
	Usage:       "key prefix to upload scan results to",
	Destination: &s3KeyPrefix,
	Value:       metadata.Name,
	EnvVars:     []string{fmt.Sprintf("%s_S3KEYPREFIX", strings.ToUpper(metadata.Name))},
	Category:    "Reporting",
}

var disabled bool
var disabledFlag = cli.BoolFlag{
	Name:        "disable",
	Usage:       "disable application processing",
	Destination: &disabled,
	EnvVars:     []string{fmt.Sprintf("%s_DISABLED", strings.ToUpper(metadata.Name))},
	Category:    "Scanning",
	Hidden:      true,
}

// ----------------------------------------------------------------------------
// CLI application
// ----------------------------------------------------------------------------

// New creates a new cli application.
func New() *cli.App {
	return &cli.App{
		Name:                 metadata.Name,
		EnableBashCompletion: true,
		Commands: []*cli.Command{
			{
				Name:  "init",
				Usage: "Initializes imagecheck configuration in current directory",
				Action: func(c *cli.Context) error {
					if c.NArg() > 0 {
						return fmt.Errorf("too many arguments")
					}

					settings := app.NewSettings(metadata.Username, metadata.Hostname, metadata.Version)
					path := defaultConfigFile
					if err := app.SaveSettings(settings, path); err != nil {
						return err
					}
					fmt.Printf("created %s\n", path)
					return nil
				},
			},
			{
				Name:  "version",
				Usage: "Shows application version",
				Action: func(c *cli.Context) error {
					fmt.Println(metadata.Version)
					return nil
				},
			},
			{
				Name:  "buildinfo",
				Usage: "Shows application build information",
				Action: func(c *cli.Context) error {
					tbl := getBuildInfoTable()
					tbl.Print()
					return nil
				},
			},
			{
				Name:  "scanners",
				Usage: "Shows scanner tools information",
				Action: func(c *cli.Context) error {
					tbl := getScanToolsTable()
					tbl.Print()
					return nil
				},
			},
			{
				Name:  "scan",
				Usage: "Checks image for defects and vulnerabilities",
				Description: `This command checks a container image and all associated source code and
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
output and summaries to bucket configured for use.`,
				Flags: []cli.Flag{
					&configFileFlag,
					&forceFlag,
					&disabledFlag,
					&dryRunFlag,
					&verboseFlag,
					&severityFlag,
					&ignoreFlag,
					&pipelineFlag,
					&gitRepoFlag,
					&buildIdFlag,
					&cacheDirFlag,
					&s3BucketFlag,
					&s3KeyPrefixFlag,
				},
				Action: func(c *cli.Context) error {
					// Ensure application is not disabled, show the application build info,
					// config info, scanner tools info, and version info as needed and exit.
					if disabled {
						fmt.Println("exiting disabled application")
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
					for _, ignoreFixState := range strings.Split(ignore, ",") {
						if ignoreFixState != "" && !isValidIgnoreFixState(ignoreFixState) {
							return fmt.Errorf("invalid ignore state: %s. Chose one of %s", ignoreFixState, strings.Join(validIgnoreFixStates, ", "))
						}
					}

					// Ensure that if --s3-bucket option is provided, so are --git-repo and --build-id options.
					if s3Bucket != "" && (gitRepo == "" || buildId == "") {
						return fmt.Errorf("--git-repo and --build-id required in pipeline mode")
					}

					// Ensure that if we're running in pipeline mode, the repo is not in a dirty state (unless forced).
					if pipeline && metadata.Build.Dirty && !force {
						return fmt.Errorf("dirty git repository not allowed in pipeline mode")
					}

					// Normalize the --severity option value to lowercase and ensure it's valid.
					severity = strings.ToLower(severity)
					if !isValidSeverity(severity) {
						return fmt.Errorf("invalid severity: %s. Chose one of %s", severity, strings.Join(validSeverities, ", "))
					}

					// Ensure required scan tools are available in PATH.
					for name := range app.ScanTools {
						if path, _ := exec.LookPath(name); path == "" {
							return fmt.Errorf("missing scanner: %s", name)
						}
					}

					// Print application details if necessary.
					if verbose || pipeline {
						var pipelineMode string
						if pipeline {
							pipelineMode = "(pipeline mode)"
						}
						fmt.Printf("%s %s %s\n\n", metadata.Name, metadata.Version, pipelineMode)

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
					if verbose || pipeline {
						fmt.Println("Running scans ...")
					}
					runner := app.NewScanRunner(app.ScanRunnerConfig{
						Severity:        severity,
						IgnoreFixStates: ignore,
						PipelineMode:    pipeline,
						Verbose:         verbose,
						DryRun:          dryRun,
					})
					beginTime := time.Now()
					scans := runner.Scan(image)

					// We're done if we're not running in pipeline mode or if running in dry run mode.
					if !pipeline || dryRun {
						return nil
					}

					// Otherwise, continue pipeline mode processing by printing a table of scan results.
					fmt.Println("\nRESULTS")
					tbl := getScansTable(scans)
					tbl.Print()
					fmt.Println()

					// Create a new scan reporter and report the scans.
					reporter := app.NewScanReporter(app.ScanReporterConfig{
						CacheDir:    cacheDir,
						Verbose:     verbose,
						GitRepo:     gitRepo,
						BuildId:     buildId,
						S3Bucket:    s3Bucket,
						S3KeyPrefix: s3KeyPrefix,
					})
					if err := reporter.Report(scans, beginTime); err != nil {
						return err
					}

					// We're done, but first check to see if any defects or vulnerabilities
					// meet or exceed the severity specified in the fail flag.
					if checkFailed(scans, severity) {
						return fmt.Errorf("%s severity %s threshold met or exceeded", metadata.Name, severity)
					}
					fmt.Printf("\n%s succeeded.\n", metadata.Name)
					return nil
				},
			},
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

// ----------------------------------------------------------------------------
// Pretty tables support
// ----------------------------------------------------------------------------

var headerFmt = color.New(color.FgGreen, color.Underline).SprintfFunc()
var columnFmt = color.New(color.FgYellow).SprintfFunc()

func getBuildInfoTable() table.Table {
	tbl := table.New("Name", "Value")
	tbl.WithHeaderFormatter(headerFmt).WithFirstColumnFormatter(columnFmt)
	tbl.AddRow("Commit", metadata.Build.Commit)
	tbl.AddRow("Timestamp", metadata.Build.Timestamp)
	tbl.AddRow("Dirty", metadata.Build.Dirty)
	return tbl
}

func getConfigTable() table.Table {
	tbl := table.New("Name", "Value")
	tbl.WithHeaderFormatter(headerFmt).WithFirstColumnFormatter(columnFmt)
	tbl.AddRow("Dry Run", dryRun)
	tbl.AddRow("Verbose", verbose)
	tbl.AddRow("Severity", severity)
	tbl.AddRow("Ignore ", ignore)
	tbl.AddRow("Pipeline", pipeline)
	tbl.AddRow("Git Repo", gitRepo)
	tbl.AddRow("Build Id", buildId)
	tbl.AddRow("Cache Dir", cacheDir)
	tbl.AddRow("S3 Bucket", s3Bucket)
	tbl.AddRow("S3 Key Prefix", s3KeyPrefix)
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

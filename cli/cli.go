// Package cli provides the application command line interface.
package cli

import (
	"fmt"
	"os"
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

const (
	defaultCacheDir = "cache"
	defaultSeverity = "medium"
)

var (
	defaultSettingsFile  = fmt.Sprintf(".%s.settings.json", metadata.Name)
	validSeverities      = []string{"critical", "high", "medium", "low"}
	validIgnoreFixStates = []string{"fixed", "not-fixed", "wont-fix", "unknown"}
)

// ----------------------------------------------------------------------------
// CLI application flags
// ----------------------------------------------------------------------------

var settingsFileFlag = cli.StringFlag{
	Name:     "settings-file",
	Usage:    "settings file `PATH`",
	Value:    defaultSettingsFile,
	EnvVars:  []string{fmt.Sprintf("%s_SETTINGS_FILE", strings.ToUpper(metadata.Name))},
	Category: "Scanning",
}

var ignoreSettingsFlag = cli.BoolFlag{
	Name:     "ignore-settings",
	Usage:    "ignore settings file and use default settings",
	EnvVars:  []string{fmt.Sprintf("%s_IGNORE_SETTINGS", strings.ToUpper(metadata.Name))},
	Category: "Scanning",
}

var forceFlag = cli.BoolFlag{
	Name:     "force",
	Aliases:  []string{"f"},
	Usage:    "force the scan to run even if the git repository is dirty when in pipeline mode",
	EnvVars:  []string{fmt.Sprintf("%s_FORCE", strings.ToUpper(metadata.Name))},
	Category: "Scanning",
	Hidden:   true,
}

var dryRunFlag = cli.BoolFlag{
	Name:     "dry-run",
	Usage:    "perform a dry run without actually running the scans",
	EnvVars:  []string{fmt.Sprintf("%s_DRY_RUN", strings.ToUpper(metadata.Name))},
	Category: "Scanning",
}

var verboseFlag = cli.BoolFlag{
	Name:     "verbose",
	Aliases:  []string{"v"},
	Usage:    "show verbose output",
	EnvVars:  []string{fmt.Sprintf("%s_VERBOSE", strings.ToUpper(metadata.Name))},
	Category: "General",
}

var severityFlag = cli.StringFlag{
	Name:     "severity",
	Aliases:  []string{"s"},
	Usage:    "fail check if any defects or vulnerabilities meets or exceeds the specified `VALUE`",
	Value:    defaultSeverity,
	EnvVars:  []string{fmt.Sprintf("%s_SEVERITY", strings.ToUpper(metadata.Name))},
	Category: "Scanning",
}

var ignoreIDsFlag = cli.StringSliceFlag{
	Name:     "ignore-id",
	Usage:    "ignore vulnerabilities with id `ID`",
	Category: "Scanning",
}

var ignoreFixStatesFlag = cli.StringSliceFlag{
	Name:     "ignore-fix-state",
	Usage:    "ignore vulnerabilities with fix state `STATE`",
	Category: "Scanning",
}

var pipelineFlag = cli.BoolFlag{
	Name:     "pipeline",
	Aliases:  []string{"p"},
	Usage:    "run in pipeline mode",
	EnvVars:  []string{fmt.Sprintf("%s_PIPELINE", strings.ToUpper(metadata.Name))},
	Category: "General",
}

var repoIDFlag = cli.StringFlag{
	Name:     "repo-id",
	Usage:    "repo `ID` of git repository containing application being scanned, e.g., org/repo",
	Value:    metadata.GitRepoName,
	EnvVars:  []string{fmt.Sprintf("%s_REPO_ID", strings.ToUpper(metadata.Name))},
	Category: "Reporting",
}

var buildIDFlag = cli.StringFlag{
	Name:     "build-id",
	Usage:    "build `ID` of git repository pipeline of application being scanned",
	EnvVars:  []string{fmt.Sprintf("%s_BUILD_ID", strings.ToUpper(metadata.Name))},
	Category: "Reporting",
}

var cacheDirFlag = cli.StringFlag{
	Name:     "cache-dir",
	Usage:    "cache directory `PATH` for S3 uploads in pipeline mode",
	Value:    defaultCacheDir,
	EnvVars:  []string{fmt.Sprintf("%s_CACHE_DIR", strings.ToUpper(metadata.Name))},
	Category: "Reporting",
}

var s3BucketFlag = cli.StringFlag{
	Name:     "s3-bucket",
	Usage:    "bucket `NAME` to upload scan results to",
	EnvVars:  []string{fmt.Sprintf("%s_S3_BUCKET", strings.ToUpper(metadata.Name))},
	Category: "Reporting",
}

var s3KeyPrefixFlag = cli.StringFlag{
	Name:     "s3-key-prefix",
	Usage:    "bucket key `PREFIX` to upload scan results under",
	Value:    metadata.Name,
	EnvVars:  []string{fmt.Sprintf("%s_S3_KEY_PREFIX", strings.ToUpper(metadata.Name))},
	Category: "Reporting",
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
				Usage: "Initializes imagecheck settings in current directory",
				Flags: []cli.Flag{
					&settingsFileFlag,
					&verboseFlag,
					&severityFlag,
					&ignoreIDsFlag,
					&ignoreFixStatesFlag,
				},
				Action: func(cCtx *cli.Context) error {
					if cCtx.NArg() > 0 {
						return fmt.Errorf("too many arguments")
					}

					// Fetch inputs from command line options.
					settingsFile := cCtx.String("settings-file")
					verbose := cCtx.Bool("verbose")
					severity := cCtx.String("severity")
					ignoreIDs := cCtx.StringSlice("ignore-id")
					ignoreFixStates := cCtx.StringSlice("ignore-fix-state")

					// Ensure the desired settings file does not already exist.
					if fileExists(settingsFile) {
						return fmt.Errorf("settings file exists: %s", settingsFile)
					}

					// Create and save the settings file.
					settings := app.NewScansSettings(metadata.Version, severity, ignoreIDs, ignoreFixStates)
					if err := app.SaveSettings(settings, settingsFile); err != nil {
						return err
					}
					if verbose {
						fmt.Printf("created %s\n", settingsFile)
					}
					return nil
				},
			},
			{
				Name:  "version",
				Usage: "Shows application version",
				Action: func(cCtx *cli.Context) error {
					if cCtx.NArg() > 0 {
						return fmt.Errorf("no arguments allowed")
					}
					fmt.Println(metadata.Version)
					return nil
				},
			},
			{
				Name:  "buildinfo",
				Usage: "Shows application build information",
				Action: func(cCtx *cli.Context) error {
					if cCtx.NArg() > 0 {
						return fmt.Errorf("no arguments allowed")
					}
					tbl := getBuildInfoTable()
					tbl.Print()
					return nil
				},
			},
			{
				Name:  "settings",
				Usage: "Shows application settings file content",
				Flags: []cli.Flag{
					&settingsFileFlag,
					&verboseFlag,
					&severityFlag,
					&ignoreIDsFlag,
					&ignoreFixStatesFlag,
				},
				Action: func(cCtx *cli.Context) error {
					if cCtx.NArg() > 0 {
						return fmt.Errorf("no arguments allowed")
					}

					// Fetch inputs from command line options.
					settingsFile := cCtx.String("settings-file")
					verbose := cCtx.Bool("verbose")
					severity := cCtx.String("severity")
					ignoreIDs := cCtx.StringSlice("ignore-id")
					ignoreFixStates := cCtx.StringSlice("ignore-fix-state")

					// Load the scan settings from the settings file as configured or
					// create a new settings object as needed.
					var err error
					var settings *app.ScansSettings
					if fileExists(settingsFile) {
						if verbose {
							fmt.Printf("Loading settings from %s ...\n", settingsFile)
						}
						if settings, err = app.LoadSettings(settingsFile); err != nil {
							return err
						}
					} else {
						if verbose {
							fmt.Println("Using default settings ...")
						}
						settings = app.NewScansSettings(metadata.Version, severity, ignoreIDs, ignoreFixStates)
					}
					text, err := settings.ToJSON()
					if err != nil {
						return err
					}
					fmt.Printf("%s\n", text)
					return nil
				},
			},
			{
				Name:  "scanners",
				Usage: "Shows scanner tools information",
				Flags: []cli.Flag{
					&settingsFileFlag,
					&ignoreSettingsFlag,
					&verboseFlag,
					&severityFlag,
					&ignoreIDsFlag,
					&ignoreFixStatesFlag,
				},
				Action: func(cCtx *cli.Context) error {
					if cCtx.NArg() > 0 {
						return fmt.Errorf("no arguments allowed")
					}

					// Fetch inputs from command line options.
					settingsFile := cCtx.String("settings-file")
					ignoreSettings := cCtx.Bool("ignore-settings")
					verbose := cCtx.Bool("verbose")
					severity := cCtx.String("severity")
					ignoreIDs := cCtx.StringSlice("ignore-id")
					ignoreFixStates := cCtx.StringSlice("ignore-fix-state")

					// Load the scan settings from the settings file as configured or
					// create a new settings object as needed.
					var err error
					var settings *app.ScansSettings
					if fileExists(settingsFile) && !ignoreSettings {
						if verbose {
							fmt.Printf("Loading settings from %s ...\n", settingsFile)
						}
						if settings, err = app.LoadSettings(settingsFile); err != nil {
							return err
						}
					} else {
						if verbose {
							fmt.Println("Using default settings ...")
						}
						settings = app.NewScansSettings(metadata.Version, severity, ignoreIDs, ignoreFixStates)
					}

					scanTools := settings.EnabledScanTools()
					tbl := getScanToolsTable(scanTools)
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

The --ignore option specifies the fix states to ignore when reporting defects
or vulnerabilities. Valid --ignore values include "fixed", "not-fixed",
"wont-fix", and "unknown".

If the --dry-run option is provided, the scanner commands will not actually be
run, and will simply be displayed.

When run in pipeline mode with the --pipeline option, the scans output and
summaries are cached locally and written to an AWS S3 bucket. When running in
pipeline mode, provide the following additional options:

* --repo-id        The Git repository id of the application being scanned
* --build-id       The Git repository pipeline build id of the application being scanned
* --s3-bucket      The S3 bucket to upload scan results to

When run in pipeline mode, the app requires AWS IAM permissions to upload scans
output and summaries to the S3 bucket and key prefix configured for use.`,
				Flags: []cli.Flag{
					&settingsFileFlag,
					&ignoreSettingsFlag,
					&forceFlag,
					&dryRunFlag,
					&verboseFlag,
					&severityFlag,
					&ignoreIDsFlag,
					&ignoreFixStatesFlag,
					&pipelineFlag,
					&repoIDFlag,
					&buildIDFlag,
					&cacheDirFlag,
					&s3BucketFlag,
					&s3KeyPrefixFlag,
				},
				Action: func(cCtx *cli.Context) error {
					// Ensure a single image argument is provided.
					if cCtx.NArg() == 0 {
						return fmt.Errorf("missing image argument")
					}
					if cCtx.NArg() > 1 {
						return fmt.Errorf("too many image arguments")
					}
					image := cCtx.Args().First()

					// Fetch other inputs from command line options.
					settingsFile := cCtx.String("settings-file")
					ignoreSettings := cCtx.Bool("ignore-settings")
					force := cCtx.Bool("force")
					dryRun := cCtx.Bool("dry-run")
					verbose := cCtx.Bool("verbose")
					severity := cCtx.String("severity")
					ignoreIDs := cCtx.StringSlice("ignore-id")
					ignoreFixStates := cCtx.StringSlice("ignore-fix-state")
					pipeline := cCtx.Bool("pipeline")
					repoID := cCtx.String("repo-id")
					buildID := cCtx.String("build-id")
					cacheDir := cCtx.String("cache-dir")
					s3Bucket := cCtx.String("s3-bucket")
					s3KeyPrefix := cCtx.String("s3-key-prefix")

					// Load the scan settings from the settings file as configured or
					// create a new settings object as needed.
					var err error
					var settings *app.ScansSettings
					if fileExists(settingsFile) && !ignoreSettings {
						if verbose || pipeline {
							fmt.Printf("Loading settings from %s ...\n", settingsFile)
						}
						if settings, err = app.LoadSettings(settingsFile); err != nil {
							return err
						}
					} else {
						if verbose || pipeline {
							fmt.Println("Using default settings ...")
						}
						settings = app.NewScansSettings(metadata.Version, severity, ignoreIDs, ignoreFixStates)
					}

					// Exit early if disabled in settings.
					if settings.Disabled {
						fmt.Println("exiting disabled application")
						return nil
					}

					// Ensure the --severity option is valid.
					if !isValidSeverity(severity) {
						return fmt.Errorf("invalid severity: %s. Chose one of %s", severity, strings.Join(validSeverities, ", "))
					}

					// Ensure --ignore-fix-state options are valid.
					for _, ignoreFixState := range ignoreFixStates {
						if ignoreFixState != "" && !isValidIgnoreFixState(ignoreFixState) {
							return fmt.Errorf("invalid ignore fix state: %s. Chose one of %s", ignoreFixState, strings.Join(validIgnoreFixStates, ", "))
						}
					}

					// Ensure if we're running in pipeline mode, we have a build id.
					if pipeline && buildID == "" {
						return fmt.Errorf("--build-id required in pipeline mode")
					}

					// Ensure if we're running in pipeline mode, the repo is not in a dirty state (unless forced).
					if pipeline && metadata.Build.Dirty && !force {
						return fmt.Errorf("dirty git repository not allowed in pipeline mode")
					}

					// Get enabled scan tools.
					scanTools := settings.EnabledScanTools()

					// Inputs look good for processing, so let's continue on.
					// First, print the settings if we're running in pipeline mode.
					if pipeline {
						settingsText, err := settings.ToJSON()
						if err != nil {
							return err
						}
						fmt.Println("SCAN SETTINGS")
						fmt.Printf("%s\n\n", settingsText)
					}

					// Next, print application details as configured.
					if verbose || pipeline {
						fmt.Printf("%s %s\n\n", metadata.Name, metadata.Version)

						fmt.Println("BUILD")
						tbl := getBuildInfoTable()
						tbl.Print()
						fmt.Println()

						fmt.Println("CONFIG")
						tbl = getConfigTable(dryRun, verbose, severity, ignoreIDs, ignoreFixStates, pipeline, repoID, buildID, cacheDir, s3Bucket, s3KeyPrefix)
						tbl.Print()
						fmt.Println()

						fmt.Println("SCAN TOOLS")
						tbl = getScanToolsTable(scanTools)
						tbl.Print()
						fmt.Println()
					}
					// Get the start time timestamp, create a scan runner, and run the scans.
					if verbose || pipeline {
						fmt.Println("Running scans ...")
					}
					runner := app.NewScanRunner(app.ScanRunnerConfig{
						Severity:     severity,
						IgnoreCVEs:   ignoreIDs,
						IgnoreStates: ignoreFixStates,
						PipelineMode: pipeline,
						Verbose:      verbose,
						DryRun:       dryRun,
						Settings:     *settings,
					})
					beginTime := time.Now()
					scans := runner.Scan(image)

					// We're done if we're not running in pipeline mode or if running in dry run mode.
					if !pipeline || dryRun {
						return nil
					}

					// Print the table of scan results.
					fmt.Println("\nRESULTS")
					tbl := getScansTable(scans)
					tbl.Print()
					fmt.Println()

					// Create a new scan reporter and report the scans.
					reporter := app.NewScanReporter(app.ScanReporterConfig{
						CacheDir:    cacheDir,
						Verbose:     verbose,
						RepoID:      repoID,
						BuildID:     buildID,
						S3Bucket:    s3Bucket,
						S3KeyPrefix: s3KeyPrefix,
					})
					if err := reporter.Report(scanTools, scans, beginTime); err != nil {
						return err
					}

					// We're done, but first check to see if any defects or vulnerabilities
					// meet or exceed the severity specified in the fail flag.
					if checkFailed(scans) {
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

func checkFailed(scans []*app.Scan) bool {
	for _, scan := range scans {
		if scan.Failed {
			return true
		}
	}
	return false
}

func fileExists(file string) bool {
	if _, err := os.Stat(file); err != nil {
		return false
	}
	return true
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

func getConfigTable(dryRun, verbose bool, severity string, ignoreIDs, ignoreFixStates []string, pipeline bool, repoID, buildID, cacheDir, s3Bucket, s3KeyPrefix string) table.Table {
	tbl := table.New("Name", "Value")
	tbl.WithHeaderFormatter(headerFmt).WithFirstColumnFormatter(columnFmt)
	tbl.AddRow("Dry Run", dryRun)
	tbl.AddRow("Verbose", verbose)
	tbl.AddRow("Severity", severity)
	tbl.AddRow("Ignore CVS IDs", strings.Join(ignoreIDs, ", "))
	tbl.AddRow("Ignore CVE Fix States ", strings.Join(ignoreFixStates, ", "))
	tbl.AddRow("Pipeline Mode", pipeline)
	tbl.AddRow("Repo ID", repoID)
	tbl.AddRow("Build ID", buildID)
	tbl.AddRow("Cache Dir", cacheDir)
	tbl.AddRow("S3 Bucket", s3Bucket)
	tbl.AddRow("S3 Key Prefix", s3KeyPrefix)
	return tbl
}

func getScansTable(scans []*app.Scan) table.Table {
	tbl := table.New("Scan Tool", "Scan Type", "Scan Target",
		"Total", "Critical", "High", "Medium", "Low", "Negligible", "Unknown", "Ignored",
		"Exit", "Error")
	tbl.WithHeaderFormatter(headerFmt).WithFirstColumnFormatter(columnFmt)
	for _, scan := range scans {
		tbl.AddRow(scan.Settings.ScanTool, scan.Settings.ScanType, scan.Target,
			scan.NumTotal, scan.NumCritical, scan.NumHigh, scan.NumMedium, scan.NumLow, scan.NumNegligible, scan.NumUnknown, scan.NumIgnored,
			scan.ExitCode, scan.Error)
	}
	return tbl
}

func getScanToolsTable(scanners map[string]app.ScanTool) table.Table {
	tbl := table.New("Name", "Version", "Path")
	tbl.WithHeaderFormatter(headerFmt).WithFirstColumnFormatter(columnFmt)
	for name, scanTool := range scanners {
		path, err := exec.LookPath(name)
		version := scanTool.Version()
		if err != nil {
			path = "not found"
		}
		tbl.AddRow(name, version, path)
	}
	return tbl
}

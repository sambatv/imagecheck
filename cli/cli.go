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

// Options represents the command line options.
type Options struct {
	SettingsFile    string          `json:"settings_file"`
	IgnoreSettings  bool            `json:"ignore_settings"`
	Force           bool            `json:"force"`
	DryRun          bool            `json:"dry_run"`
	Verbose         bool            `json:"verbose"`
	Severity        string          `json:"severity"`
	IgnoreFailures  bool            `json:"ignore_failures"`
	IgnoreIDs       cli.StringSlice `json:"ignore_ids"`
	IgnoreFixStates cli.StringSlice `json:"ignore_fix_states"`
	Pipeline        bool            `json:"pipeline"`
	RepoID          string          `json:"repo_id"`
	BuildID         string          `json:"build_id"`
	CacheDir        string          `json:"cache_dir"`
	S3Bucket        string          `json:"s3_bucket"`
	S3KeyPrefix     string          `json:"s3_key_prefix"`
}

var options Options

var settingsFileFlag = cli.StringFlag{
	Name:        "settings-file",
	Usage:       "settings file `PATH`",
	Destination: &options.SettingsFile,
	Value:       defaultSettingsFile,
	EnvVars:     []string{fmt.Sprintf("%s_SETTINGS_FILE", strings.ToUpper(metadata.Name))},
	Category:    "Scanning",
}

var ignoreSettingsFlag = cli.BoolFlag{
	Name:        "ignore-settings",
	Usage:       "ignore settings file and use default settings",
	Destination: &options.IgnoreSettings,
	EnvVars:     []string{fmt.Sprintf("%s_IGNORE_SETTINGS", strings.ToUpper(metadata.Name))},
	Category:    "Scanning",
}

var forceFlag = cli.BoolFlag{
	Name:        "force",
	Aliases:     []string{"f"},
	Usage:       "force the scan to run even if the git repository is dirty when in pipeline mode",
	Destination: &options.Force,
	EnvVars:     []string{fmt.Sprintf("%s_FORCE", strings.ToUpper(metadata.Name))},
	Category:    "Scanning",
	Hidden:      true,
}

var dryRunFlag = cli.BoolFlag{
	Name:        "dry-run",
	Usage:       "perform a dry run without actually running the scans",
	Destination: &options.DryRun,
	EnvVars:     []string{fmt.Sprintf("%s_DRY_RUN", strings.ToUpper(metadata.Name))},
	Category:    "Scanning",
}

var verboseFlag = cli.BoolFlag{
	Name:        "verbose",
	Aliases:     []string{"v"},
	Usage:       "show verbose output",
	Destination: &options.Verbose,
	EnvVars:     []string{fmt.Sprintf("%s_VERBOSE", strings.ToUpper(metadata.Name))},
	Category:    "General",
}

var severityFlag = cli.StringFlag{
	Name:        "severity",
	Aliases:     []string{"s"},
	Usage:       "fail check if any defects or vulnerabilities meets or exceeds the specified `VALUE`",
	Destination: &options.Severity,
	Value:       defaultSeverity,
	EnvVars:     []string{fmt.Sprintf("%s_SEVERITY", strings.ToUpper(metadata.Name))},
	Category:    "Scanning",
}

var ignoreFailuresFlag = cli.BoolFlag{
	Name:        "ignore-failures",
	Usage:       "do not fail the scan if any defects or vulnerabilities are found",
	Destination: &options.IgnoreFailures,
	EnvVars:     []string{fmt.Sprintf("%s_NO_FAIL", strings.ToUpper(metadata.Name))},
	Category:    "Scanning",
}

var ignoreIDsFlag = cli.StringSliceFlag{
	Name:        "ignore-id",
	Usage:       "ignore vulnerabilities with id `ID`",
	Destination: &options.IgnoreIDs,
	Category:    "Scanning",
}

var ignoreFixStatesFlag = cli.StringSliceFlag{
	Name:        "ignore-fix-state",
	Usage:       "ignore vulnerabilities with fix state `STATE`",
	Destination: &options.IgnoreFixStates,
	Category:    "Scanning",
}

var pipelineFlag = cli.BoolFlag{
	Name:        "pipeline",
	Aliases:     []string{"p"},
	Usage:       "run in pipeline mode",
	Destination: &options.Pipeline,
	EnvVars:     []string{fmt.Sprintf("%s_PIPELINE", strings.ToUpper(metadata.Name))},
	Category:    "General",
}

var repoIDFlag = cli.StringFlag{
	Name:        "repo-id",
	Usage:       "repo `ID` of git repository containing application being scanned, e.g., org/repo",
	Destination: &options.RepoID,
	Value:       metadata.GitRepoName,
	EnvVars:     []string{fmt.Sprintf("%s_REPO_ID", strings.ToUpper(metadata.Name))},
	Category:    "Reporting",
}

var buildIDFlag = cli.StringFlag{
	Name:        "build-id",
	Usage:       "build `ID` of git repository pipeline of application being scanned",
	Destination: &options.BuildID,
	EnvVars:     []string{fmt.Sprintf("%s_BUILD_ID", strings.ToUpper(metadata.Name))},
	Category:    "Reporting",
}

var cacheDirFlag = cli.StringFlag{
	Name:        "cache-dir",
	Usage:       "cache directory `PATH` for S3 uploads in pipeline mode",
	Destination: &options.CacheDir,
	Value:       defaultCacheDir,
	EnvVars:     []string{fmt.Sprintf("%s_CACHE_DIR", strings.ToUpper(metadata.Name))},
	Category:    "Reporting",
}

var s3BucketFlag = cli.StringFlag{
	Name:        "s3-bucket",
	Usage:       "bucket `NAME` to upload scan results to",
	Destination: &options.S3Bucket,
	EnvVars:     []string{fmt.Sprintf("%s_S3_BUCKET", strings.ToUpper(metadata.Name))},
	Category:    "Reporting",
}

var s3KeyPrefixFlag = cli.StringFlag{
	Name:        "s3-key-prefix",
	Usage:       "bucket key `PREFIX` to upload scan results under",
	Destination: &options.S3KeyPrefix,
	Value:       metadata.Name,
	EnvVars:     []string{fmt.Sprintf("%s_S3_KEY_PREFIX", strings.ToUpper(metadata.Name))},
	Category:    "Reporting",
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

					// Ensure the desired settings file does not already exist.
					if fileExists(options.SettingsFile) {
						return fmt.Errorf("settings file exists: %s", options.SettingsFile)
					}

					// Create and save the settings file.
					settings := app.NewScansSettings(metadata.Version, options.Severity, options.IgnoreFailures, options.IgnoreIDs.Value(), options.IgnoreFixStates.Value())
					if err := app.SaveSettings(settings, options.SettingsFile); err != nil {
						return err
					}
					fmt.Printf("created %s\n", options.SettingsFile)
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
					&ignoreFailuresFlag,
					&ignoreIDsFlag,
					&ignoreFixStatesFlag,
				},
				Action: func(cCtx *cli.Context) error {
					if cCtx.NArg() > 0 {
						return fmt.Errorf("no arguments allowed")
					}

					// Load the scan settings from the settings file as configured or create a new settings object as needed.
					var err error
					var settings *app.ScansSettings
					if fileExists(options.SettingsFile) {
						if options.Verbose {
							fmt.Printf("Loading settings from %s ...\n", options.SettingsFile)
						}
						if settings, err = app.LoadSettings(options.SettingsFile); err != nil {
							return err
						}
					} else {
						if options.Verbose {
							fmt.Println("Using default settings ...")
						}
						settings = app.NewScansSettings(metadata.Version, options.Severity, options.IgnoreFailures, options.IgnoreIDs.Value(), options.IgnoreFixStates.Value())
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
					&ignoreFailuresFlag,
					&ignoreIDsFlag,
					&ignoreFixStatesFlag,
				},
				Action: func(cCtx *cli.Context) error {
					if cCtx.NArg() > 0 {
						return fmt.Errorf("no arguments allowed")
					}

					// Load the scan settings from the settings file as configured or create a new settings object as needed.
					var err error
					var settings *app.ScansSettings
					if fileExists(options.SettingsFile) && !options.IgnoreSettings {
						if options.Verbose {
							fmt.Printf("Loading settings from %s ...\n", options.SettingsFile)
						}
						if settings, err = app.LoadSettings(options.SettingsFile); err != nil {
							return err
						}
					} else {
						if options.Verbose {
							fmt.Println("Using default settings ...")
						}
						settings = app.NewScansSettings(metadata.Version, options.Severity, options.IgnoreFailures, options.IgnoreIDs.Value(), options.IgnoreFixStates.Value())
					}

					// Create scan runner.
					runner := app.NewScanRunner(app.ScanRunnerConfig{
						Settings: settings,
					})
					tbl := getScanToolsTable(runner.Tools())
					tbl.Print()
					return nil
				},
			},
			{
				Name:  "scan",
				Usage: "Checks image for defects and vulnerabilities",
				Description: `This command checks a container image and all associated source code and
configuration artifacts for defects and vulnerabilities using multiple scanner
tools. 

* grype
* trivy
* trufflehog

It is intended to be used in a CI/CD pipeline to ensure that images are
safe to deploy, but is also useful for scanning changes by developers during
local development workflows.

It accepts a single image argument.

The --severity option specifies the severity level at which the application
should fail the scan.  The default severity level is "medium", which is an
ISO requirement for us.

Valid --severity values include "critical", "high", "medium", and "low".

If the --ignore-failures option is provided, the application will not return a
non-zero exit code if any defects or vulnerabilities are found. This is useful
temporarily but should not be the common case, unless you simply want to be
informed of defects when running in --pipeline mode.

The --ignore-fix-state option specifies the fix states to ignore when reporting defects
or vulnerabilities. Valid --ignore values include "fixed", "not-fixed",
"wont-fix", and "unknown".

The --ignore-id option specifies an id to ignore when reporting defects
or vulnerabilities. These ids are dependent on the scan type, but are often
CVE IDs.

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
					&ignoreFailuresFlag,
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

					// Load the scan settings from the settings file as configured or create a new settings object as needed.
					var err error
					var settings *app.ScansSettings
					if fileExists(options.SettingsFile) && !options.IgnoreSettings {
						if options.Verbose || options.Pipeline {
							fmt.Printf("Loading settings from %s ...\n", options.SettingsFile)
						}
						if settings, err = app.LoadSettings(options.SettingsFile); err != nil {
							return err
						}
					} else {
						if options.Verbose || options.Pipeline {
							fmt.Println("Using default settings ...")
						}
						settings = app.NewScansSettings(metadata.Version, options.Severity, options.IgnoreFailures, options.IgnoreIDs.Value(), options.IgnoreFixStates.Value())
					}

					// Exit early if disabled in settings.
					if settings.Disabled {
						fmt.Println("exiting disabled application")
						return nil
					}

					// Ensure the --severity option is valid.
					if !isValidSeverity(options.Severity) {
						return fmt.Errorf("invalid severity: %s. Chose one of %s", options.Severity, strings.Join(validSeverities, ", "))
					}

					// Ensure --ignore-fix-state options are valid.
					for _, ignoreFixState := range options.IgnoreFixStates.Value() {
						if ignoreFixState != "" && !isValidIgnoreFixState(ignoreFixState) {
							return fmt.Errorf("invalid ignore fix state: %s. Chose one of %s", ignoreFixState, strings.Join(validIgnoreFixStates, ", "))
						}
					}

					// Ensure if we're running in pipeline mode, we have a build id.
					if options.Pipeline && options.BuildID == "" {
						return fmt.Errorf("--build-id required in pipeline mode")
					}

					// Ensure if we're running in pipeline mode, the repo is not in a dirty state (unless forced).
					if options.Pipeline && metadata.Build.Dirty && !options.Force {
						return fmt.Errorf("dirty git repository not allowed in pipeline mode")
					}

					// Create scan runner.
					runner := app.NewScanRunner(app.ScanRunnerConfig{
						PipelineMode: options.Pipeline,
						Verbose:      options.Verbose,
						DryRun:       options.DryRun,
						Settings:     settings,
					})

					// Inputs look good for processing, so let's continue on.
					// First, print the settings if we're running in pipeline mode.
					if options.Pipeline {
						settingsText, err := settings.ToJSON()
						if err != nil {
							return err
						}
						fmt.Println("SETTINGS")
						fmt.Printf("%s\n\n", settingsText)
					}

					// Next, print application details as configured.
					if options.Verbose || options.Pipeline {
						fmt.Println("BUILD")
						tbl := getBuildInfoTable()
						tbl.Print()
						fmt.Println()

						fmt.Println("OPTIONS")
						tbl = getOptionsTable(&options)
						tbl.Print()
						fmt.Println()

						fmt.Println("SCANNERS")
						tbl = getScanToolsTable(runner.Tools())
						tbl.Print()
						fmt.Println()
					}
					// Get the start time timestamp, create a scan runner, and run the scans.
					if options.Verbose || options.Pipeline {
						fmt.Println("Running scans ...")
					}
					beginTime := time.Now()
					scans := runner.Scan(image)

					// We're done if we're not running in pipeline mode or if running in dry run mode.
					if !options.Pipeline || options.DryRun {
						return nil
					}

					// Print the table of scan results.
					fmt.Println("\nRESULTS")
					tbl := getScansTable(scans, options.Verbose)
					tbl.Print()
					fmt.Println()

					// Create a new scan reporter and report the scans.
					reporter := app.NewScanReporter(app.ScanReporterConfig{
						CacheDir:    options.CacheDir,
						Verbose:     options.Verbose,
						RepoID:      options.RepoID,
						BuildID:     options.BuildID,
						S3Bucket:    options.S3Bucket,
						S3KeyPrefix: options.S3KeyPrefix,
					})
					if err := reporter.Report(runner.Tools(), scans, beginTime); err != nil {
						return err
					}

					// We're done, but first check to see if any defects or vulnerabilities
					// meet or exceed the severity specified in the fail flag.
					if checkFailed(scans) {
						// If we're ignoring failures, inform the user and return nil (exits 0).
						if options.IgnoreFailures || settings.IgnoreFailures {
							fmt.Printf("%s severity %s threshold met or exceeded", metadata.Name, options.Severity)
							return nil
						}
						// Otherwise, return an error (exits non-0).
						return fmt.Errorf("%s severity %s threshold met or exceeded", metadata.Name, options.Severity)
					}
					// All checks passed, no failures found. Inform the user and return nil (exits 0).
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

func getOptionsTable(options *Options) table.Table {
	tbl := table.New("Option", "Value")
	tbl.WithHeaderFormatter(headerFmt).WithFirstColumnFormatter(columnFmt)
	tbl.AddRow("Dry Run", options.DryRun)
	tbl.AddRow("Verbose", options.Verbose)
	tbl.AddRow("Severity", options.Severity)
	tbl.AddRow("Ignore Failures", options.IgnoreFailures)
	tbl.AddRow("Ignore CVS IDs", strings.Join(options.IgnoreIDs.Value(), ", "))
	tbl.AddRow("Ignore CVE Fix States ", strings.Join(options.IgnoreFixStates.Value(), ", "))
	tbl.AddRow("Pipeline Mode", options.Pipeline)
	tbl.AddRow("Repo ID", options.RepoID)
	tbl.AddRow("Build ID", options.BuildID)
	tbl.AddRow("Cache Dir", options.CacheDir)
	tbl.AddRow("S3 Bucket", options.S3Bucket)
	tbl.AddRow("S3 Key Prefix", options.S3KeyPrefix)
	return tbl
}

func getScansTable(scans []*app.Scan, verbose bool) table.Table {
	var tbl table.Table
	// Verbose output includes exit code and error message.
	if verbose {
		tbl = table.New("Scan Tool", "Scan Type", "Scan Target",
			"Total", "Ignored", "Critical", "High", "Medium", "Low", "Negligible", "Unknown",
			"Exit", "Error")
	} else {
		tbl = table.New("Scan Tool", "Scan Type", "Scan Target",
			"Total", "Ignored", "Critical", "High", "Medium", "Low", "Negligible", "Unknown")
	}
	tbl.WithHeaderFormatter(headerFmt).WithFirstColumnFormatter(columnFmt)
	for _, scan := range scans {
		if verbose {
			tbl.AddRow(scan.Settings.ScanTool, scan.Settings.ScanType, scan.Target,
				scan.NumTotal, scan.NumIgnored, scan.NumCritical, scan.NumHigh, scan.NumMedium, scan.NumLow, scan.NumNegligible, scan.NumUnknown,
				scan.ExitCode, scan.Error)
		} else {
			tbl.AddRow(scan.Settings.ScanTool, scan.Settings.ScanType, scan.Target,
				scan.NumTotal, scan.NumIgnored, scan.NumCritical, scan.NumHigh, scan.NumMedium, scan.NumLow, scan.NumNegligible, scan.NumUnknown)
		}
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

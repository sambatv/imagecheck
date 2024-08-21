// Package cli provides the application command line interface.
package cli

import (
	"fmt"
	"strings"
	"time"

	"github.com/fatih/color"
	"github.com/rodaine/table"
	"github.com/urfave/cli/v2"

	"github.com/sambatv/imagecheck/app"
)

// ----------------------------------------------------------------------------
// CLI application flags
// ----------------------------------------------------------------------------

var cacheDirFlag = cli.StringFlag{
	Name:        "cache-dir",
	Aliases:     []string{"d"},
	Usage:       "Specify application cache directory for S3 uploads in pipeline mode",
	Destination: &app.Config.CacheDir,
	Value:       app.DefaultCacheDir,
	EnvVars:     []string{fmt.Sprintf("%s_CACHEDIR", strings.ToUpper(app.Name))},
}

var dryRunFlag = cli.BoolFlag{
	Name:        "dry-run",
	Usage:       "Display the command that would be executed, but do not execute it",
	Destination: &app.Config.DryRun,
	EnvVars:     []string{fmt.Sprintf("%s_DRYRUN", strings.ToUpper(app.Name))},
}

var forceFlag = cli.BoolFlag{
	Name:        "force",
	Aliases:     []string{"f"},
	Usage:       "Force scan caching/publishing if already exists",
	Destination: &app.Config.Force,
	EnvVars:     []string{fmt.Sprintf("%s_FORCE", strings.ToUpper(app.Name))},
}

var verboseFlag = cli.BoolFlag{
	Name:        "verbose",
	Aliases:     []string{"v"},
	Usage:       "Display verbose output",
	Destination: &app.Config.Verbose,
	EnvVars:     []string{fmt.Sprintf("%s_VERBOSE", strings.ToUpper(app.Name))},
}

var severityFlag = cli.StringFlag{
	Name:        "severity",
	Aliases:     []string{"s"},
	Usage:       "Severity the application if any defects or vulnerabilities meets or exceeds the specified severity",
	Value:       app.DefaultSeverity,
	Destination: &app.Config.Severity,
	EnvVars:     []string{fmt.Sprintf("%s_SEVERITY", strings.ToUpper(app.Name))},
}

var imageFlag = cli.StringFlag{
	Name:        "image",
	Aliases:     []string{"i"},
	Usage:       "The name of the container image to scan",
	Destination: &app.Config.Image,
	EnvVars:     []string{fmt.Sprintf("%s_IMAGE", strings.ToUpper(app.Name))},
}

var s3BucketFlag = cli.StringFlag{
	Name:        "s3-bucket",
	Usage:       "The S3 bucket to upload scan results to",
	Destination: &app.Config.S3Bucket,
	EnvVars:     []string{fmt.Sprintf("%s_S3BUCKET", strings.ToUpper(app.Name))},
}

var s3KeyPrefixFlag = cli.StringFlag{
	Name:        "s3-key-prefix",
	Usage:       "The S3 key prefix to upload scan results to",
	Destination: &app.Config.S3KeyPrefix,
	EnvVars:     []string{fmt.Sprintf("%s_S3KEYPREFIX", strings.ToUpper(app.Name))},
}

var gitRepoFlag = cli.StringFlag{
	Name:        "git-repo",
	Usage:       "The Git repository id containing the application being scanned",
	Destination: &app.Config.GitRepo,
	EnvVars:     []string{fmt.Sprintf("%s_GITREPO", strings.ToUpper(app.CurrentDir))},
}

var buildIdFlag = cli.StringFlag{
	Name:        "build-id",
	Usage:       "The build id of the Git repository pipeline of the application being scanned",
	Destination: &app.Config.BuildId,
	EnvVars:     []string{fmt.Sprintf("%s_BUILDID", strings.ToUpper(app.Name))},
}

// ----------------------------------------------------------------------------
// CLI application
// ----------------------------------------------------------------------------

// New creates a new cli application.
func New() *cli.App {
	return &cli.App{
		Name:                 app.Name,
		Usage:                app.Usage,
		Description:          app.Description,
		EnableBashCompletion: true,
		Flags: []cli.Flag{
			&cacheDirFlag,
			&dryRunFlag,
			&forceFlag,
			&verboseFlag,
			&severityFlag,
			&imageFlag,
			&s3BucketFlag,
			&s3KeyPrefixFlag,
			&gitRepoFlag,
			&buildIdFlag,
		},
		Commands: []*cli.Command{
			{
				Name:  "scan",
				Usage: "Runs scanners",
				Action: func(_ *cli.Context) error {
					// Ensure that if we're running in pipeline mode, the repo is not in a dirty state.
					if app.Config.PipelineMode() && app.Build.Dirty {
						return fmt.Errorf("dirty git repository not allowed in pipeline mode")
					}

					// Normalize the severity flag value to lowercase and ensure it's valid.
					app.Config.Severity = strings.ToLower(app.Config.Severity)
					if !app.IsValidSeverity(app.Config.Severity) {
						return fmt.Errorf("invalid severity: %s. Chose one of %s", app.Config.Severity, strings.Join(app.ValidSeverities, ", "))
					}

					// Print the application version and configuration if we're running in verbose or pipeline mode.
					if app.Config.Verbose || app.Config.PipelineMode() {
						fmt.Printf("%s v%s\n", app.Name, app.Version)
						tbl := getConfigTable()
						fmt.Println(tbl)
					}

					// Ensure required scanners are available in PATH.
					for name, scanner := range app.Scanners {
						if scanner.Path() == "" {
							return fmt.Errorf("missing scanner: %s", name)
						}
					}

					// Print the scanner details if we're running in verbose or pipeline mode.
					if app.Config.Verbose || app.Config.PipelineMode() {
						tbl := getScannersTable()
						tbl.Print()
						fmt.Println()
					}

					// Get the start time timestamp and run the scans.
					fmt.Println("Running scans...")
					startTime := time.Now()
					scans := app.RunScans()

					// Print table of scan results.
					tbl := getScansTable(scans)
					tbl.Print()
					fmt.Println()

					// If pipeline mode is not configured, we're done.
					if !app.Config.PipelineMode() {
						// But first, check to see if any defects or vulnerabilities meet
						// or exceed the severity specified in the fail flag.
						if scans.Failure() {
							return fmt.Errorf("%s severity %s threshold met or exceeded", app.Name, app.Config.Severity)
						}
						fmt.Printf("\n%s succeeded.\n", app.Name)
						return nil
					}

					// Otherwise, create a new scans report, cache it locally, and upload cached report to S3.
					report := scans.Report(startTime)
					fmt.Println("\nCaching scans report...")
					if err := report.Cache(); err != nil {
						return err
					}
					fmt.Println("\nUploading scans report...")
					if err := report.Upload(); err != nil {
						return err
					}

					// We're done, but first check to see if any defects or vulnerabilities
					// meet or exceed the severity specified in the fail flag.
					if scans.Failure() {
						return fmt.Errorf("%s severity %s threshold met or exceeded", app.Name, app.Config.Severity)
					}
					fmt.Printf("\n%s succeeded.\n", app.Name)
					return nil
				},
			},
			{
				Name:  "buildinfo",
				Usage: "Prints application build information",
				Action: func(_ *cli.Context) error {
					tbl := getBuildInfoTable()
					tbl.Print()
					return nil
				},
			},
			{
				Name:  "config",
				Usage: "Prints application configuration",
				Action: func(_ *cli.Context) error {
					tbl := getConfigTable()
					tbl.Print()
					return nil
				},
			},
			{
				Name:  "scanners",
				Usage: "Prints application scanners details",
				Action: func(_ *cli.Context) error {
					tbl := getScannersTable()
					tbl.Print()
					return nil
				},
			},
			{
				Name:  "version",
				Usage: "Prints application version",
				Action: func(_ *cli.Context) error {
					fmt.Println(app.Version)
					return nil
				},
			},
		},
	}
}

// ----------------------------------------------------------------------------
// Pretty tables support
// ----------------------------------------------------------------------------

var headerFmt = color.New(color.FgGreen, color.Underline).SprintfFunc()
var columnFmt = color.New(color.FgYellow).SprintfFunc()

func getBuildInfoTable() table.Table {
	tbl := table.New("Name", "Value")
	tbl.WithHeaderFormatter(headerFmt).WithFirstColumnFormatter(columnFmt)
	tbl.AddRow("Version", app.Build.Version)
	tbl.AddRow("Commit", app.Build.Commit)
	tbl.AddRow("Timestamp", app.Build.Timestamp)
	tbl.AddRow("Dirty", app.Build.Dirty)
	return tbl
}
func getConfigTable() table.Table {
	tbl := table.New("Config", "Value")
	tbl.WithHeaderFormatter(headerFmt).WithFirstColumnFormatter(columnFmt)
	tbl.AddRow("Cache directory", app.Config.CacheDir)
	tbl.AddRow("Dry run", app.Config.DryRun)
	tbl.AddRow("Force", app.Config.Force)
	tbl.AddRow("Verbose", app.Config.Verbose)
	tbl.AddRow("Severity", app.Config.Severity)
	tbl.AddRow("Image", app.Config.Image)
	tbl.AddRow("S3 bucket", app.Config.S3Bucket)
	tbl.AddRow("S3 key prefix", app.Config.S3KeyPrefix)
	tbl.AddRow("Git repository", app.Config.GitRepo)
	tbl.AddRow("Build ID", app.Config.BuildId)
	return tbl
}

func getScansTable(scans app.Scans) table.Table {
	tbl := table.New("Scanner", "Scan Type", "Scan Target", "Exit Code", "Critical", "High", "Medium", "Low", "Unknown", "Error")
	tbl.WithHeaderFormatter(headerFmt).WithFirstColumnFormatter(columnFmt)
	for _, scan := range scans {
		tbl.AddRow(scan.Scanner, scan.ScanType, scan.ScanTarget, scan.ExitCode, scan.NumCritical, scan.NumHigh, scan.NumMedium, scan.NumLow, scan.NumUnknown, scan.Error)
	}
	return tbl
}

func getScannersTable() table.Table {
	tbl := table.New("Name", "Version", "Path")
	tbl.WithHeaderFormatter(headerFmt).WithFirstColumnFormatter(columnFmt)
	for name, scanner := range app.Scanners {
		version := scanner.Version()
		if version == "" {
			version = "not found"
		}
		path := scanner.Path()
		if path == "" {
			path = "not found"
		}
		tbl.AddRow(name, version, path)
	}
	return tbl
}

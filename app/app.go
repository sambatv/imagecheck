// Package app provides core application support.
package app

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"os/user"
	"path"
	"path/filepath"
	"runtime/debug"
	"strconv"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/feature/s3/manager"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/s3/types"
)

// ----------------------------------------------------------------------------
// High-level scanner support
// ----------------------------------------------------------------------------

// RunScans runs the scans and returns their results.
func RunScans() Scans {
	scans := make(Scans, 0)
	runScan := func(scanner, scanType, scanTarget string) Scan {
		return Scanners[scanner].Scan(scanType, scanTarget)
	}
	scans = append(scans, runScan("grype", "files", CurrentDir))
	scans = append(scans, runScan("trivy", "config", CurrentDir))
	scans = append(scans, runScan("trivy", "files", CurrentDir))
	//scans = append(scans, runScan("trufflehog", "files", CurrentDir))
	if Config.Image != "" {
		scans = append(scans, runScan("grype", "image", Config.Image))
		//scans = append(scans, runScan("trivy", "image", Config.Image))
		//scans = append(scans, runScan("trufflehog", "image", Config.Image))
	}
	return scans
}

// ----------------------------------------------------------------------------
// Application metadata
// ----------------------------------------------------------------------------

// Name is the name of the application.
const Name = "imagecheck"

// Usage is the usage of the application.
const Usage = "Run scans of application for defects and vulnerabilities"

// Description is the description of the application.
const Description = `This application checks a container image and all associated source code and
configuration artifacts for defects and vulnerabilities. It is intended to be
used in a CI/CD pipeline to ensure that images are safe to deploy, but is also
useful for scanning changes by developers during local development workflows.

When run in the repository root directory it performs the following scans:
 
- a grype filesystem scan of the repository
- a trivy config scan of the repository, notably including the Dockerfile
- a trivy filesystem scan of the repository
- a trufflehog filesystem scan of the repository

If the --image option is provided it performs the following additional scans
on the specified container image:

- a grype image scan
- a trufflehog image scan

The --severity option specifies the severity level at which the application
should fail the scan.  The default severity level is "medium", which is an
ISO requirement for us. 

Valid --severity values include "critical", "high", "medium", and "low".

When run in a build pipeline, the --s3-bucket option can be set to an
AWS S3 bucket name to write results to. The --s3-key-prefix option can
also be set to a key prefix to write results under.

When run in a build pipeline with the --s3-bucket option, the --git-repo
and --build-id options must be used to specify the Git repository id and
build id of the pipeline.

When run in a build pipeline with the --s3-bucket option, the app requires
AWS IAM permissions to upload scan results and summaries to the --s3-bucket
under the --s3-key-prefix, if any.`

// Version is the version of the application set during build with -ldflags.
var Version string

// ----------------------------------------------------------------------------
// Application constants
// ----------------------------------------------------------------------------

// init initializes some application "constants".
func init() {
	cwd, err := os.Getwd()
	if err != nil {
		panic(err)
	}
	if CurrentDir, err = filepath.Abs(cwd); err != nil {
		panic(err)
	}
	if DefaultCacheDir, err = HomeDirPath(".cache", Name); err != nil {
		panic(err)
	}
	if Hostname, err = os.Hostname(); err != nil {
		panic(err)
	}
	if Build, err = GetBuildInfo(); err != nil {
		panic(err)
	}
	currentUser, err := user.Current()
	if err != nil {
		panic(err)
	}
	Username = currentUser.Username
}

// CurrentDir is the current directory of the application.
var CurrentDir string

// DefaultCacheDir is the default application cache directory when not provided.
var DefaultCacheDir string

// Hostname is the hostname of the system running the application.
var Hostname string

// Username is the username of the user running the application.
var Username string

// Build is the build information for the application.
var Build BuildInfo

// DefaultSeverity is the default severity level to fail scans on.
const DefaultSeverity = "medium" // Per ISO-27001

// ValidSeverities is the list of valid severity levels to fail scans on.
var ValidSeverities = []string{"critical", "high", "medium", "low"}

// ----------------------------------------------------------------------------
// Application build and configuration support
// ----------------------------------------------------------------------------

// BuildInfo represents the build information for the application.
type BuildInfo struct {
	Version   string `json:"version"`
	Commit    string `json:"commit"`
	Dirty     bool   `json:"dirty"`
	Timestamp string `json:"timestamp"`
}

// Configuration represents the configuration for the application.
type Configuration struct {
	CacheDir    string `json:"cacheDir"`
	DryRun      bool   `json:"dryRun"`
	Force       bool   `json:"force"`
	Verbose     bool   `json:"verbose"`
	Severity    string `json:"severity"`
	Image       string `json:"image"`
	GitRepo     string `json:"gitRepo"`
	BuildId     string `json:"buildId"`
	S3Bucket    string `json:"s3Bucket"`
	S3KeyPrefix string `json:"s3KeyPrefix"`
}

// PipelineMode returns true if the application is running in pipeline mode.
func (c Configuration) PipelineMode() bool {
	return c.S3Bucket != ""
}

// Config is the configuration for the application.
var Config = Configuration{}

// Scans is a slice of scans that can be reported.
type Scans []Scan

// Report returns a report of the scans.
func (scans Scans) Report(timestamp time.Time) *Report {
	scanners := make(map[string]string)
	for name, scanner := range Scanners {
		scanners[name] = scanner.Version()
	}
	return &Report{
		Version:      Version,
		Hostname:     Hostname,
		Username:     Username,
		Timestamp:    timestamp.Format(time.RFC3339),
		DurationSecs: time.Since(timestamp).Seconds(),
		BuildInfo:    Build,
		Image:        Config.Image,
		Scanners:     scanners,
		Scans:        scans,
		GitRepo:      Config.GitRepo,
		BuildId:      Config.BuildId,
	}
}

// Failure returns true if any of the scans failed.
func (scans Scans) Failure() bool {
	for _, scan := range scans {
		if scan.ExitCode != 0 {
			return true
		}
	}
	return false
}

// Scan represents the results of a scan.
type Scan struct {
	Scanner      string  `json:"scanner"`
	ScanType     string  `json:"scanType"`
	ScanTarget   string  `json:"scanTarget"`
	CommandLine  string  `json:"commandLine"`
	DurationSecs float64 `json:"durationSecs"`
	Error        string  `json:"error"`
	ExitCode     int     `json:"exitCode"`
	NumCritical  int     `json:"numCritical"`
	NumHigh      int     `json:"numHigh"`
	NumMedium    int     `json:"numMedium"`
	NumLow       int     `json:"numLow"`
	NumUnknown   int     `json:"numUnknown"`
	err          error
	stdout       []byte
}

// IsZero returns true if the scan is empty, or zero-valued.
func (s *Scan) IsZero() bool {
	return s == &Scan{}
}

// Score scores the scan based on the severity of the vulnerability.
func (s *Scan) Score(severity string) {
	switch severity {
	case "CRITICAL":
		s.NumCritical++
	case "HIGH":
		s.NumHigh++
	case "MEDIUM":
		s.NumMedium++
	case "LOW":
		s.NumLow++
	default:
		s.NumUnknown++
	}
}

// FileName returns the name of the cache file for the scan.
func (s *Scan) FileName() string {
	return fmt.Sprintf("%s.%s.json", s.Scanner, s.ScanType)
}

// Cache caches the scan results to a local file.
func (s *Scan) Cache() error {
	cachePath := s.CachePath()
	if FileExists(cachePath) && !Config.Force {
		return fmt.Errorf("scan already cached: %s", cachePath)
	}
	// Ensure the directory to contain the cache file exists.
	cacheDir := path.Dir(cachePath)
	if err := EnsureDir(cacheDir); err != nil {
		return err
	}

	// Write the json data to the cache file.
	data, err := json.Marshal(s)
	if err != nil {
		return err
	}
	return os.WriteFile(cachePath, data, 0644)
}

// CachePath returns the absolute path to the cache file for the scan.
func (s *Scan) CachePath() string {
	return path.Join(Config.CacheDir, Config.GitRepo, Config.BuildId, s.FileName())
}

// Upload uploads the scan cache file to S3.
func (s *Scan) Upload() error {
	uploaded, err := S3ObjectExists(Config.S3Bucket, s.S3Key())
	if err != nil {
		return err
	}
	if uploaded && !Config.Force {
		return fmt.Errorf("scan already uploaded: %s", s.S3Key())
	}
	return UploadS3Object(Config.S3Bucket, s.S3Key(), s.CachePath())
}

// S3Key returns the S3 key for the scan cache file.
func (s *Scan) S3Key() string {
	if Config.S3KeyPrefix != "" {
		return path.Join(Config.S3KeyPrefix, Config.GitRepo, Config.BuildId, s.FileName())
	}
	return path.Join(Config.GitRepo, Config.BuildId, s.FileName())
}

// Scanner defines behaviors for a scanner application used to scan a target for a type of defect or vulnerability.
type Scanner interface {
	// Scan scans a target for a type of defect or vulnerability.
	Scan(scanType, scanTarget string) Scan

	// Name returns the name of the scanner application.
	Name() string

	// Path returns the path to the scanner application.
	Path() string

	// Version returns the version of the scanner application.
	Version() string
}

// Scanners is a map of scanners by name.
var Scanners = map[string]Scanner{
	"grype":      &GrypeScanner{},
	"trivy":      &TrivyScanner{},
	"trufflehog": &TrufflehogScanner{},
}

// ----------------------------------------------------------------------------
// Grype scanner support
// ----------------------------------------------------------------------------

// GrypeScanner is a struct that represents a grype scanner.
type GrypeScanner struct{}

// Scan scans a target for a type of defect or vulnerability with grype.
func (s GrypeScanner) Scan(scanType, scanTarget string) Scan {
	// Set output format to JSON in pipeline mode.
	var outputOpt string
	if Config.PipelineMode() {
		outputOpt = "--output=json"
	}

	// Set the failure severity option.
	severityOpt := fmt.Sprintf("--fail-on %s", strings.ToLower(Config.Severity))

	// Run the appropriate scan command line.
	switch scanType {
	case "files":
		return s.run(fmt.Sprintf("grype %s %s dir:%s", severityOpt, outputOpt, scanTarget), scanType, scanTarget)
	case "image":
		return s.run(fmt.Sprintf("grype %s %s %s", severityOpt, outputOpt, scanTarget), scanType, scanTarget)
	default:
		return Scan{}
	}
}

// Name returns the name of the grype scanner application.
func (s GrypeScanner) Name() string {
	return "grype"
}

// Path returns the path to the grype scanner application.
func (s GrypeScanner) Path() string {
	binPath, _ := exec.LookPath(s.Name())
	return binPath
}

// Version returns the version of the grype scanner application.
func (s GrypeScanner) Version() string {
	cmd := exec.Command("grype", "version", "--output", "json")
	output, err := cmd.Output()
	if err != nil {
		return ""
	}
	var data map[string]interface{}
	if err := json.Unmarshal(output, &data); err != nil {
		return ""
	}
	return data["version"].(string)
}

func (s GrypeScanner) run(cmdline, scanType, scanTarget string) Scan {
	beginTime := time.Now()
	exitCode, stdout, err := ExecCommand(cmdline)
	durationSecs := time.Since(beginTime).Seconds()
	scan := Scan{
		Scanner:      s.Name(),
		ScanType:     scanType,
		ScanTarget:   scanTarget,
		CommandLine:  cmdline,
		DurationSecs: durationSecs,
		ExitCode:     exitCode,
		stdout:       stdout,
		err:          err,
	}
	if err != nil {
		scan.Error = err.Error()
	}
	if Config.DryRun {
		return scan
	}

	// Parse the JSON output to get the number of vulnerabilities.
	var data map[string]any
	if err := json.Unmarshal(stdout, &data); err != nil {
		return scan
	}

	// Count the number of vulnerabilities in "matches" by severity.
	matches := data["matches"].([]interface{})
	for _, match := range matches {
		vulnerability := match.(map[string]any)["vulnerability"].(map[string]any)
		severity := vulnerability["severity"].(string)
		scan.Score(severity)
	}
	return scan
}

// ----------------------------------------------------------------------------
// Trivy scanner support
// ----------------------------------------------------------------------------

// TrivyScanner is a struct that represents a trivy scanner.
type TrivyScanner struct{}

// Scan scans a target for a type of defect or vulnerability with trivy.
func (s TrivyScanner) Scan(scanType, scanTarget string) Scan {
	// Set output format to JSON in pipeline mode.
	var outputOpt string
	if Config.PipelineMode() {
		outputOpt = "--format=json"
	}

	// Set the failure severity option.
	var severityOpt string
	switch Config.Severity {
	case "critical":
		severityOpt = "--severity=CRITICAL"
	case "high":
		severityOpt = "--severity=CRITICAL,HIGH"
	case "medium":
		severityOpt = "--severity=CRITICAL,HIGH,MEDIUM"
	case "low":
		severityOpt = "--severity=CRITICAL,HIGH,MEDIUM,LOW"
	}

	// Run the appropriate scan command line.
	switch scanType {
	case "config":
		return s.run(fmt.Sprintf("trivy config %s %s %s", severityOpt, outputOpt, scanTarget), scanType, scanTarget)
	case "files":
		return s.run(fmt.Sprintf("trivy filesystem %s %s %s", severityOpt, outputOpt, scanTarget), scanType, scanTarget)
	case "image":
		return s.run(fmt.Sprintf("trivy image %s %s %s", severityOpt, outputOpt, scanTarget), scanType, scanTarget)
	default:
		return Scan{}
	}
}

// Name returns the name of the trivy scanner application.
func (s TrivyScanner) Name() string {
	return "trivy"
}

// Path returns the path to the trivy scanner application.
func (s TrivyScanner) Path() string {
	binPath, _ := exec.LookPath(s.Name())
	return binPath
}

// Version returns the version of the trivy scanner application.
func (s TrivyScanner) Version() string {
	cmd := exec.Command("trivy", "version", "--format", "json")
	output, err := cmd.Output()
	if err != nil {
		return ""
	}
	var data map[string]interface{}
	if err := json.Unmarshal(output, &data); err != nil {
		return ""
	}
	return data["Version"].(string)
}

func (s TrivyScanner) run(cmdline, scanType, scanTarget string) Scan {
	beginTime := time.Now()
	exitCode, stdout, err := ExecCommand(cmdline)
	durationSecs := time.Since(beginTime).Seconds()
	scan := Scan{
		Scanner:      s.Name(),
		ScanType:     scanType,
		ScanTarget:   scanTarget,
		CommandLine:  cmdline,
		DurationSecs: durationSecs,
		ExitCode:     exitCode,
		stdout:       stdout,
		err:          err,
	}
	if err != nil {
		scan.Error = err.Error()
	}
	if Config.DryRun {
		return scan
	}

	// Parse the JSON output to get the number of vulnerabilities.
	var data map[string]any
	if err := json.Unmarshal(stdout, &data); err != nil {
		return scan
	}

	switch scanType {
	case "config":
		results := data["Results"].([]any)
		for _, result := range results {
			misconfigurations := result.(map[string]any)["Misconfigurations"].([]any)
			for _, misconfiguration := range misconfigurations {
				severity := misconfiguration.(map[string]any)["Severity"].(string)
				scan.Score(severity)
			}
		}
	case "image":
		results := data["Results"].([]any)
		for _, result := range results {
			vulnerabilities := result.(map[string]any)["Vulnerabilities"].([]any)
			for _, vulnerability := range vulnerabilities {
				severity := vulnerability.(map[string]any)["Severity"].(string)
				scan.Score(severity)
			}
		}
	}
	return scan
}

// ----------------------------------------------------------------------------
// Trufflehog scanner support
// ----------------------------------------------------------------------------

// TrufflehogScanner is a struct that represents a trufflehog scanner.
type TrufflehogScanner struct{}

// Scan scans a target for a type of defect or vulnerability with trufflehog.
func (s TrufflehogScanner) Scan(scanType, scanTarget string) Scan {
	// Set output format to JSON in pipeline mode.
	var outputOpt string
	if Config.PipelineMode() {
		outputOpt = "--json"
	}

	// Run the appropriate scan command line.
	switch scanType {
	case "files":
		return s.run(fmt.Sprintf("trufflehog --fail %s filesystem %s", outputOpt, scanTarget), scanType, scanTarget)
	case "image":
		return s.run(fmt.Sprintf("trufflehog --fail %s docker --image=%s", outputOpt, scanTarget), scanType, scanTarget)
	default:
		return Scan{}
	}
}

// Name returns the name of the trufflehog scanner application.
func (s TrufflehogScanner) Name() string {
	return "trufflehog"
}

// Path returns the path to the trufflehog scanner application.
func (s TrufflehogScanner) Path() string {
	binPath, _ := exec.LookPath(s.Name())
	return binPath
}

// Version returns the version of the trufflehog scanner application.
func (s TrufflehogScanner) Version() string {
	cmd := exec.Command("trufflehog", "--version")
	output, err := cmd.CombinedOutput()
	if err != nil {
		return ""
	}
	text := strings.TrimSpace(string(output))
	return strings.Split(text, " ")[1]
}

func (s TrufflehogScanner) run(cmdline, scanType, scanTarget string) Scan {
	beginTime := time.Now()
	exitCode, stdout, err := ExecCommand(cmdline)
	durationSecs := time.Since(beginTime).Seconds()
	scan := Scan{
		Scanner:      s.Name(),
		ScanType:     scanType,
		ScanTarget:   scanTarget,
		CommandLine:  cmdline,
		DurationSecs: durationSecs,
		ExitCode:     exitCode,
		stdout:       stdout,
		err:          err,
	}
	if err != nil {
		scan.Error = err.Error()
	}
	if Config.DryRun {
		return scan
	}

	// TODO: Parse the output to get the number of vulnerabilities.
	return scan
}

// ----------------------------------------------------------------------------
// Reporting support
// ----------------------------------------------------------------------------

// Report represents the report summarizing the results of scans.
type Report struct {
	Version      string            `json:"version"`
	Hostname     string            `json:"hostname"`
	Username     string            `json:"username"`
	Timestamp    string            `json:"timestamp"`
	DurationSecs float64           `json:"durationSecs"`
	BuildInfo    BuildInfo         `json:"buildInfo"`
	Image        string            `json:"image"`
	Config       Configuration     `json:"config"`
	Scanners     map[string]string `json:"scanners"`
	Scans        Scans             `json:"scans"`
	GitRepo      string            `json:"gitRepo"`
	BuildId      string            `json:"buildId"`
}

// FileName returns the name of the cache file for the scan.
func (r Report) FileName() string {
	return "report.json"
}

// Cache caches the scan results to a local file.
func (r Report) Cache() error {
	cachePath := r.CachePath()
	if FileExists(cachePath) && !Config.Force {
		return fmt.Errorf("report already cached: %s", cachePath)
	}
	// Ensure the directory to contain the cache file exists.
	cacheDir := path.Dir(cachePath)
	if err := EnsureDir(cacheDir); err != nil {
		return err
	}

	// Write the json data to the cache file.
	data, err := json.Marshal(r)
	if err != nil {
		return err
	}
	return os.WriteFile(cachePath, data, 0644)
}

// CachePath returns the absolute path to the cache file for the scan.
func (r Report) CachePath() string {
	return path.Join(Config.CacheDir, Config.GitRepo, Config.BuildId, r.FileName())
}

// Upload uploads the cached scan to S3.
func (r Report) Upload() error {
	uploaded, err := S3ObjectExists(Config.S3Bucket, r.S3Key())
	if err != nil {
		return err
	}
	if uploaded && !Config.Force {
		return fmt.Errorf("report already uploaded: %s", r.S3Key())
	}
	return UploadS3Object(Config.S3Bucket, r.S3Key(), r.CachePath())
}

// S3Key returns the S3 key for the scan cache file.
func (r Report) S3Key() string {
	if Config.S3KeyPrefix != "" {
		return path.Join(Config.S3KeyPrefix, Config.GitRepo, Config.BuildId, r.FileName())
	}
	return path.Join(Config.GitRepo, Config.BuildId, r.FileName())
}

// ----------------------------------------------------------------------------
// Utility support
// ----------------------------------------------------------------------------

// EnsureDir ensures directory exists in the filesystem.
func EnsureDir(path string) error {
	if _, err := os.Stat(path); os.IsNotExist(err) {
		return os.MkdirAll(path, 0755)
	}
	return nil
}

// FileExists tests if a file exists in the filesystem.
func FileExists(path string) bool {
	_, err := os.Stat(path)
	return !os.IsNotExist(err)
}

// ExecCommand executes a command line and returns its exit code, stdout and stderr.
func ExecCommand(cmdline string) (int, []byte, error) {
	// Otherwise, continue to execute the command line.
	var (
		exitCode int
		stdout   []byte
		err      error
	)

	// Print the command line if in dry-run or verbose mode and return immediately if in dry-run mode.
	fmt.Printf("\nrunning: %s\n", cmdline)
	if Config.DryRun {
		return exitCode, stdout, err
	}

	// Build command.
	parts := strings.Fields(cmdline)
	executable := parts[0]
	args := parts[1:]
	cmd := exec.Command(executable, args...)

	// If not in pipeline mode, print the command's stderr, typically progress info, to the console.
	if Config.PipelineMode() {
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
	if Config.PipelineMode() {
		fmt.Println(string(stdout))
	}
	return exitCode, stdout, err
}

// GetBuildInfo returns the build information for the application.
func GetBuildInfo() (BuildInfo, error) {
	buildInfo := BuildInfo{Version: Version}
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

// HomeDirPath returns the absolute path of the home directory with the provided path parts.
func HomeDirPath(parts ...string) (string, error) {
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

// IsValidSeverity returns true if the severity is a valid one.
func IsValidSeverity(severity string) bool {
	for _, valid := range ValidSeverities {
		if severity == valid {
			return true
		}
	}
	return false
}

func S3ObjectExists(bucket, key string) (bool, error) {
	// Load the default AWS configuration
	cfg, err := config.LoadDefaultConfig(context.TODO())
	if err != nil {
		return false, fmt.Errorf("unable to load AWS SDK config, %v", err)
	}

	// Create an S3 client and make a HeadObject request to check if the object exists
	client := s3.NewFromConfig(cfg)
	_, err = client.HeadObject(context.TODO(), &s3.HeadObjectInput{
		Bucket: aws.String(bucket),
		Key:    aws.String(key),
	})

	// If the error is nil, the object exists.
	if err == nil {
		return true, nil
	}

	// Otherwise, check if the error is a NotFound error
	var notFoundErr *types.NotFound
	if ok := errors.As(err, &notFoundErr); ok {
		return false, nil
	}
	return false, fmt.Errorf("failed to check if object exists: %v", err)
}

func UploadS3Object(bucket, key, filePath string) error {
	// Load the default AWS configuration
	cfg, err := config.LoadDefaultConfig(context.TODO())
	if err != nil {
		return fmt.Errorf("unable to load AWS SDK config, %v", err)
	}

	// Open the file to upload
	uploadFile, err := os.Open(filePath)
	if err != nil {
		return fmt.Errorf("failed to open file, %v", err)
	}

	// Create an S3 uploader and upload the file.
	client := s3.NewFromConfig(cfg)
	uploader := manager.NewUploader(client)
	if _, err = uploader.Upload(context.TODO(), &s3.PutObjectInput{
		Bucket: aws.String(bucket),
		Key:    aws.String(key),
		Body:   uploadFile,
	}); err != nil {
		return fmt.Errorf("failed to upload object, %v", err)
	}
	return nil
}

package app

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path"
	"path/filepath"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/feature/s3/manager"
	"github.com/aws/aws-sdk-go-v2/service/s3"

	"github.com/sambatv/imagecheck/metadata"
)

// ScanReporterConfig represents the configuration for a ScanReporter.
type ScanReporterConfig struct {
	Verbose     bool   `json:"verbose"`
	RepoID      string `json:"repo_id"`
	BuildID     string `json:"build_id"`
	CacheDir    string `json:"cache_dir"`
	S3Bucket    string `json:"s3_bucket"`
	S3KeyPrefix string `json:"s3_key_prefix"`
}

// ScanReporter reports the results of scans.
type ScanReporter struct {
	cfg    ScanReporterConfig
	runner *ScanRunner
}

// NewScanReporter creates a new configured ScanReporter.
func NewScanReporter(config ScanReporterConfig) *ScanReporter {
	return &ScanReporter{cfg: config}
}

// Report reports the results of scans.
func (r ScanReporter) Report(scanTools map[string]ScanTool, scans []*Scan, timestamp time.Time) error {
	// Ensure the cache directory exists.
	if err := ensureDir(r.cfg.CacheDir); err != nil {
		return err
	}

	// Cache all scan output results.
	fmt.Println("Caching scans ...")
	for _, scan := range scans {
		if err := r.CacheScan(scan); err != nil {
			return err
		}
	}

	// Enrich all scans with the S3 URL of their scan output.
	for i := range scans {
		sPath := outputPath(scans[i])
		s3Key := r.S3Key(sPath)
		scans[i].S3URL = fmt.Sprintf("s3://%s/%s", r.cfg.S3Bucket, s3Key)
	}

	// Cache the scan summary.
	summary := NewSummary(scanTools, scans, timestamp)
	if err := r.CacheSummary(summary); err != nil {
		return err
	}

	// If no S3 bucket is specified, we're done with reporting.
	if r.cfg.S3Bucket == "" {
		if r.cfg.Verbose {
			fmt.Println("\nNo S3 bucket specified. skipping upload ...")
		}
		return nil
	}

	// Upload all cached scan results.
	fmt.Println("\nUploading scans ...")
	for _, scan := range scans {
		if err := r.UploadScan(scan); err != nil {
			return err
		}
	}

	// Upload the scan summary.
	if err := r.UploadSummary(); err != nil {
		return err
	}
	return nil
}

func (r ScanReporter) CachePath(filename string) string {
	return path.Join(r.cfg.CacheDir, r.cfg.RepoID, "builds", r.cfg.BuildID, filename)
}

// CacheScan caches the scan output to a local file.
func (r ScanReporter) CacheScan(scan *Scan) error {
	// Add the S3 URL to the scan for output in report.
	cachePath := r.CachePath(outputPath(scan))
	fmt.Printf("caching: %s\n", cachePath)
	if err := ensureDir(path.Dir(cachePath)); err != nil {
		return err
	}
	return os.WriteFile(cachePath, scan.stdout, 0644)
}

// CacheSummary caches the scan summary to a local file.
func (r ScanReporter) CacheSummary(summary Summary) error {
	cachePath := r.CachePath(summaryPath())
	data, err := json.Marshal(summary)
	if err != nil {
		return err
	}
	return os.WriteFile(cachePath, data, 0644)
}

// S3Key returns the S3 key for the scan cache file.
func (r ScanReporter) S3Key(filename string) string {
	if r.cfg.S3KeyPrefix != "" {
		return path.Join(r.cfg.S3KeyPrefix, r.cfg.RepoID, "builds", r.cfg.BuildID, filename)
	}
	return path.Join(r.cfg.RepoID, "builds", r.cfg.BuildID, filename)
}

// UploadScan uploads the scan cache file to S3.
func (r ScanReporter) UploadScan(scan *Scan) error {
	filePath := outputPath(scan)
	srcPath := r.CachePath(filePath)
	dstKey := r.S3Key(filePath)
	return uploadS3Object(r.cfg.S3Bucket, dstKey, srcPath)
}

// UploadSummary uploads the scan summary cache file to S3.
func (r ScanReporter) UploadSummary() error {
	filePath := summaryPath()
	srcPath := r.CachePath(filePath)
	dstKey := r.S3Key(filePath)
	return uploadS3Object(r.cfg.S3Bucket, dstKey, srcPath)
}

// ensureDir ensures directory exists in the filesystem.
func ensureDir(path string) error {
	if _, err := os.Stat(path); os.IsNotExist(err) {
		return os.MkdirAll(path, 0755)
	}
	return nil
}

func uploadS3Object(bucket, key, filePath string) error {
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
	fmt.Printf("uploading: s3://%s/%s\n", bucket, key)
	if _, err = uploader.Upload(context.TODO(), &s3.PutObjectInput{
		Bucket: aws.String(bucket),
		Key:    aws.String(key),
		Body:   uploadFile,
	}); err != nil {
		return fmt.Errorf("failed to upload object, %v", err)
	}
	return nil
}

// Summary represents the report summarizing the results of scans.
type Summary struct {
	Version      string            `json:"version"`
	Hostname     string            `json:"hostname"`
	Username     string            `json:"username"`
	Timestamp    string            `json:"timestamp"`
	DurationSecs float64           `json:"duration_secs"`
	ToolVersions map[string]string `json:"tool_versions"`
	Scans        []*Scan           `json:"scans"`
}

// NewSummary creates a new Summary report.
func NewSummary(scanTools map[string]ScanTool, scans []*Scan, timestamp time.Time) Summary {
	toolVersions := make(map[string]string, len(scanTools))
	for name, scanTool := range scanTools {
		toolVersions[name] = scanTool.Version()
	}
	return Summary{
		Version:      metadata.Version,
		Hostname:     metadata.Hostname,
		Username:     metadata.Username,
		Timestamp:    timestamp.Format(time.RFC3339),
		DurationSecs: time.Since(timestamp).Seconds(),
		ToolVersions: toolVersions,
		Scans:        scans,
	}
}

// outputPath returns the path of the scan output file.
func outputPath(s *Scan) string {
	var target string
	switch s.Settings.ScanType {
	case "image":
		target = s.Target
	default:
		target = "cwd"
	}
	return filepath.Join(s.Settings.ScanTool, s.Settings.ScanType, target, "output.json")
}

// summaryPath returns the path of the summary output file.
func summaryPath() string {
	return "summary.json"
}

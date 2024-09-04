package app

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/feature/s3/manager"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/s3/types"
)

// ScanReporterConfig represents the configuration for a ScanReporter.
type ScanReporterConfig struct {
	CacheDir    string `json:"cacheDir"`
	Force       bool   `json:"force"`
	Verbose     bool   `json:"verbose"`
	GitRepo     string `json:"gitRepo"`
	BuildId     string `json:"buildId"`
	S3Bucket    string `json:"s3Bucket"`
	S3KeyPrefix string `json:"s3KeyPrefix"`
}

// ScanReporter reports the results of scans.
type ScanReporter struct {
	Config ScanReporterConfig
}

// NewScanReporter creates a new configured ScanReporter.
func NewScanReporter(config ScanReporterConfig) *ScanReporter {
	return &ScanReporter{Config: config}
}

// Report reports the results of scans.
func (r ScanReporter) Report(scans []Scan, timestamp time.Time) error {
	// Ensure the cache directory exists.
	if err := ensureDir(r.Config.CacheDir); err != nil {
		return err
	}

	// Cache all scan output results.
	for _, scan := range scans {
		if err := r.CacheScan(scan); err != nil {
			return err
		}
	}

	// Cache the scan summary.
	summary := NewSummary(scans, timestamp)
	if err := r.CacheSummary(summary); err != nil {
		return err
	}

	// If no S3 bucket is specified, we're done with reporting.
	if r.Config.S3Bucket == "" {
		if r.Config.Verbose {
			fmt.Println("no S3 bucket specified, skipping upload")
		}
		return nil
	}

	// Upload all cached scan results.
	for _, scan := range scans {
		if err := r.UploadScan(scan); err != nil {
			return err
		}
	}

	// Upload the scan summary.
	if err := r.UploadSummary(summary); err != nil {
		return err
	}
	return nil
}

func (r ScanReporter) CachePath(filename string) string {
	return path.Join(r.Config.CacheDir, r.Config.GitRepo, r.Config.BuildId, filename)
}

// CacheScan caches the scan results to a local file.
func (r ScanReporter) CacheScan(scan Scan) error {
	cachePath := r.CachePath(scan.FileName())
	if fileExists(cachePath) && !r.Config.Force {
		return fmt.Errorf("scan already cached: %s", cachePath)
	}

	// Write the json data to the cache file.
	data, err := json.Marshal(scan)
	if err != nil {
		return err
	}
	if r.Config.Verbose {
		fmt.Printf("caching scan: %s\n", cachePath)
	}
	if err := ensureDir(path.Dir(cachePath)); err != nil {
		return err
	}
	return os.WriteFile(cachePath, data, 0644)
}

// CacheSummary caches the scan summary to a local file.
func (r ScanReporter) CacheSummary(summary Summary) error {
	cachePath := r.CachePath(summary.FileName())
	if fileExists(cachePath) && !r.Config.Force {
		return fmt.Errorf("summary already cached: %s", cachePath)
	}

	// Write the json data to the cache file.
	data, err := json.Marshal(summary)
	if err != nil {
		return err
	}
	return os.WriteFile(cachePath, data, 0644)
}

// S3Key returns the S3 key for the scan cache file.
func (r ScanReporter) S3Key(filename string) string {
	if r.Config.S3KeyPrefix != "" {
		return path.Join(r.Config.S3KeyPrefix, r.Config.GitRepo, r.Config.BuildId, filename)
	}
	return path.Join(r.Config.GitRepo, r.Config.BuildId, filename)
}

// UploadScan uploads the scan cache file to S3.
func (r ScanReporter) UploadScan(scan Scan) error {
	fileName := scan.FileName()
	s3Key := r.S3Key(fileName)
	uploaded, err := s3ObjectExists(r.Config.S3Bucket, s3Key)
	if err != nil {
		return err
	}
	if uploaded && !r.Config.Force {
		return fmt.Errorf("scan already uploaded: %s", s3Key)
	}
	return uploadS3Object(r.Config.S3Bucket, s3Key, r.CachePath(fileName))
}

// UploadSummary uploads the scan summary cache file to S3.
func (r ScanReporter) UploadSummary(summary Summary) error {
	fileName := summary.FileName()
	s3Key := r.S3Key(fileName)
	uploaded, err := s3ObjectExists(r.Config.S3Bucket, s3Key)
	if err != nil {
		return err
	}
	if uploaded && !r.Config.Force {
		return fmt.Errorf("summary already uploaded: %s", s3Key)
	}
	return uploadS3Object(r.Config.S3Bucket, s3Key, r.CachePath(fileName))
}

// ensureDir ensures directory exists in the filesystem.
func ensureDir(path string) error {
	if _, err := os.Stat(path); os.IsNotExist(err) {
		return os.MkdirAll(path, 0755)
	}
	return nil
}

// fileExists tests if a file exists in the filesystem.
func fileExists(path string) bool {
	_, err := os.Stat(path)
	return !os.IsNotExist(err)
}

func s3ObjectExists(bucket, key string) (bool, error) {
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
	DurationSecs float64           `json:"durationSecs"`
	Scanners     map[string]string `json:"scanners"`
	Scans        []Scan            `json:"scans"`
}

// FileName returns the name of the cache file for the Summary.
func (r Summary) FileName() string {
	return "summary.json"
}

// NewSummary creates a new Summary report.
func NewSummary(scans []Scan, timestamp time.Time) Summary {
	scanTools := make(map[string]string)
	for name, scanTool := range ScanTools {
		scanTools[name] = scanTool.Version()
	}
	return Summary{
		Version:      Version,
		Hostname:     hostname,
		Username:     username,
		Timestamp:    timestamp.Format(time.RFC3339),
		DurationSecs: time.Since(timestamp).Seconds(),
		Scanners:     scanTools,
		Scans:        scans,
	}
}

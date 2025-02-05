package metadata

import (
	"fmt"
	"os"
	"os/user"
	"runtime/debug"
	"strconv"
	"strings"

	"github.com/go-git/go-git/v5"
)

// Name is the name of the application.
const Name = "imagecheck"

// "constants" with non-trivial initialization.
var (
	// Version is the version of the application set during build with -ldflags.
	Version string

	// Hostname is the hostname of the machine running the application.
	Hostname string

	// Username is the username of the user running the application.
	Username string

	// GitRepoName is the name of the git repository.
	GitRepoName string
)

func init() {
	var err error
	if Hostname, err = os.Hostname(); err != nil {
		panic(err)
	}
	currentUser, err := user.Current()
	if err != nil {
		panic(err)
	}
	Username = currentUser.Username
	if Build, err = getBuildInfo(); err != nil {
		panic(err)
	}
	GitRepoName, _ = getGitRepoName()
}

// BuildInfo represents the build information for the application.
type BuildInfo struct {
	Commit    string `json:"commit"`
	Dirty     bool   `json:"dirty"`
	Timestamp string `json:"timestamp"`
}

// Build represents the build information for the application.
var Build BuildInfo

// getBuildInfo returns the build information for the application.
func getBuildInfo() (BuildInfo, error) {
	buildInfo := BuildInfo{}
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

// getGitRepoName returns the name of the git repository.
func getGitRepoName() (string, error) {
	var gitRepoName string

	// Open the git repository
	repo, err := git.PlainOpen(".") // Assumes the current directory is a git repo
	if err != nil {
		return "", err
	}

	// List remotes
	remotes, err := repo.Remotes()
	if err != nil {
		return "", err
	}

	// Find the "origin" remote
	var originRemote *git.Remote
	for _, remote := range remotes {
		if remote.Config().Name == "origin" {
			originRemote = remote
			break
		}
	}
	if originRemote == nil {
		return "", fmt.Errorf("no origin remote found")
	}

	// Parse out the forge, organization, and repository name from the remote URL
	// For example, the URL "git@github.com:sambatv/imagecheck.git" would be parsed
	// into "github.com/sambatv/imagecheck".
	urls := originRemote.Config().URLs
	if len(urls) == 0 {
		return "", fmt.Errorf("no URLs found for origin remote")
	}

	const (
		gitPrefix   = "git@"
		gitSuffix   = ".git"
		httpsPrefix = "https://"
	)
	s := urls[0]
	if strings.HasPrefix(s, gitPrefix) {
		s = strings.TrimPrefix(s, gitPrefix)
		s = strings.TrimSuffix(s, gitSuffix)
		s = strings.Replace(s, ":", "/", 1)
	} else if strings.HasPrefix(s, httpsPrefix) {
		s = strings.TrimPrefix(s, httpsPrefix)
		s = strings.TrimSuffix(s, gitSuffix)
	}
	gitRepoName = strings.ToLower(s)
	return gitRepoName, nil
}

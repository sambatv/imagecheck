package metadata

import (
	"fmt"
	"os"
	"os/user"
	"runtime/debug"
	"strconv"
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

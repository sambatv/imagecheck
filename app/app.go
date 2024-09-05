// Package app provides core application support.
package app

import (
	"os"
	"os/user"
	"path/filepath"
)

// Name is the name of the application.
const Name = "imagecheck"

// "constants" with non-trivial initialization.
var (
	// Version is the version of the application set during build with -ldflags.
	Version string

	// Application "constants" set by init function below.
	currentDir, hostname, username string
)

func init() {
	cwd, err := os.Getwd()
	if err != nil {
		panic(err)
	}
	if currentDir, err = filepath.Abs(cwd); err != nil {
		panic(err)
	}
	if hostname, err = os.Hostname(); err != nil {
		panic(err)
	}
	currentUser, err := user.Current()
	if err != nil {
		panic(err)
	}
	username = currentUser.Username
}

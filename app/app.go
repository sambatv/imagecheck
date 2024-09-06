// Package app provides core application support.
package app

import (
	"os"
	"path/filepath"
)

var currentDir string

func init() {
	cwd, err := os.Getwd()
	if err != nil {
		panic(err)
	}
	if currentDir, err = filepath.Abs(cwd); err != nil {
		panic(err)
	}
}

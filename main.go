// Package main provides the entry point for the application.
package main

import (
	"fmt"
	"os"

	"github.com/sambatv/imagecheck/cli"
)

// main is the entry point for the application.
func main() {
	if err := cli.New().Run(os.Args); err != nil {
		fmt.Printf("error: %s\n", err)
		os.Exit(1)
	}
}

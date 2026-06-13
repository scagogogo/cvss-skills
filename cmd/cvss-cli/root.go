package main

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
)

// cliVersion is set via -ldflags at build time.
var cliVersion = "dev"

var rootCmd = &cobra.Command{
	Use:   "cvss",
	Short: "CVSS v3.x vector parser, calculator, and comparison tool",
	Long: `CVSS CLI — parse, score, validate, compare, and serialize CVSS v3.0/v3.1 vectors.

Supports all CVSS 3.x capabilities:
  • Parse and validate vector strings
  • Calculate base, temporal, and environmental scores
  • Compute severity ratings
  • Compare vectors (diff, merge, distance)
  • Serialize to JSON, XML, or vector string format
  • Generate random vectors and presets`,
	Version: cliVersion,
}

func main() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

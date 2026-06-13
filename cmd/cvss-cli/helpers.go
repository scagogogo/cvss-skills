package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"github.com/spf13/cobra"
)

// die prints msg to stderr and exits with code 1.
func die(msg string) {
	fmt.Fprintln(os.Stderr, msg)
	os.Exit(1)
}

// dief prints a formatted message to stderr and exits with code 1.
func dief(format string, args ...any) {
	fmt.Fprintf(os.Stderr, format, args...)
	os.Exit(1)
}

// marshalJSON returns the JSON encoding of v, indented with two spaces.
// On error, prints the error to stderr and exits with code 1.
func marshalJSON(v any) string {
	data, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		dief("JSON encoding error: %v\n", err)
	}
	return string(data)
}

// mustGetString retrieves a flag value and uppercases it.
// Used by the build command for metric flag values.
func mustGetString(cmd *cobra.Command, name string) string {
	val, _ := cmd.Flags().GetString(name)
	return strings.ToUpper(val)
}

// readLines reads lines from a file or stdin. Lines starting with "#"
// and blank lines are skipped. The special arg "-" means stdin.
func readLines(cmd *cobra.Command, args []string) []string {
	var r *os.File
	if len(args) == 0 || args[0] == "-" {
		r = os.Stdin
	} else {
		f, err := os.Open(args[0])
		if err != nil {
			die(fmt.Sprintf("Cannot open file: %v", err))
		}
		defer f.Close()
		r = f
	}

	var lines []string
	scanner := bufio.NewScanner(r)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line != "" && !strings.HasPrefix(line, "#") {
			lines = append(lines, line)
		}
	}
	if err := scanner.Err(); err != nil {
		dief("Error reading input: %v\n", err)
	}
	return lines
}

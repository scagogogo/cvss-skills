package main

import (
	"fmt"
	"os"

	"github.com/scagogogo/cvss-parser/pkg/cvss"
	"github.com/scagogogo/cvss-parser/pkg/parser"
	"github.com/spf13/cobra"
)

var csvCmd = &cobra.Command{
	Use:   "csv",
	Short: "CSV file I/O for CVSS vectors",
	Long: `Read or write CVSS vectors from/to CSV files.

CSV format: first column is the vector string, followed by score columns.
The write subcommand reads vectors from arguments or stdin (one per line).
The read subcommand parses vectors from a CSV file.

Examples:
  cvss csv write -o output.csv "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" "CVSS:3.1/AV:L/AC:H/PR:H/UI:R/S:C/C:L/I:L/A:N"
  echo "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" | cvss csv write -
  cvss csv read input.csv
  cat vectors.csv | cvss csv read -`,
}

var csvWriteCmd = &cobra.Command{
	Use:   "write [vector-strings...]",
	Short: "Write CVSS vectors to CSV",
	Long: `Write CVSS vectors to a CSV file with scores.

If no output file is specified, writes to stdout.
Vectors can be passed as arguments or piped via stdin (one per line).`,
	Args: cobra.MinimumNArgs(0),
	Run: func(cmd *cobra.Command, args []string) {
		outputFile, _ := cmd.Flags().GetString("output")

		// Parse vectors from args or stdin
		var vectors []*cvss.Cvss3x

		if len(args) == 1 && args[0] == "-" {
			// Explicit stdin request
			lines := readLines(cmd, nil)
			for _, line := range lines {
				cv, err := parser.ParseString(line)
				if err != nil {
					fmt.Fprintf(os.Stderr, "Skipping invalid vector: %s (%v)\n", line, err)
					continue
				}
				vectors = append(vectors, cv)
			}
		} else if len(args) == 0 {
			// No args: try stdin if it's not a terminal
			stat, _ := os.Stdin.Stat()
			if (stat.Mode() & os.ModeCharDevice) == 0 {
				lines := readLines(cmd, nil)
				for _, line := range lines {
					cv, err := parser.ParseString(line)
					if err != nil {
						fmt.Fprintf(os.Stderr, "Skipping invalid vector: %s (%v)\n", line, err)
						continue
					}
					vectors = append(vectors, cv)
				}
			}
		} else {
			for _, s := range args {
				cv, err := parser.ParseString(s)
				if err != nil {
					fmt.Fprintf(os.Stderr, "Skipping invalid vector: %s (%v)\n", s, err)
					continue
				}
				vectors = append(vectors, cv)
			}
		}

		if len(vectors) == 0 {
			die("No valid vectors to write")
		}

		var w *os.File
		if outputFile != "" && outputFile != "-" {
			f, err := os.Create(outputFile)
			if err != nil {
				die(fmt.Sprintf("Cannot create file: %v", err))
			}
			defer f.Close()
			w = f
		} else {
			w = os.Stdout
		}

		if err := cvss.WriteCSV(w, vectors); err != nil {
			dief("CSV write error: %v\n", err)
		}
	},
}

var csvReadCmd = &cobra.Command{
	Use:   "read [file]",
	Short: "Read CVSS vectors from CSV",
	Long: `Read CVSS vectors from a CSV file.

If no file is specified or file is "-", reads from stdin.`,
	Args: cobra.MaximumNArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		lax, _ := cmd.Flags().GetBool("lax")

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

		if lax {
			vectors, errors, err := cvss.ReadCSVLax(r)
			if err != nil {
				dief("CSV read error: %v\n", err)
			}
			for _, cv := range vectors {
				fmt.Println(cv.String())
			}
			for _, e := range errors {
				fmt.Fprintf(os.Stderr, "Warning: %s\n", e.String())
			}
		} else {
			vectors, err := cvss.ReadCSV(r)
			if err != nil {
				dief("CSV read error: %v\n", err)
			}
			for _, cv := range vectors {
				fmt.Println(cv.String())
			}
		}
	},
}

func init() {
	csvWriteCmd.Flags().StringP("output", "o", "", "output file (default: stdout)")
	csvReadCmd.Flags().Bool("lax", false, "tolerant mode: skip invalid rows instead of failing")

	csvCmd.AddCommand(csvWriteCmd)
	csvCmd.AddCommand(csvReadCmd)
	rootCmd.AddCommand(csvCmd)
}

package main

import (
	"fmt"
	"os"

	"github.com/scagogogo/cvss-skills/pkg/cvss"
	"github.com/scagogogo/cvss-skills/pkg/parser"
	"github.com/spf13/cobra"
)

var batchCmd = &cobra.Command{
	Use:   "batch",
	Short: "Batch operations on multiple CVSS vectors",
	Long: `Process multiple CVSS vectors from a file or stdin.

Reads one vector string per line and processes them in parallel.

Examples:
  cvss batch score vectors.txt
  cat vectors.txt | cvss batch validate -
  cvss batch score --format json --workers 8 vectors.txt`,
}

var batchScoreCmd = &cobra.Command{
	Use:   "score [file]",
	Short: "Batch score multiple vectors",
	Long:  `Calculate scores for multiple vectors from a file or stdin.`,
	Args:  cobra.MaximumNArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		format, _ := cmd.Flags().GetString("format")
		workers, _ := cmd.Flags().GetInt("workers")

		lines := readLines(cmd, args)
		if len(lines) == 0 {
			return
		}

		// Parse
		parseResults := parser.BatchParse(lines, workers)
		var vectors []*cvss.Cvss3x
		var validIndices []int
		for _, r := range parseResults {
			if r.Error != nil {
				fmt.Fprintf(os.Stderr, "Line %d: parse error: %v\n", r.Index+1, r.Error)
				continue
			}
			vectors = append(vectors, r.Vector)
			validIndices = append(validIndices, r.Index)
		}

		if len(vectors) == 0 {
			return
		}

		// Score
		scoreResults := cvss.BatchScore(vectors, workers)

		for i, r := range scoreResults {
			origLine := validIndices[i] + 1
			if r.Error != nil {
				if format == "json" {
					fmt.Printf("{\"line\":%d,\"error\":\"%v\"}\n", origLine, r.Error)
				} else {
					fmt.Fprintf(os.Stderr, "Line %d: score error: %v\n", origLine, r.Error)
				}
				continue
			}
			if format == "json" {
				out := map[string]interface{}{
					"line":     origLine,
					"vector":   r.Vector.String(),
					"score":    r.Score,
					"severity": r.Severity.String(),
				}
				fmt.Println(marshalJSON(out))
			} else {
				fmt.Printf("%.1f (%s)  %s\n", r.Score, r.Severity, r.Vector.String())
			}
		}
	},
}

var batchValidateCmd = &cobra.Command{
	Use:   "validate [file]",
	Short: "Batch validate multiple vectors",
	Long:  `Validate multiple vectors from a file or stdin.`,
	Args:  cobra.MaximumNArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		workers, _ := cmd.Flags().GetInt("workers")

		lines := readLines(cmd, args)
		if len(lines) == 0 {
			return
		}

		results := parser.BatchValidate(lines, workers)
		hasErrors := false
		for _, r := range results {
			if r.Valid {
				fmt.Printf("PASS Line %d: %s\n", r.Index+1, lines[r.Index])
			} else {
				hasErrors = true
				fmt.Printf("FAIL Line %d: %s\n", r.Index+1, lines[r.Index])
				for _, e := range r.Errors {
					fmt.Printf("  - %s\n", e)
				}
			}
		}

		if hasErrors {
			os.Exit(1)
		}
	},
}

func init() {
	batchScoreCmd.Flags().String("format", "text", "output format: text or json")
	batchScoreCmd.Flags().Int("workers", 4, "number of parallel workers")
	batchValidateCmd.Flags().Int("workers", 4, "number of parallel workers")

	batchCmd.AddCommand(batchScoreCmd)
	batchCmd.AddCommand(batchValidateCmd)
	rootCmd.AddCommand(batchCmd)
}

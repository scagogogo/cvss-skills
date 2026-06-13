package main

import (
	"fmt"
	"strconv"

	"github.com/scagogogo/cvss-parser/pkg/cvss"
	"github.com/spf13/cobra"
)

var severityCmd = &cobra.Command{
	Use:   "severity [score]",
	Short: "Lookup severity rating from a numeric score",
	Long: `Convert a numeric CVSS score to its severity rating.

Thresholds (CVSS v3.1):
  None:     0.0
  Low:      0.1 - 3.9
  Medium:   4.0 - 6.9
  High:     7.0 - 8.9
  Critical: 9.0 - 10.0

Examples:
  cvss severity 9.8
  cvss severity --format json 5.5`,
	Args: cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		score, err := strconv.ParseFloat(args[0], 64)
		if err != nil {
			dief("Invalid score: %v\n", err)
		}
		severity := cvss.GetSeverity(score)
		format, _ := cmd.Flags().GetString("format")

		if format == "json" {
			out := map[string]interface{}{
				"score":    score,
				"severity": severity.String(),
			}
			fmt.Println(marshalJSON(out))
		} else {
			fmt.Println(severity)
		}
	},
}

func init() {
	severityCmd.Flags().String("format", "text", "output format: text or json")
	rootCmd.AddCommand(severityCmd)
}

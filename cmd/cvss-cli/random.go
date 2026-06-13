package main

import (
	"fmt"

	"github.com/scagogogo/cvss-parser/pkg/cvss"
	"github.com/scagogogo/cvss-parser/pkg/mock"
	"github.com/spf13/cobra"
)

var randomCmd = &cobra.Command{
	Use:   "random",
	Short: "Generate a random CVSS vector",
	Long: `Generate a random CVSS vector for testing or demonstration.

By default generates base-only metrics. Use flags to include temporal
or full (temporal + environmental) metrics.

Examples:
  cvss random
  cvss random --temporal
  cvss random --full
  cvss random --cvss-version 3.0 --full --score
  cvss random --format json`,
	Run: func(cmd *cobra.Command, args []string) {
		version, _ := cmd.Flags().GetString("cvss-version")
		full, _ := cmd.Flags().GetBool("full")
		temporal, _ := cmd.Flags().GetBool("temporal")

		minor := 1
		if version == "3.0" {
			minor = 0
		}

		var cv *cvss.Cvss3x
		if full {
			cv = mock.RandomCvss3xFull(minor)
		} else if temporal {
			cv = mock.RandomCvss3xWithTemporal(minor)
		} else {
			cv = mock.RandomCvss3x(minor)
		}

		showScore, _ := cmd.Flags().GetBool("score")
		format, _ := cmd.Flags().GetString("format")

		if format == "json" {
			out := map[string]interface{}{
				"vector": cv.String(),
			}
			if showScore {
				calc := cvss.NewCalculator(cv)
				score, err := calc.Calculate()
				if err == nil {
					out["score"] = score
					out["severity"] = cvss.GetSeverity(score).String()
				}
			}
			fmt.Println(marshalJSON(out))
			return
		}

		fmt.Println(cv.String())
		if showScore {
			calc := cvss.NewCalculator(cv)
			score, err := calc.Calculate()
			if err != nil {
				fmt.Printf("Score: (error: %v)\n", err)
			} else {
				fmt.Printf("Score: %.1f (%s)\n", score, cvss.GetSeverity(score))
			}
		}
	},
}

func init() {
	randomCmd.Flags().Bool("temporal", false, "include temporal metrics")
	randomCmd.Flags().Bool("full", false, "include temporal and environmental metrics")
	randomCmd.Flags().String("cvss-version", "3.1", "CVSS version: 3.0 or 3.1")
	randomCmd.Flags().Bool("score", false, "show calculated score")
	randomCmd.Flags().String("format", "text", "output format: text or json")
	rootCmd.AddCommand(randomCmd)
}

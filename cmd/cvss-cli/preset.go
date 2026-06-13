package main

import (
	"fmt"

	"github.com/scagogogo/cvss-parser/pkg/cvss"
	"github.com/spf13/cobra"
)

var presetCmd = &cobra.Command{
	Use:   "preset [severity]",
	Short: "Generate a preset CVSS vector",
	Long: `Generate a preset CVSS vector for a given severity level.

Available severity levels: critical, high, medium, low, none
Default version is 3.1; use --version to get 3.0 presets.

Examples:
  cvss preset critical
  cvss preset --version 3.0 high
  cvss preset --score medium
  cvss preset --format json critical`,
	Args: cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		severity := args[0]
		version, _ := cmd.Flags().GetString("version")
		showScore, _ := cmd.Flags().GetBool("score")
		format, _ := cmd.Flags().GetString("format")

		var cv *cvss.Cvss3x

		if version == "3.0" {
			switch severity {
			case "critical":
				cv = cvss.CriticalV30()
			case "high":
				cv = cvss.HighV30()
			case "medium":
				cv = cvss.MediumV30()
			case "low":
				cv = cvss.LowV30()
			case "none":
				cv = cvss.NoneV30()
			default:
				dief("Unknown severity: %s (use: critical, high, medium, low, none)\n", severity)
			}
		} else {
			switch severity {
			case "critical":
				cv = cvss.CriticalV31()
			case "high":
				cv = cvss.HighV31()
			case "medium":
				cv = cvss.MediumV31()
			case "low":
				cv = cvss.LowV31()
			case "none":
				cv = cvss.NoneV31()
			default:
				dief("Unknown severity: %s (use: critical, high, medium, low, none)\n", severity)
			}
		}

		if format == "json" {
			out := map[string]interface{}{
				"severity": severity,
				"vector":   cv.String(),
			}
			if showScore {
				calc := cvss.NewCalculator(cv)
				score, _ := calc.Calculate()
				out["score"] = score
				out["severity_rating"] = cvss.GetSeverity(score).String()
			}
			fmt.Println(marshalJSON(out))
			return
		}

		fmt.Println(cv.String())
		if showScore {
			calc := cvss.NewCalculator(cv)
			score, _ := calc.Calculate()
			fmt.Printf("Score: %.1f (%s)\n", score, cvss.GetSeverity(score))
		}
	},
}

func init() {
	presetCmd.Flags().String("version", "3.1", "CVSS version: 3.0 or 3.1")
	presetCmd.Flags().Bool("score", false, "show score alongside vector string")
	presetCmd.Flags().String("format", "text", "output format: text or json")
	rootCmd.AddCommand(presetCmd)
}

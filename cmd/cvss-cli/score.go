package main

import (
	"fmt"

	"github.com/scagogogo/cvss-skills/pkg/cvss"
	"github.com/scagogogo/cvss-skills/pkg/parser"
	"github.com/spf13/cobra"
)

var scoreCmd = &cobra.Command{
	Use:   "score [vector-string]",
	Short: "Calculate CVSS scores",
	Long: `Calculate CVSS scores from a vector string.

Outputs the overall score by default. Use flags to get specific scores:
  --all        Show all scores (base, temporal, environmental) with severities
  --breakdown  Show per-metric score breakdown
  --format     Output format: text (default), json

Examples:
  cvss score "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
  cvss score --all "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
  cvss score --breakdown "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
  cvss score --format json "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"`,
	Args: cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		cv, err := parser.ParseString(args[0])
		if err != nil {
			dief("Parse error: %v\n", err)
		}

		calc := cvss.NewCalculator(cv)
		showAll, _ := cmd.Flags().GetBool("all")
		showBreakdown, _ := cmd.Flags().GetBool("breakdown")
		format, _ := cmd.Flags().GetString("format")

		if showBreakdown {
			bd, err := calc.GetScoreBreakdown()
			if err != nil {
				dief("Error: %v\n", err)
			}
			printBreakdown(bd)
			return
		}

		if showAll {
			scores, err := calc.GetAllScores()
			if err != nil {
				dief("Error: %v\n", err)
			}
			if format == "json" {
				fmt.Println(marshalJSON(scores))
			} else {
				fmt.Println(scores.String())
			}
			return
		}

		// Default: calculate overall score
		score, err := calc.Calculate()
		if err != nil {
			dief("Error: %v\n", err)
		}
		severity := cvss.GetSeverity(score)
		if format == "json" {
			out := map[string]interface{}{
				"score":    score,
				"severity": severity.String(),
			}
			fmt.Println(marshalJSON(out))
		} else {
			fmt.Printf("%.1f (%s)\n", score, severity)
		}
	},
}

func printBreakdown(bd *cvss.ScoreBreakdown) {
	fmt.Println("=== Score Breakdown ===")
	fmt.Println("--- Base Metrics ---")
	printMetricScore(bd.AttackVector)
	printMetricScore(bd.AttackComplexity)
	printMetricScore(bd.PrivilegesRequired)
	printMetricScore(bd.UserInteraction)
	printMetricScore(bd.Scope)
	printMetricScore(bd.Confidentiality)
	printMetricScore(bd.Integrity)
	printMetricScore(bd.Availability)

	if bd.ExploitCodeMaturity.ShortName != "" {
		fmt.Println("--- Temporal Metrics ---")
		printMetricScore(bd.ExploitCodeMaturity)
		printMetricScore(bd.RemediationLevel)
		printMetricScore(bd.ReportConfidence)
	}

	if bd.ConfidentialityRequirement.ShortName != "" {
		fmt.Println("--- Environmental Metrics ---")
		printMetricScore(bd.ConfidentialityRequirement)
		printMetricScore(bd.IntegrityRequirement)
		printMetricScore(bd.AvailabilityRequirement)
		printMetricScore(bd.ModifiedAttackVector)
		printMetricScore(bd.ModifiedAttackComplexity)
		printMetricScore(bd.ModifiedPrivilegesRequired)
		printMetricScore(bd.ModifiedUserInteraction)
		printMetricScore(bd.ModifiedScope)
		printMetricScore(bd.ModifiedConfidentiality)
		printMetricScore(bd.ModifiedIntegrity)
		printMetricScore(bd.ModifiedAvailability)
	}
}

func printMetricScore(ms cvss.MetricScore) {
	if ms.ShortName == "" {
		return
	}
	fmt.Printf("  %s:%s = %.4f  (%s)\n", ms.ShortName, ms.Value, ms.Score, ms.LongName)
}

func init() {
	scoreCmd.Flags().Bool("all", false, "show all scores with severities")
	scoreCmd.Flags().Bool("breakdown", false, "show per-metric score breakdown")
	scoreCmd.Flags().String("format", "text", "output format: text or json")
	rootCmd.AddCommand(scoreCmd)
}
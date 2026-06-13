package main

import (
	"fmt"

	"github.com/scagogogo/cvss-parser/pkg/cvss"
	"github.com/scagogogo/cvss-parser/pkg/parser"
	"github.com/spf13/cobra"
)

var analyzeCmd = &cobra.Command{
	Use:   "analyze [vector-string]",
	Short: "Analyze score impact and sensitivity of a CVSS vector",
	Long: `Analyze how each metric affects the overall CVSS score.

Shows:
  • Impact analysis: how changing each metric affects the score
  • Sensitivity analysis: which metrics have the largest score swing

Examples:
  cvss analyze "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
  cvss analyze --target 7.0 "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"`,
	Args: cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		cv, err := parser.ParseString(args[0])
		if err != nil {
			dief("Parse error: %v\n", err)
		}

		target, _ := cmd.Flags().GetFloat64("target")
		sensOnly, _ := cmd.Flags().GetBool("sensitivity")

		if !sensOnly {
			// Impact analysis
			impacts, err := cvss.ImpactAnalysis(cv)
			if err != nil {
				dief("Analysis error: %v\n", err)
			}

			fmt.Println("=== Impact Analysis ===")
			for _, mi := range impacts {
				fmt.Print(mi.String())
			}
			fmt.Println()
		}

		// Sensitivity analysis
		sens, err := cvss.SensitivityAnalysis(cv)
		if err != nil {
			dief("Sensitivity error: %v\n", err)
		}

		fmt.Println("=== Sensitivity Analysis ===")
		for _, s := range sens {
			fmt.Println(s.String())
		}

		// Target score analysis
		if target > 0 {
			changes, err := cvss.FindMetricChangesToReachTarget(cv, target)
			if err != nil {
				dief("Target analysis error: %v\n", err)
			}

			fmt.Printf("\n=== Changes to reach score %.1f ===\n", target)
			if len(changes) == 0 {
				fmt.Println("Already at target score")
			} else {
				for _, c := range changes {
					fmt.Println(c.String())
				}
			}
		}
	},
}

func init() {
	analyzeCmd.Flags().Float64("target", 0, "find metric changes to reach target score")
	analyzeCmd.Flags().Bool("sensitivity", false, "only show sensitivity analysis")
	rootCmd.AddCommand(analyzeCmd)
}
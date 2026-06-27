package main

import (
	"fmt"

	"github.com/scagogogo/cvss-skills/pkg/cvss"
	"github.com/scagogogo/cvss-skills/pkg/parser"
	"github.com/spf13/cobra"
)

var subsCmd = &cobra.Command{
	Use:   "subs [vector-string]",
	Short: "Display sub-scores (Impact and Exploitability)",
	Long: `Display the Impact Sub-Score and Exploitability Sub-Score.

For vectors with environmental metrics, also shows Modified Impact
and Modified Exploitability sub-scores.

Examples:
  cvss subs "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
  cvss subs --format json "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"`,
	Args: cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		cv, err := parser.ParseString(args[0])
		if err != nil {
			dief("Parse error: %v\n", err)
		}

		calc := cvss.NewCalculator(cv)
		format, _ := cmd.Flags().GetString("format")

		impact, err := calc.GetImpactSubScore()
		if err != nil {
			dief("Error: %v\n", err)
		}
		exploitability, err := calc.GetExploitabilitySubScore()
		if err != nil {
			dief("Error: %v\n", err)
		}

		if format == "json" {
			out := map[string]interface{}{
				"impact_sub_score":        impact,
				"exploitability_sub_score": exploitability,
			}
			if cv.HasEnvironmentalMetrics() {
				modImpact, err := calc.GetModifiedImpactSubScore()
				if err == nil {
					out["modified_impact_sub_score"] = modImpact
				}
				modExploit, err := calc.GetModifiedExploitabilitySubScore()
				if err == nil {
					out["modified_exploitability_sub_score"] = modExploit
				}
			}
			fmt.Println(marshalJSON(out))
			return
		}

		fmt.Printf("Impact Sub-Score:        %.4f\n", impact)
		fmt.Printf("Exploitability Sub-Score: %.4f\n", exploitability)

		if cv.HasEnvironmentalMetrics() {
			modImpact, err := calc.GetModifiedImpactSubScore()
			if err == nil {
				fmt.Printf("Modified Impact Sub-Score:        %.4f\n", modImpact)
			}
			modExploit, err := calc.GetModifiedExploitabilitySubScore()
			if err == nil {
				fmt.Printf("Modified Exploitability Sub-Score: %.4f\n", modExploit)
			}
		}
	},
}

func init() {
	subsCmd.Flags().String("format", "text", "output format: text or json")
	rootCmd.AddCommand(subsCmd)
}

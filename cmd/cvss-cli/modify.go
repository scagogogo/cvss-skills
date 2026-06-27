package main

import (
	"fmt"
	"strings"

	"github.com/scagogogo/cvss-skills/pkg/cvss"
	"github.com/scagogogo/cvss-skills/pkg/parser"
	"github.com/spf13/cobra"
)

var modifyCmd = &cobra.Command{
	Use:   "modify [vector-string]",
	Short: "Modify one or more metrics in a CVSS vector",
	Long: `Modify metrics in an existing CVSS vector and output the result.

Accepts a vector string and metric changes as flags. Returns a new
vector with the changes applied (original is not modified).

Examples:
  cvss modify "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" --AV=L
  cvss modify "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" --AV=L --S=C --E=F
  cvss modify --format json "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" --AV=L`,
	Args: cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		cv, err := parser.ParseString(args[0])
		if err != nil {
			dief("Parse error: %v\n", err)
		}

		// Apply each metric modification
		metrics := []string{
			"AV", "AC", "PR", "UI", "S", "C", "I", "A",
			"E", "RL", "RC",
			"CR", "IR", "AR",
			"MAV", "MAC", "MPR", "MUI", "MS", "MC", "MI", "MA",
		}

		showScore, _ := cmd.Flags().GetBool("score")
		format, _ := cmd.Flags().GetString("format")
		modified := cv

		for _, m := range metrics {
			val, _ := cmd.Flags().GetString(m)
			if val == "" {
				continue
			}
			r := []rune(strings.ToUpper(val))[0]
			result, err := modified.SetMetricValue(m, r)
			if err != nil {
				dief("Error setting %s=%s: %v\n", m, val, err)
			}
			modified = result
		}

		if format == "json" {
			calc := cvss.NewCalculator(modified)
			data, err := modified.ToJSON(calc)
			if err != nil {
				dief("JSON error: %v\n", err)
			}
			fmt.Println(string(data))
		} else {
			fmt.Println(modified.String())
			if showScore {
				calc := cvss.NewCalculator(modified)
				score, _ := calc.Calculate()
				fmt.Printf("Score: %.1f (%s)\n", score, cvss.GetSeverity(score))
			}
		}
	},
}

func init() {
	// Base metrics
	modifyCmd.Flags().String("AV", "", "Attack Vector (N/A/L/P)")
	modifyCmd.Flags().String("AC", "", "Attack Complexity (L/H)")
	modifyCmd.Flags().String("PR", "", "Privileges Required (N/L/H)")
	modifyCmd.Flags().String("UI", "", "User Interaction (N/R)")
	modifyCmd.Flags().String("S", "", "Scope (U/C)")
	modifyCmd.Flags().String("C", "", "Confidentiality (H/L/N)")
	modifyCmd.Flags().String("I", "", "Integrity (H/L/N)")
	modifyCmd.Flags().String("A", "", "Availability (H/L/N)")
	// Temporal
	modifyCmd.Flags().String("E", "", "Exploit Code Maturity (X/U/P/F/H)")
	modifyCmd.Flags().String("RL", "", "Remediation Level (X/O/T/W/U)")
	modifyCmd.Flags().String("RC", "", "Report Confidence (X/U/R/C)")
	// Environmental requirements
	modifyCmd.Flags().String("CR", "", "Confidentiality Requirement (X/H/M/L)")
	modifyCmd.Flags().String("IR", "", "Integrity Requirement (X/H/M/L)")
	modifyCmd.Flags().String("AR", "", "Availability Requirement (X/H/M/L)")
	// Modified base metrics
	modifyCmd.Flags().String("MAV", "", "Modified Attack Vector (X/N/A/L/P)")
	modifyCmd.Flags().String("MAC", "", "Modified Attack Complexity (X/L/H)")
	modifyCmd.Flags().String("MPR", "", "Modified Privileges Required (X/N/L/H)")
	modifyCmd.Flags().String("MUI", "", "Modified User Interaction (X/N/R)")
	modifyCmd.Flags().String("MS", "", "Modified Scope (X/U/C)")
	modifyCmd.Flags().String("MC", "", "Modified Confidentiality (X/H/L/N)")
	modifyCmd.Flags().String("MI", "", "Modified Integrity (X/H/L/N)")
	modifyCmd.Flags().String("MA", "", "Modified Availability (X/H/L/N)")
	modifyCmd.Flags().Bool("score", false, "show calculated score")
	modifyCmd.Flags().String("format", "text", "output format: text or json")

	rootCmd.AddCommand(modifyCmd)
}

package main

import (
	"fmt"

	"github.com/scagogogo/cvss-skills/pkg/cvss"
	"github.com/scagogogo/cvss-skills/pkg/parser"
	"github.com/spf13/cobra"
)

var describeCmd = &cobra.Command{
	Use:   "describe [vector-string]",
	Short: "Human-readable description of a CVSS vector",
	Long: `Display a human-readable description of all metrics in a CVSS vector.

Examples:
  cvss describe "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
  cvss describe --format json "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"`,
	Args: cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		cv, err := parser.ParseString(args[0])
		if err != nil {
			dief("Parse error: %v\n", err)
		}

		format, _ := cmd.Flags().GetString("format")
		if format == "json" {
			calc := cvss.NewCalculator(cv)
			data, err := cv.ToJSON(calc)
			if err != nil {
				dief("JSON error: %v\n", err)
			}
			fmt.Println(string(data))
		} else {
			fmt.Println(cv.Description())
		}
	},
}

func init() {
	describeCmd.Flags().String("format", "text", "output format: text or json")
	rootCmd.AddCommand(describeCmd)
}

package main

import (
	"fmt"

	"github.com/scagogogo/cvss-skills/pkg/cvss"
	"github.com/scagogogo/cvss-skills/pkg/parser"
	"github.com/spf13/cobra"
)

var parseCmd = &cobra.Command{
	Use:   "parse [vector-string]",
	Short: "Parse a CVSS vector string",
	Long: `Parse a CVSS vector string and display its components.

By default, requires the "CVSS:3.x/" prefix. Use --relaxed to parse
without the prefix, with an optional default version.

Examples:
  cvss parse "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
  cvss parse --relaxed --default-version 3.1 "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"`,
	Args: cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		var cv *cvss.Cvss3x
		var err error

		relaxed, _ := cmd.Flags().GetBool("relaxed")
		defaultVersion, _ := cmd.Flags().GetString("default-version")

		if relaxed {
			cv, err = parser.ParseRelaxed(args[0], defaultVersion)
		} else {
			cv, err = parser.ParseString(args[0])
		}
		if err != nil {
			dief("Parse error: %v\n", err)
		}

		fmt.Println("Version:", cv.Version())
		fmt.Println("Complete:", cv.IsComplete())
		fmt.Println("Has Temporal:", cv.HasTemporalMetrics())
		fmt.Println("Has Environmental:", cv.HasEnvironmentalMetrics())
		fmt.Println()
		fmt.Println("Vector String:", cv.String())
		fmt.Println()
		fmt.Println("Description:")
		fmt.Println(cv.Description())
	},
}

func init() {
	parseCmd.Flags().Bool("relaxed", false, "parse without CVSS: prefix")
	parseCmd.Flags().String("default-version", "3.1", "default version for relaxed parsing")
	rootCmd.AddCommand(parseCmd)
}

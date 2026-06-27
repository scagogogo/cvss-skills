package main

import (
	"fmt"
	"os"

	"github.com/scagogogo/cvss-skills/pkg/cvss"
	"github.com/scagogogo/cvss-skills/pkg/parser"
	"github.com/spf13/cobra"
)

var jsonCmd = &cobra.Command{
	Use:   "json [vector-string]",
	Short: "Serialize CVSS vector to JSON",
	Long: `Serialize a CVSS vector string to structured JSON format.

The JSON output includes the vector string, all scores, severity ratings,
and metric details with long names.

Examples:
  cvss json "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"`,
	Args: cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		cv, err := parser.ParseString(args[0])
		if err != nil {
			fmt.Fprintln(os.Stderr, "Parse error:", err)
			os.Exit(1)
		}

		calc := cvss.NewCalculator(cv)
		data, err := cv.ToJSON(calc)
		if err != nil {
			fmt.Fprintln(os.Stderr, "JSON error:", err)
			os.Exit(1)
		}

		fmt.Println(string(data))
	},
}

func init() {
	rootCmd.AddCommand(jsonCmd)
}

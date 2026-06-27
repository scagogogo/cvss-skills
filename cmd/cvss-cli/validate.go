package main

import (
	"fmt"
	"os"

	"github.com/scagogogo/cvss-skills/pkg/parser"
	"github.com/spf13/cobra"
)

var validateCmd = &cobra.Command{
	Use:   "validate [vector-string]",
	Short: "Validate a CVSS vector string",
	Long: `Validate a CVSS vector string and report any issues.

Reports all missing or invalid metrics in one pass (not short-circuit).

Examples:
  cvss validate "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
  cvss validate --format json "CVSS:3.1/AV:N/AC:L"`,
	Args: cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		format, _ := cmd.Flags().GetString("format")

		cv, err := parser.ParseAndValidate(args[0])
		if err != nil {
			if format == "json" {
				out := map[string]interface{}{
					"valid":  false,
					"errors": err.Error(),
				}
				fmt.Println(marshalJSON(out))
			} else {
				fmt.Fprintln(os.Stderr, "Validation failed:", err)
			}
			os.Exit(1)
		}

		if format == "json" {
			out := map[string]interface{}{
				"valid":    true,
				"version":  cv.Version(),
				"complete": cv.IsComplete(),
			}
			fmt.Println(marshalJSON(out))
		} else {
			fmt.Println("Valid [PASS]")
			fmt.Printf("  Version: %s\n", cv.Version())
			fmt.Printf("  Complete: %v\n", cv.IsComplete())
		}
	},
}

func init() {
	validateCmd.Flags().String("format", "text", "output format: text or json")
	rootCmd.AddCommand(validateCmd)
}

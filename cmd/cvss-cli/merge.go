package main

import (
	"fmt"

	"github.com/scagogogo/cvss-parser/pkg/cvss"
	"github.com/scagogogo/cvss-parser/pkg/parser"
	"github.com/spf13/cobra"
)

var mergeCmd = &cobra.Command{
	Use:   "merge [vector1] [vector2]",
	Short: "Merge two CVSS vectors",
	Long: `Merge two CVSS vectors. Fields from vector2 fill in missing
fields in vector1. Existing fields in vector1 are not overwritten.

Examples:
  cvss merge "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" "CVSS:3.1/E:F/RL:T/RC:C"
  cvss merge --format json "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" "CVSS:3.1/E:F/RL:T/RC:C"`,
	Args: cobra.ExactArgs(2),
	Run: func(cmd *cobra.Command, args []string) {
		cv1, err := parser.ParseString(args[0])
		if err != nil {
			dief("Parse error (vector1): %v\n", err)
		}
		cv2, err := parser.ParseString(args[1])
		if err != nil {
			dief("Parse error (vector2): %v\n", err)
		}

		merged := cv1.Merge(cv2)
		format, _ := cmd.Flags().GetString("format")

		if format == "json" {
			calc := cvss.NewCalculator(merged)
			data, err := merged.ToJSON(calc)
			if err != nil {
				dief("JSON error: %v\n", err)
			}
			fmt.Println(string(data))
		} else {
			fmt.Println(merged.String())
		}
	},
}

func init() {
	mergeCmd.Flags().String("format", "text", "output format: text or json")
	rootCmd.AddCommand(mergeCmd)
}

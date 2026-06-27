package main

import (
	"fmt"
	"os"

	"github.com/scagogogo/cvss-skills/pkg/parser"
	"github.com/spf13/cobra"
)

var equalCmd = &cobra.Command{
	Use:   "equal [vector1] [vector2]",
	Short: "Check if two CVSS vectors are equal",
	Long: `Check if two CVSS vectors are identical (deep equality).

Exit code 0 if equal, 1 if different or on error.

Examples:
  cvss equal "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
  cvss equal --format json "CVSS:3.1/AV:N/..." "CVSS:3.1/AV:L/..."`,
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

		eq := cv1.Equal(cv2)
		format, _ := cmd.Flags().GetString("format")

		if format == "json" {
			out := map[string]interface{}{
				"equal":   eq,
				"vector1": cv1.String(),
				"vector2": cv2.String(),
			}
			fmt.Println(marshalJSON(out))
		} else {
			if eq {
				fmt.Println("Equal")
			} else {
				fmt.Println("Not equal")
			}
		}

		if !eq {
			fmt.Fprintf(os.Stderr, "not equal\n")
			os.Exit(1)
		}
	},
}

func init() {
	equalCmd.Flags().String("format", "text", "output format: text or json")
	rootCmd.AddCommand(equalCmd)
}

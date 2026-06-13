package main

import (
	"fmt"

	"github.com/scagogogo/cvss-parser/pkg/parser"
	"github.com/spf13/cobra"
)

var mapCmd = &cobra.Command{
	Use:   "map [vector-string]",
	Short: "Output CVSS vector as key=value pairs",
	Long: `Output a CVSS vector as key=value pairs, useful for scripting.

Examples:
  cvss map "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
  # Output:
  # AV=N
  # AC=L
  # PR=N
  # ...`,
	Args: cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		cv, err := parser.ParseString(args[0])
		if err != nil {
			dief("Parse error: %v\n", err)
		}

		m := cv.ToMap()
		// Print in canonical order
		order := []string{"version", "AV", "AC", "PR", "UI", "S", "C", "I", "A",
			"E", "RL", "RC", "CR", "IR", "AR", "MAV", "MAC", "MPR", "MUI", "MS", "MC", "MI", "MA"}

		for _, key := range order {
			if val, ok := m[key]; ok {
				fmt.Printf("%s=%s\n", key, val)
			}
		}
	},
}

func init() {
	rootCmd.AddCommand(mapCmd)
}

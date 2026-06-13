package main

import (
	"fmt"

	"github.com/scagogogo/cvss-parser/pkg/parser"
	"github.com/spf13/cobra"
)

var groupsCmd = &cobra.Command{
	Use:   "groups [vector-string]",
	Short: "Display metric groups (Base/Temporal/Environmental)",
	Long: `Display the metrics of a CVSS vector organized by group.

Shows each metric with its short name, current value, and long name,
grouped into Base, Temporal, and Environmental sections.

Examples:
  cvss groups "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
  cvss groups --format json "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H/E:F/RL:T/RC:C"`,
	Args: cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		cv, err := parser.ParseString(args[0])
		if err != nil {
			dief("Parse error: %v\n", err)
		}

		groups := cv.GetMetricGroups()
		format, _ := cmd.Flags().GetString("format")

		if format == "json" {
			fmt.Println(marshalJSON(groups))
			return
		}

		for _, g := range groups {
			fmt.Printf("\n[%s]\n", g.Name)
			for _, m := range g.Metrics {
				fmt.Printf("  %s:%s  %s = %s\n", m.ShortName, m.Value, m.LongName, m.LongValue)
			}
		}
	},
}

func init() {
	groupsCmd.Flags().String("format", "text", "output format: text or json")
	rootCmd.AddCommand(groupsCmd)
}

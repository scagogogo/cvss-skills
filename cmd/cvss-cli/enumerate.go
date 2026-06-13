package main

import (
	"fmt"
	"os"
	"strings"

	"github.com/scagogogo/cvss-parser/pkg/cvss"
	"github.com/spf13/cobra"
)

var enumerateCmd = &cobra.Command{
	Use:   "enumerate",
	Short: "List CVSS metric definitions and valid values",
	Long: `List all CVSS v3.x metrics, their valid values, and scores.

Examples:
  cvss enumerate
  cvss enumerate --metric AV
  cvss enumerate --validate-value AV:N
  cvss enumerate --format json`,
	Run: func(cmd *cobra.Command, args []string) {
		metric, _ := cmd.Flags().GetString("metric")
		validateValue, _ := cmd.Flags().GetString("validate-value")
		format, _ := cmd.Flags().GetString("format")

		if validateValue != "" {
			// Validate a specific metric value
			if len(validateValue) < 3 {
				dief("Invalid format, use METRIC:VALUE (e.g. AV:N)\n")
			}
			parts := strings.SplitN(validateValue, ":", 2)
			if len(parts) != 2 || len(parts[1]) != 1 {
				dief("Invalid format, use METRIC:VALUE (e.g. AV:N)\n")
			}
			shortName := parts[0]
			r := []rune(parts[1])[0]
			valid := cvss.IsValidMetricValue(shortName, r)
			if valid {
				info, _ := cvss.GetMetricInfo(shortName)
				for _, v := range info.Values {
					if v.ShortValue == r {
						if format == "json" {
							out := map[string]interface{}{
								"valid":      true,
								"metric":     shortName,
								"value":      string(r),
								"long_value": v.LongValue,
								"score":      v.Score,
							}
							fmt.Println(marshalJSON(out))
						} else {
							fmt.Printf("Valid: %s = %s (%s, score: %.2f)\n",
								shortName, string(r), v.LongValue, v.Score)
						}
						return
					}
				}
			} else {
				if format == "json" {
					out := map[string]interface{}{
						"valid":  false,
						"metric": shortName,
						"value":  string(r),
					}
					fmt.Println(marshalJSON(out))
				} else {
					fmt.Printf("Invalid: %s is not a valid value for %s\n", string(r), shortName)
				}
				os.Exit(1)
			}
			return
		}

		if metric != "" {
			// Show specific metric
			info, err := cvss.GetMetricInfo(metric)
			if err != nil {
				dief("Error: %v\n", err)
			}
			if format == "json" {
				fmt.Println(marshalJSON(info))
			} else {
				fmt.Print(info.String())
			}
			return
		}

		// Show all metrics
		metrics := cvss.ListAllMetrics()
		if format == "json" {
			fmt.Println(marshalJSON(metrics))
			return
		}
		currentGroup := ""
		for _, m := range metrics {
			if m.Group != currentGroup {
				currentGroup = m.Group
				fmt.Printf("\n=== %s Metrics ===\n", currentGroup)
			}
			fmt.Print(m.String())
		}
	},
}

func init() {
	enumerateCmd.Flags().String("metric", "", "show details for a specific metric (e.g. AV)")
	enumerateCmd.Flags().String("validate-value", "", "validate a metric:value pair (e.g. AV:N)")
	enumerateCmd.Flags().String("format", "text", "output format: text or json")
	rootCmd.AddCommand(enumerateCmd)
}

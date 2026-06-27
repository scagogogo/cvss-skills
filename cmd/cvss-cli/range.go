package main

import (
	"fmt"
	"os"

	"github.com/scagogogo/cvss-skills/pkg/cvss"
	"github.com/scagogogo/cvss-skills/pkg/parser"
	"github.com/spf13/cobra"
)

var rangeCmd = &cobra.Command{
	Use:   "range [vector-string]",
	Short: "Calculate score range for a (possibly partial) CVSS vector",
	Long: `Calculate the minimum and maximum possible score for a CVSS vector.

For complete vectors, min = max = actual score.
For partial vectors (missing base metrics), shows the score range
by trying all possible combinations of missing metrics.

Use --worst or --best to see the filled-in vector that produces
the highest or lowest score.

Examples:
  cvss range "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
  cvss range "CVSS:3.1/AV:N/AC:L"
  cvss range --worst "CVSS:3.1/AV:N/AC:L"
  cvss range --best --format json "CVSS:3.1/AV:N/AC:L"`,
	Args: cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		cv, err := parser.ParseRelaxed(args[0], "3.1")
		if err != nil {
			dief("Parse error: %v\n", err)
		}

		showWorst, _ := cmd.Flags().GetBool("worst")
		showBest, _ := cmd.Flags().GetBool("best")
		format, _ := cmd.Flags().GetString("format")

		rng := cvss.GetScoreRange(cv)

		if format == "json" {
			fmt.Println(marshalJSON(rng))
			return
		}

		fmt.Printf("Score range: %.1f (%s) ~ %.1f (%s)\n",
			rng.MinScore, rng.MinSeverity, rng.MaxScore, rng.MaxSeverity)
		fmt.Printf("Complete: %v, Missing metrics: %d\n", rng.IsComplete, rng.MissingCount)

		if showWorst {
			worst, score, err := cvss.GetWorstCase(cv)
			if err != nil {
				fmt.Fprintln(os.Stderr, "Worst case error:", err)
			} else {
				fmt.Printf("Worst case: %s (%.1f)\n", worst.String(), score)
			}
		}

		if showBest {
			best, score, err := cvss.GetBestCase(cv)
			if err != nil {
				fmt.Fprintln(os.Stderr, "Best case error:", err)
			} else {
				fmt.Printf("Best case: %s (%.1f)\n", best.String(), score)
			}
		}
	},
}

func init() {
	rangeCmd.Flags().Bool("worst", false, "show the worst-case (highest score) vector")
	rangeCmd.Flags().Bool("best", false, "show the best-case (lowest score) vector")
	rangeCmd.Flags().String("format", "text", "output format: text or json")
	rootCmd.AddCommand(rangeCmd)
}
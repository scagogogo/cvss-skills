package main

import (
	"fmt"

	"github.com/scagogogo/cvss-parser/pkg/cvss"
	"github.com/scagogogo/cvss-parser/pkg/parser"
	"github.com/spf13/cobra"
)

var diffCmd = &cobra.Command{
	Use:   "diff [vector1] [vector2]",
	Short: "Compare two CVSS vectors",
	Long: `Compare two CVSS vectors and show differences.

Shows which metrics differ between the two vectors, along with
score differences and severity changes.

Examples:
  cvss diff "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" "CVSS:3.1/AV:L/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
  cvss diff --format json "CVSS:3.1/AV:N/..." "CVSS:3.1/AV:L/..."`,
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

		format, _ := cmd.Flags().GetString("format")
		diffs := cv1.Diff(cv2)

		calc1 := cvss.NewCalculator(cv1)
		calc2 := cvss.NewCalculator(cv2)
		s1, _ := calc1.Calculate()
		s2, _ := calc2.Calculate()

		if format == "json" {
			type diffEntry struct {
				Metric  string `json:"metric"`
				V1      string `json:"v1"`
				V1Long  string `json:"v1_long"`
				V2      string `json:"v2"`
				V2Long  string `json:"v2_long"`
			}
			entries := make([]diffEntry, len(diffs))
			for i, d := range diffs {
				entries[i] = diffEntry{
					Metric:  d.Metric,
					V1:      d.V1,
					V1Long:  d.V1Long,
					V2:      d.V2,
					V2Long:  d.V2Long,
				}
			}
			out := map[string]interface{}{
				"differences": entries,
				"score1":      s1,
				"severity1":   cvss.GetSeverity(s1).String(),
				"score2":      s2,
				"severity2":   cvss.GetSeverity(s2).String(),
				"score_delta": s2 - s1,
			}
			fmt.Println(marshalJSON(out))
			return
		}

		if len(diffs) == 0 {
			fmt.Println("Vectors are identical")
			return
		}

		fmt.Printf("Found %d difference(s):\n\n", len(diffs))
		for _, d := range diffs {
			fmt.Printf("  %s: %s (%s) → %s (%s)\n", d.Metric, d.V1, d.V1Long, d.V2, d.V2Long)
		}

		fmt.Printf("\nScore: %.1f (%s) → %.1f (%s)  [Δ=%.1f]\n",
			s1, cvss.GetSeverity(s1), s2, cvss.GetSeverity(s2), s2-s1)
	},
}

func init() {
	diffCmd.Flags().String("format", "text", "output format: text or json")
	rootCmd.AddCommand(diffCmd)
}

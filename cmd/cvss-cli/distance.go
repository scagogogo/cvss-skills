package main

import (
	"fmt"

	"github.com/scagogogo/cvss-parser/pkg/cvss"
	"github.com/scagogogo/cvss-parser/pkg/parser"
	"github.com/spf13/cobra"
)

var distanceCmd = &cobra.Command{
	Use:   "distance [vector1] [vector2]",
	Short: "Calculate distance between two CVSS vectors",
	Long: `Calculate various distance metrics between two CVSS vectors.

Available distance metrics:
  - Euclidean distance (numeric score differences)
  - Manhattan distance (sum of absolute score differences)
  - Hamming distance (count of different metrics)
  - Jaccard similarity (ratio of same metrics)
  - Score difference (absolute score difference)

Use --env to include environmental metrics in distance calculations.

Examples:
  cvss distance "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" "CVSS:3.1/AV:L/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
  cvss distance --env "CVSS:3.1/AV:N/..." "CVSS:3.1/AV:L/..."
  cvss distance --format json "CVSS:3.1/AV:N/..." "CVSS:3.1/AV:L/..."`,
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

		withEnv, _ := cmd.Flags().GetBool("env")
		format, _ := cmd.Flags().GetString("format")
		dc := cvss.NewDistanceCalculator(cv1, cv2)

		if format == "json" {
			out := map[string]interface{}{
				"vector1": cv1.String(),
				"vector2": cv2.String(),
			}
			if withEnv {
				out["euclidean"] = dc.EuclideanDistanceWithEnv()
				out["manhattan"] = dc.ManhattanDistanceWithEnv()
				out["hamming"] = dc.HammingDistanceWithEnv()
				out["jaccard"] = dc.JaccardSimilarityWithEnv()
			} else {
				out["euclidean"] = dc.EuclideanDistance()
				out["manhattan"] = dc.ManhattanDistance()
				out["hamming"] = dc.HammingDistance()
				out["jaccard"] = dc.JaccardSimilarity()
			}
			out["score_diff"] = dc.ScoreDifference()
			fmt.Println(marshalJSON(out))
			return
		}

		if withEnv {
			fmt.Printf("Euclidean (with env):  %.4f\n", dc.EuclideanDistanceWithEnv())
			fmt.Printf("Manhattan (with env):  %.4f\n", dc.ManhattanDistanceWithEnv())
			fmt.Printf("Hamming (with env):    %d\n", dc.HammingDistanceWithEnv())
			fmt.Printf("Jaccard (with env):    %.4f\n", dc.JaccardSimilarityWithEnv())
		} else {
			fmt.Printf("Euclidean:  %.4f\n", dc.EuclideanDistance())
			fmt.Printf("Manhattan:  %.4f\n", dc.ManhattanDistance())
			fmt.Printf("Hamming:    %d\n", dc.HammingDistance())
			fmt.Printf("Jaccard:    %.4f\n", dc.JaccardSimilarity())
		}
		fmt.Printf("Score diff: %.1f\n", dc.ScoreDifference())
	},
}

func init() {
	distanceCmd.Flags().Bool("env", false, "include environmental metrics in distance calculations")
	distanceCmd.Flags().String("format", "text", "output format: text or json")
	rootCmd.AddCommand(distanceCmd)
}

package main

import (
	"fmt"
	"os"

	"github.com/scagogogo/cvss-parser/pkg/cvss"
	"github.com/scagogogo/cvss-parser/pkg/parser"
	"github.com/spf13/cobra"
)

var sortCmd = &cobra.Command{
	Use:   "sort [file]",
	Short: "Sort CVSS vectors by score",
	Long: `Read CVSS vectors from a file or stdin and sort them by score.

Default sort order is descending (highest score first).
Use --asc for ascending order.

Examples:
  cvss sort vectors.txt
  cat vectors.txt | cvss sort -
  cvss sort --asc vectors.txt`,
	Args: cobra.MaximumNArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		asc, _ := cmd.Flags().GetBool("asc")

		lines := readLines(cmd, args)
		if len(lines) == 0 {
			return
		}

		var vectors []*cvss.Cvss3x
		for _, line := range lines {
			cv, err := parser.ParseString(line)
			if err != nil {
				fmt.Fprintf(os.Stderr, "Skipping invalid: %s\n", line)
				continue
			}
			vectors = append(vectors, cv)
		}

		if len(vectors) == 0 {
			return
		}

		slice := cvss.NewCvss3xSlice(vectors...)
		if asc {
			slice.Asc()
		}
		slice.Sort()

		for _, cv := range slice.Items() {
			calc := cvss.NewCalculator(cv)
			score, _ := calc.Calculate()
			fmt.Printf("%.1f  %s\n", score, cv.String())
		}
	},
}

func init() {
	sortCmd.Flags().Bool("asc", false, "sort ascending (lowest score first)")
	rootCmd.AddCommand(sortCmd)
}

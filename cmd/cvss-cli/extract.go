package main

import (
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/scagogogo/cvss-skills/pkg/extract"
	"github.com/spf13/cobra"
)

var extractCmd = &cobra.Command{
	Use:   "extract [file]",
	Short: "Extract CVSS scores from a vulnerability report",
	Long: `Extract CVSS scores from a Trivy-compatible JSON report.

Sources are selected in priority order (NVD, GHSA, Red Hat) for CVSS v3;
NVD CVSS v2 is used only as an explicitly marked fallback. Use - for stdin.

Examples:
  cvss extract trivy.json
  cat trivy.json | cvss extract - --format json
  cvss extract --source-priority ghsa,nvd trivy.json`,
	Args: cobra.MaximumNArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		format, _ := cmd.Flags().GetString("format")
		priorityText, _ := cmd.Flags().GetString("source-priority")
		priority := strings.Split(priorityText, ",")
		var data []byte
		var err error
		if len(args) == 0 || args[0] == "-" {
			data, err = readAll(os.Stdin)
		} else {
			data, err = os.ReadFile(args[0])
		}
		if err != nil {
			dief("Cannot read report: %v\n", err)
		}
		result, err := extract.ExtractWithOptions(data, extract.Options{SourcePriority: priority})
		if err != nil {
			dief("Extract error: %v\n", err)
		}
		if format == "json" {
			fmt.Println(marshalJSON(result))
			return
		}
		for _, item := range result.Results {
			cv := item.CVSS
			score := "N/A"
			if cv.Score != nil {
				score = fmt.Sprintf("%.1f", *cv.Score)
			}
			extra := ""
			if cv.Source != "" {
				extra = fmt.Sprintf(" source=%s version=%s", cv.Source, cv.Version)
			}
			if cv.Fallback {
				extra += " fallback"
			}
			fmt.Printf("%s\t%s\t%s%s\n", item.VulnerabilityID, item.Package, score, extra)
		}
	},
}

func readAll(r io.Reader) ([]byte, error) { return io.ReadAll(r) }

func init() {
	extractCmd.Flags().String("format", "text", "output format: text or json")
	extractCmd.Flags().String("source-priority", "nvd,ghsa,redhat", "CVSS v3 source priority, comma-separated")
	rootCmd.AddCommand(extractCmd)
}

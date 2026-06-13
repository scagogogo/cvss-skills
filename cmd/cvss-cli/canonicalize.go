package main

import (
	"fmt"
	"os"

	"github.com/scagogogo/cvss-parser/pkg/cvss"
	"github.com/spf13/cobra"
)

var canonicalizeCmd = &cobra.Command{
	Use:   "canonicalize [vector-string]",
	Short: "Normalize a CVSS vector string to canonical order",
	Long: `Reorder a CVSS vector string into the canonical metric order.

CVSS canonical order: AV, AC, PR, UI, S, C, I, A, E, RL, RC, CR, IR, AR, MAV, MAC, MPR, MUI, MS, MC, MI, MA

Use --check to verify if a vector is already canonical.

Examples:
  cvss canonicalize "CVSS:3.1/S:U/C:H/I:H/A:H/AV:N/AC:L/PR:N/UI:N"
  cvss canonicalize --check "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
  cvss canonicalize --format json "CVSS:3.1/S:U/C:H/I:H/A:H/AV:N/AC:L/PR:N/UI:N"`,
	Args: cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		checkOnly, _ := cmd.Flags().GetBool("check")
		format, _ := cmd.Flags().GetString("format")

		if checkOnly {
			isCanonical := cvss.IsCanonical(args[0])
			if format == "json" {
				out := map[string]interface{}{
					"vector":       args[0],
					"is_canonical": isCanonical,
				}
				fmt.Println(marshalJSON(out))
			} else {
				if isCanonical {
					fmt.Println("Canonical [PASS]")
				} else {
					fmt.Println("Not canonical")
				}
			}
			if !isCanonical {
				os.Exit(1)
			}
			return
		}

		result, err := cvss.Canonicalize(args[0])
		if err != nil {
			dief("Error: %v\n", err)
		}

		if format == "json" {
			out := map[string]interface{}{
				"original":     args[0],
				"canonical":    result,
				"was_canonical": cvss.IsCanonical(args[0]),
			}
			fmt.Println(marshalJSON(out))
		} else {
			fmt.Println(result)
		}
	},
}

func init() {
	canonicalizeCmd.Flags().Bool("check", false, "only check if the vector is canonical (exit 0=yes, 1=no)")
	canonicalizeCmd.Flags().String("format", "text", "output format: text or json")
	rootCmd.AddCommand(canonicalizeCmd)
}

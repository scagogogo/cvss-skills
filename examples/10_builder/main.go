package main

import (
	"fmt"

	"github.com/scagogogo/cvss-parser/pkg/cvss"
)

func main() {
	// Builder API — fluent construction of Cvss3x vectors
	// Short method names match the CVSS metric abbreviations

	// Base-only vector
	cv := cvss.NewBuilder().Version(3, 1).
		AV('N').AC('L').PR('N').UI('N').S('U').
		C('H').I('H').A('H').MustBuild()

	fmt.Printf("Vector: %s\n", cv.String())
	fmt.Printf("IsComplete: %v\n", cv.IsComplete())
	fmt.Printf("Description: %s\n", cv.Description())

	// Calculate score
	calc := cvss.NewCalculator(cv)
	score, err := calc.Calculate()
	if err != nil {
		fmt.Printf("Error: %v\n", err)
		return
	}
	fmt.Printf("Score: %.1f\n", score)

	// With temporal metrics
	cvTemporal := cvss.NewBuilder().Version(3, 1).
		AV('N').AC('L').PR('N').UI('N').S('U').
		C('H').I('H').A('H').
		E('U').RL('W').RC('R').MustBuild()

	fmt.Printf("\nTemporal vector: %s\n", cvTemporal.String())
	fmt.Printf("Has temporal: %v\n", cvTemporal.HasTemporalMetrics())

	// Score breakdown
	breakdown, _ := calc.GetScoreBreakdown()
	fmt.Printf("\nScore Breakdown:\n")
	fmt.Printf("  AV: %s=%.2f\n", breakdown.AttackVector.Value, breakdown.AttackVector.Score)
	fmt.Printf("  PR: %s=%.2f (scope-adjusted)\n", breakdown.PrivilegesRequired.Value, breakdown.PrivilegesRequired.Score)

	// Error handling
	_, err = cvss.NewBuilder().AV('Z').Build()
	if err != nil {
		fmt.Printf("\nInvalid value error: %v\n", err)
	}
}
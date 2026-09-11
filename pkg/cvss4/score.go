package cvss4

import (
	"errors"
	"math"
	"strconv"
	"strings"
)

// ErrScoringUnavailable is retained for compatibility. Normative CVSS v4.0
// MacroVector scoring is now provided via cvssLookup and the interpolation
// algorithm from the FIRST reference calculator.
var ErrScoringUnavailable = errors.New("CVSS v4.0 scoring is unavailable")

// maxSeverity holds the depth (+1) of each MacroVector EQ, from
// FIRST's cvss-v4-calculator max_severity.js. eq3eq6 is indexed [eq3][eq6].
var maxSeverity = map[string]interface{}{
	"eq1":    map[int]float64{0: 1, 1: 4, 2: 5},
	"eq2":    map[int]float64{0: 1, 1: 2},
	"eq3eq6": map[int]map[int]float64{0: {0: 7, 1: 6}, 1: {0: 8, 1: 8}, 2: {1: 10}},
	"eq4":    map[int]float64{0: 6, 1: 5, 2: 4},
	"eq5":    map[int]float64{0: 1, 1: 1, 2: 1},
}

// maxComposed holds the highest-severity vectors per EQ value, from FIRST's
// max_composed.js. getEQMaxes(macroVector, eq) = maxComposed["eqX"][mv[eq-1]],
// and EQ3 also selects by EQ6 (mv[5]).
var maxComposed = map[string]map[string][]string{
	"eq1": {"0": {"AV:N/PR:N/UI:N/"}, "1": {"AV:A/PR:N/UI:N/", "AV:N/PR:L/UI:N/", "AV:N/PR:N/UI:P/"}, "2": {"AV:P/PR:N/UI:N/", "AV:A/PR:L/UI:P/"}},
	"eq2": {"0": {"AC:L/AT:N/"}, "1": {"AC:H/AT:N/", "AC:L/AT:P/"}},
	"eq4": {"0": {"SC:H/SI:S/SA:S/"}, "1": {"SC:H/SI:H/SA:H/"}, "2": {"SC:L/SI:L/SA:L/"}},
	"eq5": {"0": {"E:A/"}, "1": {"E:P/"}, "2": {"E:U/"}},
}
var maxComposedEq3 = map[string]map[string][]string{
	"0": {"0": {"VC:H/VI:H/VA:H/CR:H/IR:H/AR:H/"}, "1": {"VC:H/VI:H/VA:L/CR:M/IR:M/AR:H/", "VC:H/VI:H/VA:H/CR:M/IR:M/AR:M/"}},
	"1": {"0": {"VC:L/VI:H/VA:H/CR:H/IR:H/AR:H/", "VC:H/VI:L/VA:H/CR:H/IR:H/AR:H/"}, "1": {"VC:L/VI:H/VA:L/CR:H/IR:M/AR:H/", "VC:L/VI:H/VA:H/CR:H/IR:M/AR:M/", "VC:H/VI:L/VA:H/CR:M/IR:H/AR:M/", "VC:H/VI:L/VA:L/CR:M/IR:H/AR:H/", "VC:L/VI:L/VA:H/CR:H/IR:H/AR:M/"}},
	"2": {"1": {"VC:L/VI:L/VA:L/CR:H/IR:H/AR:H/"}},
}

// metricLevels maps each metric value to its severity-distance index (0 is the
// highest severity), from FIRST's cvss_score.js.
var metricLevels = map[string]map[string]float64{
	"AV": {"N": 0, "A": .1, "L": .2, "P": .3}, "PR": {"N": 0, "L": .1, "H": .2}, "UI": {"N": 0, "P": .1, "A": .2},
	"AC": {"L": 0, "H": .1}, "AT": {"N": 0, "P": .1},
	"VC": {"H": 0, "L": .1, "N": .2}, "VI": {"H": 0, "L": .1, "N": .2}, "VA": {"H": 0, "L": .1, "N": .2},
	"SC": {"H": .1, "L": .2, "N": .3}, "SI": {"S": 0, "H": .1, "L": .2, "N": .3}, "SA": {"S": 0, "H": .1, "L": .2, "N": .3},
	"CR": {"H": 0, "M": .1, "L": .2}, "IR": {"H": 0, "M": .1, "L": .2}, "AR": {"H": 0, "M": .1, "L": .2},
}

// selected resolves the effective value of a metric for scoring. Threat and
// requirements metrics default to their worst case when not defined (X), and
// an available Modified metric overrides its base counterpart.
func (v *Vector) selected(key string) string {
	value, ok := v.metrics[key]
	if key == "E" && (!ok || value == "X") {
		return "A"
	}
	if (key == "CR" || key == "IR" || key == "AR") && (!ok || value == "X") {
		return "H"
	}
	if !ok {
		return ""
	}
	if !strings.HasPrefix(key, "M") {
		if mv, ok := v.metrics["M"+key]; ok && mv != "X" {
			return mv
		}
	}
	return value
}

// macroVector computes the six-digit MacroVector for a vector.
func (v *Vector) macroVector() string {
	av, pr, ui := v.selected("AV"), v.selected("PR"), v.selected("UI")
	eq1 := "2"
	if av == "N" && pr == "N" && ui == "N" {
		eq1 = "0"
	} else if (av == "N" || pr == "N" || ui == "N") && av != "P" {
		eq1 = "1"
	}
	eq2 := "1"
	if v.selected("AC") == "L" && v.selected("AT") == "N" {
		eq2 = "0"
	}
	vc, vi, va := v.selected("VC"), v.selected("VI"), v.selected("VA")
	eq3 := "2"
	if vc == "H" && vi == "H" {
		eq3 = "0"
	} else if vc == "H" || vi == "H" || va == "H" {
		eq3 = "1"
	}
	msi, msa := v.selected("MSI"), v.selected("MSA")
	si, sa := v.selected("SI"), v.selected("SA")
	// EQ4 is 0 when the (modified) downstream scope changes, 1 when a scope or
	// integrity/availability value is High, else 2 — matching the reference.
	eq4 := "2"
	if msi == "S" || msa == "S" {
		eq4 = "0"
	} else if v.selected("SC") == "H" || si == "H" || sa == "H" {
		eq4 = "1"
	}
	eq5 := "2"
	if v.selected("E") == "A" {
		eq5 = "0"
	} else if v.selected("E") == "P" {
		eq5 = "1"
	}
	eq6 := "1"
	if (v.selected("CR") == "H" && vc == "H") || (v.selected("IR") == "H" && vi == "H") || (v.selected("AR") == "H" && va == "H") {
		eq6 = "0"
	}
	return eq1 + eq2 + eq3 + eq4 + eq5 + eq6
}

func metricValueIn(vector, key string) string {
	for _, part := range strings.Split(vector, "/") {
		pair := strings.SplitN(part, ":", 2)
		if len(pair) == 2 && pair[0] == key {
			return pair[1]
		}
	}
	return ""
}

// nextLower returns the MacroVector one level lower on the given EQ, or nil if
// none exists.
func nextLower(mv string, index int) []string {
	b := []byte(mv)
	if index == 2 { // EQ3+EQ6 are related
		eq3, eq6 := b[2], b[5]
		switch {
		case eq3 == '2':
			// 21/20 -> 32 does not exist
			return nil
		case eq3 == '1' && eq6 == '1':
			// 11 -> 21
			return []string{mv[:2] + "2" + mv[3:]}
		case eq3 == '1' && eq6 == '0':
			// 10 -> 11
			return []string{mv[:5] + "1"}
		case eq3 == '0' && eq6 == '1':
			// 01 -> 11
			return []string{mv[:2] + "1" + mv[3:]}
		default:
			// 00 -> 01 or 10
			return []string{mv[:5] + "1", mv[:2] + "1" + mv[3:]}
		}
	}
	i := b[index] - '0'
	if i >= 2 {
		return nil
	}
	b[index] = b[index] + 1
	return []string{string(b)}
}

// lowerScore returns the lookup score of the next-lower MacroVector for an EQ,
// or NaN when it does not exist.
func (v *Vector) lowerScore(mv string, index int) float64 {
	value, ok := cvssLookup[mv]
	if !ok {
		return math.NaN()
	}
	best, found := math.NaN(), false
	for _, lower := range nextLower(mv, index) {
		if s, ok := cvssLookup[lower]; ok && (!found || s > best) {
			best, found = s, true
		}
	}
	if !found {
		return math.NaN()
	}
	return value - best
}

// severityDistance computes the distance of the vector from a max vector.
func (v *Vector) severityDistance(maxVector string) float64 {
	total := 0.0
	for _, key := range []string{"AV", "PR", "UI", "AC", "AT", "VC", "VI", "VA", "SC", "SI", "SA", "CR", "IR", "AR"} {
		total += metricLevels[key][v.selected(key)] - metricLevels[key][metricValueIn(maxVector, key)]
	}
	return total
}

// Score returns the normative CVSS v4.0 score for the vector using the FIRST
// MacroVector lookup table and severity-distance interpolation algorithm.
func (v *Vector) Score() (float64, error) {
	if err := v.Validate(); err != nil {
		return 0, err
	}
	// No impact on any affected system: score is zero.
	if v.selected("VC") == "N" && v.selected("VI") == "N" && v.selected("VA") == "N" &&
		v.selected("SC") == "N" && v.selected("SI") == "N" && v.selected("SA") == "N" {
		return 0, nil
	}
	mv := v.macroVector()
	value, ok := cvssLookup[mv]
	if !ok {
		return 0, ErrScoringUnavailable
	}

	// Available scoring distance to the next-lower MacroVector per EQ.
	available := []float64{v.lowerScore(mv, 0), v.lowerScore(mv, 1), v.lowerScore(mv, 2), v.lowerScore(mv, 3), v.lowerScore(mv, 4)}

	eq1, _ := strconv.Atoi(mv[0:1])
	eq2, _ := strconv.Atoi(mv[1:2])
	eq3, _ := strconv.Atoi(mv[2:3])
	eq4, _ := strconv.Atoi(mv[3:4])
	eq6, _ := strconv.Atoi(mv[5:6])

	// Compose candidate max vectors and pick the first whose severity distance
	// is non-negative for every metric.
	depth := maxSeverity["eq3eq6"].(map[int]map[int]float64)[eq3][eq6] * 0.1
	chosen := ""
	lastCandidate := ""
outer:
	for _, a := range maxComposed["eq1"][mv[0:1]] {
		for _, b := range maxComposed["eq2"][mv[1:2]] {
			for _, c := range maxComposedEq3[mv[2:3]][mv[5:6]] {
				for _, d := range maxComposed["eq4"][mv[3:4]] {
					for _, e := range maxComposed["eq5"][mv[4:5]] {
						cand := a + b + c + d + e
						lastCandidate = cand
						if ok := true; true {
							ok = true
							for _, key := range []string{"AV", "PR", "UI", "AC", "AT", "VC", "VI", "VA", "SC", "SI", "SA", "CR", "IR", "AR"} {
								if metricLevels[key][v.selected(key)]-metricLevels[key][metricValueIn(cand, key)] < 0 {
									ok = false
									break
								}
							}
							if ok {
								chosen = cand
								break outer
							}
						}
					}
				}
			}
		}
	}
	if chosen == "" {
		chosen = lastCandidate
	}
	if chosen == "" {
		return 0, ErrScoringUnavailable
	}

	// Per-EQ severity distance from the chosen max vector.
	d := func(keys ...string) float64 {
		total := 0.0
		for _, key := range keys {
			total += metricLevels[key][v.selected(key)] - metricLevels[key][metricValueIn(chosen, key)]
		}
		return total
	}
	dist := []float64{
		d("AV", "PR", "UI"),
		d("AC", "AT"),
		d("VC", "VI", "VA", "CR", "IR", "AR"),
		d("SC", "SI", "SA"),
		0,
	}
	depths := []float64{
		maxSeverity["eq1"].(map[int]float64)[eq1] * 0.1,
		maxSeverity["eq2"].(map[int]float64)[eq2] * 0.1,
		depth,
		maxSeverity["eq4"].(map[int]float64)[eq4] * 0.1,
		0.1,
	}

	mean, count := 0.0, 0
	for i, avail := range available {
		if math.IsNaN(avail) {
			continue
		}
		mean += avail * (dist[i] / depths[i])
		count++
	}
	if count > 0 {
		value -= mean / float64(count)
	}
	if value < 0 {
		value = 0
	}
	if value > 10 {
		value = 10
	}
	return math.Round(value*10) / 10, nil
}

// Severity returns the qualitative CVSS v4.0 severity for the vector score.
func (v *Vector) Severity() (string, error) {
	score, err := v.Score()
	if err != nil {
		return "", err
	}
	switch {
	case score == 0:
		return "None", nil
	case score < 4.0:
		return "Low", nil
	case score < 7.0:
		return "Medium", nil
	case score < 9.0:
		return "High", nil
	default:
		return "Critical", nil
	}
}

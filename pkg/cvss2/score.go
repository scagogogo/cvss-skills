package cvss2

import (
	"fmt"
	"math"
)

// Scores holds the CVSS v2.0 Base, Temporal, and Environmental scores.
type Scores struct {
	BaseScore          float64
	TemporalScore      float64
	EnvironmentalScore float64
	HasTemporal        bool
	HasEnvironmental   bool
}

func (v *Vector) val(key string) float64 {
	if v == nil {
		return 0
	}
	return v.scalar(key)
}

// scalar returns the numeric value of a metric; absent/Not Defined metrics
// use their neutral default per the CVSS v2.0 specification.
func (v *Vector) scalar(key string) float64 {
	value, ok := v.metrics[key]
	if !ok || value == "ND" {
		switch key {
		case "AV", "MAV":
			return avScore["N"]
		case "AC", "MAC":
			return acScore["L"]
		case "Au", "MAu":
			return auScore["N"]
		case "C", "I", "A", "MC", "MI", "MA":
			return 0
		case "E":
			return eScore["H"]
		case "RL":
			return rlScore["U"]
		case "RC":
			return rcScore["C"]
		case "CDP":
			return cdpScore["ND"]
		case "TD":
			return tdScore["ND"]
		case "CR", "IR", "AR":
			return reqScore["ND"]
		}
		return 0
	}
	switch key {
	case "AV", "MAV":
		return avScore[value]
	case "AC", "MAC":
		return acScore[value]
	case "Au", "MAu":
		return auScore[value]
	case "C", "I", "A", "MC", "MI", "MA":
		return cioScore[value]
	case "E":
		return eScore[value]
	case "RL":
		return rlScore[value]
	case "RC":
		return rcScore[value]
	case "CDP":
		return cdpScore[value]
	case "TD":
		return tdScore[value]
	case "CR", "IR", "AR":
		return reqScore[value]
	}
	return 0
}

func (v *Vector) has(key string) bool {
	if v == nil {
		return false
	}
	value, ok := v.metrics[key]
	return ok && value != "ND"
}

func (v *Vector) effective(base, modified string) float64 {
	if v != nil {
		if value, ok := v.metrics[modified]; ok && value != "ND" {
			return v.scalar(modified)
		}
	}
	return v.scalar(base)
}

// baseImpactExploitability computes the raw impact and exploitability scores
// for the given confidentiality/integrity/availability factors.
func baseImpactExploitability(c, i, a, av, ac, au float64) (impact, exploit float64) {
	impact = 10.41 * (1 - (1-c)*(1-i)*(1-a))
	exploit = 20 * av * ac * au
	return impact, exploit
}

func baseScore(impact, exploit float64) float64 {
	return math.Max(0, math.Min(10, roundToOne(rawBaseScore(impact, exploit))))
}

func rawBaseScore(impact, exploit float64) float64 {
	return (0.6*impact + 0.4*exploit - 1.5) * fImpact(impact)
}

// Score returns the CVSS v2.0 Base score.
func (v *Vector) Score() (float64, error) {
	if err := v.Validate(); err != nil {
		return 0, err
	}
	impact, exploit := baseImpactExploitability(v.scalar("C"), v.scalar("I"), v.scalar("A"), v.scalar("AV"), v.scalar("AC"), v.scalar("Au"))
	return baseScore(impact, exploit), nil
}

// Calculate returns Base, Temporal, and Environmental scores.
func (v *Vector) Calculate() (*Scores, error) {
	if err := v.Validate(); err != nil {
		return nil, err
	}
	out := &Scores{}
	impact, exploit := baseImpactExploitability(v.scalar("C"), v.scalar("I"), v.scalar("A"), v.scalar("AV"), v.scalar("AC"), v.scalar("Au"))
	out.BaseScore = baseScore(impact, exploit)

	out.HasTemporal = v.has("E") || v.has("RL") || v.has("RC")
	if out.HasTemporal {
		out.TemporalScore = math.Max(0, roundToOne(out.BaseScore*v.scalar("E")*v.scalar("RL")*v.scalar("RC")))
	} else {
		out.TemporalScore = out.BaseScore
	}

	// Environmental metrics adjust the base CIA by requirements factors, then
	// apply collateral damage potential and target distribution.
	out.HasEnvironmental = v.has("CDP") || v.has("TD") || v.has("CR") || v.has("IR") || v.has("AR")
	if out.HasEnvironmental {
		c := v.effective("C", "MC") * v.scalar("CR")
		i := v.effective("I", "MI") * v.scalar("IR")
		a := v.effective("A", "MA") * v.scalar("AR")
		eImpact, eExploit := baseImpactExploitability(c, i, a, v.effective("AV", "MAV"), v.effective("AC", "MAC"), v.effective("Au", "MAu"))
		if eImpact > 10 {
			eImpact = 10
		}
		// adjusted base is the ROUNDED environmental base; then temporal scales
		// the rounded value and rounds again.
		adjBase := baseScore(eImpact, eExploit)
		adjTemporal := roundToOne(adjBase * v.scalar("E") * v.scalar("RL") * v.scalar("RC"))
		env := roundToOne((adjTemporal + (10-adjTemporal)*v.scalar("CDP")) * v.scalar("TD"))
		out.EnvironmentalScore = math.Max(0, math.Min(10, env))
	} else {
		out.EnvironmentalScore = out.TemporalScore
	}
	return out, nil
}

func (s *Scores) String() string {
	if s == nil {
		return "<nil>"
	}
	return fmt.Sprintf("Base: %.1f, Temporal: %.1f, Environmental: %.1f", s.BaseScore, s.TemporalScore, s.EnvironmentalScore)
}

package cvss

import (
	"encoding/json"
	"fmt"
)

// JSONOutput CVSS JSON输出格式
type JSONOutput struct {
	Version               string       `json:"version"`
	VectorString          string       `json:"vectorString"`
	BaseScore             float64      `json:"baseScore"`
	TemporalScore         float64      `json:"temporalScore,omitempty"`
	EnvironmentalScore    float64      `json:"environmentalScore,omitempty"`
	BaseSeverity          string       `json:"baseSeverity"`
	TemporalSeverity      string       `json:"temporalSeverity,omitempty"`
	EnvironmentalSeverity string       `json:"environmentalSeverity,omitempty"`
	Metrics               *JSONMetrics `json:"metrics"`
}

// JSONMetrics 包含所有CVSS指标
type JSONMetrics struct {
	Base          *JSONBaseMetrics          `json:"base"`
	Temporal      *JSONTemporalMetrics      `json:"temporal,omitempty"`
	Environmental *JSONEnvironmentalMetrics `json:"environmental,omitempty"`
}

// JSONBaseMetrics 基础指标JSON格式
type JSONBaseMetrics struct {
	AttackVector        string  `json:"attackVector"`
	AttackComplexity    string  `json:"attackComplexity"`
	PrivilegesRequired  string  `json:"privilegesRequired"`
	UserInteraction     string  `json:"userInteraction"`
	Scope               string  `json:"scope"`
	Confidentiality     string  `json:"confidentiality"`
	Integrity           string  `json:"integrity"`
	Availability        string  `json:"availability"`
	ExploitabilityScore float64 `json:"exploitabilityScore"`
	ImpactScore         float64 `json:"impactScore"`
}

// JSONTemporalMetrics 时间指标JSON格式
type JSONTemporalMetrics struct {
	ExploitCodeMaturity string `json:"exploitCodeMaturity"`
	RemediationLevel    string `json:"remediationLevel"`
	ReportConfidence    string `json:"reportConfidence"`
}

// JSONEnvironmentalMetrics 环境指标JSON格式
type JSONEnvironmentalMetrics struct {
	ConfidentialityRequirement  string  `json:"confidentialityRequirement,omitempty"`
	IntegrityRequirement        string  `json:"integrityRequirement,omitempty"`
	AvailabilityRequirement     string  `json:"availabilityRequirement,omitempty"`
	ModifiedAttackVector        string  `json:"modifiedAttackVector,omitempty"`
	ModifiedAttackComplexity    string  `json:"modifiedAttackComplexity,omitempty"`
	ModifiedPrivilegesRequired  string  `json:"modifiedPrivilegesRequired,omitempty"`
	ModifiedUserInteraction     string  `json:"modifiedUserInteraction,omitempty"`
	ModifiedScope               string  `json:"modifiedScope,omitempty"`
	ModifiedConfidentiality     string  `json:"modifiedConfidentiality,omitempty"`
	ModifiedIntegrity           string  `json:"modifiedIntegrity,omitempty"`
	ModifiedAvailability        string  `json:"modifiedAvailability,omitempty"`
	ModifiedExploitabilityScore float64 `json:"modifiedExploitabilityScore,omitempty"`
	ModifiedImpactScore         float64 `json:"modifiedImpactScore,omitempty"`
}

// ToJSON 将CVSS对象转换为JSON格式
func (x *Cvss3x) ToJSON(calculator *Calculator) ([]byte, error) {
	if calculator == nil {
		calculator = NewCalculator(x)
	}

	// 计算各级评分
	baseScore, err := calculator.Calculate()
	if err != nil {
		return nil, err
	}

	// 构建JSON输出
	output := &JSONOutput{
		Version:      fmt.Sprintf("3.%d", x.MinorVersion),
		VectorString: x.String(),
		BaseScore:    baseScore,
		BaseSeverity: calculator.GetSeverityRating(baseScore),
		Metrics: &JSONMetrics{
			Base: &JSONBaseMetrics{
				AttackVector:        x.Cvss3xBase.AttackVector.GetLongValue(),
				AttackComplexity:    x.Cvss3xBase.AttackComplexity.GetLongValue(),
				PrivilegesRequired:  x.Cvss3xBase.PrivilegesRequired.GetLongValue(),
				UserInteraction:     x.Cvss3xBase.UserInteraction.GetLongValue(),
				Scope:               x.Cvss3xBase.Scope.GetLongValue(),
				Confidentiality:     x.Cvss3xBase.Confidentiality.GetLongValue(),
				Integrity:           x.Cvss3xBase.Integrity.GetLongValue(),
				Availability:        x.Cvss3xBase.Availability.GetLongValue(),
				ExploitabilityScore: calculator.calculateExploitabilitySubScore(),
				ImpactScore:         calculator.calculateImpactSubScore(),
			},
		},
	}

	// 添加时间指标（如果存在）
	if calculator.hasTemporalMetrics() {
		temporalScore := calculator.calculateTemporalScore(baseScore)
		output.TemporalScore = temporalScore
		output.TemporalSeverity = calculator.GetSeverityRating(temporalScore)
		output.Metrics.Temporal = &JSONTemporalMetrics{
			ExploitCodeMaturity: x.Cvss3xTemporal.ExploitCodeMaturity.GetLongValue(),
			RemediationLevel:    x.Cvss3xTemporal.RemediationLevel.GetLongValue(),
			ReportConfidence:    x.Cvss3xTemporal.ReportConfidence.GetLongValue(),
		}
	}

	// 添加环境指标（如果存在）
	if calculator.hasEnvironmentalMetrics() {
		environmentalScore := calculator.calculateEnvironmentalScore()
		output.EnvironmentalScore = environmentalScore
		output.EnvironmentalSeverity = calculator.GetSeverityRating(environmentalScore)

		output.Metrics.Environmental = &JSONEnvironmentalMetrics{
			ModifiedExploitabilityScore: calculator.calculateModifiedExploitabilitySubScore(),
			ModifiedImpactScore:         calculator.calculateModifiedImpactSubScore(),
		}

		// 添加CIA需求指标
		if x.Cvss3xEnvironmental.ConfidentialityRequirement != nil {
			output.Metrics.Environmental.ConfidentialityRequirement = x.Cvss3xEnvironmental.ConfidentialityRequirement.GetLongValue()
		}
		if x.Cvss3xEnvironmental.IntegrityRequirement != nil {
			output.Metrics.Environmental.IntegrityRequirement = x.Cvss3xEnvironmental.IntegrityRequirement.GetLongValue()
		}
		if x.Cvss3xEnvironmental.AvailabilityRequirement != nil {
			output.Metrics.Environmental.AvailabilityRequirement = x.Cvss3xEnvironmental.AvailabilityRequirement.GetLongValue()
		}

		// 添加修改后的指标
		if x.Cvss3xEnvironmental.ModifiedAttackVector != nil {
			output.Metrics.Environmental.ModifiedAttackVector = x.Cvss3xEnvironmental.ModifiedAttackVector.GetLongValue()
		}
		if x.Cvss3xEnvironmental.ModifiedAttackComplexity != nil {
			output.Metrics.Environmental.ModifiedAttackComplexity = x.Cvss3xEnvironmental.ModifiedAttackComplexity.GetLongValue()
		}
		if x.Cvss3xEnvironmental.ModifiedPrivilegesRequired != nil {
			output.Metrics.Environmental.ModifiedPrivilegesRequired = x.Cvss3xEnvironmental.ModifiedPrivilegesRequired.GetLongValue()
		}
		if x.Cvss3xEnvironmental.ModifiedUserInteraction != nil {
			output.Metrics.Environmental.ModifiedUserInteraction = x.Cvss3xEnvironmental.ModifiedUserInteraction.GetLongValue()
		}
		if x.Cvss3xEnvironmental.ModifiedScope != nil {
			output.Metrics.Environmental.ModifiedScope = x.Cvss3xEnvironmental.ModifiedScope.GetLongValue()
		}
		if x.Cvss3xEnvironmental.ModifiedConfidentiality != nil {
			output.Metrics.Environmental.ModifiedConfidentiality = x.Cvss3xEnvironmental.ModifiedConfidentiality.GetLongValue()
		}
		if x.Cvss3xEnvironmental.ModifiedIntegrity != nil {
			output.Metrics.Environmental.ModifiedIntegrity = x.Cvss3xEnvironmental.ModifiedIntegrity.GetLongValue()
		}
		if x.Cvss3xEnvironmental.ModifiedAvailability != nil {
			output.Metrics.Environmental.ModifiedAvailability = x.Cvss3xEnvironmental.ModifiedAvailability.GetLongValue()
		}
	}

	return json.MarshalIndent(output, "", "  ")
}

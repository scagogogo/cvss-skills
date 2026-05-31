package cvss

import (
	"math"

	"github.com/scagogogo/cvss-parser/pkg/vector"
)

// Calculator CVSS 3.x 评分计算器
type Calculator struct {
	cvss *Cvss3x
}

// NewCalculator 创建一个新的评分计算器
func NewCalculator(cvss *Cvss3x) *Calculator {
	return &Calculator{
		cvss: cvss,
	}
}

// Calculate 计算CVSS评分
func (c *Calculator) Calculate() (float64, error) {
	// 检查CVSS是否有效
	if err := c.cvss.Check(); err != nil {
		return 0, err
	}

	// 计算基础评分
	baseScore := c.calculateBaseScore()

	// 如果没有设置时间指标，返回基础评分
	if !c.hasTemporalMetrics() {
		return baseScore, nil
	}

	// 计算时间评分
	temporalScore := c.calculateTemporalScore(baseScore)

	// 如果没有设置环境指标，返回时间评分
	if !c.hasEnvironmentalMetrics() {
		return temporalScore, nil
	}

	// 计算环境评分
	environmentalScore := c.calculateEnvironmentalScore()

	return environmentalScore, nil
}

// 计算基础评分
func (c *Calculator) calculateBaseScore() float64 {
	// 计算基础指标分数
	impactSubScore := c.calculateImpactSubScore()
	exploitabilitySubScore := c.calculateExploitabilitySubScore()

	// 根据范围是否改变调整影响子评分
	if c.isChangedScope() {
		return roundUp(math.Min(1.08*(impactSubScore+exploitabilitySubScore), 10))
	} else {
		return roundUp(math.Min(impactSubScore+exploitabilitySubScore, 10))
	}
}

// 计算影响子评分
func (c *Calculator) calculateImpactSubScore() float64 {
	// 获取CIA三项指标分数
	confidentialityScore := c.cvss.Cvss3xBase.Confidentiality.GetScore()
	integrityScore := c.cvss.Cvss3xBase.Integrity.GetScore()
	availabilityScore := c.cvss.Cvss3xBase.Availability.GetScore()

	// 计算影响基本分数
	impactBaseScore := 1 - ((1 - confidentialityScore) * (1 - integrityScore) * (1 - availabilityScore))

	// 如果所有CIA都是None (0)，则影响子评分为0
	if confidentialityScore == 0 && integrityScore == 0 && availabilityScore == 0 {
		return 0
	}

	// 根据范围是否改变调整影响评分
	if c.isChangedScope() {
		// 修正公式：7.52 * (impactBaseScore - 0.029) - 3.25 * pow((impactBaseScore * 0.9731 - 0.02), 13)
		return 7.52*(impactBaseScore-0.029) - 3.25*math.Pow(impactBaseScore*0.9731-0.02, 13)
	} else {
		return 6.42 * impactBaseScore
	}
}

// 计算可利用性子评分
func (c *Calculator) calculateExploitabilitySubScore() float64 {
	// 获取各项指标分数
	attackVectorScore := c.cvss.Cvss3xBase.AttackVector.GetScore()
	attackComplexityScore := c.cvss.Cvss3xBase.AttackComplexity.GetScore()
	privilegesRequiredScore := c.getAdjustedPrivilegesRequiredScore()
	userInteractionScore := c.cvss.Cvss3xBase.UserInteraction.GetScore()

	// 计算可利用性子评分
	return 8.22 * attackVectorScore * attackComplexityScore * privilegesRequiredScore * userInteractionScore
}

// 获取调整后的特权要求评分（考虑范围变化）
func (c *Calculator) getAdjustedPrivilegesRequiredScore() float64 {
	return vector.GetPrivilegesRequiredScore(c.cvss.Cvss3xBase.PrivilegesRequired, c.isChangedScope())
}

// 判断范围是否改变
func (c *Calculator) isChangedScope() bool {
	return vector.IsScopeChanged(c.cvss.Cvss3xBase.Scope)
}

// 计算时间评分
// 未设置的 Temporal 指标使用默认分数 1.0（即 "Not Defined"）
func (c *Calculator) calculateTemporalScore(baseScore float64) float64 {
	// 获取时间因素评分，未设置的使用 1.0
	exploitCodeMaturityScore := 1.0
	if c.cvss.Cvss3xTemporal.ExploitCodeMaturity != nil {
		exploitCodeMaturityScore = c.cvss.Cvss3xTemporal.ExploitCodeMaturity.GetScore()
	}

	remediationLevelScore := 1.0
	if c.cvss.Cvss3xTemporal.RemediationLevel != nil {
		remediationLevelScore = c.cvss.Cvss3xTemporal.RemediationLevel.GetScore()
	}

	reportConfidenceScore := 1.0
	if c.cvss.Cvss3xTemporal.ReportConfidence != nil {
		reportConfidenceScore = c.cvss.Cvss3xTemporal.ReportConfidence.GetScore()
	}

	// 计算时间评分
	return roundUp(baseScore * exploitCodeMaturityScore * remediationLevelScore * reportConfidenceScore)
}

// 计算环境评分
func (c *Calculator) calculateEnvironmentalScore() float64 {
	// 环境评分需要考虑修改后的基础指标和安全需求指标

	// 步骤1: 计算修改后的影响子评分
	modifiedImpactSubScore := c.calculateModifiedImpactSubScore()

	// 步骤2: 计算修改后的可利用性子评分
	modifiedExploitabilitySubScore := c.calculateModifiedExploitabilitySubScore()

	// 步骤3: 计算修改后的基础评分
	if c.isModifiedChangedScope() {
		environmentalScore := roundUp(math.Min(1.08*(modifiedImpactSubScore+modifiedExploitabilitySubScore), 10))
		return environmentalScore
	} else {
		environmentalScore := roundUp(math.Min(modifiedImpactSubScore+modifiedExploitabilitySubScore, 10))
		return environmentalScore
	}
}

// 计算修改后的影响子评分
func (c *Calculator) calculateModifiedImpactSubScore() float64 {
	// 获取环境指标(如果有修改)或使用基础值
	modifiedConfidentialityScore := c.getModifiedConfidentialityScore()
	modifiedIntegrityScore := c.getModifiedIntegrityScore()
	modifiedAvailabilityScore := c.getModifiedAvailabilityScore()

	// 获取安全需求调整因子
	confReqFactor := c.getConfidentialityRequirementFactor()
	integReqFactor := c.getIntegrityRequirementFactor()
	availReqFactor := c.getAvailabilityRequirementFactor()

	// 应用安全需求调整
	adjustedConfScore := modifiedConfidentialityScore * confReqFactor
	adjustedIntegScore := modifiedIntegrityScore * integReqFactor
	adjustedAvailScore := modifiedAvailabilityScore * availReqFactor

	// 计算修改后的影响基本分数
	modifiedImpactBaseScore := 1 - ((1 - adjustedConfScore) * (1 - adjustedIntegScore) * (1 - adjustedAvailScore))

	// 如果所有CIA都是None (0)，则影响子评分为0
	if modifiedConfidentialityScore == 0 && modifiedIntegrityScore == 0 && modifiedAvailabilityScore == 0 {
		return 0
	}

	// 根据范围是否改变调整影响评分
	if c.isModifiedChangedScope() {
		// 修正公式：7.52 * (impactBaseScore - 0.029) - 3.25 * pow((impactBaseScore * 0.9731 - 0.02), 13)
		return 7.52*(modifiedImpactBaseScore-0.029) - 3.25*math.Pow(modifiedImpactBaseScore*0.9731-0.02, 13)
	} else {
		return 6.42 * modifiedImpactBaseScore
	}
}

// 计算修改后的可利用性子评分
func (c *Calculator) calculateModifiedExploitabilitySubScore() float64 {
	// 获取修改后的各项指标分数
	modifiedAttackVectorScore := c.getModifiedAttackVectorScore()
	modifiedAttackComplexityScore := c.getModifiedAttackComplexityScore()
	modifiedPrivilegesRequiredScore := c.getModifiedPrivilegesRequiredScore()
	modifiedUserInteractionScore := c.getModifiedUserInteractionScore()

	// 计算可利用性子评分
	return 8.22 * modifiedAttackVectorScore * modifiedAttackComplexityScore * modifiedPrivilegesRequiredScore * modifiedUserInteractionScore
}

// 获取修改后的机密性评分
func (c *Calculator) getModifiedConfidentialityScore() float64 {
	if c.cvss.Cvss3xEnvironmental.ModifiedConfidentiality != nil &&
		c.cvss.Cvss3xEnvironmental.ModifiedConfidentiality.GetShortValue() != 'X' {
		return c.cvss.Cvss3xEnvironmental.ModifiedConfidentiality.GetScore()
	}
	return c.cvss.Cvss3xBase.Confidentiality.GetScore()
}

// 获取修改后的完整性评分
func (c *Calculator) getModifiedIntegrityScore() float64 {
	if c.cvss.Cvss3xEnvironmental.ModifiedIntegrity != nil &&
		c.cvss.Cvss3xEnvironmental.ModifiedIntegrity.GetShortValue() != 'X' {
		return c.cvss.Cvss3xEnvironmental.ModifiedIntegrity.GetScore()
	}
	return c.cvss.Cvss3xBase.Integrity.GetScore()
}

// 获取修改后的可用性评分
func (c *Calculator) getModifiedAvailabilityScore() float64 {
	if c.cvss.Cvss3xEnvironmental.ModifiedAvailability != nil &&
		c.cvss.Cvss3xEnvironmental.ModifiedAvailability.GetShortValue() != 'X' {
		return c.cvss.Cvss3xEnvironmental.ModifiedAvailability.GetScore()
	}
	return c.cvss.Cvss3xBase.Availability.GetScore()
}

// 获取修改后的攻击向量评分
func (c *Calculator) getModifiedAttackVectorScore() float64 {
	if c.cvss.Cvss3xEnvironmental.ModifiedAttackVector != nil &&
		c.cvss.Cvss3xEnvironmental.ModifiedAttackVector.GetShortValue() != 'X' {
		return c.cvss.Cvss3xEnvironmental.ModifiedAttackVector.GetScore()
	}
	return c.cvss.Cvss3xBase.AttackVector.GetScore()
}

// 获取修改后的攻击复杂性评分
func (c *Calculator) getModifiedAttackComplexityScore() float64 {
	if c.cvss.Cvss3xEnvironmental.ModifiedAttackComplexity != nil &&
		c.cvss.Cvss3xEnvironmental.ModifiedAttackComplexity.GetShortValue() != 'X' {
		return c.cvss.Cvss3xEnvironmental.ModifiedAttackComplexity.GetScore()
	}
	return c.cvss.Cvss3xBase.AttackComplexity.GetScore()
}

// 获取修改后的特权要求评分
func (c *Calculator) getModifiedPrivilegesRequiredScore() float64 {
	var pr vector.Vector
	if c.cvss.Cvss3xEnvironmental.ModifiedPrivilegesRequired != nil &&
		c.cvss.Cvss3xEnvironmental.ModifiedPrivilegesRequired.GetShortValue() != 'X' {
		pr = c.cvss.Cvss3xEnvironmental.ModifiedPrivilegesRequired
	} else {
		pr = c.cvss.Cvss3xBase.PrivilegesRequired
	}

	scopeChanged := c.isModifiedChangedScope()
	return vector.GetPrivilegesRequiredScore(pr, scopeChanged)
}

// 获取修改后的用户交互评分
func (c *Calculator) getModifiedUserInteractionScore() float64 {
	if c.cvss.Cvss3xEnvironmental.ModifiedUserInteraction != nil &&
		c.cvss.Cvss3xEnvironmental.ModifiedUserInteraction.GetShortValue() != 'X' {
		return c.cvss.Cvss3xEnvironmental.ModifiedUserInteraction.GetScore()
	}
	return c.cvss.Cvss3xBase.UserInteraction.GetScore()
}

// 判断修改后的范围是否改变
func (c *Calculator) isModifiedChangedScope() bool {
	return vector.IsModifiedScopeChanged(c.cvss.Cvss3xEnvironmental.ModifiedScope, c.cvss.Cvss3xBase.Scope)
}

// 获取机密性需求调整因子
func (c *Calculator) getConfidentialityRequirementFactor() float64 {
	if c.cvss.Cvss3xEnvironmental.ConfidentialityRequirement != nil {
		switch c.cvss.Cvss3xEnvironmental.ConfidentialityRequirement.GetShortValue() {
		case 'H':
			return 1.5
		case 'M':
			return 1.0
		case 'L':
			return 0.5
		}
	}
	return 1.0 // 未定义或其他值默认为1.0
}

// 获取完整性需求调整因子
func (c *Calculator) getIntegrityRequirementFactor() float64 {
	if c.cvss.Cvss3xEnvironmental.IntegrityRequirement != nil {
		switch c.cvss.Cvss3xEnvironmental.IntegrityRequirement.GetShortValue() {
		case 'H':
			return 1.5
		case 'M':
			return 1.0
		case 'L':
			return 0.5
		}
	}
	return 1.0 // 未定义或其他值默认为1.0
}

// 获取可用性需求调整因子
func (c *Calculator) getAvailabilityRequirementFactor() float64 {
	if c.cvss.Cvss3xEnvironmental.AvailabilityRequirement != nil {
		switch c.cvss.Cvss3xEnvironmental.AvailabilityRequirement.GetShortValue() {
		case 'H':
			return 1.5
		case 'M':
			return 1.0
		case 'L':
			return 0.5
		}
	}
	return 1.0 // 未定义或其他值默认为1.0
}

// 判断是否设置了时间指标
// 只要有任一 Temporal 指标被设置，就认为需要计算 Temporal 评分
// 未设置的指标在计算时会使用默认值 1.0（即 "Not Defined" 的分数）
func (c *Calculator) hasTemporalMetrics() bool {
	return c.cvss.Cvss3xTemporal != nil &&
		(c.cvss.Cvss3xTemporal.ExploitCodeMaturity != nil ||
			c.cvss.Cvss3xTemporal.RemediationLevel != nil ||
			c.cvss.Cvss3xTemporal.ReportConfidence != nil)
}

// 判断是否设置了环境指标
func (c *Calculator) hasEnvironmentalMetrics() bool {
	// 简化判断，如果有任一环境指标被设置，则认为需要计算环境评分
	return c.cvss.Cvss3xEnvironmental != nil &&
		(c.cvss.Cvss3xEnvironmental.ConfidentialityRequirement != nil ||
			c.cvss.Cvss3xEnvironmental.IntegrityRequirement != nil ||
			c.cvss.Cvss3xEnvironmental.AvailabilityRequirement != nil ||
			c.cvss.Cvss3xEnvironmental.ModifiedAttackVector != nil ||
			c.cvss.Cvss3xEnvironmental.ModifiedAttackComplexity != nil ||
			c.cvss.Cvss3xEnvironmental.ModifiedPrivilegesRequired != nil ||
			c.cvss.Cvss3xEnvironmental.ModifiedUserInteraction != nil ||
			c.cvss.Cvss3xEnvironmental.ModifiedScope != nil ||
			c.cvss.Cvss3xEnvironmental.ModifiedConfidentiality != nil ||
			c.cvss.Cvss3xEnvironmental.ModifiedIntegrity != nil ||
			c.cvss.Cvss3xEnvironmental.ModifiedAvailability != nil)
}

// 向上取整到小数点后一位
func roundUp(x float64) float64 {
	return math.Ceil(x*10) / 10
}

// GetSeverityRating 获取严重性等级
func (c *Calculator) GetSeverityRating(score float64) string {
	if score == 0 {
		return "None"
	} else if score < 4.0 {
		return "Low"
	} else if score < 7.0 {
		return "Medium"
	} else if score < 9.0 {
		return "High"
	} else {
		return "Critical"
	}
}

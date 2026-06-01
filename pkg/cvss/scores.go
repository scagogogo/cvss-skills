package cvss

// GetBaseScore 计算并返回基础评分
// 基础评分仅依赖于基础指标（AV, AC, PR, UI, S, C, I, A）
func (c *Calculator) GetBaseScore() (float64, error) {
	if err := c.cvss.Check(); err != nil {
		return 0, err
	}
	return c.calculateBaseScore(), nil
}

// GetTemporalScore 计算并返回时间评分
// 时间评分 = 基础评分 × E × RL × RC
// 如果没有设置时间指标，返回基础评分
func (c *Calculator) GetTemporalScore() (float64, error) {
	if err := c.cvss.Check(); err != nil {
		return 0, err
	}
	baseScore := c.calculateBaseScore()
	if !c.hasTemporalMetrics() {
		return baseScore, nil
	}
	return c.calculateTemporalScore(baseScore), nil
}

// GetEnvironmentalScore 计算并返回环境评分
// 环境评分包含修改后的指标、安全需求调整因子和时间因子
// 如果没有设置环境指标，返回时间评分
func (c *Calculator) GetEnvironmentalScore() (float64, error) {
	if err := c.cvss.Check(); err != nil {
		return 0, err
	}
	baseScore := c.calculateBaseScore()

	// 没有环境指标时，返回时间评分（或基础评分）
	if !c.hasEnvironmentalMetrics() {
		if c.hasTemporalMetrics() {
			return c.calculateTemporalScore(baseScore), nil
		}
		return baseScore, nil
	}

	return c.calculateEnvironmentalScore(), nil
}

// GetImpactSubScore 计算并返回影响子评分（ISC）
// 影响 = 1 - (1-C)×(1-I)×(1-A)，经 Scope 调整后的值
func (c *Calculator) GetImpactSubScore() (float64, error) {
	if err := c.cvss.Check(); err != nil {
		return 0, err
	}
	return c.calculateImpactSubScore(), nil
}

// GetExploitabilitySubScore 计算并返回可利用性子评分（ESC）
// 可利用性 = 8.22 × AV × AC × PR × UI
func (c *Calculator) GetExploitabilitySubScore() (float64, error) {
	if err := c.cvss.Check(); err != nil {
		return 0, err
	}
	return c.calculateExploitabilitySubScore(), nil
}

// GetModifiedImpactSubScore 计算并返回修改后的影响子评分
// 仅在存在环境指标时有效
func (c *Calculator) GetModifiedImpactSubScore() (float64, error) {
	if err := c.cvss.Check(); err != nil {
		return 0, err
	}
	return c.calculateModifiedImpactSubScore(), nil
}

// GetModifiedExploitabilitySubScore 计算并返回修改后的可利用性子评分
// 仅在存在环境指标时有效
func (c *Calculator) GetModifiedExploitabilitySubScore() (float64, error) {
	if err := c.cvss.Check(); err != nil {
		return 0, err
	}
	return c.calculateModifiedExploitabilitySubScore(), nil
}

// AllScores 包含 CVSS 所有可能的评分和严重性等级
type AllScores struct {
	BaseScore                    float64
	TemporalScore                float64
	EnvironmentalScore           float64
	BaseSeverity                 Severity
	TemporalSeverity             Severity
	EnvironmentalSeverity        Severity
	ImpactSubScore               float64
	ExploitabilitySubScore       float64
	ModifiedImpactSubScore       float64
	ModifiedExploitabilitySubScore float64
	HasTemporal                  bool
	HasEnvironmental             bool
}

// GetAllScores 一次性计算并返回所有评分和严重性等级
// 避免多次独立调用导致的重复计算
func (c *Calculator) GetAllScores() (*AllScores, error) {
	if err := c.cvss.Check(); err != nil {
		return nil, err
	}

	baseScore := c.calculateBaseScore()
	result := &AllScores{
		BaseScore:              baseScore,
		BaseSeverity:           c.GetSeverityRating(baseScore),
		ImpactSubScore:         c.calculateImpactSubScore(),
		ExploitabilitySubScore: c.calculateExploitabilitySubScore(),
		HasTemporal:            c.hasTemporalMetrics(),
		HasEnvironmental:       c.hasEnvironmentalMetrics(),
	}

	if result.HasTemporal {
		temporalScore := c.calculateTemporalScore(baseScore)
		result.TemporalScore = temporalScore
		result.TemporalSeverity = c.GetSeverityRating(temporalScore)
	}

	if result.HasEnvironmental {
		result.ModifiedImpactSubScore = c.calculateModifiedImpactSubScore()
		result.ModifiedExploitabilitySubScore = c.calculateModifiedExploitabilitySubScore()
		envScore := c.calculateEnvironmentalScore()
		result.EnvironmentalScore = envScore
		result.EnvironmentalSeverity = c.GetSeverityRating(envScore)
	}

	return result, nil
}

// RoundUp 向上取整到小数点后一位，遵循 CVSS 规范的取整算法
// 公开此函数以便外部使用者对分数进行同样的取整处理
func RoundUp(x float64) float64 {
	return roundUp(x)
}

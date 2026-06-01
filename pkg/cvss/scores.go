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

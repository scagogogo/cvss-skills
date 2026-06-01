# CVSS SDK API Completeness Fix Plan

> **For agentic workers:** REQUIRED SUB-SKILL: `superpowers:subagent-driven-development`
> Steps use checkbox (`- [ ]`) syntax.

**Goal:** Fix critical Environmental score formula bug, add public score accessors, fix vector string ordering to match spec, fix i18n inconsistencies, fix filename issues, and implement the mock package.

**Architecture:** Fix the `calculateEnvironmentalScore()` method to multiply by temporal factors (E, RL, RC) per CVSS v3.1 spec → Add `GetBaseScore()`, `GetTemporalScore()`, `GetEnvironmentalScore()` public methods → Fix `String()` methods to output metrics in spec-mandated order → Fix Chinese descriptions to English → Rename file with trailing space → Implement mock data generator.

**Tech Stack:** Go 1.18, existing project structure under `pkg/cvss`, `pkg/vector`, `pkg/parser`, `pkg/mock`

**Risks:**
- Task 1 modifies the core calculator formula — must verify against FIRST reference calculator → 缓解：添加 spec 参考测试用例
- Task 3 changes `String()` output format — downstream users may depend on current ordering → 缓解：spec-mandated ordering is the correct behavior; this is a fix, not a breaking change
- Task 5 file rename may break imports → 缓解：Go package name unchanged, only filename changes

---

### Task 1: Fix Environmental Score Formula — Temporal Multipliers Missing

**Depends on:** None
**Files:**
- Modify: `pkg/cvss/calculator.go:22-48,134-151`

- [ ] **Step 1: 修改 Calculate 方法以正确传递 Temporal 乘数到 Environmental 分数**

文件: `pkg/cvss/calculator.go:22-48`（替换整个 Calculate 方法）

```go
// Calculate 计算CVSS评分
func (c *Calculator) Calculate() (float64, error) {
	// 检查CVSS是否有效
	if err := c.cvss.Check(); err != nil {
		return 0, err
	}

	// 计算基础评分
	baseScore := c.calculateBaseScore()

	// 如果没有设置时间指标和环境指标，返回基础评分
	if !c.hasTemporalMetrics() && !c.hasEnvironmentalMetrics() {
		return baseScore, nil
	}

	// 如果没有环境指标，计算时间评分并返回
	if !c.hasEnvironmentalMetrics() {
		temporalScore := c.calculateTemporalScore(baseScore)
		return temporalScore, nil
	}

	// 计算环境评分（包含 Temporal 乘数）
	environmentalScore := c.calculateEnvironmentalScore()
	return environmentalScore, nil
}
```

- [ ] **Step 2: 修改 calculateEnvironmentalScore 方法以乘以 Temporal 因子**

文件: `pkg/cvss/calculator.go:134-151`（替换整个 calculateEnvironmentalScore 方法）

```go
// 计算环境评分
// 根据 CVSS v3.1 规范，Environmental Score = Roundup(Min(1.08 × (ModifiedImpact + ModifiedExploitability), 10)) × E × RL × RC
func (c *Calculator) calculateEnvironmentalScore() float64 {
	// 环境评分需要考虑修改后的基础指标和安全需求指标

	// 步骤1: 计算修改后的影响子评分
	modifiedImpactSubScore := c.calculateModifiedImpactSubScore()

	// 步骤2: 计算修改后的可利用性子评分
	modifiedExploitabilitySubScore := c.calculateModifiedExploitabilitySubScore()

	// 步骤3: 计算修改后的基础评分
	var envScore float64
	if c.isModifiedChangedScope() {
		envScore = roundUp(math.Min(1.08*(modifiedImpactSubScore+modifiedExploitabilitySubScore), 10))
	} else {
		envScore = roundUp(math.Min(modifiedImpactSubScore+modifiedExploitabilitySubScore, 10))
	}

	// 步骤4: 乘以时间因子（如果有设置时间指标）
	// 未设置的 Temporal 指标使用默认分数 1.0（即 "Not Defined"）
	exploitCodeMaturityScore := 1.0
	if c.cvss.Cvss3xTemporal != nil && c.cvss.Cvss3xTemporal.ExploitCodeMaturity != nil {
		exploitCodeMaturityScore = c.cvss.Cvss3xTemporal.ExploitCodeMaturity.GetScore()
	}

	remediationLevelScore := 1.0
	if c.cvss.Cvss3xTemporal != nil && c.cvss.Cvss3xTemporal.RemediationLevel != nil {
		remediationLevelScore = c.cvss.Cvss3xTemporal.RemediationLevel.GetScore()
	}

	reportConfidenceScore := 1.0
	if c.cvss.Cvss3xTemporal != nil && c.cvss.Cvss3xTemporal.ReportConfidence != nil {
		reportConfidenceScore = c.cvss.Cvss3xTemporal.ReportConfidence.GetScore()
	}

	return roundUp(envScore * exploitCodeMaturityScore * remediationLevelScore * reportConfidenceScore)
}
```

- [ ] **Step 3: 验证 Environmental + Temporal 公式修复**
Run: `cd /home/cc11001100/github/scagogogo/cvss && go test ./pkg/cvss/ -v -run "TestEnvironmental" 2>&1 | head -40`
Expected:
  - Exit code: 0
  - Output contains: "PASS"

- [ ] **Step 4: 运行所有测试确认无回归**
Run: `cd /home/cc11001100/github/scagogogo/cvss && go test ./...`
Expected:
  - Exit code: 0
  - Output does NOT contain: "FAIL"

- [ ] **Step 5: 提交**
Run: `cd /home/cc11001100/github/scagogogo/cvss && git add pkg/cvss/calculator.go && git commit -m "fix(cvss): apply temporal multipliers to environmental score per CVSS v3.1 spec"`

---

### Task 2: Add Public Score Accessor Methods — GetBaseScore/GetTemporalScore/GetEnvironmentalScore

**Depends on:** Task 1
**Files:**
- Create: `pkg/cvss/scores.go`

- [ ] **Step 1: 创建 scores.go — 提供公开的独立分数访问方法**

```go
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
```

- [ ] **Step 2: 验证新增公开方法**
Run: `cd /home/cc11001100/github/scagogogo/cvss && go build ./pkg/cvss/ && go test ./pkg/cvss/ -v -run "TestCalculator" 2>&1 | head -30`
Expected:
  - Exit code: 0
  - Output contains: "PASS"

- [ ] **Step 3: 运行全部测试**
Run: `cd /home/cc11001100/github/scagogogo/cvss && go test ./...`
Expected:
  - Exit code: 0

- [ ] **Step 4: 提交**
Run: `cd /home/cc11001100/github/scagogogo/cvss && git add pkg/cvss/scores.go && git commit -m "feat(cvss): add GetBaseScore, GetTemporalScore, GetEnvironmentalScore public methods"`

---

### Task 3: Fix Vector String Metric Ordering — Spec-Mandated Order

**Depends on:** None
**Files:**
- Modify: `pkg/cvss/cvss3x_base.go:74-110`
- Modify: `pkg/cvss/cvss3x_temporal.go:31-47`
- Modify: `pkg/cvss/cvss3x_environmental.go:75-123`

- [ ] **Step 1: 修改 Cvss3xBase.String 以按规范顺序输出**

文件: `pkg/cvss/cvss3x_base.go:74-110`（替换整个 String 方法）

```go
func (x *Cvss3xBase) String() string {
	slice := make([]string, 0, 8)

	// 按 CVSS 规范顺序: AV, AC, PR, UI, S, C, I, A
	if x.AttackVector != nil {
		slice = append(slice, x.AttackVector.String())
	}
	if x.AttackComplexity != nil {
		slice = append(slice, x.AttackComplexity.String())
	}
	if x.PrivilegesRequired != nil {
		slice = append(slice, x.PrivilegesRequired.String())
	}
	if x.UserInteraction != nil {
		slice = append(slice, x.UserInteraction.String())
	}
	if x.Scope != nil {
		slice = append(slice, x.Scope.String())
	}
	if x.Confidentiality != nil {
		slice = append(slice, x.Confidentiality.String())
	}
	if x.Integrity != nil {
		slice = append(slice, x.Integrity.String())
	}
	if x.Availability != nil {
		slice = append(slice, x.Availability.String())
	}

	return strings.Join(slice, "/")
}
```

- [ ] **Step 2: 修改 Cvss3xTemporal.String 以按规范顺序输出**

文件: `pkg/cvss/cvss3x_temporal.go:31-47`（替换整个 String 方法）

```go
func (x *Cvss3xTemporal) String() string {
	slice := make([]string, 0, 3)

	// 按 CVSS 规范顺序: E, RL, RC
	if x.ExploitCodeMaturity != nil {
		slice = append(slice, x.ExploitCodeMaturity.String())
	}
	if x.RemediationLevel != nil {
		slice = append(slice, x.RemediationLevel.String())
	}
	if x.ReportConfidence != nil {
		slice = append(slice, x.ReportConfidence.String())
	}

	return strings.Join(slice, "/")
}
```

- [ ] **Step 3: 修改 Cvss3xEnvironmental.String 以按规范顺序输出**

文件: `pkg/cvss/cvss3x_environmental.go:75-123`（替换整个 String 方法）

```go
func (x *Cvss3xEnvironmental) String() string {
	slice := make([]string, 0, 11)

	// 按 CVSS 规范顺序: CR, IR, AR, MAV, MAC, MPR, MUI, MS, MC, MI, MA
	if x.ConfidentialityRequirement != nil {
		slice = append(slice, x.ConfidentialityRequirement.String())
	}
	if x.IntegrityRequirement != nil {
		slice = append(slice, x.IntegrityRequirement.String())
	}
	if x.AvailabilityRequirement != nil {
		slice = append(slice, x.AvailabilityRequirement.String())
	}
	if x.ModifiedAttackVector != nil {
		slice = append(slice, x.ModifiedAttackVector.String())
	}
	if x.ModifiedAttackComplexity != nil {
		slice = append(slice, x.ModifiedAttackComplexity.String())
	}
	if x.ModifiedPrivilegesRequired != nil {
		slice = append(slice, x.ModifiedPrivilegesRequired.String())
	}
	if x.ModifiedUserInteraction != nil {
		slice = append(slice, x.ModifiedUserInteraction.String())
	}
	if x.ModifiedScope != nil {
		slice = append(slice, x.ModifiedScope.String())
	}
	if x.ModifiedConfidentiality != nil {
		slice = append(slice, x.ModifiedConfidentiality.String())
	}
	if x.ModifiedIntegrity != nil {
		slice = append(slice, x.ModifiedIntegrity.String())
	}
	if x.ModifiedAvailability != nil {
		slice = append(slice, x.ModifiedAvailability.String())
	}

	return strings.Join(slice, "/")
}
```

- [ ] **Step 4: 验证向量字符串排序修复**
Run: `cd /home/cc11001100/github/scagogogo/cvss && go test ./...`
Expected:
  - Exit code: 0
  - Output does NOT contain: "FAIL"

- [ ] **Step 5: 提交**
Run: `cd /home/cc11001100/github/scagogogo/cvss && git add pkg/cvss/cvss3x_base.go pkg/cvss/cvss3x_temporal.go pkg/cvss/cvss3x_environmental.go && git commit -m "fix(cvss): output vector string metrics in spec-mandated order"`

---

### Task 4: Fix i18n — Replace Chinese Descriptions with English

**Depends on:** None
**Files:**
- Modify: `pkg/vector/not_defined_vectors.go:1-109`

- [ ] **Step 1: 修改 not_defined_vectors.go — 将中文描述替换为英文**

文件: `pkg/vector/not_defined_vectors.go`（替换整个文件内容）

```go
package vector

// "Not Defined" variants for Environmental modified metrics
// When a modified metric is set to "Not Defined" (X), the base metric value is used instead.

var (
	// AttackVectorNotDefined represents a Not Defined (X) value for Modified Attack Vector
	AttackVectorNotDefined = &AttackVector{
		VectorImpl: &VectorImpl{
			GroupName:   "Environmental",
			ShortName:   "MAV",
			LongName:    "Modified Attack Vector",
			ShortValue:  'X',
			LongValue:   "Not Defined",
			Description: "Not Defined means this metric should not modify the base metric value",
			Score:       1.0,
		},
	}

	// AttackComplexityNotDefined represents a Not Defined (X) value for Modified Attack Complexity
	AttackComplexityNotDefined = &AttackComplexity{
		VectorImpl: &VectorImpl{
			GroupName:   "Environmental",
			ShortName:   "MAC",
			LongName:    "Modified Attack Complexity",
			ShortValue:  'X',
			LongValue:   "Not Defined",
			Description: "Not Defined means this metric should not modify the base metric value",
			Score:       1.0,
		},
	}

	// PrivilegesRequiredNotDefined represents a Not Defined (X) value for Modified Privileges Required
	PrivilegesRequiredNotDefined = &PrivilegesRequired{
		VectorImpl: &VectorImpl{
			GroupName:   "Environmental",
			ShortName:   "MPR",
			LongName:    "Modified Privileges Required",
			ShortValue:  'X',
			LongValue:   "Not Defined",
			Description: "Not Defined means this metric should not modify the base metric value",
			Score:       1.0,
		},
	}

	// UserInteractionNotDefined represents a Not Defined (X) value for Modified User Interaction
	UserInteractionNotDefined = &UserInteraction{
		VectorImpl: &VectorImpl{
			GroupName:   "Environmental",
			ShortName:   "MUI",
			LongName:    "Modified User Interaction",
			ShortValue:  'X',
			LongValue:   "Not Defined",
			Description: "Not Defined means this metric should not modify the base metric value",
			Score:       1.0,
		},
	}

	// ScopeNotDefined represents a Not Defined (X) value for Modified Scope
	ScopeNotDefined = &Scope{
		VectorImpl: &VectorImpl{
			GroupName:   "Environmental",
			ShortName:   "MS",
			LongName:    "Modified Scope",
			ShortValue:  'X',
			LongValue:   "Not Defined",
			Description: "Not Defined means this metric should not modify the base metric value",
			Score:       1.0,
		},
	}

	// ConfidentialityNotDefined represents a Not Defined (X) value for Modified Confidentiality
	ConfidentialityNotDefined = &Confidentiality{
		VectorImpl: &VectorImpl{
			GroupName:   "Environmental",
			ShortName:   "MC",
			LongName:    "Modified Confidentiality",
			ShortValue:  'X',
			LongValue:   "Not Defined",
			Description: "Not Defined means this metric should not modify the base metric value",
			Score:       1.0,
		},
	}

	// IntegrityNotDefined represents a Not Defined (X) value for Modified Integrity
	IntegrityNotDefined = &Integrity{
		VectorImpl: &VectorImpl{
			GroupName:   "Environmental",
			ShortName:   "MI",
			LongName:    "Modified Integrity",
			ShortValue:  'X',
			LongValue:   "Not Defined",
			Description: "Not Defined means this metric should not modify the base metric value",
			Score:       1.0,
		},
	}

	// AvailabilityNotDefined represents a Not Defined (X) value for Modified Availability
	AvailabilityNotDefined = &Availability{
		VectorImpl: &VectorImpl{
			GroupName:   "Environmental",
			ShortName:   "MA",
			LongName:    "Modified Availability",
			ShortValue:  'X',
			LongValue:   "Not Defined",
			Description: "Not Defined means this metric should not modify the base metric value",
			Score:       1.0,
		},
	}
)
```

- [ ] **Step 2: 验证 i18n 修复**
Run: `cd /home/cc11001100/github/scagogogo/cvss && go test ./pkg/vector/ -v -run "TestNotDefined" 2>&1 | head -20`
Expected:
  - Exit code: 0
  - Output contains: "PASS"

- [ ] **Step 3: 提交**
Run: `cd /home/cc11001100/github/scagogogo/cvss && git add pkg/vector/not_defined_vectors.go && git commit -m "fix(vector): replace Chinese descriptions with English in Not Defined vectors"`

---

### Task 5: Fix Filename — Remove Trailing Space from confidentiality_requirement File

**Depends on:** None
**Files:**
- Rename: `pkg/vector/confidentiality_requirement .go` → `pkg/vector/confidentiality_requirement.go`

- [ ] **Step 1: 重命名文件去掉尾部空格**
Run: `cd /home/cc11001100/github/scagogogo/cvss && git mv 'pkg/vector/confidentiality_requirement .go' pkg/vector/confidentiality_requirement.go`

- [ ] **Step 2: 验证重命名后代码编译通过**
Run: `cd /home/cc11001100/github/scagogogo/cvss && go build ./... && go test ./...`
Expected:
  - Exit code: 0
  - Output does NOT contain: "FAIL"

- [ ] **Step 3: 提交**
Run: `cd /home/cc11001100/github/scagogogo/cvss && git add -A && git commit -m "fix(vector): remove trailing space from confidentiality_requirement filename"`

---

### Task 6: Implement Mock Package — Random CVSS Data Generator

**Depends on:** Task 1
**Files:**
- Modify: `pkg/mock/mock.go`

- [ ] **Step 1: 实现 Mock 包 — 提供随机 CVSS 3.x 数据生成器**

```go
package mock

import (
	"fmt"
	"math/rand"

	"github.com/scagogogo/cvss-parser/pkg/cvss"
	"github.com/scagogogo/cvss-parser/pkg/vector"
)

// RandomCvss3x 生成一个随机的 CVSS 3.x 对象（仅包含基础指标）
// minorVersion 指定次版本号（0 或 1）
func RandomCvss3x(minorVersion int) *cvss.Cvss3x {
	if minorVersion != 0 && minorVersion != 1 {
		minorVersion = 1
	}

	result := cvss.NewCvss3x()
	result.MajorVersion = 3
	result.MinorVersion = minorVersion

	// 随机基础指标
	result.Cvss3xBase.AttackVector = randomFromSlice([]vector.Vector{
		vector.AttackVectorNetwork, vector.AttackVectorAdjacent,
		vector.AttackVectorLocal, vector.AttackVectorPhysical,
	})
	result.Cvss3xBase.AttackComplexity = randomFromSlice([]vector.Vector{
		vector.AttackComplexityLow, vector.AttackComplexityHigh,
	})
	result.Cvss3xBase.PrivilegesRequired = randomFromSlice([]vector.Vector{
		vector.PrivilegesRequiredNone, vector.PrivilegesRequiredLow,
		vector.PrivilegesRequiredHigh,
	})
	result.Cvss3xBase.UserInteraction = randomFromSlice([]vector.Vector{
		vector.UserInteractionNone, vector.UserInteractionRequired,
	})
	result.Cvss3xBase.Scope = randomFromSlice([]vector.Vector{
		vector.ScopeUnchanged, vector.ScopeChanged,
	})
	result.Cvss3xBase.Confidentiality = randomFromSlice([]vector.Vector{
		vector.ConfidentialityHigh, vector.ConfidentialityLow, vector.ConfidentialityNone,
	})
	result.Cvss3xBase.Integrity = randomFromSlice([]vector.Vector{
		vector.IntegrityHigh, vector.IntegrityLow, vector.IntegrityNone,
	})
	result.Cvss3xBase.Availability = randomFromSlice([]vector.Vector{
		vector.AvailabilityHigh, vector.AvailabilityLow, vector.AvailabilityNone,
	})

	return result
}

// RandomCvss3xWithTemporal 生成一个随机的 CVSS 3.x 对象（包含基础和时间指标）
func RandomCvss3xWithTemporal(minorVersion int) *cvss.Cvss3x {
	result := RandomCvss3x(minorVersion)

	result.Cvss3xTemporal.ExploitCodeMaturity = randomFromSlice([]vector.Vector{
		vector.ExploitCodeMaturityNotDefined, vector.ExploitCodeMaturityUnproven,
		vector.ExploitCodeMaturityProofOfConcept, vector.ExploitCodeMaturityFunctional,
		vector.ExploitCodeMaturityHigh,
	})
	result.Cvss3xTemporal.RemediationLevel = randomFromSlice([]vector.Vector{
		vector.RemediationLevelNotDefined, vector.RemediationLevelOfficialFix,
		vector.RemediationLevelTemporaryFix, vector.RemediationLevelWorkaround,
		vector.RemediationLevelUnavailable,
	})
	result.Cvss3xTemporal.ReportConfidence = randomFromSlice([]vector.Vector{
		vector.ReportConfidenceNotDefined, vector.ReportConfidenceUnknown,
		vector.ReportConfidenceReasonable, vector.ReportConfidenceConfirmed,
	})

	return result
}

// RandomCvss3xFull 生成一个随机的 CVSS 3.x 对象（包含所有指标）
func RandomCvss3xFull(minorVersion int) *cvss.Cvss3x {
	result := RandomCvss3xWithTemporal(minorVersion)

	// CIA Requirements
	result.Cvss3xEnvironmental.ConfidentialityRequirement = randomFromSlice([]vector.Vector{
		vector.ConfidentialityRequirementNotDefined, vector.ConfidentialityRequirementLow,
		vector.ConfidentialityRequirementMedium, vector.ConfidentialityRequirementHigh,
	})
	result.Cvss3xEnvironmental.IntegrityRequirement = randomFromSlice([]vector.Vector{
		vector.IntegrityRequirementNotDefined, vector.IntegrityRequirementLow,
		vector.IntegrityRequirementMedium, vector.IntegrityRequirementHigh,
	})
	result.Cvss3xEnvironmental.AvailabilityRequirement = randomFromSlice([]vector.Vector{
		vector.AvailabilityRequirementNotDefined, vector.AvailabilityRequirementLow,
		vector.AvailabilityRequirementMedium, vector.AvailabilityRequirementHigh,
	})

	// Modified Base Metrics
	result.Cvss3xEnvironmental.ModifiedAttackVector = randomFromSlice([]vector.Vector{
		vector.AttackVectorNotDefined, vector.ModifiedAttackVectorNetwork,
		vector.ModifiedAttackVectorAdjacent, vector.ModifiedAttackVectorLocal,
		vector.ModifiedAttackVectorPhysical,
	})
	result.Cvss3xEnvironmental.ModifiedAttackComplexity = randomFromSlice([]vector.Vector{
		vector.AttackComplexityNotDefined, vector.ModifiedAttackComplexityLow,
		vector.ModifiedAttackComplexityHigh,
	})
	result.Cvss3xEnvironmental.ModifiedPrivilegesRequired = randomFromSlice([]vector.Vector{
		vector.PrivilegesRequiredNotDefined, vector.ModifiedPrivilegesRequiredNone,
		vector.ModifiedPrivilegesRequiredLow, vector.ModifiedPrivilegesRequiredHigh,
	})
	result.Cvss3xEnvironmental.ModifiedUserInteraction = randomFromSlice([]vector.Vector{
		vector.UserInteractionNotDefined, vector.ModifiedUserInteractionNone,
		vector.ModifiedUserInteractionRequired,
	})
	result.Cvss3xEnvironmental.ModifiedScope = randomFromSlice([]vector.Vector{
		vector.ScopeNotDefined, vector.ModifiedScopeUnchanged,
		vector.ModifiedScopeChanged,
	})
	result.Cvss3xEnvironmental.ModifiedConfidentiality = randomFromSlice([]vector.Vector{
		vector.ConfidentialityNotDefined, vector.ModifiedConfidentialityNone,
		vector.ModifiedConfidentialityLow, vector.ModifiedConfidentialityHigh,
	})
	result.Cvss3xEnvironmental.ModifiedIntegrity = randomFromSlice([]vector.Vector{
		vector.IntegrityNotDefined, vector.ModifiedIntegrityNone,
		vector.ModifiedIntegrityLow, vector.ModifiedIntegrityHigh,
	})
	result.Cvss3xEnvironmental.ModifiedAvailability = randomFromSlice([]vector.Vector{
		vector.AvailabilityNotDefined, vector.ModifiedAvailabilityNone,
		vector.ModifiedAvailabilityLow, vector.ModifiedAvailabilityHigh,
	})

	return result
}

// RandomCvss3xVectorString 生成一个随机的 CVSS 3.x 向量字符串
func RandomCvss3xVectorString(minorVersion int) string {
	return RandomCvss3x(minorVersion).String()
}

// RandomCvss3xWithScore 生成一个随机 CVSS 3.x 对象并计算评分
// 返回对象和评分，如果计算出错则返回错误
func RandomCvss3xWithScore(minorVersion int) (*cvss.Cvss3x, float64, error) {
	obj := RandomCvss3x(minorVersion)
	calc := cvss.NewCalculator(obj)
	score, err := calc.Calculate()
	if err != nil {
		return nil, 0, fmt.Errorf("failed to calculate score: %w", err)
	}
	return obj, score, nil
}

func randomFromSlice(options []vector.Vector) vector.Vector {
	return options[rand.Intn(len(options))]
}
```

- [ ] **Step 2: 验证 Mock 包编译通过**
Run: `cd /home/cc11001100/github/scagogogo/cvss && go build ./pkg/mock/ && go test ./...`
Expected:
  - Exit code: 0
  - Output does NOT contain: "FAIL"

- [ ] **Step 3: 提交**
Run: `cd /home/cc11001100/github/scagogogo/cvss && git add pkg/mock/mock.go && git commit -m "feat(mock): implement random CVSS 3.x data generator for testing"`

package vector

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

type mockVector struct {
	shortName        string
	longName         string
	score            float64
	shortValue       rune
	longValue        string
	description      string
	groupName        string
	baseGroup        bool
	temporalGroup    bool
	environmentGroup bool
}

func (m *mockVector) GetGroupName() string   { return m.groupName }
func (m *mockVector) GetShortName() string   { return m.shortName }
func (m *mockVector) GetLongName() string    { return m.longName }
func (m *mockVector) GetScore() float64      { return m.score }
func (m *mockVector) GetShortValue() rune    { return m.shortValue }
func (m *mockVector) GetLongValue() string   { return m.longValue }
func (m *mockVector) GetDescription() string { return m.description }
func (m *mockVector) String() string         { return m.shortName + ":" + string(m.shortValue) }

// TestVectorInterface 测试Vector接口及实现
func TestVectorInterface(t *testing.T) {
	// 创建一个模拟向量以测试接口方法
	mock := &mockVector{
		shortName:        "TEST",
		longName:         "Test Vector",
		score:            0.5,
		shortValue:       'T',
		longValue:        "Test",
		description:      "This is a test vector",
		groupName:        "Test Group",
		baseGroup:        true,
		temporalGroup:    false,
		environmentGroup: false,
	}

	// 测试接口方法
	assert.Equal(t, "TEST", mock.GetShortName())
	assert.Equal(t, "Test Vector", mock.GetLongName())
	assert.Equal(t, 0.5, mock.GetScore())
	assert.Equal(t, 'T', mock.GetShortValue())
	assert.Equal(t, "Test", mock.GetLongValue())
	assert.Equal(t, "This is a test vector", mock.GetDescription())
	assert.Equal(t, "Test Group", mock.GetGroupName())
	assert.Equal(t, "TEST:T", mock.String())

	// 测试一个真实的向量实例 - 攻击向量网络
	av := AttackVectorNetwork

	assert.Equal(t, "AV", av.GetShortName())
	assert.Equal(t, "Attack Vector", av.GetLongName())
	assert.Equal(t, 0.85, av.GetScore())
	assert.Equal(t, 'N', av.GetShortValue())
	assert.Equal(t, "Network", av.GetLongValue())
	assert.NotEmpty(t, av.GetDescription())
	assert.Equal(t, "Base Metrics", av.GetGroupName())
	assert.Contains(t, av.String(), "AV:N")
}

// TestVectorGroups 测试向量分组相关方法
func TestVectorGroups(t *testing.T) {
	// 测试基础度量向量
	baseVectors := []Vector{
		AttackVectorNetwork,
		AttackComplexityLow,
		PrivilegesRequiredHigh,
		UserInteractionRequired,
		ScopeChanged,
		ConfidentialityHigh,
		IntegrityNone,
		AvailabilityLow,
	}

	for _, v := range baseVectors {
		assert.Equal(t, "Base Metrics", v.GetGroupName(), "Vector %s should be in Base Group", v.GetShortName())
	}

	// 测试时间度量向量
	temporalVectors := []Vector{
		ExploitCodeMaturityFunctional,
		RemediationLevelOfficialFix,
		ReportConfidenceConfirmed,
	}

	for _, v := range temporalVectors {
		assert.Equal(t, "Temporal Metrics", v.GetGroupName(), "Vector %s should be in Temporal Group", v.GetShortName())
	}

	// 测试环境度量修改向量
	modifiedVectors := []Vector{
		ModifiedAttackVectorPhysical,
		ModifiedAttackComplexityHigh,
		ModifiedPrivilegesRequiredLow,
		ModifiedUserInteractionRequired,
		ModifiedScopeChanged,
		ModifiedConfidentialityHigh,
		ModifiedIntegrityLow,
		ModifiedAvailabilityNone,
	}

	for _, v := range modifiedVectors {
		assert.Equal(t, "Environmental Metrics", v.GetGroupName(), "Vector %s should be in Environmental Metrics Group", v.GetShortName())
	}

	// 测试环境度量要求向量
	requirementVectors := []Vector{
		ConfidentialityRequirementHigh,
		IntegrityRequirementLow,
		AvailabilityRequirementMedium,
	}

	for _, v := range requirementVectors {
		assert.Equal(t, "Environmental Metrics", v.GetGroupName(), "Vector %s should be in Environmental Metrics Group", v.GetShortName())
	}
}

// TestVectorImplementation 测试具体向量实现
func TestVectorImplementation(t *testing.T) {
	// 测试攻击向量实现
	t.Run("AttackVector", func(t *testing.T) {
		vectors := []struct {
			vector   Vector
			shortVal rune
			longVal  string
			score    float64
		}{
			{AttackVectorNetwork, 'N', "Network", 0.85},
			{AttackVectorAdjacent, 'A', "Adjacent", 0.62},
			{AttackVectorLocal, 'L', "Local", 0.55},
			{AttackVectorPhysical, 'P', "Physical", 0.2},
		}

		for _, v := range vectors {
			assert.Equal(t, "AV", v.vector.GetShortName())
			assert.Equal(t, "Attack Vector", v.vector.GetLongName())
			assert.Equal(t, v.shortVal, v.vector.GetShortValue())
			assert.Equal(t, v.longVal, v.vector.GetLongValue())
			assert.Equal(t, v.score, v.vector.GetScore())
			assert.NotEmpty(t, v.vector.GetDescription())
		}
	})

	// 测试攻击复杂性实现
	t.Run("AttackComplexity", func(t *testing.T) {
		vectors := []struct {
			vector   Vector
			shortVal rune
			longVal  string
			score    float64
		}{
			{AttackComplexityLow, 'L', "Low", 0.77},
			{AttackComplexityHigh, 'H', "High", 0.44},
		}

		for _, v := range vectors {
			assert.Equal(t, "AC", v.vector.GetShortName())
			assert.Equal(t, "Attack Complexity", v.vector.GetLongName())
			assert.Equal(t, v.shortVal, v.vector.GetShortValue())
			assert.Equal(t, v.longVal, v.vector.GetLongValue())
			assert.Equal(t, v.score, v.vector.GetScore())
			assert.NotEmpty(t, v.vector.GetDescription())
		}
	})

	// 测试权限要求实现
	t.Run("PrivilegesRequired", func(t *testing.T) {
		vectors := []struct {
			vector   Vector
			shortVal rune
			longVal  string
			score    float64
			scopeU   float64
			scopeC   float64
		}{
			{PrivilegesRequiredNone, 'N', "None", 0.85, 0.85, 0.85},
			{PrivilegesRequiredLow, 'L', "Low", 0.62, 0.62, 0.68},
			{PrivilegesRequiredHigh, 'H', "High", 0.27, 0.27, 0.5},
		}

		for _, v := range vectors {
			assert.Equal(t, "PR", v.vector.GetShortName())
			assert.Equal(t, "Privileges Required", v.vector.GetLongName())
			assert.Equal(t, v.shortVal, v.vector.GetShortValue())
			assert.Equal(t, v.longVal, v.vector.GetLongValue())

			// PR值受Scope影响，测试默认值
			assert.Equal(t, v.score, v.vector.GetScore())
			assert.NotEmpty(t, v.vector.GetDescription())
		}
	})

	// 测试修改版向量实现
	t.Run("ModifiedVectors", func(t *testing.T) {
		assert.Equal(t, "MAV", ModifiedAttackVectorNetwork.GetShortName())
		assert.Equal(t, "Modified Attack Vector", ModifiedAttackVectorNetwork.GetLongName())
		assert.Equal(t, 'N', ModifiedAttackVectorNetwork.GetShortValue())
		assert.Equal(t, "Network", ModifiedAttackVectorNetwork.GetLongValue())
		assert.Equal(t, AttackVectorNetwork.GetScore(), ModifiedAttackVectorNetwork.GetScore())
		assert.Equal(t, "Environmental Metrics", ModifiedAttackVectorNetwork.GetGroupName())
	})

	// 测试环境需求向量实现
	t.Run("RequirementVectors", func(t *testing.T) {
		vectors := []struct {
			vector   Vector
			shortVal rune
			longVal  string
			score    float64
		}{
			{ConfidentialityRequirementLow, 'L', "Low", 0.5},
			{ConfidentialityRequirementMedium, 'M', "Medium", 1.0},
			{ConfidentialityRequirementHigh, 'H', "High", 1.5},
			{ConfidentialityRequirementNotDefined, 'X', "Not Defined", 1.0},
		}

		for _, v := range vectors {
			assert.Equal(t, "CR", v.vector.GetShortName())
			assert.Equal(t, "Confidentiality Requirement", v.vector.GetLongName())
			assert.Equal(t, v.shortVal, v.vector.GetShortValue())
			assert.Equal(t, v.longVal, v.vector.GetLongValue())
			assert.Equal(t, v.score, v.vector.GetScore())
			assert.Equal(t, "Environmental Metrics", v.vector.GetGroupName())
		}
	})
}

// TestVectorDescriptions 测试向量描述是否提供了有意义的内容
func TestVectorDescriptions(t *testing.T) {
	vectors := []Vector{
		// 基础度量
		AttackVectorNetwork,
		AttackComplexityLow,
		PrivilegesRequiredNone,
		UserInteractionNone,
		ScopeUnchanged,
		ConfidentialityHigh,
		IntegrityHigh,
		AvailabilityHigh,
		// 时间度量
		ExploitCodeMaturityHigh,
		RemediationLevelOfficialFix,
		ReportConfidenceConfirmed,
		// 环境度量
		ConfidentialityRequirementHigh,
		IntegrityRequirementHigh,
		AvailabilityRequirementHigh,
		ModifiedAttackVectorNetwork,
	}

	for _, v := range vectors {
		description := v.GetDescription()
		assert.NotEmpty(t, description, "Vector %s should have a non-empty description", v.GetShortName())
		assert.True(t, len(description) > 10, "Vector %s should have a meaningful description", v.GetShortName())
	}
}

// TestBaseVectorsDefaults 测试基础向量的默认值
func TestBaseVectorsDefaults(t *testing.T) {
	// 测试所有预定义向量是否符合期望
	assert.Equal(t, float64(0.85), AttackVectorNetwork.GetScore())
	assert.Equal(t, float64(0.62), AttackVectorAdjacent.GetScore())
	assert.Equal(t, float64(0.55), AttackVectorLocal.GetScore())
	assert.Equal(t, float64(0.2), AttackVectorPhysical.GetScore())

	assert.Equal(t, float64(0.77), AttackComplexityLow.GetScore())
	assert.Equal(t, float64(0.44), AttackComplexityHigh.GetScore())

	assert.Equal(t, float64(0.85), PrivilegesRequiredNone.GetScore())

	assert.Equal(t, float64(0.85), UserInteractionNone.GetScore())
	assert.Equal(t, float64(0.62), UserInteractionRequired.GetScore())

	assert.Equal(t, float64(0), ScopeUnchanged.GetScore())

	assert.Equal(t, float64(0), ConfidentialityNone.GetScore())
	assert.Equal(t, float64(0.22), ConfidentialityLow.GetScore())
	assert.Equal(t, float64(0.56), ConfidentialityHigh.GetScore())

	assert.Equal(t, float64(0), IntegrityNone.GetScore())
	assert.Equal(t, float64(0.22), IntegrityLow.GetScore())
	assert.Equal(t, float64(0.56), IntegrityHigh.GetScore())

	assert.Equal(t, float64(0), AvailabilityNone.GetScore())
	assert.Equal(t, float64(0.22), AvailabilityLow.GetScore())
	assert.Equal(t, float64(0.56), AvailabilityHigh.GetScore())
}

// TestNotDefinedDefaultValues 测试NotDefined向量的默认值
func TestNotDefinedDefaultValues(t *testing.T) {
	// 测试NotDefined的值是否符合期望（这些实际上是修改版向量的NotDefined）
	assert.Equal(t, "Modified Attack Vector", AttackVectorNotDefined.GetLongName())
	assert.Equal(t, "MAV", AttackVectorNotDefined.GetShortName())
	assert.Equal(t, 'X', AttackVectorNotDefined.GetShortValue())
	assert.Equal(t, "Not Defined", AttackVectorNotDefined.GetLongValue())
	assert.Equal(t, float64(1.0), AttackVectorNotDefined.GetScore())

	// 测试其他修改版向量的NotDefined
	assert.Equal(t, "Modified Attack Complexity", AttackComplexityNotDefined.GetLongName())
	assert.Equal(t, "MAC", AttackComplexityNotDefined.GetShortName())
	assert.Equal(t, 'X', AttackComplexityNotDefined.GetShortValue())
	assert.Equal(t, "Not Defined", AttackComplexityNotDefined.GetLongValue())
}

// TestTemporalVectorsDefaults 测试时间向量的默认值
func TestTemporalVectorsDefaults(t *testing.T) {
	assert.Equal(t, float64(1.0), ExploitCodeMaturityNotDefined.GetScore())
	assert.Equal(t, float64(0.91), ExploitCodeMaturityUnproven.GetScore())
	assert.Equal(t, float64(0.94), ExploitCodeMaturityProofOfConcept.GetScore())
	assert.Equal(t, float64(0.97), ExploitCodeMaturityFunctional.GetScore())
	assert.Equal(t, float64(1), ExploitCodeMaturityHigh.GetScore())

	assert.Equal(t, float64(1), RemediationLevelNotDefined.GetScore())
	assert.Equal(t, float64(0.95), RemediationLevelOfficialFix.GetScore())
	assert.Equal(t, float64(0.96), RemediationLevelTemporaryFix.GetScore())
	assert.Equal(t, float64(0.97), RemediationLevelWorkaround.GetScore())
	assert.Equal(t, float64(1), RemediationLevelUnavailable.GetScore())

	assert.Equal(t, float64(1), ReportConfidenceNotDefined.GetScore())
	assert.Equal(t, float64(0.92), ReportConfidenceUnknown.GetScore())
	assert.Equal(t, float64(0.96), ReportConfidenceReasonable.GetScore())
	assert.Equal(t, float64(1), ReportConfidenceConfirmed.GetScore())
}

// TestEnvironmentalVectorsDefaults 测试环境向量的默认值
func TestEnvironmentalVectorsDefaults(t *testing.T) {
	assert.Equal(t, float64(1), ConfidentialityRequirementNotDefined.GetScore())
	assert.Equal(t, float64(0.5), ConfidentialityRequirementLow.GetScore())
	assert.Equal(t, float64(1), ConfidentialityRequirementMedium.GetScore())
	assert.Equal(t, float64(1.5), ConfidentialityRequirementHigh.GetScore())

	assert.Equal(t, float64(1), IntegrityRequirementNotDefined.GetScore())
	assert.Equal(t, float64(0.5), IntegrityRequirementLow.GetScore())
	assert.Equal(t, float64(1), IntegrityRequirementMedium.GetScore())
	assert.Equal(t, float64(1.5), IntegrityRequirementHigh.GetScore())

	assert.Equal(t, float64(1), AvailabilityRequirementNotDefined.GetScore())
	assert.Equal(t, float64(0.5), AvailabilityRequirementLow.GetScore())
	assert.Equal(t, float64(1), AvailabilityRequirementMedium.GetScore())
	assert.Equal(t, float64(1.5), AvailabilityRequirementHigh.GetScore())
}

// TestScopeVectors 单独测试Scope向量
func TestScopeVectors(t *testing.T) {
	assert.Equal(t, "S", ScopeUnchanged.GetShortName())
	assert.Equal(t, "S", ScopeChanged.GetShortName())
	assert.Equal(t, 'U', ScopeUnchanged.GetShortValue())
	assert.Equal(t, 'C', ScopeChanged.GetShortValue())
	assert.Equal(t, "Unchanged", ScopeUnchanged.GetLongValue())
	assert.Equal(t, "Changed", ScopeChanged.GetLongValue())

	// 从文档来看，ScopeChanged的值应该是0，而不是6.42
	assert.Equal(t, float64(0), ScopeChanged.GetScore())
}

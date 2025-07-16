package vector

// 定义在factory.go中引用但尚未定义的"NotDefined"变量

var (
	// 攻击向量未定义
	AttackVectorNotDefined = &AttackVector{
		VectorImpl: &VectorImpl{
			GroupName:   "Environmental",
			ShortName:   "MAV",
			LongName:    "Modified Attack Vector",
			ShortValue:  'X',
			LongValue:   "Not Defined",
			Description: "未定义表示此指标不应修改基本指标值",
			Score:       1.0,
		},
	}

	// 攻击复杂性未定义
	AttackComplexityNotDefined = &AttackComplexity{
		VectorImpl: &VectorImpl{
			GroupName:   "Environmental",
			ShortName:   "MAC",
			LongName:    "Modified Attack Complexity",
			ShortValue:  'X',
			LongValue:   "Not Defined",
			Description: "未定义表示此指标不应修改基本指标值",
			Score:       1.0,
		},
	}

	// 特权要求未定义
	PrivilegesRequiredNotDefined = &PrivilegesRequired{
		VectorImpl: &VectorImpl{
			GroupName:   "Environmental",
			ShortName:   "MPR",
			LongName:    "Modified Privileges Required",
			ShortValue:  'X',
			LongValue:   "Not Defined",
			Description: "未定义表示此指标不应修改基本指标值",
			Score:       1.0,
		},
	}

	// 用户交互未定义
	UserInteractionNotDefined = &UserInteraction{
		VectorImpl: &VectorImpl{
			GroupName:   "Environmental",
			ShortName:   "MUI",
			LongName:    "Modified User Interaction",
			ShortValue:  'X',
			LongValue:   "Not Defined",
			Description: "未定义表示此指标不应修改基本指标值",
			Score:       1.0,
		},
	}

	// 范围未定义
	ScopeNotDefined = &Scope{
		VectorImpl: &VectorImpl{
			GroupName:   "Environmental",
			ShortName:   "MS",
			LongName:    "Modified Scope",
			ShortValue:  'X',
			LongValue:   "Not Defined",
			Description: "未定义表示此指标不应修改基本指标值",
			Score:       1.0,
		},
	}

	// 机密性未定义
	ConfidentialityNotDefined = &Confidentiality{
		VectorImpl: &VectorImpl{
			GroupName:   "Environmental",
			ShortName:   "MC",
			LongName:    "Modified Confidentiality",
			ShortValue:  'X',
			LongValue:   "Not Defined",
			Description: "未定义表示此指标不应修改基本指标值",
			Score:       1.0,
		},
	}

	// 完整性未定义
	IntegrityNotDefined = &Integrity{
		VectorImpl: &VectorImpl{
			GroupName:   "Environmental",
			ShortName:   "MI",
			LongName:    "Modified Integrity",
			ShortValue:  'X',
			LongValue:   "Not Defined",
			Description: "未定义表示此指标不应修改基本指标值",
			Score:       1.0,
		},
	}

	// 可用性未定义
	AvailabilityNotDefined = &Availability{
		VectorImpl: &VectorImpl{
			GroupName:   "Environmental",
			ShortName:   "MA",
			LongName:    "Modified Availability",
			ShortValue:  'X',
			LongValue:   "Not Defined",
			Description: "未定义表示此指标不应修改基本指标值",
			Score:       1.0,
		},
	}
)

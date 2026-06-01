package vector

type PrivilegesRequired struct {
	*VectorImpl
}

var _ Vector = &PrivilegesRequired{}

var (
	PrivilegesRequiredNone = &PrivilegesRequired{
		VectorImpl: &VectorImpl{
			GroupName:   "Base Metrics",
			ShortName:   "PR",
			LongName:    "Privileges Required",
			ShortValue:  'N',
			LongValue:   "None",
			Description: `The attacker is unauthorized prior to attack, and therefore does not require any access to settings or files of the vulnerable system to carry out an attack.`,
			Score:       0.85,
		},
	}

	PrivilegesRequiredLow = &PrivilegesRequired{
		VectorImpl: &VectorImpl{
			GroupName:   "Base Metrics",
			ShortName:   "PR",
			LongName:    "Privileges Required",
			ShortValue:  'L',
			LongValue:   "Low",
			Description: `The attacker requires privileges that provide basic user capabilities that could normally affect only settings and files owned by a user. Alternatively, an attacker with Low privileges has the ability to access only non-sensitive resources.`,
			// Score: 0.62 (Scope Unchanged) / 0.68 (Scope Changed) — use GetPrivilegesRequiredScore() for correct value
			Score: 0.62,
		},
	}

	PrivilegesRequiredHigh = &PrivilegesRequired{
		VectorImpl: &VectorImpl{
			GroupName:   "Base Metrics",
			ShortName:   "PR",
			LongName:    "Privileges Required",
			ShortValue:  'H',
			LongValue:   "High",
			Description: `The attacker requires privileges that provide significant (e.g., administrative) control over the vulnerable component allowing access to component-wide settings and files.`,
			// Score: 0.27 (Scope Unchanged) / 0.5 (Scope Changed) — use GetPrivilegesRequiredScore() for correct value
			Score: 0.27,
		},
	}
)

var (
	ModifiedPrivilegesRequiredNone = &PrivilegesRequired{
		VectorImpl: &VectorImpl{
			GroupName:   "Environmental Metrics",
			ShortName:   "MPR",
			LongName:    "Modified Privileges Required",
			ShortValue:  'N',
			LongValue:   "None",
			Description: `The attacker is unauthorized prior to attack, and therefore does not require any access to settings or files of the vulnerable system to carry out an attack.`,
			Score:       0.85,
		},
	}

	ModifiedPrivilegesRequiredLow = &PrivilegesRequired{
		VectorImpl: &VectorImpl{
			GroupName:   "Environmental Metrics",
			ShortName:   "MPR",
			LongName:    "Modified Privileges Required",
			ShortValue:  'L',
			LongValue:   "Low",
			Description: `The attacker requires privileges that provide basic user capabilities that could normally affect only settings and files owned by a user. Alternatively, an attacker with Low privileges has the ability to access only non-sensitive resources.`,
			// Score: 0.62 (Scope Unchanged) / 0.68 (Scope Changed) — use GetPrivilegesRequiredScore() for correct value
			Score: 0.62,
		},
	}

	ModifiedPrivilegesRequiredHigh = &PrivilegesRequired{
		VectorImpl: &VectorImpl{
			GroupName:   "Environmental Metrics",
			ShortName:   "MPR",
			LongName:    "Modified Privileges Required",
			ShortValue:  'H',
			LongValue:   "High",
			Description: `The attacker requires privileges that provide significant (e.g., administrative) control over the vulnerable component allowing access to component-wide settings and files.`,
			// Score: 0.27 (Scope Unchanged) / 0.5 (Scope Changed) — use GetPrivilegesRequiredScore() for correct value
			Score: 0.27,
		},
	}
)

// GetPrivilegesRequiredScore 返回考虑 Scope 依赖后的正确 PR 分数。
// CVSS v3.x 规范中，PR 的分数取决于 Scope 是否为 Changed：
//   - PR: None → 0.85（不受 Scope 影响）
//   - PR: Low  → 0.62（Scope Unchanged）/ 0.68（Scope Changed）
//   - PR: High → 0.27（Scope Unchanged）/ 0.5（Scope Changed）
//
// pr 为 PR 或 MPR 的 Vector 对象，scopeChanged 表示 Scope 是否为 Changed。
// 当 pr 为 nil 或 ShortValue 为 'X'（Not Defined）时返回 1.0。
func GetPrivilegesRequiredScore(pr Vector, scopeChanged bool) float64 {
	if pr == nil {
		return 1.0
	}

	switch pr.GetShortValue() {
	case 'N':
		return 0.85
	case 'L':
		if scopeChanged {
			return 0.68
		}
		return 0.62
	case 'H':
		if scopeChanged {
			return 0.5
		}
		return 0.27
	case 'X':
		return 1.0
	default:
		// 不应到达此处，返回静态值作为 fallback
		return pr.GetScore()
	}
}

// IsScopeChanged 判断 Scope 向量是否为 Changed。
// 如果 scope 为 nil 或 ShortValue 不是 'C'，返回 false。
func IsScopeChanged(scope Vector) bool {
	return scope != nil && scope.GetShortValue() == 'C'
}

// IsModifiedScopeChanged 判断 Modified Scope 是否为 Changed。
// 如果 modifiedScope 为 nil 或 ShortValue 为 'X'（Not Defined），则回退到 baseScope 判断。
func IsModifiedScopeChanged(modifiedScope Vector, baseScope Vector) bool {
	if modifiedScope != nil && modifiedScope.GetShortValue() != 'X' {
		return modifiedScope.GetShortValue() == 'C'
	}
	return IsScopeChanged(baseScope)
}

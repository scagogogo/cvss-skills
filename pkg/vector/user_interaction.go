package vector

type UserInteraction struct {
	*VectorImpl
}

var _ Vector = &UserInteraction{}

var (
	UserInteractionNone = &UserInteraction{
		VectorImpl: &VectorImpl{
			GroupName:   "Base Metrics",
			ShortName:   "UI",
			LongName:    "User Interaction",
			ShortValue:  'N',
			LongValue:   "None",
			Description: `The vulnerable system can be exploited without interaction from any user.`,
			Score:       0.85,
		},
	}

	UserInteractionRequired = &UserInteraction{
		VectorImpl: &VectorImpl{
			GroupName:   "Base Metrics",
			ShortName:   "UI",
			LongName:    "User Interaction",
			ShortValue:  'R',
			LongValue:   "Required",
			Description: `Successful exploitation of this vulnerability requires a user to take some action before the vulnerability can be exploited. For example, a successful exploit may only be possible during the installation of an application by a system administrator.`,
			Score:       0.62, // CVSS v3.1 value; v3.0 uses 0.56
		},
	}
)

// GetUserInteractionScore 返回用户交互分数，考虑 CVSS 版本差异
// CVSS v3.0: UI:R = 0.56; CVSS v3.1: UI:R = 0.62; UI:N = 0.85 (both versions)
func GetUserInteractionScore(ui Vector, minorVersion int) float64 {
	if ui == nil || ui.IsNotDefined() {
		return 1.0
	}
	switch ui.GetShortValue() {
	case 'N':
		return 0.85
	case 'R':
		if minorVersion == 0 {
			return 0.56 // CVSS v3.0 value
		}
		return 0.62 // CVSS v3.1 value
	default:
		return ui.GetScore()
	}
}

var (
	ModifiedUserInteractionNone = &UserInteraction{
		VectorImpl: &VectorImpl{
			GroupName:   "Environmental Metrics",
			ShortName:   "MUI",
			LongName:    "Modified User Interaction",
			ShortValue:  'N',
			LongValue:   "None",
			Description: `The vulnerable system can be exploited without interaction from any user.`,
			Score:       0.85,
		},
	}

	ModifiedUserInteractionRequired = &UserInteraction{
		VectorImpl: &VectorImpl{
			GroupName:   "Environmental Metrics",
			ShortName:   "MUI",
			LongName:    "Modified User Interaction",
			ShortValue:  'R',
			LongValue:   "Required",
			Description: `Successful exploitation of this vulnerability requires a user to take some action before the vulnerability can be exploited. For example, a successful exploit may only be possible during the installation of an application by a system administrator.`,
			Score:       0.62,
		},
	}
)

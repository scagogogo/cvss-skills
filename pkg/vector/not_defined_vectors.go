package vector

// "Not Defined" variants for Environmental modified metrics
// When a modified metric is set to "Not Defined" (X), the base metric value is used instead.

var (
	// AttackVectorNotDefined represents a Not Defined (X) value for Modified Attack Vector
	AttackVectorNotDefined = &AttackVector{
		VectorImpl: &VectorImpl{
			GroupName:   "Environmental Metrics",
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
			GroupName:   "Environmental Metrics",
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
			GroupName:   "Environmental Metrics",
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
			GroupName:   "Environmental Metrics",
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
			GroupName:   "Environmental Metrics",
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
			GroupName:   "Environmental Metrics",
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
			GroupName:   "Environmental Metrics",
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
			GroupName:   "Environmental Metrics",
			ShortName:   "MA",
			LongName:    "Modified Availability",
			ShortValue:  'X',
			LongValue:   "Not Defined",
			Description: "Not Defined means this metric should not modify the base metric value",
			Score:       1.0,
		},
	}
)

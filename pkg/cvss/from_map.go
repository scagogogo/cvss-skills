package cvss

import (
	"fmt"

)

// FromMap 从 map[string]string 构造 Cvss3x 对象
// key 为指标短名称（如 "AV", "AC", "PR"），value 为指标短值（如 "N", "L", "H"）
// 必须包含 "version" 键（格式 "3.0" 或 "3.1"），或通过 WithVersion Option 单独指定
//
// 用法:
//
//	cv, err := cvss.FromMap(map[string]string{
//	    "version": "3.1",
//	    "AV": "N", "AC": "L", "PR": "N", "UI": "N",
//	    "S": "U", "C": "H", "I": "H", "A": "H",
//	    "E": "F", "RL": "T",
//	})
func FromMap(m map[string]string) (*Cvss3x, error) {
	if m == nil {
		return nil, fmt.Errorf("map is nil")
	}

	result := &Cvss3x{
		Cvss3xBase:          &Cvss3xBase{},
		Cvss3xTemporal:      nil,
		Cvss3xEnvironmental: nil,
		MajorVersion:        3,
		MinorVersion:        1,
	}

	// 解析版本号
	if v, ok := m["version"]; ok {
		major, minor, err := parseVersionString(v)
		if err != nil {
			return nil, fmt.Errorf("invalid version %q: %w", v, err)
		}
		result.MajorVersion = major
		result.MinorVersion = minor
	}

	// 遍历 map 并设置指标
	var errs []string
	for key, val := range m {
		if key == "version" {
			continue // 版本号已处理
		}
		if err := mapKeyValueToStruct(result, key, val); err != nil {
			errs = append(errs, fmt.Sprintf("%s=%s: %v", key, val, err))
		}
	}

	if len(errs) > 0 {
		return nil, fmt.Errorf("FromMap errors: %v", errs)
	}

	return result, nil
}

// MustFromMap 从 map 构造 Cvss3x，出错则 panic
func MustFromMap(m map[string]string) *Cvss3x {
	result, err := FromMap(m)
	if err != nil {
		panic(err)
	}
	return result
}

// ToMap 将 Cvss3x 转换为 map[string]string
// 返回所有已设置的指标，key 为短名称，value 为短值
func (x *Cvss3x) ToMap() map[string]string {
	if x == nil {
		return nil
	}

	m := map[string]string{
		"version": fmt.Sprintf("%d.%d", x.MajorVersion, x.MinorVersion),
	}

	// Base metrics
	if x.Cvss3xBase != nil {
		if x.Cvss3xBase.AttackVector != nil {
			m["AV"] = string(x.Cvss3xBase.AttackVector.GetShortValue())
		}
		if x.Cvss3xBase.AttackComplexity != nil {
			m["AC"] = string(x.Cvss3xBase.AttackComplexity.GetShortValue())
		}
		if x.Cvss3xBase.PrivilegesRequired != nil {
			m["PR"] = string(x.Cvss3xBase.PrivilegesRequired.GetShortValue())
		}
		if x.Cvss3xBase.UserInteraction != nil {
			m["UI"] = string(x.Cvss3xBase.UserInteraction.GetShortValue())
		}
		if x.Cvss3xBase.Scope != nil {
			m["S"] = string(x.Cvss3xBase.Scope.GetShortValue())
		}
		if x.Cvss3xBase.Confidentiality != nil {
			m["C"] = string(x.Cvss3xBase.Confidentiality.GetShortValue())
		}
		if x.Cvss3xBase.Integrity != nil {
			m["I"] = string(x.Cvss3xBase.Integrity.GetShortValue())
		}
		if x.Cvss3xBase.Availability != nil {
			m["A"] = string(x.Cvss3xBase.Availability.GetShortValue())
		}
	}

	// Temporal metrics
	if x.Cvss3xTemporal != nil {
		if x.Cvss3xTemporal.ExploitCodeMaturity != nil {
			m["E"] = string(x.Cvss3xTemporal.ExploitCodeMaturity.GetShortValue())
		}
		if x.Cvss3xTemporal.RemediationLevel != nil {
			m["RL"] = string(x.Cvss3xTemporal.RemediationLevel.GetShortValue())
		}
		if x.Cvss3xTemporal.ReportConfidence != nil {
			m["RC"] = string(x.Cvss3xTemporal.ReportConfidence.GetShortValue())
		}
	}

	// Environmental metrics
	if x.Cvss3xEnvironmental != nil {
		if x.Cvss3xEnvironmental.ConfidentialityRequirement != nil {
			m["CR"] = string(x.Cvss3xEnvironmental.ConfidentialityRequirement.GetShortValue())
		}
		if x.Cvss3xEnvironmental.IntegrityRequirement != nil {
			m["IR"] = string(x.Cvss3xEnvironmental.IntegrityRequirement.GetShortValue())
		}
		if x.Cvss3xEnvironmental.AvailabilityRequirement != nil {
			m["AR"] = string(x.Cvss3xEnvironmental.AvailabilityRequirement.GetShortValue())
		}
		if x.Cvss3xEnvironmental.ModifiedAttackVector != nil {
			m["MAV"] = string(x.Cvss3xEnvironmental.ModifiedAttackVector.GetShortValue())
		}
		if x.Cvss3xEnvironmental.ModifiedAttackComplexity != nil {
			m["MAC"] = string(x.Cvss3xEnvironmental.ModifiedAttackComplexity.GetShortValue())
		}
		if x.Cvss3xEnvironmental.ModifiedPrivilegesRequired != nil {
			m["MPR"] = string(x.Cvss3xEnvironmental.ModifiedPrivilegesRequired.GetShortValue())
		}
		if x.Cvss3xEnvironmental.ModifiedUserInteraction != nil {
			m["MUI"] = string(x.Cvss3xEnvironmental.ModifiedUserInteraction.GetShortValue())
		}
		if x.Cvss3xEnvironmental.ModifiedScope != nil {
			m["MS"] = string(x.Cvss3xEnvironmental.ModifiedScope.GetShortValue())
		}
		if x.Cvss3xEnvironmental.ModifiedConfidentiality != nil {
			m["MC"] = string(x.Cvss3xEnvironmental.ModifiedConfidentiality.GetShortValue())
		}
		if x.Cvss3xEnvironmental.ModifiedIntegrity != nil {
			m["MI"] = string(x.Cvss3xEnvironmental.ModifiedIntegrity.GetShortValue())
		}
		if x.Cvss3xEnvironmental.ModifiedAvailability != nil {
			m["MA"] = string(x.Cvss3xEnvironmental.ModifiedAvailability.GetShortValue())
		}
	}

	return m
}

// parseVersionString 解析版本字符串 "3.1" 为 (3, 1)
func parseVersionString(v string) (int, int, error) {
	if len(v) < 3 {
		return 0, 0, fmt.Errorf("version string too short")
	}
	parts := splitVersion(v)
	if len(parts) != 2 {
		return 0, 0, fmt.Errorf("expected major.minor format")
	}
	major, err := parseInt(parts[0])
	if err != nil {
		return 0, 0, err
	}
	minor, err := parseInt(parts[1])
	if err != nil {
		return 0, 0, err
	}
	return major, minor, nil
}

// splitVersion 按点号分割版本字符串
func splitVersion(v string) []string {
	for i, c := range v {
		if c == '.' {
			return []string{v[:i], v[i+1:]}
		}
	}
	return []string{v}
}

// FromVectorValues 从指标值列表构造 Cvss3x
// 接受 key:value 对的变参，如 "AV:N", "AC:L", "PR:N"
//
// 用法:
//
//	cv, err := cvss.FromVectorValues("3.1", "AV:N", "AC:L", "PR:N", "UI:N", "S:U", "C:H", "I:H", "A:H")
func FromVectorValues(version string, pairs ...string) (*Cvss3x, error) {
	if len(pairs) == 0 {
		return nil, fmt.Errorf("no metric pairs provided")
	}

	major, minor, err := parseVersionString(version)
	if err != nil {
		return nil, fmt.Errorf("invalid version %q: %w", version, err)
	}

	result := &Cvss3x{
		Cvss3xBase:          &Cvss3xBase{},
		Cvss3xTemporal:      nil,
		Cvss3xEnvironmental: nil,
		MajorVersion:        major,
		MinorVersion:        minor,
	}

	for _, pair := range pairs {
		key, val, err := splitKeyValue(pair)
		if err != nil {
			return nil, fmt.Errorf("invalid pair %q: %w", pair, err)
		}
		if err := mapKeyValueToStruct(result, key, val); err != nil {
			return nil, fmt.Errorf("%s:%s: %w", key, val, err)
		}
	}

	return result, nil
}

// splitKeyValue 拆分 "AV:N" 格式的 key:value 对
func splitKeyValue(pair string) (string, string, error) {
	for i, c := range pair {
		if c == ':' {
			return pair[:i], pair[i+1:], nil
		}
	}
	return "", "", fmt.Errorf("missing colon separator")
}


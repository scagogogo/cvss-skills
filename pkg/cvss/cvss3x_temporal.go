package cvss

import (
	"fmt"

	"github.com/scagogogo/cvss-skills/pkg/vector"
	"strings"
)

type Cvss3xTemporal struct {
	ExploitCodeMaturity vector.Vector
	RemediationLevel    vector.Vector
	ReportConfidence    vector.Vector
}

// Check 校验时间指标的合法性
// 已设置的时间指标必须属于正确的类别（短名称必须为 E、RL 或 RC）
func (x *Cvss3xTemporal) Check() error {
	if x.ExploitCodeMaturity != nil && x.ExploitCodeMaturity.GetShortName() != "E" {
		return fmt.Errorf("ExploitCodeMaturity has invalid short name: %s, expected 'E'", x.ExploitCodeMaturity.GetShortName())
	}
	if x.RemediationLevel != nil && x.RemediationLevel.GetShortName() != "RL" {
		return fmt.Errorf("RemediationLevel has invalid short name: %s, expected 'RL'", x.RemediationLevel.GetShortName())
	}
	if x.ReportConfidence != nil && x.ReportConfidence.GetShortName() != "RC" {
		return fmt.Errorf("ReportConfidence has invalid short name: %s, expected 'RC'", x.ReportConfidence.GetShortName())
	}
	return nil
}

func (x *Cvss3xTemporal) String() string {
	slice := make([]string, 0)

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

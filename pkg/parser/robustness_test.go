package parser

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestParser_LowercaseInput(t *testing.T) {
	result, err := ParseString("cvss:3.1/av:n/ac:l/pr:n/ui:n/s:u/c:h/i:h/a:h")
	assert.NoError(t, err)
	assert.NotNil(t, result)
	assert.Equal(t, 3, result.MajorVersion)
	assert.Equal(t, 1, result.MinorVersion)
}

func TestParser_MixedCaseInput(t *testing.T) {
	result, err := ParseString("CVSS:3.1/Av:N/Ac:L/Pr:N/Ui:N/S:U/C:h/I:h/A:h")
	assert.NoError(t, err)
	assert.NotNil(t, result)
}

func TestParser_WhitespaceBetweenMetrics(t *testing.T) {
	result, err := ParseString("CVSS:3.1/ AV:N / AC:L / PR:N / UI:N / S:U / C:H / I:H / A:H")
	assert.NoError(t, err)
	assert.NotNil(t, result)
}

func TestParser_LeadingTrailingWhitespace(t *testing.T) {
	result, err := ParseString("  CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H  ")
	assert.NoError(t, err)
	assert.NotNil(t, result)
}

func TestParser_DuplicateKey(t *testing.T) {
	_, err := ParseString("CVSS:3.1/AV:N/AV:L/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "duplicate")
}

func TestParser_DuplicateKeyTemporal(t *testing.T) {
	_, err := ParseString("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H/E:H/E:F")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "duplicate")
}

func TestParser_LowercaseTemporalAndEnvironmental(t *testing.T) {
	result, err := ParseString("cvss:3.1/av:n/ac:l/pr:n/ui:n/s:u/c:h/i:h/a:h/e:f/rl:w/rc:c/cr:h/ir:h/ar:h")
	assert.NoError(t, err)
	assert.NotNil(t, result)
	assert.NotNil(t, result.Cvss3xTemporal)
	assert.NotNil(t, result.Cvss3xEnvironmental)
}

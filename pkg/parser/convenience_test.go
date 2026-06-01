package parser

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestParseString(t *testing.T) {
	result, err := ParseString("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")
	assert.NoError(t, err)
	assert.NotNil(t, result)
	assert.Equal(t, 3, result.MajorVersion)
	assert.Equal(t, 1, result.MinorVersion)
}

func TestParseString_Invalid(t *testing.T) {
	result, err := ParseString("invalid")
	assert.Error(t, err)
	assert.Nil(t, result)
}

func TestMustParse(t *testing.T) {
	result := MustParse("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")
	assert.NotNil(t, result)
	assert.Equal(t, 3, result.MajorVersion)
}

func TestMustParse_Panic(t *testing.T) {
	assert.Panics(t, func() {
		MustParse("invalid")
	})
}

func TestParseRelaxed_WithoutPrefix(t *testing.T) {
	result, err := ParseRelaxed("AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", "3.1")
	assert.NoError(t, err)
	assert.NotNil(t, result)
	assert.Equal(t, 3, result.MajorVersion)
	assert.Equal(t, 1, result.MinorVersion)
}

func TestParseRelaxed_WithPrefix(t *testing.T) {
	result, err := ParseRelaxed("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", "3.1")
	assert.NoError(t, err)
	assert.NotNil(t, result)
}

func TestParseRelaxed_DefaultVersion(t *testing.T) {
	result, err := ParseRelaxed("AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", "")
	assert.NoError(t, err)
	assert.Equal(t, 1, result.MinorVersion) // default is 3.1
}

func TestParseRelaxed_v30(t *testing.T) {
	result, err := ParseRelaxed("AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", "3.0")
	assert.NoError(t, err)
	assert.Equal(t, 0, result.MinorVersion)
}

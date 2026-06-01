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

package parser

import "testing"

// FuzzParseStringNeverPanics ensures arbitrary input is handled as a parse
// error rather than causing an index-out-of-range or other panic.
func FuzzParseStringNeverPanics(f *testing.F) {
	for _, seed := range []string{
		"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
		"CVSS:3.0/AV:L/AC:H/PR:H/UI:R/S:C/C:L/I:L/A:N",
		"",
		"CVSS:4.0/AV:N",
		"CVSS:3.1/AV:N/AV:N",
	} {
		f.Add(seed)
	}

	f.Fuzz(func(t *testing.T, input string) {
		cv, err := ParseString(input)
		if err != nil {
			return
		}
		if cv == nil {
			t.Fatal("successful parse returned nil vector")
		}
		// Parsed objects must always round-trip through String() without
		// panicking, regardless of metric completeness.
		_ = cv.String()
		again, err := ParseString(cv.String())
		if err != nil {
			t.Fatalf("String() output failed to re-parse: %q -> %v", cv.String(), err)
		}
		if again == nil {
			t.Fatal("re-parse returned nil vector")
		}
	})
}

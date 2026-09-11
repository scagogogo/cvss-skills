package extract

import (
	"strings"
	"testing"
)

const vector31 = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
const vector30 = "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"

func fp(v float64) *float64 { return &v }
func TestExtractPriorityAndFallback(t *testing.T) {
	tests := []struct {
		name                    string
		sources                 map[string]CVSSSource
		wantSource, wantVersion string
		fallback                bool
	}{
		{"nvd priority", map[string]CVSSSource{"nvd": {V3Vector: vector31, V3Score: fp(9.8)}, "ghsa": {V3Vector: vector31, V3Score: fp(8)}}, "nvd", "3.1", false},
		{"ghsa fallback", map[string]CVSSSource{"nvd": {}, "ghsa": {V3Vector: vector30, V3Score: fp(9.8)}}, "ghsa", "3.0", false},
		{"redhat alias", map[string]CVSSSource{"red-hat": {V3Vector: vector31, V3Score: fp(9.8)}}, "redhat", "3.1", false},
		{"v2 fallback", map[string]CVSSSource{"NVD": {V2Vector: "AV:N/AC:L/Au:N/C:P/I:P/A:P", V2Score: fp(7.5)}}, "nvd", "2.0", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := selectScore(Vulnerability{CVSS: tt.sources}, DefaultOptions())
			if got.Source != tt.wantSource || got.Version != tt.wantVersion || got.Fallback != tt.fallback {
				t.Fatalf("got %+v", got)
			}
		})
	}
}
func TestExtractSkipsInvalidHighPriority(t *testing.T) {
	got := selectScore(Vulnerability{CVSS: map[string]CVSSSource{"nvd": {V3Vector: "bad", V3Score: fp(9)}, "ghsa": {V3Vector: vector31, V3Score: fp(9)}}}, DefaultOptions())
	if got.Source != "ghsa" {
		t.Fatalf("got %+v", got)
	}
}
func TestExtractDocumentPreservesContext(t *testing.T) {
	got := ExtractDocument(Document{Results: []ScanResult{{Target: "os", Vulnerabilities: []Vulnerability{{VulnerabilityID: "CVE-1", PkgName: "x", Severity: "HIGH", CVSS: map[string]CVSSSource{"nvd": {V3Vector: vector31, V3Score: fp(9.8)}}}}}}}, DefaultOptions())
	if len(got.Results) != 1 || got.Results[0].Target != "os" || got.Results[0].CVSS.Score == nil {
		t.Fatalf("got %+v", got)
	}
}
func TestExtractInputErrorsAndEmpty(t *testing.T) {
	if _, err := Extract([]byte("{")); err == nil {
		t.Fatal("expected JSON error")
	}
	got, err := Extract([]byte(`{"Results":[]}`))
	if err != nil || len(got.Results) != 0 {
		t.Fatalf("got %v %+v", err, got)
	}
}
func TestExtractScoreTypeAndRange(t *testing.T) {
	var s CVSSSource
	if err := s.UnmarshalJSON([]byte(`{"V3Score":"9.8"}`)); err != nil || s.V3Score == nil {
		t.Fatalf("string score: %v", err)
	}
	if err := s.UnmarshalJSON([]byte(`{"V3Score":11}`)); err == nil {
		t.Fatal("expected range error")
	}
}
func TestExtractCustomPriority(t *testing.T) {
	got := selectScore(Vulnerability{CVSS: map[string]CVSSSource{"ghsa": {V3Vector: vector31, V3Score: fp(9)}, "nvd": {V3Vector: vector31, V3Score: fp(9.8)}}}, Options{SourcePriority: []string{"ghsa", "nvd"}})
	if got.Source != "ghsa" {
		t.Fatal(got.Source)
	}
}
func TestVectorVersionDefaultsOnlyKnownVersions(t *testing.T) {
	if vectorVersion(vector31) != "3.1" || vectorVersion(vector30) != "3.0" || !strings.HasPrefix(vector31, "CVSS:") {
		t.Fatal("unexpected version")
	}
}

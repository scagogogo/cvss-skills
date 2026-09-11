// Package extract selects CVSS scores from vulnerability scanner reports.
package extract

import (
	"encoding/json"
	"fmt"
	"io"
	"math"
	"strings"

	"github.com/scagogogo/cvss-skills/pkg/cvss"
	"github.com/scagogogo/cvss-skills/pkg/parser"
)

type Document struct {
	Results []ScanResult `json:"Results"`
}
type ScanResult struct {
	Target          string          `json:"Target,omitempty"`
	Vulnerabilities []Vulnerability `json:"Vulnerabilities"`
}
type Vulnerability struct {
	VulnerabilityID  string                `json:"VulnerabilityID,omitempty"`
	PkgName          string                `json:"PkgName,omitempty"`
	InstalledVersion string                `json:"InstalledVersion,omitempty"`
	FixedVersion     string                `json:"FixedVersion,omitempty"`
	Severity         string                `json:"Severity,omitempty"`
	Title            string                `json:"Title,omitempty"`
	CVSS             map[string]CVSSSource `json:"CVSS"`
}
type CVSSSource struct {
	V2Vector string   `json:"V2Vector,omitempty"`
	V2Score  *float64 `json:"V2Score,omitempty"`
	V3Vector string   `json:"V3Vector,omitempty"`
	V3Score  *float64 `json:"V3Score,omitempty"`
}

// UnmarshalJSON keeps one malformed source from discarding the whole report.
func (v *Vulnerability) UnmarshalJSON(data []byte) error {
	type plain Vulnerability
	var raw struct {
		VulnerabilityID  string                     `json:"VulnerabilityID"`
		PkgName          string                     `json:"PkgName"`
		InstalledVersion string                     `json:"InstalledVersion"`
		FixedVersion     string                     `json:"FixedVersion"`
		Severity         string                     `json:"Severity"`
		Title            string                     `json:"Title"`
		CVSS             map[string]json.RawMessage `json:"CVSS"`
	}
	if err := json.Unmarshal(data, &raw); err != nil {
		return err
	}
	*v = Vulnerability{VulnerabilityID: raw.VulnerabilityID, PkgName: raw.PkgName, InstalledVersion: raw.InstalledVersion, FixedVersion: raw.FixedVersion, Severity: raw.Severity, Title: raw.Title, CVSS: make(map[string]CVSSSource)}
	for name, candidate := range raw.CVSS {
		var source CVSSSource
		if err := json.Unmarshal(candidate, &source); err == nil {
			v.CVSS[name] = source
		}
	}
	return nil
}

// UnmarshalJSON accepts numeric scores and numeric strings used by scanner exports.
func (s *CVSSSource) UnmarshalJSON(data []byte) error {
	var raw struct {
		V2Vector string          `json:"V2Vector"`
		V2Score  json.RawMessage `json:"V2Score"`
		V3Vector string          `json:"V3Vector"`
		V3Score  json.RawMessage `json:"V3Score"`
	}
	if err := json.Unmarshal(data, &raw); err != nil {
		return err
	}
	var err error
	s.V2Vector, s.V3Vector = raw.V2Vector, raw.V3Vector
	if len(raw.V2Score) != 0 && string(raw.V2Score) != "null" {
		s.V2Score, err = parseScore(raw.V2Score)
		if err != nil {
			return fmt.Errorf("V2Score: %w", err)
		}
	}
	if len(raw.V3Score) != 0 && string(raw.V3Score) != "null" {
		s.V3Score, err = parseScore(raw.V3Score)
		if err != nil {
			return fmt.Errorf("V3Score: %w", err)
		}
	}
	return nil
}
func parseScore(raw []byte) (*float64, error) {
	var n float64
	if err := json.Unmarshal(raw, &n); err == nil {
		return validScore(n)
	}
	var text string
	if err := json.Unmarshal(raw, &text); err != nil {
		return nil, fmt.Errorf("must be a number")
	}
	if _, err := fmt.Sscan(strings.TrimSpace(text), &n); err != nil {
		return nil, fmt.Errorf("must be a number")
	}
	return validScore(n)
}
func validScore(n float64) (*float64, error) {
	if math.IsNaN(n) || math.IsInf(n, 0) || n < 0 || n > 10 {
		return nil, fmt.Errorf("score %.2f outside 0.0-10.0", n)
	}
	return &n, nil
}

type Options struct{ SourcePriority []string }

func DefaultOptions() Options { return Options{SourcePriority: []string{"nvd", "ghsa", "redhat"}} }

type Score struct {
	Score         *float64 `json:"score,omitempty"`
	ReportedScore *float64 `json:"reportedScore,omitempty"`
	Version       string   `json:"version,omitempty"`
	Source        string   `json:"source,omitempty"`
	Vector        string   `json:"vector,omitempty"`
	Severity      string   `json:"cvssSeverity,omitempty"`
	Status        string   `json:"status"`
	Fallback      bool     `json:"fallback,omitempty"`
	Error         string   `json:"error,omitempty"`
}
type Result struct {
	Target           string `json:"target,omitempty"`
	VulnerabilityID  string `json:"vulnerabilityID,omitempty"`
	Package          string `json:"package,omitempty"`
	InstalledVersion string `json:"installedVersion,omitempty"`
	FixedVersion     string `json:"fixedVersion,omitempty"`
	ScannerSeverity  string `json:"scannerSeverity,omitempty"`
	Title            string `json:"title,omitempty"`
	CVSS             Score  `json:"cvss"`
}
type Extraction struct {
	Results []Result `json:"results"`
}

func Extract(data []byte) (*Extraction, error) { return ExtractWithOptions(data, DefaultOptions()) }
func ExtractWithOptions(data []byte, opts Options) (*Extraction, error) {
	var d Document
	if err := json.Unmarshal(data, &d); err != nil {
		return nil, err
	}
	return ExtractDocument(d, opts), nil
}
func ExtractReader(r io.Reader) (*Extraction, error) {
	return ExtractReaderWithOptions(r, DefaultOptions())
}
func ExtractReaderWithOptions(r io.Reader, opts Options) (*Extraction, error) {
	var d Document
	if err := json.NewDecoder(r).Decode(&d); err != nil {
		return nil, err
	}
	return ExtractDocument(d, opts), nil
}
func ExtractDocument(d Document, opts Options) *Extraction {
	if len(opts.SourcePriority) == 0 {
		opts = DefaultOptions()
	}
	out := &Extraction{}
	for _, scan := range d.Results {
		for _, v := range scan.Vulnerabilities {
			out.Results = append(out.Results, Result{Target: scan.Target, VulnerabilityID: v.VulnerabilityID, Package: v.PkgName, InstalledVersion: v.InstalledVersion, FixedVersion: v.FixedVersion, ScannerSeverity: v.Severity, Title: v.Title, CVSS: selectScore(v, opts)})
		}
	}
	return out
}
func normalize(s string) string {
	s = strings.ToLower(strings.TrimSpace(s))
	s = strings.ReplaceAll(s, "-", "")
	s = strings.ReplaceAll(s, "_", "")
	return s
}
func findSource(m map[string]CVSSSource, name string) (CVSSSource, bool) {
	want := normalize(name)
	for k, v := range m {
		if normalize(k) == want {
			return v, true
		}
	}
	return CVSSSource{}, false
}
func selectScore(v Vulnerability, opts Options) Score {
	for _, name := range opts.SourcePriority {
		src, ok := findSource(v.CVSS, name)
		if !ok || src.V3Score == nil || strings.TrimSpace(src.V3Vector) == "" {
			continue
		}
		cv, err := parser.ParseString(src.V3Vector)
		if err != nil {
			continue
		}
		calculated, err := cvss.NewCalculator(cv).Calculate()
		if err != nil {
			continue
		}
		sev := cvss.GetSeverity(calculated).String()
		return Score{Score: &calculated, ReportedScore: src.V3Score, Version: vectorVersion(src.V3Vector), Source: normalize(name), Vector: src.V3Vector, Severity: sev, Status: "selected"}
	}
	if src, ok := findSource(v.CVSS, "nvd"); ok && src.V2Score != nil {
		return Score{Score: src.V2Score, ReportedScore: src.V2Score, Version: "2.0", Source: "nvd", Vector: src.V2Vector, Status: "selected", Fallback: true}
	}
	return Score{Status: "na"}
}
func vectorVersion(v string) string {
	if strings.HasPrefix(v, "CVSS:3.0/") {
		return "3.0"
	}
	return "3.1"
}

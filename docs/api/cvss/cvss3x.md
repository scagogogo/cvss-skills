# Cvss3x Data Structure

The `Cvss3x` struct is the core data structure in CVSS Skills, representing a complete CVSS 3.x vector with all its metrics and metadata.

## Type Definition

```go
type Cvss3x struct {
    MajorVersion         int                   `json:"majorVersion"`
    MinorVersion         int                   `json:"minorVersion"`
    Cvss3xBase          *Cvss3xBase           `json:"base"`
    Cvss3xTemporal      *Cvss3xTemporal       `json:"temporal,omitempty"`
    Cvss3xEnvironmental *Cvss3xEnvironmental  `json:"environmental,omitempty"`
}
```

## Core Components

### Version Information

```go
type Cvss3x struct {
    MajorVersion int `json:"majorVersion"` // CVSS major version (3)
    MinorVersion int `json:"minorVersion"` // CVSS minor version (0 or 1)
    // ...
}
```

**Supported Versions:**
- CVSS 3.0: `MajorVersion: 3, MinorVersion: 0`
- CVSS 3.1: `MajorVersion: 3, MinorVersion: 1`

### Base Metrics

```go
type Cvss3xBase struct {
    AttackVector          vector.Vector `json:"attackVector"`
    AttackComplexity      vector.Vector `json:"attackComplexity"`
    PrivilegesRequired    vector.Vector `json:"privilegesRequired"`
    UserInteraction       vector.Vector `json:"userInteraction"`
    Scope                 vector.Vector `json:"scope"`
    ConfidentialityImpact vector.Vector `json:"confidentialityImpact"`
    IntegrityImpact       vector.Vector `json:"integrityImpact"`
    AvailabilityImpact    vector.Vector `json:"availabilityImpact"`
}
```

**Required Metrics:**
- **Attack Vector (AV)**: Network, Adjacent, Local, Physical
- **Attack Complexity (AC)**: Low, High
- **Privileges Required (PR)**: None, Low, High
- **User Interaction (UI)**: None, Required
- **Scope (S)**: Unchanged, Changed
- **Confidentiality Impact (C)**: None, Low, High
- **Integrity Impact (I)**: None, Low, High
- **Availability Impact (A)**: None, Low, High

### Temporal Metrics

```go
type Cvss3xTemporal struct {
    ExploitCodeMaturity vector.Vector `json:"exploitCodeMaturity,omitempty"`
    RemediationLevel    vector.Vector `json:"remediationLevel,omitempty"`
    ReportConfidence    vector.Vector `json:"reportConfidence,omitempty"`
}
```

**Optional Metrics:**
- **Exploit Code Maturity (E)**: Not Defined, Unproven, Proof-of-Concept, Functional, High
- **Remediation Level (RL)**: Not Defined, Official Fix, Temporary Fix, Workaround, Unavailable
- **Report Confidence (RC)**: Not Defined, Unknown, Reasonable, Confirmed

### Environmental Metrics

```go
type Cvss3xEnvironmental struct {
    // Environmental Requirements
    ConfidentialityRequirement vector.Vector `json:"confidentialityRequirement,omitempty"`
    IntegrityRequirement       vector.Vector `json:"integrityRequirement,omitempty"`
    AvailabilityRequirement    vector.Vector `json:"availabilityRequirement,omitempty"`
    
    // Modified Base Metrics
    ModifiedAttackVector          vector.Vector `json:"modifiedAttackVector,omitempty"`
    ModifiedAttackComplexity      vector.Vector `json:"modifiedAttackComplexity,omitempty"`
    ModifiedPrivilegesRequired    vector.Vector `json:"modifiedPrivilegesRequired,omitempty"`
    ModifiedUserInteraction       vector.Vector `json:"modifiedUserInteraction,omitempty"`
    ModifiedScope                 vector.Vector `json:"modifiedScope,omitempty"`
    ModifiedConfidentialityImpact vector.Vector `json:"modifiedConfidentialityImpact,omitempty"`
    ModifiedIntegrityImpact       vector.Vector `json:"modifiedIntegrityImpact,omitempty"`
    ModifiedAvailabilityImpact    vector.Vector `json:"modifiedAvailabilityImpact,omitempty"`
}
```

## Constructor Functions

### NewCvss3x

```go
func NewCvss3x(majorVersion, minorVersion int) *Cvss3x
```

Creates a new CVSS 3.x instance with specified version.

**Parameters:**
- `majorVersion`: Major version number (3)
- `minorVersion`: Minor version number (0 or 1)

**Returns:**
- `*Cvss3x`: New CVSS 3.x instance

**Example:**
```go
cvss := cvss.NewCvss3x(3, 1) // CVSS 3.1
```

### NewCvss3xBase

```go
func NewCvss3xBase() *Cvss3xBase
```

Creates a new base metrics group.

**Example:**
```go
base := cvss.NewCvss3xBase()
base.AttackVector = &vector.AttackVectorNetwork{}
base.AttackComplexity = &vector.AttackComplexityLow{}
// ... set other metrics
```

## Main Methods

### String

```go
func (c *Cvss3x) String() string
```

Returns the CVSS vector string representation.

**Returns:**
- `string`: CVSS vector string

**Example:**
```go
cvss := cvss.NewCvss3x(3, 1)
// ... set metrics
vectorStr := cvss.String()
fmt.Println(vectorStr) // "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
```

### IsValid

```go
func (c *Cvss3x) IsValid() bool
```

Checks if the CVSS vector is valid (all required metrics are set).

**Returns:**
- `bool`: True if valid, false otherwise

**Example:**
```go
if cvss.IsValid() {
    fmt.Println("CVSS vector is valid")
} else {
    fmt.Println("CVSS vector is incomplete")
}
```

### GetVersion

```go
func (c *Cvss3x) GetVersion() string
```

Returns the version string.

**Returns:**
- `string`: Version string (e.g., "3.1")

**Example:**
```go
version := cvss.GetVersion()
fmt.Printf("CVSS Version: %s\n", version) // "3.1"
```

### HasTemporal

```go
func (c *Cvss3x) HasTemporal() bool
```

Checks if temporal metrics are present.

**Returns:**
- `bool`: True if temporal metrics exist

**Example:**
```go
if cvss.HasTemporal() {
    fmt.Println("Vector includes temporal metrics")
}
```

### HasEnvironmental

```go
func (c *Cvss3x) HasEnvironmental() bool
```

Checks if environmental metrics are present.

**Returns:**
- `bool`: True if environmental metrics exist

**Example:**
```go
if cvss.HasEnvironmental() {
    fmt.Println("Vector includes environmental metrics")
}
```

## Usage Examples

### Creating Complete Vector

```go
package main

import (
    "fmt"
    
    "github.com/scagogogo/cvss-skills/pkg/cvss"
    "github.com/scagogogo/cvss-skills/pkg/vector"
)

func main() {
    // Create CVSS 3.1 vector
    cvss := cvss.NewCvss3x(3, 1)
    
    // Set base metrics
    cvss.Cvss3xBase = cvss.NewCvss3xBase()
    cvss.Cvss3xBase.AttackVector = &vector.AttackVectorNetwork{}
    cvss.Cvss3xBase.AttackComplexity = &vector.AttackComplexityLow{}
    cvss.Cvss3xBase.PrivilegesRequired = &vector.PrivilegesRequiredNone{}
    cvss.Cvss3xBase.UserInteraction = &vector.UserInteractionNone{}
    cvss.Cvss3xBase.Scope = &vector.ScopeUnchanged{}
    cvss.Cvss3xBase.ConfidentialityImpact = &vector.ConfidentialityHigh{}
    cvss.Cvss3xBase.IntegrityImpact = &vector.IntegrityHigh{}
    cvss.Cvss3xBase.AvailabilityImpact = &vector.AvailabilityHigh{}
    
    // Add temporal metrics (optional)
    cvss.Cvss3xTemporal = &cvss.Cvss3xTemporal{
        ExploitCodeMaturity: &vector.ExploitCodeMaturityFunctional{},
        RemediationLevel:    &vector.RemediationLevelOfficialFix{},
        ReportConfidence:    &vector.ReportConfidenceConfirmed{},
    }
    
    // Output vector
    fmt.Printf("CVSS Vector: %s\n", cvss.String())
    fmt.Printf("Version: %s\n", cvss.GetVersion())
    fmt.Printf("Valid: %t\n", cvss.IsValid())
    fmt.Printf("Has Temporal: %t\n", cvss.HasTemporal())
}
```

### Vector Validation

```go
func validateCvssVector(cvss *cvss.Cvss3x) error {
    if cvss == nil {
        return fmt.Errorf("CVSS vector is nil")
    }
    
    if cvss.MajorVersion != 3 {
        return fmt.Errorf("unsupported major version: %d", cvss.MajorVersion)
    }
    
    if cvss.MinorVersion != 0 && cvss.MinorVersion != 1 {
        return fmt.Errorf("unsupported minor version: %d", cvss.MinorVersion)
    }
    
    if cvss.Cvss3xBase == nil {
        return fmt.Errorf("base metrics are required")
    }
    
    // Validate required base metrics
    if cvss.Cvss3xBase.AttackVector == nil {
        return fmt.Errorf("attack vector is required")
    }
    
    if cvss.Cvss3xBase.AttackComplexity == nil {
        return fmt.Errorf("attack complexity is required")
    }
    
    // ... validate other required metrics
    
    return nil
}
```

### Vector Comparison

```go
func compareVectors(v1, v2 *cvss.Cvss3x) {
    fmt.Printf("Comparing vectors:\n")
    fmt.Printf("  Vector 1: %s\n", v1.String())
    fmt.Printf("  Vector 2: %s\n", v2.String())
    
    // Compare versions
    if v1.GetVersion() != v2.GetVersion() {
        fmt.Printf("  Different versions: %s vs %s\n", v1.GetVersion(), v2.GetVersion())
    }
    
    // Compare base metrics
    if v1.Cvss3xBase.AttackVector.GetShortValue() != v2.Cvss3xBase.AttackVector.GetShortValue() {
        fmt.Printf("  Different attack vectors: %c vs %c\n", 
            v1.Cvss3xBase.AttackVector.GetShortValue(),
            v2.Cvss3xBase.AttackVector.GetShortValue())
    }
    
    // ... compare other metrics
}
```

### Vector Modification

```go
func modifyVector(cvss *cvss.Cvss3x) *cvss.Cvss3x {
    // Create a copy
    modified := *cvss
    
    // Modify attack vector
    modified.Cvss3xBase.AttackVector = &vector.AttackVectorLocal{}
    
    // Add temporal metrics if not present
    if modified.Cvss3xTemporal == nil {
        modified.Cvss3xTemporal = &cvss.Cvss3xTemporal{
            ExploitCodeMaturity: &vector.ExploitCodeMaturityProofOfConcept{},
            RemediationLevel:    &vector.RemediationLevelWorkaround{},
            ReportConfidence:    &vector.ReportConfidenceReasonable{},
        }
    }
    
    return &modified
}
```

## JSON Serialization

### Marshal to JSON

```go
import "encoding/json"

func vectorToJSON(cvss *cvss.Cvss3x) ([]byte, error) {
    return json.MarshalIndent(cvss, "", "  ")
}

// Usage
jsonData, err := vectorToJSON(cvss)
if err != nil {
    log.Fatal(err)
}
fmt.Println(string(jsonData))
```

### Unmarshal from JSON

```go
func vectorFromJSON(jsonData []byte) (*cvss.Cvss3x, error) {
    var cvss cvss.Cvss3x
    err := json.Unmarshal(jsonData, &cvss)
    return &cvss, err
}

// Usage
cvss, err := vectorFromJSON(jsonData)
if err != nil {
    log.Fatal(err)
}
```

## Best Practices

### 1. Immutability

```go
// Create immutable vectors
func createImmutableVector() *cvss.Cvss3x {
    cvss := cvss.NewCvss3x(3, 1)
    
    // Set all metrics at once
    cvss.Cvss3xBase = &cvss.Cvss3xBase{
        AttackVector:          &vector.AttackVectorNetwork{},
        AttackComplexity:      &vector.AttackComplexityLow{},
        PrivilegesRequired:    &vector.PrivilegesRequiredNone{},
        UserInteraction:       &vector.UserInteractionNone{},
        Scope:                 &vector.ScopeUnchanged{},
        ConfidentialityImpact: &vector.ConfidentialityHigh{},
        IntegrityImpact:       &vector.IntegrityHigh{},
        AvailabilityImpact:    &vector.AvailabilityHigh{},
    }
    
    return cvss
}
```

### 2. Validation

```go
func createValidatedVector() (*cvss.Cvss3x, error) {
    cvss := createImmutableVector()
    
    if err := validateCvssVector(cvss); err != nil {
        return nil, fmt.Errorf("vector validation failed: %w", err)
    }
    
    return cvss, nil
}
```

### 3. Builder Pattern

```go
type Cvss3xBuilder struct {
    cvss *cvss.Cvss3x
}

func NewCvss3xBuilder() *Cvss3xBuilder {
    return &Cvss3xBuilder{
        cvss: cvss.NewCvss3x(3, 1),
    }
}

func (b *Cvss3xBuilder) AttackVector(av vector.Vector) *Cvss3xBuilder {
    if b.cvss.Cvss3xBase == nil {
        b.cvss.Cvss3xBase = cvss.NewCvss3xBase()
    }
    b.cvss.Cvss3xBase.AttackVector = av
    return b
}

func (b *Cvss3xBuilder) Build() (*cvss.Cvss3x, error) {
    if err := validateCvssVector(b.cvss); err != nil {
        return nil, err
    }
    return b.cvss, nil
}

// Usage
cvss, err := NewCvss3xBuilder().
    AttackVector(&vector.AttackVectorNetwork{}).
    // ... set other metrics
    Build()
```

## Related Documentation

- [Calculator](/api/cvss/calculator) - Score calculation
- [DistanceCalculator](/api/cvss/distance) - Vector comparison
- [JSON Support](/api/cvss/json) - Serialization
- [Parser](/api/parser/cvss3x-parser) - String parsing

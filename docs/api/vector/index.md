# vector Package

The `vector` package provides unified interfaces and concrete implementations for all CVSS metrics. It defines the behavior and properties of all CVSS 3.x metrics, providing the foundational data structures for parsers and calculators.

## Package Overview

```go
import "github.com/scagogogo/cvss-parser/pkg/vector"
```

## Core Interface

### Vector Interface

All CVSS metrics implement the `Vector` interface:

```go
type Vector interface {
    GetGroupName() string    // Get metric group name
    GetShortName() string    // Get metric short name
    GetLongName() string     // Get metric full name
    GetShortValue() rune     // Get metric short value
    GetLongValue() string    // Get metric full value
    GetDescription() string  // Get metric description
    GetScore() float64       // Get metric score
    String() string          // String representation
}
```

Detailed documentation: [Vector Interface](/api/vector/interface)

## Metric Categories

### Base Metrics

Base metrics describe the intrinsic characteristics of a vulnerability that do not change over time or environment.

#### Exploitability Metrics

| Metric | Short | Implementation Types | Possible Values |
|--------|-------|---------------------|-----------------|
| Attack Vector | AV | `AttackVector*` | Network, Adjacent, Local, Physical |
| Attack Complexity | AC | `AttackComplexity*` | Low, High |
| Privileges Required | PR | `PrivilegesRequired*` | None, Low, High |
| User Interaction | UI | `UserInteraction*` | None, Required |

#### Impact Metrics

| Metric | Short | Implementation Types | Possible Values |
|--------|-------|---------------------|-----------------|
| Scope | S | `Scope*` | Unchanged, Changed |
| Confidentiality Impact | C | `Confidentiality*` | None, Low, High |
| Integrity Impact | I | `Integrity*` | None, Low, High |
| Availability Impact | A | `Availability*` | None, Low, High |

### Temporal Metrics

Temporal metrics reflect the characteristics of a vulnerability that change over time.

| Metric | Short | Implementation Types | Possible Values |
|--------|-------|---------------------|-----------------|
| Exploit Code Maturity | E | `ExploitCodeMaturity*` | Not Defined, Unproven, Proof-of-Concept, Functional, High |
| Remediation Level | RL | `RemediationLevel*` | Not Defined, Official Fix, Temporary Fix, Workaround, Unavailable |
| Report Confidence | RC | `ReportConfidence*` | Not Defined, Unknown, Reasonable, Confirmed |

### Environmental Metrics

Environmental metrics allow analysts to customize CVSS scores according to specific environments.

#### Environmental Requirement Metrics

| Metric | Short | Implementation Types | Possible Values |
|--------|-------|---------------------|-----------------|
| Confidentiality Requirement | CR | `ConfidentialityRequirement*` | Not Defined, Low, Medium, High |
| Integrity Requirement | IR | `IntegrityRequirement*` | Not Defined, Low, Medium, High |
| Availability Requirement | AR | `AvailabilityRequirement*` | Not Defined, Low, Medium, High |

#### Modified Base Metrics

All base metrics have corresponding modified versions, prefixed with `Modified`:

- `ModifiedAttackVector*`
- `ModifiedAttackComplexity*`
- `ModifiedPrivilegesRequired*`
- etc...

## Usage Examples

### Creating Metric Instances

```go
// Create attack vector metric
attackVector := &vector.AttackVectorNetwork{}
fmt.Printf("Attack Vector: %s (%s)\n", 
    attackVector.GetLongValue(), 
    attackVector.GetDescription())

// Create attack complexity metric
attackComplexity := &vector.AttackComplexityLow{}
fmt.Printf("Attack Complexity: %s (Score: %.2f)\n", 
    attackComplexity.GetLongValue(), 
    attackComplexity.GetScore())
```

### Using Interface

```go
func printVectorInfo(v vector.Vector) {
    fmt.Printf("Metric: %s (%s)\n", v.GetLongName(), v.GetShortName())
    fmt.Printf("  Group: %s\n", v.GetGroupName())
    fmt.Printf("  Value: %s (%c)\n", v.GetLongValue(), v.GetShortValue())
    fmt.Printf("  Score: %.2f\n", v.GetScore())
    fmt.Printf("  String: %s\n", v.String())
}

// Usage example
av := &vector.AttackVectorNetwork{}
printVectorInfo(av)
```

### Vector Factory

```go
type VectorFactory struct{}

func (f *VectorFactory) CreateAttackVector(value rune) (vector.Vector, error) {
    switch value {
    case 'N':
        return &vector.AttackVectorNetwork{}, nil
    case 'A':
        return &vector.AttackVectorAdjacent{}, nil
    case 'L':
        return &vector.AttackVectorLocal{}, nil
    case 'P':
        return &vector.AttackVectorPhysical{}, nil
    default:
        return nil, fmt.Errorf("unknown attack vector value: %c", value)
    }
}
```

## Metric Details

### Attack Vector

Describes how an attacker accesses the vulnerable component.

```go
// Network attack vector
type AttackVectorNetwork struct{}
func (a *AttackVectorNetwork) GetShortValue() rune { return 'N' }
func (a *AttackVectorNetwork) GetScore() float64 { return 0.85 }

// Adjacent network attack vector
type AttackVectorAdjacent struct{}
func (a *AttackVectorAdjacent) GetShortValue() rune { return 'A' }
func (a *AttackVectorAdjacent) GetScore() float64 { return 0.62 }

// Local attack vector
type AttackVectorLocal struct{}
func (a *AttackVectorLocal) GetShortValue() rune { return 'L' }
func (a *AttackVectorLocal) GetScore() float64 { return 0.55 }

// Physical attack vector
type AttackVectorPhysical struct{}
func (a *AttackVectorPhysical) GetShortValue() rune { return 'P' }
func (a *AttackVectorPhysical) GetScore() float64 { return 0.2 }
```

### Attack Complexity

Describes the conditions required for a successful attack.

```go
// Low complexity
type AttackComplexityLow struct{}
func (a *AttackComplexityLow) GetShortValue() rune { return 'L' }
func (a *AttackComplexityLow) GetScore() float64 { return 0.77 }

// High complexity
type AttackComplexityHigh struct{}
func (a *AttackComplexityHigh) GetShortValue() rune { return 'H' }
func (a *AttackComplexityHigh) GetScore() float64 { return 0.44 }
```

### Impact Metrics

Impact metrics describe the degree of impact a successful attack has on the system.

```go
// Confidentiality impact
type ConfidentialityHigh struct{}
func (c *ConfidentialityHigh) GetShortValue() rune { return 'H' }
func (c *ConfidentialityHigh) GetScore() float64 { return 0.56 }

type ConfidentialityLow struct{}
func (c *ConfidentialityLow) GetShortValue() rune { return 'L' }
func (c *ConfidentialityLow) GetScore() float64 { return 0.22 }

type ConfidentialityNone struct{}
func (c *ConfidentialityNone) GetShortValue() rune { return 'N' }
func (c *ConfidentialityNone) GetScore() float64 { return 0.0 }
```

## Vector Validation

### Basic Validation

```go
func validateVector(v vector.Vector) error {
    if v.GetShortName() == "" {
        return fmt.Errorf("metric short name cannot be empty")
    }
    
    if v.GetShortValue() == 0 {
        return fmt.Errorf("metric value cannot be empty")
    }
    
    score := v.GetScore()
    if score < 0 || score > 1 {
        return fmt.Errorf("metric score must be between 0-1, current value: %.2f", score)
    }
    
    return nil
}
```

### Batch Validation

```go
func validateVectors(vectors []vector.Vector) []error {
    var errors []error
    
    for i, v := range vectors {
        if err := validateVector(v); err != nil {
            errors = append(errors, fmt.Errorf("vector %d validation failed: %w", i, err))
        }
    }
    
    return errors
}
```

## Vector Comparison

### Basic Comparison

```go
func compareVectors(v1, v2 vector.Vector) {
    fmt.Printf("Comparing %s and %s:\n", v1.String(), v2.String())
    
    if v1.GetShortName() != v2.GetShortName() {
        fmt.Println("  Different metric types, cannot compare")
        return
    }
    
    score1 := v1.GetScore()
    score2 := v2.GetScore()
    
    if score1 > score2 {
        fmt.Printf("  %s (%.2f) > %s (%.2f)\n", 
            v1.GetDescription(), score1, v2.GetDescription(), score2)
    } else if score1 < score2 {
        fmt.Printf("  %s (%.2f) < %s (%.2f)\n", 
            v1.GetDescription(), score1, v2.GetDescription(), score2)
    } else {
        fmt.Printf("  %s = %s (%.2f)\n", 
            v1.GetDescription(), v2.GetDescription(), score1)
    }
}
```

### Vector Grouping

```go
func groupVectorsByType(vectors []vector.Vector) map[string][]vector.Vector {
    groups := make(map[string][]vector.Vector)
    
    for _, v := range vectors {
        groupName := v.GetGroupName()
        groups[groupName] = append(groups[groupName], v)
    }
    
    return groups
}
```

## Extension and Customization

### Custom Vector

```go
// Custom vector implementation
type CustomVector struct {
    groupName   string
    shortName   string
    longName    string
    shortValue  rune
    longValue   string
    description string
    score       float64
}

func (c *CustomVector) GetGroupName() string { return c.groupName }
func (c *CustomVector) GetShortName() string { return c.shortName }
func (c *CustomVector) GetLongName() string { return c.longName }
func (c *CustomVector) GetShortValue() rune { return c.shortValue }
func (c *CustomVector) GetLongValue() string { return c.longValue }
func (c *CustomVector) GetDescription() string { return c.description }
func (c *CustomVector) GetScore() float64 { return c.score }
func (c *CustomVector) String() string {
    return fmt.Sprintf("%s:%c", c.shortName, c.shortValue)
}
```

### Vector Registry

```go
type VectorRegistry struct {
    vectors map[string]map[rune]vector.Vector
}

func NewVectorRegistry() *VectorRegistry {
    return &VectorRegistry{
        vectors: make(map[string]map[rune]vector.Vector),
    }
}

func (r *VectorRegistry) Register(shortName string, value rune, v vector.Vector) {
    if r.vectors[shortName] == nil {
        r.vectors[shortName] = make(map[rune]vector.Vector)
    }
    r.vectors[shortName][value] = v
}

func (r *VectorRegistry) Get(shortName string, value rune) (vector.Vector, bool) {
    if group, exists := r.vectors[shortName]; exists {
        if v, found := group[value]; found {
            return v, true
        }
    }
    return nil, false
}
```

## Performance Optimization

### Vector Caching

```go
var vectorCache = make(map[string]vector.Vector)
var cacheMutex sync.RWMutex

func getCachedVector(key string) (vector.Vector, bool) {
    cacheMutex.RLock()
    defer cacheMutex.RUnlock()
    
    v, exists := vectorCache[key]
    return v, exists
}

func setCachedVector(key string, v vector.Vector) {
    cacheMutex.Lock()
    defer cacheMutex.Unlock()
    
    vectorCache[key] = v
}
```

### Object Pool

```go
var vectorPool = sync.Pool{
    New: func() interface{} {
        return &vector.AttackVectorNetwork{}
    },
}

func getVectorFromPool() vector.Vector {
    return vectorPool.Get().(vector.Vector)
}

func putVectorToPool(v vector.Vector) {
    vectorPool.Put(v)
}
```

## Best Practices

### 1. Type Safety

```go
func getAttackVectorScore(v vector.Vector) (float64, error) {
    if v.GetShortName() != "AV" {
        return 0, fmt.Errorf("not an attack vector metric")
    }
    return v.GetScore(), nil
}
```

### 2. Null Value Handling

```go
func safeGetScore(v vector.Vector) float64 {
    if v == nil {
        return 0.0
    }
    return v.GetScore()
}
```

### 3. Interface Composition

```go
type CVSSVector interface {
    vector.Vector
    IsRequired() bool
    GetCategory() string
}
```

## Related Documentation

- [Vector Interface Details](/api/vector/interface)
- [Cvss3x Data Structure](/api/cvss/cvss3x)
- [Parser](/api/parser/cvss3x-parser)
- [Usage Examples](/examples/basic)

# Vector Interface

The `Vector` interface is the unified abstraction for all metrics in CVSS Skills, defining the basic behavior and properties of metrics.

## Interface Definition

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

## Method Details

### GetGroupName

```go
GetGroupName() string
```

Returns the group name that the metric belongs to.

**Returns:**
- `string`: Metric group name

**Possible Values:**
- `"Base"` - Base metrics group
- `"Temporal"` - Temporal metrics group
- `"Environmental"` - Environmental metrics group

**Example:**
```go
av := &vector.AttackVectorNetwork{}
groupName := av.GetGroupName()
fmt.Printf("Group: %s\n", groupName) // "Base"
```

### GetShortName

```go
GetShortName() string
```

Returns the short name (abbreviation) of the metric.

**Returns:**
- `string`: Metric short name

**Example:**
```go
av := &vector.AttackVectorNetwork{}
shortName := av.GetShortName()
fmt.Printf("Short name: %s\n", shortName) // "AV"
```

### GetLongName

```go
GetLongName() string
```

Returns the full name of the metric.

**Returns:**
- `string`: Metric full name

**Example:**
```go
av := &vector.AttackVectorNetwork{}
longName := av.GetLongName()
fmt.Printf("Long name: %s\n", longName) // "Attack Vector"
```

### GetShortValue

```go
GetShortValue() rune
```

Returns the short value (single character) of the metric.

**Returns:**
- `rune`: Metric short value

**Example:**
```go
av := &vector.AttackVectorNetwork{}
shortValue := av.GetShortValue()
fmt.Printf("Short value: %c\n", shortValue) // 'N'
```

### GetLongValue

```go
GetLongValue() string
```

Returns the full value description of the metric.

**Returns:**
- `string`: Metric full value

**Example:**
```go
av := &vector.AttackVectorNetwork{}
longValue := av.GetLongValue()
fmt.Printf("Long value: %s\n", longValue) // "Network"
```

### GetDescription

```go
GetDescription() string
```

Returns a detailed description of the metric.

**Returns:**
- `string`: Metric description

**Example:**
```go
av := &vector.AttackVectorNetwork{}
description := av.GetDescription()
fmt.Printf("Description: %s\n", description)
// "The vulnerable component is bound to the network stack..."
```

### GetScore

```go
GetScore() float64
```

Returns the numerical score value of the metric used in CVSS calculations.

**Returns:**
- `float64`: Metric score (typically between 0.0 and 1.0)

**Example:**
```go
av := &vector.AttackVectorNetwork{}
score := av.GetScore()
fmt.Printf("Score: %.2f\n", score) // 0.85
```

### String

```go
String() string
```

Returns the string representation of the metric in CVSS vector format.

**Returns:**
- `string`: String representation

**Example:**
```go
av := &vector.AttackVectorNetwork{}
str := av.String()
fmt.Printf("String: %s\n", str) // "AV:N"
```

## Implementation Examples

### Base Metric Implementation

```go
// Attack Vector Network implementation
type AttackVectorNetwork struct{}

func (a *AttackVectorNetwork) GetGroupName() string {
    return "Base"
}

func (a *AttackVectorNetwork) GetShortName() string {
    return "AV"
}

func (a *AttackVectorNetwork) GetLongName() string {
    return "Attack Vector"
}

func (a *AttackVectorNetwork) GetShortValue() rune {
    return 'N'
}

func (a *AttackVectorNetwork) GetLongValue() string {
    return "Network"
}

func (a *AttackVectorNetwork) GetDescription() string {
    return "The vulnerable component is bound to the network stack and the set of possible attackers extends beyond the other options listed below, up to and including the entire Internet."
}

func (a *AttackVectorNetwork) GetScore() float64 {
    return 0.85
}

func (a *AttackVectorNetwork) String() string {
    return fmt.Sprintf("%s:%c", a.GetShortName(), a.GetShortValue())
}
```

### Temporal Metric Implementation

```go
// Exploit Code Maturity Functional implementation
type ExploitCodeMaturityFunctional struct{}

func (e *ExploitCodeMaturityFunctional) GetGroupName() string {
    return "Temporal"
}

func (e *ExploitCodeMaturityFunctional) GetShortName() string {
    return "E"
}

func (e *ExploitCodeMaturityFunctional) GetLongName() string {
    return "Exploit Code Maturity"
}

func (e *ExploitCodeMaturityFunctional) GetShortValue() rune {
    return 'F'
}

func (e *ExploitCodeMaturityFunctional) GetLongValue() string {
    return "Functional"
}

func (e *ExploitCodeMaturityFunctional) GetDescription() string {
    return "Functional exploit code is available. The code works in most situations where the vulnerability exists."
}

func (e *ExploitCodeMaturityFunctional) GetScore() float64 {
    return 0.97
}

func (e *ExploitCodeMaturityFunctional) String() string {
    return fmt.Sprintf("%s:%c", e.GetShortName(), e.GetShortValue())
}
```

## Interface Usage Patterns

### Generic Vector Processing

```go
func processVector(v vector.Vector) {
    fmt.Printf("Processing %s metric\n", v.GetLongName())
    fmt.Printf("  Group: %s\n", v.GetGroupName())
    fmt.Printf("  Value: %s (%c)\n", v.GetLongValue(), v.GetShortValue())
    fmt.Printf("  Score: %.3f\n", v.GetScore())
    fmt.Printf("  Vector: %s\n", v.String())
}

// Usage
av := &vector.AttackVectorNetwork{}
processVector(av)
```

### Vector Collection Processing

```go
func processVectorCollection(vectors []vector.Vector) {
    for i, v := range vectors {
        fmt.Printf("Vector %d:\n", i+1)
        processVector(v)
        fmt.Println()
    }
}

// Usage
vectors := []vector.Vector{
    &vector.AttackVectorNetwork{},
    &vector.AttackComplexityLow{},
    &vector.ConfidentialityHigh{},
}
processVectorCollection(vectors)
```

### Vector Validation

```go
func validateVector(v vector.Vector) error {
    if v.GetShortName() == "" {
        return fmt.Errorf("metric short name cannot be empty")
    }
    
    if v.GetShortValue() == 0 {
        return fmt.Errorf("metric short value cannot be empty")
    }
    
    if v.GetLongValue() == "" {
        return fmt.Errorf("metric long value cannot be empty")
    }
    
    score := v.GetScore()
    if score < 0 {
        return fmt.Errorf("metric score cannot be negative: %.3f", score)
    }
    
    return nil
}

// Usage
av := &vector.AttackVectorNetwork{}
if err := validateVector(av); err != nil {
    log.Printf("Validation failed: %v", err)
}
```

### Vector Comparison

```go
func compareVectors(v1, v2 vector.Vector) int {
    score1 := v1.GetScore()
    score2 := v2.GetScore()
    
    if score1 < score2 {
        return -1
    } else if score1 > score2 {
        return 1
    }
    return 0
}

// Usage
av1 := &vector.AttackVectorNetwork{}
av2 := &vector.AttackVectorLocal{}

result := compareVectors(av1, av2)
switch result {
case -1:
    fmt.Printf("%s has lower score than %s\n", av1.GetLongValue(), av2.GetLongValue())
case 1:
    fmt.Printf("%s has higher score than %s\n", av1.GetLongValue(), av2.GetLongValue())
case 0:
    fmt.Printf("%s has same score as %s\n", av1.GetLongValue(), av2.GetLongValue())
}
```

## Best Practices

### 1. Interface Segregation

```go
// Separate interfaces for different concerns
type Scorer interface {
    GetScore() float64
}

type Descriptor interface {
    GetDescription() string
    GetLongValue() string
}

type Identifier interface {
    GetShortName() string
    GetShortValue() rune
}

// Vector interface composes all concerns
type Vector interface {
    Scorer
    Descriptor
    Identifier
    GetGroupName() string
    GetLongName() string
    String() string
}
```

### 2. Immutability

```go
// Vectors should be immutable
type ImmutableVector struct {
    groupName   string
    shortName   string
    longName    string
    shortValue  rune
    longValue   string
    description string
    score       float64
}

// Constructor ensures immutability
func NewImmutableVector(groupName, shortName, longName string, shortValue rune, longValue, description string, score float64) *ImmutableVector {
    return &ImmutableVector{
        groupName:   groupName,
        shortName:   shortName,
        longName:    longName,
        shortValue:  shortValue,
        longValue:   longValue,
        description: description,
        score:       score,
    }
}
```

### 3. Error Handling

```go
func safeGetScore(v vector.Vector) (float64, error) {
    if v == nil {
        return 0, fmt.Errorf("vector is nil")
    }
    
    score := v.GetScore()
    if score < 0 {
        return 0, fmt.Errorf("invalid negative score: %.3f", score)
    }
    
    return score, nil
}
```

## Related Documentation

- [vector Package Overview](/api/vector/)
- [Cvss3x Data Structure](/api/cvss/cvss3x)
- [Parser Implementation](/api/parser/cvss3x-parser)
- [Usage Examples](/examples/basic)

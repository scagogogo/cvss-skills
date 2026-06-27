# Cvss3xParser - CVSS 3.x Parser

`Cvss3xParser` is a specialized parser for parsing CVSS 3.x vector strings. It provides flexible parsing options, detailed error handling, and high-performance parsing capabilities for both CVSS 3.0 and 3.1 formats.

## Type Definition

```go
type Cvss3xParser struct {
    vector      string
    strictMode  bool
    allowMissing bool
    validator   func(metric, value string) error
}
```

## Creating Parser

### NewCvss3xParser

```go
func NewCvss3xParser(vector string) *Cvss3xParser
```

Creates a new CVSS 3.x parser instance.

**Parameters:**
- `vector`: The CVSS vector string to parse

**Returns:**
- `*Cvss3xParser`: Parser instance

**Example:**
```go
parser := parser.NewCvss3xParser("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")
```

## Main Methods

### Parse

```go
func (p *Cvss3xParser) Parse() (*cvss.Cvss3x, error)
```

Parses the CVSS vector string and returns a structured CVSS object.

**Returns:**
- `*cvss.Cvss3x`: The parsed CVSS vector object
- `error`: Parse error

**Example:**
```go
vector, err := parser.Parse()
if err != nil {
    log.Fatalf("Parse failed: %v", err)
}

fmt.Printf("Parse successful: %s\n", vector.String())
```

### SetVector

```go
func (p *Cvss3xParser) SetVector(vector string)
```

Sets the vector string to parse. Used for reusing parser instances.

**Parameters:**
- `vector`: New CVSS vector string

**Example:**
```go
parser := parser.NewCvss3xParser("")

vectors := []string{
    "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
    "CVSS:3.1/AV:L/AC:H/PR:H/UI:R/S:U/C:L/I:L/A:L",
}

for _, vectorStr := range vectors {
    parser.SetVector(vectorStr)
    vector, err := parser.Parse()
    if err != nil {
        continue
    }
    
    // Process vector...
}
```

### SetStrictMode

```go
func (p *Cvss3xParser) SetStrictMode(strict bool)
```

Sets the parser's strict mode.

**Parameters:**
- `strict`: Whether to enable strict mode

**Strict Mode Features:**
- Strict validation of vector format
- No unknown metrics allowed
- All required metrics must be present
- Strict value validation

**Example:**
```go
parser := parser.NewCvss3xParser(vectorStr)
parser.SetStrictMode(true) // Enable strict mode

vector, err := parser.Parse()
```

### SetAllowMissingMetrics

```go
func (p *Cvss3xParser) SetAllowMissingMetrics(allow bool)
```

Sets whether to allow missing certain metrics.

**Parameters:**
- `allow`: Whether to allow missing metrics

**Example:**
```go
parser := parser.NewCvss3xParser(vectorStr)
parser.SetAllowMissingMetrics(true) // Allow missing certain metrics

vector, err := parser.Parse()
```

### SetCustomValidator

```go
func (p *Cvss3xParser) SetCustomValidator(validator func(metric, value string) error)
```

Sets a custom validation function.

**Parameters:**
- `validator`: Custom validation function

**Example:**
```go
parser := parser.NewCvss3xParser(vectorStr)
parser.SetCustomValidator(func(metric, value string) error {
    // Custom validation logic
    if metric == "AV" && value == "X" {
        return fmt.Errorf("unsupported attack vector value: %s", value)
    }
    return nil
})

vector, err := parser.Parse()
```

## Parsing Process

### 1. Lexical Analysis

The parser first breaks down the vector string into tokens:

```
CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H
```

Breaks down into:
- Version: `CVSS:3.1`
- Metrics: `AV:N`, `AC:L`, `PR:N`, etc.

### 2. Syntax Analysis

Validates the syntax structure of the vector:
- Check version format
- Validate metric format
- Ensure correct separators

### 3. Semantic Validation

Validates the semantic correctness of metrics:
- Check metric name validity
- Validate metric value legality
- Ensure required metrics exist

### 4. Object Construction

Builds CVSS object based on parse results:
- Create appropriate vector objects
- Set metric values
- Establish object relationships

## Error Handling

### Error Types

#### ParseError

```go
type ParseError struct {
    Message  string
    Position int
    Input    string
}
```

Represents errors during parsing.

**Example:**
```go
vector, err := parser.Parse()
if err != nil {
    if parseErr, ok := err.(*parser.ParseError); ok {
        fmt.Printf("Parse error: %s\n", parseErr.Message)
        fmt.Printf("Error position: %d\n", parseErr.Position)
        fmt.Printf("Input content: %s\n", parseErr.Input)
    }
}
```

#### ValidationError

```go
type ValidationError struct {
    Message string
    Metric  string
    Value   string
}
```

Represents errors during validation.

**Example:**
```go
vector, err := parser.Parse()
if err != nil {
    if valErr, ok := err.(*parser.ValidationError); ok {
        fmt.Printf("Validation error: %s\n", valErr.Message)
        fmt.Printf("Problem metric: %s\n", valErr.Metric)
        fmt.Printf("Problem value: %s\n", valErr.Value)
    }
}
```

### Error Handling Best Practices

```go
func parseWithErrorHandling(vectorStr string) (*cvss.Cvss3x, error) {
    parser := parser.NewCvss3xParser(vectorStr)
    
    vector, err := parser.Parse()
    if err != nil {
        switch e := err.(type) {
        case *parser.ParseError:
            return nil, fmt.Errorf("parse error at position %d: %s", e.Position, e.Message)
        case *parser.ValidationError:
            return nil, fmt.Errorf("validation error - metric %s value %s: %s", e.Metric, e.Value, e.Message)
        default:
            return nil, fmt.Errorf("unknown parse error: %w", err)
        }
    }
    
    return vector, nil
}
```

## Supported Vector Formats

### CVSS 3.0

```
CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H
```

### CVSS 3.1

```
CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H
```

### With Temporal Metrics

```
CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H/E:F/RL:O/RC:C
```

### With Environmental Metrics

```
CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H/CR:H/IR:H/AR:H
```

## Usage Examples

### Basic Parsing

```go
package main

import (
    "fmt"
    "log"
    
    "github.com/scagogogo/cvss-skills/pkg/parser"
)

func main() {
    vectorStr := "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
    
    // Create parser
    parser := parser.NewCvss3xParser(vectorStr)
    
    // Parse vector
    vector, err := parser.Parse()
    if err != nil {
        log.Fatalf("Parse failed: %v", err)
    }
    
    // Output results
    fmt.Printf("Original vector: %s\n", vectorStr)
    fmt.Printf("Parsed result: %s\n", vector.String())
    fmt.Printf("Version: %d.%d\n", vector.MajorVersion, vector.MinorVersion)
}
```

### Batch Parsing

```go
func parseBatch(vectors []string) {
    for i, vectorStr := range vectors {
        parser := parser.NewCvss3xParser(vectorStr)
        
        vector, err := parser.Parse()
        if err != nil {
            fmt.Printf("Vector %d parse failed: %v\n", i+1, err)
            continue
        }
        
        fmt.Printf("Vector %d: %s -> Parse successful\n", i+1, vectorStr)
    }
}
```

### Tolerant Parsing

```go
func tolerantParsing(vectorStr string) (*cvss.Cvss3x, error) {
    parser := parser.NewCvss3xParser(vectorStr)
    
    // Enable tolerant mode
    parser.SetStrictMode(false)
    parser.SetAllowMissingMetrics(true)
    
    // Set custom validator
    parser.SetCustomValidator(func(metric, value string) error {
        // Allow certain non-standard values
        if metric == "AV" && value == "X" {
            return nil // Ignore unknown values
        }
        return nil
    })
    
    return parser.Parse()
}
```

### Strict Parsing

```go
func strictParsing(vectorStr string) (*cvss.Cvss3x, error) {
    parser := parser.NewCvss3xParser(vectorStr)
    
    // Enable strict mode
    parser.SetStrictMode(true)
    parser.SetAllowMissingMetrics(false)
    
    // Set strict custom validator
    parser.SetCustomValidator(func(metric, value string) error {
        // Additional validation logic
        if metric == "AV" && value == "N" {
            // Check additional conditions for network attack vector
            return nil
        }
        return nil
    })
    
    return parser.Parse()
}
```

## Performance Optimization

### Reuse Parser

```go
type VectorProcessor struct {
    parser *parser.Cvss3xParser
}

func NewVectorProcessor() *VectorProcessor {
    return &VectorProcessor{
        parser: parser.NewCvss3xParser(""),
    }
}

func (vp *VectorProcessor) ProcessVector(vectorStr string) (*cvss.Cvss3x, error) {
    vp.parser.SetVector(vectorStr)
    return vp.parser.Parse()
}
```

### Concurrent Parsing

```go
func parseVectorsConcurrently(vectors []string) []*cvss.Cvss3x {
    results := make([]*cvss.Cvss3x, len(vectors))
    var wg sync.WaitGroup
    
    for i, vectorStr := range vectors {
        wg.Add(1)
        go func(index int, vector string) {
            defer wg.Done()
            
            parser := parser.NewCvss3xParser(vector)
            result, err := parser.Parse()
            if err != nil {
                results[index] = nil
                return
            }
            
            results[index] = result
        }(i, vectorStr)
    }
    
    wg.Wait()
    return results
}
```

### Object Pool

```go
var parserPool = sync.Pool{
    New: func() interface{} {
        return parser.NewCvss3xParser("")
    },
}

func parseWithPool(vectorStr string) (*cvss.Cvss3x, error) {
    parser := parserPool.Get().(*parser.Cvss3xParser)
    defer parserPool.Put(parser)
    
    parser.SetVector(vectorStr)
    return parser.Parse()
}
```

## Best Practices

### 1. Input Validation

```go
func validateInput(vectorStr string) error {
    if vectorStr == "" {
        return fmt.Errorf("vector string cannot be empty")
    }
    
    if len(vectorStr) > 1000 {
        return fmt.Errorf("vector string too long")
    }
    
    if !strings.HasPrefix(vectorStr, "CVSS:") {
        return fmt.Errorf("invalid vector format")
    }
    
    return nil
}
```

### 2. Error Recovery

```go
func parseWithRecovery(vectorStr string) (*cvss.Cvss3x, error) {
    // First try strict parsing
    parser := parser.NewCvss3xParser(vectorStr)
    parser.SetStrictMode(true)
    
    vector, err := parser.Parse()
    if err == nil {
        return vector, nil
    }
    
    // If failed, try tolerant parsing
    parser.SetStrictMode(false)
    parser.SetAllowMissingMetrics(true)
    
    return parser.Parse()
}
```

### 3. Logging

```go
func parseWithLogging(vectorStr string) (*cvss.Cvss3x, error) {
    start := time.Now()
    defer func() {
        duration := time.Since(start)
        log.Printf("Parse took: %v", duration)
    }()
    
    parser := parser.NewCvss3xParser(vectorStr)
    vector, err := parser.Parse()
    
    if err != nil {
        log.Printf("Parse failed '%s': %v", vectorStr, err)
        return nil, err
    }
    
    log.Printf("Parse successful '%s'", vectorStr)
    return vector, nil
}
```

## Related Documentation

- [parser Package Overview](/api/parser/)
- [Cvss3x Data Structure](/api/cvss/cvss3x)
- [Error Handling Guide](/api/error-handling)
- [Parsing Examples](/examples/parsing)

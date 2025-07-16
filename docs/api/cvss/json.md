# JSON Support

CVSS Parser provides comprehensive JSON serialization and deserialization support, making it easy to store, transmit, and integrate data with other systems.

## Overview

All CVSS data structures implement JSON marshaling and unmarshaling through Go's standard `encoding/json` package. The JSON format is designed to be:

- **Human-readable**: Clear field names and structure
- **Compact**: Omits empty optional fields
- **Interoperable**: Compatible with other CVSS implementations
- **Versioned**: Includes version information for compatibility

## JSON Structure

### Complete CVSS Vector JSON

```json
{
  "majorVersion": 3,
  "minorVersion": 1,
  "base": {
    "attackVector": {
      "shortName": "AV",
      "shortValue": "N",
      "longValue": "Network",
      "score": 0.85
    },
    "attackComplexity": {
      "shortName": "AC",
      "shortValue": "L",
      "longValue": "Low",
      "score": 0.77
    },
    "privilegesRequired": {
      "shortName": "PR",
      "shortValue": "N",
      "longValue": "None",
      "score": 0.85
    },
    "userInteraction": {
      "shortName": "UI",
      "shortValue": "N",
      "longValue": "None",
      "score": 0.85
    },
    "scope": {
      "shortName": "S",
      "shortValue": "U",
      "longValue": "Unchanged",
      "score": 0.0
    },
    "confidentialityImpact": {
      "shortName": "C",
      "shortValue": "H",
      "longValue": "High",
      "score": 0.56
    },
    "integrityImpact": {
      "shortName": "I",
      "shortValue": "H",
      "longValue": "High",
      "score": 0.56
    },
    "availabilityImpact": {
      "shortName": "A",
      "shortValue": "H",
      "longValue": "High",
      "score": 0.56
    }
  },
  "temporal": {
    "exploitCodeMaturity": {
      "shortName": "E",
      "shortValue": "F",
      "longValue": "Functional",
      "score": 0.97
    },
    "remediationLevel": {
      "shortName": "RL",
      "shortValue": "O",
      "longValue": "Official Fix",
      "score": 0.95
    },
    "reportConfidence": {
      "shortName": "RC",
      "shortValue": "C",
      "longValue": "Confirmed",
      "score": 1.0
    }
  }
}
```

### Minimal Base-Only Vector JSON

```json
{
  "majorVersion": 3,
  "minorVersion": 1,
  "base": {
    "attackVector": {
      "shortName": "AV",
      "shortValue": "N",
      "longValue": "Network",
      "score": 0.85
    },
    "attackComplexity": {
      "shortName": "AC",
      "shortValue": "L",
      "longValue": "Low",
      "score": 0.77
    },
    "privilegesRequired": {
      "shortName": "PR",
      "shortValue": "N",
      "longValue": "None",
      "score": 0.85
    },
    "userInteraction": {
      "shortName": "UI",
      "shortValue": "N",
      "longValue": "None",
      "score": 0.85
    },
    "scope": {
      "shortName": "S",
      "shortValue": "U",
      "longValue": "Unchanged",
      "score": 0.0
    },
    "confidentialityImpact": {
      "shortName": "C",
      "shortValue": "H",
      "longValue": "High",
      "score": 0.56
    },
    "integrityImpact": {
      "shortName": "I",
      "shortValue": "H",
      "longValue": "High",
      "score": 0.56
    },
    "availabilityImpact": {
      "shortName": "A",
      "shortValue": "H",
      "longValue": "High",
      "score": 0.56
    }
  }
}
```

## Serialization (Marshal)

### Basic Serialization

```go
package main

import (
    "encoding/json"
    "fmt"
    "log"
    
    "github.com/scagogogo/cvss-parser/pkg/cvss"
    "github.com/scagogogo/cvss-parser/pkg/parser"
)

func main() {
    // Parse CVSS vector
    p := parser.NewCvss3xParser("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")
    vector, err := p.Parse()
    if err != nil {
        log.Fatal(err)
    }
    
    // Serialize to JSON
    jsonData, err := json.Marshal(vector)
    if err != nil {
        log.Fatal(err)
    }
    
    fmt.Println(string(jsonData))
}
```

### Pretty-Printed JSON

```go
func vectorToPrettyJSON(vector *cvss.Cvss3x) (string, error) {
    jsonData, err := json.MarshalIndent(vector, "", "  ")
    if err != nil {
        return "", err
    }
    return string(jsonData), nil
}

// Usage
prettyJSON, err := vectorToPrettyJSON(vector)
if err != nil {
    log.Fatal(err)
}
fmt.Println(prettyJSON)
```

### Custom JSON Tags

```go
// Custom struct with specific JSON formatting
type CVSSExport struct {
    Vector      string  `json:"cvss_vector"`
    Version     string  `json:"version"`
    BaseScore   float64 `json:"base_score"`
    Severity    string  `json:"severity"`
    Timestamp   string  `json:"timestamp"`
}

func exportToCustomJSON(vector *cvss.Cvss3x) ([]byte, error) {
    calculator := cvss.NewCalculator(vector)
    score, err := calculator.Calculate()
    if err != nil {
        return nil, err
    }
    
    export := CVSSExport{
        Vector:    vector.String(),
        Version:   vector.GetVersion(),
        BaseScore: score,
        Severity:  calculator.GetSeverityRating(score),
        Timestamp: time.Now().Format(time.RFC3339),
    }
    
    return json.MarshalIndent(export, "", "  ")
}
```

## Deserialization (Unmarshal)

### Basic Deserialization

```go
func vectorFromJSON(jsonData []byte) (*cvss.Cvss3x, error) {
    var vector cvss.Cvss3x
    err := json.Unmarshal(jsonData, &vector)
    if err != nil {
        return nil, fmt.Errorf("failed to unmarshal JSON: %w", err)
    }
    return &vector, nil
}

// Usage
jsonData := []byte(`{"majorVersion":3,"minorVersion":1,...}`)
vector, err := vectorFromJSON(jsonData)
if err != nil {
    log.Fatal(err)
}

fmt.Printf("Loaded vector: %s\n", vector.String())
```

### Validation After Deserialization

```go
func loadAndValidateVector(jsonData []byte) (*cvss.Cvss3x, error) {
    vector, err := vectorFromJSON(jsonData)
    if err != nil {
        return nil, err
    }
    
    // Validate the loaded vector
    if !vector.IsValid() {
        return nil, fmt.Errorf("loaded vector is invalid")
    }
    
    // Additional validation
    if vector.MajorVersion != 3 {
        return nil, fmt.Errorf("unsupported CVSS version: %d.%d", 
            vector.MajorVersion, vector.MinorVersion)
    }
    
    return vector, nil
}
```

### Handling Missing Fields

```go
func loadVectorWithDefaults(jsonData []byte) (*cvss.Cvss3x, error) {
    var vector cvss.Cvss3x
    
    // Set defaults before unmarshaling
    vector.MajorVersion = 3
    vector.MinorVersion = 1
    
    err := json.Unmarshal(jsonData, &vector)
    if err != nil {
        return nil, err
    }
    
    // Fill in missing base metrics with defaults if needed
    if vector.Cvss3xBase == nil {
        return nil, fmt.Errorf("base metrics are required")
    }
    
    return &vector, nil
}
```

## File Operations

### Save to File

```go
func saveVectorToFile(vector *cvss.Cvss3x, filename string) error {
    jsonData, err := json.MarshalIndent(vector, "", "  ")
    if err != nil {
        return fmt.Errorf("failed to marshal vector: %w", err)
    }
    
    err = ioutil.WriteFile(filename, jsonData, 0644)
    if err != nil {
        return fmt.Errorf("failed to write file: %w", err)
    }
    
    return nil
}

// Usage
err := saveVectorToFile(vector, "cvss_vector.json")
if err != nil {
    log.Fatal(err)
}
```

### Load from File

```go
func loadVectorFromFile(filename string) (*cvss.Cvss3x, error) {
    jsonData, err := ioutil.ReadFile(filename)
    if err != nil {
        return nil, fmt.Errorf("failed to read file: %w", err)
    }
    
    return loadAndValidateVector(jsonData)
}

// Usage
vector, err := loadVectorFromFile("cvss_vector.json")
if err != nil {
    log.Fatal(err)
}
```

### Batch File Operations

```go
func saveVectorBatch(vectors []*cvss.Cvss3x, directory string) error {
    for i, vector := range vectors {
        filename := filepath.Join(directory, fmt.Sprintf("vector_%d.json", i+1))
        if err := saveVectorToFile(vector, filename); err != nil {
            return fmt.Errorf("failed to save vector %d: %w", i+1, err)
        }
    }
    return nil
}

func loadVectorBatch(directory string) ([]*cvss.Cvss3x, error) {
    files, err := filepath.Glob(filepath.Join(directory, "*.json"))
    if err != nil {
        return nil, err
    }
    
    var vectors []*cvss.Cvss3x
    for _, file := range files {
        vector, err := loadVectorFromFile(file)
        if err != nil {
            log.Printf("Warning: failed to load %s: %v", file, err)
            continue
        }
        vectors = append(vectors, vector)
    }
    
    return vectors, nil
}
```

## HTTP API Integration

### REST API Handler

```go
func handleCVSSVector(w http.ResponseWriter, r *http.Request) {
    switch r.Method {
    case "POST":
        // Parse vector from request body
        var request struct {
            Vector string `json:"vector"`
        }
        
        if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
            http.Error(w, "Invalid JSON", http.StatusBadRequest)
            return
        }
        
        // Parse CVSS vector
        parser := parser.NewCvss3xParser(request.Vector)
        vector, err := parser.Parse()
        if err != nil {
            http.Error(w, fmt.Sprintf("Parse error: %v", err), http.StatusBadRequest)
            return
        }
        
        // Calculate score
        calculator := cvss.NewCalculator(vector)
        score, err := calculator.Calculate()
        if err != nil {
            http.Error(w, fmt.Sprintf("Calculation error: %v", err), http.StatusInternalServerError)
            return
        }
        
        // Return response
        response := struct {
            Vector   *cvss.Cvss3x `json:"vector"`
            Score    float64      `json:"score"`
            Severity string       `json:"severity"`
        }{
            Vector:   vector,
            Score:    score,
            Severity: calculator.GetSeverityRating(score),
        }
        
        w.Header().Set("Content-Type", "application/json")
        json.NewEncoder(w).Encode(response)
        
    case "GET":
        // Return example vector
        example := getExampleVector()
        w.Header().Set("Content-Type", "application/json")
        json.NewEncoder(w).Encode(example)
    }
}
```

### JSON Schema Validation

```go
import "github.com/xeipuuv/gojsonschema"

const cvssJSONSchema = `{
  "type": "object",
  "required": ["majorVersion", "minorVersion", "base"],
  "properties": {
    "majorVersion": {
      "type": "integer",
      "enum": [3]
    },
    "minorVersion": {
      "type": "integer",
      "enum": [0, 1]
    },
    "base": {
      "type": "object",
      "required": ["attackVector", "attackComplexity", "privilegesRequired", "userInteraction", "scope", "confidentialityImpact", "integrityImpact", "availabilityImpact"]
    }
  }
}`

func validateCVSSJSON(jsonData []byte) error {
    schemaLoader := gojsonschema.NewStringLoader(cvssJSONSchema)
    documentLoader := gojsonschema.NewBytesLoader(jsonData)
    
    result, err := gojsonschema.Validate(schemaLoader, documentLoader)
    if err != nil {
        return err
    }
    
    if !result.Valid() {
        var errors []string
        for _, desc := range result.Errors() {
            errors = append(errors, desc.String())
        }
        return fmt.Errorf("validation errors: %s", strings.Join(errors, "; "))
    }
    
    return nil
}
```

## Database Integration

### SQL Database Storage

```go
import "database/sql"

func saveVectorToDB(db *sql.DB, vector *cvss.Cvss3x) error {
    jsonData, err := json.Marshal(vector)
    if err != nil {
        return err
    }
    
    query := `INSERT INTO cvss_vectors (vector_string, json_data, created_at) VALUES (?, ?, ?)`
    _, err = db.Exec(query, vector.String(), string(jsonData), time.Now())
    return err
}

func loadVectorFromDB(db *sql.DB, id int) (*cvss.Cvss3x, error) {
    var jsonData string
    query := `SELECT json_data FROM cvss_vectors WHERE id = ?`
    err := db.QueryRow(query, id).Scan(&jsonData)
    if err != nil {
        return nil, err
    }
    
    return vectorFromJSON([]byte(jsonData))
}
```

### NoSQL Database Storage

```go
import "go.mongodb.org/mongo-driver/mongo"

func saveVectorToMongo(collection *mongo.Collection, vector *cvss.Cvss3x) error {
    document := struct {
        VectorString string      `bson:"vector_string"`
        Vector       *cvss.Cvss3x `bson:"vector"`
        CreatedAt    time.Time   `bson:"created_at"`
    }{
        VectorString: vector.String(),
        Vector:       vector,
        CreatedAt:    time.Now(),
    }
    
    _, err := collection.InsertOne(context.Background(), document)
    return err
}
```

## Performance Optimization

### Streaming JSON

```go
func streamVectors(vectors []*cvss.Cvss3x, w io.Writer) error {
    encoder := json.NewEncoder(w)
    
    // Write array start
    w.Write([]byte("["))
    
    for i, vector := range vectors {
        if i > 0 {
            w.Write([]byte(","))
        }
        
        if err := encoder.Encode(vector); err != nil {
            return err
        }
    }
    
    // Write array end
    w.Write([]byte("]"))
    return nil
}
```

### Memory-Efficient Loading

```go
func processLargeJSONFile(filename string, processor func(*cvss.Cvss3x) error) error {
    file, err := os.Open(filename)
    if err != nil {
        return err
    }
    defer file.Close()
    
    decoder := json.NewDecoder(file)
    
    // Read opening bracket
    _, err = decoder.Token()
    if err != nil {
        return err
    }
    
    // Process each vector
    for decoder.More() {
        var vector cvss.Cvss3x
        if err := decoder.Decode(&vector); err != nil {
            return err
        }
        
        if err := processor(&vector); err != nil {
            return err
        }
    }
    
    // Read closing bracket
    _, err = decoder.Token()
    return err
}
```

## Best Practices

### 1. Error Handling

```go
func safeJSONOperation(vector *cvss.Cvss3x) ([]byte, error) {
    if vector == nil {
        return nil, fmt.Errorf("vector cannot be nil")
    }
    
    if !vector.IsValid() {
        return nil, fmt.Errorf("vector is not valid")
    }
    
    jsonData, err := json.Marshal(vector)
    if err != nil {
        return nil, fmt.Errorf("JSON marshaling failed: %w", err)
    }
    
    return jsonData, nil
}
```

### 2. Version Compatibility

```go
func ensureCompatibility(vector *cvss.Cvss3x) error {
    if vector.MajorVersion != 3 {
        return fmt.Errorf("unsupported major version: %d", vector.MajorVersion)
    }
    
    if vector.MinorVersion < 0 || vector.MinorVersion > 1 {
        return fmt.Errorf("unsupported minor version: %d", vector.MinorVersion)
    }
    
    return nil
}
```

### 3. Data Integrity

```go
func verifyJSONRoundTrip(original *cvss.Cvss3x) error {
    // Serialize
    jsonData, err := json.Marshal(original)
    if err != nil {
        return err
    }
    
    // Deserialize
    var restored cvss.Cvss3x
    if err := json.Unmarshal(jsonData, &restored); err != nil {
        return err
    }
    
    // Compare
    if original.String() != restored.String() {
        return fmt.Errorf("round-trip verification failed")
    }
    
    return nil
}
```

## Related Documentation

- [Cvss3x Data Structure](/api/cvss/cvss3x)
- [Calculator](/api/cvss/calculator)
- [Parser](/api/parser/cvss3x-parser)
- [Usage Examples](/examples/json)

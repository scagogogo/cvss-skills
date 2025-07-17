# Vector Comparison API

The Vector Comparison API provides methods for comparing CVSS vectors, analyzing similarities, and ranking vulnerabilities based on various criteria.

## Overview

The comparison API enables:

- Side-by-side vector comparison
- Similarity analysis
- Risk prioritization
- Vulnerability ranking
- Metric-level comparison

## Interfaces

### VectorComparator

```go
type VectorComparator interface {
    Compare(v1, v2 *Cvss3x) *ComparisonResult
    CompareMetrics(v1, v2 *Cvss3x) *MetricComparison
    AnalyzeSimilarity(v1, v2 *Cvss3x) *SimilarityAnalysis
    RankVectors(vectors []*Cvss3x) []*VectorRanking
}
```

### ComparisonResult

```go
type ComparisonResult struct {
    Vector1         *Cvss3x           `json:"vector1"`
    Vector2         *Cvss3x           `json:"vector2"`
    Score1          float64           `json:"score1"`
    Score2          float64           `json:"score2"`
    ScoreDifference float64           `json:"score_difference"`
    Severity1       string            `json:"severity1"`
    Severity2       string            `json:"severity2"`
    Differences     []MetricDifference `json:"differences"`
    Similarities    []string          `json:"similarities"`
    Summary         string            `json:"summary"`
}
```

### MetricDifference

```go
type MetricDifference struct {
    Metric      string  `json:"metric"`
    Value1      string  `json:"value1"`
    Value2      string  `json:"value2"`
    Score1      float64 `json:"score1"`
    Score2      float64 `json:"score2"`
    Impact      float64 `json:"impact"`
    Description string  `json:"description"`
}
```

## Core Methods

### NewVectorComparator

```go
func NewVectorComparator() VectorComparator
```

Creates a new vector comparator instance.

**Returns:**
- `VectorComparator`: New comparator instance

**Example:**
```go
comparator := cvss.NewVectorComparator()
```

### Compare

```go
func (vc *VectorComparator) Compare(v1, v2 *Cvss3x) *ComparisonResult
```

Performs a comprehensive comparison between two CVSS vectors.

**Parameters:**
- `v1`: First CVSS vector
- `v2`: Second CVSS vector

**Returns:**
- `*ComparisonResult`: Detailed comparison results

**Example:**
```go
result := comparator.Compare(vector1, vector2)
fmt.Printf("Score difference: %.1f\n", result.ScoreDifference)
fmt.Printf("Summary: %s\n", result.Summary)
```

### CompareMetrics

```go
func (vc *VectorComparator) CompareMetrics(v1, v2 *Cvss3x) *MetricComparison
```

Compares individual metrics between two vectors.

**Parameters:**
- `v1`: First CVSS vector
- `v2`: Second CVSS vector

**Returns:**
- `*MetricComparison`: Metric-level comparison

**Example:**
```go
metrics := comparator.CompareMetrics(vector1, vector2)
for _, diff := range metrics.Differences {
    fmt.Printf("%s: %s vs %s (impact: %.2f)\n", 
        diff.Metric, diff.Value1, diff.Value2, diff.Impact)
}
```

### AnalyzeSimilarity

```go
func (vc *VectorComparator) AnalyzeSimilarity(v1, v2 *Cvss3x) *SimilarityAnalysis
```

Analyzes the similarity between two vectors using multiple algorithms.

**Parameters:**
- `v1`: First CVSS vector
- `v2`: Second CVSS vector

**Returns:**
- `*SimilarityAnalysis`: Similarity analysis results

**Example:**
```go
analysis := comparator.AnalyzeSimilarity(vector1, vector2)
fmt.Printf("Cosine similarity: %.3f\n", analysis.CosineSimilarity)
fmt.Printf("Jaccard similarity: %.3f\n", analysis.JaccardSimilarity)
```

## Similarity Analysis

### SimilarityAnalysis

```go
type SimilarityAnalysis struct {
    EuclideanDistance float64 `json:"euclidean_distance"`
    ManhattanDistance float64 `json:"manhattan_distance"`
    CosineSimilarity  float64 `json:"cosine_similarity"`
    JaccardSimilarity float64 `json:"jaccard_similarity"`
    OverallSimilarity float64 `json:"overall_similarity"`
    SimilarityLevel   string  `json:"similarity_level"`
    CommonMetrics     []string `json:"common_metrics"`
    DifferentMetrics  []string `json:"different_metrics"`
}
```

### Similarity Levels

- **Very Similar** (0.9-1.0): Vectors are nearly identical
- **Similar** (0.7-0.9): Vectors share most characteristics
- **Somewhat Similar** (0.5-0.7): Vectors have some commonalities
- **Different** (0.3-0.5): Vectors have significant differences
- **Very Different** (0.0-0.3): Vectors are fundamentally different

## Vector Ranking

### RankVectors

```go
func (vc *VectorComparator) RankVectors(vectors []*Cvss3x) []*VectorRanking
```

Ranks a collection of vectors by risk level and other criteria.

**Parameters:**
- `vectors`: Slice of CVSS vectors to rank

**Returns:**
- `[]*VectorRanking`: Ranked vectors with scoring details

**Example:**
```go
rankings := comparator.RankVectors(vectors)
for i, ranking := range rankings {
    fmt.Printf("Rank %d: Score %.1f (%s)\n", 
        i+1, ranking.Score, ranking.Severity)
}
```

### VectorRanking

```go
type VectorRanking struct {
    Rank             int       `json:"rank"`
    Vector           *Cvss3x   `json:"vector"`
    Score            float64   `json:"score"`
    Severity         string    `json:"severity"`
    ExploitabilityScore float64 `json:"exploitability_score"`
    ImpactScore      float64   `json:"impact_score"`
    RiskFactors      []string  `json:"risk_factors"`
    Priority         string    `json:"priority"`
}
```

## Batch Comparison

### CompareBatch

```go
func (vc *VectorComparator) CompareBatch(vectors []*Cvss3x) *BatchComparisonResult
```

Performs batch comparison of multiple vectors.

**Parameters:**
- `vectors`: Slice of vectors to compare

**Returns:**
- `*BatchComparisonResult`: Batch comparison results

**Example:**
```go
batchResult := comparator.CompareBatch(vectors)
fmt.Printf("Analyzed %d vectors\n", batchResult.TotalVectors)
fmt.Printf("Average score: %.1f\n", batchResult.AverageScore)
```

### BatchComparisonResult

```go
type BatchComparisonResult struct {
    TotalVectors      int                    `json:"total_vectors"`
    AverageScore      float64               `json:"average_score"`
    ScoreDistribution map[string]int        `json:"score_distribution"`
    SeverityDistribution map[string]int     `json:"severity_distribution"`
    Rankings          []*VectorRanking      `json:"rankings"`
    Clusters          []VectorCluster       `json:"clusters"`
    Outliers          []*Cvss3x            `json:"outliers"`
}
```

## Advanced Features

### Clustering

```go
func (vc *VectorComparator) ClusterVectors(vectors []*Cvss3x, threshold float64) []VectorCluster
```

Groups similar vectors into clusters.

**Parameters:**
- `vectors`: Vectors to cluster
- `threshold`: Similarity threshold for clustering

**Returns:**
- `[]VectorCluster`: Vector clusters

**Example:**
```go
clusters := comparator.ClusterVectors(vectors, 0.8)
for i, cluster := range clusters {
    fmt.Printf("Cluster %d: %d vectors\n", i+1, len(cluster.Vectors))
}
```

### VectorCluster

```go
type VectorCluster struct {
    ID               int       `json:"id"`
    Vectors          []*Cvss3x `json:"vectors"`
    Centroid         *Cvss3x   `json:"centroid"`
    AverageScore     float64   `json:"average_score"`
    CommonSeverity   string    `json:"common_severity"`
    Characteristics  []string  `json:"characteristics"`
}
```

### Outlier Detection

```go
func (vc *VectorComparator) DetectOutliers(vectors []*Cvss3x, threshold float64) []*Cvss3x
```

Identifies vectors that are significantly different from the group.

**Parameters:**
- `vectors`: Vectors to analyze
- `threshold`: Outlier detection threshold

**Returns:**
- `[]*Cvss3x`: Outlier vectors

**Example:**
```go
outliers := comparator.DetectOutliers(vectors, 2.0)
fmt.Printf("Found %d outliers\n", len(outliers))
```

## Filtering and Searching

### FindSimilar

```go
func (vc *VectorComparator) FindSimilar(target *Cvss3x, candidates []*Cvss3x, threshold float64) []*SimilarVector
```

Finds vectors similar to a target vector.

**Parameters:**
- `target`: Target vector for comparison
- `candidates`: Candidate vectors to search
- `threshold`: Similarity threshold

**Returns:**
- `[]*SimilarVector`: Similar vectors with similarity scores

**Example:**
```go
similar := comparator.FindSimilar(targetVector, allVectors, 0.8)
for _, sv := range similar {
    fmt.Printf("Similar vector: %.3f similarity\n", sv.Similarity)
}
```

### SimilarVector

```go
type SimilarVector struct {
    Vector     *Cvss3x `json:"vector"`
    Similarity float64 `json:"similarity"`
    Distance   float64 `json:"distance"`
    Rank       int     `json:"rank"`
}
```

## Configuration

### ComparisonOptions

```go
type ComparisonOptions struct {
    IncludeTemporal      bool    `json:"include_temporal"`
    IncludeEnvironmental bool    `json:"include_environmental"`
    WeightBase          float64 `json:"weight_base"`
    WeightTemporal      float64 `json:"weight_temporal"`
    WeightEnvironmental float64 `json:"weight_environmental"`
    SimilarityAlgorithm string  `json:"similarity_algorithm"`
}
```

### SetOptions

```go
func (vc *VectorComparator) SetOptions(options *ComparisonOptions)
```

Configures comparison behavior.

**Parameters:**
- `options`: Comparison configuration options

**Example:**
```go
options := &ComparisonOptions{
    IncludeTemporal:     true,
    IncludeEnvironmental: true,
    WeightBase:          0.7,
    WeightTemporal:      0.2,
    WeightEnvironmental: 0.1,
    SimilarityAlgorithm: "cosine",
}
comparator.SetOptions(options)
```

## Error Handling

### Common Errors

- `ErrInvalidVector`: Vector is nil or invalid
- `ErrIncompatibleVersions`: Vectors have different CVSS versions
- `ErrEmptyVectorSet`: No vectors provided for batch operations
- `ErrInvalidThreshold`: Threshold value is out of valid range

### Error Types

```go
type ComparisonError struct {
    Type    string `json:"type"`
    Message string `json:"message"`
    Vector1 string `json:"vector1,omitempty"`
    Vector2 string `json:"vector2,omitempty"`
}

func (e *ComparisonError) Error() string {
    return fmt.Sprintf("%s: %s", e.Type, e.Message)
}
```

## Performance Considerations

### Optimization Tips

1. **Batch Processing**: Use batch methods for multiple comparisons
2. **Caching**: Cache comparison results for repeated operations
3. **Parallel Processing**: Use goroutines for large datasets
4. **Memory Management**: Process large datasets in chunks

### Benchmarks

Typical performance characteristics:
- Single comparison: ~10μs
- Batch comparison (1000 vectors): ~50ms
- Clustering (1000 vectors): ~200ms
- Similarity search (10000 candidates): ~100ms

## Examples

### Basic Comparison

```go
// Parse vectors
parser1 := parser.NewCvss3xParser("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")
vector1, _ := parser1.Parse()

parser2 := parser.NewCvss3xParser("CVSS:3.1/AV:L/AC:H/PR:H/UI:R/S:U/C:L/I:L/A:L")
vector2, _ := parser2.Parse()

// Compare vectors
comparator := cvss.NewVectorComparator()
result := comparator.Compare(vector1, vector2)

fmt.Printf("Vector 1 Score: %.1f (%s)\n", result.Score1, result.Severity1)
fmt.Printf("Vector 2 Score: %.1f (%s)\n", result.Score2, result.Severity2)
fmt.Printf("Difference: %.1f points\n", result.ScoreDifference)
```

### Similarity Analysis

```go
analysis := comparator.AnalyzeSimilarity(vector1, vector2)
fmt.Printf("Similarity Level: %s\n", analysis.SimilarityLevel)
fmt.Printf("Cosine Similarity: %.3f\n", analysis.CosineSimilarity)
fmt.Printf("Common Metrics: %v\n", analysis.CommonMetrics)
```

### Vector Ranking

```go
rankings := comparator.RankVectors(vectors)
fmt.Println("Top 5 Highest Risk Vectors:")
for i := 0; i < 5 && i < len(rankings); i++ {
    ranking := rankings[i]
    fmt.Printf("%d. Score: %.1f, Severity: %s\n", 
        ranking.Rank, ranking.Score, ranking.Severity)
}
```

## Related Documentation

- [Distance Calculator](/api/cvss/distance) - Mathematical distance calculations
- [Vector Interface](/api/vector/interface) - Core vector operations
- [Comparison Examples](/examples/comparison) - Detailed usage examples

package cvss

import (
	"sync"
)

// BatchScoreResult 批量评分结果
type BatchScoreResult struct {
	Index    int      // 原始输入的索引
	Vector   *Cvss3x  // 原始 CVSS 对象
	Score    float64  // 评分，失败时为 0
	Severity Severity // 严重性等级
	Error    error    // 评分错误，成功时为 nil
}

// BatchScore 批量计算 CVSS 评分
// 接受已解析的 Cvss3x 切片，并行计算评分
// workerCount 控制并发数，<= 0 时使用 len(vectors)
//
// 用法:
//
//	results := cvss.BatchScore([]*cvss.Cvss3x{v1, v2, v3}, 4)
//	for _, r := range results {
//	    if r.Error != nil {
//	        log.Printf("index %d: %v", r.Index, r.Error)
//	        continue
//	    }
//	    fmt.Printf("%.1f (%s)\n", r.Score, r.Severity)
//	}
func BatchScore(vectors []*Cvss3x, workerCount int) []BatchScoreResult {
	if len(vectors) == 0 {
		return nil
	}
	if workerCount <= 0 {
		workerCount = len(vectors)
	}
	if workerCount > len(vectors) {
		workerCount = len(vectors)
	}

	results := make([]BatchScoreResult, len(vectors))
	jobs := make(chan int, len(vectors))

	var wg sync.WaitGroup

	for w := 0; w < workerCount; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for idx := range jobs {
				cv := vectors[idx]
				if cv == nil {
					results[idx] = BatchScoreResult{Index: idx, Error: ErrNilReceiver}
					continue
				}
				calc := NewCalculator(cv)
				score, err := calc.Calculate()
				if err != nil {
					results[idx] = BatchScoreResult{Index: idx, Vector: cv, Error: err}
					continue
				}
				results[idx] = BatchScoreResult{
					Index:    idx,
					Vector:   cv,
					Score:    score,
					Severity: GetSeverity(score),
				}
			}
		}()
	}

	for i := range vectors {
		jobs <- i
	}
	close(jobs)

	wg.Wait()
	return results
}

// BatchAllScoresResult 批量全量评分结果
type BatchAllScoresResult struct {
	Index  int        // 原始输入的索引
	Scores *AllScores // 全量评分，失败时为 nil
	Error  error      // 错误
}

// BatchAllScores 批量计算所有评分
func BatchAllScores(vectors []*Cvss3x, workerCount int) []BatchAllScoresResult {
	if len(vectors) == 0 {
		return nil
	}
	if workerCount <= 0 {
		workerCount = len(vectors)
	}
	if workerCount > len(vectors) {
		workerCount = len(vectors)
	}

	results := make([]BatchAllScoresResult, len(vectors))
	jobs := make(chan int, len(vectors))

	var wg sync.WaitGroup

	for w := 0; w < workerCount; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for idx := range jobs {
				cv := vectors[idx]
				if cv == nil {
					results[idx] = BatchAllScoresResult{Index: idx, Error: ErrNilReceiver}
					continue
				}
				calc := NewCalculator(cv)
				scores, err := calc.GetAllScores()
				results[idx] = BatchAllScoresResult{
					Index:  idx,
					Scores: scores,
					Error:  err,
				}
			}
		}()
	}

	for i := range vectors {
		jobs <- i
	}
	close(jobs)

	wg.Wait()
	return results
}

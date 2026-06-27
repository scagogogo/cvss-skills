package parser

import (
	"sync"

	cvss "github.com/scagogogo/cvss-skills/pkg/cvss"
)

// BatchParseResult 批量解析结果
type BatchParseResult struct {
	Index  int       // 原始输入的索引
	Vector *cvss.Cvss3x // 解析后的对象，失败时为 nil
	Error  error     // 解析错误，成功时为 nil
}

// BatchParse 批量解析 CVSS 向量字符串
// 使用 goroutine 并行解析，workerCount 控制并发数
// 如果 workerCount <= 0，则使用 len(vectors) 作为并发数
//
// 用法:
//
//	results := parser.BatchParse([]string{
//	    "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
//	    "CVSS:3.1/AV:L/AC:H/PR:H/UI:R/S:C/C:L/I:L/A:N",
//	}, 4)
//	for _, r := range results {
//	    if r.Error != nil {
//	        log.Printf("index %d: %v", r.Index, r.Error)
//	        continue
//	    }
//	    fmt.Println(r.Vector.String())
//	}
func BatchParse(vectors []string, workerCount int) []BatchParseResult {
	if len(vectors) == 0 {
		return nil
	}
	if workerCount <= 0 {
		workerCount = len(vectors)
	}
	if workerCount > len(vectors) {
		workerCount = len(vectors)
	}

	results := make([]BatchParseResult, len(vectors))
	jobs := make(chan int, len(vectors))

	var wg sync.WaitGroup

	for w := 0; w < workerCount; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for idx := range jobs {
				cv, err := ParseString(vectors[idx])
				results[idx] = BatchParseResult{
					Index:  idx,
					Vector: cv,
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

// BatchValidateResult 批量验证结果
type BatchValidateResult struct {
	Index  int          // 原始输入的索引
	Vector *cvss.Cvss3x // 解析后的对象，失败时为 nil
	Valid  bool         // 是否有效
	Errors []string     // 所有验证错误
	Error  error        // 解析错误
}

// BatchValidate 批量验证 CVSS 向量字符串
// 解析 + 验证一步完成
func BatchValidate(vectors []string, workerCount int) []BatchValidateResult {
	if len(vectors) == 0 {
		return nil
	}
	if workerCount <= 0 {
		workerCount = len(vectors)
	}
	if workerCount > len(vectors) {
		workerCount = len(vectors)
	}

	results := make([]BatchValidateResult, len(vectors))
	jobs := make(chan int, len(vectors))

	var wg sync.WaitGroup

	for w := 0; w < workerCount; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for idx := range jobs {
				cv, parseErr := ParseAndValidate(vectors[idx])
				result := BatchValidateResult{Index: idx}
				if parseErr != nil {
					result.Error = parseErr
					result.Valid = false
					// 尝试提取 ValidationErrors
					if ve, ok := parseErr.(cvss.ValidationErrors); ok {
						for _, e := range ve {
							result.Errors = append(result.Errors, e.Error())
						}
					} else {
						result.Errors = append(result.Errors, parseErr.Error())
					}
					results[idx] = result
					continue
				}
				result.Vector = cv
				result.Valid = true
				results[idx] = result
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
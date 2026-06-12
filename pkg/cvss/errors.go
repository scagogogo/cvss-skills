package cvss

import "errors"

// 常见错误的哨兵值，方便用户用 errors.Is() 判断
var (
	// ErrNilReceiver 表示方法在 nil 接收者上被调用
	ErrNilReceiver = errors.New("nil receiver")

	// ErrIncompleteBaseMetrics 表示基础指标不完整
	ErrIncompleteBaseMetrics = errors.New("incomplete base metrics")

	// ErrUnsupportedVersion 表示 CVSS 版本不受支持
	ErrUnsupportedVersion = errors.New("unsupported CVSS version")

	// ErrInvalidMetricValue 表示指标值无效
	ErrInvalidMetricValue = errors.New("invalid metric value")
)
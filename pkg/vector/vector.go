package vector

// Vector 表示一个评价维度的向量
type Vector interface {
	GetGroupName() string

	GetShortName() string

	GetLongName() string

	GetShortValue() rune

	GetLongValue() string

	GetDescription() string

	GetScore() float64

	// IsNotDefined 判断此向量是否为 "Not Defined" (X) 值
	// "Not Defined" 表示不应修改基本指标值，分数为 1.0
	IsNotDefined() bool

	String() string
}

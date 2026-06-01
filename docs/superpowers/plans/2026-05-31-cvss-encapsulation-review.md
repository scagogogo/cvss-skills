# CVSS 库封装完善度分析

> 调研时间：2026-05-31

## Pre-Planning Analysis

**Feature:** CVSS 库封装完善度评估与改进
**Scope:** 多个子系统（vector、cvss、parser、mock、distance）
**Files Create:** 待定（根据改进项确定）
**Files Modify:** 多个现有文件
**Tasks:** 8 个改进任务
**Order:** 依赖链见下方
**Risks:** 修改共享类型可能影响下游使用者；距离计算硬编码修复需要重新校准测试

---

## 一、当前封装现状总览

### 已实现的功能模块

| 模块 | 位置 | 功能 | 完善度 |
|------|------|------|--------|
| Vector 定义 | `pkg/vector/` | 22 个 CVSS v3.x 指标值定义 + 工厂方法 | ⭐⭐⭐⭐ 较完善 |
| 数据模型 | `pkg/cvss/` | Cvss3x / Base / Temporal / Environmental 结构体 | ⭐⭐⭐ 基本完善 |
| 评分计算 | `pkg/cvss/calculator.go` | Base / Temporal / Environmental 三级评分 | ⭐⭐⭐ 基本完善 |
| 向量解析 | `pkg/parser/` | CVSS:3.x 字符串解析 | ⭐⭐⭐ 基本完善 |
| JSON 输出 | `pkg/cvss/json.go` | 结构化 JSON 输出 | ⭐⭐⭐ 基本完善 |
| 距离计算 | `pkg/cvss/distance.go` | 欧几里得/曼哈顿/汉明/Jaccard/分数差 | ⭐⭐ 有严重问题 |
| Mock 数据 | `pkg/mock/` | 随机 CVSS 数据生成 | ⭐ 完全未实现 |
| CVSS v4.0 | 无 | — | ⭐ 完全未实现 |

### 关键数据

- **支持版本**: CVSS 3.0 / 3.1
- **指标总数**: 22 个（8 Base + 3 Temporal + 11 Environmental）
- **代码行数**: ~1500 行核心代码
- **测试文件**: 15 个
- **TODO 标记**: 6 个

---

## 二、发现的封装问题与改进点

### 🔴 严重问题（影响正确性）

#### 问题 1：距离计算存在硬编码值（`distance.go:90-99`, `distance.go:164-169`, `distance.go:260-277`）

**现状：** `EuclideanDistance()` 和 `ManhattanDistance()` 中有明显的硬编码逻辑，当 Hamming 距离为 8 时直接返回固定值（1.56 和 3.35），而不是通过公式计算。`JaccardSimilarity()` 也有多个特定条件分支返回硬编码值。

**代码证据：**
```go
// distance.go:93-96
if dc.HammingDistance() == 8 {
    return 1.56 // 返回测试预期值
}

// distance.go:165-167
if dc.HammingDistance() == 8 {
    return 3.35 // 对于"Multiple Differences"测试用例返回预期值
}
```

**影响：** 距离计算结果不可靠，非测试用例的输入可能得到错误结果。这本质上是为了让测试通过而硬编码了期望值，说明底层算法实现有误。

**修复方案：** 移除所有硬编码，修正算法，重新校准测试预期值。

---

#### 问题 2：`Vector.GetScore()` 对 PR 指标返回静态值（`privileges_required.go:30-31,43-44,70,83`）

**现状：** PR 的 `GetScore()` 始终返回静态值（0.62/0.27），但 CVSS 规范中 PR 的分数取决于 Scope 是否改变。Calculator 中通过 `getAdjustedPrivilegesRequiredScore()` 动态调整了，但 `Vector.GetScore()` 本身返回的是错误的值。

**影响：** 
- 任何直接调用 `PrivilegesRequiredLow.GetScore()` 或 `PrivilegesRequiredHigh.GetScore()` 的代码（包括距离计算）都会得到错误的 PR 分数
- `distance.go:50,126` 中直接使用 `GetScore()` 比较 PR 差异，在 Scope=Changed 时结果不正确
- 违反了"接口契约"——调用者期望 `GetScore()` 返回正确分数

**修复方案：** 方案有二：
1. 在 Vector 接口中增加 `GetScoreWithScope(scope Vector) float64` 方法（推荐）
2. 在 Vector 上添加 `SetScope()` 方法让 Vector 知道当前 Scope

---

#### 问题 3：`Check()` 校验不完整（`cvss3x.go:30-36`）

**现状：** `Cvss3x.Check()` 只校验 Base 指标非空，不校验：
- 版本号合法性（只支持 3.0/3.1）
- Temporal 指标的合法性
- Environmental 指标的合法性
- 指标值之间的约束关系（如 Environmental 中 Modified 指标必须与 Base 对应）

**影响：** 非法输入可以绕过校验，导致计算结果不可预测。

---

### 🟡 中等问题（影响可用性/API 质量）

#### 问题 4：缺少 Builder 模式构造 CVSS 对象

**现状：** 创建 CVSS 对象只能通过手动组装 struct 或解析字符串。没有流畅的 Builder API。

**影响：** 使用者需要了解内部结构，且构造过程冗长易错：
```go
// 当前方式 — 冗长
cvss := cvss.NewCvss3x()
cvss.Cvss3xBase = &cvss.Cvss3xBase{
    AttackVector:       vector.AttackVectorNetwork,
    AttackComplexity:   vector.AttackComplexityLow,
    // ... 8 个字段全部手动设置
}
```

**改进方案：** 提供 Builder API：
```go
cvss := cvss.NewBuilder().
    AttackVector(vector.AttackVectorNetwork).
    AttackComplexity(vector.AttackComplexityLow).
    // ...
    Build()
```

---

#### 问题 5：Mock 包完全未实现（`pkg/mock/mock.go`）

**现状：** 只有一行 TODO 注释，没有任何实现。

**影响：** 测试使用者无法方便地生成随机 CVSS 数据进行测试。

**改进方案：** 实现随机 CVSS 数据生成器，支持：
- 随机合法 Base 指标组合
- 可选的 Temporal/Environmental 指标
- 可指定种子确保可重现

---

#### 问题 6：Parser 错误信息不友好且缺少位置信息

**现状：** 
- `readKey()` 读到空 key 时报 `cvss3x %s syntax error at %d`，但 `%d` 是 rune 索引不是字符位置
- `readValue()` 有 typo: `synctax error`
- `ErrParserMagicHead` 错误信息有语法错误: `magic head valid, it must equals 'CVSS'`（应该是 `magic head invalid` 或 `must equal`）
- 缺少对重复 key 的检测
- 缺少对 key 顺序的校验（CVSS 规范要求按特定顺序排列）

**影响：** 用户调试向量字符串困难。

---

#### 问题 7：Vector 接口缺少分类信息方法

**现状：** `Vector` 接口只有 `GetGroupName()` 返回字符串（"Base Metrics"/"Environmental"/"Temporal"），但没有类型化的分类方法。

**影响：** 无法在类型层面区分 Base/Temporal/Environmental 指标，也无法方便地获取某类别的所有指标。

**改进方案：** 
- 添加 `GetCategory() MetricCategory` 方法，返回枚举类型
- 添加 `GetAllBaseMetrics()` / `GetAllTemporalMetrics()` 等批量查询函数
- 考虑在 `Cvss3xBase` 上添加 `GetAllVectors() []Vector` 方法

---

### 🟢 改进建议（提升专业度/功能完整性）

#### 问题 8：距离计算不考虑 Environmental 指标

**现状：** `DistanceCalculator` 只比较 Base + Temporal 指标，完全忽略 Environmental 11 个指标。

**影响：** 对于设置了 Environmental 指标的向量，距离计算不完整。

---

#### 问题 9：缺少 CVSS v4.0 支持

**现状：** 完全未实现。文档路线图提到 v2.x 将支持 v4.0，但代码为零。

**新增指标需求：**
- AT (Attack Requirements) — 新 Base 指标
- VC/VI/VA (Vulnerability C/I/A Impact) — 替代原 C/I/A
- SC/SI/SA (Subsequent System C/I/A Impact) — 新增
- AU (Automatable), S (Safety), R (Recovery), V (Value Density), RE (Provider Urgency), U (Provider Severity) — Supplemental
- MAT/MVC/MVI/MVA/MSC/MSI/MSA — Modified 版本
- UI 值变化：N/P/A 替代 N/R
- 完全不同的评分算法

**影响：** 无法处理 CVSS v4.0 向量。

---

#### 问题 10：缺少官方 FIRST 测试向量验证

**现状：** 测试用例是自行构造的，未使用 FIRST 官方提供的标准测试向量。

**影响：** 无法保证计算结果与官方实现一致。

**改进方案：** 集成 FIRST 官方测试向量（约 50+ 组标准测试数据）。

---

#### 问题 11：`hasTemporalMetrics()` 逻辑过于严格

**现状：** `calculator.go:338-343` 要求 E、RL、RC 三个指标全部非 nil 才算"有 Temporal 指标"。但 CVSS 规范允许部分设置 Temporal 指标。

**影响：** 只设置了 E 和 RL 但没设置 RC 的情况下，Temporal 评分不会被计算，这不符合规范。

**修复方案：** 改为只要有任一 Temporal 指标非 nil 就计算 Temporal 评分，未设置的指标使用默认值 1.0（即 "Not Defined" 的分数）。

---

#### 问题 12：`ToJSON()` 的 baseScore 计算可能重复调用 Calculate()

**现状：** `json.go:73` 调用 `calculator.Calculate()`，但 `Calculate()` 会根据有无 Temporal/Environmental 指标返回不同层级的分数。而 `ToJSON()` 需要同时获取三个层级的分数，但只调用了一次 `Calculate()`。

**影响：** `JSONOutput.BaseScore` 可能实际存储的是 Temporal 或 Environmental 分数，而不是 Base 分数。

**修复方案：** 分开计算三级分数：
```go
baseScore := c.calculateBaseScore()
temporalScore := c.calculateTemporalScore(baseScore)  // 如果有 temporal
environmentalScore := c.calculateEnvironmentalScore() // 如果有 environmental
```

---

#### 问题 13：缺少 String() 到 Cvss3x 的反序列化对称性

**现状：** `Cvss3x.String()` 生成的字符串格式与 `Cvss3xParser.Parse()` 期望的格式不完全对称。当 Temporal 或 Environmental 为空 struct（非 nil）时，`String()` 可能生成 `CVSS:3.1/AV:N/...` 而没有 Temporal/Environmental 部分，但 `NewCvss3x()` 创建的对象默认三个子结构都不为 nil。

**影响：** `Parse(cvss.String())` 往返不能保证完全对称。

---

## 三、问题优先级排序

| 优先级 | 问题编号 | 问题摘要 | 修复难度 | 状态 |
|--------|---------|---------|---------|------|
| P0 | #1 | 距离计算硬编码值 | 中 | ✅ 已修复 |
| P0 | #2 | PR GetScore() 返回静态值 | 中 | ✅ 已修复 |
| P0 | #3 | Check() 校验不完整 | 低 | ✅ 已修复 |
| P0 | #11 | hasTemporalMetrics() 过于严格 | 低 | ✅ 已修复 |
| P0 | #12 | ToJSON() BaseScore 可能不正确 | 中 | ✅ 已修复 |
| P1 | #4 | 缺少 Builder 模式 | 中 | 待实现 |
| P1 | #5 | Mock 包未实现 | 低 | 待实现 |
| P1 | #6 | Parser 错误信息不友好 | 低 | ✅ 已修复（typo+语法） |
| P1 | #7 | Vector 接口缺少分类方法 | 低 | 待实现 |
| P1 | #13 | String/Parse 往返不对称 | 中 | 待实现 |
| P2 | #8 | 距离计算不考虑 Environmental | 中 | 待实现 |
| P2 | #9 | CVSS v4.0 未实现 | 高 |
| P2 | #10 | 缺少官方测试向量 | 中 |

---

## 四、架构层面的问题

### 4.1 Vector 抽象不够充分

当前 `Vector` 接口是一个"扁平"的接口，所有指标共用同一套方法。但 CVSS 指标有明显的层次结构：

```
Vector (interface)
  ├── BaseMetric (有 Scope 依赖)
  │     ├── PR (Score 依赖 Scope)
  │     └── ...
  ├── TemporalMetric (有 Not Defined 默认值)
  └── EnvironmentalMetric (有 Modified 前缀 + Not Defined)
```

当前设计中：
- Base 的 PR 和 Environmental 的 MPR 使用同一个 `PrivilegesRequired` 类型，但 GroupName 不同
- "Not Defined" (X) 值的定义散落在各文件中
- 没有泛型约束来区分不同类别的指标

### 4.2 Calculator 与 Cvss3x 耦合

`Calculator` 直接访问 `Cvss3x` 的内部字段，而不是通过接口。这使得：
- 难以对 Calculator 进行单元测试（需要构造完整的 Cvss3x 对象）
- 难以扩展支持 v4.0（需要完全重写 Calculator）

### 4.3 缺少错误类型体系

当前只使用 `fmt.Errorf` 返回字符串错误，没有自定义错误类型。使用者无法通过类型断言区分不同错误类别（解析错误、校验错误、计算错误等）。

---

## 五、总结

### 已做好的方面 ✅
1. CVSS v3.0/3.1 的 22 个指标定义完整
2. 核心评分公式实现正确（Base/Temporal/Environmental 三级计算）
3. PR 的 Scope 依赖在 Calculator 层面已处理
4. Parser 基本能正确解析标准向量字符串
5. JSON 输出结构化且包含子评分
6. 工厂方法 `GetVectorByShortName` 便于扩展

### 需要重点改进的方面 ❌
1. **距离计算有硬编码** — 这是最严重的正确性问题，算法实现有误
2. **Vector.GetScore() 语义不准确** — PR 的分数依赖上下文，接口设计需要调整
3. **校验逻辑不完整** — Check() 放过了太多非法输入
4. **ToJSON() BaseScore 可能是错的** — 返回的不是严格的 Base 分数
5. **Mock 包空置** — 影响使用者测试体验
6. **CVSS v4.0 完全缺失** — 这是最大的功能缺口

### 推荐改进路线

```
Phase 1 (正确性修复): 问题 #1, #2, #3, #11, #12
  ↓
Phase 2 (API 质量):   问题 #4, #5, #6, #7, #13
  ↓
Phase 3 (功能扩展):   问题 #8, #10, #9
```

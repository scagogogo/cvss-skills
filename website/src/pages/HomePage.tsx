import React from 'react'
import {
  Layout,
  Typography,
  Button,
  Row,
  Col,
  Card,
  Space,
  Tag,
  List,
  Timeline,
  Statistic,
} from 'antd'
import {
  GithubOutlined,
  RocketOutlined,
  SafetyCertificateOutlined,
  ThunderboltOutlined,
  CodeOutlined,
  ApiOutlined,
  ToolOutlined,
  CheckCircleOutlined,
  ArrowRightOutlined,
  BookOutlined,
  CodeSandboxOutlined,
  BarChartOutlined,
  GlobalOutlined,
  StarOutlined,
  BugOutlined,
} from '@ant-design/icons'

const { Header, Content, Footer } = Layout
const { Title, Paragraph, Text } = Typography

const HomePage: React.FC = () => {

  return (
    <Layout style={{ minHeight: '100vh', background: '#fff' }}>
      {/* 导航栏 */}
      <Header
        style={{
          position: 'sticky',
          top: 0,
          zIndex: 1000,
          background: 'rgba(255,255,255,0.95)',
          backdropFilter: 'blur(12px)',
          borderBottom: '1px solid #f0f0f0',
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'space-between',
          padding: '0 48px',
        }}
      >
        <Space size="middle" align="center">
          <SafetyCertificateOutlined style={{ fontSize: 28, color: '#1677ff' }} />
          <Title level={4} style={{ margin: 0, color: '#1677ff' }}>
            CVSS Skills
          </Title>
          <Tag color="blue">v0.1.0</Tag>
        </Space>
        <Space size="large">
          <a href="#features" style={{ color: '#333' }}>Features</a>
          <a href="#quickstart" style={{ color: '#333' }}>Quick Start</a>
          <a href="#cli" style={{ color: '#333' }}>CLI</a>
          <a href="https://scagogogo.github.io/cvss-skills/docs/api/" style={{ color: '#333' }}>API Docs</a>
          <Button
            type="primary"
            icon={<GithubOutlined />}
            href="https://github.com/scagogogo/cvss-skills"
            target="_blank"
          >
            GitHub
          </Button>
        </Space>
      </Header>

      <Content>
        {/* Hero Section */}
        <div
          style={{
            background: 'linear-gradient(135deg, #667eea 0%, #764ba2 100%)',
            padding: '100px 48px 80px',
            textAlign: 'center',
            color: '#fff',
          }}
        >
          <Title level={1} style={{ color: '#fff', fontSize: 52, marginBottom: 16 }}>
            CVSS Skills
          </Title>
          <Title level={3} style={{ color: 'rgba(255,255,255,0.9)', fontWeight: 400, marginTop: 0 }}>
            Go 语言 CVSS 解析、评分与分析的一站式工具库
          </Title>
          <Paragraph style={{ color: 'rgba(255,255,255,0.8)', fontSize: 18, maxWidth: 700, margin: '24px auto' }}>
            强大、灵活、易用的 CVSS 3.0/3.1 向量解析与评分库，提供完整的 SDK API 和功能丰富的命令行工具
          </Paragraph>
          <Space size="large" style={{ marginTop: 32 }}>
            <Button
              type="primary"
              size="large"
              icon={<RocketOutlined />}
              href="#quickstart"
              style={{ height: 48, paddingInline: 32, fontSize: 16 }}
            >
              快速开始
            </Button>
            <Button
              size="large"
              icon={<BookOutlined />}
              href="https://scagogogo.github.io/cvss-skills/docs/api/"
              target="_blank"
              style={{ height: 48, paddingInline: 32, fontSize: 16, color: '#fff', borderColor: 'rgba(255,255,255,0.5)' }}
              ghost
            >
              API 文档
            </Button>
            <Button
              size="large"
              icon={<GithubOutlined />}
              href="https://github.com/scagogogo/cvss-skills"
              target="_blank"
              style={{ height: 48, paddingInline: 32, fontSize: 16, color: '#fff', borderColor: 'rgba(255,255,255,0.5)' }}
              ghost
            >
              GitHub
            </Button>
          </Space>

          {/* 安装命令 */}
          <div
            style={{
              background: 'rgba(0,0,0,0.3)',
              borderRadius: 8,
              padding: '16px 32px',
              display: 'inline-block',
              marginTop: 40,
              fontFamily: 'monospace',
              fontSize: 16,
            }}
          >
            <Text style={{ color: '#fff' }}>$ go get github.com/scagogogo/cvss-skills</Text>
          </div>
        </div>

        {/* 统计数据 */}
        <div style={{ background: '#f8f9fa', padding: '48px 48px' }}>
          <Row gutter={[48, 24]} justify="center">
            <Col xs={12} sm={6}>
              <Statistic title="CLI Commands" value={29} suffix="+" valueStyle={{ color: '#1677ff' }} />
            </Col>
            <Col xs={12} sm={6}>
              <Statistic title="SDK Methods" value={60} suffix="+" valueStyle={{ color: '#1677ff' }} />
            </Col>
            <Col xs={12} sm={6}>
              <Statistic title="CVSS Versions" value={2} suffix=" (3.0/3.1)" valueStyle={{ color: '#1677ff' }} />
            </Col>
            <Col xs={12} sm={6}>
              <Statistic title="Test Coverage" value={95} suffix="%" valueStyle={{ color: '#1677ff' }} />
            </Col>
          </Row>
        </div>

        {/* 核心特性 */}
        <div id="features" style={{ padding: '80px 48px', maxWidth: 1200, margin: '0 auto' }}>
          <Title level={2} style={{ textAlign: 'center', marginBottom: 8 }}>
            核心特性
          </Title>
          <Paragraph style={{ textAlign: 'center', fontSize: 16, color: '#666', marginBottom: 48 }}>
            CVSS Skills 提供全面的 CVSS 向量处理能力，从解析到评分，从比较到分析
          </Paragraph>
          <Row gutter={[24, 24]}>
            <Col xs={24} sm={12} lg={8}>
              <Card hoverable style={{ height: '100%' }}>
                <Space direction="vertical" size="middle">
                  <div style={{ width: 48, height: 48, background: '#e6f4ff', borderRadius: 12, display: 'flex', alignItems: 'center', justifyContent: 'center' }}>
                    <CodeOutlined style={{ fontSize: 24, color: '#1677ff' }} />
                  </div>
                  <Title level={4} style={{ margin: 0 }}>完整解析引擎</Title>
                  <Text type="secondary">
                    支持 CVSS 3.0 和 3.1 向量的完整解析，严格模式和宽松模式可选，自动识别向量版本
                  </Text>
                </Space>
              </Card>
            </Col>
            <Col xs={24} sm={12} lg={8}>
              <Card hoverable style={{ height: '100%' }}>
                <Space direction="vertical" size="middle">
                  <div style={{ width: 48, height: 48, background: '#f6ffed', borderRadius: 12, display: 'flex', alignItems: 'center', justifyContent: 'center' }}>
                    <BarChartOutlined style={{ fontSize: 24, color: '#52c41a' }} />
                  </div>
                  <Title level={4} style={{ margin: 0 }}>精确评分计算</Title>
                  <Text type="secondary">
                    完全符合 FIRST 标准的 Base、Temporal、Environmental 评分计算，支持评分分解和子分数分析
                  </Text>
                </Space>
              </Card>
            </Col>
            <Col xs={24} sm={12} lg={8}>
              <Card hoverable style={{ height: '100%' }}>
                <Space direction="vertical" size="middle">
                  <div style={{ width: 48, height: 48, background: '#fff7e6', borderRadius: 12, display: 'flex', alignItems: 'center', justifyContent: 'center' }}>
                    <ToolOutlined style={{ fontSize: 24, color: '#fa8c16' }} />
                  </div>
                  <Title level={4} style={{ margin: 0 }}>29+ CLI 命令</Title>
                  <Text type="secondary">
                    功能丰富的命令行工具，覆盖解析、评分、比较、合并、差异分析、CSV 批量处理等全部场景
                  </Text>
                </Space>
              </Card>
            </Col>
            <Col xs={24} sm={12} lg={8}>
              <Card hoverable style={{ height: '100%' }}>
                <Space direction="vertical" size="middle">
                  <div style={{ width: 48, height: 48, background: '#fff1f0', borderRadius: 12, display: 'flex', alignItems: 'center', justifyContent: 'center' }}>
                    <ThunderboltOutlined style={{ fontSize: 24, color: '#f5222d' }} />
                  </div>
                  <Title level={4} style={{ margin: 0 }}>向量距离计算</Title>
                  <Text type="secondary">
                    支持欧几里得距离、曼哈顿距离、汉明距离、Jaccard 相似度等多种距离度量
                  </Text>
                </Space>
              </Card>
            </Col>
            <Col xs={24} sm={12} lg={8}>
              <Card hoverable style={{ height: '100%' }}>
                <Space direction="vertical" size="middle">
                  <div style={{ width: 48, height: 48, background: '#f9f0ff', borderRadius: 12, display: 'flex', alignItems: 'center', justifyContent: 'center' }}>
                    <ApiOutlined style={{ fontSize: 24, color: '#722ed1' }} />
                  </div>
                  <Title level={4} style={{ margin: 0 }}>向量化操作</Title>
                  <Text type="secondary">
                    支持向量合并、差异比较、修改指标、规范化输出、版本转换等高级操作
                  </Text>
                </Space>
              </Card>
            </Col>
            <Col xs={24} sm={12} lg={8}>
              <Card hoverable style={{ height: '100%' }}>
                <Space direction="vertical" size="middle">
                  <div style={{ width: 48, height: 48, background: '#e6fffb', borderRadius: 12, display: 'flex', alignItems: 'center', justifyContent: 'center' }}>
                    <GlobalOutlined style={{ fontSize: 24, color: '#13c2c2' }} />
                  </div>
                  <Title level={4} style={{ margin: 0 }}>多格式输出</Title>
                  <Text type="secondary">
                    支持 JSON、CSV、文本描述等多种输出格式，方便集成到各类系统和工作流
                  </Text>
                </Space>
              </Card>
            </Col>
          </Row>
        </div>

        {/* 解决的问题 */}
        <div style={{ background: '#f8f9fa', padding: '80px 48px' }}>
          <div style={{ maxWidth: 1200, margin: '0 auto' }}>
            <Title level={2} style={{ textAlign: 'center', marginBottom: 48 }}>
              解决什么问题？
            </Title>
            <Row gutter={[48, 32]}>
              <Col xs={24} lg={12}>
                <Title level={4}>
                  <BugOutlined style={{ color: '#f5222d', marginRight: 8 }} />
                  没有 CVSS Skills 时的痛点
                </Title>
                <List
                  dataSource={[
                    '手工解析 CVSS 向量字符串，容易出错且效率低',
                    '评分计算需要对照 FIRST 规范手动计算，公式复杂',
                    '缺乏标准化工具来比较不同 CVSS 向量的差异',
                    '无法方便地批量处理大量 CVSS 向量',
                    '集成到现有系统需要从零开发解析和计算逻辑',
                  ]}
                  renderItem={(item) => (
                    <List.Item style={{ padding: '8px 0', border: 'none' }}>
                      <Text type="danger">✗</Text> <Text>{item}</Text>
                    </List.Item>
                  )}
                />
              </Col>
              <Col xs={24} lg={12}>
                <Title level={4}>
                  <StarOutlined style={{ color: '#52c41a', marginRight: 8 }} />
                  有了 CVSS Skills 后
                </Title>
                <List
                  dataSource={[
                    '一行代码完成 CVSS 向量解析，自动验证格式和版本',
                    '精确计算 Base/Temporal/Environmental 评分，符合 FIRST 标准',
                    '内置多种距离度量算法，轻松比较向量差异',
                    'CLI 和 SDK 均支持批量处理，可处理 CSV 文件',
                    '提供完整 SDK 和 29+ CLI 命令，开箱即用',
                  ]}
                  renderItem={(item) => (
                    <List.Item style={{ padding: '8px 0', border: 'none' }}>
                      <Text style={{ color: '#52c41a' }}>✓</Text> <Text>{item}</Text>
                    </List.Item>
                  )}
                />
              </Col>
            </Row>
          </div>
        </div>

        {/* 快速开始 */}
        <div id="quickstart" style={{ padding: '80px 48px', maxWidth: 1200, margin: '0 auto' }}>
          <Title level={2} style={{ textAlign: 'center', marginBottom: 48 }}>
            快速开始
          </Title>
          <Row gutter={[48, 32]}>
            <Col xs={24} lg={14}>
              <Title level={4}>SDK 使用</Title>
              <div
                style={{
                  background: '#1e1e1e',
                  borderRadius: 8,
                  padding: 24,
                  color: '#d4d4d4',
                  fontFamily: 'monospace',
                  fontSize: 14,
                  lineHeight: 1.8,
                  overflow: 'auto',
                }}
              >
                <div>
                  <span style={{ color: '#6a9955' }}>// 解析 CVSS 向量</span>
                </div>
                <div>
                  <span style={{ color: '#569cd6' }}>import</span> (
                  <span style={{ color: '#ce9178' }}>"github.com/scagogogo/cvss-skills/pkg/parser"</span>
                  )
                </div>
                <div>
                  <div>result, err := parser.NewCvss3xParser(</div>
                  <div style={{ paddingLeft: 16 }}>
                    <span style={{ color: '#ce9178' }}>"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"</span>,
                  </div>
                  <div>).Parse()</div>
                </div>
                <div style={{ marginTop: 8 }}>
                  <span style={{ color: '#6a9955' }}>// 计算评分</span>
                </div>
                <div>cvssObj := cvss.NewCvss3x(result)</div>
                <div>baseScore := cvssObj.Score()</div>
                <div>severity := cvssObj.Severity()</div>
                <div style={{ marginTop: 8 }}>
                  <span style={{ color: '#6a9955' }}>// 输出: Score=9.8, Severity=Critical</span>
                </div>
              </div>
            </Col>
            <Col xs={24} lg={10}>
              <Title level={4}>安装</Title>
              <Space direction="vertical" size="middle" style={{ width: '100%' }}>
                <Card size="small" title="SDK 安装">
                  <code style={{ background: '#f5f5f5', padding: '4px 8px', borderRadius: 4, fontSize: 13 }}>
                    go get github.com/scagogogo/cvss-skills
                  </code>
                </Card>
                <Card size="small" title="CLI 安装">
                  <code style={{ background: '#f5f5f5', padding: '4px 8px', borderRadius: 4, fontSize: 13 }}>
                    go install github.com/scagogogo/cvss-skills/cmd/cvss-cli@latest
                  </code>
                </Card>
                <Card size="small" title="Homebrew 安装">
                  <code style={{ background: '#f5f5f5', padding: '4px 8px', borderRadius: 4, fontSize: 13 }}>
                    brew install scagogogo/tap/cvss-cli
                  </code>
                </Card>
              </Space>
            </Col>
          </Row>
        </div>

        {/* CLI 展示 */}
        <div id="cli" style={{ background: '#f8f9fa', padding: '80px 48px' }}>
          <div style={{ maxWidth: 1200, margin: '0 auto' }}>
            <Title level={2} style={{ textAlign: 'center', marginBottom: 8 }}>
              命令行工具
            </Title>
            <Paragraph style={{ textAlign: 'center', fontSize: 16, color: '#666', marginBottom: 48 }}>
              29+ 子命令，覆盖 CVSS 处理的全部场景
            </Paragraph>
            <Row gutter={[24, 24]}>
              <Col xs={24} lg={14}>
                <div
                  style={{
                    background: '#1e1e1e',
                    borderRadius: 8,
                    padding: 24,
                    fontFamily: 'monospace',
                    fontSize: 13,
                    lineHeight: 2,
                    color: '#d4d4d4',
                  }}
                >
                  <div><span style={{ color: '#6a995555' }}>$</span> <span style={{ color: '#dcdcaa' }}>cvss score</span> <span style={{ color: '#ce9178' }}>"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"</span></div>
                  <div style={{ color: '#4ec9b0' }}>  9.8 Critical</div>
                  <div style={{ marginTop: 8 }}><span style={{ color: '#6a995555' }}>$</span> <span style={{ color: '#dcdcaa' }}>cvss diff</span> <span style={{ color: '#ce9178' }}>"CVSS:3.1/AV:N/..."</span> <span style={{ color: '#ce9178' }}>"CVSS:3.1/AV:L/..."</span></div>
                  <div style={{ color: '#4ec9b0' }}>  AV: N→L, AC: L→H, PR: N→H, UI: N→R</div>
                  <div style={{ marginTop: 8 }}><span style={{ color: '#6a995555' }}>$</span> <span style={{ color: '#dcdcaa' }}>cvss distance</span> <span style={{ color: '#ce9178' }}>vector1 vector2</span> <span style={{ color: '#569cd6' }}>-m euclidean</span></div>
                  <div style={{ color: '#4ec9b0' }}>  Euclidean distance: 3.46</div>
                  <div style={{ marginTop: 8 }}><span style={{ color: '#6a995555' }}>$</span> <span style={{ color: '#dcdcaa' }}>cvss merge</span> <span style={{ color: '#ce9178' }}>base_vector temporal_vector</span></div>
                  <div style={{ marginTop: 8 }}><span style={{ color: '#6a995555' }}>$</span> <span style={{ color: '#dcdcaa' }}>cvss batch score</span> <span style={{ color: '#ce9178' }}>vectors.txt</span> <span style={{ color: '#569cd6' }}>-o results.csv</span></div>
                  <div style={{ marginTop: 8 }}><span style={{ color: '#6a995555' }}>$</span> <span style={{ color: '#dcdcaa' }}>cvss analyze</span> <span style={{ color: '#ce9178' }}>"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"</span></div>
                  <div style={{ color: '#4ec9b0' }}>  Impact: Confidentiality is most affected...</div>
                  <div style={{ color: '#4ec9b0' }}>  Sensitivity: Score is most sensitive to AV changes</div>
                </div>
              </Col>
              <Col xs={24} lg={10}>
                <Title level={5} style={{ marginBottom: 16 }}>常用命令一览</Title>
                <Space direction="vertical" size="small" style={{ width: '100%' }}>
                  {[
                    { cmd: 'score', desc: '计算评分和严重性', color: 'blue' },
                    { cmd: 'parse', desc: '解析 CVSS 向量', color: 'green' },
                    { cmd: 'validate', desc: '验证向量有效性', color: 'orange' },
                    { cmd: 'diff', desc: '比较两个向量差异', color: 'purple' },
                    { cmd: 'distance', desc: '计算向量间距离', color: 'cyan' },
                    { cmd: 'merge', desc: '合并多个向量', color: 'magenta' },
                    { cmd: 'analyze', desc: '深度影响分析', color: 'red' },
                    { cmd: 'build', desc: '交互式构建向量', color: 'geekblue' },
                    { cmd: 'batch', desc: '批量评分/验证', color: 'gold' },
                    { cmd: 'csv', desc: 'CSV 文件处理', color: 'lime' },
                    { cmd: 'json', desc: 'JSON 格式输出', color: 'volcano' },
                    { cmd: 'random', desc: '生成随机向量', color: 'orange' },
                  ].map(({ cmd, desc, color }) => (
                    <div key={cmd} style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                      <Tag color={color} style={{ minWidth: 80, textAlign: 'center', fontFamily: 'monospace' }}>
                        {cmd}
                      </Tag>
                      <Text type="secondary">{desc}</Text>
                    </div>
                  ))}
                </Space>
              </Col>
            </Row>
          </div>
        </div>

        {/* 优势对比 */}
        <div style={{ padding: '80px 48px', maxWidth: 1200, margin: '0 auto' }}>
          <Title level={2} style={{ textAlign: 'center', marginBottom: 48 }}>
            为什么选择 CVSS Skills？
          </Title>
          <Row gutter={[24, 24]}>
            <Col xs={24} sm={12} lg={6}>
              <Card hoverable style={{ textAlign: 'center', height: '100%' }}>
                <CheckCircleOutlined style={{ fontSize: 36, color: '#52c41a', marginBottom: 16 }} />
                <Title level={5}>符合 FIRST 标准</Title>
                <Text type="secondary">
                  评分计算完全遵循 FIRST CVSS v3.1 规范，确保评分结果的准确性和一致性
                </Text>
              </Card>
            </Col>
            <Col xs={24} sm={12} lg={6}>
              <Card hoverable style={{ textAlign: 'center', height: '100%' }}>
                <RocketOutlined style={{ fontSize: 36, color: '#1677ff', marginBottom: 16 }} />
                <Title level={5}>零依赖轻量</Title>
                <Text type="secondary">
                  纯 Go 实现，无 CGO 依赖，编译后单个二进制文件，跨平台部署零成本
                </Text>
              </Card>
            </Col>
            <Col xs={24} sm={12} lg={6}>
              <Card hoverable style={{ textAlign: 'center', height: '100%' }}>
                <CodeSandboxOutlined style={{ fontSize: 36, color: '#722ed1', marginBottom: 16 }} />
                <Title level={5}>SDK + CLI 双模式</Title>
                <Text type="secondary">
                  既可作为 Go SDK 集成到项目，也可通过功能丰富的 CLI 命令行直接使用
                </Text>
              </Card>
            </Col>
            <Col xs={24} sm={12} lg={6}>
              <Card hoverable style={{ textAlign: 'center', height: '100%' }}>
                <SafetyCertificateOutlined style={{ fontSize: 36, color: '#fa8c16', marginBottom: 16 }} />
                <Title level={5}>生产就绪</Title>
                <Text type="secondary">
                  完善的测试覆盖、错误处理、输入验证，已在多个生产环境中稳定运行
                </Text>
              </Card>
            </Col>
          </Row>
        </div>

        {/* 架构概览 */}
        <div style={{ background: '#f8f9fa', padding: '80px 48px' }}>
          <div style={{ maxWidth: 1200, margin: '0 auto' }}>
            <Title level={2} style={{ textAlign: 'center', marginBottom: 48 }}>
              项目架构
            </Title>
            <Row gutter={[48, 32]} align="middle">
              <Col xs={24} lg={12}>
                <Timeline
                  items={[
                    {
                      color: 'blue',
                      children: (
                        <>
                          <Text strong>cmd/cvss-cli/</Text>
                          <br />
                          <Text type="secondary">命令行工具入口，29+ 子命令，Cobra 框架</Text>
                        </>
                      ),
                    },
                    {
                      color: 'green',
                      children: (
                        <>
                          <Text strong>pkg/cvss/</Text>
                          <br />
                          <Text type="secondary">核心包：Cvss3x 结构体、评分计算、距离度量、向量操作</Text>
                        </>
                      ),
                    },
                    {
                      color: 'orange',
                      children: (
                        <>
                          <Text strong>pkg/parser/</Text>
                          <br />
                          <Text type="secondary">解析器：CVSS 3.x 向量解析，严格/宽松模式，版本校验</Text>
                        </>
                      ),
                    },
                    {
                      color: 'purple',
                      children: (
                        <>
                          <Text strong>pkg/vector/</Text>
                          <br />
                          <Text type="secondary">向量接口：统一的 CVSS 向量抽象接口</Text>
                        </>
                      ),
                    },
                  ]}
                />
              </Col>
              <Col xs={24} lg={12}>
                <Card>
                  <Title level={5}>数据流</Title>
                  <Paragraph type="secondary" style={{ fontSize: 15, lineHeight: 2 }}>
                    <Text code>CVSS String</Text>{' '}
                    <ArrowRightOutlined />{' '}
                    <Text code>Parser</Text>{' '}
                    <ArrowRightOutlined />{' '}
                    <Text code>Parsed Result</Text>{' '}
                    <ArrowRightOutlined />{' '}
                    <Text code>Cvss3x Object</Text>
                  </Paragraph>
                  <Paragraph type="secondary" style={{ fontSize: 15, lineHeight: 2 }}>
                    从 Cvss3x 对象可以执行：Score()、Severity()、Diff()、Merge()、
                    Distance()、Analyze()、JSON()、Validate() 等 60+ 操作
                  </Paragraph>
                </Card>
              </Col>
            </Row>
          </div>
        </div>

        {/* CTA */}
        <div
          style={{
            background: 'linear-gradient(135deg, #667eea 0%, #764ba2 100%)',
            padding: '80px 48px',
            textAlign: 'center',
          }}
        >
          <Title level={2} style={{ color: '#fff', marginBottom: 16 }}>
            开始使用 CVSS Skills
          </Title>
          <Paragraph style={{ color: 'rgba(255,255,255,0.8)', fontSize: 18, marginBottom: 32 }}>
            只需一行命令，即可拥有完整的 CVSS 处理能力
          </Paragraph>
          <Space size="large">
            <Button
              type="primary"
              size="large"
              icon={<RocketOutlined />}
              href="https://scagogogo.github.io/cvss-skills/docs/api/getting-started"
              target="_blank"
              style={{ height: 48, paddingInline: 32, fontSize: 16 }}
            >
              阅读文档
            </Button>
            <Button
              size="large"
              icon={<GithubOutlined />}
              href="https://github.com/scagogogo/cvss-skills"
              target="_blank"
              style={{ height: 48, paddingInline: 32, fontSize: 16, color: '#fff', borderColor: 'rgba(255,255,255,0.5)' }}
              ghost
            >
              查看源码
            </Button>
          </Space>
        </div>
      </Content>

      {/* Footer */}
      <Footer style={{ background: '#001529', color: 'rgba(255,255,255,0.65)', textAlign: 'center', padding: '24px 48px' }}>
        <Space direction="vertical" size="small">
          <Space size="large">
            <a href="https://github.com/scagogogo/cvss-skills" target="_blank" style={{ color: 'rgba(255,255,255,0.65)' }}>
              <GithubOutlined style={{ fontSize: 20 }} />
            </a>
          </Space>
          <Text style={{ color: 'rgba(255,255,255,0.45)' }}>
            © 2024-2026 CVSS Skills · Released under the MIT License
          </Text>
          <Text style={{ color: 'rgba(255,255,255,0.45)' }}>
            CVSS is a registered trademark of FIRST.org, Inc.
          </Text>
        </Space>
      </Footer>
    </Layout>
  )
}

export default HomePage

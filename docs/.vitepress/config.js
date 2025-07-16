import { defineConfig } from 'vitepress'

export default defineConfig({
  title: 'CVSS Parser',
  description: 'Go语言CVSS解析器 - 完整的API文档',
  base: '/cvss/',
  ignoreDeadLinks: true,
  
  themeConfig: {
    nav: [
      { text: '首页', link: '/' },
      { text: 'API文档', link: '/api/' },
      { text: '示例', link: '/examples/' },
      { text: 'GitHub', link: 'https://github.com/scagogogo/cvss' }
    ],

    sidebar: {
      '/api/': [
        {
          text: 'API 参考',
          items: [
            { text: '概述', link: '/api/' },
            { text: '快速开始', link: '/api/getting-started' },
            {
              text: '核心包',
              collapsed: false,
              items: [
                { text: 'cvss', link: '/api/cvss/' },
                { text: 'parser', link: '/api/parser/' },
                { text: 'vector', link: '/api/vector/' }
              ]
            },
            {
              text: 'CVSS 包详细文档',
              collapsed: false,
              items: [
                { text: 'Cvss3x', link: '/api/cvss/cvss3x' },
                { text: 'Calculator', link: '/api/cvss/calculator' },
                { text: 'DistanceCalculator', link: '/api/cvss/distance' },
                { text: 'JSON 支持', link: '/api/cvss/json' }
              ]
            },
            {
              text: 'Parser 包详细文档',
              collapsed: false,
              items: [
                { text: 'Cvss3xParser', link: '/api/parser/cvss3x-parser' },
                { text: 'VectorParser', link: '/api/parser/vector-parser' }
              ]
            },
            {
              text: 'Vector 包详细文档',
              collapsed: false,
              items: [
                { text: 'Vector 接口', link: '/api/vector/interface' },
                { text: '基础指标', link: '/api/vector/base-metrics' },
                { text: '时间指标', link: '/api/vector/temporal-metrics' },
                { text: '环境指标', link: '/api/vector/environmental-metrics' }
              ]
            }
          ]
        }
      ],
      '/examples/': [
        {
          text: '示例',
          items: [
            { text: '概述', link: '/examples/' },
            { text: '基础用法', link: '/examples/basic' },
            { text: '解析向量', link: '/examples/parsing' },
            { text: 'JSON 输出', link: '/examples/json' },
            { text: '时间指标', link: '/examples/temporal' },
            { text: '环境指标', link: '/examples/environmental' },
            { text: '距离计算', link: '/examples/distance' },
            { text: '向量比较', link: '/examples/comparison' },
            { text: '严重性级别', link: '/examples/severity' },
            { text: '边缘情况', link: '/examples/edge-cases' }
          ]
        }
      ]
    },

    socialLinks: [
      { icon: 'github', link: 'https://github.com/scagogogo/cvss' }
    ],

    footer: {
      message: 'Released under the MIT License.',
      copyright: 'Copyright © 2024 CVSS Parser'
    },

    search: {
      provider: 'local'
    }
  }
})

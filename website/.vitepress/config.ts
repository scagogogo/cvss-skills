import { defineConfig } from 'vitepress'

// CVSS Skills 官网配置
// 部署在 GitHub Pages 项目站点根路径: https://scagogogo.github.io/cvss-skills/
// API 深度文档部署在 /docs 子路径，由 docs/.vitepress 独立构建
export default defineConfig({
  lang: 'en-US',
  title: 'CVSS Skills',
  titleTemplate: false,
  description:
    'Professional CVSS v3.0/v3.1 toolkit — parse, score, validate, compare & build vulnerability vectors. Go SDK, CLI, Claude Code Skills, MCP.',
  base: '/cvss-skills/',
  cleanUrls: true,
  lastUpdated: true,
  ignoreDeadLinks: true,

  head: [
    ['meta', { name: 'theme-color', content: '#1677ff' }],
    [
      'meta',
      {
        name: 'keywords',
        content:
          'CVSS, CVSS 3.1, CVSS 3.0, vulnerability scoring, Go, CLI, Claude Code Skills, MCP',
      },
    ],
  ],

  locales: {
    root: {
      label: 'English',
      lang: 'en',
      themeConfig: {
        nav: nav(),
        sidebar: sidebar(),
        editLink: {
          text: 'Edit this page on GitHub',
          pattern: 'https://github.com/scagogogo/cvss-skills/edit/main/website/:path',
        },
      },
    },
    zh: {
      label: '简体中文',
      lang: 'zh-CN',
      themeConfig: {
        nav: navZh(),
        sidebar: sidebarZh(),
        editLink: {
          text: '在 GitHub 上编辑此页',
          pattern: 'https://github.com/scagogogo/cvss-skills/edit/main/website/:path',
        },
      },
    },
  },

  themeConfig: {
    logo: '/images/integration-methods.png',

    socialLinks: [
      { icon: 'github', link: 'https://github.com/scagogogo/cvss-skills' },
    ],

    search: { provider: 'local' },

    footer: {
      message: 'Released under the MIT License.',
      copyright: 'Copyright © 2024-2026 CVSS Skills',
    },
  },
})

function nav() {
  return [
    { text: 'Integration', link: '/integration/' },
    { text: 'CLI', link: '/cli/' },
    { text: 'Downloads', link: '/downloads/' },
    { text: 'API Docs', link: '/docs/api/' },
    { text: 'Examples', link: '/docs/examples/' },
    { text: 'GitHub', link: 'https://github.com/scagogogo/cvss-skills' },
  ]
}

function navZh() {
  return [
    { text: '集成方式', link: '/zh/integration/' },
    { text: '命令行', link: '/zh/cli/' },
    { text: '下载', link: '/zh/downloads/' },
    { text: 'API 文档', link: '/docs/zh/api/' },
    { text: '示例', link: '/docs/zh/examples/' },
    { text: 'GitHub', link: 'https://github.com/scagogogo/cvss-skills' },
  ]
}

function sidebar() {
  return [
    {
      text: 'Guide',
      items: [
        { text: 'Introduction', link: '/' },
        { text: 'Integration Methods', link: '/integration/' },
        { text: 'CLI Reference', link: '/cli/' },
        { text: 'Downloads', link: '/downloads/' },
      ],
    },
  ]
}

function sidebarZh() {
  return [
    {
      text: '指南',
      items: [
        { text: '简介', link: '/zh/' },
        { text: '集成方式', link: '/zh/integration/' },
        { text: '命令行参考', link: '/zh/cli/' },
        { text: '下载', link: '/zh/downloads/' },
      ],
    },
  ]
}

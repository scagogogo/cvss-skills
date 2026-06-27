import React from 'react'
import { ConfigProvider } from 'antd'
import { BrowserRouter, Routes, Route } from 'react-router-dom'
import HomePage from './pages/HomePage'

const App: React.FC = () => (
  <ConfigProvider
    theme={{
      token: {
        colorPrimary: '#1677ff',
        borderRadius: 8,
        fontFamily: '-apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif',
      },
    }}
  >
    <BrowserRouter basename="/cvss-skills">
      <Routes>
        <Route path="/" element={<HomePage />} />
      </Routes>
    </BrowserRouter>
  </ConfigProvider>
)

export default App

'use client'

import React from 'react'
import { AlertTriangle, RefreshCw, Home } from 'lucide-react'
import Link from 'next/link'

interface Props {
  children: React.ReactNode
  fallback?: React.ReactNode
}

interface State {
  hasError: boolean
  error?: Error
}

export class ErrorBoundary extends React.Component<Props, State> {
  constructor(props: Props) {
    super(props)
    this.state = { hasError: false }
  }

  static getDerivedStateFromError(error: Error): State {
    return { hasError: true, error }
  }

  componentDidCatch(error: Error, info: React.ErrorInfo) {
    console.error('[ErrorBoundary]', error, info)
  }

  render() {
    if (this.state.hasError) {
      if (this.props.fallback) return this.props.fallback
      return (
        <div className="flex flex-col items-center justify-center min-h-[400px] gap-4 text-center px-4">
          <div className="w-12 h-12 rounded-full bg-red-900/30 flex items-center justify-center">
            <AlertTriangle className="w-6 h-6 text-[#e8002d]" />
          </div>
          <div>
            <h2 className="text-white font-semibold text-lg">表示エラーが発生しました</h2>
            <p className="text-[#7d92b0] text-sm mt-1">{this.state.error?.message || '予期しないエラーが発生しました'}</p>
          </div>
          <div className="flex gap-3">
            <button
              onClick={() => this.setState({ hasError: false })}
              className="flex items-center gap-2 px-4 py-2 bg-[#1d2f4a] hover:bg-[#253a5a] text-white rounded-sm text-sm transition-colors"
            >
              <RefreshCw className="w-4 h-4" /> 再試行
            </button>
            <Link href="/dashboard" className="flex items-center gap-2 px-4 py-2 bg-[#0d1220] border border-[#1e2d42] hover:border-[#3d5068] text-[#7d92b0] hover:text-white rounded-sm text-sm transition-colors">
              <Home className="w-4 h-4" /> ダッシュボード
            </Link>
          </div>
        </div>
      )
    }
    return this.props.children
  }
}

// Functional wrapper for convenience
export function withErrorBoundary<P extends object>(
  Component: React.ComponentType<P>,
  fallback?: React.ReactNode
) {
  return function WrappedComponent(props: P) {
    return (
      <ErrorBoundary fallback={fallback}>
        <Component {...props} />
      </ErrorBoundary>
    )
  }
}

import { describe, it, expect } from 'vitest'
import { render, screen } from '@testing-library/react'
import {
  SeverityBadge,
  StatusBadge,
  OSIcon,
  AgentStatusBadge,
  getSeverityColor,
  getSeverityLabel,
} from '@/components/ui/badges'

// ─── SeverityBadge ────────────────────────────────────────────────────────────

describe('SeverityBadge', () => {
  it('severity 9 以上で CRITICAL と表示されること', () => {
    render(<SeverityBadge severity={9} />)
    expect(screen.getByText('CRITICAL')).toBeInTheDocument()
    expect(screen.getByText('Lv9')).toBeInTheDocument()
  })

  it('severity 7-8 で HIGH と表示されること', () => {
    render(<SeverityBadge severity={7} />)
    expect(screen.getByText('HIGH')).toBeInTheDocument()
  })

  it('severity 5-6 で MEDIUM と表示されること', () => {
    render(<SeverityBadge severity={5} />)
    expect(screen.getByText('MEDIUM')).toBeInTheDocument()
  })

  it('severity 3-4 で LOW と表示されること', () => {
    render(<SeverityBadge severity={3} />)
    expect(screen.getByText('LOW')).toBeInTheDocument()
  })

  it('severity 1-2 で INFO と表示されること', () => {
    render(<SeverityBadge severity={1} />)
    expect(screen.getByText('INFO')).toBeInTheDocument()
  })

  it('showLabel=false でラベルが非表示になること', () => {
    render(<SeverityBadge severity={9} showLabel={false} />)
    expect(screen.queryByText('CRITICAL')).toBeNull()
    expect(screen.getByText('Lv9')).toBeInTheDocument()
  })

  it('数値型の severity を受け付けること', () => {
    render(<SeverityBadge severity={10} />)
    expect(screen.getByText('CRITICAL')).toBeInTheDocument()
  })
})

// ─── StatusBadge ──────────────────────────────────────────────────────────────

describe('StatusBadge', () => {
  it('status "open" で 未対応 と表示されること', () => {
    render(<StatusBadge status="open" />)
    expect(screen.getByText('未対応')).toBeInTheDocument()
  })

  it('status "investigating" で 調査中 と表示されること', () => {
    render(<StatusBadge status="investigating" />)
    expect(screen.getByText('調査中')).toBeInTheDocument()
  })

  it('status "in_progress" で 対応中 と表示されること', () => {
    render(<StatusBadge status="in_progress" />)
    expect(screen.getByText('対応中')).toBeInTheDocument()
  })

  it('status "resolved" で 解決済み と表示されること', () => {
    render(<StatusBadge status="resolved" />)
    expect(screen.getByText('解決済み')).toBeInTheDocument()
  })

  it('status "false_positive" で 誤検知 と表示されること', () => {
    render(<StatusBadge status="false_positive" />)
    expect(screen.getByText('誤検知')).toBeInTheDocument()
  })

  it('status "auto_resolved" で 自動解決 と表示されること', () => {
    render(<StatusBadge status="auto_resolved" />)
    expect(screen.getByText('自動解決')).toBeInTheDocument()
  })

  it('status "escalated" で エスカレート と表示されること', () => {
    render(<StatusBadge status="escalated" />)
    expect(screen.getByText('エスカレート')).toBeInTheDocument()
  })

  it('未知の status でもそのまま表示されること', () => {
    render(<StatusBadge status="custom_status" />)
    expect(screen.getByText('custom_status')).toBeInTheDocument()
  })
})

// ─── OSIcon ───────────────────────────────────────────────────────────────────

describe('OSIcon', () => {
  it('windows で Windows と表示されること', () => {
    render(<OSIcon os="windows" />)
    expect(screen.getByText('Windows')).toBeInTheDocument()
  })

  it('linux で Linux と表示されること', () => {
    render(<OSIcon os="linux" />)
    expect(screen.getByText('Linux')).toBeInTheDocument()
  })

  it('darwin で macOS と表示されること', () => {
    render(<OSIcon os="darwin" />)
    expect(screen.getByText('macOS')).toBeInTheDocument()
  })

  it('未知の OS でも文字列がそのまま表示されること', () => {
    render(<OSIcon os="freebsd" />)
    expect(screen.getByText('freebsd')).toBeInTheDocument()
  })

  it('title 属性に OS 名が設定されること', () => {
    const { container } = render(<OSIcon os="windows" />)
    const el = container.querySelector('[title="windows"]')
    expect(el).not.toBeNull()
  })
})

// ─── AgentStatusBadge ─────────────────────────────────────────────────────────

describe('AgentStatusBadge', () => {
  it('status "online" で オンライン と表示されること', () => {
    render(<AgentStatusBadge status="online" />)
    expect(screen.getByText('オンライン')).toBeInTheDocument()
  })

  it('status "offline" で オフライン と表示されること', () => {
    render(<AgentStatusBadge status="offline" />)
    expect(screen.getByText('オフライン')).toBeInTheDocument()
  })

  it('status "isolated" で 隔離中 と表示されること', () => {
    render(<AgentStatusBadge status="isolated" />)
    expect(screen.getByText('隔離中')).toBeInTheDocument()
  })

  it('status "error" で エラー と表示されること', () => {
    render(<AgentStatusBadge status="error" />)
    expect(screen.getByText('エラー')).toBeInTheDocument()
  })

  // 'inactive' は DeadAgentCleanup が 30 日以上未確認のエージェントへ付ける状態。
  // 未知値フォールバックに落ちると「オフライン」と誤ラベル表示されるため、
  // 専用ラベルが出ることを固定する。
  it('status "inactive" で 非アクティブ と表示されること', () => {
    render(<AgentStatusBadge status="inactive" />)
    expect(screen.getByText('非アクティブ')).toBeInTheDocument()
    expect(screen.queryByText('オフライン')).toBeNull()
  })

  it('未知の status は offline にフォールバックされること', () => {
    render(<AgentStatusBadge status="unknown_xyz" />)
    expect(screen.getByText('オフライン')).toBeInTheDocument()
  })
})

// ─── getSeverityColor ─────────────────────────────────────────────────────────

describe('getSeverityColor', () => {
  it('severity 9+ で CRITICAL カラー (#e8002d) を返すこと', () => {
    expect(getSeverityColor(9)).toBe('#e8002d')
    expect(getSeverityColor(10)).toBe('#e8002d')
  })

  it('severity 7-8 で HIGH カラー (#ff6b35) を返すこと', () => {
    expect(getSeverityColor(7)).toBe('#ff6b35')
    expect(getSeverityColor(8)).toBe('#ff6b35')
  })

  it('severity 5-6 で MEDIUM カラー (#ff9800) を返すこと', () => {
    expect(getSeverityColor(5)).toBe('#ff9800')
    expect(getSeverityColor(6)).toBe('#ff9800')
  })

  it('severity 3-4 で LOW カラー (#1a6bff) を返すこと', () => {
    expect(getSeverityColor(3)).toBe('#1a6bff')
    expect(getSeverityColor(4)).toBe('#1a6bff')
  })

  it('severity 1-2 で INFO カラー (#3d5068) を返すこと', () => {
    expect(getSeverityColor(1)).toBe('#3d5068')
    expect(getSeverityColor(2)).toBe('#3d5068')
  })
})

// ─── getSeverityLabel ─────────────────────────────────────────────────────────

describe('getSeverityLabel', () => {
  it('severity 9+ で CRITICAL を返すこと', () => {
    expect(getSeverityLabel(9)).toBe('CRITICAL')
    expect(getSeverityLabel(10)).toBe('CRITICAL')
  })

  it('severity 7-8 で HIGH を返すこと', () => {
    expect(getSeverityLabel(7)).toBe('HIGH')
    expect(getSeverityLabel(8)).toBe('HIGH')
  })

  it('severity 5-6 で MEDIUM を返すこと', () => {
    expect(getSeverityLabel(5)).toBe('MEDIUM')
  })

  it('severity 3-4 で LOW を返すこと', () => {
    expect(getSeverityLabel(3)).toBe('LOW')
  })

  it('severity 1-2 で INFO を返すこと', () => {
    expect(getSeverityLabel(1)).toBe('INFO')
    expect(getSeverityLabel(0)).toBe('INFO')
  })
})

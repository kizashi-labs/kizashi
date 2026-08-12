import { describe, it, expect, vi } from 'vitest'
import { render, screen } from '@testing-library/react'
import { AlertCard } from '@/components/alerts/AlertCard'
import type { Alert } from '@/types/api'

// next/link をモック
vi.mock('next/link', () => ({
  default: ({ children, href, className, style }: {
    children: React.ReactNode
    href: string
    className?: string
    style?: React.CSSProperties
  }) => (
    <a href={href} className={className} style={style}>{children}</a>
  ),
}))

// lucide-react をモック
vi.mock('lucide-react', () => ({
  Bot:          () => <span data-testid="icon-bot" />,
  ChevronRight: () => <span data-testid="icon-chevron" />,
  Monitor:      () => <span data-testid="icon-monitor" />,
  MessageSquare:() => <span data-testid="icon-message" />,
  UserCheck:    () => <span data-testid="icon-usercheck" />,
  Clock:        () => <span data-testid="icon-clock" />,
}))

// date-fns はそのまま使用（軽量で副作用なし）

function makeAlert(overrides: Partial<Alert> = {}): Alert {
  return {
    id: 'alert-uuid-1',
    title: 'SuspiciousProcess Detection',
    rule_name: 'TestRule',
    severity: 7,
    status: 'open',
    agent_id: 'agent-1',
    agent_hostname: 'host-win-01',
    agent_os: 'windows',
    mitre_technique: 'T1059',
    ai_analyzed: false,
    ai_summary: undefined,
    assigned_to: undefined,
    assigned_to_name: undefined,
    comment_count: 0,
    created_at: new Date().toISOString(),
    updated_at: new Date().toISOString(),
    ...overrides,
  }
}

// ─── フルカード ────────────────────────────────────────────────────────────────

describe('AlertCard (フルサイズ)', () => {
  it('タイトルが表示されること', () => {
    render(<AlertCard alert={makeAlert()} />)
    expect(screen.getByText('SuspiciousProcess Detection')).toBeInTheDocument()
  })

  it('ホスト名が表示されること', () => {
    render(<AlertCard alert={makeAlert()} />)
    expect(screen.getByText('host-win-01')).toBeInTheDocument()
  })

  it('アラート詳細ページへのリンクが正しいこと', () => {
    const { container } = render(<AlertCard alert={makeAlert({ id: 'alert-uuid-1' })} />)
    const link = container.querySelector('a')
    expect(link?.getAttribute('href')).toBe('/alerts/alert-uuid-1')
  })

  it('severity バッジが表示されること', () => {
    render(<AlertCard alert={makeAlert({ severity: 9 })} />)
    expect(screen.getByText('CRITICAL')).toBeInTheDocument()
  })

  it('status バッジが表示されること', () => {
    render(<AlertCard alert={makeAlert({ status: 'investigating' })} />)
    expect(screen.getByText('調査中')).toBeInTheDocument()
  })

  it('ai_analyzed=true で AI バッジが表示されること', () => {
    render(<AlertCard alert={makeAlert({ ai_analyzed: true })} />)
    expect(screen.getByTestId('icon-bot')).toBeInTheDocument()
    expect(screen.getByText('AI')).toBeInTheDocument()
  })

  it('ai_analyzed=false で AI バッジが非表示なこと', () => {
    render(<AlertCard alert={makeAlert({ ai_analyzed: false })} />)
    expect(screen.queryByText('AI')).toBeNull()
  })

  it('ai_summary が指定された場合に表示されること', () => {
    render(<AlertCard alert={makeAlert({ ai_analyzed: true, ai_summary: 'AI解析結果の要約' })} />)
    expect(screen.getByText('AI解析結果の要約')).toBeInTheDocument()
  })

  it('ai_summary がない場合は表示されないこと', () => {
    render(<AlertCard alert={makeAlert({ ai_summary: undefined })} />)
    expect(screen.queryByText('AI解析結果の要約')).toBeNull()
  })

  it('assigned_to_name が表示されること', () => {
    render(<AlertCard alert={makeAlert({ assigned_to_name: 'taro.yamada' })} />)
    expect(screen.getByText('taro.yamada')).toBeInTheDocument()
    expect(screen.getByTestId('icon-usercheck')).toBeInTheDocument()
  })

  it('comment_count > 0 でコメント数が表示されること', () => {
    render(<AlertCard alert={makeAlert({ comment_count: 3 })} />)
    expect(screen.getByText('3')).toBeInTheDocument()
    expect(screen.getByTestId('icon-message')).toBeInTheDocument()
  })

  it('comment_count = 0 でコメント数が非表示なこと', () => {
    render(<AlertCard alert={makeAlert({ comment_count: 0 })} />)
    expect(screen.queryByTestId('icon-message')).toBeNull()
  })

  it('resolved ステータスで AlertAge が表示されないこと', () => {
    render(<AlertCard alert={makeAlert({ status: 'resolved' })} />)
    // AlertAge は resolved のとき null を返す → Clock アイコンなし
    expect(screen.queryByTestId('icon-clock')).toBeNull()
  })

  it('open ステータスで AlertAge が表示されること', () => {
    render(<AlertCard alert={makeAlert({ status: 'open' })} />)
    expect(screen.getByTestId('icon-clock')).toBeInTheDocument()
  })
})

// ─── コンパクトカード ──────────────────────────────────────────────────────────

describe('AlertCard (compact=true)', () => {
  it('タイトルが表示されること', () => {
    render(<AlertCard alert={makeAlert()} compact />)
    expect(screen.getByText('SuspiciousProcess Detection')).toBeInTheDocument()
  })

  it('ホスト名が表示されること', () => {
    render(<AlertCard alert={makeAlert()} compact />)
    expect(screen.getByText(/host-win-01/)).toBeInTheDocument()
  })

  it('アラート詳細ページへのリンクが正しいこと', () => {
    const { container } = render(<AlertCard alert={makeAlert({ id: 'cmp-1' })} compact />)
    const link = container.querySelector('a')
    expect(link?.getAttribute('href')).toBe('/alerts/cmp-1')
  })

  it('ai_analyzed=true で Bot アイコンが表示されること', () => {
    render(<AlertCard alert={makeAlert({ ai_analyzed: true })} compact />)
    expect(screen.getByTestId('icon-bot')).toBeInTheDocument()
  })

  it('ai_analyzed=false で Bot アイコンが非表示なこと', () => {
    render(<AlertCard alert={makeAlert({ ai_analyzed: false })} compact />)
    expect(screen.queryByTestId('icon-bot')).toBeNull()
  })

  it('status バッジが表示されること', () => {
    render(<AlertCard alert={makeAlert({ status: 'resolved' })} compact />)
    expect(screen.getByText('解決済み')).toBeInTheDocument()
  })
})

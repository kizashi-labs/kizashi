import { describe, it, expect } from 'vitest'
import { render, screen } from '@testing-library/react'
import { StatCard } from '@/components/ui/StatCard'

const DummyIcon = () => <svg data-testid="dummy-icon" />

describe('StatCard', () => {
  it('title と value が表示されること', () => {
    render(<StatCard title="総アラート" value={42} icon={<DummyIcon />} color="red" />)
    expect(screen.getByText('総アラート')).toBeInTheDocument()
    expect(screen.getByText('42')).toBeInTheDocument()
  })

  it('string 型の value も表示されること', () => {
    render(<StatCard title="ステータス" value="正常" icon={<DummyIcon />} color="green" />)
    expect(screen.getByText('正常')).toBeInTheDocument()
  })

  it('subtext が指定された場合に表示されること', () => {
    render(
      <StatCard title="タイトル" value={10} icon={<DummyIcon />} color="blue" subtext="前日比 +5" />
    )
    expect(screen.getByText('前日比 +5')).toBeInTheDocument()
  })

  it('subtext が指定されない場合は表示されないこと', () => {
    const { container } = render(
      <StatCard title="タイトル" value={10} icon={<DummyIcon />} color="blue" />
    )
    // subtext 用の <p> は存在しない (value と title 以外の p が余分にないこと)
    const paragraphs = container.querySelectorAll('p')
    expect(paragraphs).toHaveLength(2) // title + value のみ
  })

  it('trend > 0 で ↑ と正の値が表示されること', () => {
    render(<StatCard title="タイトル" value={10} icon={<DummyIcon />} color="orange" trend={15} />)
    expect(screen.getByText(/↑/)).toBeInTheDocument()
    expect(screen.getByText(/15%/)).toBeInTheDocument()
  })

  it('trend < 0 で ↓ と絶対値が表示されること', () => {
    render(<StatCard title="タイトル" value={10} icon={<DummyIcon />} color="green" trend={-20} />)
    expect(screen.getByText(/↓/)).toBeInTheDocument()
    expect(screen.getByText(/20%/)).toBeInTheDocument()
  })

  it('trend = 0 で → が表示されること', () => {
    render(<StatCard title="タイトル" value={10} icon={<DummyIcon />} color="gray" trend={0} />)
    expect(screen.getByText(/→/)).toBeInTheDocument()
  })

  it('trend が指定されない場合はトレンド表示がないこと', () => {
    render(<StatCard title="タイトル" value={10} icon={<DummyIcon />} color="cyan" />)
    expect(screen.queryByText(/↑/)).toBeNull()
    expect(screen.queryByText(/↓/)).toBeNull()
    expect(screen.queryByText(/→/)).toBeNull()
  })

  it('icon が描画されること', () => {
    render(<StatCard title="タイトル" value={0} icon={<DummyIcon />} color="blue" />)
    expect(screen.getByTestId('dummy-icon')).toBeInTheDocument()
  })

  it('href が指定された場合は <a> タグでラップされること', () => {
    const { container } = render(
      <StatCard title="タイトル" value={5} icon={<DummyIcon />} color="red" href="/alerts" />
    )
    const anchor = container.querySelector('a')
    expect(anchor).not.toBeNull()
    expect(anchor?.getAttribute('href')).toBe('/alerts')
  })

  it('href が指定されない場合は <a> タグなしで描画されること', () => {
    const { container } = render(
      <StatCard title="タイトル" value={5} icon={<DummyIcon />} color="red" />
    )
    expect(container.querySelector('a')).toBeNull()
  })

  it('全カラーバリアントが例外なく描画されること', () => {
    const colors = ['blue', 'green', 'red', 'orange', 'yellow', 'gray', 'cyan'] as const
    colors.forEach((color) => {
      const { unmount } = render(
        <StatCard title={`title-${color}`} value={1} icon={<DummyIcon />} color={color} />
      )
      expect(screen.getByText(`title-${color}`)).toBeInTheDocument()
      unmount()
    })
  })
})

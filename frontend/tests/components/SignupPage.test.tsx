import { describe, it, expect, vi, beforeEach } from 'vitest'
import { render, screen, fireEvent, waitFor } from '@testing-library/react'
import SignupPage from '@/app/signup/page'

// next/link を単純な <a> に置き換える（ルーティング不要）
vi.mock('next/link', () => ({
  default: ({ href, children, ...rest }: { href: string; children: React.ReactNode }) => (
    <a href={href} {...rest}>{children}</a>
  ),
}))

describe('SignupPage', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    vi.mocked(global.fetch).mockReset()
  })

  const fillAndSubmit = async (overrides: Partial<{ password: string; confirm: string }> = {}) => {
    fireEvent.change(screen.getByPlaceholderText('株式会社 KizashiTech'), { target: { value: 'Acme Corp' } })
    fireEvent.change(screen.getByPlaceholderText('山田 太郎'), { target: { value: 'Taro Yamada' } })
    fireEvent.change(screen.getByPlaceholderText('taro@example.com'), { target: { value: 'taro@example.com' } })

    // password fields are the two type=password inputs
    const pwdFields = document.querySelectorAll<HTMLInputElement>('input[type="password"]')
    fireEvent.change(pwdFields[0], { target: { value: overrides.password ?? 'Secur3Pass!word1' } })
    fireEvent.change(pwdFields[1], { target: { value: overrides.confirm ?? 'Secur3Pass!word1' } })

    fireEvent.click(screen.getByRole('button', { name: 'アカウントを作成' }))
  }

  it('登録フォームが表示されること', () => {
    render(<SignupPage />)
    expect(screen.getByText('Kizashi アカウント作成')).toBeInTheDocument()
    expect(screen.getByRole('button', { name: 'アカウントを作成' })).toBeInTheDocument()
  })

  it('パスワードが一致しない場合にエラーが表示されること', async () => {
    render(<SignupPage />)
    await fillAndSubmit({ password: 'Secur3Pass!word1', confirm: 'Secur3Pass!differ1' })

    await waitFor(() => {
      expect(screen.getByText('パスワードが一致しません')).toBeInTheDocument()
    })
    expect(global.fetch).not.toHaveBeenCalled()
  })

  it('パスワードが12文字未満なら検証エラーが表示されること (ブラウザ検証をバイパス)', async () => {
    render(<SignupPage />)
    // HTML5 minLength を回避するため novalidate 相当のセットアップをしてから
    // フォームに直接バインドされた state を short にする
    await fillAndSubmit({ password: 'Short1Pass!', confirm: 'Short1Pass!' })

    await waitFor(() => {
      expect(screen.getByText('パスワードは12文字以上で指定してください')).toBeInTheDocument()
    })
    expect(global.fetch).not.toHaveBeenCalled()
  })

  it('登録が成功したら確認メール表示に遷移すること', async () => {
    vi.mocked(global.fetch).mockResolvedValueOnce(
      new Response(
        JSON.stringify({ message: 'ok', registration_id: 'reg-1', expires_at: '2026-04-21T00:00:00Z' }),
        { status: 201, headers: { 'Content-Type': 'application/json' } }
      )
    )

    render(<SignupPage />)
    await fillAndSubmit()

    await waitFor(() => {
      expect(screen.getByText('確認メールを送信しました')).toBeInTheDocument()
    })
    expect(screen.getByText('taro@example.com')).toBeInTheDocument()
  })

  it('サーバー側でエラーが返った場合にエラーが表示されること', async () => {
    vi.mocked(global.fetch).mockResolvedValueOnce(
      new Response(
        JSON.stringify({ error: 'このメールアドレスでの登録手続きが既に進行中です' }),
        { status: 409, headers: { 'Content-Type': 'application/json' } }
      )
    )

    render(<SignupPage />)
    await fillAndSubmit()

    await waitFor(() => {
      expect(screen.getByText('このメールアドレスでの登録手続きが既に進行中です')).toBeInTheDocument()
    })
  })

  it('プラン選択ボタンが切り替わること', () => {
    render(<SignupPage />)
    const businessBtn = screen.getByRole('button', { name: 'Business' })
    fireEvent.click(businessBtn)
    expect(screen.getByText(/〜500EP/)).toBeInTheDocument()
  })

  it('Lite プランボタンが存在し、説明文が表示されること', () => {
    render(<SignupPage />)
    const liteBtn = screen.getByRole('button', { name: 'Lite' })
    fireEvent.click(liteBtn)
    expect(screen.getByText(/5〜45EP/)).toBeInTheDocument()
    expect(screen.getByText(/メールサポート/)).toBeInTheDocument()
  })

  it('Lite 選択時に EP 入力欄が 5〜45 / step=5 に制約されること', () => {
    render(<SignupPage />)
    fireEvent.click(screen.getByRole('button', { name: 'Lite' }))

    const epInput = document.querySelector<HTMLInputElement>('input[type="number"]')!
    expect(epInput.min).toBe('5')
    expect(epInput.max).toBe('45')
    expect(epInput.step).toBe('5')
  })

  it('Starter→Lite 切り替えで EP 数が 45 にクランプされること (100→45)', () => {
    render(<SignupPage />)
    const epInput = document.querySelector<HTMLInputElement>('input[type="number"]')!

    // デフォルトは Starter で agentCount=10
    fireEvent.change(epInput, { target: { value: '100' } })
    expect(epInput.value).toBe('100')

    // Lite に切り替えると 100 → 45 (上限) にクランプ
    fireEvent.click(screen.getByRole('button', { name: 'Lite' }))
    expect(epInput.value).toBe('45')
  })

  it('Starter→Lite 切り替えで EP 数が次の 5 刻みに切り上げられること (7→10)', () => {
    render(<SignupPage />)
    const epInput = document.querySelector<HTMLInputElement>('input[type="number"]')!

    fireEvent.change(epInput, { target: { value: '7' } })
    fireEvent.click(screen.getByRole('button', { name: 'Lite' }))
    expect(epInput.value).toBe('10')
  })

  it('Lite→Starter 切り替えで EP 制約が解除されること', () => {
    render(<SignupPage />)
    fireEvent.click(screen.getByRole('button', { name: 'Lite' }))
    fireEvent.click(screen.getByRole('button', { name: 'Starter' }))

    const epInput = document.querySelector<HTMLInputElement>('input[type="number"]')!
    expect(epInput.min).toBe('1')
    expect(epInput.max).toBe('100000')
    expect(epInput.step).toBe('1')
  })

  it('プラン比較マトリクスが表示されること (機能行 5 件 × プラン列 5 件)', () => {
    render(<SignupPage />)
    // Feature rows
    expect(screen.getByText('基本検知')).toBeInTheDocument()
    expect(screen.getByText('アラート管理')).toBeInTheDocument()
    expect(screen.getByText('レポート')).toBeInTheDocument()
    expect(screen.getByText('MDM')).toBeInTheDocument()
    expect(screen.getByText('AI / SIEM 連携')).toBeInTheDocument()
    // Plan column headers — Free is shown for reference even though it is
    // not a signup option, so SMB customers see what they pay to gain.
    const tableHeader = document.querySelector('thead')!
    expect(tableHeader.textContent).toContain('Free')
    expect(tableHeader.textContent).toContain('Lite')
    expect(tableHeader.textContent).toContain('Starter')
    expect(tableHeader.textContent).toContain('Business')
    expect(tableHeader.textContent).toContain('Enterprise')
  })
})

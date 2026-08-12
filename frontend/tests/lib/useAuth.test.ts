import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest'
import { renderHook, act, waitFor } from '@testing-library/react'
import React from 'react'
import { AuthProvider, useAuth } from '@/lib/auth'

// next/navigation をモック
const mockRouterPush = vi.fn()
vi.mock('next/navigation', () => ({
  useRouter: () => ({
    push: mockRouterPush,
  }),
}))

// wrapper として AuthProvider を使用するヘルパー
function makeWrapper() {
  return function Wrapper({ children }: { children: React.ReactNode }) {
    return React.createElement(AuthProvider, null, children)
  }
}

describe('useAuth', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    localStorage.clear()
    vi.mocked(global.fetch).mockReset()
  })

  afterEach(() => {
    localStorage.clear()
  })

  it('初期状態: token=null, isLoading=true', () => {
    // useEffect が走る前の瞬間のみ isLoading=true であるが、
    // renderHook は同期的にマウントされるため useEffect が直後に走る。
    // よって初期値としての token=null かつ初期描画時の isLoading=true を確認する。
    let initialToken: string | null | undefined
    let initialIsLoading: boolean | undefined

    const { result } = renderHook(
      () => {
        const auth = useAuth()
        // 初回レンダリング時の値をキャプチャ
        if (initialToken === undefined) {
          initialToken = auth.token
          initialIsLoading = auth.isLoading
        }
        return auth
      },
      { wrapper: makeWrapper() }
    )

    // 初回レンダリング時に token=null であること
    expect(initialToken).toBeNull()
    // 初回レンダリング時に isLoading=true であること
    expect(initialIsLoading).toBe(true)

    // useEffect 実行後は isLoading=false になること
    return waitFor(() => {
      expect(result.current.isLoading).toBe(false)
    })
  })

  it('localStorage に token がなければ token=null のまま isLoading=false になること', async () => {
    const { result } = renderHook(() => useAuth(), { wrapper: makeWrapper() })

    await waitFor(() => {
      expect(result.current.isLoading).toBe(false)
    })

    expect(result.current.token).toBeNull()
    expect(result.current.user).toBeNull()
  })

  it('localStorage に token があれば読み込まれること', async () => {
    const token = 'stored-token'
    const user = { id: '1', email: 'test@example.com', full_name: 'Test User', role: 'admin' }
    localStorage.setItem('edr_token', token)
    localStorage.setItem('edr_user', JSON.stringify(user))

    const { result } = renderHook(() => useAuth(), { wrapper: makeWrapper() })

    await waitFor(() => {
      expect(result.current.isLoading).toBe(false)
    })

    expect(result.current.token).toBe(token)
    expect(result.current.user).toEqual(user)
  })

  it('localStorage に token はあるが user が不正な JSON の場合はクリアされること', async () => {
    localStorage.setItem('edr_token', 'some-token')
    localStorage.setItem('edr_user', 'invalid json')

    const { result } = renderHook(() => useAuth(), { wrapper: makeWrapper() })

    await waitFor(() => {
      expect(result.current.isLoading).toBe(false)
    })

    expect(result.current.token).toBeNull()
    expect(result.current.user).toBeNull()
    expect(localStorage.getItem('edr_token')).toBeNull()
    expect(localStorage.getItem('edr_user')).toBeNull()
  })

  it('login() でトークンが設定されること', async () => {
    const token = 'new-token'
    const user = { id: '2', email: 'user@example.com', full_name: 'Login User', role: 'viewer' }

    vi.mocked(global.fetch).mockResolvedValueOnce(
      new Response(
        JSON.stringify({ token, user, mfa_required: false, must_change_password: false }),
        { status: 200, headers: { 'Content-Type': 'application/json' } }
      )
    )

    const { result } = renderHook(() => useAuth(), { wrapper: makeWrapper() })

    await waitFor(() => {
      expect(result.current.isLoading).toBe(false)
    })

    await act(async () => {
      await result.current.login('user@example.com', 'password123')
    })

    expect(result.current.token).toBe(token)
    expect(result.current.user).toEqual(user)
    expect(localStorage.getItem('edr_token')).toBe(token)
  })

  it('login() が成功したら /dashboard にリダイレクトされること', async () => {
    const token = 'dash-token'
    const user = { id: '3', email: 'dash@example.com', full_name: 'Dash User', role: 'analyst' }

    vi.mocked(global.fetch).mockResolvedValueOnce(
      new Response(
        JSON.stringify({ token, user, mfa_required: false, must_change_password: false }),
        { status: 200, headers: { 'Content-Type': 'application/json' } }
      )
    )

    const { result } = renderHook(() => useAuth(), { wrapper: makeWrapper() })

    await waitFor(() => {
      expect(result.current.isLoading).toBe(false)
    })

    await act(async () => {
      await result.current.login('dash@example.com', 'password')
    })

    expect(mockRouterPush).toHaveBeenCalledWith('/dashboard')
  })

  it('login() でパスワード変更必須の場合 /change-password にリダイレクトされること', async () => {
    const token = 'change-pw-token'
    const user = { id: '4', email: 'pw@example.com', full_name: 'PW User', role: 'viewer' }

    vi.mocked(global.fetch).mockResolvedValueOnce(
      new Response(
        JSON.stringify({ token, user, mfa_required: false, must_change_password: true }),
        { status: 200, headers: { 'Content-Type': 'application/json' } }
      )
    )

    const { result } = renderHook(() => useAuth(), { wrapper: makeWrapper() })

    await waitFor(() => {
      expect(result.current.isLoading).toBe(false)
    })

    await act(async () => {
      await result.current.login('pw@example.com', 'password')
    })

    expect(mockRouterPush).toHaveBeenCalledWith('/change-password')
  })

  it('login() で MFA が必要な場合 mfaRequired=true を返すこと', async () => {
    vi.mocked(global.fetch).mockResolvedValueOnce(
      new Response(
        JSON.stringify({ mfa_required: true, pre_auth_token: 'pre-auth-123' }),
        { status: 200, headers: { 'Content-Type': 'application/json' } }
      )
    )

    const { result } = renderHook(() => useAuth(), { wrapper: makeWrapper() })

    await waitFor(() => {
      expect(result.current.isLoading).toBe(false)
    })

    let loginResult: { mfaRequired: boolean; preAuthToken?: string } | undefined
    await act(async () => {
      loginResult = await result.current.login('mfa@example.com', 'password')
    })

    expect(loginResult).toEqual({ mfaRequired: true, preAuthToken: 'pre-auth-123' })
    // MFA 必須の場合はトークンが設定されないこと
    expect(result.current.token).toBeNull()
  })

  it('login() が失敗した場合にエラーが throw されること', async () => {
    vi.mocked(global.fetch).mockResolvedValueOnce(
      new Response(
        JSON.stringify({ error: 'Invalid credentials' }),
        { status: 401, headers: { 'Content-Type': 'application/json' } }
      )
    )

    const { result } = renderHook(() => useAuth(), { wrapper: makeWrapper() })

    await waitFor(() => {
      expect(result.current.isLoading).toBe(false)
    })

    await expect(
      act(async () => {
        await result.current.login('wrong@example.com', 'wrong')
      })
    ).rejects.toThrow('Invalid credentials')
  })

  it('logout() でトークンがクリアされること', async () => {
    const token = 'logout-token'
    const user = { id: '5', email: 'logout@example.com', full_name: 'Logout User', role: 'viewer' }
    localStorage.setItem('edr_token', token)
    localStorage.setItem('edr_user', JSON.stringify(user))

    const { result } = renderHook(() => useAuth(), { wrapper: makeWrapper() })

    await waitFor(() => {
      expect(result.current.token).toBe(token)
      expect(result.current.isLoading).toBe(false)
    })

    await act(async () => {
      await result.current.logout()
    })

    expect(result.current.token).toBeNull()
    expect(result.current.user).toBeNull()
    expect(localStorage.getItem('edr_token')).toBeNull()
    expect(localStorage.getItem('edr_user')).toBeNull()
  })

  it('logout() で /login にリダイレクトされること', async () => {
    const { result } = renderHook(() => useAuth(), { wrapper: makeWrapper() })

    await waitFor(() => {
      expect(result.current.isLoading).toBe(false)
    })

    await act(async () => {
      await result.current.logout()
    })

    expect(mockRouterPush).toHaveBeenCalledWith('/login')
  })

  it('AuthProvider なしで useAuth を使うと エラーが throw されること', () => {
    // エラーをコンソールに出力しないよう抑制
    const consoleSpy = vi.spyOn(console, 'error').mockImplementation(() => {})
    expect(() => {
      renderHook(() => useAuth())
    }).toThrow('useAuth must be used within AuthProvider')
    consoleSpy.mockRestore()
  })
})

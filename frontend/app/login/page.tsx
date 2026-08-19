'use client'

import { useState, FormEvent, useEffect } from 'react'
import { useRouter } from 'next/navigation'
import { useAuth } from '@/lib/auth'
import { Shield, KeyRound, Lock, User } from 'lucide-react'

interface SSOProvider {
  id: string
  name: string
}

export default function LoginPage() {
  const { login, verifyMFA } = useAuth()
  const router = useRouter()
  const [username, setUsername] = useState('')
  const [password, setPassword] = useState('')
  const [error, setError] = useState('')
  const [isLoading, setIsLoading] = useState(false)

  const [mfaState, setMfaState] = useState<{ preAuthToken: string } | null>(null)
  const [mfaCode, setMfaCode] = useState('')

  // SSO providers — fetched from public endpoint on mount
  const [ssoProviders, setSsoProviders] = useState<SSOProvider[]>([])

  useEffect(() => {
    // Silently fetch enabled SSO providers to conditionally show the SSO button.
    // Failures are intentionally swallowed — SSO is optional.
    fetch('/api/v1/auth/sso/providers')
      .then(r => r.ok ? r.json() : { providers: [] })
      .then(data => setSsoProviders(data.providers ?? []))
      .catch(() => { /* SSO unavailable — hide button */ })
  }, [])

  const handleSubmit = async (e: FormEvent) => {
    e.preventDefault()
    setError('')
    setIsLoading(true)
    try {
      const result = await login(username, password)
      if (result.mfaRequired && result.preAuthToken) {
        setMfaState({ preAuthToken: result.preAuthToken })
      }
    } catch (err) {
      setError(err instanceof Error ? err.message : 'ログインに失敗しました')
    } finally {
      setIsLoading(false)
    }
  }

  const handleMFASubmit = async (e: FormEvent) => {
    e.preventDefault()
    if (!mfaState) return
    setError('')
    setIsLoading(true)
    try {
      await verifyMFA(mfaState.preAuthToken, mfaCode)
    } catch (err) {
      setError(err instanceof Error ? err.message : 'MFA認証に失敗しました')
      setMfaCode('')
    } finally {
      setIsLoading(false)
    }
  }

  return (
    <div className="min-h-screen flex bg-[#080c14]">
      {/* Left panel - brand */}
      <div className="hidden lg:flex w-[420px] shrink-0 flex-col bg-[#0d1220] border-r border-[#1e2d42] items-center justify-center p-12 relative overflow-hidden">
        {/* Background grid decoration */}
        <div className="absolute inset-0 opacity-[0.03]"
             style={{
               backgroundImage: 'linear-gradient(#e2e8f4 1px, transparent 1px), linear-gradient(90deg, #e2e8f4 1px, transparent 1px)',
               backgroundSize: '32px 32px',
             }} />
        {/* Red glow */}
        <div className="absolute top-1/2 left-1/2 -translate-x-1/2 -translate-y-1/2 w-64 h-64 rounded-full bg-[#e8002d]/5 blur-3xl pointer-events-none" />

        <div className="relative z-10 flex flex-col items-center text-center">
          <div className="w-20 h-20 rounded-xl bg-linear-to-br from-[#e8002d] to-[#a80020] flex items-center justify-center shadow-falcon-glow-red mb-6">
            <Shield className="w-10 h-10 text-white" strokeWidth={1.5} />
          </div>
          <h1 className="text-2xl font-bold text-white tracking-tight mb-2">Kizashi</h1>
          <p className="text-[#3d5068] text-sm uppercase tracking-widest font-medium mb-8">
            Endpoint Protection Platform
          </p>

          <div className="space-y-3 w-full max-w-xs">
            {[
              { label: 'リアルタイム検知', desc: 'AI駆動の脅威検知' },
              { label: '自動対応', desc: 'プレイブックで即座に対処' },
              { label: '完全可視性', desc: '全エンドポイントを一元管理' },
            ].map(item => (
              <div key={item.label}
                   className="flex items-center gap-3 px-4 py-3 rounded-sm bg-[#161f33]/60 border border-[#1e2d42]">
                <span className="w-1.5 h-1.5 rounded-full bg-[#e8002d] shrink-0" />
                <div className="text-left">
                  <p className="text-[#e2e8f4] text-xs font-semibold">{item.label}</p>
                  <p className="text-[#3d5068] text-[10px]">{item.desc}</p>
                </div>
              </div>
            ))}
          </div>
        </div>

        {/* Bottom version info */}
        <div className="absolute bottom-6 left-0 right-0 flex justify-center">
          <span className="text-[#3d5068] text-[10px] font-mono tracking-wider">
            KIZASHI EDR v2.0 · PROTECTED
          </span>
        </div>
      </div>

      {/* Right panel - form */}
      <div className="flex-1 flex items-center justify-center p-8">
        <div className="w-full max-w-sm animate-fade-in">
          {/* Mobile logo */}
          <div className="lg:hidden flex items-center gap-3 mb-8 justify-center">
            <div className="w-10 h-10 rounded-sm bg-linear-to-br from-[#e8002d] to-[#a80020] flex items-center justify-center">
              <Shield className="w-5 h-5 text-white" />
            </div>
            <p className="text-white font-bold text-lg">Kizashi</p>
          </div>

          {mfaState ? (
            /* ── MFA Step ────────────────────────────── */
            <div>
              <div className="flex items-center gap-2 mb-1">
                <KeyRound className="w-5 h-5 text-[#e8002d]" />
                <h2 className="text-white font-bold text-xl">二要素認証</h2>
              </div>
              <p className="text-[#7d92b0] text-sm mb-8">
                認証アプリの6桁コードを入力してください。
              </p>

              <form onSubmit={handleMFASubmit} className="space-y-4">
                <div>
                  <label className="block text-[10px] font-semibold tracking-widest uppercase text-[#7d92b0] mb-2">
                    認証コード
                  </label>
                  <input
                    type="text"
                    inputMode="numeric"
                    pattern="[0-9]*"
                    maxLength={8}
                    value={mfaCode}
                    onChange={e => setMfaCode(e.target.value.replace(/\D/g, ''))}
                    required
                    autoFocus
                    autoComplete="one-time-code"
                    className="w-full bg-[#0d1220] border border-[#1e2d42] text-white rounded-sm px-4 py-3 text-center tracking-[0.6em] font-mono text-lg focus:outline-hidden focus:border-[#e8002d] focus:ring-1 focus:ring-[#e8002d]/30 placeholder-[#3d5068] transition-colors"
                    placeholder="000000"
                  />
                </div>

                {error && <ErrorBox message={error} />}

                <button
                  type="submit"
                  disabled={isLoading || mfaCode.length < 6}
                  className="w-full fc-btn-primary justify-center py-2.5 disabled:opacity-40"
                >
                  {isLoading ? (
                    <span className="flex items-center gap-2">
                      <span className="w-4 h-4 border-2 border-white/30 border-t-white rounded-full animate-spin" />
                      認証中...
                    </span>
                  ) : '認証する'}
                </button>

                <button
                  type="button"
                  onClick={() => { setMfaState(null); setError('') }}
                  className="w-full text-[#7d92b0] hover:text-[#e2e8f4] text-sm py-2 transition-colors"
                >
                  ← ログイン画面に戻る
                </button>
              </form>
            </div>
          ) : (
            /* ── Login Step ──────────────────────────── */
            <div>
              <h2 className="text-white font-bold text-xl mb-1">ログイン</h2>
              <p className="text-[#7d92b0] text-sm mb-8">認証情報を入力してください。</p>

              <form onSubmit={handleSubmit} className="space-y-4">
                <div>
                  <label className="block text-[10px] font-semibold tracking-widest uppercase text-[#7d92b0] mb-2">
                    ユーザー名
                  </label>
                  <div className="relative">
                    <User className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-[#3d5068]" />
                    <input
                      type="text"
                      value={username}
                      onChange={e => setUsername(e.target.value)}
                      required
                      autoComplete="username"
                      className="w-full bg-[#0d1220] border border-[#1e2d42] text-[#e2e8f4] rounded-sm pl-9 pr-4 py-2.5 text-sm focus:outline-hidden focus:border-[#1a6bff] focus:ring-1 focus:ring-[#1a6bff]/30 placeholder-[#3d5068] transition-colors"
                      placeholder="admin"
                    />
                  </div>
                </div>

                <div>
                  <label className="block text-[10px] font-semibold tracking-widest uppercase text-[#7d92b0] mb-2">
                    パスワード
                  </label>
                  <div className="relative">
                    <Lock className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-[#3d5068]" />
                    <input
                      type="password"
                      value={password}
                      onChange={e => setPassword(e.target.value)}
                      required
                      autoComplete="current-password"
                      className="w-full bg-[#0d1220] border border-[#1e2d42] text-[#e2e8f4] rounded-sm pl-9 pr-4 py-2.5 text-sm focus:outline-hidden focus:border-[#1a6bff] focus:ring-1 focus:ring-[#1a6bff]/30 placeholder-[#3d5068] transition-colors"
                      placeholder="••••••••"
                    />
                  </div>
                </div>

                <div className="flex justify-end">
                  <button
                    type="button"
                    onClick={() => router.push('/auth/forgot-password')}
                    className="text-[#3d5068] hover:text-[#7d92b0] text-xs transition-colors"
                  >
                    パスワードを忘れた方はこちら
                  </button>
                </div>

                {error && <ErrorBox message={error} />}

                <button
                  type="submit"
                  disabled={isLoading}
                  className="w-full fc-btn-primary justify-center py-2.5 mt-2 disabled:opacity-40"
                >
                  {isLoading ? (
                    <span className="flex items-center gap-2">
                      <span className="w-4 h-4 border-2 border-white/30 border-t-white rounded-full animate-spin" />
                      ログイン中...
                    </span>
                  ) : (
                    <span className="flex items-center gap-2">
                      <Shield className="w-4 h-4" />
                      ログイン
                    </span>
                  )}
                </button>
              </form>

              {/* SSO login button — only shown when at least one provider is enabled */}
              {ssoProviders.length > 0 && (
                <div className="mt-5">
                  <div className="flex items-center gap-3 mb-4">
                    <div className="flex-1 h-px bg-[#1e2d42]" />
                    <span className="text-[#3d5068] text-[10px] uppercase tracking-widest">または</span>
                    <div className="flex-1 h-px bg-[#1e2d42]" />
                  </div>

                  {ssoProviders.map(provider => (
                    <button
                      key={provider.id}
                      type="button"
                      onClick={() => router.push(`/auth/sso?provider=${provider.id}`)}
                      className="w-full flex items-center justify-center gap-2 py-2.5 mb-2 bg-[#0d1220] border border-[#1e3a5f] text-[#4a9eff] rounded-sm hover:bg-[#161f33] hover:border-[#4a9eff]/40 transition-colors text-sm font-medium"
                    >
                      <Shield className="w-4 h-4" />
                      {provider.name} でSSOログイン
                    </button>
                  ))}
                </div>
              )}

              <p className="text-[#3d5068] text-[10px] text-center mt-8 uppercase tracking-widest">
                KIZASHI EDR · Secured Access
              </p>
            </div>
          )}
        </div>
      </div>
    </div>
  )
}

function ErrorBox({ message }: { message: string }) {
  return (
    <div className="flex items-start gap-2 px-3 py-2.5 rounded-sm bg-[#e8002d]/10 border border-[#e8002d]/30 text-[#ff4d6d] text-sm">
      <span className="text-[#e8002d] mt-0.5 shrink-0">▲</span>
      {message}
    </div>
  )
}

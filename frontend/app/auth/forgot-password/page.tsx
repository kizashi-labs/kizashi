'use client'

import { useState, FormEvent } from 'react'
import Link from 'next/link'
import { Shield, Mail, ArrowLeft } from 'lucide-react'

export default function ForgotPasswordPage() {
  const [email, setEmail] = useState('')
  const [error, setError] = useState('')
  const [isLoading, setIsLoading] = useState(false)
  const [sent, setSent] = useState(false)

  const handleSubmit = async (e: FormEvent) => {
    e.preventDefault()
    setError('')
    setIsLoading(true)
    try {
      const res = await fetch('/api/v1/auth/password-reset/request', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ email }),
      })
      if (!res.ok) {
        const data = await res.json().catch(() => ({}))
        throw new Error(data.error || 'リクエストに失敗しました')
      }
      setSent(true)
    } catch (err) {
      setError(err instanceof Error ? err.message : 'リクエストに失敗しました')
    } finally {
      setIsLoading(false)
    }
  }

  return (
    <div className="min-h-screen flex bg-falcon-bg">
      {/* Left panel - brand */}
      <div className="hidden lg:flex w-[420px] shrink-0 flex-col bg-falcon-surface border-r border-falcon-border
                      items-center justify-center p-12 relative overflow-hidden">
        <div className="absolute inset-0 opacity-[0.03]"
             style={{
               backgroundImage: 'linear-gradient(#e2e8f4 1px, transparent 1px), linear-gradient(90deg, #e2e8f4 1px, transparent 1px)',
               backgroundSize: '32px 32px',
             }} />
        <div className="absolute top-1/2 left-1/2 -translate-x-1/2 -translate-y-1/2 w-64 h-64
                        rounded-full bg-falcon-red/5 blur-3xl pointer-events-none" />

        <div className="relative z-10 flex flex-col items-center text-center">
          <div className="w-20 h-20 rounded-xl bg-linear-to-br from-falcon-red to-falcon-red-dark
                          flex items-center justify-center shadow-falcon-glow-red mb-6">
            <Shield className="w-10 h-10 text-white" strokeWidth={1.5} />
          </div>
          <h1 className="text-2xl font-bold text-white tracking-tight mb-2">Kizashi</h1>
          <p className="text-falcon-subtle text-sm uppercase tracking-widest font-medium mb-8">
            Endpoint Protection Platform
          </p>
        </div>

        <div className="absolute bottom-6 left-0 right-0 flex justify-center">
          <span className="text-falcon-subtle text-[10px] font-mono tracking-wider">
            KIZASHI EDR v2.0 · PROTECTED
          </span>
        </div>
      </div>

      {/* Right panel - form */}
      <div className="flex-1 flex items-center justify-center p-8">
        <div className="w-full max-w-sm animate-fade-in">
          {/* Mobile logo */}
          <div className="lg:hidden flex items-center gap-3 mb-8 justify-center">
            <div className="w-10 h-10 rounded-sm bg-linear-to-br from-falcon-red to-falcon-red-dark flex items-center justify-center">
              <Shield className="w-5 h-5 text-white" />
            </div>
            <p className="text-white font-bold text-lg">Kizashi</p>
          </div>

          {sent ? (
            /* ── Success State ─────────────────────────── */
            <div className="text-center">
              <div className="w-16 h-16 rounded-full bg-falcon-blue/10 border border-falcon-blue/30
                              flex items-center justify-center mx-auto mb-4">
                <Mail className="w-8 h-8 text-falcon-blue" />
              </div>
              <h2 className="text-white font-bold text-xl mb-2">メールを送信しました</h2>
              <p className="text-falcon-muted text-sm mb-6">
                入力したメールアドレスにパスワードリセットリンクを送信しました。
                メールが届かない場合は迷惑メールフォルダをご確認ください。
              </p>
              <Link
                href="/login"
                className="inline-flex items-center gap-2 text-falcon-muted hover:text-falcon-text text-sm transition-colors"
              >
                <ArrowLeft className="w-4 h-4" />
                ログイン画面に戻る
              </Link>
            </div>
          ) : (
            /* ── Request Form ──────────────────────────── */
            <div>
              <div className="flex items-center gap-2 mb-1">
                <Mail className="w-5 h-5 text-falcon-red" />
                <h2 className="text-white font-bold text-xl">パスワードのリセット</h2>
              </div>
              <p className="text-falcon-muted text-sm mb-8">
                登録済みのメールアドレスを入力してください。パスワードリセット用のリンクをお送りします。
              </p>

              <form onSubmit={handleSubmit} className="space-y-4">
                <div>
                  <label className="block text-[10px] font-semibold tracking-widest uppercase text-falcon-muted mb-2">
                    メールアドレス
                  </label>
                  <div className="relative">
                    <Mail className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-falcon-subtle" />
                    <input
                      type="email"
                      value={email}
                      onChange={e => setEmail(e.target.value)}
                      required
                      autoComplete="email"
                      autoFocus
                      className="w-full bg-falcon-surface border border-falcon-border text-falcon-text rounded
                                 pl-9 pr-4 py-2.5 text-sm
                                 focus:outline-hidden focus:border-falcon-blue focus:ring-1 focus:ring-falcon-blue/30
                                 placeholder-falcon-subtle transition-colors"
                      placeholder="user@example.com"
                    />
                  </div>
                </div>

                {error && <ErrorBox message={error} />}

                <button
                  type="submit"
                  disabled={isLoading || !email}
                  className="w-full fc-btn-primary justify-center py-2.5 mt-2 disabled:opacity-40"
                >
                  {isLoading ? (
                    <span className="flex items-center gap-2">
                      <span className="w-4 h-4 border-2 border-white/30 border-t-white rounded-full animate-spin" />
                      送信中...
                    </span>
                  ) : (
                    <span className="flex items-center gap-2">
                      <Mail className="w-4 h-4" />
                      リセットリンクを送信
                    </span>
                  )}
                </button>
              </form>

              <div className="mt-6 text-center">
                <Link
                  href="/login"
                  className="inline-flex items-center gap-2 text-falcon-muted hover:text-falcon-text text-sm transition-colors"
                >
                  <ArrowLeft className="w-4 h-4" />
                  ログイン画面に戻る
                </Link>
              </div>
            </div>
          )}
        </div>
      </div>
    </div>
  )
}

function ErrorBox({ message }: { message: string }) {
  return (
    <div className="flex items-start gap-2 px-3 py-2.5 rounded bg-falcon-red/10
                    border border-falcon-red/30 text-[#ff4d6d] text-sm">
      <span className="text-falcon-red mt-0.5 shrink-0">▲</span>
      {message}
    </div>
  )
}

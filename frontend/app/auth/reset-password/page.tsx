'use client'

import { useState, FormEvent, useEffect, Suspense } from 'react'
import { useRouter, useSearchParams } from 'next/navigation'
import Link from 'next/link'
import { Shield, Lock, ArrowLeft, CheckCircle } from 'lucide-react'

function ResetPasswordForm() {
  const router = useRouter()
  const searchParams = useSearchParams()
  const token = searchParams.get('token') ?? ''

  const [newPassword, setNewPassword] = useState('')
  const [confirmPassword, setConfirmPassword] = useState('')
  const [error, setError] = useState('')
  const [isLoading, setIsLoading] = useState(false)
  const [success, setSuccess] = useState(false)

  useEffect(() => {
    if (!token) {
      setError('リセットトークンが見つかりません。メールのリンクを再度クリックしてください。')
    }
  }, [token])

  const handleSubmit = async (e: FormEvent) => {
    e.preventDefault()
    setError('')

    if (newPassword !== confirmPassword) {
      setError('パスワードが一致しません')
      return
    }
    if (newPassword.length < 8) {
      setError('パスワードは8文字以上必要です')
      return
    }

    setIsLoading(true)
    try {
      const res = await fetch('/api/v1/auth/password-reset/confirm', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ token, new_password: newPassword }),
      })
      const data = await res.json().catch(() => ({}))
      if (!res.ok) {
        throw new Error(data.error || 'パスワードの変更に失敗しました')
      }
      setSuccess(true)
      // Redirect to login after 2 seconds
      setTimeout(() => router.push('/login'), 2000)
    } catch (err) {
      setError(err instanceof Error ? err.message : 'パスワードの変更に失敗しました')
    } finally {
      setIsLoading(false)
    }
  }

  return (
    <div className="min-h-screen flex bg-[#080c14]">
      {/* Left panel - brand */}
      <div className="hidden lg:flex w-[420px] flex-shrink-0 flex-col bg-[#0d1220] border-r border-[#1e2d42]
                      items-center justify-center p-12 relative overflow-hidden">
        <div className="absolute inset-0 opacity-[0.03]"
             style={{
               backgroundImage: 'linear-gradient(#e2e8f4 1px, transparent 1px), linear-gradient(90deg, #e2e8f4 1px, transparent 1px)',
               backgroundSize: '32px 32px',
             }} />
        <div className="absolute top-1/2 left-1/2 -translate-x-1/2 -translate-y-1/2 w-64 h-64
                        rounded-full bg-[#e8002d]/5 blur-3xl pointer-events-none" />

        <div className="relative z-10 flex flex-col items-center text-center">
          <div className="w-20 h-20 rounded-xl bg-gradient-to-br from-[#e8002d] to-[#a80020]
                          flex items-center justify-center shadow-falcon-glow-red mb-6">
            <Shield className="w-10 h-10 text-white" strokeWidth={1.5} />
          </div>
          <h1 className="text-2xl font-bold text-white tracking-tight mb-2">Kizashi</h1>
          <p className="text-[#3d5068] text-sm uppercase tracking-widest font-medium mb-8">
            Endpoint Protection Platform
          </p>
        </div>

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
            <div className="w-10 h-10 rounded bg-gradient-to-br from-[#e8002d] to-[#a80020] flex items-center justify-center">
              <Shield className="w-5 h-5 text-white" />
            </div>
            <p className="text-white font-bold text-lg">Kizashi</p>
          </div>

          {success ? (
            /* ── Success State ─────────────────────────── */
            <div className="text-center">
              <div className="w-16 h-16 rounded-full bg-emerald-500/10 border border-emerald-500/30
                              flex items-center justify-center mx-auto mb-4">
                <CheckCircle className="w-8 h-8 text-emerald-400" />
              </div>
              <h2 className="text-white font-bold text-xl mb-2">パスワードを変更しました</h2>
              <p className="text-[#7d92b0] text-sm mb-6">
                パスワードが正常に変更されました。ログイン画面に移動します...
              </p>
              <Link
                href="/login"
                className="inline-flex items-center gap-2 text-[#7d92b0] hover:text-[#e2e8f4] text-sm transition-colors"
              >
                <ArrowLeft className="w-4 h-4" />
                ログイン画面へ
              </Link>
            </div>
          ) : (
            /* ── Reset Form ────────────────────────────── */
            <div>
              <div className="flex items-center gap-2 mb-1">
                <Lock className="w-5 h-5 text-[#e8002d]" />
                <h2 className="text-white font-bold text-xl">新しいパスワードを設定</h2>
              </div>
              <p className="text-[#7d92b0] text-sm mb-8">
                新しいパスワードを入力してください。8文字以上で英字と数字を含む必要があります。
              </p>

              {!token && error && <ErrorBox message={error} />}

              {token && (
                <form onSubmit={handleSubmit} className="space-y-4">
                  <div>
                    <label className="block text-[10px] font-semibold tracking-widest uppercase text-[#7d92b0] mb-2">
                      新しいパスワード
                    </label>
                    <div className="relative">
                      <Lock className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-[#3d5068]" />
                      <input
                        type="password"
                        value={newPassword}
                        onChange={e => setNewPassword(e.target.value)}
                        required
                        autoComplete="new-password"
                        autoFocus
                        minLength={8}
                        className="w-full bg-[#0d1220] border border-[#1e2d42] text-[#e2e8f4] rounded
                                   pl-9 pr-4 py-2.5 text-sm
                                   focus:outline-none focus:border-[#1a6bff] focus:ring-1 focus:ring-[#1a6bff]/30
                                   placeholder-[#3d5068] transition-colors"
                        placeholder="••••••••"
                      />
                    </div>
                  </div>

                  <div>
                    <label className="block text-[10px] font-semibold tracking-widest uppercase text-[#7d92b0] mb-2">
                      パスワード確認
                    </label>
                    <div className="relative">
                      <Lock className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-[#3d5068]" />
                      <input
                        type="password"
                        value={confirmPassword}
                        onChange={e => setConfirmPassword(e.target.value)}
                        required
                        autoComplete="new-password"
                        minLength={8}
                        className="w-full bg-[#0d1220] border border-[#1e2d42] text-[#e2e8f4] rounded
                                   pl-9 pr-4 py-2.5 text-sm
                                   focus:outline-none focus:border-[#1a6bff] focus:ring-1 focus:ring-[#1a6bff]/30
                                   placeholder-[#3d5068] transition-colors"
                        placeholder="••••••••"
                      />
                    </div>
                  </div>

                  {error && <ErrorBox message={error} />}

                  <button
                    type="submit"
                    disabled={isLoading || !newPassword || !confirmPassword}
                    className="w-full fc-btn-primary justify-center py-2.5 mt-2 disabled:opacity-40"
                  >
                    {isLoading ? (
                      <span className="flex items-center gap-2">
                        <span className="w-4 h-4 border-2 border-white/30 border-t-white rounded-full animate-spin" />
                        変更中...
                      </span>
                    ) : (
                      <span className="flex items-center gap-2">
                        <Lock className="w-4 h-4" />
                        パスワードを変更する
                      </span>
                    )}
                  </button>
                </form>
              )}

              <div className="mt-6 text-center">
                <Link
                  href="/login"
                  className="inline-flex items-center gap-2 text-[#7d92b0] hover:text-[#e2e8f4] text-sm transition-colors"
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

export default function ResetPasswordPage() {
  return (
    <Suspense fallback={
      <div className="min-h-screen flex items-center justify-center bg-[#080c14]">
        <div className="w-8 h-8 border-2 border-[#1a6bff]/30 border-t-[#1a6bff] rounded-full animate-spin" />
      </div>
    }>
      <ResetPasswordForm />
    </Suspense>
  )
}

function ErrorBox({ message }: { message: string }) {
  return (
    <div className="flex items-start gap-2 px-3 py-2.5 rounded bg-[#e8002d]/10
                    border border-[#e8002d]/30 text-[#ff4d6d] text-sm">
      <span className="text-[#e8002d] mt-0.5 flex-shrink-0">▲</span>
      {message}
    </div>
  )
}

'use client'

import { useState, FormEvent } from 'react'
import { useRouter } from 'next/navigation'
import { Shield, Lock, Eye, EyeOff } from 'lucide-react'
import { useAuth } from '@/lib/auth'
import { apiFetch } from '@/lib/api'

export default function ChangePasswordPage() {
  const { user, token, isLoading: authLoading } = useAuth()
  const router = useRouter()
  const isAdmin = user?.role === 'admin'
  const [currentPassword, setCurrentPassword] = useState('')
  const [showCurrent, setShowCurrent] = useState(false)
  const [newPassword, setNewPassword] = useState('')
  const [confirm, setConfirm] = useState('')
  const [showNew, setShowNew] = useState(false)
  const [showConfirm, setShowConfirm] = useState(false)
  const [error, setError] = useState('')
  const [isLoading, setIsLoading] = useState(false)

  // 認証状態が確定するまで待つ
  if (authLoading) {
    return (
      <div className="min-h-screen flex items-center justify-center bg-falcon-bg">
        <div className="w-6 h-6 border-2 border-falcon-red/30 border-t-falcon-red rounded-full animate-spin" />
      </div>
    )
  }

  if (!token) {
    router.replace('/login')
    return null
  }

  const handleSubmit = async (e: FormEvent) => {
    e.preventDefault()
    setError('')

    if (!isAdmin && !currentPassword) {
      setError('現在のパスワードを入力してください')
      return
    }
    if (newPassword.length < 8) {
      setError('パスワードは8文字以上にしてください')
      return
    }
    if (newPassword !== confirm) {
      setError('パスワードが一致しません')
      return
    }

    setIsLoading(true)
    try {
      const userID = user?.id
      if (!userID) throw new Error('ユーザー情報が取得できません')

      const payload: Record<string, string> = { password: newPassword }
      if (!isAdmin) payload.current_password = currentPassword

      await apiFetch(`/api/v1/users/${userID}/password`, {
        method: 'PUT',
        body: JSON.stringify(payload),
      })

      // Update stored user to clear must_change_password flag
      const stored = localStorage.getItem('edr_user')
      if (stored) {
        try {
          const u = JSON.parse(stored)
          u.must_change_password = false
          localStorage.setItem('edr_user', JSON.stringify(u))
        } catch { /* ignore */ }
      }

      router.push('/dashboard')
    } catch (err) {
      setError(err instanceof Error ? err.message : 'パスワードの変更に失敗しました')
    } finally {
      setIsLoading(false)
    }
  }

  const strength = (() => {
    if (!newPassword) return 0
    let s = 0
    if (newPassword.length >= 8) s++
    if (newPassword.length >= 12) s++
    if (/[A-Z]/.test(newPassword)) s++
    if (/[0-9]/.test(newPassword)) s++
    if (/[^A-Za-z0-9]/.test(newPassword)) s++
    return s
  })()

  const strengthLabel = ['', '弱い', '弱い', '普通', '強い', '非常に強い'][strength]
  const strengthColor = ['', 'bg-red-500', 'bg-orange-500', 'bg-yellow-500', 'bg-green-500', 'bg-emerald-400'][strength]

  return (
    <div className="min-h-screen flex items-center justify-center bg-falcon-bg px-4">
      <div className="w-full max-w-sm">
        {/* Header */}
        <div className="flex flex-col items-center mb-8">
          <div className="w-14 h-14 rounded-xl bg-linear-to-br from-falcon-red to-falcon-red-dark
                          flex items-center justify-center shadow-lg mb-4">
            <Shield className="w-7 h-7 text-white" strokeWidth={1.5} />
          </div>
          <h1 className="text-white font-bold text-xl mb-1">パスワードの変更</h1>
          <p className="text-falcon-muted text-sm text-center">
            初回ログインのため、新しいパスワードを設定してください。
          </p>
        </div>

        <form onSubmit={handleSubmit} className="space-y-4">
          {/* Current password (non-admin only) */}
          {!isAdmin && (
            <div>
              <label className="block text-[10px] font-semibold tracking-widest uppercase text-falcon-muted mb-2">
                現在のパスワード
              </label>
              <div className="relative">
                <Lock className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-falcon-subtle" />
                <input
                  type={showCurrent ? 'text' : 'password'}
                  value={currentPassword}
                  onChange={e => setCurrentPassword(e.target.value)}
                  required
                  autoFocus
                  autoComplete="current-password"
                  className="w-full bg-falcon-surface border border-falcon-border text-falcon-text rounded
                             pl-9 pr-10 py-2.5 text-sm
                             focus:outline-hidden focus:border-falcon-blue focus:ring-1 focus:ring-falcon-blue/30
                             placeholder-falcon-subtle transition-colors"
                  placeholder="現在のパスワード"
                />
                <button
                  type="button"
                  onClick={() => setShowCurrent(v => !v)}
                  className="absolute right-3 top-1/2 -translate-y-1/2 text-falcon-subtle hover:text-falcon-muted"
                >
                  {showCurrent ? <EyeOff className="w-4 h-4" /> : <Eye className="w-4 h-4" />}
                </button>
              </div>
            </div>
          )}

          {/* New password */}
          <div>
            <label className="block text-[10px] font-semibold tracking-widest uppercase text-falcon-muted mb-2">
              新しいパスワード
            </label>
            <div className="relative">
              <Lock className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-falcon-subtle" />
              <input
                type={showNew ? 'text' : 'password'}
                value={newPassword}
                onChange={e => setNewPassword(e.target.value)}
                required
                autoFocus={isAdmin}
                autoComplete="new-password"
                className="w-full bg-falcon-surface border border-falcon-border text-falcon-text rounded
                           pl-9 pr-10 py-2.5 text-sm
                           focus:outline-hidden focus:border-falcon-blue focus:ring-1 focus:ring-falcon-blue/30
                           placeholder-falcon-subtle transition-colors"
                placeholder="8文字以上"
              />
              <button
                type="button"
                onClick={() => setShowNew(v => !v)}
                className="absolute right-3 top-1/2 -translate-y-1/2 text-falcon-subtle hover:text-falcon-muted"
              >
                {showNew ? <EyeOff className="w-4 h-4" /> : <Eye className="w-4 h-4" />}
              </button>
            </div>
            {/* Strength bar */}
            {newPassword && (
              <div className="mt-2 space-y-1">
                <div className="flex gap-1">
                  {[1,2,3,4,5].map(i => (
                    <div
                      key={i}
                      className={`h-1 flex-1 rounded-full transition-colors ${
                        i <= strength ? strengthColor : 'bg-falcon-border'
                      }`}
                    />
                  ))}
                </div>
                <p className="text-[10px] text-[#5a6a7a]">強度: {strengthLabel}</p>
              </div>
            )}
          </div>

          {/* Confirm */}
          <div>
            <label className="block text-[10px] font-semibold tracking-widest uppercase text-falcon-muted mb-2">
              パスワードの確認
            </label>
            <div className="relative">
              <Lock className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-falcon-subtle" />
              <input
                type={showConfirm ? 'text' : 'password'}
                value={confirm}
                onChange={e => setConfirm(e.target.value)}
                required
                autoComplete="new-password"
                className={`w-full bg-falcon-surface border text-falcon-text rounded
                           pl-9 pr-10 py-2.5 text-sm
                           focus:outline-hidden focus:ring-1 transition-colors
                           placeholder-falcon-subtle
                           ${confirm && newPassword !== confirm
                             ? 'border-falcon-red focus:border-falcon-red focus:ring-falcon-red/30'
                             : 'border-falcon-border focus:border-falcon-blue focus:ring-falcon-blue/30'}`}
                placeholder="もう一度入力"
              />
              <button
                type="button"
                onClick={() => setShowConfirm(v => !v)}
                className="absolute right-3 top-1/2 -translate-y-1/2 text-falcon-subtle hover:text-falcon-muted"
              >
                {showConfirm ? <EyeOff className="w-4 h-4" /> : <Eye className="w-4 h-4" />}
              </button>
            </div>
            {confirm && newPassword !== confirm && (
              <p className="mt-1 text-[11px] text-falcon-red">パスワードが一致しません</p>
            )}
          </div>

          {error && (
            <div className="flex items-start gap-2 px-3 py-2.5 rounded bg-falcon-red/10
                            border border-falcon-red/30 text-[#ff4d6d] text-sm">
              <span className="text-falcon-red mt-0.5 shrink-0">▲</span>
              {error}
            </div>
          )}

          <button
            type="submit"
            disabled={isLoading || newPassword !== confirm || newPassword.length < 8}
            className="w-full flex items-center justify-center gap-2 px-4 py-2.5
                       bg-falcon-blue hover:bg-[#1557cc] text-white text-sm font-semibold
                       rounded transition-colors disabled:opacity-40 disabled:cursor-not-allowed mt-2"
          >
            {isLoading ? (
              <>
                <span className="w-4 h-4 border-2 border-white/30 border-t-white rounded-full animate-spin" />
                変更中...
              </>
            ) : (
              <>
                <Lock className="w-4 h-4" />
                パスワードを変更する
              </>
            )}
          </button>
        </form>

        <p className="text-falcon-subtle text-[10px] text-center mt-8 uppercase tracking-widest">
          KIZASHI EDR · Secure Access
        </p>
      </div>
    </div>
  )
}

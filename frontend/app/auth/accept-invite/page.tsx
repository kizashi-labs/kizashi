'use client'

import { useState, useEffect, Suspense } from 'react'
import { useSearchParams, useRouter } from 'next/navigation'
import { Shield, Eye, EyeOff, User, Mail, Lock, CheckCircle } from 'lucide-react'

interface InviteInfo {
  email: string
  role: string
}

const ROLE_LABELS: Record<string, string> = {
  admin:   '管理者',
  analyst: 'アナリスト',
  viewer:  '閲覧者',
}

function AcceptInvitePageInner() {
  const searchParams = useSearchParams()
  const router = useRouter()

  const token = searchParams.get('token') ?? ''

  const [inviteInfo, setInviteInfo] = useState<InviteInfo | null>(null)
  const [infoError, setInfoError] = useState('')
  const [infoLoading, setInfoLoading] = useState(true)

  const [fullName, setFullName] = useState('')
  const [password, setPassword] = useState('')
  const [passwordConfirm, setPasswordConfirm] = useState('')
  const [showPw, setShowPw] = useState(false)
  const [showPwConfirm, setShowPwConfirm] = useState(false)

  const [submitting, setSubmitting] = useState(false)
  const [submitError, setSubmitError] = useState('')
  const [done, setDone] = useState(false)

  // Fetch invite info on mount
  useEffect(() => {
    if (!token) {
      setInfoError('招待トークンが見つかりません')
      setInfoLoading(false)
      return
    }

    fetch(`/api/v1/auth/invite/info?token=${encodeURIComponent(token)}`)
      .then(res => {
        if (!res.ok) throw new Error('招待が見つかりません。期限切れか無効なリンクです')
        return res.json()
      })
      .then((data: InviteInfo) => {
        setInviteInfo(data)
      })
      .catch((err: Error) => {
        setInfoError(err.message)
      })
      .finally(() => {
        setInfoLoading(false)
      })
  }, [token])

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault()
    setSubmitError('')

    if (password.length < 8) {
      setSubmitError('パスワードは8文字以上にしてください')
      return
    }
    if (password !== passwordConfirm) {
      setSubmitError('パスワードが一致しません')
      return
    }

    setSubmitting(true)
    try {
      const res = await fetch('/api/v1/auth/invite/accept', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ token, full_name: fullName, password }),
      })
      const data = await res.json()
      if (!res.ok) {
        throw new Error(data.error ?? 'アカウントの作成に失敗しました')
      }
      setDone(true)
    } catch (err: unknown) {
      setSubmitError(err instanceof Error ? err.message : 'アカウントの作成に失敗しました')
    } finally {
      setSubmitting(false)
    }
  }

  if (infoLoading) {
    return (
      <div className="min-h-screen bg-[#080c14] flex items-center justify-center">
        <div className="w-8 h-8 border-2 border-blue-500 border-t-transparent rounded-full animate-spin" />
      </div>
    )
  }

  if (infoError) {
    return (
      <div className="min-h-screen bg-[#080c14] flex items-center justify-center p-4">
        <div className="bg-[#111827] rounded-2xl p-8 w-full max-w-md border border-[#1e2d42] text-center">
          <Shield className="w-12 h-12 text-red-400 mx-auto mb-4" />
          <h1 className="text-xl font-bold text-white mb-2">招待リンクが無効です</h1>
          <p className="text-[#8899aa] text-sm">{infoError}</p>
        </div>
      </div>
    )
  }

  if (done) {
    return (
      <div className="min-h-screen bg-[#080c14] flex items-center justify-center p-4">
        <div className="bg-[#111827] rounded-2xl p-8 w-full max-w-md border border-[#1e2d42] text-center">
          <CheckCircle className="w-12 h-12 text-green-400 mx-auto mb-4" />
          <h1 className="text-xl font-bold text-white mb-2">アカウントを作成しました</h1>
          <p className="text-[#8899aa] text-sm mb-6">
            ログインしてEDR Platformをご利用ください。
          </p>
          <button
            onClick={() => router.push('/login')}
            className="w-full py-2.5 bg-[#1a6bff] text-white rounded-lg hover:bg-[#1557d4] transition-colors font-medium"
          >
            ログインページへ
          </button>
        </div>
      </div>
    )
  }

  return (
    <div className="min-h-screen bg-[#080c14] flex items-center justify-center p-4">
      <div className="bg-[#111827] rounded-2xl p-8 w-full max-w-md border border-[#1e2d42]">
        {/* Header */}
        <div className="flex items-center gap-3 mb-6">
          <div className="w-10 h-10 bg-blue-600/20 rounded-xl flex items-center justify-center">
            <Shield className="w-5 h-5 text-blue-400" />
          </div>
          <div>
            <h1 className="text-xl font-bold text-white">招待を受け入れる</h1>
            <p className="text-[#8899aa] text-xs">EDR Platformアカウントを設定してください</p>
          </div>
        </div>

        {/* Invite info */}
        {inviteInfo && (
          <div className="bg-[#0d1525] rounded-xl p-4 mb-6 border border-[#1e2d42]">
            <div className="flex items-center gap-2 mb-1">
              <Mail className="w-4 h-4 text-[#8899aa]" />
              <span className="text-white text-sm font-medium">{inviteInfo.email}</span>
            </div>
            <div className="flex items-center gap-2">
              <Shield className="w-4 h-4 text-[#8899aa]" />
              <span className="text-[#8899aa] text-xs">
                ロール: {ROLE_LABELS[inviteInfo.role] ?? inviteInfo.role}
              </span>
            </div>
          </div>
        )}

        <form onSubmit={handleSubmit} className="space-y-4">
          {/* Full name */}
          <div>
            <label className="text-[#8899aa] text-sm block mb-1">氏名</label>
            <div className="relative">
              <User className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-[#5a6a7a]" />
              <input
                type="text"
                value={fullName}
                onChange={e => setFullName(e.target.value)}
                placeholder="田中 太郎"
                className="w-full bg-[#080c14] text-white pl-10 pr-3 py-2.5 rounded-lg border border-[#1e2d42] text-sm focus:outline-hidden focus:border-[#1a6bff] transition-colors"
              />
            </div>
          </div>

          {/* Password */}
          <div>
            <label className="text-[#8899aa] text-sm block mb-1">
              パスワード <span className="text-red-400">*</span>
            </label>
            <div className="relative">
              <Lock className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-[#5a6a7a]" />
              <input
                type={showPw ? 'text' : 'password'}
                value={password}
                onChange={e => setPassword(e.target.value)}
                placeholder="8文字以上"
                required
                className="w-full bg-[#080c14] text-white pl-10 pr-10 py-2.5 rounded-lg border border-[#1e2d42] text-sm focus:outline-hidden focus:border-[#1a6bff] transition-colors"
              />
              <button
                type="button"
                onClick={() => setShowPw(v => !v)}
                className="absolute right-3 top-1/2 -translate-y-1/2 text-[#8899aa] hover:text-white transition-colors"
              >
                {showPw ? <EyeOff className="w-4 h-4" /> : <Eye className="w-4 h-4" />}
              </button>
            </div>
          </div>

          {/* Password confirm */}
          <div>
            <label className="text-[#8899aa] text-sm block mb-1">
              パスワード（確認） <span className="text-red-400">*</span>
            </label>
            <div className="relative">
              <Lock className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-[#5a6a7a]" />
              <input
                type={showPwConfirm ? 'text' : 'password'}
                value={passwordConfirm}
                onChange={e => setPasswordConfirm(e.target.value)}
                placeholder="パスワードを再入力"
                required
                className="w-full bg-[#080c14] text-white pl-10 pr-10 py-2.5 rounded-lg border border-[#1e2d42] text-sm focus:outline-hidden focus:border-[#1a6bff] transition-colors"
              />
              <button
                type="button"
                onClick={() => setShowPwConfirm(v => !v)}
                className="absolute right-3 top-1/2 -translate-y-1/2 text-[#8899aa] hover:text-white transition-colors"
              >
                {showPwConfirm ? <EyeOff className="w-4 h-4" /> : <Eye className="w-4 h-4" />}
              </button>
            </div>
          </div>

          {/* Error */}
          {submitError && (
            <p className="text-red-400 text-sm bg-red-900/20 border border-red-700/30 rounded-lg px-3 py-2">
              {submitError}
            </p>
          )}

          {/* Submit */}
          <button
            type="submit"
            disabled={submitting || !password || !passwordConfirm}
            className="w-full py-2.5 bg-[#1a6bff] text-white rounded-lg hover:bg-[#1557d4] transition-colors font-medium disabled:opacity-50 flex items-center justify-center gap-2"
          >
            {submitting ? (
              <div className="w-4 h-4 border-2 border-white/30 border-t-white rounded-full animate-spin" />
            ) : (
              <Shield className="w-4 h-4" />
            )}
            アカウントを作成する
          </button>
        </form>
      </div>
    </div>
  )
}

export default function AcceptInvitePage() {
  return (
    <Suspense fallback={
      <div className="min-h-screen bg-[#080c14] flex items-center justify-center">
        <div className="w-8 h-8 border-2 border-blue-500 border-t-transparent rounded-full animate-spin" />
      </div>
    }>
      <AcceptInvitePageInner />
    </Suspense>
  )
}

'use client'

import { useState } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { apiFetch } from '@/lib/api'
import { useAuth } from '@/lib/auth'
import {
  ShieldCheck,
  ShieldOff,
  Mail,
  Smartphone,
  KeyRound,
  CheckCircle,
  AlertCircle,
  Loader2,
  QrCode,
  Copy,
} from 'lucide-react'

import { PageDataUnavailable } from '@/components/PageDataUnavailable'

// ─── 型定義 ──────────────────────────────────────────────────────────────────

interface UserProfile {
  id: string
  email: string
  full_name?: string
  role: string
  mfa_enabled: boolean
  mfa_type?: string
}

interface MFASetupData {
  secret: string
  otpauth_url: string
  backup_codes: string[]
}

// ─── タブ型 ───────────────────────────────────────────────────────────────────

type Tab = 'totp' | 'email'

// ─── メインページ ─────────────────────────────────────────────────────────────

export default function SecurityPage() {
  const [activeTab, setActiveTab] = useState<Tab>('totp')

  const { data: profile, isLoading } = useQuery<UserProfile>({
    queryKey: ['me'],
    queryFn: () => apiFetch<UserProfile>('/api/v1/users/me'),
  })

  if (isLoading || !profile) {
    return (
      <div className="p-6 flex items-center justify-center">
        <Loader2 className="animate-spin w-8 h-8 text-blue-500" />
      </div>
    )
  }

  const currentMFAType = profile.mfa_type ?? (profile.mfa_enabled ? 'totp' : 'none')

  return (
    <div className="p-6 max-w-2xl space-y-6">
      <PageDataUnavailable />
      {/* ページヘッダー */}
      <div>
        <h1 className="text-2xl font-bold text-white">セキュリティ設定</h1>
        <p className="text-[#8899aa] text-sm mt-1">
          多要素認証 (MFA) の設定と管理
        </p>
      </div>

      {/* 現在のMFA状態バナー */}
      <div className="bg-[#111827] rounded-xl border border-[#1e2d42] p-4 flex items-center gap-3">
        {profile.mfa_enabled ? (
          <>
            <ShieldCheck className="w-5 h-5 text-green-400 shrink-0" />
            <div className="flex-1 min-w-0">
              <p className="text-white text-sm font-medium">MFAが有効です</p>
              <p className="text-[#8899aa] text-xs mt-0.5">
                認証方式:{' '}
                <span className="text-white">
                  {currentMFAType === 'email'
                    ? 'メールOTP'
                    : currentMFAType === 'totp'
                    ? '認証アプリ (TOTP)'
                    : '不明'}
                </span>
              </p>
            </div>
            <span className="text-xs px-2.5 py-1 rounded-full bg-green-900/40 text-green-300 font-medium shrink-0">
              有効
            </span>
          </>
        ) : (
          <>
            <ShieldOff className="w-5 h-5 text-[#5a6a7a] shrink-0" />
            <div className="flex-1 min-w-0">
              <p className="text-white text-sm font-medium">MFAが無効です</p>
              <p className="text-[#8899aa] text-xs mt-0.5">
                セキュリティ向上のためMFAを設定することを推奨します
              </p>
            </div>
            <span className="text-xs px-2.5 py-1 rounded-full bg-[#161f33] text-[#8899aa] font-medium shrink-0">
              無効
            </span>
          </>
        )}
      </div>

      {/* タブ */}
      <div className="bg-[#111827] rounded-xl border border-[#1e2d42] overflow-hidden">
        {/* タブヘッダー */}
        <div className="flex border-b border-[#1e2d42]">
          <button
            onClick={() => setActiveTab('totp')}
            className={`flex items-center gap-2 px-5 py-3.5 text-sm font-medium transition-colors border-b-2 -mb-px ${
              activeTab === 'totp'
                ? 'text-white border-[#1a6bff] bg-[#1a6bff]/5'
                : 'text-[#8899aa] border-transparent hover:text-white hover:bg-[#161f33]'
            }`}
          >
            <Smartphone className="w-4 h-4" />
            認証アプリ (TOTP)
          </button>
          <button
            onClick={() => setActiveTab('email')}
            className={`flex items-center gap-2 px-5 py-3.5 text-sm font-medium transition-colors border-b-2 -mb-px ${
              activeTab === 'email'
                ? 'text-white border-[#1a6bff] bg-[#1a6bff]/5'
                : 'text-[#8899aa] border-transparent hover:text-white hover:bg-[#161f33]'
            }`}
          >
            <Mail className="w-4 h-4" />
            メールOTP
          </button>
        </div>

        {/* タブコンテンツ */}
        <div className="p-5">
          {activeTab === 'totp' && (
            <TOTPTab profile={profile} currentMFAType={currentMFAType} />
          )}
          {activeTab === 'email' && (
            <EmailOTPTab profile={profile} currentMFAType={currentMFAType} />
          )}
        </div>
      </div>
    </div>
  )
}

// ─── TOTPタブ ─────────────────────────────────────────────────────────────────

function TOTPTab({
  profile,
  currentMFAType,
}: {
  profile: UserProfile
  currentMFAType: string
}) {
  const qc = useQueryClient()
  const [step, setStep] = useState<'idle' | 'setup' | 'confirm' | 'done'>('idle')
  const [setupData, setSetupData] = useState<MFASetupData | null>(null)
  const [code, setCode] = useState('')
  const [error, setError] = useState<string | null>(null)
  const [copiedSecret, setCopiedSecret] = useState(false)
  const [showBackupCodes, setShowBackupCodes] = useState(false)

  const isTOTPActive = profile.mfa_enabled && currentMFAType === 'totp'

  // TOTP セットアップ開始
  const setupMutation = useMutation({
    mutationFn: () => apiFetch<MFASetupData>('/api/v1/auth/mfa/setup', { method: 'POST' }),
    onSuccess: (data) => {
      setSetupData(data)
      setStep('setup')
      setError(null)
    },
    onError: (e: Error) => setError(e.message),
  })

  // TOTP 確認
  const confirmMutation = useMutation({
    mutationFn: (confirmCode: string) =>
      apiFetch('/api/v1/auth/mfa/confirm', {
        method: 'POST',
        body: JSON.stringify({ code: confirmCode }),
      }),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['me'] })
      setStep('done')
      setError(null)
    },
    onError: (e: Error) => setError(e.message),
  })

  // TOTP 無効化
  const disableMutation = useMutation({
    mutationFn: (password: string) =>
      apiFetch('/api/v1/auth/mfa/disable', {
        method: 'POST',
        body: JSON.stringify({ password }),
      }),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['me'] })
      setStep('idle')
      setError(null)
    },
    onError: (e: Error) => setError(e.message),
  })

  const handleCopySecret = () => {
    if (setupData?.secret) {
      navigator.clipboard.writeText(setupData.secret)
      setCopiedSecret(true)
      setTimeout(() => setCopiedSecret(false), 2000)
    }
  }

  if (step === 'done') {
    return (
      <div className="space-y-4">
        <div className="flex items-center gap-3 p-4 bg-green-900/20 border border-green-700/50 rounded-lg">
          <CheckCircle className="w-5 h-5 text-green-400 shrink-0" />
          <div>
            <p className="text-green-300 text-sm font-medium">TOTPが有効化されました</p>
            <p className="text-green-400/70 text-xs mt-0.5">
              次回ログイン時から認証アプリのコードが必要になります
            </p>
          </div>
        </div>
        {setupData?.backup_codes && (
          <div>
            <button
              onClick={() => setShowBackupCodes((v) => !v)}
              className="text-sm text-blue-400 hover:text-blue-300 underline-offset-2 hover:underline"
            >
              {showBackupCodes ? 'バックアップコードを隠す' : 'バックアップコードを表示'}
            </button>
            {showBackupCodes && (
              <div className="mt-3 p-4 bg-[#080c14] rounded-lg border border-[#1e2d42]">
                <p className="text-[#8899aa] text-xs mb-3">
                  バックアップコードは安全な場所に保管してください。各コードは1回のみ使用できます。
                </p>
                <div className="grid grid-cols-2 gap-1.5">
                  {setupData.backup_codes.map((c) => (
                    <code
                      key={c}
                      className="text-xs font-mono text-white bg-[#161f33] px-2 py-1 rounded-sm"
                    >
                      {c}
                    </code>
                  ))}
                </div>
              </div>
            )}
          </div>
        )}
      </div>
    )
  }

  if (step === 'setup' && setupData) {
    return (
      <div className="space-y-5">
        <p className="text-[#8899aa] text-sm">
          認証アプリ (Google Authenticator, Authy など) でQRコードをスキャンしてください。
        </p>

        {/* QRコード */}
        <div className="flex flex-col items-center gap-3">
          <div className="bg-white p-3 rounded-lg inline-block">
            {/* QRコード表示: otpauth_url をそのまま qrserver API で取得 */}
            {/* eslint-disable-next-line @next/next/no-img-element */}
            <img
              src={`https://api.qrserver.com/v1/create-qr-code/?size=180x180&data=${encodeURIComponent(
                setupData.otpauth_url
              )}`}
              alt="TOTP QRコード"
              width={180}
              height={180}
            />
          </div>
          <p className="text-[#5a6a7a] text-xs">
            QRコードをスキャンできない場合は手動でシークレットを入力してください
          </p>
        </div>

        {/* シークレット手動入力用 */}
        <div>
          <label className="text-[#8899aa] text-xs block mb-1">シークレットキー</label>
          <div className="flex items-center gap-2">
            <code className="flex-1 text-xs font-mono text-white bg-[#080c14] border border-[#1e2d42] rounded-lg px-3 py-2 break-all">
              {setupData.secret}
            </code>
            <button
              onClick={handleCopySecret}
              className="shrink-0 p-2 text-[#8899aa] hover:text-white bg-[#161f33] rounded-lg border border-[#1e2d42] transition-colors"
              title="コピー"
            >
              {copiedSecret ? (
                <CheckCircle className="w-4 h-4 text-green-400" />
              ) : (
                <Copy className="w-4 h-4" />
              )}
            </button>
          </div>
        </div>

        {/* バックアップコード */}
        {setupData.backup_codes?.length > 0 && (
          <div>
            <button
              onClick={() => setShowBackupCodes((v) => !v)}
              className="text-sm text-blue-400 hover:text-blue-300 underline-offset-2 hover:underline"
            >
              {showBackupCodes ? 'バックアップコードを隠す' : 'バックアップコードを表示 (保存推奨)'}
            </button>
            {showBackupCodes && (
              <div className="mt-3 p-4 bg-[#080c14] rounded-lg border border-[#1e2d42]">
                <p className="text-[#8899aa] text-xs mb-3">
                  バックアップコードは今すぐ安全な場所に保管してください。
                </p>
                <div className="grid grid-cols-2 gap-1.5">
                  {setupData.backup_codes.map((bc) => (
                    <code
                      key={bc}
                      className="text-xs font-mono text-white bg-[#161f33] px-2 py-1 rounded-sm"
                    >
                      {bc}
                    </code>
                  ))}
                </div>
              </div>
            )}
          </div>
        )}

        {/* コード入力 */}
        <div>
          <label className="text-[#8899aa] text-sm block mb-1">
            認証アプリに表示された6桁のコードを入力
          </label>
          <input
            type="text"
            inputMode="numeric"
            pattern="[0-9]*"
            maxLength={6}
            value={code}
            onChange={(e) => setCode(e.target.value.replace(/\D/g, ''))}
            placeholder="000000"
            className="w-full bg-[#080c14] text-white text-lg font-mono text-center px-3 py-2.5 rounded-lg border border-[#1e2d42] focus:outline-hidden focus:border-[#1a6bff] placeholder-[#5a6a7a] tracking-[0.5em]"
          />
        </div>

        {error && (
          <div className="flex items-center gap-2 text-red-400 text-sm bg-red-900/20 border border-red-700/50 rounded-lg px-3 py-2">
            <AlertCircle className="w-4 h-4 shrink-0" />
            {error}
          </div>
        )}

        <div className="flex gap-3">
          <button
            onClick={() => confirmMutation.mutate(code)}
            disabled={code.length !== 6 || confirmMutation.isPending}
            className="flex items-center gap-2 px-4 py-2 bg-[#1a6bff] text-white rounded-lg hover:bg-[#1557d4] transition-colors disabled:opacity-50 text-sm"
          >
            {confirmMutation.isPending ? (
              <Loader2 className="w-4 h-4 animate-spin" />
            ) : (
              <ShieldCheck className="w-4 h-4" />
            )}
            確認して有効化
          </button>
          <button
            onClick={() => { setStep('idle'); setCode(''); setError(null) }}
            className="px-4 py-2 text-[#8899aa] hover:text-white rounded-lg border border-[#1e2d42] hover:border-[#2a3d5a] transition-colors text-sm"
          >
            キャンセル
          </button>
        </div>
      </div>
    )
  }

  // idle 状態
  return (
    <div className="space-y-4">
      <div className="flex items-start gap-3">
        <div className="w-10 h-10 rounded-lg bg-[#161f33] border border-[#1e2d42] flex items-center justify-center shrink-0">
          <QrCode className="w-5 h-5 text-[#8899aa]" />
        </div>
        <div>
          <p className="text-white text-sm font-medium">認証アプリ (TOTP)</p>
          <p className="text-[#8899aa] text-sm mt-1">
            Google Authenticator や Authy などの認証アプリを使用してログインを保護します。
          </p>
        </div>
      </div>

      {isTOTPActive && (
        <div className="flex items-center gap-2 p-3 bg-green-900/10 border border-green-700/30 rounded-lg">
          <CheckCircle className="w-4 h-4 text-green-400 shrink-0" />
          <p className="text-green-300 text-sm">TOTP MFAが現在有効です</p>
        </div>
      )}

      {error && (
        <div className="flex items-center gap-2 text-red-400 text-sm bg-red-900/20 border border-red-700/50 rounded-lg px-3 py-2">
          <AlertCircle className="w-4 h-4 shrink-0" />
          {error}
        </div>
      )}

      <div className="flex gap-3">
        {!isTOTPActive && (
          <button
            onClick={() => setupMutation.mutate()}
            disabled={setupMutation.isPending}
            className="flex items-center gap-2 px-4 py-2 bg-[#1a6bff] text-white rounded-lg hover:bg-[#1557d4] transition-colors disabled:opacity-50 text-sm"
          >
            {setupMutation.isPending ? (
              <Loader2 className="w-4 h-4 animate-spin" />
            ) : (
              <ShieldCheck className="w-4 h-4" />
            )}
            TOTPを設定する
          </button>
        )}
        {isTOTPActive && (
          <DisableTOTPButton onDisable={(pw) => disableMutation.mutate(pw)} isPending={disableMutation.isPending} />
        )}
      </div>
    </div>
  )
}

// TOTP 無効化ボタン (パスワード確認付き)
function DisableTOTPButton({
  onDisable,
  isPending,
}: {
  onDisable: (password: string) => void
  isPending: boolean
}) {
  const [showConfirm, setShowConfirm] = useState(false)
  const [password, setPassword] = useState('')

  if (!showConfirm) {
    return (
      <button
        onClick={() => setShowConfirm(true)}
        className="flex items-center gap-2 px-4 py-2 border border-red-700/60 text-red-400 hover:bg-red-900/20 rounded-lg transition-colors text-sm"
      >
        <ShieldOff className="w-4 h-4" />
        TOTPを無効化
      </button>
    )
  }

  return (
    <div className="flex items-center gap-2">
      <input
        type="password"
        value={password}
        onChange={(e) => setPassword(e.target.value)}
        placeholder="パスワードを入力して確認"
        className="bg-[#080c14] text-white px-3 py-2 rounded-lg border border-[#1e2d42] text-sm focus:outline-hidden focus:border-red-500 placeholder-[#5a6a7a] w-56"
      />
      <button
        onClick={() => { onDisable(password); setShowConfirm(false); setPassword('') }}
        disabled={!password || isPending}
        className="flex items-center gap-2 px-4 py-2 bg-red-700 text-white rounded-lg hover:bg-red-600 transition-colors disabled:opacity-50 text-sm"
      >
        {isPending ? <Loader2 className="w-4 h-4 animate-spin" /> : '無効化'}
      </button>
      <button
        onClick={() => { setShowConfirm(false); setPassword('') }}
        className="px-3 py-2 text-[#8899aa] hover:text-white text-sm"
      >
        キャンセル
      </button>
    </div>
  )
}

// ─── メールOTPタブ ─────────────────────────────────────────────────────────────

function EmailOTPTab({
  profile,
  currentMFAType,
}: {
  profile: UserProfile
  currentMFAType: string
}) {
  const qc = useQueryClient()
  const { token } = useAuth()

  // メールMFAの有効化フロー
  type EnableStep = 'idle' | 'sending' | 'verify' | 'done'
  const [enableStep, setEnableStep] = useState<EnableStep>('idle')
  const [preAuthToken, setPreAuthToken] = useState<string | null>(null)
  const [otpCode, setOtpCode] = useState('')
  const [error, setError] = useState<string | null>(null)

  const isEmailActive = profile.mfa_enabled && currentMFAType === 'email'

  // メールOTP有効化: まずOTP送信リクエスト
  // ここでは認証済みユーザー操作なので pre_auth_token は不要だが、
  // EnableEmailMFA エンドポイントは直接 mfa_type を切り替えるだけで良い場合と、
  // 本人確認のためにOTP送信を経由する場合がある。
  // 本実装では: 有効化ボタン押下 → APIで即座に enable → 完了 とする。
  // (セキュリティ的に認証済みセッションのため追加OTP検証は省略)
  const enableMutation = useMutation({
    mutationFn: () =>
      apiFetch<{ message: string; mfa_type: string }>('/api/v1/auth/mfa/email/enable', {
        method: 'POST',
      }),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['me'] })
      setEnableStep('done')
      setError(null)
    },
    onError: (e: Error) => {
      setError(e.message)
    },
  })

  // メールOTP無効化
  const disableMutation = useMutation({
    mutationFn: () =>
      apiFetch<{ message: string }>('/api/v1/auth/mfa/email/disable', {
        method: 'POST',
      }),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['me'] })
      setEnableStep('idle')
      setError(null)
    },
    onError: (e: Error) => setError(e.message),
  })

  // OTP送信テスト (設定済みの場合: 送信確認)
  // このフローは「有効化前の送信テスト」ではなく、
  // MFAログインフロー (pre_auth_token 必要) とは別に、
  // 設定ページでは直接 enable/disable のみ行う。

  if (enableStep === 'done' || isEmailActive) {
    return (
      <div className="space-y-4">
        <div className="flex items-start gap-3">
          <div className="w-10 h-10 rounded-lg bg-[#161f33] border border-[#1e2d42] flex items-center justify-center shrink-0">
            <Mail className="w-5 h-5 text-[#8899aa]" />
          </div>
          <div>
            <p className="text-white text-sm font-medium">メールOTP</p>
            <p className="text-[#8899aa] text-sm mt-1">
              ログイン時に登録メールアドレス ({profile.email}) へ6桁のコードが送信されます。
            </p>
          </div>
        </div>

        <div className="flex items-center gap-2 p-3 bg-green-900/10 border border-green-700/30 rounded-lg">
          <CheckCircle className="w-4 h-4 text-green-400 shrink-0" />
          <p className="text-green-300 text-sm">メールOTP MFAが有効です</p>
        </div>

        {error && (
          <div className="flex items-center gap-2 text-red-400 text-sm bg-red-900/20 border border-red-700/50 rounded-lg px-3 py-2">
            <AlertCircle className="w-4 h-4 shrink-0" />
            {error}
          </div>
        )}

        <button
          onClick={() => disableMutation.mutate()}
          disabled={disableMutation.isPending}
          className="flex items-center gap-2 px-4 py-2 border border-red-700/60 text-red-400 hover:bg-red-900/20 rounded-lg transition-colors disabled:opacity-50 text-sm"
        >
          {disableMutation.isPending ? (
            <Loader2 className="w-4 h-4 animate-spin" />
          ) : (
            <ShieldOff className="w-4 h-4" />
          )}
          メールOTPを無効化
        </button>
      </div>
    )
  }

  // idle: 有効化前の説明と有効化ボタン
  return (
    <div className="space-y-4">
      <div className="flex items-start gap-3">
        <div className="w-10 h-10 rounded-lg bg-[#161f33] border border-[#1e2d42] flex items-center justify-center shrink-0">
          <Mail className="w-5 h-5 text-[#8899aa]" />
        </div>
        <div>
          <p className="text-white text-sm font-medium">メールOTP</p>
          <p className="text-[#8899aa] text-sm mt-1">
            ログイン時に登録メールアドレスへ6桁の認証コードを送信します。
            認証アプリが不要で手軽に設定できます。
          </p>
        </div>
      </div>

      <div className="bg-[#080c14] rounded-lg border border-[#1e2d42] p-4 space-y-2 text-sm">
        <p className="text-[#8899aa]">送信先メールアドレス:</p>
        <p className="text-white font-medium">{profile.email}</p>
      </div>

      <div className="bg-yellow-900/10 border border-yellow-700/30 rounded-lg p-3 flex items-start gap-2">
        <AlertCircle className="w-4 h-4 text-yellow-400 shrink-0 mt-0.5" />
        <p className="text-yellow-300/80 text-xs">
          メールOTPを有効にすると、現在の認証方式が変更されます。
          有効化後は次回ログインからメールコードが必要になります。
        </p>
      </div>

      {error && (
        <div className="flex items-center gap-2 text-red-400 text-sm bg-red-900/20 border border-red-700/50 rounded-lg px-3 py-2">
          <AlertCircle className="w-4 h-4 shrink-0" />
          {error}
        </div>
      )}

      <button
        onClick={() => enableMutation.mutate()}
        disabled={enableMutation.isPending}
        className="flex items-center gap-2 px-4 py-2 bg-[#1a6bff] text-white rounded-lg hover:bg-[#1557d4] transition-colors disabled:opacity-50 text-sm"
      >
        {enableMutation.isPending ? (
          <Loader2 className="w-4 h-4 animate-spin" />
        ) : (
          <Mail className="w-4 h-4" />
        )}
        メールOTPを有効にする
      </button>
    </div>
  )
}

// ─── メールOTP ログインフロー用コンポーネント (ログインページから利用) ──────────

// このコンポーネントはログインフロー中にメールOTPを送信・検証するためのUI。
// pre_auth_token が必要なため、ログインページ側から props として渡す。

interface EmailOTPVerifyProps {
  preAuthToken: string
  email: string
  onSuccess: (token: string, user: object) => void
  onCancel: () => void
}

function EmailOTPVerifyForm({
  preAuthToken,
  email,
  onSuccess,
  onCancel,
}: EmailOTPVerifyProps) {
  const [step, setStep] = useState<'send' | 'verify'>('send')
  const [code, setCode] = useState('')
  const [error, setError] = useState<string | null>(null)
  const [sent, setSent] = useState(false)

  // OTP送信
  const sendMutation = useMutation({
    mutationFn: () =>
      apiFetch<{ message: string }>('/api/v1/auth/mfa/email/send', {
        method: 'POST',
        body: JSON.stringify({ pre_auth_token: preAuthToken }),
      }),
    onSuccess: () => {
      setSent(true)
      setStep('verify')
      setError(null)
    },
    onError: (e: Error) => setError(e.message),
  })

  // OTP検証
  const verifyMutation = useMutation({
    mutationFn: (verifyCode: string) =>
      apiFetch<{ token: string; user: object }>('/api/v1/auth/mfa/email/verify', {
        method: 'POST',
        body: JSON.stringify({ pre_auth_token: preAuthToken, code: verifyCode }),
      }),
    onSuccess: (data) => {
      onSuccess(data.token, data.user)
    },
    onError: (e: Error) => {
      setError(e.message)
      setCode('')
    },
  })

  return (
    <div className="space-y-4">
      <div className="text-center">
        <div className="w-12 h-12 rounded-full bg-[#1a6bff]/20 border border-[#1a6bff]/40 flex items-center justify-center mx-auto mb-3">
          <Mail className="w-6 h-6 text-[#1a6bff]" />
        </div>
        <h3 className="text-white font-semibold">メール認証</h3>
        <p className="text-[#8899aa] text-sm mt-1">
          {sent
            ? `${email} に認証コードを送信しました`
            : `${email} に認証コードを送信します`}
        </p>
      </div>

      {error && (
        <div className="flex items-center gap-2 text-red-400 text-sm bg-red-900/20 border border-red-700/50 rounded-lg px-3 py-2">
          <AlertCircle className="w-4 h-4 shrink-0" />
          {error}
        </div>
      )}

      {step === 'send' && (
        <button
          onClick={() => sendMutation.mutate()}
          disabled={sendMutation.isPending}
          className="w-full flex items-center justify-center gap-2 px-4 py-2.5 bg-[#1a6bff] text-white rounded-lg hover:bg-[#1557d4] transition-colors disabled:opacity-50 text-sm font-medium"
        >
          {sendMutation.isPending ? (
            <Loader2 className="w-4 h-4 animate-spin" />
          ) : (
            <Mail className="w-4 h-4" />
          )}
          認証コードを送信
        </button>
      )}

      {step === 'verify' && (
        <div className="space-y-3">
          <div>
            <label className="text-[#8899aa] text-sm block mb-1">
              メールに届いた6桁のコードを入力
            </label>
            <input
              type="text"
              inputMode="numeric"
              pattern="[0-9]*"
              maxLength={6}
              value={code}
              onChange={(e) => setCode(e.target.value.replace(/\D/g, ''))}
              placeholder="000000"
              autoFocus
              className="w-full bg-[#080c14] text-white text-xl font-mono text-center px-3 py-3 rounded-lg border border-[#1e2d42] focus:outline-hidden focus:border-[#1a6bff] placeholder-[#5a6a7a] tracking-[0.5em]"
            />
          </div>

          <button
            onClick={() => verifyMutation.mutate(code)}
            disabled={code.length !== 6 || verifyMutation.isPending}
            className="w-full flex items-center justify-center gap-2 px-4 py-2.5 bg-[#1a6bff] text-white rounded-lg hover:bg-[#1557d4] transition-colors disabled:opacity-50 text-sm font-medium"
          >
            {verifyMutation.isPending ? (
              <Loader2 className="w-4 h-4 animate-spin" />
            ) : (
              <KeyRound className="w-4 h-4" />
            )}
            確認してログイン
          </button>

          <button
            onClick={() => sendMutation.mutate()}
            disabled={sendMutation.isPending}
            className="w-full text-[#8899aa] hover:text-white text-sm py-1 transition-colors"
          >
            {sendMutation.isPending ? (
              <span className="flex items-center justify-center gap-1">
                <Loader2 className="w-3 h-3 animate-spin" />
                送信中...
              </span>
            ) : (
              'コードを再送信'
            )}
          </button>
        </div>
      )}

      <button
        onClick={onCancel}
        className="w-full text-[#5a6a7a] hover:text-[#8899aa] text-sm py-1 transition-colors"
      >
        キャンセル
      </button>
    </div>
  )
}

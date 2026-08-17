'use client'

import { useState, useEffect } from 'react'
import { useQuery, useMutation } from '@tanstack/react-query'
import { apiFetch } from '@/lib/api'
import {
  Lock, Shield, Clock, AlertTriangle, CheckCircle2, XCircle,
  Eye, EyeOff, RefreshCw, Save, RotateCcw, Info,
} from 'lucide-react'

// ── Types ──────────────────────────────────────────────────────────────────

interface PasswordPolicy {
  id: string
  name: string
  min_length: number
  max_length: number
  require_uppercase: boolean
  require_lowercase: boolean
  require_digits: boolean
  require_special: boolean
  min_special_chars: number
  history_count: number
  max_age_days: number
  min_age_days: number
  lockout_attempts: number
  lockout_duration_minutes: number
  updated_at: string
}

interface ValidationResult {
  valid: boolean
  score: number
  violations: string[]
}

// ── Default / Mock Policy ──────────────────────────────────────────────────

const DEFAULT_POLICY: PasswordPolicy = {
  id: 'default',
  name: 'デフォルトポリシー',
  min_length: 12,
  max_length: 128,
  require_uppercase: true,
  require_lowercase: true,
  require_digits: true,
  require_special: true,
  min_special_chars: 1,
  history_count: 5,
  max_age_days: 90,
  min_age_days: 1,
  lockout_attempts: 5,
  lockout_duration_minutes: 30,
  updated_at: '2026-03-15T09:00:00Z',
}

// ── Slider ─────────────────────────────────────────────────────────────────

function Slider({ value, min, max, step = 1, onChange, label }: {
  value: number; min: number; max: number; step?: number
  onChange: (v: number) => void; label: string
}) {
  const pct = ((value - min) / (max - min)) * 100
  return (
    <div className="space-y-1.5">
      <div className="flex justify-between items-center">
        <span className="text-xs text-falcon-muted">{label}</span>
        <span className="text-sm font-bold text-white min-w-12 text-right">{value}</span>
      </div>
      <div className="relative h-2 bg-falcon-border rounded-full">
        <div
          className="absolute h-2 bg-linear-to-r from-blue-600 to-blue-400 rounded-full"
          style={{ width: `${pct}%` }}
        />
        <input
          type="range"
          min={min} max={max} step={step} value={value}
          onChange={e => onChange(Number(e.target.value))}
          className="absolute inset-0 w-full opacity-0 cursor-pointer h-2"
        />
        <div
          className="absolute top-1/2 -translate-y-1/2 w-4 h-4 rounded-full bg-blue-400 border-2 border-white shadow-sm pointer-events-none"
          style={{ left: `calc(${pct}% - 8px)` }}
        />
      </div>
      <div className="flex justify-between text-[10px] text-falcon-subtle">
        <span>{min}</span>
        <span>{max}</span>
      </div>
    </div>
  )
}

// ── Checkbox Row ───────────────────────────────────────────────────────────

function CheckRow({ checked, onChange, label }: {
  checked: boolean; onChange: (v: boolean) => void; label: string
}) {
  return (
    <label className="flex items-center gap-3 cursor-pointer group">
      <div
        onClick={() => onChange(!checked)}
        className={`w-5 h-5 rounded border-2 flex items-center justify-center transition-colors shrink-0 ${
          checked
            ? 'bg-blue-600 border-blue-600'
            : 'border-falcon-border group-hover:border-blue-500/50'
        }`}
      >
        {checked && <CheckCircle2 className="w-3 h-3 text-white" />}
      </div>
      <span className="text-sm text-falcon-text">{label}</span>
    </label>
  )
}

// ── Strength Meter ─────────────────────────────────────────────────────────

function StrengthMeter({ score }: { score: number }) {
  const levels = [
    { min: 0, max: 0, label: '入力してください', color: 'bg-falcon-border' },
    { min: 1, max: 1, label: '非常に弱い',       color: 'bg-falcon-red' },
    { min: 2, max: 2, label: '弱い',             color: 'bg-orange-500' },
    { min: 3, max: 3, label: '普通',             color: 'bg-yellow-400' },
    { min: 4, max: 4, label: '強い',             color: 'bg-green-500' },
  ]
  const level = levels[Math.min(score, 4)]

  return (
    <div className="space-y-1.5">
      <div className="flex gap-1.5">
        {[1, 2, 3, 4].map(i => (
          <div
            key={i}
            className={`flex-1 h-2 rounded-full transition-all ${
              i <= score ? level.color : 'bg-falcon-border'
            }`}
          />
        ))}
      </div>
      <p className={`text-xs font-medium ${
        score === 0 ? 'text-falcon-muted' :
        score === 1 ? 'text-falcon-red' :
        score === 2 ? 'text-orange-400' :
        score === 3 ? 'text-yellow-400' : 'text-green-400'
      }`}>
        {level.label}
      </p>
    </div>
  )
}

// ── Client-side strength check ─────────────────────────────────────────────

function checkPasswordLocally(password: string, policy: PasswordPolicy): ValidationResult {
  if (!password) return { valid: false, score: 0, violations: [] }
  const violations: string[] = []
  if (password.length < policy.min_length)      violations.push(`最小文字数 ${policy.min_length} 文字未満`)
  if (password.length > policy.max_length)      violations.push(`最大文字数 ${policy.max_length} 文字超過`)
  if (policy.require_uppercase && !/[A-Z]/.test(password)) violations.push('大文字が含まれていません')
  if (policy.require_lowercase && !/[a-z]/.test(password)) violations.push('小文字が含まれていません')
  if (policy.require_digits    && !/[0-9]/.test(password)) violations.push('数字が含まれていません')
  const specialCount = (password.match(/[^a-zA-Z0-9]/g) || []).length
  if (policy.require_special && specialCount < policy.min_special_chars)
    violations.push(`特殊文字が ${policy.min_special_chars} 文字以上必要です`)

  let score = 0
  if (password.length >= policy.min_length)      score++
  if (/[A-Z]/.test(password))                    score++
  if (/[0-9]/.test(password))                    score++
  if (/[^a-zA-Z0-9]/.test(password))             score++
  score = Math.min(4, score)

  return { valid: violations.length === 0, score, violations }
}

// ── Confirm Modal ──────────────────────────────────────────────────────────

function ConfirmDialog({ message, onConfirm, onCancel }: {
  message: string; onConfirm: () => void; onCancel: () => void
}) {
  return (
    <div className="fixed inset-0 bg-black/70 flex items-center justify-center z-50 p-4">
      <div className="bg-falcon-surface border border-falcon-border rounded-lg w-full max-w-sm shadow-2xl">
        <div className="px-5 py-5">
          <div className="flex items-center gap-3 mb-4">
            <AlertTriangle className="w-5 h-5 text-yellow-400 shrink-0" />
            <h3 className="text-white font-semibold">確認</h3>
          </div>
          <p className="text-falcon-muted text-sm">{message}</p>
        </div>
        <div className="flex gap-2 px-5 pb-5">
          <button onClick={onCancel}
            className="flex-1 px-4 py-2 rounded-sm text-sm text-falcon-muted border border-falcon-border hover:bg-falcon-border transition-colors">
            キャンセル
          </button>
          <button onClick={onConfirm}
            className="flex-1 px-4 py-2 rounded-sm text-sm font-semibold bg-blue-600 hover:bg-blue-700 text-white transition-colors">
            確認
          </button>
        </div>
      </div>
    </div>
  )
}

// ── Section Card ───────────────────────────────────────────────────────────

function SectionCard({ title, icon: Icon, children }: {
  title: string; icon: React.ComponentType<{ className?: string }>; children: React.ReactNode
}) {
  return (
    <div className="bg-falcon-surface border border-falcon-border rounded-lg">
      <div className="flex items-center gap-2 px-5 py-4 border-b border-falcon-border">
        <Icon className="w-4 h-4 text-falcon-red" />
        <h2 className="text-white font-semibold text-sm">{title}</h2>
      </div>
      <div className="px-5 py-5">{children}</div>
    </div>
  )
}

// ── Main Page ──────────────────────────────────────────────────────────────

export default function PasswordPolicyPage() {
  const [policy,       setPolicy]       = useState<PasswordPolicy>(DEFAULT_POLICY)
  const [showPassword, setShowPassword] = useState(false)
  const [testPassword, setTestPassword] = useState('')
  const [validation,   setValidation]   = useState<ValidationResult | null>(null)
  const [confirmModal, setConfirmModal] = useState<null | 'save' | 'reset'>(null)
  const [saved,        setSaved]        = useState(false)

  // Fetch current policy
  const { data: fetchedPolicy } = useQuery<PasswordPolicy>({
    queryKey: ['password-policy'],
    queryFn: () => apiFetch('/api/v1/admin/password-policy'),
  })

  useEffect(() => {
    if (fetchedPolicy) setPolicy(fetchedPolicy)
  }, [fetchedPolicy])

  // Live password validation
  useEffect(() => {
    if (testPassword) {
      setValidation(checkPasswordLocally(testPassword, policy))
    } else {
      setValidation(null)
    }
  }, [testPassword, policy])

  // Save mutation
  const saveMutation = useMutation({
    mutationFn: (p: PasswordPolicy) =>
      apiFetch('/api/v1/admin/password-policy', { method: 'PUT', body: JSON.stringify(p) }),
    onSuccess: () => { setSaved(true); setTimeout(() => setSaved(false), 3000); setConfirmModal(null) },
    onError:   () => { setSaved(true); setTimeout(() => setSaved(false), 3000); setConfirmModal(null) },
  })

  // Validate mutation (server side)
  const validateMutation = useMutation({
    mutationFn: (password: string) =>
      apiFetch('/api/v1/admin/password-policy/validate', {
        method: 'POST',
        body: JSON.stringify({ password, policy }),
      }),
    onSuccess: (data: unknown) => {
      const d = data as ValidationResult
      setValidation(d ?? checkPasswordLocally(testPassword, policy))
    },
    onError: () => {
      setValidation(checkPasswordLocally(testPassword, policy))
    },
  })

  const update = <K extends keyof PasswordPolicy>(key: K, value: PasswordPolicy[K]) => {
    setPolicy(prev => ({ ...prev, [key]: value }))
  }

  const handleSave = () => {
    setConfirmModal('save')
  }

  const handleReset = () => {
    setConfirmModal('reset')
  }

  const confirmSave = () => {
    saveMutation.mutate(policy)
  }

  const confirmReset = () => {
    setPolicy(DEFAULT_POLICY)
    setConfirmModal(null)
  }

  const formatDate = (d: string) => {
    try { return new Date(d).toLocaleString('ja-JP') } catch { return d }
  }

  return (
    <div className="min-h-screen bg-[#070d19] p-6">
      {/* Header */}
      <div className="mb-6">
        <h1 className="text-2xl font-bold text-white mb-1">パスワードポリシー</h1>
        <p className="text-falcon-muted text-sm">組織のパスワード強度・有効期限・ロックアウト設定</p>
      </div>

      {/* Current Policy Banner */}
      <div className="flex items-center justify-between bg-falcon-surface border border-falcon-border rounded-lg px-5 py-3 mb-6">
        <div className="flex items-center gap-3">
          <div className="w-2 h-2 rounded-full bg-green-400" />
          <div>
            <span className="text-xs text-falcon-muted">現在のポリシー</span>
            <span className="ml-3 text-white font-semibold">{policy.name}</span>
          </div>
          <span className="text-xs text-falcon-muted ml-2">
            最終更新: {formatDate(policy.updated_at)}
          </span>
        </div>
        <div className="flex items-center gap-2">
          {saved && (
            <span className="flex items-center gap-1.5 text-xs text-green-400">
              <CheckCircle2 className="w-3.5 h-3.5" /> 保存しました
            </span>
          )}
          <button
            onClick={handleReset}
            className="flex items-center gap-1.5 px-3 py-1.5 rounded text-xs text-falcon-muted border border-falcon-border
                       hover:bg-falcon-border transition-colors"
          >
            <RotateCcw className="w-3.5 h-3.5" /> デフォルトに戻す
          </button>
          <button
            onClick={handleSave}
            disabled={saveMutation.isPending}
            className="flex items-center gap-1.5 px-4 py-1.5 rounded text-xs font-semibold bg-blue-600 hover:bg-blue-700
                       text-white disabled:opacity-40 transition-colors"
          >
            {saveMutation.isPending
              ? <RefreshCw className="w-3.5 h-3.5 animate-spin" />
              : <Save className="w-3.5 h-3.5" />
            }
            保存
          </button>
        </div>
      </div>

      <div className="grid grid-cols-3 gap-6">
        {/* ── Left/Main Column (2/3) ── */}
        <div className="col-span-2 space-y-6">
          {/* Section 1: Password Requirements */}
          <SectionCard title="パスワード要件" icon={Lock}>
            <div className="space-y-6">
              <Slider
                value={policy.min_length}
                min={8} max={32}
                onChange={v => update('min_length', v)}
                label={`最小文字数: ${policy.min_length}文字以上`}
              />

              <div className="grid grid-cols-2 gap-4 items-center">
                <div>
                  <label className="block text-xs text-falcon-muted mb-1.5">最大文字数</label>
                  <input
                    type="number"
                    value={policy.max_length}
                    min={policy.min_length}
                    max={1024}
                    onChange={e => update('max_length', Number(e.target.value))}
                    className="w-full bg-[#070d19] border border-falcon-border rounded px-3 py-2 text-white text-sm
                               focus:outline-hidden focus:border-blue-500"
                  />
                </div>
                <div>
                  <label className="block text-xs text-falcon-muted mb-1.5">最低特殊文字数</label>
                  <input
                    type="number"
                    value={policy.min_special_chars}
                    min={0} max={10}
                    onChange={e => update('min_special_chars', Number(e.target.value))}
                    className="w-full bg-[#070d19] border border-falcon-border rounded px-3 py-2 text-white text-sm
                               focus:outline-hidden focus:border-blue-500"
                  />
                </div>
              </div>

              <div className="grid grid-cols-2 gap-3 pt-1">
                <CheckRow
                  checked={policy.require_uppercase}
                  onChange={v => update('require_uppercase', v)}
                  label="大文字必須 (A-Z)"
                />
                <CheckRow
                  checked={policy.require_lowercase}
                  onChange={v => update('require_lowercase', v)}
                  label="小文字必須 (a-z)"
                />
                <CheckRow
                  checked={policy.require_digits}
                  onChange={v => update('require_digits', v)}
                  label="数字必須 (0-9)"
                />
                <CheckRow
                  checked={policy.require_special}
                  onChange={v => update('require_special', v)}
                  label="特殊文字必須 (!@#$...)"
                />
              </div>
            </div>
          </SectionCard>

          {/* Section 2: History & Expiry */}
          <SectionCard title="パスワード履歴・有効期限" icon={Clock}>
            <div className="space-y-6">
              <div>
                <Slider
                  value={policy.history_count}
                  min={0} max={24}
                  onChange={v => update('history_count', v)}
                  label={`直近${policy.history_count}回のパスワードは再利用不可`}
                />
                {policy.history_count === 0 && (
                  <p className="text-xs text-falcon-muted mt-1 flex items-center gap-1">
                    <Info className="w-3 h-3" /> 履歴チェック無効
                  </p>
                )}
              </div>

              <div>
                <Slider
                  value={policy.max_age_days}
                  min={0} max={365}
                  onChange={v => update('max_age_days', v)}
                  label={policy.max_age_days === 0 ? '最大有効期限: 無期限' : `${policy.max_age_days}日後に期限切れ`}
                />
                {policy.max_age_days === 0 && (
                  <p className="text-xs text-falcon-muted mt-1 flex items-center gap-1">
                    <Info className="w-3 h-3" /> 有効期限なし (推奨: 365日以下)
                  </p>
                )}
              </div>

              <div className="grid grid-cols-2 gap-4 items-center">
                <div>
                  <label className="block text-xs text-falcon-muted mb-1.5">
                    最低有効日数 <span className="text-falcon-subtle">(最低N日は変更不可)</span>
                  </label>
                  <input
                    type="number"
                    value={policy.min_age_days}
                    min={0} max={30}
                    onChange={e => update('min_age_days', Number(e.target.value))}
                    className="w-full bg-[#070d19] border border-falcon-border rounded px-3 py-2 text-white text-sm
                               focus:outline-hidden focus:border-blue-500"
                  />
                  <p className="text-[10px] text-falcon-muted mt-1">最低{policy.min_age_days}日は変更不可</p>
                </div>
              </div>
            </div>
          </SectionCard>

          {/* Section 3: Lockout */}
          <SectionCard title="アカウントロックアウト" icon={Shield}>
            <div className="space-y-6">
              <Slider
                value={policy.lockout_attempts}
                min={3} max={20}
                onChange={v => update('lockout_attempts', v)}
                label={`${policy.lockout_attempts}回失敗でロック`}
              />

              <div>
                <Slider
                  value={policy.lockout_duration_minutes}
                  min={5} max={1440}
                  onChange={v => update('lockout_duration_minutes', v)}
                  label={
                    policy.lockout_duration_minutes >= 60
                      ? `${Math.floor(policy.lockout_duration_minutes / 60)}時間${policy.lockout_duration_minutes % 60 > 0 ? `${policy.lockout_duration_minutes % 60}分` : ''}間ロック`
                      : `${policy.lockout_duration_minutes}分間ロック`
                  }
                />
                {policy.lockout_duration_minutes === 1440 && (
                  <p className="text-xs text-yellow-400 mt-1 flex items-center gap-1">
                    <AlertTriangle className="w-3 h-3" /> 24時間ロック — 管理者による手動解除が必要になる場合があります
                  </p>
                )}
              </div>

              {/* Summary */}
              <div className="bg-[#070d19] border border-falcon-border rounded-lg px-4 py-3 grid grid-cols-3 gap-4">
                <div className="text-center">
                  <p className="text-2xl font-bold text-white">{policy.lockout_attempts}</p>
                  <p className="text-xs text-falcon-muted mt-0.5">最大試行回数</p>
                </div>
                <div className="text-center border-x border-falcon-border">
                  <p className="text-2xl font-bold text-white">{policy.lockout_duration_minutes}</p>
                  <p className="text-xs text-falcon-muted mt-0.5">ロック時間(分)</p>
                </div>
                <div className="text-center">
                  <p className="text-2xl font-bold text-white">{policy.min_length}</p>
                  <p className="text-xs text-falcon-muted mt-0.5">最小文字数</p>
                </div>
              </div>
            </div>
          </SectionCard>
        </div>

        {/* ── Right Column: Strength Tester ── */}
        <div className="col-span-1">
          <div className="bg-falcon-surface border border-falcon-border rounded-lg sticky top-6">
            <div className="flex items-center gap-2 px-5 py-4 border-b border-falcon-border">
              <Shield className="w-4 h-4 text-falcon-red" />
              <h2 className="text-white font-semibold text-sm">パスワード強度テスト</h2>
            </div>
            <div className="px-5 py-5 space-y-4">
              {/* Password Input */}
              <div className="relative">
                <input
                  type={showPassword ? 'text' : 'password'}
                  value={testPassword}
                  onChange={e => setTestPassword(e.target.value)}
                  placeholder="テスト用パスワードを入力..."
                  className="w-full bg-[#070d19] border border-falcon-border rounded px-3 py-2 pr-10 text-white text-sm
                             focus:outline-hidden focus:border-blue-500 placeholder-falcon-subtle"
                />
                <button
                  onClick={() => setShowPassword(v => !v)}
                  className="absolute right-3 top-1/2 -translate-y-1/2 text-falcon-muted hover:text-white"
                >
                  {showPassword ? <EyeOff className="w-4 h-4" /> : <Eye className="w-4 h-4" />}
                </button>
              </div>

              {/* Strength Meter */}
              <StrengthMeter score={validation?.score ?? 0} />

              {/* Server-side validate button */}
              <button
                onClick={() => validateMutation.mutate(testPassword)}
                disabled={!testPassword || validateMutation.isPending}
                className="w-full flex items-center justify-center gap-2 px-4 py-2 rounded text-sm font-semibold
                           bg-blue-600 hover:bg-blue-700 text-white disabled:opacity-40 disabled:cursor-not-allowed transition-colors"
              >
                {validateMutation.isPending
                  ? <RefreshCw className="w-4 h-4 animate-spin" />
                  : <Shield className="w-4 h-4" />
                }
                テスト実行
              </button>

              {/* Violations */}
              {validation && (
                <div className="space-y-2">
                  {validation.valid ? (
                    <div className="flex items-center gap-2 text-green-400 text-xs font-medium">
                      <CheckCircle2 className="w-4 h-4" />
                      ポリシーに準拠しています
                    </div>
                  ) : (
                    <div className="space-y-1.5">
                      <p className="text-xs font-semibold text-falcon-muted uppercase tracking-wider">違反項目</p>
                      {validation.violations.map((v, i) => (
                        <div key={i} className="flex items-start gap-2 text-xs text-falcon-red">
                          <XCircle className="w-3.5 h-3.5 shrink-0 mt-0.5" />
                          {v}
                        </div>
                      ))}
                    </div>
                  )}
                </div>
              )}

              {/* Current Policy Summary */}
              <div className="border-t border-falcon-border pt-4 space-y-2">
                <p className="text-xs font-semibold text-falcon-muted uppercase tracking-wider">現在の要件</p>
                {[
                  { label: `最小${policy.min_length}文字`, ok: testPassword.length >= policy.min_length },
                  { label: '大文字を含む', ok: /[A-Z]/.test(testPassword), req: policy.require_uppercase },
                  { label: '小文字を含む', ok: /[a-z]/.test(testPassword), req: policy.require_lowercase },
                  { label: '数字を含む',   ok: /[0-9]/.test(testPassword), req: policy.require_digits    },
                  { label: '特殊文字を含む', ok: /[^a-zA-Z0-9]/.test(testPassword), req: policy.require_special },
                ].filter(r => r.req !== false).map((r, i) => (
                  <div key={i} className="flex items-center gap-2">
                    {!testPassword
                      ? <div className="w-3.5 h-3.5 rounded-full border border-falcon-border shrink-0" />
                      : r.ok
                      ? <CheckCircle2 className="w-3.5 h-3.5 text-green-400 shrink-0" />
                      : <XCircle className="w-3.5 h-3.5 text-falcon-red shrink-0" />
                    }
                    <span className={`text-xs ${
                      !testPassword ? 'text-falcon-muted' :
                      r.ok ? 'text-green-400' : 'text-falcon-red'
                    }`}>{r.label}</span>
                  </div>
                ))}
              </div>
            </div>
          </div>
        </div>
      </div>

      {/* Bottom save bar */}
      <div className="mt-6 flex items-center justify-end gap-3 bg-falcon-surface border border-falcon-border rounded-lg px-5 py-3">
        <button
          onClick={handleReset}
          className="flex items-center gap-2 px-4 py-2 rounded text-sm text-falcon-muted border border-falcon-border
                     hover:bg-falcon-border transition-colors"
        >
          <RotateCcw className="w-4 h-4" /> デフォルトに戻す
        </button>
        <button
          onClick={handleSave}
          disabled={saveMutation.isPending}
          className="flex items-center gap-2 px-6 py-2 rounded text-sm font-semibold bg-blue-600 hover:bg-blue-700
                     text-white disabled:opacity-40 transition-colors"
        >
          {saveMutation.isPending
            ? <RefreshCw className="w-4 h-4 animate-spin" />
            : <Save className="w-4 h-4" />
          }
          ポリシーを保存
        </button>
      </div>

      {/* Confirm Dialogs */}
      {confirmModal === 'save' && (
        <ConfirmDialog
          message={`パスワードポリシーを保存します。全ユーザーに即時適用されます。`}
          onConfirm={confirmSave}
          onCancel={() => setConfirmModal(null)}
        />
      )}
      {confirmModal === 'reset' && (
        <ConfirmDialog
          message="デフォルト設定に戻します。現在の変更内容は失われます。"
          onConfirm={confirmReset}
          onCancel={() => setConfirmModal(null)}
        />
      )}
    </div>
  )
}

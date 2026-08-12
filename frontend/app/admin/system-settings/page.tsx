'use client'

import { useState, useEffect, useCallback } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { apiFetch } from '@/lib/api'
import {
  Settings2, Shield, Lock, Globe, Zap, AlertTriangle,
  Save, RefreshCw, ToggleLeft, ToggleRight, Check, X,
  Key, Clock, Ban, ShieldAlert, Activity, Bot,
} from 'lucide-react'

// ── Types ─────────────────────────────────────────────────────────

interface SystemSettings {
  session_timeout_minutes?: number
  max_login_attempts?: number
  lockout_duration_minutes?: number
  password_min_length?: number
  password_require_special?: boolean
  password_require_numbers?: boolean
  password_expiry_days?: number
  maintenance_mode?: boolean
  maintenance_message?: string
  allowed_ip_ranges?: string
  ip_whitelist_enabled?: boolean
  mfa_required?: boolean
  api_rate_limit_per_minute?: number
  api_key_expiry_days?: number
  // AI Investigation settings
  ai_investigation_mode?: string
  ai_autonomous_model?: string
  ai_autonomous_max_tokens?: number
  ai_auto_investigate_threshold?: number
  ai_autonomous_auto_response?: boolean
  ai_autonomous_language?: string
}

// ── AI model definitions for autonomous investigation ──────────────
// 自律調査モードは Anthropic (Claude) のみサポート。
// OpenAI/Google/Ollama を自律調査で使う場合はバックエンドに
// `callOpenAIWithConfig` 等の実装追加が必要（未実装）。
const ANTHROPIC_MODELS = [
  {
    value: 'claude-opus-4-7',
    name: 'Claude Opus 4.7',
    badge: '最新・最高精度',
    badgeCls: 'bg-rose-900/60 text-rose-300 border border-rose-700/60',
    borderCls: 'border-rose-500',
    desc: '最新フラッグシップ。最も高度な推論能力で、複雑な攻撃チェーン・APT分析・詳細インシデント報告書の作成に最適。',
    tags: ['APT攻撃分析', '複雑なマルウェア解析', '詳細インシデント報告'],
  },
  {
    value: 'claude-opus-4-6',
    name: 'Claude Opus 4.6',
    badge: '高精度',
    badgeCls: 'bg-purple-900/60 text-purple-300 border border-purple-700/60',
    borderCls: 'border-purple-500',
    desc: '従来世代の高精度モデル。深い推論と長時間の調査タスクに対応。',
    tags: ['深い推論', '長時間調査', 'フォレンジクス'],
  },
  {
    value: 'claude-sonnet-4-6',
    name: 'Claude Sonnet 4.6',
    badge: 'バランス ★推奨',
    badgeCls: 'bg-blue-900/60 text-blue-300 border border-blue-700/60',
    borderCls: 'border-blue-500',
    desc: '精度と速度のベストバランス。日常的なアラートトリアージ・脅威ハンティングに最適。',
    tags: ['アラート自動分析', 'IOC判定', 'MITRE ATT&CKマッピング'],
  },
  {
    value: 'claude-haiku-4-5-20251001',
    name: 'Claude Haiku 4.5',
    badge: '高速・低コスト',
    badgeCls: 'bg-green-900/60 text-green-300 border border-green-700/60',
    borderCls: 'border-green-600',
    desc: '超高速レスポンス。大量アラートの一次スクリーニング・リアルタイム監視に最適。',
    tags: ['大量アラート処理', 'リアルタイムスクリーニング', '低レイテンシ'],
  },
] as const

// ── Toggle component ──────────────────────────────────────────────

function Toggle({
  value,
  onChange,
  disabled,
}: {
  value: boolean
  onChange: (v: boolean) => void
  disabled?: boolean
}) {
  return (
    <button
      type="button"
      onClick={() => !disabled && onChange(!value)}
      className={`relative inline-flex h-6 w-11 items-center rounded-full transition-colors focus:outline-none
                  ${value ? 'bg-blue-600' : 'bg-gray-600'}
                  ${disabled ? 'opacity-50 cursor-not-allowed' : 'cursor-pointer'}`}
    >
      <span
        className={`inline-block h-4 w-4 transform rounded-full bg-[#e2e8f4] shadow transition-transform
                    ${value ? 'translate-x-6' : 'translate-x-1'}`}
      />
    </button>
  )
}

// ── Section wrapper ───────────────────────────────────────────────

function Section({
  title,
  icon: Icon,
  children,
  iconColor = 'text-blue-400',
}: {
  title: string
  icon: React.ComponentType<{ className?: string }>
  children: React.ReactNode
  iconColor?: string
}) {
  return (
    <div className="bg-gray-800 rounded-xl border border-gray-700 overflow-hidden">
      <div className="flex items-center gap-3 px-6 py-4 border-b border-gray-700 bg-gray-800/80">
        <Icon className={`w-5 h-5 flex-shrink-0 ${iconColor}`} />
        <h2 className="text-base font-semibold text-white">{title}</h2>
      </div>
      <div className="px-6 py-5 space-y-5">{children}</div>
    </div>
  )
}

// ── Field row ─────────────────────────────────────────────────────

function FieldRow({
  label,
  description,
  children,
}: {
  label: string
  description?: string
  children: React.ReactNode
}) {
  return (
    <div className="flex items-start justify-between gap-6">
      <div className="flex-1 min-w-0">
        <p className="text-sm font-medium text-gray-200">{label}</p>
        {description && (
          <p className="text-xs text-gray-500 mt-0.5">{description}</p>
        )}
      </div>
      <div className="flex-shrink-0">{children}</div>
    </div>
  )
}

// ── Number input ──────────────────────────────────────────────────

function NumberInput({
  value,
  onChange,
  min,
  max,
  suffix,
}: {
  value: number
  onChange: (v: number) => void
  min?: number
  max?: number
  suffix?: string
}) {
  return (
    <div className="flex items-center gap-2">
      <input
        type="number"
        value={value}
        onChange={e => onChange(Number(e.target.value))}
        min={min}
        max={max}
        className="w-24 px-3 py-1.5 bg-gray-700 border border-gray-600 rounded-lg text-sm text-white
                   focus:outline-none focus:border-blue-500 text-right tabular-nums"
      />
      {suffix && <span className="text-xs text-gray-400">{suffix}</span>}
    </div>
  )
}

// ── Slider input ──────────────────────────────────────────────────

function SliderInput({
  value,
  onChange,
  min,
  max,
  step = 1,
}: {
  value: number
  onChange: (v: number) => void
  min: number
  max: number
  step?: number
}) {
  return (
    <div className="flex items-center gap-3">
      <input
        type="range"
        value={value}
        onChange={e => onChange(Number(e.target.value))}
        min={min}
        max={max}
        step={step}
        className="w-32 h-1.5 rounded-full appearance-none bg-gray-600 accent-blue-500 cursor-pointer"
      />
      <span className="w-8 text-right text-sm font-medium text-white tabular-nums">{value}</span>
    </div>
  )
}

// ── Maintenance confirmation modal ────────────────────────────────

function MaintenanceModal({
  onConfirm,
  onCancel,
}: {
  onConfirm: () => void
  onCancel: () => void
}) {
  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 backdrop-blur-sm">
      <div className="bg-gray-800 rounded-2xl border border-red-500/60 p-8 max-w-md w-full mx-4 shadow-2xl">
        <div className="flex items-center gap-3 mb-4">
          <div className="w-10 h-10 rounded-full bg-red-900/50 flex items-center justify-center">
            <AlertTriangle className="w-5 h-5 text-red-400" />
          </div>
          <h3 className="text-lg font-bold text-white">メンテナンスモードを有効にしますか？</h3>
        </div>
        <p className="text-sm text-gray-300 mb-2">
          メンテナンスモードを有効にすると、管理者以外のすべてのユーザーがシステムにアクセスできなくなります。
        </p>
        <p className="text-xs text-red-400 mb-6">
          この操作は本番環境に影響を与えます。続行する前に確認してください。
        </p>
        <div className="flex gap-3 justify-end">
          <button
            onClick={onCancel}
            className="px-4 py-2 rounded-lg bg-gray-700 border border-gray-600 text-sm text-gray-300
                       hover:bg-gray-600 hover:text-white transition-colors"
          >
            キャンセル
          </button>
          <button
            onClick={onConfirm}
            className="px-4 py-2 rounded-lg bg-red-600 border border-red-500 text-sm text-white font-semibold
                       hover:bg-red-500 transition-colors"
          >
            有効にする
          </button>
        </div>
      </div>
    </div>
  )
}

// ── Main page ─────────────────────────────────────────────────────

export default function SystemSettingsPage() {
  const qc = useQueryClient()
  const [showMaintenanceModal, setShowMaintenanceModal] = useState(false)
  const [saveSuccess, setSaveSuccess] = useState(false)
  const [saveError, setSaveError] = useState<string | null>(null)

  // Local form state
  const [form, setForm] = useState<SystemSettings>({
    session_timeout_minutes: 60,
    max_login_attempts: 5,
    lockout_duration_minutes: 30,
    password_min_length: 12,
    password_require_special: true,
    password_require_numbers: true,
    password_expiry_days: 0,
    maintenance_mode: false,
    maintenance_message: 'システムメンテナンス中です。しばらくお待ちください。',
    allowed_ip_ranges: '',
    ip_whitelist_enabled: false,
    mfa_required: false,
    api_rate_limit_per_minute: 1000,
    api_key_expiry_days: 90,
    // AI Investigation defaults
    ai_investigation_mode: 'standard',
    ai_autonomous_model: 'claude-haiku-4-5-20251001',
    ai_autonomous_max_tokens: 4096,
    ai_auto_investigate_threshold: 7,
    ai_autonomous_auto_response: false,
    ai_autonomous_language: 'ja',
  })

  // Fetch current settings
  const { data, isLoading, refetch } = useQuery<{ settings: Record<string, unknown> }>({
    queryKey: ['system-settings'],
    queryFn: () => apiFetch('/api/v1/admin/system-settings'),
    staleTime: 30_000,
  })

  // Merge server data into form
  useEffect(() => {
    if (!data?.settings) return
    const s = data.settings
    setForm(prev => ({
      ...prev,
      session_timeout_minutes: toNum(s.session_timeout_minutes, prev.session_timeout_minutes!),
      max_login_attempts: toNum(s.max_login_attempts, prev.max_login_attempts!),
      lockout_duration_minutes: toNum(s.lockout_duration_minutes, prev.lockout_duration_minutes!),
      password_min_length: toNum(s.password_min_length, prev.password_min_length!),
      password_require_special: toBool(s.password_require_special, prev.password_require_special!),
      password_require_numbers: toBool(s.password_require_numbers, prev.password_require_numbers!),
      password_expiry_days: toNum(s.password_expiry_days, prev.password_expiry_days!),
      maintenance_mode: toBool(s.maintenance_mode, prev.maintenance_mode!),
      maintenance_message: toStr(s.maintenance_message, prev.maintenance_message!),
      allowed_ip_ranges: arrayToStr(s.allowed_ip_ranges, prev.allowed_ip_ranges!),
      ip_whitelist_enabled: toBool(s.ip_whitelist_enabled, prev.ip_whitelist_enabled!),
      mfa_required: toBool(s.mfa_required, prev.mfa_required!),
      api_rate_limit_per_minute: toNum(s.api_rate_limit_per_minute, prev.api_rate_limit_per_minute!),
      api_key_expiry_days: toNum(s.api_key_expiry_days, prev.api_key_expiry_days!),
      // AI Investigation
      ai_investigation_mode: toStr(s.ai_investigation_mode, prev.ai_investigation_mode!),
      ai_autonomous_model: toStr(s.ai_autonomous_model, prev.ai_autonomous_model!),
      ai_autonomous_max_tokens: toNum(s.ai_autonomous_max_tokens, prev.ai_autonomous_max_tokens!),
      ai_auto_investigate_threshold: toNum(s.ai_auto_investigate_threshold, prev.ai_auto_investigate_threshold!),
      ai_autonomous_auto_response: toBool(s.ai_autonomous_auto_response, prev.ai_autonomous_auto_response!),
      ai_autonomous_language: toStr(s.ai_autonomous_language, prev.ai_autonomous_language!),
    }))
  }, [data])

  // Save mutation
  const saveMutation = useMutation({
    mutationFn: async (settings: Record<string, unknown>) => {
      return apiFetch('/api/v1/admin/system-settings', {
        method: 'PUT',
        body: JSON.stringify({ settings }),
      })
    },
    onSuccess: () => {
      setSaveSuccess(true)
      setSaveError(null)
      qc.invalidateQueries({ queryKey: ['system-settings'] })
      setTimeout(() => setSaveSuccess(false), 3000)
    },
    onError: (err: Error) => {
      setSaveError(err.message || '保存に失敗しました')
    },
  })

  const setField = useCallback(<K extends keyof SystemSettings>(key: K, value: SystemSettings[K]) => {
    setForm(prev => ({ ...prev, [key]: value }))
  }, [])

  const handleSaveAll = () => {
    const ipRangesArray = form.allowed_ip_ranges
      ? form.allowed_ip_ranges.split('\n').map(s => s.trim()).filter(Boolean)
      : []

    const settings: Record<string, unknown> = {
      session_timeout_minutes: form.session_timeout_minutes,
      max_login_attempts: form.max_login_attempts,
      lockout_duration_minutes: form.lockout_duration_minutes,
      password_min_length: form.password_min_length,
      password_require_special: form.password_require_special,
      password_require_numbers: form.password_require_numbers,
      password_expiry_days: form.password_expiry_days,
      maintenance_mode: form.maintenance_mode,
      maintenance_message: form.maintenance_message,
      allowed_ip_ranges: ipRangesArray,
      ip_whitelist_enabled: form.ip_whitelist_enabled,
      mfa_required: form.mfa_required,
      api_rate_limit_per_minute: form.api_rate_limit_per_minute,
      api_key_expiry_days: form.api_key_expiry_days,
      // AI Investigation
      ai_investigation_mode: form.ai_investigation_mode,
      ai_autonomous_model: form.ai_autonomous_model,
      ai_autonomous_max_tokens: form.ai_autonomous_max_tokens,
      ai_auto_investigate_threshold: form.ai_auto_investigate_threshold,
      ai_autonomous_auto_response: form.ai_autonomous_auto_response,
      ai_autonomous_language: form.ai_autonomous_language,
    }
    saveMutation.mutate(settings)
  }

  const handleMaintenanceToggle = (newValue: boolean) => {
    if (newValue) {
      setShowMaintenanceModal(true)
    } else {
      setField('maintenance_mode', false)
    }
  }

  if (isLoading) {
    return (
      <div className="min-h-screen bg-gray-900 p-6">
        <div className="max-w-4xl mx-auto space-y-4 animate-pulse">
          {Array.from({ length: 5 }).map((_, i) => (
            <div key={i} className="h-48 bg-gray-800 rounded-xl border border-gray-700" />
          ))}
        </div>
      </div>
    )
  }

  return (
    <div className="min-h-screen bg-gray-900 p-6">
      {/* Maintenance mode banner */}
      {form.maintenance_mode && (
        <div className="mb-6 px-5 py-4 bg-red-900/40 border border-red-500/60 rounded-xl flex items-center gap-3">
          <AlertTriangle className="w-5 h-5 text-red-400 flex-shrink-0 animate-pulse" />
          <div className="flex-1">
            <p className="text-sm font-bold text-red-300 uppercase tracking-wider">
              MAINTENANCE MODE ACTIVE
            </p>
            <p className="text-xs text-red-400/80 mt-0.5">
              管理者以外のユーザーはシステムにアクセスできません
            </p>
          </div>
          <Ban className="w-5 h-5 text-red-400 flex-shrink-0" />
        </div>
      )}

      {/* Header */}
      <div className="flex items-center justify-between mb-6 max-w-4xl mx-auto">
        <div className="flex items-center gap-3">
          <Settings2 className="w-6 h-6 text-blue-400" />
          <div>
            <h1 className="text-xl font-bold text-white">システム設定</h1>
            <p className="text-xs text-gray-500 mt-0.5">セキュリティポリシー・アクセス制御・システム管理</p>
          </div>
        </div>
        <div className="flex items-center gap-2">
          <button
            onClick={() => refetch()}
            className="flex items-center gap-1.5 px-3 py-1.5 text-sm text-gray-400 bg-gray-800 border border-gray-700 rounded-lg hover:bg-gray-700 hover:text-white transition-colors"
          >
            <RefreshCw className="w-4 h-4" />
            更新
          </button>
          <button
            onClick={handleSaveAll}
            disabled={saveMutation.isPending}
            className={`flex items-center gap-1.5 px-4 py-1.5 text-sm font-semibold rounded-lg border transition-colors
              ${saveMutation.isPending
                ? 'bg-gray-700 border-gray-600 text-gray-400 cursor-wait'
                : 'bg-blue-600 border-blue-500 text-white hover:bg-blue-500'
              }`}
          >
            {saveMutation.isPending ? (
              <RefreshCw className="w-4 h-4 animate-spin" />
            ) : saveSuccess ? (
              <Check className="w-4 h-4" />
            ) : (
              <Save className="w-4 h-4" />
            )}
            {saveSuccess ? '保存しました' : '全て保存'}
          </button>
        </div>
      </div>

      {/* Save error */}
      {saveError && (
        <div className="max-w-4xl mx-auto mb-4 px-4 py-3 bg-red-900/30 border border-red-500/50 rounded-lg flex items-center gap-2 text-sm text-red-300">
          <X className="w-4 h-4 flex-shrink-0" />
          {saveError}
        </div>
      )}

      <div className="max-w-4xl mx-auto space-y-6">

        {/* ── Security Policy ─────────────────────────────────── */}
        <Section title="セキュリティポリシー" icon={Shield} iconColor="text-blue-400">
          <FieldRow
            label="セッションタイムアウト"
            description="非アクティブ後に自動ログアウトするまでの時間"
          >
            <NumberInput
              value={form.session_timeout_minutes!}
              onChange={v => setField('session_timeout_minutes', v)}
              min={1}
              max={1440}
              suffix="分"
            />
          </FieldRow>

          <div className="border-t border-gray-700/60" />

          <FieldRow
            label="最大ログイン失敗回数"
            description="アカウントがロックアウトされるまでの失敗回数"
          >
            <NumberInput
              value={form.max_login_attempts!}
              onChange={v => setField('max_login_attempts', v)}
              min={1}
              max={20}
              suffix="回"
            />
          </FieldRow>

          <div className="border-t border-gray-700/60" />

          <FieldRow
            label="ロックアウト期間"
            description="アカウントロックアウト後の解除までの時間"
          >
            <NumberInput
              value={form.lockout_duration_minutes!}
              onChange={v => setField('lockout_duration_minutes', v)}
              min={1}
              max={1440}
              suffix="分"
            />
          </FieldRow>

          <div className="border-t border-gray-700/60" />

          <FieldRow
            label="全ユーザーにMFA必須"
            description="すべてのユーザーに多要素認証を要求する"
          >
            <Toggle
              value={form.mfa_required!}
              onChange={v => setField('mfa_required', v)}
            />
          </FieldRow>
        </Section>

        {/* ── Password Policy ─────────────────────────────────── */}
        <Section title="パスワードポリシー" icon={Lock} iconColor="text-purple-400">
          <FieldRow
            label="最小パスワード長"
            description="パスワードに必要な最小文字数 (8〜32文字)"
          >
            <SliderInput
              value={form.password_min_length!}
              onChange={v => setField('password_min_length', v)}
              min={8}
              max={32}
            />
          </FieldRow>

          <div className="border-t border-gray-700/60" />

          <FieldRow
            label="特殊文字を必須にする"
            description="パスワードに記号 (!@#$% など) を必須にする"
          >
            <Toggle
              value={form.password_require_special!}
              onChange={v => setField('password_require_special', v)}
            />
          </FieldRow>

          <div className="border-t border-gray-700/60" />

          <FieldRow
            label="数字を必須にする"
            description="パスワードに数字 (0-9) を必須にする"
          >
            <Toggle
              value={form.password_require_numbers!}
              onChange={v => setField('password_require_numbers', v)}
            />
          </FieldRow>

          <div className="border-t border-gray-700/60" />

          <FieldRow
            label="パスワード有効期限"
            description="パスワードの有効日数 (0 = 期限なし)"
          >
            <NumberInput
              value={form.password_expiry_days!}
              onChange={v => setField('password_expiry_days', v)}
              min={0}
              max={365}
              suffix="日"
            />
          </FieldRow>
        </Section>

        {/* ── Access Control ───────────────────────────────────── */}
        <Section title="アクセス制御" icon={Globe} iconColor="text-green-400">
          <FieldRow
            label="IPホワイトリスト有効"
            description="許可されたIPアドレス範囲からのアクセスのみ許可する"
          >
            <Toggle
              value={form.ip_whitelist_enabled!}
              onChange={v => setField('ip_whitelist_enabled', v)}
            />
          </FieldRow>

          <div className="border-t border-gray-700/60" />

          <div className="space-y-2">
            <div className="flex items-center gap-2">
              <Key className="w-4 h-4 text-gray-400" />
              <p className="text-sm font-medium text-gray-200">許可IPアドレス範囲</p>
              {!form.ip_whitelist_enabled && (
                <span className="text-[10px] px-1.5 py-0.5 rounded bg-gray-700 text-gray-500">
                  無効
                </span>
              )}
            </div>
            <p className="text-xs text-gray-500">1行に1つのCIDR表記で入力 (例: 192.168.0.0/24)</p>
            <textarea
              value={form.allowed_ip_ranges ?? ''}
              onChange={e => setField('allowed_ip_ranges', e.target.value)}
              disabled={!form.ip_whitelist_enabled}
              rows={5}
              placeholder={'192.168.0.0/24\n10.0.0.0/8\n172.16.0.0/12'}
              className={`w-full px-3 py-2.5 bg-gray-700/50 border rounded-lg text-sm font-mono text-gray-200
                          focus:outline-none focus:border-blue-500 resize-none placeholder-gray-600
                          ${form.ip_whitelist_enabled ? 'border-gray-600' : 'border-gray-700/50 opacity-50 cursor-not-allowed'}`}
            />
          </div>
        </Section>

        {/* ── API Settings ─────────────────────────────────────── */}
        <Section title="API設定" icon={Activity} iconColor="text-yellow-400">
          <FieldRow
            label="APIレートリミット"
            description="IPアドレスごとの1分あたりの最大リクエスト数"
          >
            <NumberInput
              value={form.api_rate_limit_per_minute!}
              onChange={v => setField('api_rate_limit_per_minute', v)}
              min={10}
              max={100000}
              suffix="req/分"
            />
          </FieldRow>

          <div className="border-t border-gray-700/60" />

          <FieldRow
            label="APIキー有効期限"
            description="APIキーの有効日数 (0 = 無期限)"
          >
            <NumberInput
              value={form.api_key_expiry_days!}
              onChange={v => setField('api_key_expiry_days', v)}
              min={0}
              max={3650}
              suffix="日"
            />
          </FieldRow>
        </Section>

        {/* ── AI Investigation Mode ─────────────────────────────── */}
        <Section title="AI調査エージェント設定" icon={Bot} iconColor="text-purple-400">
          {/* Mode selector */}
          <div className="space-y-4">
            <div>
              <p className="text-sm font-medium text-gray-200 mb-1">調査モード</p>
              <p className="text-xs text-gray-500 mb-3">アラート調査時のAI動作モードを選択します</p>
              <div className="grid grid-cols-2 gap-3">
                {/* Standard mode card */}
                <button
                  type="button"
                  onClick={() => setField('ai_investigation_mode', 'standard')}
                  className={`p-4 rounded-xl border-2 text-left transition-all ${
                    form.ai_investigation_mode === 'standard'
                      ? 'border-blue-500 bg-blue-900/20'
                      : 'border-gray-700 bg-gray-800/40 hover:border-gray-600'
                  }`}
                >
                  <div className="flex items-center gap-2 mb-2">
                    <div className={`w-3 h-3 rounded-full ${
                      form.ai_investigation_mode === 'standard' ? 'bg-blue-500' : 'bg-gray-600'
                    }`} />
                    <span className="text-sm font-semibold text-white">標準モード</span>
                  </div>
                  <p className="text-xs text-gray-400 leading-relaxed">
                    基本的な脅威分析と調査サマリーを生成。高速・低コストで動作します。
                  </p>
                  <div className="flex gap-2 mt-3">
                    <span className="text-[10px] px-1.5 py-0.5 bg-blue-900/40 text-blue-300 rounded">高速</span>
                    <span className="text-[10px] px-1.5 py-0.5 bg-green-900/40 text-green-300 rounded">低コスト</span>
                  </div>
                </button>

                {/* Autonomous mode card */}
                <button
                  type="button"
                  onClick={() => setField('ai_investigation_mode', 'autonomous')}
                  className={`p-4 rounded-xl border-2 text-left transition-all ${
                    form.ai_investigation_mode === 'autonomous'
                      ? 'border-purple-500 bg-purple-900/20'
                      : 'border-gray-700 bg-gray-800/40 hover:border-gray-600'
                  }`}
                >
                  <div className="flex items-center gap-2 mb-2">
                    <div className={`w-3 h-3 rounded-full ${
                      form.ai_investigation_mode === 'autonomous' ? 'bg-purple-500' : 'bg-gray-600'
                    }`} />
                    <span className="text-sm font-semibold text-white">自律調査エージェント</span>
                  </div>
                  <p className="text-xs text-gray-400 leading-relaxed">
                    SOCアナリスト相当の詳細調査を自動実行。攻撃チェーン分析・IOC抽出・MITRE ATT&CKマッピング・対応アクション提案を含む日本語レポートを生成。
                  </p>
                  <div className="flex gap-2 mt-3">
                    <span className="text-[10px] px-1.5 py-0.5 bg-purple-900/40 text-purple-300 rounded">高品質</span>
                    <span className="text-[10px] px-1.5 py-0.5 bg-orange-900/40 text-orange-300 rounded">詳細分析</span>
                  </div>
                </button>
              </div>
            </div>
          </div>

          {/* Autonomous mode specific settings — only shown when autonomous is selected */}
          {form.ai_investigation_mode === 'autonomous' && (
            <>
              <div className="border-t border-gray-700/60" />

              <div className="space-y-3">
                <div>
                  <p className="text-sm font-medium text-gray-200 mb-1">AIプロバイダー / モデル選択</p>
                  <p className="text-xs text-gray-500 mb-3">自律調査で使用するモデルを選択します（※ autonomous 実行は現時点では Anthropic モデルのみサポート）</p>

                  {form.ai_autonomous_model && (
                    <div className="mb-3 flex items-center gap-2 px-3 py-2 bg-gray-900/60 border border-gray-700 rounded-lg">
                      <span className="w-2 h-2 rounded-full bg-green-500 flex-shrink-0" />
                      <span className="text-xs text-gray-400">現在選択中:</span>
                      <span className="text-xs font-medium text-gray-200 font-mono">{form.ai_autonomous_model}</span>
                    </div>
                  )}

                  <div className="flex items-center gap-2 mb-3 px-3 py-2 bg-gray-900/60 border border-gray-700 rounded-lg">
                    <Bot className="w-3.5 h-3.5 text-purple-400 flex-shrink-0" />
                    <span className="text-[11px] text-gray-400">
                      プロバイダー: <span className="text-gray-200 font-medium">Anthropic (Claude)</span>
                      <span className="text-gray-600 ml-2">— OpenAI / Google / Ollama は自律調査では未対応</span>
                    </span>
                  </div>

                  <div className="grid grid-cols-1 gap-2">
                    {ANTHROPIC_MODELS.map(m => {
                      const selected = form.ai_autonomous_model === m.value
                      return (
                        <button
                          key={m.value}
                          type="button"
                          onClick={() => setField('ai_autonomous_model', m.value)}
                          className={`text-left w-full rounded-lg border p-3 transition-all ${
                            selected
                              ? `${m.borderCls} bg-gray-900/70`
                              : 'border-gray-700 bg-gray-800/40 hover:border-gray-600'
                          }`}
                        >
                          <div className="flex items-center justify-between mb-1.5">
                            <div className="flex items-center gap-2">
                              <span className={`w-3 h-3 rounded-full border-2 flex-shrink-0 transition-colors ${
                                selected ? `${m.borderCls} bg-gray-700` : 'border-gray-600'
                              }`} />
                              <span className="text-sm font-semibold text-gray-100">{m.name}</span>
                              {selected && <span className="text-[10px] text-green-400 font-medium">✓ 使用中</span>}
                            </div>
                            <span className={`text-[10px] font-medium px-2 py-0.5 rounded-full ${m.badgeCls}`}>
                              {m.badge}
                            </span>
                          </div>
                          <p className="text-xs text-gray-400 mb-2 ml-5 leading-relaxed">{m.desc}</p>
                          <div className="flex flex-wrap gap-1 ml-5">
                            {m.tags.map(t => (
                              <span key={t} className="text-[10px] text-gray-500 bg-gray-900/60 border border-gray-700 px-1.5 py-0.5 rounded">
                                {t}
                              </span>
                            ))}
                          </div>
                        </button>
                      )
                    })}
                  </div>
                </div>
              </div>

              <div className="border-t border-gray-700/60" />

              <FieldRow
                label="最大トークン数"
                description="AIレスポンスの最大トークン数（大きいほど詳細なレポート）"
              >
                <NumberInput
                  value={form.ai_autonomous_max_tokens!}
                  onChange={v => setField('ai_autonomous_max_tokens', v)}
                  min={1024}
                  max={8192}
                  suffix="tokens"
                />
              </FieldRow>

              <div className="border-t border-gray-700/60" />

              <FieldRow
                label="自動調査の重大度閾値"
                description="この重大度以上のアラートに対してAI自動調査を実行（1〜10）"
              >
                <SliderInput
                  value={form.ai_auto_investigate_threshold!}
                  onChange={v => setField('ai_auto_investigate_threshold', v)}
                  min={1}
                  max={10}
                />
              </FieldRow>

              <div className="border-t border-gray-700/60" />

              <FieldRow
                label="レポート言語"
                description="AI調査レポートの出力言語"
              >
                <select
                  value={form.ai_autonomous_language}
                  onChange={e => setField('ai_autonomous_language', e.target.value)}
                  className="px-3 py-1.5 bg-gray-700 border border-gray-600 rounded-lg text-sm text-white
                             focus:outline-none focus:border-blue-500"
                >
                  <option value="ja">日本語</option>
                  <option value="en">English</option>
                </select>
              </FieldRow>

              <div className="border-t border-gray-700/60" />

              <FieldRow
                label="自動対応アクションの提案"
                description="AIが隔離・プロセス停止・ファイル隔離等の対応アクションを推奨するか"
              >
                <Toggle
                  value={form.ai_autonomous_auto_response!}
                  onChange={v => setField('ai_autonomous_auto_response', v)}
                />
              </FieldRow>

              {form.ai_autonomous_auto_response && (
                <div className="flex items-start gap-3 p-3 rounded-lg bg-yellow-900/20 border border-yellow-700/40">
                  <AlertTriangle className="w-4 h-4 text-yellow-400 flex-shrink-0 mt-0.5" />
                  <p className="text-xs text-yellow-300/80">
                    自動対応アクションの提案を有効にすると、AIがエンドポイントの隔離やプロセス停止を推奨する場合があります。
                    実際の実行には別途承認が必要です。
                  </p>
                </div>
              )}
            </>
          )}
        </Section>

        {/* ── Maintenance Mode ─────────────────────────────────── */}
        <Section title="メンテナンスモード" icon={ShieldAlert} iconColor="text-red-400">
          <div className="space-y-5">
            {/* Big toggle with status */}
            <div className="flex items-center gap-5 p-4 rounded-xl border-2 transition-colors
                            ${form.maintenance_mode
                              ? 'border-red-500/60 bg-red-900/20'
                              : 'border-gray-700 bg-gray-700/20'}">
              <div className={`w-14 h-14 rounded-full flex items-center justify-center flex-shrink-0 ${
                form.maintenance_mode ? 'bg-red-900/50' : 'bg-gray-700/50'
              }`}>
                {form.maintenance_mode
                  ? <ToggleRight className="w-8 h-8 text-red-400" />
                  : <ToggleLeft className="w-8 h-8 text-gray-500" />
                }
              </div>
              <div className="flex-1">
                <p className={`text-base font-bold ${form.maintenance_mode ? 'text-red-300' : 'text-gray-200'}`}>
                  {form.maintenance_mode ? 'メンテナンスモード有効' : 'メンテナンスモード無効'}
                </p>
                <p className="text-xs text-gray-500 mt-0.5">
                  {form.maintenance_mode
                    ? '管理者以外のユーザーはアクセスできません'
                    : '全ユーザーが通常通りアクセスできます'}
                </p>
              </div>
              <Toggle
                value={form.maintenance_mode!}
                onChange={handleMaintenanceToggle}
              />
            </div>

            {/* Maintenance message */}
            <div className="space-y-2">
              <label className="block text-sm font-medium text-gray-300">
                メンテナンスメッセージ
              </label>
              <p className="text-xs text-gray-500">メンテナンス中にユーザーに表示されるメッセージ</p>
              <textarea
                value={form.maintenance_message ?? ''}
                onChange={e => setField('maintenance_message', e.target.value)}
                rows={3}
                className="w-full px-3 py-2.5 bg-gray-700/50 border border-gray-600 rounded-lg text-sm text-gray-200
                           focus:outline-none focus:border-blue-500 resize-none"
              />
            </div>

            {/* Warning notice */}
            <div className="flex items-start gap-3 p-3 rounded-lg bg-yellow-900/20 border border-yellow-700/40">
              <AlertTriangle className="w-4 h-4 text-yellow-400 flex-shrink-0 mt-0.5" />
              <p className="text-xs text-yellow-300/80">
                メンテナンスモードを有効にすると、管理者以外のすべてのユーザーがシステムにアクセスできなくなります。
                本番環境での使用には十分注意してください。
              </p>
            </div>
          </div>
        </Section>

        {/* ── Save button (bottom) ─────────────────────────────── */}
        <div className="flex items-center justify-between py-4">
          <div className="flex items-center gap-2">
            {saveSuccess && (
              <div className="flex items-center gap-2 text-sm text-green-400">
                <Check className="w-4 h-4" />
                設定を保存しました
              </div>
            )}
            {saveError && (
              <div className="flex items-center gap-2 text-sm text-red-400">
                <X className="w-4 h-4" />
                {saveError}
              </div>
            )}
          </div>
          <div className="flex items-center gap-3">
            <button
              onClick={() => refetch()}
              className="px-4 py-2 text-sm text-gray-400 bg-gray-800 border border-gray-700 rounded-lg
                         hover:bg-gray-700 hover:text-white transition-colors"
            >
              変更を破棄
            </button>
            <button
              onClick={handleSaveAll}
              disabled={saveMutation.isPending}
              className={`flex items-center gap-2 px-6 py-2 text-sm font-semibold rounded-lg border transition-colors
                ${saveMutation.isPending
                  ? 'bg-gray-700 border-gray-600 text-gray-400 cursor-wait'
                  : 'bg-blue-600 border-blue-500 text-white hover:bg-blue-500'
                }`}
            >
              {saveMutation.isPending ? (
                <RefreshCw className="w-4 h-4 animate-spin" />
              ) : (
                <Save className="w-4 h-4" />
              )}
              全て保存
            </button>
          </div>
        </div>
      </div>

      {/* Maintenance confirmation modal */}
      {showMaintenanceModal && (
        <MaintenanceModal
          onConfirm={() => {
            setField('maintenance_mode', true)
            setShowMaintenanceModal(false)
          }}
          onCancel={() => setShowMaintenanceModal(false)}
        />
      )}
    </div>
  )
}

// ── Helpers ───────────────────────────────────────────────────────

function toNum(v: unknown, fallback: number): number {
  if (v == null) return fallback
  const n = Number(v)
  return isNaN(n) ? fallback : n
}

function toBool(v: unknown, fallback: boolean): boolean {
  if (v == null) return fallback
  if (typeof v === 'boolean') return v
  if (typeof v === 'string') return v === 'true'
  return fallback
}

function toStr(v: unknown, fallback: string): string {
  if (v == null) return fallback
  return String(v)
}

function arrayToStr(v: unknown, fallback: string): string {
  if (v == null) return fallback
  if (Array.isArray(v)) return v.join('\n')
  if (typeof v === 'string') {
    try {
      const parsed = JSON.parse(v)
      if (Array.isArray(parsed)) return parsed.join('\n')
    } catch {
      return v
    }
  }
  return fallback
}

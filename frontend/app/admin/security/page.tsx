'use client'

import { useState } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { apiFetch } from '@/lib/api'
import {
  Shield, Save, RefreshCw, CheckCircle, AlertTriangle,
  Lock, Key, Clock, History
} from 'lucide-react'

interface PasswordPolicy {
  id: number
  min_length: number
  require_uppercase: boolean
  require_lowercase: boolean
  require_number: boolean
  require_special: boolean
  max_age_days: number
  history_count: number
  updated_at: string
}

function Toggle({
  checked,
  onChange,
  label,
  description,
}: {
  checked: boolean
  onChange: (v: boolean) => void
  label: string
  description?: string
}) {
  return (
    <label className="flex items-center justify-between gap-4 cursor-pointer group">
      <div>
        <span className="text-sm text-white group-hover:text-blue-300 transition-colors">
          {label}
        </span>
        {description && (
          <p className="text-xs text-[#8899aa] mt-0.5">{description}</p>
        )}
      </div>
      <button
        type="button"
        role="switch"
        aria-checked={checked}
        onClick={() => onChange(!checked)}
        className={`relative inline-flex h-6 w-11 shrink-0 rounded-full border-2 border-transparent
          transition-colors duration-200 ease-in-out focus:outline-hidden focus:ring-2 focus:ring-blue-500
          ${checked ? 'bg-blue-600' : 'bg-falcon-border'}`}
      >
        <span
          className={`pointer-events-none inline-block h-5 w-5 transform rounded-full bg-falcon-text shadow
            ring-0 transition duration-200 ease-in-out
            ${checked ? 'translate-x-5' : 'translate-x-0'}`}
        />
      </button>
    </label>
  )
}

export default function SecuritySettingsPage() {
  const qc = useQueryClient()
  const [saveSuccess, setSaveSuccess] = useState(false)
  const [saveError, setSaveError]     = useState<string | null>(null)

  const { data: policy, isLoading, refetch, isFetching } = useQuery<PasswordPolicy>({
    queryKey: ['password-policy'],
    queryFn: () => apiFetch('/api/v1/admin/password-policy'),
  })

  // Local form state — initialised from server data via `useEffect`-like key trick
  const [form, setForm] = useState<Omit<PasswordPolicy, 'id' | 'updated_at'>>({
    min_length:        8,
    require_uppercase: false,
    require_lowercase: false,
    require_number:    true,
    require_special:   false,
    max_age_days:      0,
    history_count:     0,
  })

  // Sync form once data arrives (only on first load)
  const [synced, setSynced] = useState(false)
  if (policy && !synced) {
    setForm({
      min_length:        policy.min_length,
      require_uppercase: policy.require_uppercase,
      require_lowercase: policy.require_lowercase,
      require_number:    policy.require_number,
      require_special:   policy.require_special,
      max_age_days:      policy.max_age_days,
      history_count:     policy.history_count,
    })
    setSynced(true)
  }

  const updateMutation = useMutation({
    mutationFn: (payload: typeof form) =>
      apiFetch('/api/v1/admin/password-policy', {
        method: 'PUT',
        body: JSON.stringify(payload),
      }),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['password-policy'] })
      setSaveSuccess(true)
      setSaveError(null)
      setTimeout(() => setSaveSuccess(false), 3000)
    },
    onError: (err: Error) => {
      setSaveError(err.message ?? '保存に失敗しました')
    },
  })

  function handleSubmit(e: React.FormEvent) {
    e.preventDefault()
    setSaveError(null)
    updateMutation.mutate(form)
  }

  return (
    <div className="p-6 space-y-6 max-w-3xl">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-white flex items-center gap-2">
            <Shield className="w-6 h-6 text-blue-400" />
            セキュリティ設定
          </h1>
          <p className="text-[#8899aa] text-sm mt-1">
            パスワードポリシーと認証要件を管理します（管理者専用）
          </p>
        </div>
        <button
          onClick={() => { setSynced(false); refetch() }}
          disabled={isFetching}
          className="p-2 text-[#8899aa] hover:text-white transition-colors disabled:opacity-50"
          title="再読み込み"
        >
          <RefreshCw className={`w-5 h-5 ${isFetching ? 'animate-spin' : ''}`} />
        </button>
      </div>

      {/* Feedback banners */}
      {saveSuccess && (
        <div className="flex items-center gap-2 px-4 py-3 bg-green-900/30 border border-green-700/50 rounded-lg text-green-300 text-sm">
          <CheckCircle className="w-4 h-4 shrink-0" />
          パスワードポリシーを保存しました
        </div>
      )}
      {saveError && (
        <div className="flex items-center gap-2 px-4 py-3 bg-red-900/30 border border-red-700/50 rounded-lg text-red-300 text-sm">
          <AlertTriangle className="w-4 h-4 shrink-0" />
          {saveError}
        </div>
      )}

      <form onSubmit={handleSubmit} className="space-y-6">
        {/* ── Password Complexity ───────────────────────── */}
        <section className="bg-falcon-card rounded-xl border border-falcon-border p-6 space-y-5">
          <div className="flex items-center gap-2 pb-3 border-b border-falcon-border">
            <Lock className="w-4 h-4 text-blue-400" />
            <h2 className="text-white font-semibold">パスワード複雑性</h2>
          </div>

          {/* Min length slider */}
          <div className="space-y-2">
            <div className="flex items-center justify-between">
              <label className="text-sm text-white">
                最小文字数
              </label>
              <span className="text-blue-400 font-mono font-semibold text-lg">
                {form.min_length}
              </span>
            </div>
            <input
              type="range"
              min={6}
              max={32}
              step={1}
              value={form.min_length}
              onChange={e => setForm(f => ({ ...f, min_length: Number(e.target.value) }))}
              disabled={isLoading}
              className="w-full h-2 rounded-full appearance-none cursor-pointer
                         bg-falcon-border accent-blue-500 disabled:opacity-50"
            />
            <div className="flex justify-between text-xs text-[#8899aa]">
              <span>6</span>
              <span>32</span>
            </div>
          </div>

          {/* Complexity toggles */}
          <div className="space-y-4 pt-1">
            <Toggle
              checked={form.require_uppercase}
              onChange={v => setForm(f => ({ ...f, require_uppercase: v }))}
              label="大文字を必須にする"
              description="A-Z を1文字以上含める"
            />
            <Toggle
              checked={form.require_lowercase}
              onChange={v => setForm(f => ({ ...f, require_lowercase: v }))}
              label="小文字を必須にする"
              description="a-z を1文字以上含める"
            />
            <Toggle
              checked={form.require_number}
              onChange={v => setForm(f => ({ ...f, require_number: v }))}
              label="数字を必須にする"
              description="0-9 を1文字以上含める"
            />
            <Toggle
              checked={form.require_special}
              onChange={v => setForm(f => ({ ...f, require_special: v }))}
              label="記号を必須にする"
              description="! @ # $ % など記号を1文字以上含める"
            />
          </div>
        </section>

        {/* ── Expiry & History ──────────────────────────── */}
        <section className="bg-falcon-card rounded-xl border border-falcon-border p-6 space-y-5">
          <div className="flex items-center gap-2 pb-3 border-b border-falcon-border">
            <Key className="w-4 h-4 text-blue-400" />
            <h2 className="text-white font-semibold">有効期限と履歴</h2>
          </div>

          {/* Max age */}
          <div className="space-y-1">
            <label className="text-sm text-white flex items-center gap-1.5">
              <Clock className="w-4 h-4 text-[#8899aa]" />
              パスワード有効期間（日数）
            </label>
            <p className="text-xs text-[#8899aa]">
              0 を設定すると有効期限なしになります
            </p>
            <input
              type="number"
              min={0}
              max={365}
              value={form.max_age_days}
              onChange={e => setForm(f => ({ ...f, max_age_days: Math.max(0, Number(e.target.value)) }))}
              disabled={isLoading}
              className="w-32 px-3 py-2 bg-[#0d1623] border border-falcon-border rounded-lg text-white
                         text-sm focus:outline-hidden focus:ring-2 focus:ring-blue-500 disabled:opacity-50"
            />
            {form.max_age_days > 0 && (
              <p className="text-xs text-blue-400 mt-1">
                {form.max_age_days} 日ごとにパスワードの変更が必要になります
              </p>
            )}
          </div>

          {/* History count */}
          <div className="space-y-1">
            <label className="text-sm text-white flex items-center gap-1.5">
              <History className="w-4 h-4 text-[#8899aa]" />
              パスワード履歴件数
            </label>
            <p className="text-xs text-[#8899aa]">
              直近 N 件のパスワードの再利用を禁止します（0 = 制限なし）
            </p>
            <input
              type="number"
              min={0}
              max={24}
              value={form.history_count}
              onChange={e => setForm(f => ({ ...f, history_count: Math.max(0, Number(e.target.value)) }))}
              disabled={isLoading}
              className="w-32 px-3 py-2 bg-[#0d1623] border border-falcon-border rounded-lg text-white
                         text-sm focus:outline-hidden focus:ring-2 focus:ring-blue-500 disabled:opacity-50"
            />
          </div>
        </section>

        {/* ── MFA Enforcement (future) ─────────────────── */}
        <section className="bg-falcon-card rounded-xl border border-falcon-border p-6 space-y-4 opacity-60">
          <div className="flex items-center gap-2 pb-3 border-b border-falcon-border">
            <Shield className="w-4 h-4 text-[#8899aa]" />
            <h2 className="text-white font-semibold">多要素認証（MFA）強制</h2>
            <span className="ml-auto text-xs text-[#8899aa] border border-falcon-border rounded-sm px-2 py-0.5">
              近日公開
            </span>
          </div>
          <Toggle
            checked={false}
            onChange={() => {}}
            label="全ユーザーに MFA を強制する"
            description="有効にすると、ログイン時に MFA コードの入力が必須になります"
          />
        </section>

        {/* Save button */}
        <div className="flex items-center justify-between pt-2">
          {policy?.updated_at && (
            <p className="text-xs text-[#8899aa]">
              最終更新: {new Date(policy.updated_at).toLocaleString('ja-JP')}
            </p>
          )}
          <button
            type="submit"
            disabled={updateMutation.isPending || isLoading}
            className="flex items-center gap-2 px-5 py-2.5 bg-falcon-blue text-white rounded-lg
                       hover:bg-[#1557d4] transition-colors text-sm font-medium
                       disabled:opacity-50 disabled:cursor-not-allowed ml-auto"
          >
            {updateMutation.isPending ? (
              <RefreshCw className="w-4 h-4 animate-spin" />
            ) : (
              <Save className="w-4 h-4" />
            )}
            {updateMutation.isPending ? '保存中...' : '設定を保存'}
          </button>
        </div>
      </form>
    </div>
  )
}

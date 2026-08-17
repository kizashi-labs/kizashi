'use client'

import { useState } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { apiFetch } from '@/lib/api'
import {
  Shield, Settings, Plus, Trash2, Edit2, CheckCircle,
  Users, Globe, X, RefreshCw, AlertTriangle, Check, Ban,
} from 'lucide-react'

// ─── 型定義 ──────────────────────────────────────────────────────────────────

interface PolicyConfig {
  collection_interval?: number
  send_interval?: number
  enabled_collectors?: string[]
  fim_enabled?: boolean
  fim_paths?: string[]
  process_monitoring?: boolean
  resource_monitoring?: boolean
}

interface AgentPolicy {
  id: string
  name: string
  description: string
  config: PolicyConfig
  group_id?: string
  is_default: boolean
  created_at: string
}

interface AgentGroup {
  id: string
  name: string
  description: string
}

interface PolicyForm {
  name: string
  description: string
  group_id: string
  is_default: boolean
  config: PolicyConfig
}

interface ProcessBlockRule {
  id: string
  name: string
  process_name: string
  rule_type: 'allow' | 'deny'
  scope: 'all' | 'group' | 'agent'
  scope_id?: string
  action: 'alert' | 'block' | 'alert_and_block'
  enabled: boolean
  severity: 'low' | 'medium' | 'high' | 'critical'
  created_at: string
}

interface ProcessBlockRuleForm {
  name: string
  process_name: string
  rule_type: 'allow' | 'deny'
  scope: 'all' | 'group' | 'agent'
  scope_id: string
  action: 'alert' | 'block' | 'alert_and_block'
  severity: 'low' | 'medium' | 'high' | 'critical'
  enabled: boolean
}

// ─── 定数 ────────────────────────────────────────────────────────────────────

const COLLECTOR_OPTIONS = ['system', 'network', 'fim', 'device', 'resource'] as const
type CollectorOption = typeof COLLECTOR_OPTIONS[number]

const EMPTY_FORM: PolicyForm = {
  name: '',
  description: '',
  group_id: '',
  is_default: false,
  config: {
    collection_interval: 60,
    send_interval: 300,
    enabled_collectors: ['system', 'network'],
    fim_enabled: false,
    fim_paths: [],
    process_monitoring: true,
    resource_monitoring: true,
  },
}

const EMPTY_PROCESS_RULE_FORM: ProcessBlockRuleForm = {
  name: '',
  process_name: '',
  rule_type: 'deny',
  scope: 'all',
  scope_id: '',
  action: 'block',
  severity: 'medium',
  enabled: true,
}

// ─── ユーティリティ ───────────────────────────────────────────────────────────

function configSummary(config: PolicyConfig): string {
  const parts: string[] = []
  if (config.collection_interval != null) parts.push(`収集: ${config.collection_interval}s`)
  if (config.fim_enabled) parts.push('FIM ON')
  if (config.process_monitoring) parts.push('プロセス監視')
  if (config.resource_monitoring) parts.push('リソース監視')
  if ((config.enabled_collectors ?? []).length > 0) {
    parts.push(`コレクタ: ${(config.enabled_collectors ?? []).join(', ')}`)
  }
  return parts.length > 0 ? parts.join(' · ') : '—'
}

const SEVERITY_STYLE: Record<ProcessBlockRule['severity'], string> = {
  low:      'bg-blue-900/30 text-blue-300 border-blue-700/50',
  medium:   'bg-yellow-900/30 text-yellow-300 border-yellow-700/50',
  high:     'bg-orange-900/30 text-orange-300 border-orange-700/50',
  critical: 'bg-red-900/30 text-red-300 border-red-700/50',
}

const SEVERITY_LABEL: Record<ProcessBlockRule['severity'], string> = {
  low: '低', medium: '中', high: '高', critical: '重大',
}

const ACTION_LABEL: Record<ProcessBlockRule['action'], string> = {
  alert: 'アラート', block: 'ブロック', alert_and_block: 'アラート+ブロック',
}

const ACTION_STYLE: Record<ProcessBlockRule['action'], string> = {
  alert:           'bg-yellow-900/30 text-yellow-300 border-yellow-700/50',
  block:           'bg-red-900/30 text-red-300 border-red-700/50',
  alert_and_block: 'bg-orange-900/30 text-orange-300 border-orange-700/50',
}

// ─── トグルスイッチ ───────────────────────────────────────────────────────────

function Toggle({
  checked,
  onChange,
  label,
}: {
  checked: boolean
  onChange: (v: boolean) => void
  label: string
}) {
  return (
    <label className="flex items-center gap-3 cursor-pointer select-none">
      <div
        onClick={() => onChange(!checked)}
        className={`relative w-10 h-5 rounded-full transition-colors cursor-pointer ${
          checked ? 'bg-blue-600' : 'bg-falcon-border'
        }`}
      >
        <div
          className={`absolute top-0.5 left-0.5 w-4 h-4 rounded-full bg-falcon-text shadow transition-transform ${
            checked ? 'translate-x-5' : 'translate-x-0'
          }`}
        />
      </div>
      <span className="text-sm text-[#c8d4e4]">{label}</span>
    </label>
  )
}

// ─── ポリシーフォームモーダル ──────────────────────────────────────────────────

function PolicyFormModal({
  title,
  initial,
  groups,
  onClose,
  onSubmit,
  isPending,
}: {
  title: string
  initial: PolicyForm
  groups: AgentGroup[]
  onClose: () => void
  onSubmit: (f: PolicyForm) => void
  isPending: boolean
}) {
  const [form, setForm] = useState<PolicyForm>(initial)

  const setField = <K extends keyof PolicyForm>(k: K, v: PolicyForm[K]) =>
    setForm(f => ({ ...f, [k]: v }))

  const setConfig = <K extends keyof PolicyConfig>(k: K, v: PolicyConfig[K]) =>
    setForm(f => ({ ...f, config: { ...f.config, [k]: v } }))

  const toggleCollector = (c: CollectorOption) => {
    const current = form.config.enabled_collectors ?? []
    const next = current.includes(c)
      ? current.filter(x => x !== c)
      : [...current, c]
    setConfig('enabled_collectors', next)
  }

  const handleFimPaths = (raw: string) => {
    const paths = raw.split('\n').map(s => s.trim()).filter(Boolean)
    setConfig('fim_paths', paths)
  }

  const enabledCollectors = form.config.enabled_collectors ?? []

  return (
    <div className="fixed inset-0 bg-black/70 backdrop-blur-xs flex items-start justify-center z-50 overflow-y-auto py-8 px-4">
      <div className="bg-gray-800 rounded-2xl w-full max-w-2xl border border-gray-700 shadow-2xl">

        {/* ヘッダー */}
        <div className="flex items-center justify-between px-6 py-4 border-b border-gray-700">
          <h2 className="text-lg font-bold text-white flex items-center gap-2">
            <Shield className="w-5 h-5 text-blue-400" />
            {title}
          </h2>
          <button
            onClick={onClose}
            className="text-gray-400 hover:text-white transition-colors"
          >
            <X className="w-5 h-5" />
          </button>
        </div>

        <form
          onSubmit={e => { e.preventDefault(); onSubmit(form) }}
          className="p-6 space-y-6"
        >
          {/* 基本情報 */}
          <section className="space-y-4">
            <h3 className="text-xs font-semibold text-gray-400 uppercase tracking-wider">
              基本情報
            </h3>
            <div>
              <label className="text-sm text-gray-400 block mb-1">
                ポリシー名 <span className="text-red-400">*</span>
              </label>
              <input
                value={form.name}
                onChange={e => setField('name', e.target.value)}
                required
                placeholder="例: Production Servers Policy"
                className="w-full bg-gray-900 text-white px-3 py-2 rounded-lg border border-gray-600
                           text-sm focus:outline-hidden focus:border-blue-500 transition-colors"
              />
            </div>
            <div>
              <label className="text-sm text-gray-400 block mb-1">説明</label>
              <textarea
                value={form.description}
                onChange={e => setField('description', e.target.value)}
                rows={2}
                placeholder="このポリシーの用途や適用範囲..."
                className="w-full bg-gray-900 text-white px-3 py-2 rounded-lg border border-gray-600
                           text-sm focus:outline-hidden focus:border-blue-500 transition-colors resize-none"
              />
            </div>
            <div>
              <label className="text-sm text-gray-400 block mb-1">グループ</label>
              <select
                value={form.group_id}
                onChange={e => setField('group_id', e.target.value)}
                className="w-full bg-gray-900 text-white px-3 py-2 rounded-lg border border-gray-600
                           text-sm focus:outline-hidden focus:border-blue-500 transition-colors"
              >
                <option value="">全エージェント</option>
                {groups.map(g => (
                  <option key={g.id} value={g.id}>{g.name}</option>
                ))}
              </select>
            </div>
            <label className="flex items-center gap-3 cursor-pointer">
              <input
                type="checkbox"
                checked={form.is_default}
                onChange={e => setField('is_default', e.target.checked)}
                className="w-4 h-4 accent-blue-500 rounded-sm"
              />
              <span className="text-sm text-gray-300">デフォルトポリシーとして設定</span>
            </label>
          </section>

          {/* 収集設定 */}
          <section className="space-y-4">
            <h3 className="text-xs font-semibold text-gray-400 uppercase tracking-wider flex items-center gap-1.5">
              <Settings className="w-3.5 h-3.5" /> 収集設定
            </h3>
            <div className="grid grid-cols-2 gap-4">
              <div>
                <label className="text-sm text-gray-400 block mb-1">
                  収集間隔 (秒)
                </label>
                <input
                  type="number"
                  min={10}
                  value={form.config.collection_interval ?? ''}
                  onChange={e =>
                    setConfig('collection_interval', e.target.value ? Number(e.target.value) : undefined)
                  }
                  placeholder="60"
                  className="w-full bg-gray-900 text-white px-3 py-2 rounded-lg border border-gray-600
                             text-sm focus:outline-hidden focus:border-blue-500 transition-colors"
                />
              </div>
              <div>
                <label className="text-sm text-gray-400 block mb-1">
                  送信間隔 (秒)
                </label>
                <input
                  type="number"
                  min={10}
                  value={form.config.send_interval ?? ''}
                  onChange={e =>
                    setConfig('send_interval', e.target.value ? Number(e.target.value) : undefined)
                  }
                  placeholder="300"
                  className="w-full bg-gray-900 text-white px-3 py-2 rounded-lg border border-gray-600
                             text-sm focus:outline-hidden focus:border-blue-500 transition-colors"
                />
              </div>
            </div>
          </section>

          {/* 有効コレクタ */}
          <section className="space-y-3">
            <h3 className="text-xs font-semibold text-gray-400 uppercase tracking-wider">
              有効コレクタ
            </h3>
            <div className="flex flex-wrap gap-2">
              {COLLECTOR_OPTIONS.map(c => (
                <button
                  key={c}
                  type="button"
                  onClick={() => toggleCollector(c)}
                  className={`px-3 py-1.5 rounded-lg border text-sm transition-colors font-mono ${
                    enabledCollectors.includes(c)
                      ? 'bg-blue-600/20 text-blue-300 border-blue-500/60'
                      : 'bg-gray-900 text-gray-400 border-gray-600 hover:border-gray-500'
                  }`}
                >
                  {c}
                </button>
              ))}
            </div>
          </section>

          {/* 監視オプション */}
          <section className="space-y-4">
            <h3 className="text-xs font-semibold text-gray-400 uppercase tracking-wider">
              監視オプション
            </h3>
            <div className="space-y-3">
              <Toggle
                checked={!!form.config.process_monitoring}
                onChange={v => setConfig('process_monitoring', v)}
                label="プロセス監視"
              />
              <Toggle
                checked={!!form.config.resource_monitoring}
                onChange={v => setConfig('resource_monitoring', v)}
                label="リソース監視"
              />
              <Toggle
                checked={!!form.config.fim_enabled}
                onChange={v => setConfig('fim_enabled', v)}
                label="FIM (ファイル変更監視) を有効化"
              />
            </div>

            {form.config.fim_enabled && (
              <div>
                <label className="text-sm text-gray-400 block mb-1">
                  FIM 監視パス (1行ずつ入力)
                </label>
                <textarea
                  rows={4}
                  value={(form.config.fim_paths ?? []).join('\n')}
                  onChange={e => handleFimPaths(e.target.value)}
                  placeholder={'/etc\n/var/log\nC:\\Windows\\System32'}
                  className="w-full bg-gray-900 text-white px-3 py-2 rounded-lg border border-gray-600
                             text-sm font-mono focus:outline-hidden focus:border-blue-500 transition-colors resize-none"
                />
              </div>
            )}
          </section>

          {/* フッター */}
          <div className="flex items-center justify-end gap-3 pt-2 border-t border-gray-700">
            <button
              type="button"
              onClick={onClose}
              className="px-4 py-2 text-sm text-gray-400 hover:text-white transition-colors"
            >
              キャンセル
            </button>
            <button
              type="submit"
              disabled={isPending}
              className="flex items-center gap-2 px-5 py-2 bg-blue-600 text-white rounded-lg
                         text-sm hover:bg-blue-500 transition-colors disabled:opacity-50 disabled:cursor-not-allowed"
            >
              {isPending ? (
                <div className="w-4 h-4 border-2 border-white border-t-transparent rounded-full animate-spin" />
              ) : (
                <Check className="w-4 h-4" />
              )}
              保存
            </button>
          </div>
        </form>
      </div>
    </div>
  )
}

// ─── ポリシーカード ────────────────────────────────────────────────────────────

function PolicyCard({
  policy,
  groupName,
  onEdit,
  onDelete,
}: {
  policy: AgentPolicy
  groupName: string | null
  onEdit: (p: AgentPolicy) => void
  onDelete: (id: string) => void
}) {
  const [confirmDelete, setConfirmDelete] = useState(false)

  return (
    <div className="bg-gray-800 rounded-xl border border-gray-700 p-5 space-y-4 hover:border-gray-600 transition-colors">

      {/* カードヘッダー */}
      <div className="flex items-start justify-between gap-3">
        <div className="flex-1 min-w-0">
          <div className="flex items-center gap-2 flex-wrap">
            <h3 className="text-white font-semibold truncate">{policy.name}</h3>
            {policy.is_default && (
              <span className="flex items-center gap-1 text-xs px-2 py-0.5 rounded-full
                               bg-green-900/40 text-green-300 border border-green-700/50 shrink-0">
                <CheckCircle className="w-3 h-3" />
                デフォルト
              </span>
            )}
          </div>
          {policy.description && (
            <p className="text-gray-400 text-sm mt-0.5 line-clamp-2">{policy.description}</p>
          )}
        </div>

        <div className="flex items-center gap-1 shrink-0">
          <button
            onClick={() => onEdit(policy)}
            className="p-1.5 text-gray-500 hover:text-blue-400 transition-colors rounded-lg hover:bg-blue-900/20"
            title="編集"
          >
            <Edit2 className="w-4 h-4" />
          </button>
          {confirmDelete ? (
            <div className="flex items-center gap-1">
              <button
                onClick={() => { onDelete(policy.id); setConfirmDelete(false) }}
                className="text-xs text-red-300 bg-red-900/40 px-2 py-1 rounded-sm hover:bg-red-900/60 transition-colors"
              >
                確認
              </button>
              <button
                onClick={() => setConfirmDelete(false)}
                className="text-xs text-gray-400 hover:text-white transition-colors"
              >
                <X className="w-3.5 h-3.5" />
              </button>
            </div>
          ) : (
            <button
              onClick={() => setConfirmDelete(true)}
              className="p-1.5 text-gray-500 hover:text-red-400 transition-colors rounded-lg hover:bg-red-900/20"
              title="削除"
            >
              <Trash2 className="w-4 h-4" />
            </button>
          )}
        </div>
      </div>

      {/* グループバッジ */}
      <div className="flex items-center gap-1.5">
        {groupName ? (
          <span className="flex items-center gap-1 text-xs px-2.5 py-1 rounded-full
                           bg-purple-900/30 text-purple-300 border border-purple-700/50">
            <Users className="w-3 h-3" />
            {groupName}
          </span>
        ) : (
          <span className="flex items-center gap-1 text-xs px-2.5 py-1 rounded-full
                           bg-gray-700/60 text-gray-400 border border-gray-600/50">
            <Globe className="w-3 h-3" />
            全エージェント
          </span>
        )}
      </div>

      {/* 設定サマリー */}
      <div className="bg-gray-900 rounded-lg px-3 py-2">
        <p className="text-xs text-gray-500 mb-0.5">設定サマリー</p>
        <p className="text-xs text-gray-300 font-mono leading-relaxed">
          {configSummary(policy.config)}
        </p>
      </div>

      {/* コレクタバッジ */}
      {(policy.config.enabled_collectors ?? []).length > 0 && (
        <div className="flex flex-wrap gap-1.5">
          {(policy.config.enabled_collectors ?? []).map(c => (
            <span
              key={c}
              className="text-xs font-mono px-2 py-0.5 rounded-sm bg-blue-900/20 text-blue-300 border border-blue-700/40"
            >
              {c}
            </span>
          ))}
        </div>
      )}

      {/* 作成日時 */}
      <p className="text-gray-600 text-xs">
        作成: {new Date(policy.created_at).toLocaleString('ja-JP')}
      </p>
    </div>
  )
}

// ─── プロセスブロックルール フォームモーダル ─────────────────────────────────

function ProcessRuleFormModal({
  title,
  initial,
  onClose,
  onSubmit,
  isPending,
}: {
  title: string
  initial: ProcessBlockRuleForm
  onClose: () => void
  onSubmit: (f: ProcessBlockRuleForm) => void
  isPending: boolean
}) {
  const [form, setForm] = useState<ProcessBlockRuleForm>(initial)

  const setField = <K extends keyof ProcessBlockRuleForm>(k: K, v: ProcessBlockRuleForm[K]) =>
    setForm(f => ({ ...f, [k]: v }))

  return (
    <div className="fixed inset-0 bg-black/70 backdrop-blur-xs flex items-start justify-center z-50 overflow-y-auto py-8 px-4">
      <div className="bg-falcon-surface rounded-2xl w-full max-w-lg border border-falcon-border shadow-2xl">

        {/* ヘッダー */}
        <div className="flex items-center justify-between px-6 py-4 border-b border-falcon-border">
          <h2 className="text-lg font-bold text-white flex items-center gap-2">
            <Ban className="w-5 h-5 text-red-400" />
            {title}
          </h2>
          <button onClick={onClose} className="text-gray-400 hover:text-white transition-colors">
            <X className="w-5 h-5" />
          </button>
        </div>

        <form
          onSubmit={e => { e.preventDefault(); onSubmit(form) }}
          className="p-6 space-y-5"
        >
          {/* ルール名 */}
          <div>
            <label className="text-sm text-[#8899aa] block mb-1">
              ルール名 <span className="text-red-400">*</span>
            </label>
            <input
              value={form.name}
              onChange={e => setField('name', e.target.value)}
              required
              placeholder="例: Block Mimikatz"
              className="w-full bg-[#070d19] text-white px-3 py-2 rounded-lg border border-falcon-border
                         text-sm focus:outline-hidden focus:border-blue-500 transition-colors"
            />
          </div>

          {/* プロセス名 */}
          <div>
            <label className="text-sm text-[#8899aa] block mb-1">
              プロセス名 <span className="text-red-400">*</span>
            </label>
            <input
              value={form.process_name}
              onChange={e => setField('process_name', e.target.value)}
              required
              placeholder="例: mimikatz.exe"
              className="w-full bg-[#070d19] text-white px-3 py-2 rounded-lg border border-falcon-border
                         text-sm font-mono focus:outline-hidden focus:border-blue-500 transition-colors"
            />
          </div>

          {/* ルールタイプ */}
          <div>
            <label className="text-sm text-[#8899aa] block mb-2">タイプ</label>
            <div className="flex gap-3">
              {(['allow', 'deny'] as const).map(v => (
                <label key={v} className="flex items-center gap-2 cursor-pointer">
                  <input
                    type="radio"
                    name="rule_type"
                    value={v}
                    checked={form.rule_type === v}
                    onChange={() => setField('rule_type', v)}
                    className="accent-blue-500"
                  />
                  <span className={`text-sm font-medium ${v === 'deny' ? 'text-red-300' : 'text-green-300'}`}>
                    {v === 'allow' ? 'Allow (許可)' : 'Deny (拒否)'}
                  </span>
                </label>
              ))}
            </div>
          </div>

          {/* スコープ */}
          <div>
            <label className="text-sm text-[#8899aa] block mb-1">スコープ</label>
            <select
              value={form.scope}
              onChange={e => setField('scope', e.target.value as ProcessBlockRuleForm['scope'])}
              className="w-full bg-[#070d19] text-white px-3 py-2 rounded-lg border border-falcon-border
                         text-sm focus:outline-hidden focus:border-blue-500 transition-colors"
            >
              <option value="all">全エージェント (all)</option>
              <option value="group">グループ (group)</option>
              <option value="agent">エージェント (agent)</option>
            </select>
          </div>

          {/* スコープID (scope != all のとき表示) */}
          {form.scope !== 'all' && (
            <div>
              <label className="text-sm text-[#8899aa] block mb-1">
                {form.scope === 'group' ? 'グループID' : 'エージェントID'}
              </label>
              <input
                value={form.scope_id}
                onChange={e => setField('scope_id', e.target.value)}
                placeholder={form.scope === 'group' ? 'グループIDを入力' : 'エージェントIDを入力'}
                className="w-full bg-[#070d19] text-white px-3 py-2 rounded-lg border border-falcon-border
                           text-sm font-mono focus:outline-hidden focus:border-blue-500 transition-colors"
              />
            </div>
          )}

          {/* アクション */}
          <div>
            <label className="text-sm text-[#8899aa] block mb-1">アクション</label>
            <select
              value={form.action}
              onChange={e => setField('action', e.target.value as ProcessBlockRuleForm['action'])}
              className="w-full bg-[#070d19] text-white px-3 py-2 rounded-lg border border-falcon-border
                         text-sm focus:outline-hidden focus:border-blue-500 transition-colors"
            >
              <option value="alert">アラートのみ (alert)</option>
              <option value="block">ブロック (block)</option>
              <option value="alert_and_block">アラート + ブロック (alert_and_block)</option>
            </select>
          </div>

          {/* 重大度 */}
          <div>
            <label className="text-sm text-[#8899aa] block mb-1">重大度</label>
            <select
              value={form.severity}
              onChange={e => setField('severity', e.target.value as ProcessBlockRuleForm['severity'])}
              className="w-full bg-[#070d19] text-white px-3 py-2 rounded-lg border border-falcon-border
                         text-sm focus:outline-hidden focus:border-blue-500 transition-colors"
            >
              <option value="low">低 (low)</option>
              <option value="medium">中 (medium)</option>
              <option value="high">高 (high)</option>
              <option value="critical">重大 (critical)</option>
            </select>
          </div>

          {/* 有効/無効 */}
          <Toggle
            checked={form.enabled}
            onChange={v => setField('enabled', v)}
            label="ルールを有効にする"
          />

          {/* フッター */}
          <div className="flex items-center justify-end gap-3 pt-2 border-t border-falcon-border">
            <button
              type="button"
              onClick={onClose}
              className="px-4 py-2 text-sm text-[#8899aa] hover:text-white transition-colors"
            >
              キャンセル
            </button>
            <button
              type="submit"
              disabled={isPending}
              className="flex items-center gap-2 px-5 py-2 bg-blue-600 text-white rounded-lg
                         text-sm hover:bg-blue-500 transition-colors disabled:opacity-50 disabled:cursor-not-allowed"
            >
              {isPending ? (
                <div className="w-4 h-4 border-2 border-white border-t-transparent rounded-full animate-spin" />
              ) : (
                <Check className="w-4 h-4" />
              )}
              保存
            </button>
          </div>
        </form>
      </div>
    </div>
  )
}

// ─── プロセスブロックルール タブ ─────────────────────────────────────────────

function ProcessBlockRulesTab() {
  const qc = useQueryClient()
  const [showCreate, setShowCreate] = useState(false)
  const [editingRule, setEditingRule] = useState<ProcessBlockRule | null>(null)
  const [error, setError] = useState<string | null>(null)
  const [confirmDeleteId, setConfirmDeleteId] = useState<string | null>(null)

  // ─── 一覧取得 ───────────────────────────────────────────────────────────
  const {
    data: rulesRaw,
    isLoading,
    isFetching,
    refetch,
  } = useQuery<{ data: ProcessBlockRule[]; total: number; limit: number; offset: number }>({
    queryKey: ['process-block-rules'],
    queryFn: () => apiFetch('/api/v1/process-rules'),
  })

  const rules: ProcessBlockRule[] = rulesRaw?.data ?? []

  // ─── ミューテーション ────────────────────────────────────────────────────

  const createMutation = useMutation({
    mutationFn: (payload: ProcessBlockRuleForm) =>
      apiFetch('/api/v1/process-rules', {
        method: 'POST',
        body: JSON.stringify({
          ...payload,
          scope_id: payload.scope !== 'all' ? payload.scope_id || undefined : undefined,
        }),
      }),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['process-block-rules'] })
      setShowCreate(false)
      setError(null)
    },
    onError: (err: Error) => setError(err.message || 'ルールの作成に失敗しました'),
  })

  const updateMutation = useMutation({
    mutationFn: ({ id, payload }: { id: string; payload: ProcessBlockRuleForm }) =>
      apiFetch(`/api/v1/process-rules/${id}`, {
        method: 'PUT',
        body: JSON.stringify({
          ...payload,
          scope_id: payload.scope !== 'all' ? payload.scope_id || undefined : undefined,
        }),
      }),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['process-block-rules'] })
      setEditingRule(null)
      setError(null)
    },
    onError: (err: Error) => setError(err.message || 'ルールの更新に失敗しました'),
  })

  const deleteMutation = useMutation({
    mutationFn: (id: string) =>
      apiFetch(`/api/v1/process-rules/${id}`, { method: 'DELETE' }),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['process-block-rules'] })
      setConfirmDeleteId(null)
      setError(null)
    },
    onError: (err: Error) => setError(err.message || 'ルールの削除に失敗しました'),
  })

  const toggleMutation = useMutation({
    mutationFn: (id: string) =>
      apiFetch(`/api/v1/process-rules/${id}/toggle`, { method: 'PATCH' }),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['process-block-rules'] })
    },
    onError: (err: Error) => setError(err.message || 'トグルに失敗しました'),
  })

  // ─── フォーム初期値 ──────────────────────────────────────────────────────

  const editInitial: ProcessBlockRuleForm = editingRule
    ? {
        name:         editingRule.name,
        process_name: editingRule.process_name,
        rule_type:    editingRule.rule_type,
        scope:        editingRule.scope,
        scope_id:     editingRule.scope_id ?? '',
        action:       editingRule.action,
        severity:     editingRule.severity,
        enabled:      editingRule.enabled,
      }
    : EMPTY_PROCESS_RULE_FORM

  return (
    <div className="space-y-6">

      {/* ツールバー */}
      <div className="flex items-center justify-between gap-4">
        <div>
          <p className="text-[#8899aa] text-sm">
            プロセスの実行を許可・拒否するルールを管理します
          </p>
        </div>
        <div className="flex items-center gap-2">
          <button
            onClick={() => refetch()}
            disabled={isFetching}
            className="p-2 text-[#8899aa] hover:text-white transition-colors disabled:opacity-50
                       rounded-lg hover:bg-falcon-border"
            title="更新"
          >
            <RefreshCw className={`w-4 h-4 ${isFetching ? 'animate-spin' : ''}`} />
          </button>
          <button
            onClick={() => { setShowCreate(true); setError(null) }}
            className="flex items-center gap-2 px-4 py-2 bg-blue-600 text-white rounded-lg
                       hover:bg-blue-500 transition-colors text-sm"
          >
            <Plus className="w-4 h-4" />
            ルールを追加
          </button>
        </div>
      </div>

      {/* エラーバナー */}
      {error && (
        <div className="flex items-center gap-3 bg-red-900/30 border border-red-700/50 rounded-xl px-4 py-3 text-red-300 text-sm">
          <AlertTriangle className="w-4 h-4 shrink-0" />
          <span className="flex-1">{error}</span>
          <button
            onClick={() => setError(null)}
            className="text-red-400 hover:text-red-200 transition-colors"
          >
            <X className="w-4 h-4" />
          </button>
        </div>
      )}

      {/* テーブル */}
      {isLoading ? (
        <div className="flex items-center justify-center h-48">
          <div className="w-8 h-8 border-2 border-blue-500 border-t-transparent rounded-full animate-spin" />
        </div>
      ) : rules.length === 0 ? (
        <div className="flex flex-col items-center justify-center h-48 bg-falcon-surface rounded-xl border border-falcon-border">
          <Ban className="w-12 h-12 text-falcon-border mb-3" />
          <p className="text-[#8899aa] text-sm font-medium">ルールがありません</p>
          <p className="text-[#4a5568] text-xs mt-1">「ルールを追加」からプロセスブロックルールを作成してください</p>
          <button
            onClick={() => { setShowCreate(true); setError(null) }}
            className="mt-4 flex items-center gap-1.5 px-4 py-2 bg-blue-600/20 text-blue-300
                       border border-blue-600/50 rounded-lg text-sm hover:bg-blue-600/30 transition-colors"
          >
            <Plus className="w-4 h-4" />
            ルールを追加
          </button>
        </div>
      ) : (
        <div className="bg-falcon-surface rounded-xl border border-falcon-border overflow-hidden">
          <div className="overflow-x-auto">
            <table className="w-full text-sm">
              <thead>
                <tr className="border-b border-falcon-border">
                  {['ルール名', 'プロセス名', 'タイプ', 'アクション', 'スコープ', '重大度', '有効/無効', '操作'].map(h => (
                    <th
                      key={h}
                      className="text-left text-xs font-semibold text-[#8899aa] px-4 py-3 uppercase tracking-wider whitespace-nowrap"
                    >
                      {h}
                    </th>
                  ))}
                </tr>
              </thead>
              <tbody className="divide-y divide-falcon-border">
                {rules.map(rule => (
                  <tr key={rule.id} className="hover:bg-[#0a1020] transition-colors group">

                    {/* ルール名 */}
                    <td className="px-4 py-3 text-white font-medium whitespace-nowrap">
                      {rule.name}
                    </td>

                    {/* プロセス名 */}
                    <td className="px-4 py-3">
                      <span className="font-mono text-xs bg-[#070d19] text-[#c8d4e4] px-2 py-1 rounded-sm border border-falcon-border">
                        {rule.process_name}
                      </span>
                    </td>

                    {/* タイプ */}
                    <td className="px-4 py-3 whitespace-nowrap">
                      <span className={`text-xs px-2 py-0.5 rounded-full border font-medium ${
                        rule.rule_type === 'deny'
                          ? 'bg-red-900/30 text-red-300 border-red-700/50'
                          : 'bg-green-900/30 text-green-300 border-green-700/50'
                      }`}>
                        {rule.rule_type === 'deny' ? 'Deny' : 'Allow'}
                      </span>
                    </td>

                    {/* アクション */}
                    <td className="px-4 py-3 whitespace-nowrap">
                      <span className={`text-xs px-2 py-0.5 rounded-full border ${ACTION_STYLE[rule.action]}`}>
                        {ACTION_LABEL[rule.action]}
                      </span>
                    </td>

                    {/* スコープ */}
                    <td className="px-4 py-3 whitespace-nowrap">
                      <div className="flex items-center gap-1.5">
                        {rule.scope === 'all' ? (
                          <span className="flex items-center gap-1 text-xs px-2 py-0.5 rounded-full
                                           bg-falcon-border text-[#8899aa] border border-falcon-border">
                            <Globe className="w-3 h-3" />
                            全体
                          </span>
                        ) : rule.scope === 'group' ? (
                          <span className="flex items-center gap-1 text-xs px-2 py-0.5 rounded-full
                                           bg-purple-900/30 text-purple-300 border border-purple-700/50">
                            <Users className="w-3 h-3" />
                            {rule.scope_id ?? 'group'}
                          </span>
                        ) : (
                          <span className="text-xs px-2 py-0.5 rounded-full bg-blue-900/20 text-blue-300 border border-blue-700/40">
                            {rule.scope_id ?? 'agent'}
                          </span>
                        )}
                      </div>
                    </td>

                    {/* 重大度 */}
                    <td className="px-4 py-3 whitespace-nowrap">
                      <span className={`text-xs px-2 py-0.5 rounded-full border ${SEVERITY_STYLE[rule.severity]}`}>
                        {SEVERITY_LABEL[rule.severity]}
                      </span>
                    </td>

                    {/* トグル */}
                    <td className="px-4 py-3">
                      <button
                        onClick={() => toggleMutation.mutate(rule.id)}
                        disabled={toggleMutation.isPending}
                        className="relative"
                        title={rule.enabled ? '無効にする' : '有効にする'}
                      >
                        <div className={`relative w-10 h-5 rounded-full transition-colors ${
                          rule.enabled ? 'bg-blue-600' : 'bg-falcon-border'
                        }`}>
                          <div className={`absolute top-0.5 left-0.5 w-4 h-4 rounded-full bg-falcon-text shadow transition-transform ${
                            rule.enabled ? 'translate-x-5' : 'translate-x-0'
                          }`} />
                        </div>
                      </button>
                    </td>

                    {/* 操作 */}
                    <td className="px-4 py-3 whitespace-nowrap">
                      <div className="flex items-center gap-1">
                        <button
                          onClick={() => { setEditingRule(rule); setError(null) }}
                          className="p-1.5 text-[#8899aa] hover:text-blue-400 transition-colors rounded-lg hover:bg-blue-900/20"
                          title="編集"
                        >
                          <Edit2 className="w-4 h-4" />
                        </button>
                        {confirmDeleteId === rule.id ? (
                          <div className="flex items-center gap-1">
                            <button
                              onClick={() => deleteMutation.mutate(rule.id)}
                              disabled={deleteMutation.isPending}
                              className="text-xs text-red-300 bg-red-900/40 px-2 py-1 rounded-sm hover:bg-red-900/60 transition-colors disabled:opacity-50"
                            >
                              確認
                            </button>
                            <button
                              onClick={() => setConfirmDeleteId(null)}
                              className="text-xs text-[#8899aa] hover:text-white transition-colors"
                            >
                              <X className="w-3.5 h-3.5" />
                            </button>
                          </div>
                        ) : (
                          <button
                            onClick={() => setConfirmDeleteId(rule.id)}
                            className="p-1.5 text-[#8899aa] hover:text-red-400 transition-colors rounded-lg hover:bg-red-900/20"
                            title="削除"
                          >
                            <Trash2 className="w-4 h-4" />
                          </button>
                        )}
                      </div>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>

          {/* テーブルフッター (件数) */}
          <div className="px-4 py-2.5 border-t border-falcon-border text-xs text-[#8899aa]">
            {rules.length} 件 / 合計 {rulesRaw?.total ?? rules.length} 件
          </div>
        </div>
      )}

      {/* 新規作成モーダル */}
      {showCreate && (
        <ProcessRuleFormModal
          title="プロセスブロックルールを追加"
          initial={EMPTY_PROCESS_RULE_FORM}
          onClose={() => { setShowCreate(false); setError(null) }}
          onSubmit={f => createMutation.mutate(f)}
          isPending={createMutation.isPending}
        />
      )}

      {/* 編集モーダル */}
      {editingRule && (
        <ProcessRuleFormModal
          title={`編集: ${editingRule.name}`}
          initial={editInitial}
          onClose={() => { setEditingRule(null); setError(null) }}
          onSubmit={f => updateMutation.mutate({ id: editingRule.id, payload: f })}
          isPending={updateMutation.isPending}
        />
      )}
    </div>
  )
}

// ─── メインページ ─────────────────────────────────────────────────────────────

type Tab = 'policies' | 'process-block'

export default function GroupPoliciesPage() {
  const qc = useQueryClient()
  const [activeTab, setActiveTab] = useState<Tab>('policies')
  const [showCreate, setShowCreate] = useState(false)
  const [editingPolicy, setEditingPolicy] = useState<AgentPolicy | null>(null)
  const [error, setError] = useState<string | null>(null)

  // ─── ポリシー一覧 ────────────────────────────────────────────────────────
  const {
    data: policyRaw,
    isLoading: policiesLoading,
    isFetching,
    refetch,
  } = useQuery<AgentPolicy[] | { policies: AgentPolicy[] }>({
    queryKey: ['group-policies'],
    queryFn: () => apiFetch('/api/v1/agent-policies'),
  })

  // ─── グループ一覧 (404はグレースフルに扱う) ──────────────────────────────
  const { data: groupRaw } = useQuery<{ groups: AgentGroup[] }>({
    queryKey: ['agent-groups'],
    queryFn: () => apiFetch('/api/v1/agent-groups'),
    retry: false,
  })

  // ─── ミューテーション ─────────────────────────────────────────────────────

  const createMutation = useMutation({
    mutationFn: (payload: Omit<PolicyForm, 'config'> & { config: PolicyConfig }) =>
      apiFetch('/api/v1/agent-policies', {
        method: 'POST',
        body: JSON.stringify(payload),
      }),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['group-policies'] })
      setShowCreate(false)
      setError(null)
    },
    onError: (err: Error) => setError(err.message || 'ポリシーの作成に失敗しました'),
  })

  const updateMutation = useMutation({
    mutationFn: ({
      id,
      payload,
    }: {
      id: string
      payload: Omit<PolicyForm, 'config'> & { config: PolicyConfig }
    }) =>
      apiFetch(`/api/v1/agent-policies/${id}`, {
        method: 'PUT',
        body: JSON.stringify(payload),
      }),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['group-policies'] })
      setEditingPolicy(null)
      setError(null)
    },
    onError: (err: Error) => setError(err.message || 'ポリシーの更新に失敗しました'),
  })

  const deleteMutation = useMutation({
    mutationFn: (id: string) =>
      apiFetch(`/api/v1/agent-policies/${id}`, { method: 'DELETE' }),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['group-policies'] })
      setError(null)
    },
    onError: (err: Error) => setError(err.message || 'ポリシーの削除に失敗しました'),
  })

  // ─── 派生データ ───────────────────────────────────────────────────────────

  const policies: AgentPolicy[] = Array.isArray(policyRaw)
    ? policyRaw
    : (policyRaw as { policies?: AgentPolicy[] })?.policies ?? []

  const groups: AgentGroup[] = groupRaw?.groups ?? []

  const groupById = (id?: string): string | null => {
    if (!id) return null
    return groups.find(g => g.id === id)?.name ?? null
  }

  // ─── フォーム初期値 ───────────────────────────────────────────────────────

  const editInitial: PolicyForm = editingPolicy
    ? {
        name:        editingPolicy.name,
        description: editingPolicy.description,
        group_id:    editingPolicy.group_id ?? '',
        is_default:  editingPolicy.is_default,
        config:      editingPolicy.config,
      }
    : EMPTY_FORM

  // ─── ハンドラー ───────────────────────────────────────────────────────────

  const handleCreate = (form: PolicyForm) => {
    createMutation.mutate({
      ...form,
      group_id: form.group_id || undefined,
    } as never)
  }

  const handleUpdate = (form: PolicyForm) => {
    if (!editingPolicy) return
    updateMutation.mutate({
      id: editingPolicy.id,
      payload: {
        ...form,
        group_id: form.group_id || undefined,
      } as never,
    })
  }

  const defaultCount = policies.filter(p => p.is_default).length
  const groupCount   = policies.filter(p => p.group_id).length

  return (
    <div className="min-h-screen bg-[#070d19] p-6 space-y-6">

      {/* ─── ページヘッダー ─────────────────────────────────────────────── */}
      <div className="flex items-start justify-between gap-4">
        <div>
          <h1 className="text-2xl font-bold text-white flex items-center gap-2">
            <Shield className="w-6 h-6 text-blue-400" />
            エンドポイントグループポリシー
          </h1>
          <p className="text-[#8899aa] text-sm mt-1">
            エージェントの収集・監視設定をグループ単位でポリシーとして管理します
          </p>
        </div>

        {/* ポリシータブのときだけ「新規作成」ボタンを表示 */}
        {activeTab === 'policies' && (
          <div className="flex items-center gap-3">
            <button
              onClick={() => { refetch(); qc.invalidateQueries({ queryKey: ['agent-groups'] }) }}
              disabled={isFetching}
              className="p-2 text-[#8899aa] hover:text-white transition-colors disabled:opacity-50 rounded-lg hover:bg-falcon-surface"
              title="更新"
            >
              <RefreshCw className={`w-5 h-5 ${isFetching ? 'animate-spin' : ''}`} />
            </button>
            <button
              onClick={() => { setShowCreate(true); setError(null) }}
              className="flex items-center gap-2 px-4 py-2 bg-blue-600 text-white rounded-lg
                         hover:bg-blue-500 transition-colors text-sm"
            >
              <Plus className="w-4 h-4" />
              新しいポリシーを作成
            </button>
          </div>
        )}
      </div>

      {/* ─── タブナビゲーション ─────────────────────────────────────────── */}
      <div className="flex gap-1 border-b border-falcon-border">
        <button
          onClick={() => setActiveTab('policies')}
          className={`flex items-center gap-2 px-4 py-2.5 text-sm font-medium transition-colors border-b-2 -mb-px ${
            activeTab === 'policies'
              ? 'border-blue-500 text-blue-400'
              : 'border-transparent text-[#8899aa] hover:text-white hover:border-falcon-border'
          }`}
        >
          <Shield className="w-4 h-4" />
          グループポリシー
        </button>
        <button
          onClick={() => setActiveTab('process-block')}
          className={`flex items-center gap-2 px-4 py-2.5 text-sm font-medium transition-colors border-b-2 -mb-px ${
            activeTab === 'process-block'
              ? 'border-red-500 text-red-400'
              : 'border-transparent text-[#8899aa] hover:text-white hover:border-falcon-border'
          }`}
        >
          <Ban className="w-4 h-4" />
          プロセスブロック
        </button>
      </div>

      {/* ─── グループポリシータブ ────────────────────────────────────────── */}
      {activeTab === 'policies' && (
        <div className="space-y-6">

          {/* エラーバナー */}
          {error && (
            <div className="flex items-center gap-3 bg-red-900/30 border border-red-700/50 rounded-xl px-4 py-3 text-red-300 text-sm">
              <AlertTriangle className="w-4 h-4 shrink-0" />
              <span className="flex-1">{error}</span>
              <button
                onClick={() => setError(null)}
                className="text-red-400 hover:text-red-200 transition-colors"
              >
                <X className="w-4 h-4" />
              </button>
            </div>
          )}

          {/* サマリーカード */}
          <div className="grid grid-cols-3 gap-4">
            {[
              { label: '総ポリシー数',         value: policies.length,  color: 'text-white' },
              { label: 'デフォルトポリシー',    value: defaultCount,     color: 'text-green-400' },
              { label: 'グループ固有ポリシー',  value: groupCount,       color: 'text-purple-400' },
            ].map(({ label, value, color }) => (
              <div key={label} className="bg-falcon-surface rounded-xl border border-falcon-border px-5 py-4">
                <p className="text-[#8899aa] text-xs">{label}</p>
                <p className={`text-2xl font-bold mt-1 ${color}`}>{value}</p>
              </div>
            ))}
          </div>

          {/* ポリシー一覧 */}
          {policiesLoading ? (
            <div className="flex items-center justify-center h-48">
              <div className="w-8 h-8 border-2 border-blue-500 border-t-transparent rounded-full animate-spin" />
            </div>
          ) : policies.length === 0 ? (
            <div className="flex flex-col items-center justify-center h-48 bg-falcon-surface rounded-xl border border-falcon-border">
              <Shield className="w-12 h-12 text-falcon-border mb-3" />
              <p className="text-[#8899aa] text-sm font-medium">ポリシーがありません</p>
              <p className="text-[#4a5568] text-xs mt-1">「新しいポリシーを作成」からポリシーを追加してください</p>
              <button
                onClick={() => { setShowCreate(true); setError(null) }}
                className="mt-4 flex items-center gap-1.5 px-4 py-2 bg-blue-600/20 text-blue-300
                           border border-blue-600/50 rounded-lg text-sm hover:bg-blue-600/30 transition-colors"
              >
                <Plus className="w-4 h-4" />
                ポリシーを作成
              </button>
            </div>
          ) : (
            <div className="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-3 gap-4">
              {policies.map(policy => (
                <PolicyCard
                  key={policy.id}
                  policy={policy}
                  groupName={groupById(policy.group_id)}
                  onEdit={p => { setEditingPolicy(p); setError(null) }}
                  onDelete={id => deleteMutation.mutate(id)}
                />
              ))}
            </div>
          )}
        </div>
      )}

      {/* ─── プロセスブロックタブ ────────────────────────────────────────── */}
      {activeTab === 'process-block' && <ProcessBlockRulesTab />}

      {/* ─── 新規作成モーダル ────────────────────────────────────────────── */}
      {showCreate && (
        <PolicyFormModal
          title="新しいポリシーを作成"
          initial={EMPTY_FORM}
          groups={groups}
          onClose={() => { setShowCreate(false); setError(null) }}
          onSubmit={handleCreate}
          isPending={createMutation.isPending}
        />
      )}

      {/* ─── 編集モーダル ────────────────────────────────────────────────── */}
      {editingPolicy && (
        <PolicyFormModal
          title={`編集: ${editingPolicy.name}`}
          initial={editInitial}
          groups={groups}
          onClose={() => { setEditingPolicy(null); setError(null) }}
          onSubmit={handleUpdate}
          isPending={updateMutation.isPending}
        />
      )}
    </div>
  )
}

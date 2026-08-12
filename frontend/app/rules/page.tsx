'use client'

import { useState } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import Link from 'next/link'
import {
  Shield, Plus, Upload, Wand2, Search, Filter,
  ToggleLeft, ToggleRight,
  FileCode, Brain, Edit3, Trash2, TestTube,
  RefreshCw, CheckCircle, XCircle, Loader2
} from 'lucide-react'
import { apiFetch } from '@/lib/api'
import { useCanWrite } from '@/lib/auth'

interface Rule {
  id: string
  name: string
  type: 'sigma' | 'yara' | 'behavioral'
  platform: string[]
  severity: number
  enabled: boolean
  source: string
  mitre_tags: string[]
  auto_isolate: boolean
  auto_kill: boolean
  auto_quarantine: boolean
  description?: string
  false_positive_rate: number
  created_at: string
  updated_at: string
}

interface AIGenerateForm {
  description: string
  type: 'sigma' | 'yara'
  platform: string
  examples: string
}

interface SyncStatus {
  syncing: boolean
  last_sync?: string
  last_error?: string
  rules_synced?: number
}

function fetchRules(params: { type?: string; enabled?: boolean; search?: string }) {
  const query = new URLSearchParams()
  if (params.type) query.set('type', params.type)
  if (params.enabled !== undefined) query.set('enabled', String(params.enabled))
  if (params.search) query.set('search', params.search)
  return apiFetch<{ rules: Rule[]; total: number }>(`/api/v1/rules?${query}`)
}

function toggleRule(id: string, enabled: boolean) {
  return apiFetch(`/api/v1/rules/${id}/toggle`, {
    method: 'PUT',
    body: JSON.stringify({ enabled }),
  })
}

function deleteRule(id: string) {
  return apiFetch(`/api/v1/rules/${id}`, { method: 'DELETE' })
}

function generateRuleWithAI(form: AIGenerateForm) {
  return apiFetch<{ rule: Rule; content: string }>('/api/v1/rules/ai-generate', {
    method: 'POST',
    body: JSON.stringify(form),
  })
}

function triggerSync(autoEnable: boolean) {
  return apiFetch('/api/v1/rules/sync', {
    method: 'POST',
    body: JSON.stringify({ auto_enable: autoEnable }),
  })
}

function fetchSyncStatus() {
  return apiFetch<SyncStatus>('/api/v1/rules/sync/status')
}

function severityColor(s: number) {
  if (s >= 9) return 'text-red-400 bg-red-900/30'
  if (s >= 7) return 'text-orange-400 bg-orange-900/30'
  if (s >= 5) return 'text-yellow-400 bg-yellow-900/30'
  return 'text-green-400 bg-green-900/30'
}

function typeIcon(type: string) {
  switch (type) {
    case 'sigma': return <FileCode className="w-4 h-4 text-blue-400" />
    case 'yara': return <Shield className="w-4 h-4 text-purple-400" />
    case 'behavioral': return <Brain className="w-4 h-4 text-green-400" />
    default: return <Shield className="w-4 h-4 text-[#8899aa]" />
  }
}

function platformBadge(p: string) {
  const colors: Record<string, string> = {
    windows: 'bg-blue-900/40 text-blue-300',
    linux: 'bg-orange-900/40 text-orange-300',
    darwin: 'bg-[#161f33] text-[#8899aa]',
  }
  return colors[p] || 'bg-[#161f33] text-[#8899aa]'
}

export default function RulesPage() {
  const canWrite = useCanWrite()
  const qc = useQueryClient()
  const [search, setSearch] = useState('')
  const [typeFilter, setTypeFilter] = useState('')
  const [enabledFilter, setEnabledFilter] = useState<boolean | undefined>(undefined)
  const [showAIModal, setShowAIModal] = useState(false)
  const [showImportModal, setShowImportModal] = useState(false)
  const [showSyncModal, setShowSyncModal] = useState(false)
  const [syncAutoEnable, setSyncAutoEnable] = useState(false)
  const [aiForm, setAIForm] = useState<AIGenerateForm>({
    description: '', type: 'sigma', platform: 'windows', examples: ''
  })
  const [generatedRule, setGeneratedRule] = useState<{ rule: Rule; content: string } | null>(null)
  const [importContent, setImportContent] = useState('')
  const [importType, setImportType] = useState<'sigma' | 'yara'>('sigma')

  const { data, isLoading } = useQuery({
    queryKey: ['rules', search, typeFilter, enabledFilter],
    queryFn: () => fetchRules({ type: typeFilter || undefined, enabled: enabledFilter, search: search || undefined }),
    refetchInterval: 30000
  })

  const toggleMutation = useMutation({
    mutationFn: ({ id, enabled }: { id: string; enabled: boolean }) => toggleRule(id, !enabled),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['rules'] })
  })

  const deleteMutation = useMutation({
    mutationFn: deleteRule,
    onSuccess: () => qc.invalidateQueries({ queryKey: ['rules'] })
  })

  const aiMutation = useMutation({
    mutationFn: generateRuleWithAI,
    onSuccess: (data) => setGeneratedRule(data)
  })

  const syncMutation = useMutation({
    mutationFn: () => triggerSync(syncAutoEnable),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['syncStatus'] })
      // poll status until sync completes
      const interval = setInterval(() => {
        qc.invalidateQueries({ queryKey: ['syncStatus'] })
      }, 2000)
      setTimeout(() => {
        clearInterval(interval)
        qc.invalidateQueries({ queryKey: ['rules'] })
      }, 30000)
    }
  })

  const { data: syncStatus } = useQuery({
    queryKey: ['syncStatus'],
    queryFn: fetchSyncStatus,
    refetchInterval: (query) => query.state.data?.syncing ? 2000 : false,
  })

  const rawRules = data?.rules || []
  const rules = [...new Map(rawRules.map(r => [`${r.name}::${r.type}`, r])).values()]
  const total = data?.total || rules.length
  const enabledCount = rules.filter(r => r.enabled).length

  return (
    <div className="p-6 space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-white">検知ルール</h1>
          <p className="text-[#8899aa] text-sm mt-1">
            {total}件のルール（有効: {enabledCount}件）
          </p>
        </div>
        <div className="flex items-center gap-3">
          {canWrite && (
            <button
              onClick={() => setShowSyncModal(true)}
              className="flex items-center gap-2 px-4 py-2 bg-[#161f33] text-[#e2e8f4] rounded-lg hover:bg-[#1d2f4a] transition-colors text-sm"
            >
              <RefreshCw className={`w-4 h-4 ${syncStatus?.syncing ? 'animate-spin text-blue-400' : ''}`} />
              SigmaHQ同期
            </button>
          )}
          {canWrite && (
            <button
              onClick={() => setShowImportModal(true)}
              className="flex items-center gap-2 px-4 py-2 bg-[#161f33] text-[#e2e8f4] rounded-lg hover:bg-[#1d2f4a] transition-colors text-sm"
            >
              <Upload className="w-4 h-4" />
              インポート
            </button>
          )}
          {canWrite && (
            <button
              onClick={() => setShowAIModal(true)}
              className="flex items-center gap-2 px-4 py-2 bg-purple-600 text-white rounded-lg hover:bg-purple-700 transition-colors text-sm"
            >
              <Wand2 className="w-4 h-4" />
              AIで生成
            </button>
          )}
          {canWrite && (
            <Link
              href="/rules/new"
              className="flex items-center gap-2 px-4 py-2 bg-[#1a6bff] text-white rounded-lg hover:bg-[#1557d4] transition-colors text-sm"
            >
              <Plus className="w-4 h-4" />
              新規ルール
            </Link>
          )}
        </div>
      </div>

      {/* Stats */}
      <div className="grid grid-cols-4 gap-4">
        {[
          { label: 'Sigma ルール', count: rules.filter(r => r.type === 'sigma').length, color: 'text-blue-400' },
          { label: 'YARA ルール', count: rules.filter(r => r.type === 'yara').length, color: 'text-purple-400' },
          { label: '自動隔離', count: rules.filter(r => r.auto_isolate).length, color: 'text-red-400' },
          { label: '自動プロセス停止', count: rules.filter(r => r.auto_kill).length, color: 'text-orange-400' },
        ].map(stat => (
          <div key={stat.label} className="bg-[#111827] rounded-xl p-4">
            <div className={`text-2xl font-bold ${stat.color}`}>{stat.count}</div>
            <div className="text-[#8899aa] text-sm mt-1">{stat.label}</div>
          </div>
        ))}
      </div>

      {/* Filters */}
      <div className="flex items-center gap-3">
        <div className="relative flex-1 max-w-xs">
          <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-[#8899aa]" />
          <input
            type="text"
            placeholder="ルール名を検索..."
            value={search}
            onChange={e => setSearch(e.target.value)}
            className="w-full bg-[#111827] text-white pl-9 pr-4 py-2 rounded-lg border border-[#1e2d42] focus:outline-none focus:border-[#1a6bff] text-sm"
          />
        </div>
        <div className="flex items-center gap-2">
          <Filter className="w-4 h-4 text-[#8899aa]" />
          <select
            value={typeFilter}
            onChange={e => setTypeFilter(e.target.value)}
            className="bg-[#111827] text-white px-3 py-2 rounded-lg border border-[#1e2d42] text-sm focus:outline-none focus:border-[#1a6bff]"
          >
            <option value="">全タイプ</option>
            <option value="sigma">Sigma</option>
            <option value="yara">YARA</option>
            <option value="behavioral">Behavioral</option>
          </select>
          <select
            value={enabledFilter === undefined ? '' : String(enabledFilter)}
            onChange={e => setEnabledFilter(e.target.value === '' ? undefined : e.target.value === 'true')}
            className="bg-[#111827] text-white px-3 py-2 rounded-lg border border-[#1e2d42] text-sm focus:outline-none focus:border-[#1a6bff]"
          >
            <option value="">全状態</option>
            <option value="true">有効</option>
            <option value="false">無効</option>
          </select>
        </div>
      </div>

      {/* Rules Table */}
      <div className="bg-[#111827] rounded-xl overflow-hidden">
        <table className="w-full">
          <thead>
            <tr className="border-b border-[#1e2d42]">
              <th className="text-left px-4 py-3 text-[#8899aa] text-sm font-medium">ルール名</th>
              <th className="text-left px-4 py-3 text-[#8899aa] text-sm font-medium">タイプ</th>
              <th className="text-left px-4 py-3 text-[#8899aa] text-sm font-medium">プラットフォーム</th>
              <th className="text-left px-4 py-3 text-[#8899aa] text-sm font-medium">深刻度</th>
              <th className="text-left px-4 py-3 text-[#8899aa] text-sm font-medium">自動対応</th>
              <th className="text-left px-4 py-3 text-[#8899aa] text-sm font-medium">MITRE</th>
              <th className="text-left px-4 py-3 text-[#8899aa] text-sm font-medium">有効</th>
              <th className="text-left px-4 py-3 text-[#8899aa] text-sm font-medium">操作</th>
            </tr>
          </thead>
          <tbody>
            {isLoading ? (
              [...Array(5)].map((_, i) => (
                <tr key={i} className="border-b border-[#1e2d42]/50">
                  {[...Array(8)].map((_, j) => (
                    <td key={j} className="px-4 py-3">
                      <div className="h-4 bg-[#161f33] rounded animate-pulse" />
                    </td>
                  ))}
                </tr>
              ))
            ) : rules.length === 0 ? (
              <tr>
                <td colSpan={8} className="px-4 py-12 text-center text-[#5a6a7a]">
                  ルールが見つかりません
                </td>
              </tr>
            ) : (
              rules.map(rule => (
                <tr key={rule.id} className="border-b border-[#1e2d42]/50 hover:bg-[#161f33] transition-colors">
                  <td className="px-4 py-3">
                    <Link href={`/rules/${rule.id}`} className="text-white hover:text-blue-400 transition-colors font-medium text-sm">
                      {rule.name}
                    </Link>
                    {rule.description && (
                      <p className="text-[#5a6a7a] text-xs mt-0.5 truncate max-w-xs">{rule.description}</p>
                    )}
                  </td>
                  <td className="px-4 py-3">
                    <div className="flex items-center gap-1.5">
                      {typeIcon(rule.type)}
                      <span className="text-[#8899aa] text-sm capitalize">{rule.type}</span>
                    </div>
                  </td>
                  <td className="px-4 py-3">
                    <div className="flex flex-wrap gap-1">
                      {rule.platform.map(p => (
                        <span key={p} className={`text-xs px-2 py-0.5 rounded-full ${platformBadge(p)}`}>{p}</span>
                      ))}
                    </div>
                  </td>
                  <td className="px-4 py-3">
                    <span className={`text-xs font-bold px-2 py-1 rounded ${severityColor(rule.severity)}`}>
                      {rule.severity}
                    </span>
                  </td>
                  <td className="px-4 py-3">
                    <div className="flex gap-1">
                      {rule.auto_isolate && (
                        <span className="text-xs bg-red-900/40 text-red-300 px-1.5 py-0.5 rounded">隔離</span>
                      )}
                      {rule.auto_kill && (
                        <span className="text-xs bg-orange-900/40 text-orange-300 px-1.5 py-0.5 rounded">停止</span>
                      )}
                      {rule.auto_quarantine && (
                        <span className="text-xs bg-yellow-900/40 text-yellow-300 px-1.5 py-0.5 rounded">検疫</span>
                      )}
                      {!rule.auto_isolate && !rule.auto_kill && !rule.auto_quarantine && (
                        <span className="text-xs text-[#5a6a7a]">なし</span>
                      )}
                    </div>
                  </td>
                  <td className="px-4 py-3">
                    <div className="flex flex-wrap gap-1 max-w-[120px]">
                      {(rule.mitre_tags || []).slice(0, 2).map(tag => (
                        <span key={tag} className="text-xs bg-[#161f33] text-[#8899aa] px-1.5 py-0.5 rounded font-mono">
                          {tag}
                        </span>
                      ))}
                      {(rule.mitre_tags || []).length > 2 && (
                        <span className="text-xs text-[#5a6a7a]">+{(rule.mitre_tags || []).length - 2}</span>
                      )}
                    </div>
                  </td>
                  <td className="px-4 py-3">
                    {canWrite ? (
                      <button
                        onClick={() => toggleMutation.mutate({ id: rule.id, enabled: rule.enabled })}
                        disabled={toggleMutation.isPending}
                        className="text-[#8899aa] hover:text-white transition-colors disabled:opacity-50"
                      >
                        {rule.enabled
                          ? <ToggleRight className="w-6 h-6 text-green-400" />
                          : <ToggleLeft className="w-6 h-6 text-[#5a6a7a]" />
                        }
                      </button>
                    ) : (
                      rule.enabled
                        ? <ToggleRight className="w-6 h-6 text-green-400" />
                        : <ToggleLeft className="w-6 h-6 text-[#5a6a7a]" />
                    )}
                  </td>
                  <td className="px-4 py-3">
                    <div className="flex items-center gap-2">
                      <Link href={`/rules/${rule.id}`} className="text-[#8899aa] hover:text-blue-400 transition-colors">
                        <Edit3 className="w-4 h-4" />
                      </Link>
                      {canWrite && (
                        <button
                          onClick={() => {
                            if (confirm(`ルール「${rule.name}」を削除しますか？`)) {
                              deleteMutation.mutate(rule.id)
                            }
                          }}
                          className="text-[#8899aa] hover:text-red-400 transition-colors"
                        >
                          <Trash2 className="w-4 h-4" />
                        </button>
                      )}
                      <Link href={`/rules/${rule.id}?tab=test`} className="text-[#8899aa] hover:text-yellow-400 transition-colors">
                        <TestTube className="w-4 h-4" />
                      </Link>
                    </div>
                  </td>
                </tr>
              ))
            )}
          </tbody>
        </table>
      </div>

      {/* SigmaHQ Sync Modal */}
      {showSyncModal && (
        <div className="fixed inset-0 bg-black/60 backdrop-blur-sm flex items-center justify-center z-50">
          <div className="bg-[#111827] rounded-2xl p-6 w-full max-w-md border border-[#1e2d42]">
            <h2 className="text-xl font-bold text-white mb-1 flex items-center gap-2">
              <RefreshCw className="w-5 h-5 text-blue-400" />
              SigmaHQコミュニティルールを同期
            </h2>
            <p className="text-[#8899aa] text-sm mb-4">
              SigmaHQのGitHubリポジトリから最新のSigmaルールを取得します。
              既存のカスタムルールは上書きされません。
            </p>

            {syncStatus?.last_sync && (
              <div className="bg-[#080c14] rounded-lg p-3 mb-4 text-sm">
                <div className="flex items-center gap-2 text-[#8899aa]">
                  {syncStatus.last_error
                    ? <XCircle className="w-4 h-4 text-red-400 flex-shrink-0" />
                    : <CheckCircle className="w-4 h-4 text-green-400 flex-shrink-0" />
                  }
                  <span>
                    前回の同期: {new Date(syncStatus.last_sync).toLocaleString('ja-JP')}
                    {syncStatus.rules_synced !== undefined && ` — ${syncStatus.rules_synced}件のルール`}
                  </span>
                </div>
                {syncStatus.last_error && (
                  <p className="text-red-400 text-xs mt-1 ml-6">{syncStatus.last_error}</p>
                )}
              </div>
            )}

            {syncStatus?.syncing && (
              <div className="flex items-center gap-2 text-blue-400 text-sm mb-4">
                <Loader2 className="w-4 h-4 animate-spin" />
                同期中... しばらくお待ちください
              </div>
            )}

            <div className="flex items-center gap-3 mb-5">
              <label className="flex items-center gap-2 cursor-pointer">
                <input
                  type="checkbox"
                  checked={syncAutoEnable}
                  onChange={e => setSyncAutoEnable(e.target.checked)}
                  className="w-4 h-4 rounded border-[#1e2d42] bg-[#161f33] text-blue-600"
                />
                <span className="text-[#8899aa] text-sm">取得したルールを自動的に有効化する</span>
              </label>
            </div>

            <div className="flex gap-3">
              <button
                onClick={() => {
                  syncMutation.mutate()
                  setShowSyncModal(false)
                }}
                disabled={syncStatus?.syncing || syncMutation.isPending}
                className="flex-1 py-2 bg-[#1a6bff] text-white rounded-lg hover:bg-[#1557d4]
                           transition-colors disabled:opacity-50 flex items-center justify-center gap-2"
              >
                <RefreshCw className="w-4 h-4" />
                同期開始
              </button>
              <button
                onClick={() => setShowSyncModal(false)}
                className="px-4 py-2 bg-[#161f33] text-[#8899aa] rounded-lg hover:bg-[#1d2f4a] transition-colors"
              >
                キャンセル
              </button>
            </div>
          </div>
        </div>
      )}

      {/* AI Generate Modal */}
      {showAIModal && (
        <div className="fixed inset-0 bg-black/60 backdrop-blur-sm flex items-center justify-center z-50">
          <div className="bg-[#111827] rounded-2xl p-6 w-full max-w-2xl border border-[#1e2d42]">
            <h2 className="text-xl font-bold text-white mb-4 flex items-center gap-2">
              <Wand2 className="w-5 h-5 text-purple-400" />
              AIでルールを生成
            </h2>
            {generatedRule ? (
              <div className="space-y-4">
                <div className="bg-[#080c14] rounded-lg p-4">
                  <div className="flex items-center justify-between mb-2">
                    <span className="text-green-400 font-medium">生成完了: {generatedRule.rule.name}</span>
                    <span className={`text-xs font-bold px-2 py-1 rounded ${severityColor(generatedRule.rule.severity)}`}>
                      深刻度 {generatedRule.rule.severity}
                    </span>
                  </div>
                  <pre className="text-[#8899aa] text-xs overflow-auto max-h-48 font-mono">{generatedRule.content}</pre>
                </div>
                <div className="flex gap-3">
                  <button
                    onClick={() => {
                      setGeneratedRule(null)
                      setShowAIModal(false)
                      qc.invalidateQueries({ queryKey: ['rules'] })
                    }}
                    className="flex-1 py-2 bg-[#1a6bff] text-white rounded-lg hover:bg-[#1557d4] transition-colors"
                  >
                    保存して閉じる
                  </button>
                  <button
                    onClick={() => setGeneratedRule(null)}
                    className="px-4 py-2 bg-[#161f33] text-[#8899aa] rounded-lg hover:bg-[#1d2f4a] transition-colors"
                  >
                    再生成
                  </button>
                </div>
              </div>
            ) : (
              <div className="space-y-4">
                <div>
                  <label className="text-[#8899aa] text-sm block mb-1">検知したい脅威の説明 *</label>
                  <textarea
                    value={aiForm.description}
                    onChange={e => setAIForm(f => ({ ...f, description: e.target.value }))}
                    placeholder="例: PowerShellを使ったダウンローダーの実行、特にエンコードされたコマンドラインを持つもの"
                    rows={3}
                    className="w-full bg-[#080c14] text-white px-3 py-2 rounded-lg border border-[#1e2d42] focus:outline-none focus:border-purple-500 text-sm resize-none"
                  />
                </div>
                <div className="grid grid-cols-2 gap-4">
                  <div>
                    <label className="text-[#8899aa] text-sm block mb-1">ルールタイプ</label>
                    <select
                      value={aiForm.type}
                      onChange={e => setAIForm(f => ({ ...f, type: e.target.value as 'sigma' | 'yara' }))}
                      className="w-full bg-[#080c14] text-white px-3 py-2 rounded-lg border border-[#1e2d42] text-sm focus:outline-none focus:border-purple-500"
                    >
                      <option value="sigma">Sigma（ログベース）</option>
                      <option value="yara">YARA（ファイルスキャン）</option>
                    </select>
                  </div>
                  <div>
                    <label className="text-[#8899aa] text-sm block mb-1">プラットフォーム</label>
                    <select
                      value={aiForm.platform}
                      onChange={e => setAIForm(f => ({ ...f, platform: e.target.value }))}
                      className="w-full bg-[#080c14] text-white px-3 py-2 rounded-lg border border-[#1e2d42] text-sm focus:outline-none focus:border-purple-500"
                    >
                      <option value="windows">Windows</option>
                      <option value="linux">Linux</option>
                      <option value="darwin">macOS</option>
                    </select>
                  </div>
                </div>
                <div>
                  <label className="text-[#8899aa] text-sm block mb-1">具体的な例（任意）</label>
                  <textarea
                    value={aiForm.examples}
                    onChange={e => setAIForm(f => ({ ...f, examples: e.target.value }))}
                    placeholder="コマンドライン例やファイル内容など..."
                    rows={2}
                    className="w-full bg-[#080c14] text-white px-3 py-2 rounded-lg border border-[#1e2d42] focus:outline-none focus:border-purple-500 text-sm resize-none"
                  />
                </div>
                <div className="flex gap-3">
                  <button
                    onClick={() => aiMutation.mutate(aiForm)}
                    disabled={!aiForm.description || aiMutation.isPending}
                    className="flex-1 py-2 bg-purple-600 text-white rounded-lg hover:bg-purple-700 transition-colors disabled:opacity-50 disabled:cursor-not-allowed flex items-center justify-center gap-2"
                  >
                    {aiMutation.isPending ? (
                      <>
                        <div className="w-4 h-4 border-2 border-white/30 border-t-white rounded-full animate-spin" />
                        生成中...
                      </>
                    ) : (
                      <>
                        <Wand2 className="w-4 h-4" />
                        ルールを生成
                      </>
                    )}
                  </button>
                  <button
                    onClick={() => setShowAIModal(false)}
                    className="px-4 py-2 bg-[#161f33] text-[#8899aa] rounded-lg hover:bg-[#1d2f4a] transition-colors"
                  >
                    キャンセル
                  </button>
                </div>
                {aiMutation.isError && (
                  <p className="text-red-400 text-sm">生成に失敗しました。再度お試しください。</p>
                )}
              </div>
            )}
          </div>
        </div>
      )}

      {/* Import Modal */}
      {showImportModal && (
        <div className="fixed inset-0 bg-black/60 backdrop-blur-sm flex items-center justify-center z-50">
          <div className="bg-[#111827] rounded-2xl p-6 w-full max-w-2xl border border-[#1e2d42]">
            <h2 className="text-xl font-bold text-white mb-4 flex items-center gap-2">
              <Upload className="w-5 h-5 text-blue-400" />
              ルールをインポート
            </h2>
            <div className="space-y-4">
              <div>
                <label className="text-[#8899aa] text-sm block mb-1">フォーマット</label>
                <div className="flex gap-3">
                  {(['sigma', 'yara'] as const).map(t => (
                    <button
                      key={t}
                      onClick={() => setImportType(t)}
                      className={`flex-1 py-2 rounded-lg border text-sm transition-colors ${
                        importType === t
                          ? 'border-blue-500 bg-blue-900/30 text-blue-300'
                          : 'border-[#1e2d42] text-[#8899aa] hover:border-[#1e2d42]'
                      }`}
                    >
                      {t.toUpperCase()}
                    </button>
                  ))}
                </div>
              </div>
              <div>
                <label className="text-[#8899aa] text-sm block mb-1">ルール内容を貼り付け</label>
                <textarea
                  value={importContent}
                  onChange={e => setImportContent(e.target.value)}
                  placeholder={importType === 'sigma' ? 'title: ...\ndetection:\n  selection:\n    ...' : 'rule RuleName {\n  strings:\n    ...\n  condition:\n    ...\n}'}
                  rows={10}
                  className="w-full bg-[#080c14] text-white px-3 py-2 rounded-lg border border-[#1e2d42] focus:outline-none focus:border-[#1a6bff] text-sm font-mono resize-none"
                />
              </div>
              <div className="flex gap-3">
                <button
                  onClick={async () => {
                    try {
                      await apiFetch('/api/v1/rules/import', {
                        method: 'POST',
                        body: JSON.stringify({ type: importType, content: importContent }),
                      })
                      setShowImportModal(false)
                      setImportContent('')
                      qc.invalidateQueries({ queryKey: ['rules'] })
                    } catch {
                      alert('インポートに失敗しました')
                    }
                  }}
                  disabled={!importContent}
                  className="flex-1 py-2 bg-[#1a6bff] text-white rounded-lg hover:bg-[#1557d4] transition-colors disabled:opacity-50"
                >
                  インポート
                </button>
                <button
                  onClick={() => setShowImportModal(false)}
                  className="px-4 py-2 bg-[#161f33] text-[#8899aa] rounded-lg hover:bg-[#1d2f4a] transition-colors"
                >
                  キャンセル
                </button>
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  )
}

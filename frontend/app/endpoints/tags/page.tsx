'use client'

import { useState, useMemo } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { apiFetch } from '@/lib/api'
import {
  Tag, Plus, Trash2, X, Check, ChevronRight, Search,
  Monitor, AlertTriangle, CheckSquare, Square,
} from 'lucide-react'
import { PageDataUnavailable } from '@/components/PageDataUnavailable'

import { USE_MOCK, m } from '@/lib/mock'

// ── Types ──────────────────────────────────────────────────────

interface EndpointTag {
  id: string
  name: string
  color: string
  endpoint_count: number
}

interface Agent {
  id: string
  hostname: string
  os: string
  status: 'online' | 'offline' | 'warning'
  tags: string[]
}

interface TagsResponse { tags: EndpointTag[] }
interface AgentsResponse { agents: Agent[]; total: number }

// ── Mock Data ──────────────────────────────────────────────────

const TAG_COLORS = [
  { label: 'Blue',   value: '#3b82f6' },
  { label: 'Green',  value: '#22c55e' },
  { label: 'Red',    value: '#e8002d' },
  { label: 'Orange', value: '#f97316' },
  { label: 'Purple', value: '#a855f7' },
  { label: 'Grey',   value: '#6b7280' },
  { label: 'Yellow', value: '#eab308' },
]

const MOCK_TAGS: EndpointTag[] = [
  { id: 't1', name: 'Production',  color: '#e8002d', endpoint_count: 8 },
  { id: 't2', name: 'Development', color: '#3b82f6', endpoint_count: 4 },
  { id: 't3', name: 'Critical',    color: '#f97316', endpoint_count: 3 },
  { id: 't4', name: 'Windows',     color: '#6b7280', endpoint_count: 9 },
  { id: 't5', name: 'Linux',       color: '#22c55e', endpoint_count: 6 },
  { id: 't6', name: 'Finance',     color: '#a855f7', endpoint_count: 2 },
]

const MOCK_AGENTS: Agent[] = [
  { id: 'a01', hostname: 'WIN-DC-01',       os: 'Windows', status: 'online',  tags: ['Production', 'Windows', 'Critical'] },
  { id: 'a02', hostname: 'WIN-WEB-02',      os: 'Windows', status: 'online',  tags: ['Production', 'Windows'] },
  { id: 'a03', hostname: 'LINUX-APP-01',    os: 'Linux',   status: 'online',  tags: ['Production', 'Linux'] },
  { id: 'a04', hostname: 'LINUX-DB-01',     os: 'Linux',   status: 'warning', tags: ['Production', 'Linux', 'Critical'] },
  { id: 'a05', hostname: 'WIN-DEV-01',      os: 'Windows', status: 'online',  tags: ['Development', 'Windows'] },
  { id: 'a06', hostname: 'LINUX-DEV-01',    os: 'Linux',   status: 'online',  tags: ['Development', 'Linux'] },
  { id: 'a07', hostname: 'WIN-FIN-01',      os: 'Windows', status: 'online',  tags: ['Finance', 'Windows', 'Production'] },
  { id: 'a08', hostname: 'WIN-FIN-02',      os: 'Windows', status: 'offline', tags: ['Finance', 'Windows'] },
  { id: 'a09', hostname: 'LINUX-MON-01',    os: 'Linux',   status: 'online',  tags: ['Linux'] },
  { id: 'a10', hostname: 'WIN-SRV-03',      os: 'Windows', status: 'online',  tags: ['Windows', 'Production'] },
  { id: 'a11', hostname: 'WIN-SRV-04',      os: 'Windows', status: 'online',  tags: ['Windows'] },
  { id: 'a12', hostname: 'LINUX-API-01',    os: 'Linux',   status: 'online',  tags: ['Development', 'Linux'] },
  { id: 'a13', hostname: 'WIN-SEC-01',      os: 'Windows', status: 'warning', tags: ['Critical', 'Windows'] },
  { id: 'a14', hostname: 'LINUX-BACKUP-01', os: 'Linux',   status: 'online',  tags: [] },
  { id: 'a15', hostname: 'WIN-TEST-01',     os: 'Windows', status: 'offline', tags: [] },
]

// ── Helpers ────────────────────────────────────────────────────

function hex2bg(hex: string, alpha = 0.15) {
  const r = parseInt(hex.slice(1, 3), 16)
  const g = parseInt(hex.slice(3, 5), 16)
  const b = parseInt(hex.slice(5, 7), 16)
  return `rgba(${r},${g},${b},${alpha})`
}

function TagBadge({ name, color, count, selected, onClick }: {
  name: string; color: string; count?: number; selected?: boolean; onClick?: () => void
}) {
  return (
    <button
      onClick={onClick}
      className={`inline-flex items-center gap-1.5 px-2.5 py-1 rounded-full text-xs font-medium transition-all border
        ${selected ? 'ring-2 ring-offset-1 ring-offset-[#0d1220]' : 'hover:opacity-80'}`}
      style={{
        backgroundColor: hex2bg(color),
        color,
        borderColor: hex2bg(color, 0.4),
      }}
    >
      <span className="w-1.5 h-1.5 rounded-full shrink-0" style={{ backgroundColor: color }} />
      {name}
      {count !== undefined && (
        <span className="ml-0.5 px-1 py-0.5 rounded-full text-[10px] font-bold" style={{ backgroundColor: hex2bg(color, 0.3) }}>
          {count}
        </span>
      )}
    </button>
  )
}

const OS_COLORS: Record<string, string> = {
  Windows: 'bg-blue-500/10 text-blue-400 border-blue-500/30',
  Linux:   'bg-green-500/10 text-green-400 border-green-500/30',
  macOS:   'bg-purple-500/10 text-purple-400 border-purple-500/30',
}

const STATUS_DOTS: Record<string, string> = {
  online:  'bg-green-400',
  offline: 'bg-[#3d5068]',
  warning: 'bg-yellow-400',
}

function Modal({ title, onClose, children }: { title: string; onClose: () => void; children: React.ReactNode }) {
  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/70 backdrop-blur-sm p-4">
      <div className="bg-[#0d1220] border border-[#1e2d42] rounded-xl w-full max-w-md shadow-2xl">
        <div className="flex items-center justify-between px-5 py-4 border-b border-[#1e2d42]">
          <h3 className="text-sm font-semibold text-white">{title}</h3>
          <button onClick={onClose} className="text-[#7d92b0] hover:text-white transition-colors">
            <X className="w-4 h-4" />
          </button>
        </div>
        <div className="p-5">{children}</div>
      </div>
    </div>
  )
}

// ── Main Page ──────────────────────────────────────────────────

export default function EndpointTagsPage() {
  const qc = useQueryClient()
  const [activeTab, setActiveTab] = useState<'list' | 'wizard'>('list')
  const [selectedTag, setSelectedTag] = useState<EndpointTag | null>(null)
  const [showCreate, setShowCreate] = useState(false)
  const [deleteTag, setDeleteTag] = useState<EndpointTag | null>(null)
  const [newTagName, setNewTagName] = useState('')
  const [newTagColor, setNewTagColor] = useState(TAG_COLORS[0].value)

  // Wizard state
  const [wizStep, setWizStep] = useState(1)
  const [wizSelected, setWizSelected] = useState<string[]>([])
  const [wizSearch, setWizSearch] = useState('')
  const [wizOp, setWizOp] = useState<'add' | 'remove'>('add')
  const [wizTag, setWizTag] = useState<EndpointTag | null>(null)
  const [wizNewName, setWizNewName] = useState('')
  const [wizNewColor, setWizNewColor] = useState(TAG_COLORS[0].value)
  const [wizCreateNew, setWizCreateNew] = useState(false)
  const [wizResult, setWizResult] = useState<{ success: number; failure: number } | null>(null)

  // ── Queries ──────────────────────────────────────────────────

  const { data: tagsData } = useQuery<TagsResponse>({
    queryKey: ['endpoint-tags'],
    queryFn: () => apiFetch<TagsResponse>('/api/v1/endpoints/tags/all'),
  })
  const tags = tagsData?.tags ?? m(MOCK_TAGS)

  const { data: agentsData } = useQuery<AgentsResponse>({
    queryKey: ['agents-for-tags'],
    queryFn: async () => {
      try {
        const res = await apiFetch<{ data: { id: string; hostname: string; os_type: string; status: string; tags?: string[] }[] }>(
          '/api/v1/agents?per_page=1000'
        )
        const agents: Agent[] = (res.data ?? []).map(a => ({
          id: a.id,
          hostname: a.hostname,
          os: a.os_type,
          status: (a.status === 'online' ? 'online' : 'offline') as Agent['status'],
          tags: a.tags ?? [],
        }))
        return { agents, total: agents.length }
      } catch {
        return { agents: m(MOCK_AGENTS), total: m(MOCK_AGENTS).length }
      }
    },
  })
  const agents = agentsData?.agents ?? m(MOCK_AGENTS)

  // ── Stats ─────────────────────────────────────────────────────

  const stats = useMemo(() => {
    const tagged = agents.filter(a => a.tags.length > 0).length
    const untagged = agents.length - tagged
    const mostUsed = [...tags].sort((a, b) => b.endpoint_count - a.endpoint_count)[0]
    return { total: tags.length, tagged, untagged, mostUsed: mostUsed?.name ?? '—' }
  }, [tags, agents])

  // ── Filtered endpoints for selected tag ──────────────────────

  const taggedEndpoints = useMemo(() => {
    if (!selectedTag) return []
    return agents.filter(a => a.tags.includes(selectedTag.name))
  }, [selectedTag, agents])

  // ── Mutations ─────────────────────────────────────────────────

  const createTagMutation = useMutation({
    mutationFn: (body: { name: string; color: string }) =>
      apiFetch('/api/v1/endpoints/tags/all', { method: 'POST', body: JSON.stringify(body) }),
    onSuccess: () => { qc.invalidateQueries({ queryKey: ['endpoint-tags'] }); setShowCreate(false); setNewTagName('') },
    onError:   () => { qc.invalidateQueries({ queryKey: ['endpoint-tags'] }); setShowCreate(false); setNewTagName('') },
  })

  const deleteTagMutation = useMutation({
    mutationFn: (id: string) => apiFetch(`/api/v1/endpoints/tags/all/${id}`, { method: 'DELETE' }),
    onSuccess: () => { qc.invalidateQueries({ queryKey: ['endpoint-tags'] }); setDeleteTag(null); if (selectedTag?.id === deleteTag?.id) setSelectedTag(null) },
    onError:   () => { qc.invalidateQueries({ queryKey: ['endpoint-tags'] }); setDeleteTag(null) },
  })

  const removeTagFromEndpoint = useMutation({
    mutationFn: ({ agentId, tag }: { agentId: string; tag: string }) =>
      apiFetch(`/api/v1/endpoints/${agentId}/tags/${encodeURIComponent(tag)}`, { method: 'DELETE' }),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['agents-for-tags'] }),
    onError:   () => qc.invalidateQueries({ queryKey: ['agents-for-tags'] }),
  })

  const bulkMutation = useMutation({
    mutationFn: ({ op, agent_ids, tag }: { op: 'add' | 'remove'; agent_ids: string[]; tag: string }) =>
      apiFetch(`/api/v1/endpoints/tags/${op === 'add' ? 'bulk-add' : 'bulk-remove'}`, {
        method: 'POST',
        body: JSON.stringify({ agent_ids, tag }),
      }),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['endpoint-tags'] })
      qc.invalidateQueries({ queryKey: ['agents-for-tags'] })
      setWizResult({ success: wizSelected.length, failure: 0 })
    },
    onError: () => {
      setWizResult({ success: 0, failure: wizSelected.length })
    },
  })

  // ── Wizard helpers ────────────────────────────────────────────

  const filteredAgents = useMemo(() =>
    agents.filter(a => a.hostname.toLowerCase().includes(wizSearch.toLowerCase())),
    [agents, wizSearch])

  const toggleWizAgent = (id: string) =>
    setWizSelected(s => s.includes(id) ? s.filter(x => x !== id) : [...s, id])

  const selectAllFiltered = () => {
    const ids = filteredAgents.map(a => a.id)
    const allSelected = ids.every(id => wizSelected.includes(id))
    if (allSelected) setWizSelected(s => s.filter(id => !ids.includes(id)))
    else setWizSelected(s => [...new Set([...s, ...ids])])
  }

  const handleBulkExecute = () => {
    const tagName = wizCreateNew ? wizNewName : (wizTag?.name ?? '')
    if (!tagName) return
    bulkMutation.mutate({ op: wizOp, agent_ids: wizSelected, tag: tagName })
  }

  const resetWizard = () => {
    setWizStep(1)
    setWizSelected([])
    setWizSearch('')
    setWizOp('add')
    setWizTag(null)
    setWizNewName('')
    setWizCreateNew(false)
    setWizResult(null)
  }

  // ── Render ────────────────────────────────────────────────────

  return (
    <div className="min-h-screen bg-[#070d19] p-6">
      <PageDataUnavailable />

      {/* Header */}
      <div className="mb-6">
        <div className="flex items-center gap-3 mb-1">
          <div className="w-8 h-8 rounded-sm bg-[#e8002d]/10 border border-[#e8002d]/30 flex items-center justify-center">
            <Tag className="w-4 h-4 text-[#e8002d]" />
          </div>
          <h1 className="text-xl font-bold text-white">エンドポイントタグ</h1>
        </div>
        <p className="text-[#7d92b0] text-sm ml-11">タグによるエンドポイントの分類・フィルタリング</p>
      </div>

      {/* Stats */}
      <div className="grid grid-cols-2 sm:grid-cols-4 gap-4 mb-6">
        {[
          { label: '使用中タグ数',         value: stats.total,    color: 'text-white' },
          { label: 'タグ付きエンドポイント', value: stats.tagged,   color: 'text-green-400' },
          { label: '未タグ',               value: stats.untagged,  color: 'text-[#7d92b0]' },
          { label: '最多使用タグ',          value: stats.mostUsed,  color: 'text-[#e8002d]', isString: true },
        ].map(s => (
          <div key={s.label} className="bg-[#0d1220] border border-[#1e2d42] rounded-lg p-4">
            <p className="text-[#7d92b0] text-xs mb-1">{s.label}</p>
            <p className={`text-xl font-bold ${s.color} ${s.isString ? 'text-base' : ''}`}>{s.value}</p>
          </div>
        ))}
      </div>

      {/* Tabs */}
      <div className="flex gap-0.5 mb-6 bg-[#0d1220] border border-[#1e2d42] rounded-lg p-1 w-fit">
        {([['list', 'タグ一覧'], ['wizard', 'タグ付けウィザード']] as const).map(([key, label]) => (
          <button
            key={key}
            onClick={() => setActiveTab(key)}
            className={`px-4 py-2 rounded-sm text-sm font-medium transition-colors ${
              activeTab === key ? 'bg-[#1e2d42] text-white' : 'text-[#7d92b0] hover:text-white'
            }`}
          >
            {label}
          </button>
        ))}
      </div>

      {/* ── Tab: タグ一覧 ───────────────────────────────────────── */}

      {activeTab === 'list' && (
        <div className="flex gap-6">
          {/* Left: tag cloud */}
          <div className="w-72 shrink-0">
            <div className="bg-[#0d1220] border border-[#1e2d42] rounded-lg overflow-hidden">
              <div className="flex items-center justify-between px-4 py-3 border-b border-[#1e2d42]">
                <h2 className="text-sm font-semibold text-white">タグ一覧</h2>
                <button
                  onClick={() => setShowCreate(true)}
                  className="flex items-center gap-1 text-xs text-[#7d92b0] hover:text-white px-2 py-1 rounded-sm hover:bg-[#1e2d42] transition-colors"
                >
                  <Plus className="w-3.5 h-3.5" />
                  タグ作成
                </button>
              </div>

              {/* Tag cloud */}
              <div className="p-4 flex flex-wrap gap-2">
                {tags.map(tag => (
                  <div key={tag.id} className="flex items-center gap-1 group">
                    <TagBadge
                      name={tag.name}
                      color={tag.color}
                      count={tag.endpoint_count}
                      selected={selectedTag?.id === tag.id}
                      onClick={() => setSelectedTag(selectedTag?.id === tag.id ? null : tag)}
                    />
                    <button
                      onClick={() => setDeleteTag(tag)}
                      className="opacity-0 group-hover:opacity-100 transition-opacity p-0.5 rounded-sm hover:bg-[#1e2d42] text-[#7d92b0] hover:text-[#e8002d]"
                    >
                      <Trash2 className="w-3 h-3" />
                    </button>
                  </div>
                ))}
              </div>

              {/* Tag list */}
              <div className="border-t border-[#1e2d42]">
                {tags.map(tag => (
                  <button
                    key={tag.id}
                    onClick={() => setSelectedTag(selectedTag?.id === tag.id ? null : tag)}
                    className={`w-full flex items-center justify-between px-4 py-2.5 text-sm transition-colors ${
                      selectedTag?.id === tag.id ? 'bg-[#1e2d42]' : 'hover:bg-[#0a1628]'
                    }`}
                  >
                    <div className="flex items-center gap-2">
                      <span className="w-2 h-2 rounded-full shrink-0" style={{ backgroundColor: tag.color }} />
                      <span className="text-[#e2e8f4] font-medium">{tag.name}</span>
                    </div>
                    <div className="flex items-center gap-2">
                      <span className="text-xs text-[#7d92b0]">{tag.endpoint_count}台</span>
                      {selectedTag?.id === tag.id && <ChevronRight className="w-3.5 h-3.5 text-[#e8002d]" />}
                    </div>
                  </button>
                ))}
              </div>
            </div>
          </div>

          {/* Right: endpoint list */}
          <div className="flex-1 min-w-0">
            {selectedTag ? (
              <div className="bg-[#0d1220] border border-[#1e2d42] rounded-lg overflow-hidden">
                <div className="px-4 py-3 border-b border-[#1e2d42] flex items-center gap-2">
                  <span className="w-2 h-2 rounded-full" style={{ backgroundColor: selectedTag.color }} />
                  <h2 className="text-sm font-semibold text-white">{selectedTag.name} のエンドポイント</h2>
                  <span className="text-xs text-[#7d92b0]">({taggedEndpoints.length}台)</span>
                </div>

                {taggedEndpoints.length === 0 ? (
                  <div className="p-8 text-center text-[#7d92b0] text-sm">
                    このタグのエンドポイントはありません
                  </div>
                ) : (
                  <table className="w-full">
                    <thead>
                      <tr className="border-b border-[#1e2d42]">
                        {['ホスト名', 'OS', 'ステータス', '現在のタグ', 'アクション'].map(h => (
                          <th key={h} className="px-4 py-3 text-left text-xs font-medium text-[#7d92b0] uppercase tracking-wider">{h}</th>
                        ))}
                      </tr>
                    </thead>
                    <tbody className="divide-y divide-[#1e2d42]">
                      {taggedEndpoints.map(agent => (
                        <tr key={agent.id} className="hover:bg-[#0a1628] transition-colors">
                          <td className="px-4 py-3">
                            <div className="flex items-center gap-2">
                              <Monitor className="w-3.5 h-3.5 text-[#3d5068]" />
                              <span className="text-sm text-white font-medium">{agent.hostname}</span>
                            </div>
                          </td>
                          <td className="px-4 py-3">
                            <span className={`text-[11px] px-2 py-0.5 rounded-sm border font-medium ${OS_COLORS[agent.os] ?? 'bg-[#1e2d42] text-[#7d92b0] border-[#1e2d42]'}`}>
                              {agent.os}
                            </span>
                          </td>
                          <td className="px-4 py-3">
                            <div className="flex items-center gap-1.5">
                              <span className={`w-2 h-2 rounded-full ${STATUS_DOTS[agent.status]}`} />
                              <span className="text-xs text-[#7d92b0] capitalize">{agent.status}</span>
                            </div>
                          </td>
                          <td className="px-4 py-3">
                            <div className="flex flex-wrap gap-1">
                              {agent.tags.map(t => {
                                const tagObj = tags.find(tg => tg.name === t)
                                return tagObj ? (
                                  <TagBadge key={t} name={t} color={tagObj.color} />
                                ) : (
                                  <span key={t} className="text-[10px] px-2 py-0.5 rounded-full bg-[#1e2d42] text-[#7d92b0] border border-[#1e2d42]">{t}</span>
                                )
                              })}
                            </div>
                          </td>
                          <td className="px-4 py-3">
                            <button
                              onClick={() => removeTagFromEndpoint.mutate({ agentId: agent.id, tag: selectedTag.name })}
                              disabled={removeTagFromEndpoint.isPending}
                              className="flex items-center gap-1 text-xs text-[#7d92b0] hover:text-[#e8002d] transition-colors px-2 py-1 rounded-sm hover:bg-[#1e2d42] disabled:opacity-50"
                            >
                              <Trash2 className="w-3.5 h-3.5" />
                              タグ削除
                            </button>
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                )}
              </div>
            ) : (
              <div className="bg-[#0d1220] border border-[#1e2d42] rounded-lg p-12 flex flex-col items-center text-center">
                <Tag className="w-10 h-10 text-[#3d5068] mb-3" />
                <p className="text-[#7d92b0] text-sm">左のタグを選択してエンドポイントを表示</p>
              </div>
            )}
          </div>
        </div>
      )}

      {/* ── Tab: ウィザード ─────────────────────────────────────── */}

      {activeTab === 'wizard' && (
        <div className="bg-[#0d1220] border border-[#1e2d42] rounded-lg overflow-hidden">
          {/* Step indicator */}
          <div className="px-5 py-4 border-b border-[#1e2d42]">
            <div className="flex items-center gap-0 max-w-lg">
              {[
                { n: 1, label: 'エンドポイント選択' },
                { n: 2, label: 'タグ操作' },
                { n: 3, label: 'タグ選択' },
                { n: 4, label: '確認・実行' },
              ].map((step, i) => (
                <div key={step.n} className="flex items-center">
                  <div className={`flex items-center gap-2 px-3 py-1.5 rounded-sm ${
                    wizStep === step.n ? 'text-white' : wizStep > step.n ? 'text-green-400' : 'text-[#3d5068]'
                  }`}>
                    <div className={`w-6 h-6 rounded-full flex items-center justify-center text-xs font-bold border-2 ${
                      wizStep === step.n ? 'border-[#e8002d] bg-[#e8002d]/10 text-white' :
                      wizStep > step.n  ? 'border-green-500 bg-green-500/10 text-green-400' :
                      'border-[#1e2d42] text-[#3d5068]'
                    }`}>
                      {wizStep > step.n ? <Check className="w-3 h-3" /> : step.n}
                    </div>
                    <span className="text-xs font-medium hidden sm:block">{step.label}</span>
                  </div>
                  {i < 3 && <div className="w-6 h-px bg-[#1e2d42] mx-1" />}
                </div>
              ))}
            </div>
          </div>

          <div className="p-5">

            {/* Result */}
            {wizResult && (
              <div className="space-y-4">
                <div className={`p-4 rounded-lg border flex items-start gap-3 ${
                  wizResult.failure === 0 ? 'bg-green-500/5 border-green-500/20' : 'bg-yellow-500/5 border-yellow-500/20'
                }`}>
                  {wizResult.failure === 0
                    ? <Check className="w-5 h-5 text-green-400 shrink-0" />
                    : <AlertTriangle className="w-5 h-5 text-yellow-400 shrink-0" />}
                  <div>
                    <p className={`font-semibold text-sm ${wizResult.failure === 0 ? 'text-green-400' : 'text-yellow-400'}`}>
                      操作完了
                    </p>
                    <p className="text-xs text-[#7d92b0] mt-0.5">
                      成功: {wizResult.success}台 / 失敗: {wizResult.failure}台
                    </p>
                  </div>
                </div>
                <button onClick={resetWizard} className="px-4 py-2 bg-[#e8002d] hover:bg-[#c8001f] text-white text-sm rounded-sm transition-colors">
                  新しい操作を開始
                </button>
              </div>
            )}

            {!wizResult && (
              <>
                {/* Step 1: Select endpoints */}
                {wizStep === 1 && (
                  <div className="space-y-4">
                    <div className="flex items-center justify-between">
                      <h3 className="text-sm font-semibold text-white">エンドポイント選択</h3>
                      {wizSelected.length > 0 && (
                        <span className="text-xs px-2 py-0.5 rounded-full bg-[#e8002d]/10 text-[#e8002d] border border-[#e8002d]/20">
                          {wizSelected.length}台選択中
                        </span>
                      )}
                    </div>

                    <div className="relative">
                      <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-[#3d5068]" />
                      <input
                        value={wizSearch}
                        onChange={e => setWizSearch(e.target.value)}
                        placeholder="ホスト名で検索..."
                        className="w-full bg-[#070d19] border border-[#1e2d42] rounded-sm pl-9 pr-3 py-2 text-sm text-white placeholder-[#3d5068] focus:outline-hidden focus:border-[#e8002d]/50"
                      />
                    </div>

                    <div className="border border-[#1e2d42] rounded-lg overflow-hidden max-h-72 overflow-y-auto">
                      <div
                        onClick={selectAllFiltered}
                        className="px-4 py-2.5 flex items-center gap-3 border-b border-[#1e2d42] bg-[#070d19] cursor-pointer hover:bg-[#0a1628] transition-colors"
                      >
                        {filteredAgents.length > 0 && filteredAgents.every(a => wizSelected.includes(a.id))
                          ? <CheckSquare className="w-4 h-4 text-[#e8002d]" />
                          : <Square className="w-4 h-4 text-[#3d5068]" />}
                        <span className="text-xs text-[#7d92b0]">すべて選択 ({filteredAgents.length}台)</span>
                      </div>
                      {filteredAgents.map(agent => (
                        <div
                          key={agent.id}
                          onClick={() => toggleWizAgent(agent.id)}
                          className={`px-4 py-2.5 flex items-center gap-3 cursor-pointer transition-colors hover:bg-[#0a1628] ${
                            wizSelected.includes(agent.id) ? 'bg-[#1e2d42]/40' : ''
                          }`}
                        >
                          {wizSelected.includes(agent.id)
                            ? <CheckSquare className="w-4 h-4 text-[#e8002d] shrink-0" />
                            : <Square className="w-4 h-4 text-[#3d5068] shrink-0" />}
                          <Monitor className="w-3.5 h-3.5 text-[#3d5068] shrink-0" />
                          <span className="text-sm text-white font-medium flex-1">{agent.hostname}</span>
                          <div className="flex items-center gap-1.5">
                            <span className={`w-1.5 h-1.5 rounded-full ${STATUS_DOTS[agent.status]}`} />
                            <span className={`text-[10px] px-1.5 py-0.5 rounded-sm border font-medium ${OS_COLORS[agent.os] ?? ''}`}>{agent.os}</span>
                          </div>
                        </div>
                      ))}
                    </div>

                    <div className="flex justify-end">
                      <button
                        onClick={() => setWizStep(2)}
                        disabled={wizSelected.length === 0}
                        className="px-4 py-2 bg-[#e8002d] hover:bg-[#c8001f] text-white text-sm rounded-sm transition-colors disabled:opacity-50"
                      >
                        次へ
                      </button>
                    </div>
                  </div>
                )}

                {/* Step 2: Operation */}
                {wizStep === 2 && (
                  <div className="space-y-4">
                    <h3 className="text-sm font-semibold text-white">タグ操作選択</h3>
                    <p className="text-xs text-[#7d92b0]">{wizSelected.length}台のエンドポイントに対して操作を選択してください</p>
                    <div className="flex flex-col gap-3">
                      {(['add', 'remove'] as const).map(op => (
                        <label key={op} className={`flex items-center gap-3 p-4 rounded-lg border cursor-pointer transition-colors ${
                          wizOp === op ? 'border-[#e8002d]/50 bg-[#e8002d]/5' : 'border-[#1e2d42] hover:border-[#7d92b0]/30'
                        }`}>
                          <input
                            type="radio"
                            name="wizOp"
                            value={op}
                            checked={wizOp === op}
                            onChange={() => setWizOp(op)}
                            className="accent-[#e8002d]"
                          />
                          <div>
                            <p className="text-sm font-medium text-white">{op === 'add' ? 'タグを追加' : 'タグを削除'}</p>
                            <p className="text-xs text-[#7d92b0]">
                              {op === 'add' ? '選択したエンドポイントにタグを追加します' : '選択したエンドポイントからタグを削除します'}
                            </p>
                          </div>
                        </label>
                      ))}
                    </div>
                    <div className="flex gap-2 justify-end">
                      <button onClick={() => setWizStep(1)} className="px-4 py-2 text-xs text-[#7d92b0] hover:text-white border border-[#1e2d42] rounded-sm hover:border-[#7d92b0]/40 transition-colors">戻る</button>
                      <button onClick={() => setWizStep(3)} className="px-4 py-2 bg-[#e8002d] hover:bg-[#c8001f] text-white text-sm rounded-sm transition-colors">次へ</button>
                    </div>
                  </div>
                )}

                {/* Step 3: Select tag */}
                {wizStep === 3 && (
                  <div className="space-y-4">
                    <h3 className="text-sm font-semibold text-white">タグ選択</h3>
                    <p className="text-xs text-[#7d92b0]">既存のタグを選択するか、新しいタグを作成してください</p>

                    <div className="flex flex-wrap gap-2">
                      {tags.map(tag => (
                        <button
                          key={tag.id}
                          onClick={() => { setWizTag(tag); setWizCreateNew(false) }}
                          className="transition-all"
                        >
                          <TagBadge
                            name={tag.name}
                            color={tag.color}
                            count={tag.endpoint_count}
                            selected={wizTag?.id === tag.id && !wizCreateNew}
                          />
                        </button>
                      ))}
                    </div>

                    <button
                      onClick={() => { setWizCreateNew(true); setWizTag(null) }}
                      className={`flex items-center gap-2 text-xs px-3 py-2 rounded-sm border transition-colors ${
                        wizCreateNew ? 'border-[#e8002d]/50 bg-[#e8002d]/5 text-white' : 'border-[#1e2d42] text-[#7d92b0] hover:text-white hover:border-[#7d92b0]/40'
                      }`}
                    >
                      <Plus className="w-3.5 h-3.5" />
                      新しいタグを作成
                    </button>

                    {wizCreateNew && (
                      <div className="pl-4 space-y-3 border-l-2 border-[#e8002d]/30">
                        <input
                          value={wizNewName}
                          onChange={e => setWizNewName(e.target.value)}
                          placeholder="タグ名"
                          className="w-full bg-[#070d19] border border-[#1e2d42] rounded-sm px-3 py-2 text-sm text-white placeholder-[#3d5068] focus:outline-hidden focus:border-[#e8002d]/50"
                        />
                        <div className="flex flex-wrap gap-2">
                          {TAG_COLORS.map(c => (
                            <button
                              key={c.value}
                              onClick={() => setWizNewColor(c.value)}
                              title={c.label}
                              className={`w-7 h-7 rounded-full border-2 transition-all ${wizNewColor === c.value ? 'border-white scale-110' : 'border-transparent'}`}
                              style={{ backgroundColor: c.value }}
                            />
                          ))}
                        </div>
                      </div>
                    )}

                    <div className="flex gap-2 justify-end">
                      <button onClick={() => setWizStep(2)} className="px-4 py-2 text-xs text-[#7d92b0] hover:text-white border border-[#1e2d42] rounded-sm hover:border-[#7d92b0]/40 transition-colors">戻る</button>
                      <button
                        onClick={() => setWizStep(4)}
                        disabled={!wizTag && (!wizCreateNew || !wizNewName)}
                        className="px-4 py-2 bg-[#e8002d] hover:bg-[#c8001f] text-white text-sm rounded-sm transition-colors disabled:opacity-50"
                      >
                        次へ
                      </button>
                    </div>
                  </div>
                )}

                {/* Step 4: Confirm */}
                {wizStep === 4 && (
                  <div className="space-y-4">
                    <h3 className="text-sm font-semibold text-white">確認・実行</h3>
                    <div className="bg-[#070d19] border border-[#1e2d42] rounded-lg p-4 space-y-3">
                      <div className="flex items-center gap-2">
                        <span className="text-xs text-[#7d92b0]">操作:</span>
                        <span className={`text-sm font-medium ${wizOp === 'add' ? 'text-green-400' : 'text-[#e8002d]'}`}>
                          {wizOp === 'add' ? 'タグを追加' : 'タグを削除'}
                        </span>
                      </div>
                      <div className="flex items-center gap-2">
                        <span className="text-xs text-[#7d92b0]">タグ:</span>
                        {(wizTag || wizCreateNew) && (
                          <TagBadge
                            name={wizCreateNew ? wizNewName : wizTag!.name}
                            color={wizCreateNew ? wizNewColor : wizTag!.color}
                          />
                        )}
                      </div>
                      <div>
                        <span className="text-xs text-[#7d92b0]">
                          {wizSelected.length}台のエンドポイントにタグ「{wizCreateNew ? wizNewName : wizTag?.name}」を{wizOp === 'add' ? '追加' : '削除'}します
                        </span>
                      </div>
                      <div className="border-t border-[#1e2d42] pt-3">
                        <div className="flex flex-wrap gap-1 max-h-24 overflow-y-auto">
                          {wizSelected.map(id => {
                            const a = agents.find(ag => ag.id === id)
                            return a ? (
                              <span key={id} className="text-[11px] px-2 py-0.5 rounded-sm bg-[#1e2d42] text-[#7d92b0] border border-[#1e2d42]">{a.hostname}</span>
                            ) : null
                          })}
                        </div>
                      </div>
                    </div>
                    <div className="flex gap-2 justify-end">
                      <button onClick={() => setWizStep(3)} className="px-4 py-2 text-xs text-[#7d92b0] hover:text-white border border-[#1e2d42] rounded-sm hover:border-[#7d92b0]/40 transition-colors">戻る</button>
                      <button
                        onClick={handleBulkExecute}
                        disabled={bulkMutation.isPending}
                        className="px-5 py-2 bg-[#e8002d] hover:bg-[#c8001f] text-white text-sm font-medium rounded-sm transition-colors disabled:opacity-50"
                      >
                        {bulkMutation.isPending ? '実行中...' : '実行'}
                      </button>
                    </div>
                  </div>
                )}
              </>
            )}
          </div>
        </div>
      )}

      {/* ── Modals ─────────────────────────────────────────────── */}

      {/* Create tag */}
      {showCreate && (
        <Modal title="タグ作成" onClose={() => setShowCreate(false)}>
          <div className="space-y-4">
            <div>
              <label className="block text-xs text-[#7d92b0] mb-1">タグ名 <span className="text-[#e8002d]">*</span></label>
              <input
                value={newTagName}
                onChange={e => setNewTagName(e.target.value)}
                placeholder="Production"
                className="w-full bg-[#070d19] border border-[#1e2d42] rounded-sm px-3 py-2 text-sm text-white placeholder-[#3d5068] focus:outline-hidden focus:border-[#e8002d]/50"
              />
            </div>
            <div>
              <label className="block text-xs text-[#7d92b0] mb-2">カラー</label>
              <div className="flex flex-wrap gap-2">
                {TAG_COLORS.map(c => (
                  <button
                    key={c.value}
                    onClick={() => setNewTagColor(c.value)}
                    title={c.label}
                    className={`w-8 h-8 rounded-full border-2 transition-all ${newTagColor === c.value ? 'border-white scale-110' : 'border-transparent hover:border-[#7d92b0]/40'}`}
                    style={{ backgroundColor: c.value }}
                  />
                ))}
              </div>
              <div className="mt-3">
                <TagBadge name={newTagName || 'プレビュー'} color={newTagColor} />
              </div>
            </div>
            <div className="flex gap-2 justify-end pt-2">
              <button onClick={() => setShowCreate(false)} className="px-4 py-2 text-xs text-[#7d92b0] hover:text-white border border-[#1e2d42] rounded-sm hover:border-[#7d92b0]/40 transition-colors">
                キャンセル
              </button>
              <button
                onClick={() => createTagMutation.mutate({ name: newTagName, color: newTagColor })}
                disabled={!newTagName || createTagMutation.isPending}
                className="px-4 py-2 text-xs text-white bg-[#e8002d] hover:bg-[#c8001f] rounded-sm transition-colors disabled:opacity-50"
              >
                {createTagMutation.isPending ? '作成中...' : '作成'}
              </button>
            </div>
          </div>
        </Modal>
      )}

      {/* Delete tag */}
      {deleteTag && (
        <Modal title="タグ削除" onClose={() => setDeleteTag(null)}>
          <div className="space-y-4">
            <div className="flex items-start gap-3 p-3 rounded-lg bg-[#e8002d]/5 border border-[#e8002d]/20">
              <AlertTriangle className="w-5 h-5 text-[#e8002d] shrink-0 mt-0.5" />
              <p className="text-sm text-[#e2e8f4]">
                このタグを <span className="font-semibold text-white">{deleteTag.endpoint_count}台</span> のエンドポイントから削除します。この操作は元に戻せません。
              </p>
            </div>
            <div className="flex gap-2 justify-end">
              <button onClick={() => setDeleteTag(null)} className="px-4 py-2 text-xs text-[#7d92b0] hover:text-white border border-[#1e2d42] rounded-sm hover:border-[#7d92b0]/40 transition-colors">
                キャンセル
              </button>
              <button
                onClick={() => deleteTagMutation.mutate(deleteTag.id)}
                disabled={deleteTagMutation.isPending}
                className="px-4 py-2 text-xs text-white bg-[#e8002d] hover:bg-[#c8001f] rounded-sm transition-colors disabled:opacity-50"
              >
                {deleteTagMutation.isPending ? '削除中...' : '削除'}
              </button>
            </div>
          </div>
        </Modal>
      )}
    </div>
  )
}

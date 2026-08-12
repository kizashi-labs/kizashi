'use client'

import { useState, useEffect, useCallback } from 'react'
import {
  UserPlus, UserMinus, Search, CheckSquare, Square,
  Loader2, CheckCircle2, AlertTriangle, X, Users,
} from 'lucide-react'
import { apiFetch } from '@/lib/api'

// ── Types ─────────────────────────────────────────────────────────────────────

interface AgentItem {
  id: string
  hostname: string
  ip_address?: string
  ip_addresses?: string[]
  status?: string
}

type Tab = 'add' | 'remove'

// ── Helpers ───────────────────────────────────────────────────────────────────

function agentIp(agent: AgentItem): string {
  if (agent.ip_address) return agent.ip_address
  if (agent.ip_addresses?.length) return agent.ip_addresses[0]
  return '—'
}

// ── Sub-component: Result banner ──────────────────────────────────────────────

interface ResultBannerProps {
  type: 'success' | 'error'
  message: string
  onDismiss: () => void
}

function ResultBanner({ type, message, onDismiss }: ResultBannerProps) {
  useEffect(() => {
    const t = setTimeout(onDismiss, 5000)
    return () => clearTimeout(t)
  }, [message, onDismiss])

  const isSuccess = type === 'success'
  return (
    <div
      className={`flex items-center gap-2 px-4 py-2.5 rounded-lg text-sm
                  ${isSuccess
                    ? 'bg-green-900/40 border border-green-700/50 text-green-300'
                    : 'bg-red-900/40 border border-red-700/50 text-red-300'}`}
    >
      {isSuccess
        ? <CheckCircle2 className="w-4 h-4 flex-shrink-0" />
        : <AlertTriangle className="w-4 h-4 flex-shrink-0" />}
      <span className="flex-1">{message}</span>
      <button
        onClick={onDismiss}
        className="opacity-60 hover:opacity-100 transition-opacity"
        aria-label="閉じる"
      >
        <X className="w-4 h-4" />
      </button>
    </div>
  )
}

// ── Sub-component: Agent checkbox list ────────────────────────────────────────

interface AgentListProps {
  agents: AgentItem[]
  selected: Set<string>
  onToggle: (id: string) => void
  onToggleAll: () => void
  loading: boolean
  emptyMessage: string
}

function AgentCheckboxList({
  agents,
  selected,
  onToggle,
  onToggleAll,
  loading,
  emptyMessage,
}: AgentListProps) {
  const allSelected = agents.length > 0 && agents.every((a) => selected.has(a.id))

  if (loading) {
    return (
      <div className="flex items-center justify-center py-8 text-[#5a6a7a] gap-2">
        <Loader2 className="w-4 h-4 animate-spin" />
        読み込み中...
      </div>
    )
  }

  if (agents.length === 0) {
    return (
      <div className="flex flex-col items-center justify-center py-10 text-[#5a6a7a] gap-2">
        <Users className="w-8 h-8 opacity-40" />
        <p className="text-sm">{emptyMessage}</p>
      </div>
    )
  }

  return (
    <div className="rounded-lg border border-[#1e2d42] overflow-hidden">
      {/* Select-all header */}
      <div
        className="flex items-center gap-3 px-4 py-2.5 bg-[#0d1628] border-b border-[#1e2d42]
                   cursor-pointer hover:bg-[#111c2e] transition-colors select-none"
        onClick={onToggleAll}
      >
        <span className={`flex-shrink-0 ${allSelected ? 'text-[#1a6bff]' : 'text-[#3d5068]'}`}>
          {allSelected
            ? <CheckSquare className="w-4 h-4" />
            : <Square className="w-4 h-4" />}
        </span>
        <span className="text-xs text-[#8899aa] font-medium">
          全選択 ({agents.length}件)
        </span>
        {selected.size > 0 && (
          <span className="ml-auto text-xs text-[#1a6bff] font-semibold">
            {selected.size}件選択中
          </span>
        )}
      </div>

      {/* Agent rows */}
      <div className="max-h-64 overflow-y-auto">
        {agents.map((agent) => {
          const checked = selected.has(agent.id)
          return (
            <div
              key={agent.id}
              onClick={() => onToggle(agent.id)}
              className={`flex items-center gap-3 px-4 py-2.5 cursor-pointer transition-colors select-none
                          border-b border-[#1e2d42]/50 last:border-b-0
                          ${checked ? 'bg-[#1a6bff]/10' : 'hover:bg-[#161f33]'}`}
            >
              <span className={`flex-shrink-0 ${checked ? 'text-[#1a6bff]' : 'text-[#3d5068]'}`}>
                {checked
                  ? <CheckSquare className="w-4 h-4" />
                  : <Square className="w-4 h-4" />}
              </span>
              <div className="flex-1 min-w-0">
                <p className="text-sm text-white font-medium truncate">{agent.hostname}</p>
                <p className="text-xs text-[#5a6a7a]">{agentIp(agent)}</p>
              </div>
              {agent.status && (
                <span
                  className={`text-xs px-2 py-0.5 rounded-full flex-shrink-0
                              ${agent.status === 'online'
                                ? 'bg-green-900/40 text-green-400'
                                : 'bg-[#161f33] text-[#5a6a7a]'}`}
                >
                  {agent.status}
                </span>
              )}
            </div>
          )
        })}
      </div>
    </div>
  )
}

// ── Props ─────────────────────────────────────────────────────────────────────

export interface GroupBulkOperationsProps {
  groupId: string
  groupName: string
}

// ── GroupBulkOperations ───────────────────────────────────────────────────────

export default function GroupBulkOperations({ groupId, groupName }: GroupBulkOperationsProps) {
  const [activeTab, setActiveTab] = useState<Tab>('add')

  // Add-tab state
  const [allAgents, setAllAgents] = useState<AgentItem[]>([])
  const [groupAgentIds, setGroupAgentIds] = useState<Set<string>>(new Set())
  const [addSearch, setAddSearch] = useState('')
  const [addSelected, setAddSelected] = useState<Set<string>>(new Set())
  const [loadingAll, setLoadingAll] = useState(false)

  // Remove-tab state
  const [groupAgents, setGroupAgents] = useState<AgentItem[]>([])
  const [removeSearch, setRemoveSearch] = useState('')
  const [removeSelected, setRemoveSelected] = useState<Set<string>>(new Set())
  const [loadingGroup, setLoadingGroup] = useState(false)

  // Shared
  const [submitting, setSubmitting] = useState(false)
  const [result, setResult] = useState<{ type: 'success' | 'error'; message: string } | null>(null)

  // ── Data fetching ──────────────────────────────────────────────────────────

  const fetchAllAgents = useCallback(async () => {
    setLoadingAll(true)
    try {
      const res = await apiFetch<{ data?: AgentItem[]; agents?: AgentItem[] }>(
        '/api/v1/agents?limit=100',
      )
      setAllAgents(res.data ?? res.agents ?? [])
    } catch {
      setAllAgents([])
    } finally {
      setLoadingAll(false)
    }
  }, [])

  const fetchGroupAgents = useCallback(async () => {
    setLoadingGroup(true)
    try {
      const res = await apiFetch<{ data?: AgentItem[]; agents?: AgentItem[] }>(
        `/api/v1/groups/${groupId}/agents`,
      )
      const list = res.data ?? res.agents ?? []
      setGroupAgents(list)
      setGroupAgentIds(new Set(list.map((a) => a.id)))
    } catch {
      setGroupAgents([])
      setGroupAgentIds(new Set())
    } finally {
      setLoadingGroup(false)
    }
  }, [groupId])

  useEffect(() => {
    fetchAllAgents()
    fetchGroupAgents()
  }, [fetchAllAgents, fetchGroupAgents])

  // ── Derived lists ──────────────────────────────────────────────────────────

  const availableToAdd = allAgents
    .filter((a) => !groupAgentIds.has(a.id))
    .filter(
      (a) =>
        addSearch === '' ||
        a.hostname.toLowerCase().includes(addSearch.toLowerCase()) ||
        agentIp(a).includes(addSearch),
    )

  const availableToRemove = groupAgents.filter(
    (a) =>
      removeSearch === '' ||
      a.hostname.toLowerCase().includes(removeSearch.toLowerCase()) ||
      agentIp(a).includes(removeSearch),
  )

  // ── Selection helpers ──────────────────────────────────────────────────────

  function toggleAdd(id: string) {
    setAddSelected((prev) => {
      const next = new Set(prev)
      next.has(id) ? next.delete(id) : next.add(id)
      return next
    })
  }

  function toggleAllAdd() {
    const ids = availableToAdd.map((a) => a.id)
    const allSel = ids.every((id) => addSelected.has(id))
    if (allSel) {
      setAddSelected(new Set())
    } else {
      setAddSelected(new Set(ids))
    }
  }

  function toggleRemove(id: string) {
    setRemoveSelected((prev) => {
      const next = new Set(prev)
      next.has(id) ? next.delete(id) : next.add(id)
      return next
    })
  }

  function toggleAllRemove() {
    const ids = availableToRemove.map((a) => a.id)
    const allSel = ids.every((id) => removeSelected.has(id))
    if (allSel) {
      setRemoveSelected(new Set())
    } else {
      setRemoveSelected(new Set(ids))
    }
  }

  // ── Submit handlers ────────────────────────────────────────────────────────

  async function handleAdd() {
    if (addSelected.size === 0) return
    setSubmitting(true)
    setResult(null)
    try {
      await apiFetch(`/api/v1/groups/${groupId}/agents`, {
        method: 'POST',
        body: JSON.stringify({ agent_ids: Array.from(addSelected) }),
      })
      const count = addSelected.size
      setAddSelected(new Set())
      await Promise.all([fetchAllAgents(), fetchGroupAgents()])
      setResult({ type: 'success', message: `${count}件のエージェントをグループに追加しました` })
    } catch (err) {
      setResult({ type: 'error', message: (err as Error).message ?? '追加に失敗しました' })
    } finally {
      setSubmitting(false)
    }
  }

  async function handleRemove() {
    if (removeSelected.size === 0) return
    setSubmitting(true)
    setResult(null)
    try {
      await apiFetch(`/api/v1/groups/${groupId}/agents`, {
        method: 'DELETE',
        body: JSON.stringify({ agent_ids: Array.from(removeSelected) }),
      })
      const count = removeSelected.size
      setRemoveSelected(new Set())
      await Promise.all([fetchAllAgents(), fetchGroupAgents()])
      setResult({ type: 'success', message: `${count}件のエージェントをグループから削除しました` })
    } catch (err) {
      setResult({ type: 'error', message: (err as Error).message ?? '削除に失敗しました' })
    } finally {
      setSubmitting(false)
    }
  }

  // ── Render ─────────────────────────────────────────────────────────────────

  return (
    <div className="bg-gray-800 rounded-xl border border-[#1e2d42] overflow-hidden">
      {/* Card header */}
      <div className="px-5 py-4 border-b border-[#1e2d42]">
        <h2 className="text-base font-semibold text-white flex items-center gap-2">
          <Users className="w-4 h-4 text-[#8899aa]" />
          {groupName} — エージェント管理
        </h2>
        <p className="text-xs text-[#5a6a7a] mt-0.5">
          現在 {groupAgentIds.size} 件のエージェントが所属しています
        </p>
      </div>

      {/* Tabs */}
      <div className="flex border-b border-[#1e2d42]">
        <button
          onClick={() => { setActiveTab('add'); setResult(null) }}
          className={`flex items-center gap-2 px-5 py-3 text-sm font-medium transition-colors
                      ${activeTab === 'add'
                        ? 'text-white border-b-2 border-[#1a6bff] bg-[#1a6bff]/5'
                        : 'text-[#8899aa] hover:text-white hover:bg-[#161f33]'}`}
        >
          <UserPlus className="w-4 h-4" />
          エージェントを追加
        </button>
        <button
          onClick={() => { setActiveTab('remove'); setResult(null) }}
          className={`flex items-center gap-2 px-5 py-3 text-sm font-medium transition-colors
                      ${activeTab === 'remove'
                        ? 'text-white border-b-2 border-red-500 bg-red-500/5'
                        : 'text-[#8899aa] hover:text-white hover:bg-[#161f33]'}`}
        >
          <UserMinus className="w-4 h-4" />
          エージェントを削除
        </button>
      </div>

      {/* Tab body */}
      <div className="p-5 space-y-4">
        {/* Result banner */}
        {result && (
          <ResultBanner
            type={result.type}
            message={result.message}
            onDismiss={() => setResult(null)}
          />
        )}

        {activeTab === 'add' ? (
          <>
            {/* Search */}
            <div className="relative">
              <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-[#5a6a7a]" />
              <input
                type="text"
                placeholder="ホスト名またはIPで検索..."
                value={addSearch}
                onChange={(e) => setAddSearch(e.target.value)}
                className="w-full bg-[#111827] text-white text-sm pl-9 pr-4 py-2 rounded-lg
                           border border-[#1e2d42] focus:outline-none focus:border-[#1a6bff]"
              />
            </div>

            {/* Agent list */}
            <AgentCheckboxList
              agents={availableToAdd}
              selected={addSelected}
              onToggle={toggleAdd}
              onToggleAll={toggleAllAdd}
              loading={loadingAll}
              emptyMessage="追加可能なエージェントがありません"
            />

            {/* Submit */}
            <button
              onClick={handleAdd}
              disabled={addSelected.size === 0 || submitting}
              className="w-full flex items-center justify-center gap-2 py-2.5 rounded-lg text-sm font-medium
                         bg-[#1a6bff] text-white hover:bg-[#1557d4] transition-colors
                         disabled:opacity-50 disabled:cursor-not-allowed"
            >
              {submitting ? (
                <>
                  <Loader2 className="w-4 h-4 animate-spin" />
                  処理中...
                </>
              ) : (
                <>
                  <UserPlus className="w-4 h-4" />
                  選択したエージェントを追加
                  {addSelected.size > 0 && (
                    <span className="bg-white/20 rounded-full px-1.5 text-xs">
                      {addSelected.size}
                    </span>
                  )}
                </>
              )}
            </button>
          </>
        ) : (
          <>
            {/* Search */}
            <div className="relative">
              <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-[#5a6a7a]" />
              <input
                type="text"
                placeholder="ホスト名またはIPで検索..."
                value={removeSearch}
                onChange={(e) => setRemoveSearch(e.target.value)}
                className="w-full bg-[#111827] text-white text-sm pl-9 pr-4 py-2 rounded-lg
                           border border-[#1e2d42] focus:outline-none focus:border-red-500/60"
              />
            </div>

            {/* Agent list */}
            <AgentCheckboxList
              agents={availableToRemove}
              selected={removeSelected}
              onToggle={toggleRemove}
              onToggleAll={toggleAllRemove}
              loading={loadingGroup}
              emptyMessage="グループにエージェントが所属していません"
            />

            {/* Submit */}
            <button
              onClick={handleRemove}
              disabled={removeSelected.size === 0 || submitting}
              className="w-full flex items-center justify-center gap-2 py-2.5 rounded-lg text-sm font-medium
                         bg-red-600/90 text-white hover:bg-red-600 transition-colors
                         disabled:opacity-50 disabled:cursor-not-allowed"
            >
              {submitting ? (
                <>
                  <Loader2 className="w-4 h-4 animate-spin" />
                  処理中...
                </>
              ) : (
                <>
                  <UserMinus className="w-4 h-4" />
                  選択したエージェントを削除
                  {removeSelected.size > 0 && (
                    <span className="bg-white/20 rounded-full px-1.5 text-xs">
                      {removeSelected.size}
                    </span>
                  )}
                </>
              )}
            </button>
          </>
        )}
      </div>
    </div>
  )
}

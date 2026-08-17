'use client'

import { useState, useMemo } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { apiFetch } from '@/lib/api'
import { Tag, ChevronDown, ChevronRight, Plus, ExternalLink, Users } from 'lucide-react'

interface TagsResponse {
  tags: string[]
}

interface AgentTagsResponse {
  agent_ids: string[]
}

interface Agent {
  id: string
  hostname: string
  os_type: string
  status: string
}

interface AgentsResponse {
  data: Agent[]
}

export default function AgentTagsPage() {
  const queryClient = useQueryClient()
  const [expandedTag, setExpandedTag] = useState<string | null>(null)
  const [quickAgent, setQuickAgent] = useState('')
  const [quickTag, setQuickTag] = useState('')
  const [inlineAgent, setInlineAgent] = useState('')
  const [successMsg, setSuccessMsg] = useState('')
  const [errorMsg, setErrorMsg] = useState('')

  const { data: tagsData, isLoading } = useQuery<TagsResponse>({
    queryKey: ['agent-tags'],
    queryFn: () => apiFetch('/api/v1/agent-tags'),
  })

  const { data: agentsData } = useQuery<AgentsResponse>({
    queryKey: ['agents-for-tags'],
    queryFn: () => apiFetch('/api/v1/agents?per_page=500'),
  })

  const agents = agentsData?.data ?? []
  const agentMap = useMemo(() => {
    const m = new Map<string, string>()
    for (const a of agents) m.set(a.id, a.hostname)
    return m
  }, [agents])

  const tags = tagsData?.tags ?? []

  const { data: agentData } = useQuery<AgentTagsResponse>({
    queryKey: ['agent-tags-agents', expandedTag],
    queryFn: () => apiFetch(`/api/v1/agent-tags/${encodeURIComponent(expandedTag!)}/agents`),
    enabled: !!expandedTag,
  })

  const addTagMutation = useMutation({
    mutationFn: ({ agentId, tag }: { agentId: string; tag: string }) =>
      apiFetch(`/api/v1/agents/${agentId}/tags`, {
        method: 'POST',
        body: JSON.stringify({ tag }),
      }),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['agent-tags'] })
      setQuickAgent('')
      setQuickTag('')
      setInlineAgent('')
      setSuccessMsg('タグを追加しました')
      setErrorMsg('')
      setTimeout(() => setSuccessMsg(''), 3000)
    },
    onError: () => {
      setErrorMsg('タグの追加に失敗しました')
      setSuccessMsg('')
    },
  })

  const handleAddTag = (agentId: string, tag: string) => {
    if (!agentId.trim() || !tag.trim()) {
      setErrorMsg('エージェントとタグを選択・入力してください')
      return
    }
    addTagMutation.mutate({ agentId: agentId.trim(), tag: tag.trim() })
  }

  const AgentSelect = ({
    value, onChange, className
  }: { value: string; onChange: (v: string) => void; className?: string }) => (
    <div className="relative">
      <select
        value={value}
        onChange={e => onChange(e.target.value)}
        className={`appearance-none bg-[#070d19] border border-falcon-border rounded-sm px-3 py-2 text-sm text-white focus:outline-hidden focus:border-falcon-red/50 pr-8 ${className ?? ''}`}
      >
        <option value="">エージェントを選択...</option>
        {agents.map(a => (
          <option key={a.id} value={a.id}>
            {a.hostname} ({a.os_type})
          </option>
        ))}
      </select>
      <ChevronDown className="absolute right-2 top-1/2 -translate-y-1/2 w-4 h-4 text-falcon-subtle pointer-events-none" />
    </div>
  )

  return (
    <div className="min-h-screen bg-[#070d19] p-6">
      {/* Header */}
      <div className="mb-6">
        <div className="flex items-center gap-3 mb-1">
          <div className="w-8 h-8 rounded-sm bg-falcon-red/10 border border-falcon-red/30 flex items-center justify-center">
            <Tag className="w-4 h-4 text-falcon-red" />
          </div>
          <h1 className="text-xl font-bold text-white">エージェントタグ管理</h1>
        </div>
        <p className="text-falcon-muted text-sm ml-11">エージェントへのタグ付けと管理</p>
      </div>

      {/* Stats */}
      <div className="grid grid-cols-2 gap-4 mb-6 max-w-sm">
        <div className="bg-falcon-surface border border-falcon-border rounded-lg p-4">
          <p className="text-falcon-muted text-xs mb-1">総タグ数</p>
          <p className="text-2xl font-bold text-white">{tags.length}</p>
        </div>
        <div className="bg-falcon-surface border border-falcon-border rounded-lg p-4">
          <p className="text-falcon-muted text-xs mb-1">登録エージェント数</p>
          <p className="text-2xl font-bold text-white">{agents.length}</p>
        </div>
      </div>

      {/* Quick Add Tag Form */}
      <div className="bg-falcon-surface border border-falcon-border rounded-lg p-4 mb-6">
        <h2 className="text-sm font-semibold text-white mb-3 flex items-center gap-2">
          <Plus className="w-4 h-4 text-falcon-red" />
          タグをエージェントに追加
        </h2>
        <div className="flex flex-wrap gap-3 items-end">
          <div className="flex flex-col gap-1">
            <label className="text-xs text-falcon-muted">エージェント</label>
            <AgentSelect value={quickAgent} onChange={setQuickAgent} className="w-64" />
          </div>
          <div className="flex flex-col gap-1">
            <label className="text-xs text-falcon-muted">タグ名</label>
            <input
              type="text"
              value={quickTag}
              onChange={e => setQuickTag(e.target.value)}
              placeholder="production"
              className="bg-[#070d19] border border-falcon-border rounded-sm px-3 py-2 text-sm text-white placeholder-falcon-subtle focus:outline-hidden focus:border-falcon-red/50 w-48"
            />
          </div>
          <button
            onClick={() => handleAddTag(quickAgent, quickTag)}
            disabled={addTagMutation.isPending}
            className="px-4 py-2 bg-falcon-red hover:bg-[#c8001f] text-white text-sm font-medium rounded-sm transition-colors disabled:opacity-50"
          >
            {addTagMutation.isPending ? '追加中...' : '追加'}
          </button>
        </div>
        {successMsg && <p className="mt-2 text-xs text-green-400">{successMsg}</p>}
        {errorMsg && <p className="mt-2 text-xs text-falcon-red">{errorMsg}</p>}
      </div>

      {/* Tags Table */}
      <div className="bg-falcon-surface border border-falcon-border rounded-lg overflow-hidden">
        <div className="px-4 py-3 border-b border-falcon-border">
          <h2 className="text-sm font-semibold text-white">タグ一覧</h2>
        </div>

        {isLoading ? (
          <div className="p-8 text-center text-falcon-muted text-sm">読み込み中...</div>
        ) : tags.length === 0 ? (
          <div className="p-8 text-center text-falcon-muted text-sm">タグが登録されていません</div>
        ) : (
          <table className="w-full">
            <thead>
              <tr className="border-b border-falcon-border">
                <th className="px-4 py-3 text-left text-xs font-medium text-falcon-muted uppercase tracking-wider">タグ名</th>
                <th className="px-4 py-3 text-left text-xs font-medium text-falcon-muted uppercase tracking-wider">エージェント数</th>
                <th className="px-4 py-3 text-left text-xs font-medium text-falcon-muted uppercase tracking-wider">操作</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-falcon-border">
              {tags.map(tag => {
                const isExpanded = expandedTag === tag
                return (
                  <>
                    <tr key={tag} className="hover:bg-[#0a1628] transition-colors">
                      <td className="px-4 py-3">
                        <span className="inline-block px-2 py-0.5 rounded-sm text-xs font-medium bg-falcon-red/10 text-falcon-red border border-falcon-red/20">
                          {tag}
                        </span>
                      </td>
                      <td className="px-4 py-3 text-sm text-falcon-muted">
                        <span className="flex items-center gap-1.5">
                          <Users className="w-3.5 h-3.5" />
                          {isExpanded && agentData ? agentData.agent_ids.length : '—'}
                        </span>
                      </td>
                      <td className="px-4 py-3">
                        <button
                          onClick={() => setExpandedTag(isExpanded ? null : tag)}
                          className="flex items-center gap-1.5 text-xs text-falcon-muted hover:text-white transition-colors px-2 py-1 rounded-sm hover:bg-falcon-border"
                        >
                          {isExpanded ? <ChevronDown className="w-3.5 h-3.5" /> : <ChevronRight className="w-3.5 h-3.5" />}
                          エージェント一覧
                        </button>
                      </td>
                    </tr>

                    {isExpanded && (
                      <tr key={`${tag}-expanded`} className="bg-[#070d19]">
                        <td colSpan={3} className="px-6 py-4">
                          <div className="border border-falcon-border rounded-lg overflow-hidden mb-3">
                            <div className="px-3 py-2 border-b border-falcon-border">
                              <span className="text-xs font-medium text-falcon-muted">タグ「{tag}」のエージェント</span>
                            </div>
                            {!agentData ? (
                              <div className="p-4 text-center text-xs text-falcon-muted">読み込み中...</div>
                            ) : agentData.agent_ids.length === 0 ? (
                              <div className="p-4 text-center text-xs text-falcon-muted">エージェントなし</div>
                            ) : (
                              <ul className="divide-y divide-falcon-border">
                                {agentData.agent_ids.map(id => (
                                  <li key={id} className="px-4 py-2.5 flex items-center justify-between hover:bg-falcon-surface">
                                    <span className="text-xs text-falcon-text font-medium">
                                      {agentMap.get(id) ?? id}
                                    </span>
                                    <a
                                      href={`/endpoints/${id}`}
                                      className="flex items-center gap-1 text-xs text-falcon-muted hover:text-falcon-red transition-colors"
                                    >
                                      <ExternalLink className="w-3 h-3" />
                                      詳細
                                    </a>
                                  </li>
                                ))}
                              </ul>
                            )}
                          </div>

                          {/* Add tag to another agent (per-tag context) */}
                          <div className="flex flex-wrap gap-2 items-end">
                            <div className="flex flex-col gap-1">
                              <label className="text-xs text-falcon-muted">別エージェントにこのタグを追加</label>
                              <AgentSelect value={inlineAgent} onChange={setInlineAgent} className="w-56" />
                            </div>
                            <button
                              onClick={() => handleAddTag(inlineAgent, tag)}
                              disabled={addTagMutation.isPending}
                              className="px-3 py-2 bg-falcon-border hover:bg-falcon-red text-white text-xs font-medium rounded-sm transition-colors disabled:opacity-50"
                            >
                              追加
                            </button>
                          </div>
                        </td>
                      </tr>
                    )}
                  </>
                )
              })}
            </tbody>
          </table>
        )}
      </div>

    </div>
  )
}

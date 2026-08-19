'use client'

import { useState } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { apiFetch, apiFetchList } from '@/lib/api'
import { Users, ChevronRight, ChevronDown, Plus, Trash2, Save, Monitor, Shield, MapPin, Tag, X, Check } from 'lucide-react'

import { PageDataUnavailable } from '@/components/PageDataUnavailable'
import { PageSaveFailed } from '@/components/PageSaveFailed'

// ─── 型定義 ──────────────────────────────────────────────────────────────────

type GroupType = 'department' | 'os' | 'location' | 'custom'
type RuleField = 'hostname' | 'os' | 'department' | 'ip_range'
type RuleOperator = 'contains' | 'equals' | 'matches'
type EndpointStatus = 'online' | 'offline' | 'warning'

interface MembershipRule {
  id: string
  field: RuleField
  operator: RuleOperator
  value: string
}

interface EndpointEntry {
  id: string
  hostname: string
  os: string
  ip_address: string
  last_seen: string
  status: EndpointStatus
}

interface GroupPolicy {
  id: string
  name: string
  type: 'edr' | 'hardening' | 'compliance' | 'custom'
}

interface EndpointGroup {
  id: string
  name: string
  type: GroupType
  description: string
  endpoint_count: number
  parent_id: string | null
  rules: MembershipRule[]
  endpoints: EndpointEntry[]
  policies: GroupPolicy[]
}

// ─── ユーティリティ ───────────────────────────────────────────────────────────

function fmtDate(iso: string): string {
  return new Date(iso).toLocaleString('ja-JP', { month: '2-digit', day: '2-digit', hour: '2-digit', minute: '2-digit' })
}

const TYPE_CONFIG: Record<GroupType, { label: string; cls: string; icon: React.ReactNode }> = {
  department: { label: '部署',       cls: 'bg-blue-900/50 text-blue-300 border border-blue-700/50',   icon: <Users className="w-3.5 h-3.5" /> },
  os:         { label: 'OS',         cls: 'bg-green-900/50 text-green-300 border border-green-700/50', icon: <Monitor className="w-3.5 h-3.5" /> },
  location:   { label: '拠点',       cls: 'bg-orange-900/50 text-orange-300 border border-orange-700/50', icon: <MapPin className="w-3.5 h-3.5" /> },
  custom:     { label: 'カスタム',    cls: 'bg-purple-900/50 text-purple-300 border border-purple-700/50', icon: <Tag className="w-3.5 h-3.5" /> },
}

const POLICY_BADGE: Record<GroupPolicy['type'], string> = {
  edr:        'bg-blue-900/40 text-blue-300 border border-blue-700/40',
  hardening:  'bg-orange-900/40 text-orange-300 border border-orange-700/40',
  compliance: 'bg-green-900/40 text-green-300 border border-green-700/40',
  custom:     'bg-purple-900/40 text-purple-300 border border-purple-700/40',
}

const STATUS_DOT: Record<EndpointStatus, string> = {
  online:  'bg-green-400',
  offline: 'bg-gray-500',
  warning: 'bg-yellow-400',
}

const RULE_FIELDS: RuleField[] = ['hostname', 'os', 'department', 'ip_range']
const RULE_OPERATORS: RuleOperator[] = ['contains', 'equals', 'matches']
const FIELD_LABELS: Record<RuleField, string> = { hostname: 'ホスト名', os: 'OS', department: '部署', ip_range: 'IPレンジ' }
const OP_LABELS: Record<RuleOperator, string> = { contains: '含む', equals: '等しい', matches: '正規表現' }

// ─── グループツリーアイテム ──────────────────────────────────────────────────

function GroupTreeItem({ group, children, selectedId, onSelect, depth = 0 }: { group: EndpointGroup; children?: EndpointGroup[]; selectedId: string | null; onSelect: (g: EndpointGroup) => void; depth?: number }) {
  const [expanded, setExpanded] = useState(true)
  const hasChildren = children && children.length > 0
  const isSelected = selectedId === group.id
  const tc = TYPE_CONFIG[group.type]

  return (
    <div>
      <div
        className={`flex items-center gap-2 p-2 rounded-lg cursor-pointer transition-colors ${isSelected ? 'bg-[#e8002d]/10 border border-[#e8002d]/30' : 'hover:bg-[#1e2d42]/40 border border-transparent'}`}
        style={{ paddingLeft: `${8 + depth * 16}px` }}
        onClick={() => onSelect(group)}
      >
        {hasChildren ? (
          <button onClick={e => { e.stopPropagation(); setExpanded(!expanded) }} className="text-[#7d92b0] hover:text-white">
            {expanded ? <ChevronDown className="w-3.5 h-3.5" /> : <ChevronRight className="w-3.5 h-3.5" />}
          </button>
        ) : <div className="w-3.5" />}
        <span className={`text-[#7d92b0] ${isSelected ? 'text-[#e8002d]' : ''}`}>{tc.icon}</span>
        <span className="text-sm text-white flex-1 truncate">{group.name}</span>
        <span className="text-xs bg-[#1e2d42] text-[#7d92b0] px-1.5 py-0.5 rounded-sm">{group.endpoint_count}</span>
      </div>
      {hasChildren && expanded && children!.map(c => (
        <GroupTreeItem key={c.id} group={c} selectedId={selectedId} onSelect={onSelect} depth={depth + 1} />
      ))}
    </div>
  )
}

// ─── メインページ ─────────────────────────────────────────────────────────────

export default function EndpointGroupsPage() {
  const qc = useQueryClient()
  const [selectedGroup, setSelectedGroup] = useState<EndpointGroup | null>(null)
  const [editingRules, setEditingRules] = useState<MembershipRule[]>([])
  const [endpointPage, setEndpointPage] = useState(1)

  const { data: groups = [] } = useQuery<EndpointGroup[]>({
    queryKey: ['endpoint-groups'],
    queryFn: () => apiFetchList<EndpointGroup>('/api/v1/admin/endpoint-groups'),
  })

  const saveGroup = useMutation({
    mutationFn: (g: EndpointGroup) => apiFetch(`/api/v1/admin/endpoint-groups/${g.id}`, { method: 'PUT', body: JSON.stringify({ ...g, rules: editingRules }) }),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['endpoint-groups'] }),
  })

  const deleteGroup = useMutation({
    mutationFn: (id: string) => apiFetch(`/api/v1/admin/endpoint-groups/${id}`, { method: 'DELETE' }),
    onSuccess: () => { setSelectedGroup(null); qc.invalidateQueries({ queryKey: ['endpoint-groups'] }) },
  })

  const handleSelect = (g: EndpointGroup) => {
    setSelectedGroup(g)
    setEditingRules(g.rules)
    setEndpointPage(1)
  }

  const addRule = () => setEditingRules(r => [...r, { id: `r_${Date.now()}`, field: 'hostname', operator: 'contains', value: '' }])
  const removeRule = (id: string) => setEditingRules(r => r.filter(x => x.id !== id))
  const updateRule = (id: string, key: keyof MembershipRule, val: string) =>
    setEditingRules(r => r.map(x => x.id === id ? { ...x, [key]: val } : x))

  const topLevel = groups.filter(g => !g.parent_id)
  const childrenOf = (id: string) => groups.filter(g => g.parent_id === id)

  const sg = selectedGroup
  const pagedEndpoints = sg ? sg.endpoints.slice((endpointPage - 1) * 5, endpointPage * 5) : []
  const totalPages = sg ? Math.ceil(sg.endpoints.length / 5) : 1

  const stats = [
    { label: '総グループ数', value: '12' },
    { label: '総エンドポイント', value: '210' },
    { label: '最大グループ', value: '本社Windows 87台' },
    { label: '未割り当て', value: '5台' },
  ]

  return (
    <div className="min-h-screen bg-[#070d19] text-white p-6">
      <PageDataUnavailable />
      <PageSaveFailed className="mb-4" />
      {/* ヘッダー */}
      <div className="mb-6">
        <div className="flex items-center gap-3 mb-1">
          <Users className="w-6 h-6 text-[#e8002d]" />
          <h1 className="text-2xl font-bold">エンドポイントグループ管理</h1>
        </div>
        <p className="text-[#7d92b0] text-sm">エンドポイントのグループ化・ポリシー適用管理</p>
      </div>

      {/* 統計行 */}
      <div className="grid grid-cols-4 gap-4 mb-6">
        {stats.map((s, i) => (
          <div key={i} className="bg-[#0d1220] border border-[#1e2d42] rounded-lg p-4">
            <p className="text-[#7d92b0] text-xs mb-1">{s.label}</p>
            <p className="text-white font-bold text-lg">{s.value}</p>
          </div>
        ))}
      </div>

      {/* メイン2カラム */}
      <div className="flex gap-4">
        {/* 左パネル: グループツリー (35%) */}
        <div className="w-[35%] bg-[#0d1220] border border-[#1e2d42] rounded-lg p-4 flex flex-col gap-2">
          <div className="flex items-center justify-between mb-1">
            <h2 className="text-sm font-semibold text-[#7d92b0] uppercase tracking-wider">グループ一覧</h2>
            <button className="flex items-center gap-1 text-xs bg-[#e8002d] hover:bg-[#c0001f] text-white px-2 py-1 rounded-sm transition-colors">
              <Plus className="w-3 h-3" /> 追加
            </button>
          </div>
          <div className="space-y-0.5">
            {topLevel.map(g => (
              <GroupTreeItem key={g.id} group={g} children={childrenOf(g.id)} selectedId={sg?.id ?? null} onSelect={handleSelect} />
            ))}
          </div>
        </div>

        {/* 右パネル: グループ詳細 (65%) */}
        <div className="w-[65%] flex flex-col gap-4">
          {sg ? (
            <>
              {/* グループ基本情報 */}
              <div className="bg-[#0d1220] border border-[#1e2d42] rounded-lg p-4">
                <div className="flex items-start justify-between">
                  <div>
                    <div className="flex items-center gap-2 mb-1">
                      <h2 className="text-lg font-bold text-white">{sg.name}</h2>
                      <span className={`flex items-center gap-1 text-xs px-2 py-0.5 rounded-full ${TYPE_CONFIG[sg.type].cls}`}>
                        {TYPE_CONFIG[sg.type].icon}{TYPE_CONFIG[sg.type].label}
                      </span>
                    </div>
                    <p className="text-sm text-[#7d92b0]">{sg.description}</p>
                  </div>
                  <span className="text-2xl font-bold text-white">{sg.endpoint_count}<span className="text-sm text-[#7d92b0] ml-1">台</span></span>
                </div>
              </div>

              {/* メンバーシップルール */}
              <div className="bg-[#0d1220] border border-[#1e2d42] rounded-lg p-4">
                <div className="flex items-center justify-between mb-3">
                  <h3 className="text-sm font-semibold text-[#7d92b0] uppercase tracking-wider">メンバーシップルール</h3>
                  <button onClick={addRule} className="flex items-center gap-1 text-xs text-[#7d92b0] hover:text-white bg-[#1e2d42] hover:bg-[#2e4060] px-2 py-1 rounded-sm transition-colors">
                    <Plus className="w-3 h-3" /> ルール追加
                  </button>
                </div>
                <div className="space-y-2">
                  {editingRules.map(rule => (
                    <div key={rule.id} className="flex items-center gap-2">
                      <select value={rule.field} onChange={e => updateRule(rule.id, 'field', e.target.value)} className="bg-[#070d19] border border-[#1e2d42] text-white text-sm px-2 py-1.5 rounded-sm focus:outline-hidden focus:border-[#e8002d]/50">
                        {RULE_FIELDS.map(f => <option key={f} value={f}>{FIELD_LABELS[f]}</option>)}
                      </select>
                      <select value={rule.operator} onChange={e => updateRule(rule.id, 'operator', e.target.value)} className="bg-[#070d19] border border-[#1e2d42] text-white text-sm px-2 py-1.5 rounded-sm focus:outline-hidden focus:border-[#e8002d]/50">
                        {RULE_OPERATORS.map(o => <option key={o} value={o}>{OP_LABELS[o]}</option>)}
                      </select>
                      <input value={rule.value} onChange={e => updateRule(rule.id, 'value', e.target.value)} placeholder="値を入力..." className="flex-1 bg-[#070d19] border border-[#1e2d42] text-white text-sm px-2 py-1.5 rounded-sm focus:outline-hidden focus:border-[#e8002d]/50" />
                      <button onClick={() => removeRule(rule.id)} className="text-[#7d92b0] hover:text-red-400 transition-colors">
                        <X className="w-4 h-4" />
                      </button>
                    </div>
                  ))}
                  {editingRules.length === 0 && <p className="text-sm text-[#7d92b0]">ルールなし（手動割り当てのみ）</p>}
                </div>
              </div>

              {/* エンドポイント一覧 */}
              <div className="bg-[#0d1220] border border-[#1e2d42] rounded-lg p-4">
                <h3 className="text-sm font-semibold text-[#7d92b0] uppercase tracking-wider mb-3">エンドポイント一覧</h3>
                <table className="w-full text-sm">
                  <thead>
                    <tr className="border-b border-[#1e2d42]">
                      {['ホスト名', 'OS', 'IPアドレス', '最終接続', 'ステータス', '操作'].map(h => (
                        <th key={h} className="text-left text-[#7d92b0] font-medium pb-2 pr-3 text-xs">{h}</th>
                      ))}
                    </tr>
                  </thead>
                  <tbody>
                    {pagedEndpoints.map(ep => (
                      <tr key={ep.id} className="border-b border-[#1e2d42]/50 hover:bg-[#1e2d42]/20 transition-colors">
                        <td className="py-2 pr-3 text-white font-mono text-xs">{ep.hostname}</td>
                        <td className="py-2 pr-3 text-[#7d92b0] text-xs">{ep.os}</td>
                        <td className="py-2 pr-3 text-[#7d92b0] font-mono text-xs">{ep.ip_address}</td>
                        <td className="py-2 pr-3 text-[#7d92b0] text-xs">{fmtDate(ep.last_seen)}</td>
                        <td className="py-2 pr-3">
                          <div className="flex items-center gap-1.5">
                            <div className={`w-2 h-2 rounded-full ${STATUS_DOT[ep.status]}`} />
                            <span className="text-xs text-[#7d92b0]">{ep.status === 'online' ? 'オンライン' : ep.status === 'offline' ? 'オフライン' : '警告'}</span>
                          </div>
                        </td>
                        <td className="py-2 pr-3">
                          <div className="flex gap-1">
                            <button className="text-xs text-blue-400 hover:text-blue-300 bg-blue-900/30 hover:bg-blue-900/50 px-1.5 py-0.5 rounded-sm transition-colors">手動追加</button>
                            <button className="text-xs text-red-400 hover:text-red-300 bg-red-900/30 hover:bg-red-900/50 px-1.5 py-0.5 rounded-sm transition-colors">除外</button>
                          </div>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
                {totalPages > 1 && (
                  <div className="flex items-center justify-end gap-2 mt-3">
                    <button onClick={() => setEndpointPage(p => Math.max(1, p - 1))} disabled={endpointPage === 1} className="text-xs text-[#7d92b0] hover:text-white disabled:opacity-40 px-2 py-1 bg-[#1e2d42] rounded-sm">前</button>
                    <span className="text-xs text-[#7d92b0]">{endpointPage} / {totalPages}</span>
                    <button onClick={() => setEndpointPage(p => Math.min(totalPages, p + 1))} disabled={endpointPage === totalPages} className="text-xs text-[#7d92b0] hover:text-white disabled:opacity-40 px-2 py-1 bg-[#1e2d42] rounded-sm">次</button>
                  </div>
                )}
              </div>

              {/* グループポリシー */}
              <div className="bg-[#0d1220] border border-[#1e2d42] rounded-lg p-4">
                <h3 className="text-sm font-semibold text-[#7d92b0] uppercase tracking-wider mb-3">グループポリシー</h3>
                <div className="flex flex-wrap gap-2">
                  {sg.policies.map(pol => (
                    <div key={pol.id} className={`flex items-center gap-1.5 text-xs px-3 py-1.5 rounded-full ${POLICY_BADGE[pol.type]}`}>
                      <Shield className="w-3 h-3" />
                      {pol.name}
                    </div>
                  ))}
                </div>
              </div>

              {/* 保存・削除ボタン */}
              <div className="flex items-center justify-between">
                <button
                  onClick={() => deleteGroup.mutate(sg.id)}
                  disabled={deleteGroup.isPending}
                  className="flex items-center gap-2 text-sm text-red-400 hover:text-white bg-red-900/30 hover:bg-red-900/50 border border-red-700/30 px-4 py-2 rounded-lg transition-colors disabled:opacity-50"
                >
                  <Trash2 className="w-4 h-4" /> 削除
                </button>
                <button
                  onClick={() => saveGroup.mutate(sg)}
                  disabled={saveGroup.isPending}
                  className="flex items-center gap-2 text-sm bg-[#e8002d] hover:bg-[#c0001f] text-white px-4 py-2 rounded-lg transition-colors disabled:opacity-50"
                >
                  {saveGroup.isPending ? <span className="w-4 h-4 border-2 border-white/30 border-t-white rounded-full animate-spin" /> : <Save className="w-4 h-4" />}
                  保存
                </button>
              </div>
            </>
          ) : (
            <div className="bg-[#0d1220] border border-[#1e2d42] rounded-lg p-12 flex items-center justify-center">
              <p className="text-[#7d92b0] text-sm">左のグループを選択してください</p>
            </div>
          )}
        </div>
      </div>
    </div>
  )
}

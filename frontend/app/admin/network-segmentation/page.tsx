'use client'

import { useState } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { apiFetch } from '@/lib/api'
import {
  GitBranch, Plus, Trash2, Edit2, X, CheckCircle, AlertTriangle,
  Shield, Server, Laptop, Wifi, ChevronRight, RefreshCw, Loader2,
} from 'lucide-react'

// ── Types ───────────────────────────────────────────────────────────────────

interface Device {
  ip: string
  hostname: string
  type: 'server' | 'workstation' | 'network' | 'iot'
}

interface Segment {
  id: string
  name: string
  description: string
  vlan_id: number
  cidr: string
  gateway: string
  dns_servers: string[]
  device_count: number
  policy_count: number
  status: 'active' | 'inactive'
  devices: Device[]
}

interface Policy {
  id: string
  from_segment: string
  to_segment: string
  action: 'allow' | 'deny' | 'inspect'
  protocol: string
  ports: string
  description: string
}

interface SegmentData {
  segments: Segment[]
  policies: Policy[]
}

// ── Helpers ──────────────────────────────────────────────────────────────────

function DeviceTypeIcon({ type }: { type: Device['type'] }) {
  const map = {
    server:      { Icon: Server, color: 'text-[#4a90e2]' },
    workstation: { Icon: Laptop, color: 'text-[#00c853]' },
    network:     { Icon: GitBranch, color: 'text-yellow-400' },
    iot:         { Icon: Wifi, color: 'text-orange-400' },
  }
  const { Icon, color } = map[type]
  return <Icon className={`w-3.5 h-3.5 ${color}`} />
}

function DeviceTypeBadge({ type }: { type: Device['type'] }) {
  const map = {
    server:      'bg-[#4a90e2]/10 text-[#4a90e2] border-[#4a90e2]/30',
    workstation: 'bg-[#00c853]/10 text-[#00c853] border-[#00c853]/30',
    network:     'bg-yellow-400/10 text-yellow-400 border-yellow-400/30',
    iot:         'bg-orange-400/10 text-orange-400 border-orange-400/30',
  }
  const labels = { server: 'サーバー', workstation: 'PC', network: 'NW', iot: 'IoT' }
  return (
    <span className={`inline-flex items-center px-1.5 py-0.5 rounded text-[10px] font-semibold border ${map[type]}`}>
      {labels[type]}
    </span>
  )
}

function ActionBadge({ action }: { action: Policy['action'] }) {
  const map = {
    allow:   'bg-[#00c853]/10 text-[#00c853] border-[#00c853]/30',
    deny:    'bg-[#e8002d]/10 text-[#e8002d] border-[#e8002d]/30',
    inspect: 'bg-yellow-400/10 text-yellow-400 border-yellow-400/30',
  }
  const labels = { allow: '許可', deny: '拒否', inspect: '検査' }
  return (
    <span className={`inline-flex items-center px-2 py-0.5 rounded text-[10px] font-bold border ${map[action]}`}>
      {labels[action]}
    </span>
  )
}

const SEGMENT_COLORS: Record<string, string> = {
  DMZ:   '#e8002d',
  CORP:  '#4a90e2',
  MGMT:  '#00c853',
  GUEST: '#f59e0b',
  OT:    '#a855f7',
}

function SegmentBox({ name, cidr, deviceCount }: { name: string; cidr: string; deviceCount: number }) {
  const color = SEGMENT_COLORS[name] ?? '#7d92b0'
  return (
    <div className="flex flex-col items-center gap-1 p-3 rounded-lg border-2" style={{ borderColor: color + '60', backgroundColor: color + '08' }}>
      <div className="w-8 h-8 rounded flex items-center justify-center" style={{ backgroundColor: color + '20' }}>
        <Shield className="w-4 h-4" style={{ color }} />
      </div>
      <span className="text-xs font-bold text-white">{name}</span>
      <span className="text-[10px] font-mono text-[#7d92b0]">{cidr}</span>
      <span className="text-[10px] text-[#7d92b0]">{deviceCount}台</span>
    </div>
  )
}

// ── Modal ────────────────────────────────────────────────────────────────────

const emptySegmentForm = { name: '', description: '', vlan_id: '', cidr: '', gateway: '', dns_servers: '' }
const emptyPolicyForm = { from_segment: '', to_segment: '', action: 'allow' as Policy['action'], protocol: 'TCP', ports: '', description: '' }

// ── Main Page ────────────────────────────────────────────────────────────────

export default function NetworkSegmentationPage() {
  const qc = useQueryClient()
  const [selectedId, setSelectedId] = useState<string | null>(null)
  const [showAddSegment, setShowAddSegment] = useState(false)
  const [showAddPolicy, setShowAddPolicy] = useState(false)
  const [segmentForm, setSegmentForm] = useState(emptySegmentForm)
  const [policyForm, setPolicyForm] = useState(emptyPolicyForm)
  const [complianceResult, setComplianceResult] = useState<string[] | null>(null)
  const [checkingCompliance, setCheckingCompliance] = useState(false)
  const [toast, setToast] = useState<{ msg: string; ok: boolean } | null>(null)

  const showToast = (msg: string, ok = true) => {
    setToast({ msg, ok })
    setTimeout(() => setToast(null), 3500)
  }

  const { data, isLoading } = useQuery<SegmentData>({
    queryKey: ['network-segments'],
    queryFn: () =>
      apiFetch<SegmentData>('/api/v1/admin/network-segments')
        .then((raw) => ({
          segments: Array.isArray(raw?.segments) ? raw.segments : [],
          policies: Array.isArray(raw?.policies) ? raw.policies : [],
        }))
        .catch(() => ({ segments: [], policies: [] })),
    staleTime: 30_000,
  })

  const segData = data ?? { segments: [], policies: [] }
  const selected = segData.segments.find(s => s.id === selectedId) ?? null

  const addSegmentMutation = useMutation({
    // Send vlan_id as a number and dns_servers as an array (the form holds strings).
    mutationFn: (body: typeof segmentForm) =>
      apiFetch('/api/v1/admin/network-segments', {
        method: 'POST',
        body: JSON.stringify({
          ...body,
          vlan_id: Number(body.vlan_id) || 0,
          dns_servers: body.dns_servers.split(',').map(s => s.trim()).filter(Boolean),
        }),
      }),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['network-segments'] })
      setShowAddSegment(false)
      setSegmentForm(emptySegmentForm)
      showToast('セグメントを追加しました')
    },
    onError: () => showToast('セグメントの追加に失敗しました', false),
  })

  const deleteSegmentMutation = useMutation({
    mutationFn: (id: string) =>
      apiFetch(`/api/v1/admin/network-segments/${id}`, { method: 'DELETE' }),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['network-segments'] })
      setSelectedId(null)
      showToast('セグメントを削除しました')
    },
    onError: () => showToast('セグメントの削除に失敗しました', false),
  })

  const addPolicyMutation = useMutation({
    mutationFn: (body: typeof policyForm) =>
      apiFetch('/api/v1/admin/network-segments/policies', { method: 'POST', body: JSON.stringify(body) }),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['network-segments'] })
      setShowAddPolicy(false)
      setPolicyForm(emptyPolicyForm)
      showToast('ポリシーを追加しました')
    },
    onError: () => showToast('ポリシーの追加に失敗しました', false),
  })

  const runComplianceCheck = async () => {
    setCheckingCompliance(true)
    setComplianceResult(null)
    try {
      // Real, data-driven compliance check over the defined segments/policies.
      const res = await apiFetch<{ issues?: string[] }>('/api/v1/admin/network-segments/compliance-check', { method: 'POST' })
      setComplianceResult(Array.isArray(res?.issues) ? res.issues : [])
    } catch {
      setComplianceResult(['コンプライアンスチェックの実行に失敗しました'])
    } finally {
      setCheckingCompliance(false)
    }
  }

  const inputCls = 'w-full px-3 py-2 rounded bg-[#070d19] border border-[#1e2d42] text-[#e2e8f4] text-sm placeholder-[#3d5068] focus:outline-none focus:border-[#3d6baa] transition-colors'
  const labelCls = 'block text-xs font-medium text-[#7d92b0] mb-1.5'

  return (
    <div className="min-h-screen bg-[#070d19] p-6 space-y-6">

      {/* Toast */}
      {toast && (
        <div className={`fixed top-4 right-4 z-50 flex items-center gap-2 px-4 py-3 rounded-lg border shadow-lg text-sm animate-fade-in
          ${toast.ok ? 'bg-[#0d1220] border-[#1e2d42] text-[#e2e8f4]' : 'bg-[#e8002d]/10 border-[#e8002d]/30 text-[#e8002d]'}`}>
          {toast.ok ? <CheckCircle className="w-4 h-4 text-[#00c853]" /> : <AlertTriangle className="w-4 h-4" />}
          {toast.msg}
        </div>
      )}

      {/* Header */}
      <div className="flex items-start justify-between flex-wrap gap-4">
        <div className="flex items-center gap-3">
          <div className="w-10 h-10 rounded-lg bg-[#4a90e2]/10 border border-[#4a90e2]/20 flex items-center justify-center">
            <GitBranch className="w-5 h-5 text-[#4a90e2]" />
          </div>
          <div>
            <h1 className="text-2xl font-bold text-white">ネットワークセグメント管理</h1>
            <p className="text-sm text-[#7d92b0] mt-0.5">VLANセグメントとセグメント間ポリシーの管理</p>
          </div>
        </div>
        <div className="flex items-center gap-3">
          <button
            onClick={runComplianceCheck}
            disabled={checkingCompliance}
            className="flex items-center gap-2 px-4 py-2 rounded-lg bg-[#0d1220] border border-[#1e2d42] text-[#7d92b0] hover:text-[#e2e8f4] hover:border-[#7d92b0]/40 text-sm font-medium transition-colors disabled:opacity-50"
          >
            {checkingCompliance ? <Loader2 className="w-4 h-4 animate-spin" /> : <Shield className="w-4 h-4" />}
            コンプライアンスチェック
          </button>
          <button
            onClick={() => setShowAddPolicy(true)}
            className="flex items-center gap-2 px-4 py-2 rounded-lg bg-[#0d1220] border border-[#1e2d42] text-[#7d92b0] hover:text-[#e2e8f4] hover:border-[#7d92b0]/40 text-sm font-medium transition-colors"
          >
            <Plus className="w-4 h-4" />
            ポリシー追加
          </button>
          <button
            onClick={() => setShowAddSegment(true)}
            className="flex items-center gap-2 px-4 py-2 rounded-lg bg-[#e8002d] hover:bg-[#c0001f] text-white text-sm font-medium transition-colors"
          >
            <Plus className="w-4 h-4" />
            セグメント追加
          </button>
        </div>
      </div>

      {/* Compliance Result */}
      {complianceResult && (
        complianceResult.length === 0 ? (
          <div className="bg-[#00c853]/5 border border-[#00c853]/30 rounded-lg p-4">
            <div className="flex items-center gap-2">
              <CheckCircle className="w-4 h-4 text-[#00c853]" />
              <span className="text-sm font-semibold text-[#00c853]">コンプライアンス違反は検出されませんでした</span>
              <button onClick={() => setComplianceResult(null)} className="ml-auto text-[#7d92b0] hover:text-[#e2e8f4]"><X className="w-4 h-4" /></button>
            </div>
          </div>
        ) : (
          <div className="bg-[#e8002d]/5 border border-[#e8002d]/30 rounded-lg p-4 space-y-2">
            <div className="flex items-center gap-2">
              <AlertTriangle className="w-4 h-4 text-[#e8002d]" />
              <span className="text-sm font-semibold text-[#e8002d]">コンプライアンス違反 {complianceResult.length}件検出</span>
              <button onClick={() => setComplianceResult(null)} className="ml-auto text-[#7d92b0] hover:text-[#e2e8f4]"><X className="w-4 h-4" /></button>
            </div>
            {complianceResult.map((issue, i) => (
              <div key={i} className="flex items-start gap-2 text-sm text-[#e2e8f4]">
                <span className="text-[#e8002d] mt-0.5">•</span>
                <span>{issue}</span>
              </div>
            ))}
          </div>
        )
      )}

      {/* Segment Cards Grid */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 xl:grid-cols-5 gap-4">
        {isLoading ? (
          Array.from({ length: 5 }).map((_, i) => (
            <div key={i} className="bg-[#0d1220] border border-[#1e2d42] rounded-lg h-40 animate-pulse" />
          ))
        ) : (
          segData.segments.map(seg => {
            const color = SEGMENT_COLORS[seg.name] ?? '#7d92b0'
            const isSelected = selectedId === seg.id
            return (
              <div
                key={seg.id}
                onClick={() => setSelectedId(isSelected ? null : seg.id)}
                className={`bg-[#0d1220] border rounded-lg p-4 cursor-pointer transition-all hover:border-opacity-80 ${
                  isSelected ? 'ring-1' : ''
                }`}
                style={{
                  borderColor: isSelected ? color : '#1e2d42',
                  ...(isSelected ? { boxShadow: `0 0 0 1px ${color}60` } : {}),
                }}
              >
                <div className="flex items-center justify-between mb-3">
                  <div className="flex items-center gap-2">
                    <div className="w-6 h-6 rounded flex items-center justify-center" style={{ backgroundColor: color + '20' }}>
                      <Shield className="w-3.5 h-3.5" style={{ color }} />
                    </div>
                    <span className="text-sm font-bold text-white">{seg.name}</span>
                  </div>
                  <span className={`text-[10px] font-semibold px-1.5 py-0.5 rounded border ${seg.status === 'active' ? 'text-[#00c853] border-[#00c853]/30 bg-[#00c853]/10' : 'text-[#7d92b0] border-[#1e2d42] bg-[#1e2d42]/30'}`}>
                    {seg.status === 'active' ? '有効' : '無効'}
                  </span>
                </div>
                <p className="text-xs text-[#7d92b0] mb-3 line-clamp-2">{seg.description}</p>
                <div className="space-y-1 text-xs">
                  <div className="flex justify-between">
                    <span className="text-[#3d5068]">VLAN</span>
                    <span className="font-mono text-[#e2e8f4]">{seg.vlan_id}</span>
                  </div>
                  <div className="flex justify-between">
                    <span className="text-[#3d5068]">CIDR</span>
                    <span className="font-mono text-[#e2e8f4]">{seg.cidr}</span>
                  </div>
                  <div className="flex justify-between">
                    <span className="text-[#3d5068]">デバイス</span>
                    <span className="font-mono text-[#e2e8f4]">{seg.device_count}台</span>
                  </div>
                  <div className="flex justify-between">
                    <span className="text-[#3d5068]">ポリシー</span>
                    <span className="font-mono text-[#e2e8f4]">{seg.policy_count}件</span>
                  </div>
                </div>
              </div>
            )
          })
        )}
      </div>

      {/* Segment Detail Panel */}
      {selected && (
        <div className="bg-[#0d1220] border border-[#1e2d42] rounded-lg overflow-hidden">
          <div className="flex items-center gap-3 px-5 py-4 border-b border-[#1e2d42]">
            <div className="w-6 h-6 rounded flex items-center justify-center" style={{ backgroundColor: (SEGMENT_COLORS[selected.name] ?? '#7d92b0') + '20' }}>
              <Shield className="w-3.5 h-3.5" style={{ color: SEGMENT_COLORS[selected.name] ?? '#7d92b0' }} />
            </div>
            <h2 className="text-white font-semibold">{selected.name} — 詳細</h2>
            <button
              onClick={() => setSelectedId(null)}
              className="ml-auto p-1.5 rounded hover:bg-[#1e2d42] text-[#7d92b0] hover:text-[#e2e8f4] transition-colors"
            >
              <X className="w-4 h-4" />
            </button>
          </div>
          <div className="p-5 grid grid-cols-1 lg:grid-cols-3 gap-6">
            {/* Info */}
            <div className="space-y-4">
              <h3 className="text-xs font-semibold text-[#7d92b0] uppercase tracking-wider">セグメント情報</h3>
              {[
                { label: '名前', value: selected.name },
                { label: '説明', value: selected.description },
                { label: 'VLAN ID', value: selected.vlan_id },
                { label: 'CIDR', value: selected.cidr },
                { label: 'ゲートウェイ', value: selected.gateway },
                { label: 'DNSサーバー', value: selected.dns_servers.join(', ') },
              ].map(({ label, value }) => (
                <div key={label}>
                  <p className="text-xs text-[#3d5068]">{label}</p>
                  <p className="text-sm font-mono text-[#e2e8f4]">{value}</p>
                </div>
              ))}
              <button
                onClick={() => deleteSegmentMutation.mutate(selected.id)}
                disabled={deleteSegmentMutation.isPending}
                className="flex items-center gap-2 px-3 py-1.5 rounded text-sm font-medium bg-[#e8002d]/10 border border-[#e8002d]/30 text-[#e8002d] hover:bg-[#e8002d]/20 transition-colors mt-2"
              >
                <Trash2 className="w-3.5 h-3.5" />
                セグメントを削除
              </button>
            </div>

            {/* Devices */}
            <div>
              <h3 className="text-xs font-semibold text-[#7d92b0] uppercase tracking-wider mb-3">
                デバイス ({selected.device_count}台)
              </h3>
              <div className="space-y-2">
                {selected.devices.map(d => (
                  <div key={d.ip} className="flex items-center gap-3 px-3 py-2 bg-[#070d19] border border-[#1e2d42] rounded">
                    <DeviceTypeIcon type={d.type} />
                    <span className="flex-1 text-xs font-mono text-[#e2e8f4]">{d.hostname}</span>
                    <span className="text-xs font-mono text-[#7d92b0]">{d.ip}</span>
                    <DeviceTypeBadge type={d.type} />
                  </div>
                ))}
                {selected.device_count > selected.devices.length && (
                  <p className="text-xs text-[#3d5068] text-center py-2">
                    ... 他 {selected.device_count - selected.devices.length}台
                  </p>
                )}
              </div>
            </div>

            {/* Policies */}
            <div>
              <h3 className="text-xs font-semibold text-[#7d92b0] uppercase tracking-wider mb-3">
                セグメント間ポリシー
              </h3>
              <div className="space-y-2">
                {segData.policies
                  .filter(p => p.from_segment === selected.name || p.to_segment === selected.name)
                  .map(p => (
                    <div key={p.id} className="px-3 py-2 bg-[#070d19] border border-[#1e2d42] rounded space-y-1">
                      <div className="flex items-center gap-2">
                        <span className="text-xs font-mono text-[#4a90e2]">{p.from_segment}</span>
                        <ChevronRight className="w-3 h-3 text-[#3d5068]" />
                        <span className="text-xs font-mono text-[#e2e8f4]">{p.to_segment}</span>
                        <ActionBadge action={p.action} />
                      </div>
                      <div className="flex items-center gap-3 text-[10px] text-[#3d5068]">
                        <span>{p.protocol}</span>
                        <span>ポート: {p.ports}</span>
                      </div>
                    </div>
                  ))}
              </div>
            </div>
          </div>
        </div>
      )}

      {/* Traffic Flow Visualization */}
      <div className="bg-[#0d1220] border border-[#1e2d42] rounded-lg overflow-hidden">
        <div className="flex items-center gap-3 px-5 py-4 border-b border-[#1e2d42]">
          <GitBranch className="w-5 h-5 text-[#e8002d]" />
          <h2 className="text-white font-semibold">トラフィックフロー ビジュアライゼーション</h2>
          <span className="ml-2 text-xs text-[#7d92b0]">（簡易ダイアグラム）</span>
        </div>
        <div className="p-6">
          <div className="flex flex-wrap items-start justify-center gap-6">
            {segData.segments.map(seg => (
              <SegmentBox key={seg.id} name={seg.name} cidr={seg.cidr} deviceCount={seg.device_count} />
            ))}
          </div>
          <div className="mt-6 grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-3">
            {segData.policies.map(p => {
              const fromColor = SEGMENT_COLORS[p.from_segment] ?? '#7d92b0'
              const arrow = p.action === 'allow' ? '→' : p.action === 'inspect' ? '⟹' : '✕'
              const arrowColor = p.action === 'allow' ? '#00c853' : p.action === 'inspect' ? '#f59e0b' : '#e8002d'
              return (
                <div key={p.id} className="flex items-center gap-2 px-3 py-2 bg-[#070d19] border border-[#1e2d42] rounded text-xs font-mono">
                  <span style={{ color: fromColor }}>{p.from_segment}</span>
                  <span style={{ color: arrowColor }} className="font-bold">{arrow}</span>
                  <span className="text-[#e2e8f4]">{p.to_segment}</span>
                  <ActionBadge action={p.action} />
                  <span className="text-[#3d5068] ml-auto">{p.ports !== '*' ? p.ports : 'ALL'}</span>
                </div>
              )
            })}
          </div>
          <div className="flex items-center gap-6 mt-4 text-xs text-[#7d92b0]">
            <span className="flex items-center gap-1.5"><span className="text-[#00c853] font-bold">→</span> 許可</span>
            <span className="flex items-center gap-1.5"><span className="text-[#e8002d] font-bold">✕</span> 拒否</span>
            <span className="flex items-center gap-1.5"><span className="text-yellow-400 font-bold">⟹</span> 検査</span>
          </div>
        </div>
      </div>

      {/* Inter-segment policies table */}
      <div className="bg-[#0d1220] border border-[#1e2d42] rounded-lg overflow-hidden">
        <div className="flex items-center gap-3 px-5 py-4 border-b border-[#1e2d42]">
          <Shield className="w-5 h-5 text-[#e8002d]" />
          <h2 className="text-white font-semibold">セグメント間ポリシー一覧</h2>
          <span className="ml-auto text-xs text-[#7d92b0] bg-[#1e2d42] px-2 py-0.5 rounded">{segData.policies.length}件</span>
        </div>
        <div className="overflow-x-auto">
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b border-[#1e2d42]">
                {['送信元', '', '宛先', 'アクション', 'プロトコル', 'ポート', '説明'].map(h => (
                  <th key={h} className="px-5 py-3 text-left text-xs font-medium text-[#7d92b0] uppercase tracking-wider">{h}</th>
                ))}
              </tr>
            </thead>
            <tbody className="divide-y divide-[#1e2d42]">
              {segData.policies.map(p => (
                <tr key={p.id} className="hover:bg-[#111827] transition-colors">
                  <td className="px-5 py-3">
                    <span className="font-mono text-sm font-semibold" style={{ color: SEGMENT_COLORS[p.from_segment] ?? '#7d92b0' }}>
                      {p.from_segment}
                    </span>
                  </td>
                  <td className="px-1 py-3 text-[#3d5068]"><ChevronRight className="w-4 h-4" /></td>
                  <td className="px-5 py-3">
                    <span className="font-mono text-sm font-semibold" style={{ color: SEGMENT_COLORS[p.to_segment] ?? '#7d92b0' }}>
                      {p.to_segment}
                    </span>
                  </td>
                  <td className="px-5 py-3"><ActionBadge action={p.action} /></td>
                  <td className="px-5 py-3 font-mono text-xs text-[#7d92b0]">{p.protocol}</td>
                  <td className="px-5 py-3 font-mono text-xs text-[#7d92b0]">{p.ports}</td>
                  <td className="px-5 py-3 text-xs text-[#7d92b0] max-w-[200px] truncate">{p.description}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>

      {/* Add Segment Modal */}
      {showAddSegment && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 backdrop-blur-sm p-4">
          <div className="bg-[#0d1220] border border-[#1e2d42] rounded-xl w-full max-w-lg shadow-2xl">
            <div className="flex items-center gap-3 px-6 py-4 border-b border-[#1e2d42]">
              <Plus className="w-5 h-5 text-[#e8002d]" />
              <h3 className="text-white font-semibold">セグメント追加</h3>
              <button onClick={() => setShowAddSegment(false)} className="ml-auto text-[#7d92b0] hover:text-[#e2e8f4]"><X className="w-5 h-5" /></button>
            </div>
            <div className="p-6 space-y-4">
              <div className="grid grid-cols-2 gap-4">
                <div>
                  <label className={labelCls}>名前</label>
                  <input className={inputCls} placeholder="SEGMENT_NAME" value={segmentForm.name} onChange={e => setSegmentForm(f => ({ ...f, name: e.target.value }))} />
                </div>
                <div>
                  <label className={labelCls}>VLAN ID</label>
                  <input className={inputCls} type="number" placeholder="400" value={segmentForm.vlan_id} onChange={e => setSegmentForm(f => ({ ...f, vlan_id: e.target.value }))} />
                </div>
              </div>
              <div>
                <label className={labelCls}>説明</label>
                <input className={inputCls} placeholder="セグメントの説明" value={segmentForm.description} onChange={e => setSegmentForm(f => ({ ...f, description: e.target.value }))} />
              </div>
              <div className="grid grid-cols-2 gap-4">
                <div>
                  <label className={labelCls}>CIDR</label>
                  <input className={inputCls} placeholder="10.40.0.0/24" value={segmentForm.cidr} onChange={e => setSegmentForm(f => ({ ...f, cidr: e.target.value }))} />
                </div>
                <div>
                  <label className={labelCls}>ゲートウェイ</label>
                  <input className={inputCls} placeholder="10.40.0.1" value={segmentForm.gateway} onChange={e => setSegmentForm(f => ({ ...f, gateway: e.target.value }))} />
                </div>
              </div>
              <div>
                <label className={labelCls}>DNSサーバー (カンマ区切り)</label>
                <input className={inputCls} placeholder="10.40.0.5, 8.8.8.8" value={segmentForm.dns_servers} onChange={e => setSegmentForm(f => ({ ...f, dns_servers: e.target.value }))} />
              </div>
            </div>
            <div className="flex justify-end gap-3 px-6 py-4 border-t border-[#1e2d42]">
              <button onClick={() => setShowAddSegment(false)} className="px-4 py-2 rounded text-sm text-[#7d92b0] hover:text-[#e2e8f4] transition-colors">キャンセル</button>
              <button
                onClick={() => addSegmentMutation.mutate(segmentForm)}
                disabled={addSegmentMutation.isPending || !segmentForm.name}
                className="flex items-center gap-2 px-5 py-2 rounded bg-[#e8002d] hover:bg-[#c0001f] text-white text-sm font-medium disabled:opacity-50 transition-colors"
              >
                {addSegmentMutation.isPending ? <Loader2 className="w-4 h-4 animate-spin" /> : <Plus className="w-4 h-4" />}
                追加
              </button>
            </div>
          </div>
        </div>
      )}

      {/* Add Policy Modal */}
      {showAddPolicy && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 backdrop-blur-sm p-4">
          <div className="bg-[#0d1220] border border-[#1e2d42] rounded-xl w-full max-w-lg shadow-2xl">
            <div className="flex items-center gap-3 px-6 py-4 border-b border-[#1e2d42]">
              <Shield className="w-5 h-5 text-[#e8002d]" />
              <h3 className="text-white font-semibold">ポリシー追加</h3>
              <button onClick={() => setShowAddPolicy(false)} className="ml-auto text-[#7d92b0] hover:text-[#e2e8f4]"><X className="w-5 h-5" /></button>
            </div>
            <div className="p-6 space-y-4">
              <div className="grid grid-cols-2 gap-4">
                <div>
                  <label className={labelCls}>送信元セグメント</label>
                  <select className={inputCls} value={policyForm.from_segment} onChange={e => setPolicyForm(f => ({ ...f, from_segment: e.target.value }))}>
                    <option value="">選択してください</option>
                    {segData.segments.map(s => <option key={s.id} value={s.name}>{s.name}</option>)}
                  </select>
                </div>
                <div>
                  <label className={labelCls}>宛先セグメント</label>
                  <select className={inputCls} value={policyForm.to_segment} onChange={e => setPolicyForm(f => ({ ...f, to_segment: e.target.value }))}>
                    <option value="">選択してください</option>
                    {segData.segments.map(s => <option key={s.id} value={s.name}>{s.name}</option>)}
                  </select>
                </div>
              </div>
              <div className="grid grid-cols-3 gap-4">
                <div>
                  <label className={labelCls}>アクション</label>
                  <select className={inputCls} value={policyForm.action} onChange={e => setPolicyForm(f => ({ ...f, action: e.target.value as Policy['action'] }))}>
                    <option value="allow">許可</option>
                    <option value="deny">拒否</option>
                    <option value="inspect">検査</option>
                  </select>
                </div>
                <div>
                  <label className={labelCls}>プロトコル</label>
                  <select className={inputCls} value={policyForm.protocol} onChange={e => setPolicyForm(f => ({ ...f, protocol: e.target.value }))}>
                    <option value="TCP">TCP</option>
                    <option value="UDP">UDP</option>
                    <option value="ICMP">ICMP</option>
                    <option value="ANY">ANY</option>
                  </select>
                </div>
                <div>
                  <label className={labelCls}>ポート</label>
                  <input className={inputCls} placeholder="80,443" value={policyForm.ports} onChange={e => setPolicyForm(f => ({ ...f, ports: e.target.value }))} />
                </div>
              </div>
              <div>
                <label className={labelCls}>説明</label>
                <input className={inputCls} placeholder="ポリシーの説明" value={policyForm.description} onChange={e => setPolicyForm(f => ({ ...f, description: e.target.value }))} />
              </div>
            </div>
            <div className="flex justify-end gap-3 px-6 py-4 border-t border-[#1e2d42]">
              <button onClick={() => setShowAddPolicy(false)} className="px-4 py-2 rounded text-sm text-[#7d92b0] hover:text-[#e2e8f4] transition-colors">キャンセル</button>
              <button
                onClick={() => addPolicyMutation.mutate(policyForm)}
                disabled={addPolicyMutation.isPending || !policyForm.from_segment || !policyForm.to_segment}
                className="flex items-center gap-2 px-5 py-2 rounded bg-[#e8002d] hover:bg-[#c0001f] text-white text-sm font-medium disabled:opacity-50 transition-colors"
              >
                {addPolicyMutation.isPending ? <Loader2 className="w-4 h-4 animate-spin" /> : <Plus className="w-4 h-4" />}
                追加
              </button>
            </div>
          </div>
        </div>
      )}

    </div>
  )
}

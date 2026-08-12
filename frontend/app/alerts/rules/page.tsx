'use client'

import { useState } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { apiFetch } from '@/lib/api'
import {
  SlidersHorizontal, Plus, Upload, Search, Filter,
  Shield, AlertTriangle, Info, CheckCircle, XCircle,
  ChevronDown, X, Zap, Clock, User,
  BookOpen, Bell, TrendingUp, ShieldOff, RefreshCw
} from 'lucide-react'
import { USE_MOCK, m } from '@/lib/mock'

// ── Types ──────────────────────────────────────────────────────

interface SigmaRule {
  id: string
  name: string
  severity: 'critical' | 'high' | 'medium' | 'low' | 'informational'
  platform: string
  enabled: boolean
  mitre_tags: string[] | null // API は ATT&CK タグ無しルールで null を返す(rules.mitre_tags は nullable)
  description?: string
  author?: string
  tags?: string[]
}

interface CustomAlertRule {
  id: string
  name: string
  severity: 'critical' | 'high' | 'medium' | 'low'
  event_type: 'process' | 'network' | 'file' | 'dns' | 'registry'
  enabled: boolean
  threshold: number
  time_window: number
  conditions: Array<{ field: string; operator: string; value: string }>
  description?: string
}

interface EscalationRule {
  id: string
  name: string
  trigger_severity: string
  target_severity: string
  conditions: string
  enabled: boolean
  delay_minutes?: number
}

interface SuppressionRule {
  id: string
  pattern: string
  reason: string
  created_by: string
  expires_at?: string
  created_at: string
  active: boolean
}

// ── Mock Data ──────────────────────────────────────────────────

const MOCK_SIGMA: SigmaRule[] = [
  { id: 's1', name: 'Mimikatz Credential Dumping', severity: 'critical', platform: 'windows', enabled: true, mitre_tags: ['T1003', 'TA0006'], description: 'Detects Mimikatz credential dumping activity' },
  { id: 's2', name: 'PowerShell Encoded Command', severity: 'high', platform: 'windows', enabled: true, mitre_tags: ['T1059.001', 'TA0002'] },
  { id: 's3', name: 'Suspicious Cron Job', severity: 'medium', platform: 'linux', enabled: false, mitre_tags: ['T1053.003', 'TA0003'] },
  { id: 's4', name: 'LSASS Memory Access', severity: 'critical', platform: 'windows', enabled: true, mitre_tags: ['T1003.001', 'TA0006'] },
  { id: 's5', name: 'Netcat Reverse Shell', severity: 'high', platform: 'linux', enabled: true, mitre_tags: ['T1059.004', 'TA0002'] },
  { id: 's6', name: 'WMI Lateral Movement', severity: 'high', platform: 'windows', enabled: true, mitre_tags: ['T1021.003', 'TA0008'] },
  { id: 's7', name: 'DNS Tunneling Detection', severity: 'medium', platform: 'all', enabled: false, mitre_tags: ['T1071.004', 'TA0011'] },
  { id: 's8', name: 'Suspicious Process Injection', severity: 'high', platform: 'windows', enabled: true, mitre_tags: ['T1055', 'TA0005'] },
]

const MOCK_CUSTOM: CustomAlertRule[] = [
  { id: 'c1', name: 'High Failed Login Rate', severity: 'high', event_type: 'process', enabled: true, threshold: 10, time_window: 5, conditions: [{ field: 'event_type', operator: 'eq', value: 'auth_failure' }] },
  { id: 'c2', name: 'Outbound Data Exfiltration', severity: 'critical', event_type: 'network', enabled: true, threshold: 100, time_window: 10, conditions: [{ field: 'bytes_sent', operator: 'gt', value: '10485760' }] },
  { id: 'c3', name: 'Suspicious File Creation in Temp', severity: 'medium', event_type: 'file', enabled: false, threshold: 5, time_window: 2, conditions: [{ field: 'path', operator: 'contains', value: '/tmp' }] },
  { id: 'c4', name: 'DNS Query to Known Bad Domain', severity: 'high', event_type: 'dns', enabled: true, threshold: 1, time_window: 60, conditions: [{ field: 'domain', operator: 'in', value: 'blocklist' }] },
]

const MOCK_ESCALATION: EscalationRule[] = [
  { id: 'e1', name: 'Critical → Immediate Page', trigger_severity: 'critical', target_severity: 'P1', conditions: 'No acknowledgment after 5min', enabled: true, delay_minutes: 5 },
  { id: 'e2', name: 'High → SOC Lead', trigger_severity: 'high', target_severity: 'P2', conditions: 'No triage after 15min', enabled: true, delay_minutes: 15 },
  { id: 'e3', name: 'Medium → Email Notify', trigger_severity: 'medium', target_severity: 'P3', conditions: 'Business hours only', enabled: false, delay_minutes: 30 },
]

const MOCK_SUPPRESSION: SuppressionRule[] = [
  { id: 'sup1', pattern: 'hostname:lab-test-*', reason: 'Lab environment - exclude from production', created_by: 'admin', expires_at: '2026-06-01T00:00:00Z', created_at: '2026-01-15T10:00:00Z', active: true },
  { id: 'sup2', pattern: 'rule:Windows Defender Scan', reason: 'Known false positive - AV scan activity', created_by: 'analyst1', expires_at: undefined, created_at: '2026-02-10T08:00:00Z', active: true },
  { id: 'sup3', pattern: 'ip:10.0.0.0/8', reason: 'Internal network monitoring exclusion', created_by: 'admin', expires_at: '2026-04-01T00:00:00Z', created_at: '2026-03-01T12:00:00Z', active: false },
]

// ── Helpers ─────────────────────────────────────────────────────

function SeverityBadge({ severity }: { severity: string }) {
  const cfg: Record<string, string> = {
    critical:      'bg-red-900/40 text-red-300 border-red-700/50',
    high:          'bg-orange-900/40 text-orange-300 border-orange-700/50',
    medium:        'bg-yellow-900/40 text-yellow-300 border-yellow-700/50',
    low:           'bg-blue-900/40 text-blue-300 border-blue-700/50',
    informational: 'bg-[#0d1220] text-[#7d92b0] border-[#1e2d42]',
    P1:            'bg-red-900/40 text-red-300 border-red-700/50',
    P2:            'bg-orange-900/40 text-orange-300 border-orange-700/50',
    P3:            'bg-yellow-900/40 text-yellow-300 border-yellow-700/50',
  }
  return (
    <span className={`inline-flex items-center px-2 py-0.5 rounded text-xs font-medium border ${cfg[severity] ?? 'bg-[#0d1220] text-[#7d92b0] border-[#1e2d42]'}`}>
      {severity}
    </span>
  )
}

function PlatformBadge({ platform }: { platform: string }) {
  const cfg: Record<string, string> = {
    windows: 'bg-blue-900/30 text-blue-300 border-blue-700/40',
    linux:   'bg-orange-900/30 text-orange-300 border-orange-700/40',
    macos:   'bg-purple-900/30 text-purple-300 border-purple-700/40',
    all:     'bg-[#0d1220] text-[#7d92b0] border-[#1e2d42]',
  }
  return (
    <span className={`inline-flex items-center px-2 py-0.5 rounded text-xs border ${cfg[platform] ?? 'bg-[#0d1220] text-[#7d92b0] border-[#1e2d42]'}`}>
      {platform}
    </span>
  )
}

function EventTypeBadge({ type }: { type: string }) {
  const cfg: Record<string, string> = {
    process:  'bg-green-900/30 text-green-300 border-green-700/40',
    network:  'bg-blue-900/30 text-blue-300 border-blue-700/40',
    file:     'bg-yellow-900/30 text-yellow-300 border-yellow-700/40',
    dns:      'bg-purple-900/30 text-purple-300 border-purple-700/40',
    registry: 'bg-orange-900/30 text-orange-300 border-orange-700/40',
  }
  return (
    <span className={`inline-flex items-center px-2 py-0.5 rounded text-xs border ${cfg[type] ?? 'bg-[#0d1220] text-[#7d92b0] border-[#1e2d42]'}`}>
      {type}
    </span>
  )
}

function ToggleSwitch({ enabled, onChange }: { enabled: boolean; onChange: () => void }) {
  return (
    <button
      onClick={onChange}
      className={`relative inline-flex h-5 w-9 items-center rounded-full transition-colors duration-200 focus:outline-none ${
        enabled ? 'bg-[#e8002d]' : 'bg-[#1e2d42]'
      }`}
    >
      <span
        className={`inline-block h-3.5 w-3.5 transform rounded-full bg-[#e2e8f4] transition-transform duration-200 ${
          enabled ? 'translate-x-5' : 'translate-x-1'
        }`}
      />
    </button>
  )
}

// ── Add Suppression Modal ──────────────────────────────────────

function AddSuppressionModal({ onClose, onAdd }: { onClose: () => void; onAdd: (s: Partial<SuppressionRule>) => void }) {
  const [pattern, setPattern] = useState('')
  const [reason, setReason] = useState('')
  const [expires, setExpires] = useState('')

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 backdrop-blur-sm">
      <div className="bg-[#0d1220] border border-[#1e2d42] rounded-xl w-full max-w-md p-6 shadow-2xl">
        <div className="flex items-center justify-between mb-5">
          <h3 className="text-white font-semibold flex items-center gap-2">
            <ShieldOff className="w-4 h-4 text-[#e8002d]" />
            抑制ルールを追加
          </h3>
          <button onClick={onClose} className="text-[#7d92b0] hover:text-white">
            <X className="w-4 h-4" />
          </button>
        </div>
        <div className="space-y-4">
          <div>
            <label className="block text-xs text-[#7d92b0] mb-1">パターン</label>
            <input
              value={pattern}
              onChange={e => setPattern(e.target.value)}
              placeholder="hostname:*, rule:rule-name, ip:1.2.3.4"
              className="w-full px-3 py-2 bg-[#070d19] border border-[#1e2d42] rounded-lg text-white text-sm placeholder-[#3d5068] focus:outline-none focus:border-[#e8002d]/50"
            />
          </div>
          <div>
            <label className="block text-xs text-[#7d92b0] mb-1">理由</label>
            <textarea
              value={reason}
              onChange={e => setReason(e.target.value)}
              placeholder="この抑制ルールの理由を記述..."
              rows={3}
              className="w-full px-3 py-2 bg-[#070d19] border border-[#1e2d42] rounded-lg text-white text-sm placeholder-[#3d5068] focus:outline-none focus:border-[#e8002d]/50 resize-none"
            />
          </div>
          <div>
            <label className="block text-xs text-[#7d92b0] mb-1">有効期限 (任意)</label>
            <input
              type="date"
              value={expires}
              onChange={e => setExpires(e.target.value)}
              className="w-full px-3 py-2 bg-[#070d19] border border-[#1e2d42] rounded-lg text-white text-sm focus:outline-none focus:border-[#e8002d]/50"
            />
          </div>
        </div>
        <div className="flex gap-3 mt-6">
          <button
            onClick={onClose}
            className="flex-1 px-4 py-2 bg-[#070d19] border border-[#1e2d42] text-[#7d92b0] rounded-lg text-sm hover:text-white hover:border-[#7d92b0]/40 transition-colors"
          >
            キャンセル
          </button>
          <button
            onClick={() => { onAdd({ pattern, reason, expires_at: expires || undefined }); onClose() }}
            disabled={!pattern || !reason}
            className="flex-1 px-4 py-2 bg-[#e8002d] text-white rounded-lg text-sm font-medium hover:bg-[#c0001f] transition-colors disabled:opacity-40 disabled:cursor-not-allowed"
          >
            追加
          </button>
        </div>
      </div>
    </div>
  )
}

// ── New Custom Rule Modal ──────────────────────────────────────

function NewCustomRuleModal({ onClose }: { onClose: () => void }) {
  const [name, setName] = useState('')
  const [severity, setSeverity] = useState('medium')
  const [eventType, setEventType] = useState('process')
  const [threshold, setThreshold] = useState('5')
  const [timeWindow, setTimeWindow] = useState('10')
  const [conditions, setConditions] = useState([{ field: '', operator: 'eq', value: '' }])

  function addCondition() {
    setConditions(c => [...c, { field: '', operator: 'eq', value: '' }])
  }
  function removeCondition(i: number) {
    setConditions(c => c.filter((_, idx) => idx !== i))
  }
  function updateCondition(i: number, key: string, val: string) {
    setConditions(c => c.map((cond, idx) => idx === i ? { ...cond, [key]: val } : cond))
  }

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 backdrop-blur-sm">
      <div className="bg-[#0d1220] border border-[#1e2d42] rounded-xl w-full max-w-2xl p-6 shadow-2xl max-h-[90vh] overflow-y-auto">
        <div className="flex items-center justify-between mb-5">
          <h3 className="text-white font-semibold flex items-center gap-2">
            <Bell className="w-4 h-4 text-[#e8002d]" />
            新しいカスタムアラートルール
          </h3>
          <button onClick={onClose} className="text-[#7d92b0] hover:text-white">
            <X className="w-4 h-4" />
          </button>
        </div>

        <div className="space-y-4">
          <div className="grid grid-cols-2 gap-4">
            <div>
              <label className="block text-xs text-[#7d92b0] mb-1">ルール名</label>
              <input
                value={name}
                onChange={e => setName(e.target.value)}
                placeholder="ルール名を入力..."
                className="w-full px-3 py-2 bg-[#070d19] border border-[#1e2d42] rounded-lg text-white text-sm placeholder-[#3d5068] focus:outline-none focus:border-[#e8002d]/50"
              />
            </div>
            <div>
              <label className="block text-xs text-[#7d92b0] mb-1">重要度</label>
              <select
                value={severity}
                onChange={e => setSeverity(e.target.value)}
                className="w-full px-3 py-2 bg-[#070d19] border border-[#1e2d42] rounded-lg text-white text-sm focus:outline-none focus:border-[#e8002d]/50"
              >
                {['critical','high','medium','low'].map(s => <option key={s} value={s}>{s}</option>)}
              </select>
            </div>
          </div>

          <div className="grid grid-cols-3 gap-4">
            <div>
              <label className="block text-xs text-[#7d92b0] mb-1">イベントタイプ</label>
              <select
                value={eventType}
                onChange={e => setEventType(e.target.value)}
                className="w-full px-3 py-2 bg-[#070d19] border border-[#1e2d42] rounded-lg text-white text-sm focus:outline-none focus:border-[#e8002d]/50"
              >
                {['process','network','file','dns','registry'].map(t => <option key={t} value={t}>{t}</option>)}
              </select>
            </div>
            <div>
              <label className="block text-xs text-[#7d92b0] mb-1">閾値 (件数)</label>
              <input
                type="number"
                value={threshold}
                onChange={e => setThreshold(e.target.value)}
                className="w-full px-3 py-2 bg-[#070d19] border border-[#1e2d42] rounded-lg text-white text-sm focus:outline-none focus:border-[#e8002d]/50"
              />
            </div>
            <div>
              <label className="block text-xs text-[#7d92b0] mb-1">時間窓 (分)</label>
              <input
                type="number"
                value={timeWindow}
                onChange={e => setTimeWindow(e.target.value)}
                className="w-full px-3 py-2 bg-[#070d19] border border-[#1e2d42] rounded-lg text-white text-sm focus:outline-none focus:border-[#e8002d]/50"
              />
            </div>
          </div>

          <div>
            <div className="flex items-center justify-between mb-2">
              <label className="text-xs text-[#7d92b0]">条件</label>
              <button onClick={addCondition} className="text-xs text-[#e8002d] hover:text-[#ff1a40] flex items-center gap-1">
                <Plus className="w-3 h-3" /> 条件を追加
              </button>
            </div>
            <div className="space-y-2">
              {conditions.map((cond, i) => (
                <div key={i} className="flex items-center gap-2">
                  <input
                    value={cond.field}
                    onChange={e => updateCondition(i, 'field', e.target.value)}
                    placeholder="フィールド"
                    className="flex-1 px-3 py-2 bg-[#070d19] border border-[#1e2d42] rounded-lg text-white text-xs placeholder-[#3d5068] focus:outline-none focus:border-[#e8002d]/50"
                  />
                  <select
                    value={cond.operator}
                    onChange={e => updateCondition(i, 'operator', e.target.value)}
                    className="px-2 py-2 bg-[#070d19] border border-[#1e2d42] rounded-lg text-white text-xs focus:outline-none focus:border-[#e8002d]/50"
                  >
                    {['eq','ne','gt','lt','contains','starts_with','ends_with','in'].map(op => <option key={op} value={op}>{op}</option>)}
                  </select>
                  <input
                    value={cond.value}
                    onChange={e => updateCondition(i, 'value', e.target.value)}
                    placeholder="値"
                    className="flex-1 px-3 py-2 bg-[#070d19] border border-[#1e2d42] rounded-lg text-white text-xs placeholder-[#3d5068] focus:outline-none focus:border-[#e8002d]/50"
                  />
                  {conditions.length > 1 && (
                    <button onClick={() => removeCondition(i)} className="text-[#7d92b0] hover:text-red-400">
                      <X className="w-4 h-4" />
                    </button>
                  )}
                </div>
              ))}
            </div>
          </div>
        </div>

        <div className="flex gap-3 mt-6">
          <button
            onClick={onClose}
            className="flex-1 px-4 py-2 bg-[#070d19] border border-[#1e2d42] text-[#7d92b0] rounded-lg text-sm hover:text-white hover:border-[#7d92b0]/40 transition-colors"
          >
            キャンセル
          </button>
          <button
            disabled={!name}
            onClick={onClose}
            className="flex-1 px-4 py-2 bg-[#e8002d] text-white rounded-lg text-sm font-medium hover:bg-[#c0001f] transition-colors disabled:opacity-40 disabled:cursor-not-allowed"
          >
            作成
          </button>
        </div>
      </div>
    </div>
  )
}

// ── Main Page ─────────────────────────────────────────────────

export default function AlertRulesPage() {
  const queryClient = useQueryClient()
  const [activeTab, setActiveTab] = useState<'sigma' | 'custom' | 'escalation' | 'suppression'>('sigma')
  const [search, setSearch] = useState('')
  const [severityFilter, setSeverityFilter] = useState<string>('all')
  const [enabledFilter, setEnabledFilter] = useState<string>('all')
  const [platformFilter, setPlatformFilter] = useState<string>('all')
  const [showSuppressionModal, setShowSuppressionModal] = useState(false)
  const [showCustomRuleModal, setShowCustomRuleModal] = useState(false)
  const [localSigma, setLocalSigma] = useState<SigmaRule[]>(m(MOCK_SIGMA))
  const [localCustom, setLocalCustom] = useState<CustomAlertRule[]>(m(MOCK_CUSTOM))
  const [localEscalation, setLocalEscalation] = useState<EscalationRule[]>(m(MOCK_ESCALATION))
  const [localSuppressions, setLocalSuppressions] = useState<SuppressionRule[]>(m(MOCK_SUPPRESSION))

  // API fetches with mock fallback
  // /api/v1/rules returns { rules: [...] }, not { data: [...] }
  const { data: sigmaData } = useQuery<{ rules: SigmaRule[] }>({
    queryKey: ['rules-sigma'],
    queryFn: () => apiFetch<{ rules: SigmaRule[] }>('/api/v1/rules?type=sigma&per_page=1000').catch(() => ({ rules: m(MOCK_SIGMA) })),
    staleTime: 60_000,
  })

  // /api/v1/admin/custom-alert-rules returns { rules: [...] }
  const { data: customData } = useQuery<{ rules: CustomAlertRule[] }>({
    queryKey: ['custom-alert-rules'],
    queryFn: () => apiFetch<{ rules: CustomAlertRule[] }>('/api/v1/admin/custom-alert-rules').catch(() => ({ rules: m(MOCK_CUSTOM) })),
    staleTime: 60_000,
  })

  const { data: escalationData } = useQuery<{ data: EscalationRule[] }>({
    queryKey: ['escalation-rules'],
    // The API lives at /escalation-rules (not /admin/...). Falling back to mock
    // rules masked the 404 with fabricated data, so fail to an empty list instead.
    queryFn: () => apiFetch<{ data: EscalationRule[] }>('/api/v1/escalation-rules').catch(() => ({ data: [] })),
    staleTime: 60_000,
  })

  const { data: suppressionData } = useQuery<{ data: SuppressionRule[] }>({
    queryKey: ['suppressions'],
    queryFn: () => apiFetch<{ data: SuppressionRule[] }>('/api/v1/suppressions').catch(() => ({ data: m(MOCK_SUPPRESSION) })),
    staleTime: 60_000,
  })

  const sigmaRules = sigmaData?.rules ?? localSigma
  const customRules = customData?.rules ?? localCustom
  const escalationRules = escalationData?.data ?? localEscalation
  const suppressionRules = suppressionData?.data ?? localSuppressions

  // Stats
  const totalRules = sigmaRules.length + customRules.length + escalationRules.length
  const enabledRules = sigmaRules.filter(r => r.enabled).length + customRules.filter(r => r.enabled).length + escalationRules.filter(r => r.enabled).length
  const sigmaCount = sigmaRules.length
  const customCount = customRules.length

  // Toggle handlers (local optimistic)
  function toggleSigma(id: string) {
    setLocalSigma(rules => rules.map(r => r.id === id ? { ...r, enabled: !r.enabled } : r))
  }
  function toggleCustom(id: string) {
    setLocalCustom(rules => rules.map(r => r.id === id ? { ...r, enabled: !r.enabled } : r))
  }
  function toggleEscalation(id: string) {
    // Optimistic local flip + real persistence (the API exists at /escalation-rules).
    setLocalEscalation(rules => rules.map(r => r.id === id ? { ...r, enabled: !r.enabled } : r))
    apiFetch(`/api/v1/escalation-rules/${id}/toggle`, { method: 'PATCH' })
      .then(() => queryClient.invalidateQueries({ queryKey: ['escalation-rules'] }))
      .catch(() => {})
  }
  function toggleSuppression(id: string) {
    setLocalSuppressions(rules => rules.map(r => r.id === id ? { ...r, active: !r.active } : r))
  }

  // Filtered sigma
  const filteredSigma = sigmaRules.filter(r => {
    if (search && !r.name.toLowerCase().includes(search.toLowerCase())) return false
    if (severityFilter !== 'all' && r.severity !== severityFilter) return false
    if (enabledFilter !== 'all' && String(r.enabled) !== enabledFilter) return false
    if (platformFilter !== 'all' && r.platform !== platformFilter) return false
    return true
  })

  const filteredCustom = customRules.filter(r => {
    if (search && !r.name.toLowerCase().includes(search.toLowerCase())) return false
    if (severityFilter !== 'all' && r.severity !== severityFilter) return false
    if (enabledFilter !== 'all' && String(r.enabled) !== enabledFilter) return false
    return true
  })

  const filteredEscalation = escalationRules.filter(r => {
    if (search && !r.name.toLowerCase().includes(search.toLowerCase())) return false
    if (enabledFilter !== 'all' && String(r.enabled) !== enabledFilter) return false
    return true
  })

  const filteredSuppressions = suppressionRules.filter(r => {
    if (search && !r.pattern.toLowerCase().includes(search.toLowerCase()) && !r.reason.toLowerCase().includes(search.toLowerCase())) return false
    return true
  })

  const tabs = [
    { id: 'sigma' as const, label: 'Sigmaルール', icon: BookOpen, count: sigmaRules.length },
    { id: 'custom' as const, label: 'カスタムルール', icon: Bell, count: customRules.length },
    { id: 'escalation' as const, label: 'エスカレーション', icon: TrendingUp, count: escalationRules.length },
    { id: 'suppression' as const, label: '抑制ルール', icon: ShieldOff, count: suppressionRules.length },
  ]

  return (
    <div className="min-h-screen bg-[#070d19] p-6 space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-white flex items-center gap-2.5">
            <SlidersHorizontal className="w-6 h-6 text-[#e8002d]" />
            アラートルール管理
          </h1>
          <p className="text-[#7d92b0] text-sm mt-1">
            Sigma、カスタム、エスカレーション、抑制ルールの統合管理
          </p>
        </div>
        <button
          onClick={() => queryClient.invalidateQueries({ queryKey: ['rules-sigma'] })}
          className="flex items-center gap-2 px-3 py-2 bg-[#0d1220] border border-[#1e2d42] text-[#7d92b0] rounded-lg text-sm hover:text-white hover:border-[#7d92b0]/40 transition-colors"
        >
          <RefreshCw className="w-4 h-4" />
          更新
        </button>
      </div>

      {/* Summary Stats */}
      <div className="grid grid-cols-4 gap-4">
        {[
          { label: '総ルール数', value: totalRules, icon: SlidersHorizontal, color: 'text-[#e8002d]', bg: 'bg-red-900/10 border-red-900/30' },
          { label: '有効ルール', value: enabledRules, icon: CheckCircle, color: 'text-green-400', bg: 'bg-green-900/10 border-green-900/30' },
          { label: 'Sigmaルール', value: sigmaCount, icon: BookOpen, color: 'text-blue-400', bg: 'bg-blue-900/10 border-blue-900/30' },
          { label: 'カスタムルール', value: customCount, icon: Bell, color: 'text-yellow-400', bg: 'bg-yellow-900/10 border-yellow-900/30' },
        ].map(stat => (
          <div key={stat.label} className={`bg-[#0d1220] border rounded-xl p-4 ${stat.bg}`}>
            <div className="flex items-center justify-between mb-2">
              <span className="text-xs text-[#7d92b0]">{stat.label}</span>
              <stat.icon className={`w-4 h-4 ${stat.color}`} />
            </div>
            <p className={`text-2xl font-bold ${stat.color}`}>{stat.value}</p>
          </div>
        ))}
      </div>

      {/* Tabs */}
      <div className="flex items-center gap-1 bg-[#0d1220] border border-[#1e2d42] rounded-xl p-1">
        {tabs.map(tab => (
          <button
            key={tab.id}
            onClick={() => setActiveTab(tab.id)}
            className={`flex items-center gap-2 px-4 py-2 rounded-lg text-sm font-medium transition-all flex-1 justify-center ${
              activeTab === tab.id
                ? 'bg-[#e8002d] text-white shadow'
                : 'text-[#7d92b0] hover:text-white hover:bg-[#1e2d42]/40'
            }`}
          >
            <tab.icon className="w-4 h-4" />
            {tab.label}
            <span className={`text-xs px-1.5 py-0.5 rounded-full ${
              activeTab === tab.id ? 'bg-white/20 text-white' : 'bg-[#1e2d42] text-[#7d92b0]'
            }`}>
              {tab.count}
            </span>
          </button>
        ))}
      </div>

      {/* Filters Row */}
      <div className="flex items-center gap-3 flex-wrap">
        <div className="relative flex-1 min-w-[200px] max-w-xs">
          <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-[#3d5068]" />
          <input
            value={search}
            onChange={e => setSearch(e.target.value)}
            placeholder="ルール名で検索..."
            className="w-full pl-9 pr-4 py-2 bg-[#0d1220] border border-[#1e2d42] rounded-lg text-white text-sm placeholder-[#3d5068] focus:outline-none focus:border-[#e8002d]/50"
          />
        </div>
        <div className="flex items-center gap-2">
          <Filter className="w-4 h-4 text-[#3d5068]" />
          <select
            value={severityFilter}
            onChange={e => setSeverityFilter(e.target.value)}
            className="px-3 py-2 bg-[#0d1220] border border-[#1e2d42] rounded-lg text-[#7d92b0] text-sm focus:outline-none focus:border-[#e8002d]/50"
          >
            <option value="all">全重要度</option>
            {['critical','high','medium','low','informational'].map(s => <option key={s} value={s}>{s}</option>)}
          </select>
          <select
            value={enabledFilter}
            onChange={e => setEnabledFilter(e.target.value)}
            className="px-3 py-2 bg-[#0d1220] border border-[#1e2d42] rounded-lg text-[#7d92b0] text-sm focus:outline-none focus:border-[#e8002d]/50"
          >
            <option value="all">全ステータス</option>
            <option value="true">有効</option>
            <option value="false">無効</option>
          </select>
          {activeTab === 'sigma' && (
            <select
              value={platformFilter}
              onChange={e => setPlatformFilter(e.target.value)}
              className="px-3 py-2 bg-[#0d1220] border border-[#1e2d42] rounded-lg text-[#7d92b0] text-sm focus:outline-none focus:border-[#e8002d]/50"
            >
              <option value="all">全プラットフォーム</option>
              {['windows','linux','macos','all'].map(p => <option key={p} value={p}>{p}</option>)}
            </select>
          )}
        </div>

        {/* Tab-specific action buttons */}
        <div className="ml-auto flex items-center gap-2">
          {activeTab === 'sigma' && (
            <a
              href="/rules"
              className="flex items-center gap-2 px-3 py-2 bg-[#e8002d]/10 border border-[#e8002d]/30 text-[#e8002d] rounded-lg text-sm hover:bg-[#e8002d]/20 transition-colors"
            >
              <Upload className="w-4 h-4" />
              インポート
            </a>
          )}
          {activeTab === 'custom' && (
            <button
              onClick={() => setShowCustomRuleModal(true)}
              className="flex items-center gap-2 px-3 py-2 bg-[#e8002d] text-white rounded-lg text-sm font-medium hover:bg-[#c0001f] transition-colors"
            >
              <Plus className="w-4 h-4" />
              新規ルール
            </button>
          )}
          {activeTab === 'suppression' && (
            <button
              onClick={() => setShowSuppressionModal(true)}
              className="flex items-center gap-2 px-3 py-2 bg-[#e8002d] text-white rounded-lg text-sm font-medium hover:bg-[#c0001f] transition-colors"
            >
              <Plus className="w-4 h-4" />
              抑制を追加
            </button>
          )}
        </div>
      </div>

      {/* ── Tab Content ── */}

      {/* Tab 1: Sigma Rules */}
      {activeTab === 'sigma' && (
        <div className="bg-[#0d1220] border border-[#1e2d42] rounded-xl overflow-hidden">
          <table className="w-full">
            <thead>
              <tr className="border-b border-[#1e2d42]">
                <th className="text-left px-4 py-3 text-xs text-[#7d92b0] font-medium">ルール名</th>
                <th className="text-left px-4 py-3 text-xs text-[#7d92b0] font-medium">重要度</th>
                <th className="text-left px-4 py-3 text-xs text-[#7d92b0] font-medium">プラットフォーム</th>
                <th className="text-left px-4 py-3 text-xs text-[#7d92b0] font-medium">MITREタグ</th>
                <th className="text-left px-4 py-3 text-xs text-[#7d92b0] font-medium">有効</th>
                <th className="text-right px-4 py-3 text-xs text-[#7d92b0] font-medium">アクション</th>
              </tr>
            </thead>
            <tbody>
              {filteredSigma.length === 0 ? (
                <tr>
                  <td colSpan={6} className="text-center py-12 text-[#7d92b0] text-sm">
                    ルールが見つかりません
                  </td>
                </tr>
              ) : filteredSigma.map((rule, i) => (
                <tr key={rule.id} className={`border-b border-[#1e2d42]/60 hover:bg-[#070d19]/50 transition-colors ${i % 2 === 0 ? '' : 'bg-[#070d19]/20'}`}>
                  <td className="px-4 py-3">
                    <p className="text-white text-sm font-medium">{rule.name}</p>
                    {rule.description && <p className="text-[#7d92b0] text-xs mt-0.5 truncate max-w-xs">{rule.description}</p>}
                  </td>
                  <td className="px-4 py-3"><SeverityBadge severity={rule.severity} /></td>
                  <td className="px-4 py-3"><PlatformBadge platform={rule.platform} /></td>
                  <td className="px-4 py-3">
                    <div className="flex flex-wrap gap-1">
                      {(rule.mitre_tags ?? []).slice(0, 3).map(tag => (
                        <span key={tag} className="text-xs px-1.5 py-0.5 bg-[#070d19] border border-[#1e2d42] rounded text-[#7d92b0] font-mono">
                          {tag}
                        </span>
                      ))}
                    </div>
                  </td>
                  <td className="px-4 py-3">
                    <ToggleSwitch enabled={rule.enabled} onChange={() => toggleSigma(rule.id)} />
                  </td>
                  <td className="px-4 py-3 text-right">
                    <button className="text-xs text-[#7d92b0] hover:text-white px-2 py-1 rounded hover:bg-[#1e2d42] transition-colors">
                      詳細
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}

      {/* Tab 2: Custom Alert Rules */}
      {activeTab === 'custom' && (
        <div className="bg-[#0d1220] border border-[#1e2d42] rounded-xl overflow-hidden">
          <table className="w-full">
            <thead>
              <tr className="border-b border-[#1e2d42]">
                <th className="text-left px-4 py-3 text-xs text-[#7d92b0] font-medium">ルール名</th>
                <th className="text-left px-4 py-3 text-xs text-[#7d92b0] font-medium">重要度</th>
                <th className="text-left px-4 py-3 text-xs text-[#7d92b0] font-medium">イベントタイプ</th>
                <th className="text-left px-4 py-3 text-xs text-[#7d92b0] font-medium">閾値 / 時間窓</th>
                <th className="text-left px-4 py-3 text-xs text-[#7d92b0] font-medium">有効</th>
                <th className="text-right px-4 py-3 text-xs text-[#7d92b0] font-medium">アクション</th>
              </tr>
            </thead>
            <tbody>
              {filteredCustom.length === 0 ? (
                <tr>
                  <td colSpan={6} className="text-center py-12 text-[#7d92b0] text-sm">
                    ルールが見つかりません
                  </td>
                </tr>
              ) : filteredCustom.map((rule, i) => (
                <tr key={rule.id} className={`border-b border-[#1e2d42]/60 hover:bg-[#070d19]/50 transition-colors ${i % 2 === 0 ? '' : 'bg-[#070d19]/20'}`}>
                  <td className="px-4 py-3">
                    <p className="text-white text-sm font-medium">{rule.name}</p>
                    {rule.conditions.length > 0 && (
                      <p className="text-[#7d92b0] text-xs mt-0.5">
                        {rule.conditions[0].field} {rule.conditions[0].operator} {rule.conditions[0].value}
                        {rule.conditions.length > 1 && ` +${rule.conditions.length - 1}件`}
                      </p>
                    )}
                  </td>
                  <td className="px-4 py-3"><SeverityBadge severity={rule.severity} /></td>
                  <td className="px-4 py-3"><EventTypeBadge type={rule.event_type} /></td>
                  <td className="px-4 py-3">
                    <span className="text-sm text-white">{rule.threshold}件</span>
                    <span className="text-xs text-[#7d92b0] ml-1">/ {rule.time_window}分</span>
                  </td>
                  <td className="px-4 py-3">
                    <ToggleSwitch enabled={rule.enabled} onChange={() => toggleCustom(rule.id)} />
                  </td>
                  <td className="px-4 py-3 text-right flex items-center gap-2 justify-end">
                    <button className="text-xs text-[#7d92b0] hover:text-white px-2 py-1 rounded hover:bg-[#1e2d42] transition-colors">
                      編集
                    </button>
                    <button className="text-xs text-red-400/70 hover:text-red-400 px-2 py-1 rounded hover:bg-red-900/20 transition-colors">
                      削除
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}

      {/* Tab 3: Escalation Rules */}
      {activeTab === 'escalation' && (
        <div className="bg-[#0d1220] border border-[#1e2d42] rounded-xl overflow-hidden">
          <table className="w-full">
            <thead>
              <tr className="border-b border-[#1e2d42]">
                <th className="text-left px-4 py-3 text-xs text-[#7d92b0] font-medium">ルール名</th>
                <th className="text-left px-4 py-3 text-xs text-[#7d92b0] font-medium">トリガー重要度</th>
                <th className="text-left px-4 py-3 text-xs text-[#7d92b0] font-medium">エスカレーション先</th>
                <th className="text-left px-4 py-3 text-xs text-[#7d92b0] font-medium">条件</th>
                <th className="text-left px-4 py-3 text-xs text-[#7d92b0] font-medium">遅延</th>
                <th className="text-left px-4 py-3 text-xs text-[#7d92b0] font-medium">有効</th>
              </tr>
            </thead>
            <tbody>
              {filteredEscalation.length === 0 ? (
                <tr>
                  <td colSpan={6} className="text-center py-12 text-[#7d92b0] text-sm">
                    ルールが見つかりません
                  </td>
                </tr>
              ) : filteredEscalation.map((rule, i) => (
                <tr key={rule.id} className={`border-b border-[#1e2d42]/60 hover:bg-[#070d19]/50 transition-colors ${i % 2 === 0 ? '' : 'bg-[#070d19]/20'}`}>
                  <td className="px-4 py-3">
                    <p className="text-white text-sm font-medium">{rule.name}</p>
                  </td>
                  <td className="px-4 py-3"><SeverityBadge severity={rule.trigger_severity} /></td>
                  <td className="px-4 py-3"><SeverityBadge severity={rule.target_severity} /></td>
                  <td className="px-4 py-3">
                    <span className="text-xs text-[#7d92b0]">{rule.conditions}</span>
                  </td>
                  <td className="px-4 py-3">
                    {rule.delay_minutes != null && (
                      <span className="flex items-center gap-1 text-xs text-[#7d92b0]">
                        <Clock className="w-3 h-3" />
                        {rule.delay_minutes}分
                      </span>
                    )}
                  </td>
                  <td className="px-4 py-3">
                    <ToggleSwitch enabled={rule.enabled} onChange={() => toggleEscalation(rule.id)} />
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}

      {/* Tab 4: Suppression Rules */}
      {activeTab === 'suppression' && (
        <div className="bg-[#0d1220] border border-[#1e2d42] rounded-xl overflow-hidden">
          <table className="w-full">
            <thead>
              <tr className="border-b border-[#1e2d42]">
                <th className="text-left px-4 py-3 text-xs text-[#7d92b0] font-medium">パターン / キーワード</th>
                <th className="text-left px-4 py-3 text-xs text-[#7d92b0] font-medium">理由</th>
                <th className="text-left px-4 py-3 text-xs text-[#7d92b0] font-medium">作成者</th>
                <th className="text-left px-4 py-3 text-xs text-[#7d92b0] font-medium">有効期限</th>
                <th className="text-left px-4 py-3 text-xs text-[#7d92b0] font-medium">有効</th>
                <th className="text-right px-4 py-3 text-xs text-[#7d92b0] font-medium">アクション</th>
              </tr>
            </thead>
            <tbody>
              {filteredSuppressions.length === 0 ? (
                <tr>
                  <td colSpan={6} className="text-center py-12 text-[#7d92b0] text-sm">
                    抑制ルールが見つかりません
                  </td>
                </tr>
              ) : filteredSuppressions.map((rule, i) => (
                <tr key={rule.id} className={`border-b border-[#1e2d42]/60 hover:bg-[#070d19]/50 transition-colors ${i % 2 === 0 ? '' : 'bg-[#070d19]/20'}`}>
                  <td className="px-4 py-3">
                    <code className="text-sm text-[#e8002d] font-mono bg-[#070d19] px-2 py-0.5 rounded border border-[#1e2d42]">
                      {rule.pattern}
                    </code>
                  </td>
                  <td className="px-4 py-3">
                    <span className="text-sm text-[#7d92b0]">{rule.reason}</span>
                  </td>
                  <td className="px-4 py-3">
                    <span className="flex items-center gap-1 text-xs text-[#7d92b0]">
                      <User className="w-3 h-3" />
                      {rule.created_by}
                    </span>
                  </td>
                  <td className="px-4 py-3">
                    {rule.expires_at ? (
                      <span className="flex items-center gap-1 text-xs text-[#7d92b0]">
                        <Clock className="w-3 h-3" />
                        {new Date(rule.expires_at).toLocaleDateString('ja-JP')}
                      </span>
                    ) : (
                      <span className="text-xs text-[#3d5068]">無期限</span>
                    )}
                  </td>
                  <td className="px-4 py-3">
                    <ToggleSwitch enabled={rule.active} onChange={() => toggleSuppression(rule.id)} />
                  </td>
                  <td className="px-4 py-3 text-right">
                    <button className="text-xs text-red-400/70 hover:text-red-400 px-2 py-1 rounded hover:bg-red-900/20 transition-colors">
                      削除
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}

      {/* Modals */}
      {showSuppressionModal && (
        <AddSuppressionModal
          onClose={() => setShowSuppressionModal(false)}
          onAdd={(s) => {
            setLocalSuppressions(prev => [...prev, {
              id: `sup${Date.now()}`,
              pattern: s.pattern ?? '',
              reason: s.reason ?? '',
              created_by: 'current_user',
              expires_at: s.expires_at,
              created_at: new Date().toISOString(),
              active: true,
            }])
          }}
        />
      )}
      {showCustomRuleModal && (
        <NewCustomRuleModal onClose={() => setShowCustomRuleModal(false)} />
      )}
    </div>
  )
}

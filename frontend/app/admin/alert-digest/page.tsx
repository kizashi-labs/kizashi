'use client'

import { useState } from 'react'
import { useQuery, useMutation } from '@tanstack/react-query'
import { apiFetch } from '@/lib/api'
import {
  Mail, Send, CheckCircle, Loader2, X, Plus, Clock,
  Calendar, Users, BarChart3, Eye, ChevronDown,
  AlertTriangle, Shield, Activity,
} from 'lucide-react'


// ── Types ─────────────────────────────────────────────────────────────────────

interface DigestRecipient {
  email: string
}

interface DailyDigestConfig {
  enabled: boolean
  send_time: string
  recipients: string[]
  min_severity: number
  sections: {
    alert_counts: boolean
    top_agents: boolean
    top_alert_types: boolean
    open_incidents: boolean
    compliance_score: boolean
  }
}

interface WeeklyDigestConfig {
  enabled: boolean
  day_of_week: string
  send_time: string
  recipients: string[]
  extra_sections: {
    agent_health: boolean
    vulnerability_summary: boolean
    soc_ticket_summary: boolean
  }
}

interface DigestConfig {
  daily: DailyDigestConfig
  weekly: WeeklyDigestConfig
}

interface DigestHistory {
  id: string
  type: 'daily' | 'weekly'
  sent_at: string
  recipients_count: number
  total_alerts: number
  status: 'delivered' | 'failed' | 'partial'
}

interface DigestStats {
  sent_this_month: number
  recipients: number
  last_sent: string
  next_scheduled: string
}

const EMPTY_CONFIG: DigestConfig = {
  daily: {
    enabled: false,
    send_time: '08:00',
    recipients: [],
    min_severity: 2,
    sections: {
      alert_counts: false,
      top_agents: false,
      top_alert_types: false,
      open_incidents: false,
      compliance_score: false,
    },
  },
  weekly: {
    enabled: false,
    day_of_week: 'Monday',
    send_time: '08:00',
    recipients: [],
    extra_sections: {
      agent_health: false,
      vulnerability_summary: false,
      soc_ticket_summary: false,
    },
  },
}

// ── Sub-components ────────────────────────────────────────────────────────────

function Toggle({
  checked,
  onChange,
}: {
  checked: boolean
  onChange: (v: boolean) => void
}) {
  return (
    <button
      type="button"
      role="switch"
      aria-checked={checked}
      onClick={() => onChange(!checked)}
      className={`relative w-10 h-5 rounded-full transition-colors duration-200 ${
        checked ? 'bg-[#e8002d]' : 'bg-[#1e2d42]'
      }`}
    >
      <span
        className={`absolute top-0.5 w-4 h-4 rounded-full bg-[#e2e8f4] shadow transition-transform duration-200 ${
          checked ? 'translate-x-5' : 'translate-x-0.5'
        }`}
      />
    </button>
  )
}

function StatCard({
  label,
  value,
  icon: Icon,
  sub,
}: {
  label: string
  value: string | number
  icon: React.ElementType
  sub?: string
}) {
  return (
    <div className="bg-[#0d1220] border border-[#1e2d42] rounded-lg p-4 flex items-start gap-3">
      <div className="w-9 h-9 rounded-lg bg-[#1e2d42] flex items-center justify-center flex-shrink-0">
        <Icon className="w-4.5 h-4.5 text-[#e8002d]" />
      </div>
      <div>
        <p className="text-xl font-bold text-[#e2e8f4]">{value}</p>
        <p className="text-xs text-[#7d92b0]">{label}</p>
        {sub && <p className="text-[10px] text-[#3d5068] mt-0.5">{sub}</p>}
      </div>
    </div>
  )
}

function EmailTagInput({
  emails,
  onChange,
}: {
  emails: string[]
  onChange: (emails: string[]) => void
}) {
  const [input, setInput] = useState('')

  const addEmail = () => {
    const trimmed = input.trim()
    if (trimmed && !emails.includes(trimmed)) {
      onChange([...emails, trimmed])
      setInput('')
    }
  }

  const removeEmail = (email: string) => {
    onChange(emails.filter((e) => e !== email))
  }

  return (
    <div className="flex flex-wrap gap-2 p-2 rounded bg-[#070d19] border border-[#1e2d42] min-h-[42px]">
      {emails.map((email) => (
        <span
          key={email}
          className="flex items-center gap-1.5 px-2 py-1 rounded bg-[#1e2d42] text-xs text-[#e2e8f4]"
        >
          {email}
          <button
            onClick={() => removeEmail(email)}
            className="text-[#7d92b0] hover:text-[#e8002d] transition-colors"
          >
            <X className="w-3 h-3" />
          </button>
        </span>
      ))}
      <input
        type="email"
        value={input}
        onChange={(e) => setInput(e.target.value)}
        onKeyDown={(e) => {
          if (e.key === 'Enter' || e.key === ',') {
            e.preventDefault()
            addEmail()
          }
        }}
        placeholder="メールアドレスを追加..."
        className="flex-1 min-w-[180px] bg-transparent text-sm text-[#e2e8f4] placeholder-[#3d5068] focus:outline-none"
      />
      <button
        onClick={addEmail}
        className="p-1 rounded hover:bg-[#1e2d42] text-[#7d92b0] hover:text-[#e2e8f4] transition-colors"
      >
        <Plus className="w-3.5 h-3.5" />
      </button>
    </div>
  )
}

function StatusBadge({ status }: { status: DigestHistory['status'] }) {
  const map = {
    delivered: { label: '配信済み', cls: 'text-[#00c853] bg-[#00c853]/10 border-[#00c853]/20' },
    partial: { label: '一部配信', cls: 'text-yellow-400 bg-yellow-400/10 border-yellow-400/20' },
    failed: { label: '失敗', cls: 'text-[#e8002d] bg-[#e8002d]/10 border-[#e8002d]/20' },
  }
  const { label, cls } = map[status]
  return (
    <span className={`px-2 py-0.5 rounded text-xs font-medium border ${cls}`}>{label}</span>
  )
}

// ── Preview Modal ─────────────────────────────────────────────────────────────

function DigestPreviewModal({
  record,
  onClose,
}: {
  record: DigestHistory
  onClose: () => void
}) {
  const date = new Date(record.sent_at)
  const dateStr = date.toLocaleDateString('ja-JP', {
    year: 'numeric',
    month: 'long',
    day: 'numeric',
  })
  const typeLabel = record.type === 'daily' ? '日次ダイジェスト' : '週次ダイジェスト'

  const mockAlerts = [
    { severity: 'Critical', count: 3, color: 'text-[#e8002d]' },
    { severity: 'High', count: 11, color: 'text-orange-400' },
    { severity: 'Medium', count: 22, color: 'text-yellow-400' },
    { severity: 'Low', count: 11, color: 'text-[#7d92b0]' },
  ]
  const mockAgents = [
    { name: 'WORKSTATION-042', alerts: 8 },
    { name: 'SERVER-DC-01', alerts: 6 },
    { name: 'LAPTOP-HR-007', alerts: 5 },
    { name: 'SERVER-WEB-02', alerts: 4 },
    { name: 'WORKSTATION-019', alerts: 3 },
  ]

  return (
    <div
      className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 backdrop-blur-sm"
      onClick={onClose}
    >
      <div
        className="w-full max-w-xl bg-[#0d1220] border border-[#1e2d42] rounded-xl shadow-2xl overflow-hidden"
        onClick={(e) => e.stopPropagation()}
      >
        {/* Modal header */}
        <div className="flex items-center justify-between px-5 py-4 border-b border-[#1e2d42]">
          <div className="flex items-center gap-2">
            <Eye className="w-4 h-4 text-[#e8002d]" />
            <span className="text-[#e2e8f4] font-semibold text-sm">ダイジェストプレビュー</span>
          </div>
          <button
            onClick={onClose}
            className="p-1 rounded hover:bg-[#1e2d42] text-[#7d92b0] hover:text-[#e2e8f4] transition-colors"
          >
            <X className="w-4 h-4" />
          </button>
        </div>

        {/* Preview content */}
        <div className="p-5 max-h-[70vh] overflow-y-auto space-y-4">
          {/* Email header */}
          <div className="p-4 rounded-lg bg-gradient-to-r from-[#e8002d]/20 to-[#070d19] border border-[#e8002d]/30">
            <div className="flex items-center gap-2 mb-1">
              <Shield className="w-5 h-5 text-[#e8002d]" />
              <span className="font-bold text-[#e2e8f4]">Kizashi — {typeLabel}</span>
            </div>
            <p className="text-xs text-[#7d92b0]">{dateStr}</p>
          </div>

          {/* Stats row */}
          <div className="grid grid-cols-3 gap-3">
            <div className="p-3 rounded bg-[#070d19] border border-[#1e2d42] text-center">
              <p className="text-xl font-bold text-[#e2e8f4]">{record.total_alerts}</p>
              <p className="text-[10px] text-[#7d92b0]">総アラート</p>
            </div>
            <div className="p-3 rounded bg-[#070d19] border border-[#1e2d42] text-center">
              <p className="text-xl font-bold text-[#e8002d]">3</p>
              <p className="text-[10px] text-[#7d92b0]">Critical</p>
            </div>
            <div className="p-3 rounded bg-[#070d19] border border-[#1e2d42] text-center">
              <p className="text-xl font-bold text-orange-400">2</p>
              <p className="text-[10px] text-[#7d92b0]">未解決インシデント</p>
            </div>
          </div>

          {/* Alert breakdown */}
          <div>
            <p className="text-xs font-semibold text-[#7d92b0] uppercase tracking-wide mb-2">
              重要度別アラート
            </p>
            <div className="rounded bg-[#070d19] border border-[#1e2d42] overflow-hidden">
              <table className="w-full text-sm">
                <thead>
                  <tr className="border-b border-[#1e2d42]">
                    <th className="px-3 py-2 text-left text-xs text-[#7d92b0] font-medium">重要度</th>
                    <th className="px-3 py-2 text-right text-xs text-[#7d92b0] font-medium">件数</th>
                  </tr>
                </thead>
                <tbody>
                  {mockAlerts.map((a) => (
                    <tr key={a.severity} className="border-b border-[#1e2d42] last:border-0">
                      <td className={`px-3 py-2 font-medium text-xs ${a.color}`}>{a.severity}</td>
                      <td className="px-3 py-2 text-right text-xs text-[#e2e8f4]">{a.count}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>

          {/* Top agents */}
          <div>
            <p className="text-xs font-semibold text-[#7d92b0] uppercase tracking-wide mb-2">
              トップ5エージェント
            </p>
            <div className="space-y-1.5">
              {mockAgents.map((a, i) => (
                <div
                  key={a.name}
                  className="flex items-center gap-3 p-2 rounded bg-[#070d19] border border-[#1e2d42]"
                >
                  <span className="text-xs text-[#3d5068] w-4">{i + 1}.</span>
                  <span className="text-xs text-[#e2e8f4] font-mono flex-1">{a.name}</span>
                  <span className="text-xs font-bold text-[#e8002d]">{a.alerts} alerts</span>
                </div>
              ))}
            </div>
          </div>

          {/* Footer */}
          <div className="p-3 rounded bg-[#070d19] border border-[#1e2d42] text-center">
            <p className="text-xs text-[#7d92b0]">
              詳細はダッシュボードで確認 —{' '}
              <span className="text-[#e8002d] font-medium">Kizashi</span>
            </p>
          </div>
        </div>
      </div>
    </div>
  )
}

// ── Main Page ─────────────────────────────────────────────────────────────────

export default function AlertDigestPage() {
  const [tab, setTab] = useState<'settings' | 'history'>('settings')
  const [config, setConfig] = useState<DigestConfig>(EMPTY_CONFIG)
  const [toast, setToast] = useState<string | null>(null)
  const [previewRecord, setPreviewRecord] = useState<DigestHistory | null>(null)
  const [sendingPeriod, setSendingPeriod] = useState<string | null>(null)

  const { data: serverConfig } = useQuery<DigestConfig>({
    queryKey: ['digest-config'],
    queryFn: async () => {
      try {
        const res = await apiFetch('/api/v1/admin/digest/config')
        const cfg = (res && 'daily' in (res as any)) ? res as DigestConfig : null
        if (cfg) setConfig(cfg)
        return cfg ?? EMPTY_CONFIG
      } catch { return EMPTY_CONFIG }
    },
    retry: false,
    staleTime: 60_000,
  } as any)

  const { data: history } = useQuery<DigestHistory[]>({
    queryKey: ['digest-history'],
    queryFn: () => apiFetch('/api/v1/admin/digest/history'),
    retry: false,
    staleTime: 60_000,
  } as any)

  const { data: stats } = useQuery<DigestStats>({
    queryKey: ['digest-stats'],
    queryFn: () => apiFetch('/api/v1/admin/digest/stats'),
    retry: false,
    staleTime: 60_000,
  } as any)

  const saveMutation = useMutation({
    mutationFn: (cfg: DigestConfig) =>
      apiFetch('/api/v1/admin/digest/config', {
        method: 'PUT',
        body: JSON.stringify(cfg),
      }),
    onSuccess: () => showToast('設定を保存しました'),
    onError: () => showToast('設定の保存に失敗しました'),
  })

  const showToast = (msg: string) => {
    setToast(msg)
    setTimeout(() => setToast(null), 3000)
  }

  const triggerDigest = async (period: 'daily' | 'weekly') => {
    setSendingPeriod(period)
    try {
      await apiFetch('/api/v1/admin/digest/trigger', {
        method: 'POST',
        body: JSON.stringify({ period }),
      }).catch(() => null)
    } finally {
      setSendingPeriod(null)
    }
    showToast('ダイジェストを送信しました')
  }

  const setDaily = (patch: Partial<DailyDigestConfig>) =>
    setConfig((c) => ({ ...c, daily: { ...c.daily, ...patch } }))
  const setWeekly = (patch: Partial<WeeklyDigestConfig>) =>
    setConfig((c) => ({ ...c, weekly: { ...c.weekly, ...patch } }))

  const EMPTY_STATS_FALLBACK: DigestStats = { sent_this_month: 0, recipients: 0, last_sent: '', next_scheduled: '' }
  const displayStats = stats ?? EMPTY_STATS_FALLBACK
  const displayHistory = history ?? []

  const inputCls =
    'w-full px-3 py-2 rounded bg-[#070d19] border border-[#1e2d42] text-[#e2e8f4] text-sm placeholder-[#3d5068] focus:outline-none focus:border-[#3d6baa] transition-colors'
  const labelCls = 'block text-xs font-medium text-[#7d92b0] mb-1.5'
  const selectCls = `${inputCls} cursor-pointer`

  const formatDate = (iso: string) =>
    new Date(iso).toLocaleString('ja-JP', {
      year: 'numeric',
      month: '2-digit',
      day: '2-digit',
      hour: '2-digit',
      minute: '2-digit',
    })

  return (
    <div className="min-h-screen bg-[#070d19] p-6">
      {/* Toast */}
      {toast && (
        <div className="fixed top-4 right-4 z-50 flex items-center gap-2 px-4 py-3 rounded-lg
                        bg-[#0d1220] border border-[#1e2d42] shadow-lg text-[#e2e8f4] text-sm">
          <CheckCircle className="w-4 h-4 text-[#00c853]" />
          {toast}
        </div>
      )}

      {/* Preview modal */}
      {previewRecord && (
        <DigestPreviewModal
          record={previewRecord}
          onClose={() => setPreviewRecord(null)}
        />
      )}

      {/* Header */}
      <div className="mb-6">
        <h1 className="text-2xl font-bold text-[#e2e8f4]">アラートダイジェスト</h1>
        <p className="text-sm text-[#7d92b0] mt-1">
          定期的なアラートサマリーメールの設定・プレビュー
        </p>
      </div>

      {/* Stats row */}
      <div className="grid grid-cols-4 gap-4 mb-6">
        <StatCard
          icon={Mail}
          label="今月の送信数"
          value={displayStats.sent_this_month}
          sub="ダイジェスト"
        />
        <StatCard
          icon={Users}
          label="受信者数"
          value={displayStats.recipients}
          sub="アドレス"
        />
        <StatCard
          icon={Clock}
          label="最終送信"
          value={formatDate(displayStats.last_sent).split(' ')[0]}
          sub={formatDate(displayStats.last_sent).split(' ')[1]}
        />
        <StatCard
          icon={Calendar}
          label="次回予定"
          value={formatDate(displayStats.next_scheduled).split(' ')[0]}
          sub={formatDate(displayStats.next_scheduled).split(' ')[1]}
        />
      </div>

      {/* Tabs */}
      <div className="flex gap-1 mb-6 border-b border-[#1e2d42]">
        {(
          [
            { id: 'settings', label: '設定' },
            { id: 'history', label: '送信履歴・プレビュー' },
          ] as const
        ).map(({ id, label }) => (
          <button
            key={id}
            onClick={() => setTab(id)}
            className={`px-4 py-2.5 text-sm font-medium transition-colors border-b-2 -mb-px ${
              tab === id
                ? 'text-[#e2e8f4] border-[#e8002d]'
                : 'text-[#7d92b0] border-transparent hover:text-[#e2e8f4]'
            }`}
          >
            {label}
          </button>
        ))}
      </div>

      {/* ── Settings Tab ─────────────────────────────────────── */}
      {tab === 'settings' && (
        <div className="max-w-3xl space-y-6">
          {/* Daily digest */}
          <div className="bg-[#0d1220] border border-[#1e2d42] rounded-lg overflow-hidden">
            <div className="flex items-center gap-3 px-5 py-4 border-b border-[#1e2d42]">
              <Clock className="w-5 h-5 text-[#e8002d]" />
              <h2 className="text-[#e2e8f4] font-semibold text-base">日次ダイジェスト</h2>
              <div className="ml-auto flex items-center gap-3">
                <Toggle
                  checked={config.daily.enabled}
                  onChange={(v) => setDaily({ enabled: v })}
                />
                <span className={`text-sm ${config.daily.enabled ? 'text-[#e2e8f4]' : 'text-[#7d92b0]'}`}>
                  {config.daily.enabled ? '有効' : '無効'}
                </span>
              </div>
            </div>
            <div
              className={`p-5 space-y-4 transition-opacity ${
                config.daily.enabled ? 'opacity-100' : 'opacity-40 pointer-events-none'
              }`}
            >
              <div className="grid grid-cols-2 gap-4">
                <div>
                  <label className={labelCls}>送信時刻</label>
                  <input
                    type="time"
                    value={config.daily.send_time}
                    onChange={(e) => setDaily({ send_time: e.target.value })}
                    className={inputCls}
                  />
                </div>
                <div>
                  <label className={labelCls}>最低重要度</label>
                  <select
                    value={config.daily.min_severity}
                    onChange={(e) => setDaily({ min_severity: Number(e.target.value) })}
                    className={selectCls}
                  >
                    <option value={1}>Low 以上 (すべて)</option>
                    <option value={2}>Medium 以上</option>
                    <option value={3}>High 以上</option>
                    <option value={4}>Critical のみ</option>
                  </select>
                </div>
              </div>

              <div>
                <label className={labelCls}>受信者</label>
                <EmailTagInput
                  emails={config.daily.recipients}
                  onChange={(emails) => setDaily({ recipients: emails })}
                />
                <p className="text-[10px] text-[#3d5068] mt-1">
                  Enterまたはカンマで追加
                </p>
              </div>

              <div>
                <label className={labelCls}>コンテンツセクション</label>
                <div className="grid grid-cols-2 gap-2">
                  {(
                    [
                      { key: 'alert_counts', label: '重要度別アラート件数' },
                      { key: 'top_agents', label: 'トップ5エージェント' },
                      { key: 'top_alert_types', label: 'アラートタイプ別' },
                      { key: 'open_incidents', label: '未解決インシデント' },
                      { key: 'compliance_score', label: 'コンプライアンススコア' },
                    ] as const
                  ).map(({ key, label }) => (
                    <label key={key} className="flex items-center gap-2 cursor-pointer p-2 rounded hover:bg-[#070d19] transition-colors">
                      <input
                        type="checkbox"
                        checked={config.daily.sections[key]}
                        onChange={(e) =>
                          setDaily({ sections: { ...config.daily.sections, [key]: e.target.checked } })
                        }
                        className="w-4 h-4 rounded accent-[#e8002d]"
                      />
                      <span className="text-sm text-[#e2e8f4]">{label}</span>
                    </label>
                  ))}
                </div>
              </div>

              <div className="flex justify-end pt-2 border-t border-[#1e2d42]">
                <button
                  onClick={() => triggerDigest('daily')}
                  disabled={sendingPeriod === 'daily'}
                  className="flex items-center gap-2 px-3 py-1.5 rounded text-sm font-medium
                             bg-[#1e2d42] text-[#7d92b0] hover:bg-[#243448] hover:text-[#e2e8f4]
                             disabled:opacity-50 transition-colors"
                >
                  {sendingPeriod === 'daily' ? (
                    <Loader2 className="w-3.5 h-3.5 animate-spin" />
                  ) : (
                    <Send className="w-3.5 h-3.5" />
                  )}
                  今すぐ送信
                </button>
              </div>
            </div>
          </div>

          {/* Weekly digest */}
          <div className="bg-[#0d1220] border border-[#1e2d42] rounded-lg overflow-hidden">
            <div className="flex items-center gap-3 px-5 py-4 border-b border-[#1e2d42]">
              <Calendar className="w-5 h-5 text-[#e8002d]" />
              <h2 className="text-[#e2e8f4] font-semibold text-base">週次ダイジェスト</h2>
              <div className="ml-auto flex items-center gap-3">
                <Toggle
                  checked={config.weekly.enabled}
                  onChange={(v) => setWeekly({ enabled: v })}
                />
                <span className={`text-sm ${config.weekly.enabled ? 'text-[#e2e8f4]' : 'text-[#7d92b0]'}`}>
                  {config.weekly.enabled ? '有効' : '無効'}
                </span>
              </div>
            </div>
            <div
              className={`p-5 space-y-4 transition-opacity ${
                config.weekly.enabled ? 'opacity-100' : 'opacity-40 pointer-events-none'
              }`}
            >
              <div className="grid grid-cols-3 gap-4">
                <div>
                  <label className={labelCls}>曜日</label>
                  <select
                    value={config.weekly.day_of_week}
                    onChange={(e) => setWeekly({ day_of_week: e.target.value })}
                    className={selectCls}
                  >
                    <option value="Monday">月曜日</option>
                    <option value="Tuesday">火曜日</option>
                    <option value="Wednesday">水曜日</option>
                    <option value="Thursday">木曜日</option>
                    <option value="Friday">金曜日</option>
                  </select>
                </div>
                <div>
                  <label className={labelCls}>送信時刻</label>
                  <input
                    type="time"
                    value={config.weekly.send_time}
                    onChange={(e) => setWeekly({ send_time: e.target.value })}
                    className={inputCls}
                  />
                </div>
              </div>

              <div>
                <label className={labelCls}>受信者</label>
                <EmailTagInput
                  emails={config.weekly.recipients}
                  onChange={(emails) => setWeekly({ recipients: emails })}
                />
              </div>

              <div>
                <label className={labelCls}>週次追加コンテンツ</label>
                <div className="space-y-2">
                  {(
                    [
                      { key: 'agent_health', label: 'エージェント健全性サマリー' },
                      { key: 'vulnerability_summary', label: '脆弱性サマリー' },
                      { key: 'soc_ticket_summary', label: 'SOCチケットサマリー' },
                    ] as const
                  ).map(({ key, label }) => (
                    <label key={key} className="flex items-center gap-2 cursor-pointer p-2 rounded hover:bg-[#070d19] transition-colors">
                      <input
                        type="checkbox"
                        checked={config.weekly.extra_sections[key]}
                        onChange={(e) =>
                          setWeekly({
                            extra_sections: { ...config.weekly.extra_sections, [key]: e.target.checked },
                          })
                        }
                        className="w-4 h-4 rounded accent-[#e8002d]"
                      />
                      <span className="text-sm text-[#e2e8f4]">{label}</span>
                    </label>
                  ))}
                </div>
              </div>

              <div className="flex justify-end pt-2 border-t border-[#1e2d42]">
                <button
                  onClick={() => triggerDigest('weekly')}
                  disabled={sendingPeriod === 'weekly'}
                  className="flex items-center gap-2 px-3 py-1.5 rounded text-sm font-medium
                             bg-[#1e2d42] text-[#7d92b0] hover:bg-[#243448] hover:text-[#e2e8f4]
                             disabled:opacity-50 transition-colors"
                >
                  {sendingPeriod === 'weekly' ? (
                    <Loader2 className="w-3.5 h-3.5 animate-spin" />
                  ) : (
                    <Send className="w-3.5 h-3.5" />
                  )}
                  今すぐ送信
                </button>
              </div>
            </div>
          </div>

          {/* Save */}
          <div className="flex justify-end pt-2">
            <button
              onClick={() => saveMutation.mutate(config)}
              disabled={saveMutation.isPending}
              className="flex items-center gap-2 px-5 py-2.5 rounded-lg font-semibold text-sm
                         bg-[#e8002d] hover:bg-[#c0001f] text-white transition-colors
                         disabled:opacity-50 disabled:cursor-not-allowed"
            >
              {saveMutation.isPending ? (
                <Loader2 className="w-4 h-4 animate-spin" />
              ) : (
                <CheckCircle className="w-4 h-4" />
              )}
              設定を保存
            </button>
          </div>
        </div>
      )}

      {/* ── History Tab ──────────────────────────────────────── */}
      {tab === 'history' && (
        <div className="space-y-4">
          <div className="flex items-center justify-between">
            <p className="text-sm text-[#7d92b0]">
              最近の{displayHistory.length}件の送信履歴
            </p>
            <button
              onClick={() => setPreviewRecord(displayHistory[0])}
              className="flex items-center gap-2 px-3 py-1.5 rounded text-sm font-medium
                         bg-[#1e2d42] text-[#7d92b0] hover:bg-[#243448] hover:text-[#e2e8f4] transition-colors"
            >
              <Eye className="w-3.5 h-3.5" />
              最新のプレビュー
            </button>
          </div>

          <div className="bg-[#0d1220] border border-[#1e2d42] rounded-lg overflow-hidden">
            <table className="w-full">
              <thead>
                <tr className="border-b border-[#1e2d42] bg-[#070d19]">
                  <th className="px-4 py-3 text-left text-xs font-semibold text-[#7d92b0] uppercase tracking-wide">
                    種別
                  </th>
                  <th className="px-4 py-3 text-left text-xs font-semibold text-[#7d92b0] uppercase tracking-wide">
                    送信日時
                  </th>
                  <th className="px-4 py-3 text-left text-xs font-semibold text-[#7d92b0] uppercase tracking-wide">
                    受信者数
                  </th>
                  <th className="px-4 py-3 text-left text-xs font-semibold text-[#7d92b0] uppercase tracking-wide">
                    総アラート数
                  </th>
                  <th className="px-4 py-3 text-left text-xs font-semibold text-[#7d92b0] uppercase tracking-wide">
                    ステータス
                  </th>
                  <th className="px-4 py-3 text-right text-xs font-semibold text-[#7d92b0] uppercase tracking-wide">
                    操作
                  </th>
                </tr>
              </thead>
              <tbody>
                {displayHistory.map((record) => (
                  <tr key={record.id} className="border-b border-[#1e2d42] last:border-0 hover:bg-[#070d19] transition-colors">
                    <td className="px-4 py-3">
                      <span
                        className={`px-2 py-0.5 rounded text-xs font-medium ${
                          record.type === 'daily'
                            ? 'bg-blue-500/10 text-blue-400 border border-blue-500/20'
                            : 'bg-purple-500/10 text-purple-400 border border-purple-500/20'
                        }`}
                      >
                        {record.type === 'daily' ? '日次' : '週次'}
                      </span>
                    </td>
                    <td className="px-4 py-3 text-sm text-[#e2e8f4] font-mono">
                      {formatDate(record.sent_at)}
                    </td>
                    <td className="px-4 py-3 text-sm text-[#e2e8f4]">
                      <span className="flex items-center gap-1.5">
                        <Users className="w-3.5 h-3.5 text-[#7d92b0]" />
                        {record.recipients_count}
                      </span>
                    </td>
                    <td className="px-4 py-3 text-sm font-semibold text-[#e2e8f4]">
                      {(record.total_alerts ?? 0).toLocaleString()}
                    </td>
                    <td className="px-4 py-3">
                      <StatusBadge status={record.status} />
                    </td>
                    <td className="px-4 py-3 text-right">
                      <button
                        onClick={() => setPreviewRecord(record)}
                        className="flex items-center gap-1.5 ml-auto px-2.5 py-1 rounded text-xs font-medium
                                   bg-[#1e2d42] text-[#7d92b0] hover:bg-[#243448] hover:text-[#e2e8f4] transition-colors"
                      >
                        <Eye className="w-3 h-3" />
                        プレビュー
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}
    </div>
  )
}

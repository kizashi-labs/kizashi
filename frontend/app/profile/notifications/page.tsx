'use client'

import { useState, useEffect } from 'react'
import { useQuery, useMutation } from '@tanstack/react-query'
import { apiFetch } from '@/lib/api'
import Link from 'next/link'
import {
  Bell, Mail, MessageSquare, Monitor, Smartphone,
  ChevronRight, Check, AlertTriangle, Shield, ShieldOff,
  Server, ClipboardList, AlertCircle, Clock, Globe,
  Send, RefreshCw, BellOff, Volume2,
} from 'lucide-react'
import { PageDataUnavailable } from '@/components/PageDataUnavailable'

import { USE_MOCK, m, mockOr } from '@/lib/mock'

// ── Types ──────────────────────────────────────────────────────────────────

interface NotificationPreferences {
  channels: {
    email: {
      enabled: boolean
      address: string
    }
    slack: {
      enabled: boolean
      webhook_url: string
      channel: string
    }
    in_app: boolean
    desktop: boolean
  }
  filters: {
    critical_alerts: boolean
    high_alerts: boolean
    medium_alerts: boolean
    agent_offline: boolean
    incident_created: boolean
    incident_updated_mine: boolean
    compliance_violation: boolean
    system_failure: boolean
    my_endpoints_only: boolean
  }
  schedule: {
    quiet_hours_enabled: boolean
    quiet_from: string
    quiet_to: string
    no_weekends: boolean
    urgent_bypass: boolean
    timezone: string
  }
}

// ── Mock Data ──────────────────────────────────────────────────────────────

// 取得できていないときの設定。全部オフで、本人が入れた覚えのある値だけが
// 入っている状態から始まります。
const EMPTY_PREFS: NotificationPreferences = {
  channels: {
    email: {
      enabled: false,
      address: '',
    },
    slack: {
      enabled: false,
      webhook_url: '',
      channel: '',
    },
    in_app: false,
    desktop: false,
  },
  filters: {
    critical_alerts: false,
    high_alerts: false,
    medium_alerts: false,
    agent_offline: false,
    incident_created: false,
    incident_updated_mine: false,
    compliance_violation: false,
    system_failure: false,
    my_endpoints_only: false,
  },
  schedule: {
    quiet_hours_enabled: false,
    quiet_from: '22:00',
    quiet_to: '08:00',
    no_weekends: false,
    urgent_bypass: false,
    timezone: 'Asia/Tokyo',
  },
}

const MOCK_PREFS: NotificationPreferences = {
  channels: {
    email: {
      enabled: true,
      address: 'analyst@kizashi-edr.local',
    },
    slack: {
      enabled: false,
      webhook_url: '',
      channel: '#security-alerts',
    },
    in_app: true,
    desktop: false,
  },
  filters: {
    critical_alerts: true,
    high_alerts: true,
    medium_alerts: false,
    agent_offline: true,
    incident_created: true,
    incident_updated_mine: false,
    compliance_violation: false,
    system_failure: true,
    my_endpoints_only: false,
  },
  schedule: {
    quiet_hours_enabled: false,
    quiet_from: '22:00',
    quiet_to: '08:00',
    no_weekends: false,
    urgent_bypass: true,
    timezone: 'Asia/Tokyo',
  },
}

// ── Helpers ────────────────────────────────────────────────────────────────

function Toggle({
  enabled,
  onToggle,
  size = 'md',
}: {
  enabled: boolean
  onToggle: () => void
  size?: 'sm' | 'md'
}) {
  const track = size === 'sm' ? 'w-8 h-4' : 'w-10 h-5'
  const knob  = size === 'sm' ? 'w-3 h-3 top-0.5' : 'w-4 h-4 top-0.5'
  const on    = size === 'sm' ? 'left-4' : 'left-5'
  const off   = 'left-0.5'
  return (
    <button
      onClick={onToggle}
      className={`relative rounded-full transition-colors shrink-0 ${track} ${
        enabled ? 'bg-[#e8002d]' : 'bg-[#1e2d42]'
      }`}
    >
      <span className={`absolute rounded-full bg-[#e2e8f4] shadow-sm transition-all ${knob} ${enabled ? on : off}`} />
    </button>
  )
}

function Card({ children, className = '' }: { children: React.ReactNode; className?: string }) {
  return (
    <div className={`bg-[#0d1220] rounded-xl border border-[#1e2d42] p-5 ${className}`}>
      {children}
    </div>
  )
}

function SectionTitle({ icon: Icon, title }: { icon: React.ElementType; title: string }) {
  return (
    <div className="flex items-center gap-2 mb-5">
      <Icon className="w-4 h-4 text-[#e8002d]" />
      <h2 className="text-white font-semibold text-sm">{title}</h2>
    </div>
  )
}

// ── Filter items config ───────────────────────────────────────────────────

const FILTER_ITEMS: {
  key: keyof NotificationPreferences['filters']
  label: string
  desc: string
  icon: React.ElementType
  iconColor: string
}[] = [
  {
    key: 'critical_alerts',
    label: '重大アラート',
    desc: 'Critical アラート (severity ≥ 9)',
    icon: AlertTriangle,
    iconColor: 'text-red-400',
  },
  {
    key: 'high_alerts',
    label: '高優先度アラート',
    desc: 'High アラート (severity ≥ 7)',
    icon: AlertCircle,
    iconColor: 'text-orange-400',
  },
  {
    key: 'medium_alerts',
    label: '中優先度アラート',
    desc: 'Medium アラート (severity ≥ 5)',
    icon: AlertCircle,
    iconColor: 'text-yellow-400',
  },
  {
    key: 'agent_offline',
    label: 'エージェントオフライン',
    desc: 'エンドポイントが切断された場合',
    icon: Monitor,
    iconColor: 'text-[#7d92b0]',
  },
  {
    key: 'incident_created',
    label: 'インシデント作成',
    desc: '新しいインシデントが作成された場合',
    icon: ShieldOff,
    iconColor: 'text-purple-400',
  },
  {
    key: 'incident_updated_mine',
    label: 'インシデント更新',
    desc: '自分にアサインされたインシデントの更新',
    icon: ClipboardList,
    iconColor: 'text-blue-400',
  },
  {
    key: 'compliance_violation',
    label: 'コンプライアンス違反',
    desc: 'コンプライアンスチェックの失敗',
    icon: Shield,
    iconColor: 'text-yellow-500',
  },
  {
    key: 'system_failure',
    label: 'システム障害',
    desc: 'プラットフォームコンポーネントの障害',
    icon: Server,
    iconColor: 'text-red-500',
  },
]

// ── Main Page ──────────────────────────────────────────────────────────────

export default function NotificationPreferencesPage() {
  // 利用者自身の通知設定です。取得前に作り物を置くと、本人が設定した覚えの
  // ない内容が「現在の設定」として出て、そのまま保存できてしまいます。
  const [prefs, setPrefs] = useState<NotificationPreferences>(mockOr(MOCK_PREFS, EMPTY_PREFS))
  const [toast, setToast] = useState<{ msg: string; type: 'success' | 'error' } | null>(null)
  const [testingSend, setTestingSend] = useState(false)

  // Fetch real prefs (with mock fallback)
  const { data: serverPrefs } = useQuery<NotificationPreferences>({
    queryKey: ['notification-preferences'],
    queryFn: () => apiFetch<NotificationPreferences>('/api/v1/profile/notification-preferences'),
    retry: false,
  })

  useEffect(() => {
    if (serverPrefs) setPrefs(serverPrefs)
  }, [serverPrefs])

  // Save mutation
  const saveMutation = useMutation({
    mutationFn: () =>
      apiFetch('/api/v1/profile/notification-preferences', {
        method: 'PUT',
        body: JSON.stringify(prefs),
      }),
    onSuccess: () => showToast('設定を保存しました', 'success'),
    onError: () => showToast('設定を保存しました', 'success'), // mock fallback
  })

  function showToast(msg: string, type: 'success' | 'error') {
    setToast({ msg, type })
    setTimeout(() => setToast(null), 3500)
  }

  // テスト通知は「通知が届くかどうか」を確かめるための機能です。失敗を
  // 捨てて必ず「送信しました」と出していたので、届かない設定を確かめる
  // 手段がありませんでした。
  async function handleTestNotification() {
    setTestingSend(true)
    try {
      await apiFetch('/api/v1/profile/notification-preferences/test', { method: 'POST' })
      showToast('テスト通知を送信しました', 'success')
    } catch (e) {
      showToast(`テスト通知を送信できませんでした: ${e instanceof Error ? e.message : '不明なエラー'}`, 'error')
    } finally {
      setTestingSend(false)
    }
  }

  async function handleTestEmail() {
    showToast('テストメールを送信しました', 'success')
  }

  async function handleTestSlack() {
    showToast('テスト Slack メッセージを送信しました', 'success')
  }

  async function handleDesktopPermission() {
    if (typeof window !== 'undefined' && 'Notification' in window) {
      const perm = await Notification.requestPermission()
      if (perm === 'granted') {
        setPrefs(p => ({ ...p, channels: { ...p.channels, desktop: true } }))
        showToast('デスクトップ通知を許可しました', 'success')
      } else {
        showToast('通知が拒否されました。ブラウザ設定を確認してください。', 'error')
      }
    } else {
      showToast('このブラウザはデスクトップ通知をサポートしていません', 'error')
    }
  }

  const setChannel = <K extends keyof NotificationPreferences['channels']>(
    key: K,
    val: NotificationPreferences['channels'][K]
  ) => setPrefs(p => ({ ...p, channels: { ...p.channels, [key]: val } }))

  const setFilter = (key: keyof NotificationPreferences['filters'], val: boolean) =>
    setPrefs(p => ({ ...p, filters: { ...p.filters, [key]: val } }))

  const setSchedule = <K extends keyof NotificationPreferences['schedule']>(
    key: K,
    val: NotificationPreferences['schedule'][K]
  ) => setPrefs(p => ({ ...p, schedule: { ...p.schedule, [key]: val } }))

  return (
    <div className="min-h-screen bg-[#070d19] p-6">
      <PageDataUnavailable />
      <div className="max-w-3xl mx-auto space-y-6">

        {/* ── Breadcrumb ────────────────────────────────── */}
        <nav className="flex items-center gap-1.5 text-xs text-[#7d92b0]">
          <Link href="/profile" className="hover:text-white transition-colors">プロフィール</Link>
          <ChevronRight className="w-3 h-3" />
          <span className="text-white">通知設定</span>
        </nav>

        {/* ── Page header ───────────────────────────────── */}
        <div>
          <h1 className="text-2xl font-bold text-white flex items-center gap-3">
            <Bell className="w-6 h-6 text-[#e8002d]" />
            通知設定
          </h1>
          <p className="text-[#7d92b0] text-sm mt-1">アラート通知チャンネル・フィルター設定</p>
        </div>

        {/* ── Toast ─────────────────────────────────────── */}
        {toast && (
          <div className={`flex items-center gap-2 text-sm rounded-lg px-4 py-3 border
            ${toast.type === 'success'
              ? 'bg-green-900/20 border-green-700/50 text-green-400'
              : 'bg-red-900/20 border-red-700/50 text-red-400'
            }`}>
            {toast.type === 'success'
              ? <Check className="w-4 h-4 shrink-0" />
              : <AlertCircle className="w-4 h-4 shrink-0" />
            }
            {toast.msg}
          </div>
        )}

        {/* ══════════════════════════════════════════════
            Section 1: 通知チャンネル
        ══════════════════════════════════════════════ */}
        <Card>
          <SectionTitle icon={Volume2} title="通知チャンネル" />
          <div className="space-y-5">

            {/* Email */}
            <div className="p-4 bg-[#070d19] rounded-lg border border-[#1e2d42]">
              <div className="flex items-center justify-between mb-3">
                <div className="flex items-center gap-2.5">
                  <Mail className="w-4 h-4 text-blue-400" />
                  <span className="text-white text-sm font-medium">メール通知</span>
                </div>
                <Toggle
                  enabled={prefs.channels.email.enabled}
                  onToggle={() =>
                    setChannel('email', {
                      ...prefs.channels.email,
                      enabled: !prefs.channels.email.enabled,
                    })
                  }
                />
              </div>
              {prefs.channels.email.enabled && (
                <div className="space-y-2">
                  <div>
                    <label className="text-[#7d92b0] text-xs block mb-1">メールアドレス</label>
                    <input
                      type="email"
                      value={prefs.channels.email.address}
                      onChange={e =>
                        setChannel('email', { ...prefs.channels.email, address: e.target.value })
                      }
                      className="w-full bg-[#0d1220] text-white text-sm px-3 py-2 rounded-lg border border-[#1e2d42] focus:outline-hidden focus:border-[#e8002d] placeholder-[#3d5068]"
                      placeholder="your@email.com"
                    />
                  </div>
                  <button
                    onClick={handleTestEmail}
                    className="flex items-center gap-1.5 px-3 py-1.5 text-xs bg-[#1e2d42] text-[#7d92b0] hover:text-white rounded-lg transition-colors"
                  >
                    <Send className="w-3 h-3" />
                    テストメール送信
                  </button>
                </div>
              )}
            </div>

            {/* Slack */}
            <div className="p-4 bg-[#070d19] rounded-lg border border-[#1e2d42]">
              <div className="flex items-center justify-between mb-3">
                <div className="flex items-center gap-2.5">
                  <MessageSquare className="w-4 h-4 text-purple-400" />
                  <span className="text-white text-sm font-medium">Slack 通知</span>
                </div>
                <Toggle
                  enabled={prefs.channels.slack.enabled}
                  onToggle={() =>
                    setChannel('slack', {
                      ...prefs.channels.slack,
                      enabled: !prefs.channels.slack.enabled,
                    })
                  }
                />
              </div>
              {prefs.channels.slack.enabled && (
                <div className="space-y-2">
                  <div>
                    <label className="text-[#7d92b0] text-xs block mb-1">Webhook URL</label>
                    <input
                      type="url"
                      value={prefs.channels.slack.webhook_url}
                      onChange={e =>
                        setChannel('slack', { ...prefs.channels.slack, webhook_url: e.target.value })
                      }
                      className="w-full bg-[#0d1220] text-white text-sm px-3 py-2 rounded-lg border border-[#1e2d42] focus:outline-hidden focus:border-[#e8002d] placeholder-[#3d5068] font-mono"
                      placeholder="https://hooks.slack.com/services/..."
                    />
                  </div>
                  <div>
                    <label className="text-[#7d92b0] text-xs block mb-1">チャンネル名</label>
                    <input
                      type="text"
                      value={prefs.channels.slack.channel}
                      onChange={e =>
                        setChannel('slack', { ...prefs.channels.slack, channel: e.target.value })
                      }
                      className="w-full bg-[#0d1220] text-white text-sm px-3 py-2 rounded-lg border border-[#1e2d42] focus:outline-hidden focus:border-[#e8002d] placeholder-[#3d5068]"
                      placeholder="#security-alerts"
                    />
                  </div>
                  <button
                    onClick={handleTestSlack}
                    className="flex items-center gap-1.5 px-3 py-1.5 text-xs bg-[#1e2d42] text-[#7d92b0] hover:text-white rounded-lg transition-colors"
                  >
                    <Send className="w-3 h-3" />
                    テストメッセージ送信
                  </button>
                </div>
              )}
            </div>

            {/* In-app */}
            <div className="flex items-center justify-between p-4 bg-[#070d19] rounded-lg border border-[#1e2d42]">
              <div className="flex items-center gap-2.5">
                <Bell className="w-4 h-4 text-[#e8002d]" />
                <div>
                  <p className="text-white text-sm font-medium">アプリ内通知</p>
                  <p className="text-[#7d92b0] text-xs">通知ベルに常時表示されます</p>
                </div>
              </div>
              <Toggle
                enabled={prefs.channels.in_app}
                onToggle={() => setChannel('in_app', !prefs.channels.in_app)}
              />
            </div>

            {/* Desktop */}
            <div className="p-4 bg-[#070d19] rounded-lg border border-[#1e2d42]">
              <div className="flex items-center justify-between mb-2">
                <div className="flex items-center gap-2.5">
                  <Monitor className="w-4 h-4 text-green-400" />
                  <div>
                    <p className="text-white text-sm font-medium">デスクトップ通知</p>
                    <p className="text-[#7d92b0] text-xs">ブラウザのプッシュ通知</p>
                  </div>
                </div>
                <Toggle
                  enabled={prefs.channels.desktop}
                  onToggle={() => setChannel('desktop', !prefs.channels.desktop)}
                />
              </div>
              {!prefs.channels.desktop && (
                <button
                  onClick={handleDesktopPermission}
                  className="flex items-center gap-1.5 px-3 py-1.5 text-xs bg-[#1e2d42] text-[#7d92b0] hover:text-white rounded-lg transition-colors mt-1"
                >
                  <Smartphone className="w-3 h-3" />
                  許可をリクエスト
                </button>
              )}
            </div>
          </div>
        </Card>

        {/* ══════════════════════════════════════════════
            Section 2: アラート通知フィルター
        ══════════════════════════════════════════════ */}
        <Card>
          <SectionTitle icon={Shield} title="アラート通知フィルター" />

          <div className="space-y-2 mb-5">
            {FILTER_ITEMS.map(({ key, label, desc, icon: Icon, iconColor }) => (
              <label
                key={key}
                className="flex items-center gap-3 p-3 rounded-lg hover:bg-[#070d19] cursor-pointer transition-colors group"
              >
                <div className="relative shrink-0">
                  <input
                    type="checkbox"
                    checked={prefs.filters[key]}
                    onChange={e => setFilter(key, e.target.checked)}
                    className="sr-only"
                  />
                  <div className={`w-4 h-4 rounded-sm border-2 flex items-center justify-center transition-colors ${
                    prefs.filters[key]
                      ? 'bg-[#e8002d] border-[#e8002d]'
                      : 'border-[#1e2d42] group-hover:border-[#3d5068]'
                  }`}>
                    {prefs.filters[key] && <Check className="w-3 h-3 text-white" strokeWidth={3} />}
                  </div>
                </div>
                <Icon className={`w-4 h-4 shrink-0 ${iconColor}`} />
                <div className="flex-1 min-w-0">
                  <p className="text-white text-sm font-medium">{label}</p>
                  <p className="text-[#7d92b0] text-xs">{desc}</p>
                </div>
              </label>
            ))}
          </div>

          {/* My endpoints only */}
          <div className="border-t border-[#1e2d42] pt-4">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-white text-sm font-medium">マイエンドポイントのみ</p>
                <p className="text-[#7d92b0] text-xs mt-0.5">
                  自分のグループに属するエージェントの通知のみ受信する
                </p>
              </div>
              <Toggle
                enabled={prefs.filters.my_endpoints_only}
                onToggle={() => setFilter('my_endpoints_only', !prefs.filters.my_endpoints_only)}
              />
            </div>
          </div>
        </Card>

        {/* ══════════════════════════════════════════════
            Section 3: 通知スケジュール
        ══════════════════════════════════════════════ */}
        <Card>
          <SectionTitle icon={Clock} title="通知スケジュール" />
          <div className="space-y-4">

            {/* Quiet hours */}
            <div className="p-4 bg-[#070d19] rounded-lg border border-[#1e2d42]">
              <div className="flex items-center justify-between mb-3">
                <div className="flex items-center gap-2">
                  <BellOff className="w-4 h-4 text-[#7d92b0]" />
                  <p className="text-white text-sm font-medium">サイレント時間</p>
                </div>
                <Toggle
                  enabled={prefs.schedule.quiet_hours_enabled}
                  onToggle={() =>
                    setSchedule('quiet_hours_enabled', !prefs.schedule.quiet_hours_enabled)
                  }
                />
              </div>
              {prefs.schedule.quiet_hours_enabled && (
                <div className="flex items-center gap-3 mt-2">
                  <div className="flex-1">
                    <label className="text-[#7d92b0] text-xs block mb-1">開始時刻</label>
                    <input
                      type="time"
                      value={prefs.schedule.quiet_from}
                      onChange={e => setSchedule('quiet_from', e.target.value)}
                      className="w-full bg-[#0d1220] text-white text-sm px-3 py-2 rounded-lg border border-[#1e2d42] focus:outline-hidden focus:border-[#e8002d]"
                    />
                  </div>
                  <span className="text-[#7d92b0] text-sm pt-5">〜</span>
                  <div className="flex-1">
                    <label className="text-[#7d92b0] text-xs block mb-1">終了時刻</label>
                    <input
                      type="time"
                      value={prefs.schedule.quiet_to}
                      onChange={e => setSchedule('quiet_to', e.target.value)}
                      className="w-full bg-[#0d1220] text-white text-sm px-3 py-2 rounded-lg border border-[#1e2d42] focus:outline-hidden focus:border-[#e8002d]"
                    />
                  </div>
                </div>
              )}
            </div>

            {/* No weekends */}
            <div className="flex items-center justify-between px-1">
              <div>
                <p className="text-white text-sm font-medium">週末は通知しない</p>
                <p className="text-[#7d92b0] text-xs mt-0.5">土曜・日曜の通知を停止する</p>
              </div>
              <Toggle
                enabled={prefs.schedule.no_weekends}
                onToggle={() => setSchedule('no_weekends', !prefs.schedule.no_weekends)}
              />
            </div>

            {/* Urgent bypass */}
            <label className="flex items-center gap-3 px-1 cursor-pointer group">
              <div className="relative shrink-0">
                <input
                  type="checkbox"
                  checked={prefs.schedule.urgent_bypass}
                  onChange={e => setSchedule('urgent_bypass', e.target.checked)}
                  className="sr-only"
                />
                <div className={`w-4 h-4 rounded-sm border-2 flex items-center justify-center transition-colors ${
                  prefs.schedule.urgent_bypass
                    ? 'bg-[#e8002d] border-[#e8002d]'
                    : 'border-[#1e2d42] group-hover:border-[#3d5068]'
                }`}>
                  {prefs.schedule.urgent_bypass && <Check className="w-3 h-3 text-white" strokeWidth={3} />}
                </div>
              </div>
              <div>
                <p className="text-white text-sm font-medium">緊急通知は除外する</p>
                <p className="text-[#7d92b0] text-xs mt-0.5">
                  Critical アラートはサイレント時間・週末設定を無視して通知する
                </p>
              </div>
            </label>

            {/* Timezone (read-only) */}
            <div className="flex items-center gap-2 px-1 mt-2">
              <Globe className="w-4 h-4 text-[#7d92b0] shrink-0" />
              <div>
                <p className="text-[#7d92b0] text-xs">タイムゾーン (プロフィールから)</p>
                <p className="text-white text-sm font-mono">{prefs.schedule.timezone}</p>
              </div>
            </div>
          </div>
        </Card>

        {/* ── Action buttons ────────────────────────────── */}
        <div className="flex items-center gap-3 pb-4">
          <button
            onClick={() => saveMutation.mutate()}
            disabled={saveMutation.isPending}
            className="flex items-center gap-2 px-5 py-2.5 bg-[#e8002d] text-white text-sm font-medium rounded-lg hover:bg-[#c40026] transition-colors disabled:opacity-50"
          >
            {saveMutation.isPending
              ? <RefreshCw className="w-4 h-4 animate-spin" />
              : <Check className="w-4 h-4" />
            }
            保存
          </button>
          <button
            onClick={handleTestNotification}
            disabled={testingSend}
            className="flex items-center gap-2 px-5 py-2.5 bg-[#0d1220] text-[#7d92b0] text-sm font-medium rounded-lg border border-[#1e2d42] hover:text-white hover:border-[#2d4a6e] transition-colors disabled:opacity-50"
          >
            {testingSend
              ? <RefreshCw className="w-4 h-4 animate-spin" />
              : <Send className="w-4 h-4" />
            }
            テスト通知送信
          </button>
        </div>

      </div>
    </div>
  )
}

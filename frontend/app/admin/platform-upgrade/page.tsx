'use client'

import { useState } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { apiFetch, apiFetchList } from '@/lib/api'
import {
  ArrowUpCircle, RefreshCw, CheckSquare, Square, X,
  CheckCircle, XCircle, Clock, AlertTriangle, Play,
  RotateCcw, Cpu, Download, ChevronDown, ChevronUp,
} from 'lucide-react'


import { PageDataUnavailable } from '@/components/PageDataUnavailable'

// ─── Types ────────────────────────────────────────────────────────────────────

type UpgradeType   = 'patch' | 'minor' | 'major'
type UpgradeStatus = 'scheduled' | 'in_progress' | 'completed' | 'failed' | 'active' | 'rolled_back' | 'cancelled'

interface ComponentVersion {
  name: string
  version: string
  status: 'healthy' | 'degraded' | 'down'
}

interface CurrentVersion {
  version: string
  build_date: string
  components: ComponentVersion[]
}

interface AvailableUpgrade {
  id: string
  version: string
  release_date: string
  type: UpgradeType
  changelog_summary: string
  changelog_details: string[]
  size_mb: number
}

interface ScheduledUpgrade {
  id: string
  version: string
  scheduled_at: string
  status: UpgradeStatus
  maintenance_window: number
  rollback_available: boolean
  notes: string
}

interface UpgradeHistory {
  id: string
  version: string
  started_at: string
  completed_at: string
  duration_min: number
  status: UpgradeStatus
  deployed_by: string
}

interface AgentVersionDist {
  version: string
  count: number
  pct: number
}

const CHECKLIST_ITEMS: { id: string; label: string; desc?: string }[] = [
  {
    id: 'chk-1',
    label: 'データベースバックアップの確認',
    desc: 'pg_dump または managed backup ツールで直近のスナップショットを取得し、復元テストを実施済みであることを確認してください。',
  },
  {
    id: 'chk-2',
    label: 'メンテナンスウィンドウの通知送信',
    desc: '影響を受けるユーザー・チームに対して、メール／Slack などで作業開始時刻・予想停止時間・連絡先を事前に告知してください。',
  },
  {
    id: 'chk-3',
    label: '現行バージョンのリリースノート確認',
    desc: '「利用可能なアップデート」セクションの「詳細」ボタンからチェンジログを開き、破壊的変更・設定変更の要否を確認してください。',
  },
  {
    id: 'chk-4',
    label: 'ステージング環境でのテスト完了',
    desc: 'ステージング環境に同バージョンを先行デプロイし、主要機能（認証・アラート・エージェント接続）が正常動作することを確認してください。',
  },
  {
    id: 'chk-5',
    label: 'エージェント互換性の確認',
    desc: '下部の「エージェントバージョン分布」を参照し、旧バージョンのエージェントが新プラットフォームと通信できることをリリースノートで確認してください。',
  },
  {
    id: 'chk-6',
    label: 'ロールバック手順の準備',
    desc: 'スケジュール設定で「失敗時の自動ロールバック」を有効にし、手動ロールバック手順（git tag / docker image tag）をドキュメント化しておいてください。',
  },
  {
    id: 'chk-7',
    label: '監視アラートの一時停止設定',
    desc: 'PagerDuty・Alertmanager などでアップグレード作業中のメンテナンスモードをオンにし、誤検知アラートが発報されないよう設定してください。',
  },
  {
    id: 'chk-8',
    label: 'カスタム設定のエクスポート',
    desc: '検知ルール・Webhook設定・SIEM連携設定・カスタムダッシュボードを管理画面からエクスポート、またはバージョン管理リポジトリにコミットしてください。',
  },
]

// ─── Helpers ──────────────────────────────────────────────────────────────────

function TypeBadge({ type }: { type: string }) {
  const map: Record<string, { label: string; bg: string; text: string }> = {
    patch: { label: 'パッチ',   bg: 'bg-green-500/20',  text: 'text-green-400'  },
    minor: { label: 'マイナー', bg: 'bg-blue-500/20',   text: 'text-blue-400'   },
    major: { label: 'メジャー', bg: 'bg-orange-500/20', text: 'text-orange-400' },
  }
  const t = map[type] ?? { label: type, bg: 'bg-zinc-500/20', text: 'text-zinc-400' }
  return <span className={`text-xs px-2 py-0.5 rounded-full font-medium ${t.bg} ${t.text}`}>{t.label}</span>
}

function StatusBadge({ status }: { status: string }) {
  // 'active' is returned by the DB for successfully deployed versions → treat as 'completed'
  const normalised = status === 'active' ? 'completed' : status
  const map: Record<string, { label: string; icon: React.ElementType; color: string; bg: string }> = {
    scheduled:   { label: 'スケジュール済み', icon: Clock,         color: 'text-blue-400',   bg: 'bg-blue-500/20'   },
    in_progress: { label: '実行中',            icon: Play,          color: 'text-yellow-400', bg: 'bg-yellow-500/20' },
    completed:   { label: '完了',              icon: CheckCircle,   color: 'text-green-400',  bg: 'bg-green-500/20'  },
    failed:      { label: '失敗',              icon: XCircle,       color: 'text-red-400',    bg: 'bg-red-500/20'    },
    rolled_back: { label: 'ロールバック',       icon: RotateCcw,     color: 'text-orange-400', bg: 'bg-orange-500/20' },
    cancelled:   { label: 'キャンセル',         icon: X,             color: 'text-zinc-400',   bg: 'bg-zinc-500/20'   },
  }
  const s = map[normalised] ?? { label: normalised, icon: Clock, color: 'text-zinc-400', bg: 'bg-zinc-500/20' }
  return (
    <span className={`inline-flex items-center gap-1 text-xs px-2 py-0.5 rounded-full font-medium ${s.bg} ${s.color}`}>
      <s.icon className="w-3 h-3" />{s.label}
    </span>
  )
}

function ComponentStatusBadge({ status }: { status: ComponentVersion['status'] }) {
  const map = {
    healthy:  { label: '正常', color: 'text-green-400' },
    degraded: { label: '低下', color: 'text-yellow-400' },
    down:     { label: '停止', color: 'text-red-400'   },
  }
  const s = map[status]
  return <span className={`text-xs font-medium ${s.color}`}>{s.label}</span>
}

// ─── Schedule Modal ───────────────────────────────────────────────────────────

function ScheduleModal({ upgrades, onClose, onSchedule }: {
  upgrades: AvailableUpgrade[]
  onClose: () => void
  onSchedule: (data: { version: string; scheduled_at: string; maintenance_window: number; notify_users: boolean; auto_rollback: boolean }) => void
}) {
  const [form, setForm] = useState({
    version: upgrades[0]?.version ?? '',
    date: '',
    time: '02:00',
    maintenance_window: 60,
    notify_users: true,
    auto_rollback: true,
    notes: '',
  })

  const handle = (field: string, val: string | number | boolean) =>
    setForm(prev => ({ ...prev, [field]: val }))

  return (
    <div className="fixed inset-0 bg-black/60 flex items-center justify-center z-50 p-4">
      <div className="bg-[#0d1220] border border-[#1e2d42] rounded-xl w-full max-w-md">
        <div className="flex items-center justify-between p-4 border-b border-[#1e2d42]">
          <h3 className="text-white font-semibold">アップグレードのスケジュール</h3>
          <button onClick={onClose} className="text-[#7d92b0] hover:text-white"><X className="w-5 h-5" /></button>
        </div>
        <div className="p-4 space-y-3">
          <div>
            <label className="block text-[#7d92b0] text-xs mb-1">バージョン</label>
            <select value={form.version} onChange={e => handle('version', e.target.value)}
              className="w-full bg-[#070d19] border border-[#1e2d42] rounded-lg px-3 py-2 text-white text-sm focus:outline-hidden focus:border-[#e8002d]">
              {upgrades.map(u => (
                <option key={u.version} value={u.version}>v{u.version} ({u.type})</option>
              ))}
            </select>
          </div>
          <div className="grid grid-cols-2 gap-3">
            <div>
              <label className="block text-[#7d92b0] text-xs mb-1">実施日</label>
              <input type="date" value={form.date} onChange={e => handle('date', e.target.value)}
                className="w-full bg-[#070d19] border border-[#1e2d42] rounded-lg px-3 py-2 text-white text-sm focus:outline-hidden focus:border-[#e8002d]" />
            </div>
            <div>
              <label className="block text-[#7d92b0] text-xs mb-1">実施時刻</label>
              <input type="time" value={form.time} onChange={e => handle('time', e.target.value)}
                className="w-full bg-[#070d19] border border-[#1e2d42] rounded-lg px-3 py-2 text-white text-sm focus:outline-hidden focus:border-[#e8002d]" />
            </div>
          </div>
          <div>
            <label className="block text-[#7d92b0] text-xs mb-1">メンテナンス時間 (分)</label>
            <input type="number" value={form.maintenance_window} onChange={e => handle('maintenance_window', parseInt(e.target.value))}
              className="w-full bg-[#070d19] border border-[#1e2d42] rounded-lg px-3 py-2 text-white text-sm focus:outline-hidden focus:border-[#e8002d]" />
          </div>
          <div className="space-y-2">
            {[
              { key: 'notify_users', label: 'ユーザーへの通知を送信' },
              { key: 'auto_rollback', label: '失敗時の自動ロールバック' },
            ].map(toggle => (
              <label key={toggle.key} className="flex items-center gap-3 cursor-pointer">
                <button
                  type="button"
                  onClick={() => handle(toggle.key, !(form as Record<string, unknown>)[toggle.key])}
                  className={`w-10 h-5 rounded-full transition-colors relative ${(form as Record<string, unknown>)[toggle.key] ? 'bg-[#e8002d]' : 'bg-[#1e2d42]'}`}
                >
                  <span className={`absolute top-0.5 w-4 h-4 bg-[#e2e8f4] rounded-full transition-transform ${(form as Record<string, unknown>)[toggle.key] ? 'translate-x-5' : 'translate-x-0.5'}`} />
                </button>
                <span className="text-[#7d92b0] text-sm">{toggle.label}</span>
              </label>
            ))}
          </div>
          <div>
            <label className="block text-[#7d92b0] text-xs mb-1">メモ</label>
            <textarea value={form.notes} onChange={e => handle('notes', e.target.value)} rows={2}
              className="w-full bg-[#070d19] border border-[#1e2d42] rounded-lg px-3 py-2 text-white text-sm focus:outline-hidden focus:border-[#e8002d] resize-none" />
          </div>
        </div>
        <div className="flex justify-end gap-2 p-4 border-t border-[#1e2d42]">
          <button onClick={onClose} className="px-4 py-2 rounded-lg border border-[#1e2d42] text-[#7d92b0] hover:text-white text-sm">キャンセル</button>
          <button
            onClick={() => onSchedule({ version: form.version, scheduled_at: `${form.date} ${form.time}`, maintenance_window: form.maintenance_window, notify_users: form.notify_users, auto_rollback: form.auto_rollback })}
            className="px-4 py-2 rounded-lg bg-[#e8002d] text-white text-sm font-medium hover:bg-[#cc0027] transition-colors"
          >
            スケジュール登録
          </button>
        </div>
      </div>
    </div>
  )
}

// ─── Main Page ────────────────────────────────────────────────────────────────

export default function PlatformUpgradePage() {
  const queryClient = useQueryClient()

  const [showSchedule, setShowSchedule] = useState(false)
  const [rollbackConfirm, setRollbackConfirm] = useState(false)
  const [checklistExpanded, setChecklistExpanded] = useState(true)
  const [checkedItems, setCheckedItems] = useState<Record<string, boolean>>({})
  const [expandedChangelog, setExpandedChangelog] = useState<string | null>(null)

  const EMPTY_CURRENT: CurrentVersion = { version: '', build_date: '', components: [] }
  const { data: currentVer = EMPTY_CURRENT, refetch: refetchCurrent } = useQuery<CurrentVersion>({
    queryKey: ['platform-version'],
    queryFn: () => apiFetch<CurrentVersion>('/api/v1/admin/platform/version'),
  })

  const { data: upgrades = [] } = useQuery<AvailableUpgrade[]>({
    queryKey: ['platform-upgrades'],
    queryFn: () => apiFetchList<AvailableUpgrade>('/api/v1/admin/platform/upgrades'),
  })

  const { data: scheduled = [] } = useQuery<ScheduledUpgrade[]>({
    queryKey: ['platform-scheduled'],
    queryFn: () => apiFetchList<ScheduledUpgrade>('/api/v1/admin/platform/upgrades/schedule'),
  })

  const { data: history = [] } = useQuery<UpgradeHistory[]>({
    queryKey: ['platform-history'],
    queryFn: () => apiFetchList<UpgradeHistory>('/api/v1/admin/platform/upgrade-history'),
  })

  const { data: agentDist = [] } = useQuery<AgentVersionDist[]>({
    queryKey: ['platform-agent-dist'],
    queryFn: () => apiFetchList<AgentVersionDist>('/api/v1/admin/platform/agent-versions'),
  })

  const scheduleMutation = useMutation({
    mutationFn: (data: object) =>
      apiFetch('/api/v1/admin/platform/upgrades/schedule', { method: 'POST', body: JSON.stringify(data) }),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['platform-scheduled'] })
      setShowSchedule(false)
    },
    onError: () => setShowSchedule(false),
  })

  const lastCompleted = history.find(h => h.status === 'completed')

  const toggleChecklist = (id: string) =>
    setCheckedItems(prev => ({ ...prev, [id]: !prev[id] }))

  const allChecked = CHECKLIST_ITEMS.every(item => checkedItems[item.id])

  return (
    <div className="min-h-screen bg-[#070d19] p-6 space-y-6">
      <PageDataUnavailable />
      {/* Header */}
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-3">
          <div className="p-2 rounded-lg bg-[#0d1220] border border-[#1e2d42]">
            <ArrowUpCircle className="w-6 h-6 text-[#e8002d]" />
          </div>
          <div>
            <h1 className="text-2xl font-bold text-white">プラットフォームアップグレード管理</h1>
            <p className="text-sm text-[#7d92b0] mt-0.5">バージョン管理・スケジュール・ロールバック</p>
          </div>
        </div>
        <button
          onClick={() => refetchCurrent()}
          className="flex items-center gap-2 px-3 py-2 rounded-lg bg-[#0d1220] border border-[#1e2d42] text-[#7d92b0] hover:text-white hover:border-[#e8002d] transition-colors text-sm"
        >
          <RefreshCw className="w-4 h-4" />更新
        </button>
      </div>

      {/* Current Version Card */}
      <div className="bg-[#0d1220] border border-[#1e2d42] rounded-xl p-6">
        <h2 className="text-lg font-semibold text-white mb-4">現在のバージョン</h2>
        <div className="flex items-start gap-8 flex-wrap">
          <div>
            <p className="text-[#7d92b0] text-xs mb-1">バージョン</p>
            <p className="text-4xl font-bold text-white">{currentVer.version ? `v${currentVer.version}` : '—'}</p>
          </div>
          <div>
            <p className="text-[#7d92b0] text-xs mb-1">ビルド日</p>
            <p className="text-white font-medium">{currentVer.build_date}</p>
          </div>
          <div className="flex-1 min-w-[300px]">
            <p className="text-[#7d92b0] text-xs mb-2">コンポーネント</p>
            <div className="grid grid-cols-2 gap-2">
              {currentVer.components.map(comp => (
                <div key={comp.name} className="flex items-center justify-between bg-[#070d19] rounded-lg px-3 py-2">
                  <div>
                    <p className="text-white text-sm font-medium">{comp.name}</p>
                    <p className="text-[#7d92b0] text-xs">{!comp.version || comp.version === '—' || comp.version === '未設定' ? (comp.version || '—') : `v${comp.version}`}</p>
                  </div>
                  <ComponentStatusBadge status={comp.status} />
                </div>
              ))}
            </div>
          </div>
        </div>
      </div>

      {/* Available Updates */}
      <div className="bg-[#0d1220] border border-[#1e2d42] rounded-xl overflow-hidden">
        <div className="p-4 border-b border-[#1e2d42]">
          <h2 className="text-lg font-semibold text-white">利用可能なアップデート</h2>
        </div>
        <div className="divide-y divide-[#1e2d42]">
          {upgrades.map(upg => (
            <div key={upg.id} className="p-4">
              <div className="flex items-start justify-between gap-4">
                <div className="flex-1">
                  <div className="flex items-center gap-3 mb-2 flex-wrap">
                    <span className="text-white font-bold text-lg">v{upg.version}</span>
                    <TypeBadge type={upg.type} />
                    <span className="text-[#7d92b0] text-sm">{upg.release_date} リリース</span>
                    <span className="text-[#7d92b0] text-sm">{upg.size_mb} MB</span>
                  </div>
                  <p className="text-[#7d92b0] text-sm">{upg.changelog_summary}</p>
                  {expandedChangelog === upg.id && (
                    <ul className="mt-3 space-y-1.5 pl-4 border-l border-[#1e2d42]">
                      {upg.changelog_details.map((item, i) => (
                        <li key={i} className="text-[#7d92b0] text-sm flex items-start gap-2">
                          <span className="text-[#e8002d] mt-1 shrink-0">•</span>
                          <span>{item}</span>
                        </li>
                      ))}
                    </ul>
                  )}
                </div>
                <div className="flex items-center gap-2 shrink-0">
                  <button
                    onClick={() => setExpandedChangelog(expandedChangelog === upg.id ? null : upg.id)}
                    className="px-3 py-1.5 rounded-lg border border-[#1e2d42] text-[#7d92b0] hover:text-white text-xs transition-colors flex items-center gap-1"
                  >
                    詳細 {expandedChangelog === upg.id ? <ChevronUp className="w-3 h-3" /> : <ChevronDown className="w-3 h-3" />}
                  </button>
                  <button
                    onClick={() => setShowSchedule(true)}
                    className="px-3 py-1.5 rounded-lg bg-[#e8002d] text-white text-xs font-medium hover:bg-[#cc0027] transition-colors"
                  >
                    スケジュール
                  </button>
                </div>
              </div>
            </div>
          ))}
        </div>
      </div>

      {/* Pre-upgrade Checklist */}
      <div className="bg-[#0d1220] border border-[#1e2d42] rounded-xl overflow-hidden">
        <button
          onClick={() => setChecklistExpanded(prev => !prev)}
          className="w-full flex items-center justify-between p-4 hover:bg-[#070d19] transition-colors"
        >
          <div className="flex items-center gap-2">
            <CheckSquare className="w-5 h-5 text-[#e8002d]" />
            <h2 className="text-lg font-semibold text-white">アップグレード前チェックリスト</h2>
            {allChecked && <span className="text-xs bg-green-500/20 text-green-400 px-2 py-0.5 rounded-full">全完了</span>}
          </div>
          {checklistExpanded ? <ChevronUp className="w-5 h-5 text-[#7d92b0]" /> : <ChevronDown className="w-5 h-5 text-[#7d92b0]" />}
        </button>
        {checklistExpanded && (
          <div className="border-t border-[#1e2d42] divide-y divide-[#1e2d42]">
            {CHECKLIST_ITEMS.map(item => (
              <div
                key={item.id}
                className="flex items-start gap-3 p-4 hover:bg-[#070d19] transition-colors cursor-pointer"
                onClick={() => toggleChecklist(item.id)}
              >
                {checkedItems[item.id]
                  ? <CheckSquare className="w-5 h-5 text-green-400 shrink-0 mt-0.5" />
                  : <Square className="w-5 h-5 text-[#7d92b0] shrink-0 mt-0.5" />
                }
                <div>
                  <p className={`text-sm font-medium ${checkedItems[item.id] ? 'text-green-400 line-through' : 'text-white'}`}>{item.label}</p>
                  <p className="text-xs text-[#7d92b0] mt-0.5">{item.desc}</p>
                </div>
              </div>
            ))}
          </div>
        )}
      </div>

      {/* Upgrade Schedule */}
      <div className="bg-[#0d1220] border border-[#1e2d42] rounded-xl overflow-hidden">
        <div className="flex items-center justify-between p-4 border-b border-[#1e2d42]">
          <h2 className="text-lg font-semibold text-white">アップグレードスケジュール</h2>
          <button onClick={() => setShowSchedule(true)}
            className="flex items-center gap-2 px-3 py-1.5 rounded-lg bg-[#e8002d] text-white text-sm font-medium hover:bg-[#cc0027] transition-colors">
            <ArrowUpCircle className="w-4 h-4" />スケジュール追加
          </button>
        </div>
        {scheduled.length === 0 ? (
          <div className="p-8 text-center text-[#7d92b0] text-sm">スケジュールされたアップグレードはありません</div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full">
              <thead>
                <tr className="border-b border-[#1e2d42]">
                  {['バージョン', '予定日時', 'ステータス', 'メンテナンス時間', 'ロールバック', 'メモ'].map(h => (
                    <th key={h} className="text-left px-4 py-3 text-[#7d92b0] text-xs font-medium uppercase whitespace-nowrap">{h}</th>
                  ))}
                </tr>
              </thead>
              <tbody>
                {scheduled.map(s => (
                  <tr key={s.id} className="border-b border-[#1e2d42] hover:bg-[#070d19] transition-colors">
                    <td className="px-4 py-3 text-white font-medium text-sm">v{s.version}</td>
                    <td className="px-4 py-3 text-[#7d92b0] text-sm whitespace-nowrap">{s.scheduled_at}</td>
                    <td className="px-4 py-3"><StatusBadge status={s.status} /></td>
                    <td className="px-4 py-3 text-[#7d92b0] text-sm">{s.maintenance_window}分</td>
                    <td className="px-4 py-3">
                      <span className={`text-xs font-medium ${s.rollback_available ? 'text-green-400' : 'text-[#7d92b0]'}`}>
                        {s.rollback_available ? '有効' : '無効'}
                      </span>
                    </td>
                    <td className="px-4 py-3 text-[#7d92b0] text-sm">{s.notes}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>

      {/* Upgrade History */}
      <div className="bg-[#0d1220] border border-[#1e2d42] rounded-xl overflow-hidden">
        <div className="flex items-center justify-between p-4 border-b border-[#1e2d42]">
          <h2 className="text-lg font-semibold text-white">アップグレード履歴</h2>
          {lastCompleted && (
            <button
              onClick={() => setRollbackConfirm(true)}
              className="flex items-center gap-2 px-3 py-1.5 rounded-lg border border-orange-500/50 text-orange-400 hover:bg-orange-500/10 text-sm transition-colors"
            >
              <RotateCcw className="w-4 h-4" />v{lastCompleted.version}へロールバック
            </button>
          )}
        </div>
        <div className="overflow-x-auto">
          <table className="w-full">
            <thead>
              <tr className="border-b border-[#1e2d42]">
                {['バージョン', '開始日時', '完了日時', '所要時間', 'ステータス', 'デプロイ担当'].map(h => (
                  <th key={h} className="text-left px-4 py-3 text-[#7d92b0] text-xs font-medium uppercase whitespace-nowrap">{h}</th>
                ))}
              </tr>
            </thead>
            <tbody>
              {history.map(h => (
                <tr key={h.id} className="border-b border-[#1e2d42] hover:bg-[#070d19] transition-colors">
                  <td className="px-4 py-3 text-white font-medium text-sm">v{h.version}</td>
                  <td className="px-4 py-3 text-[#7d92b0] text-sm whitespace-nowrap">{h.started_at}</td>
                  <td className="px-4 py-3 text-[#7d92b0] text-sm whitespace-nowrap">{h.completed_at}</td>
                  <td className="px-4 py-3 text-[#7d92b0] text-sm">{h.duration_min}分</td>
                  <td className="px-4 py-3"><StatusBadge status={h.status} /></td>
                  <td className="px-4 py-3 text-[#7d92b0] text-sm">{h.deployed_by}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>

      {/* Agent Version Distribution */}
      <div className="bg-[#0d1220] border border-[#1e2d42] rounded-xl overflow-hidden">
        <div className="p-4 border-b border-[#1e2d42]">
          <div className="flex items-center gap-2">
            <Cpu className="w-5 h-5 text-[#e8002d]" />
            <h2 className="text-lg font-semibold text-white">エージェントバージョン分布</h2>
          </div>
        </div>
        <div className="overflow-x-auto">
          <table className="w-full">
            <thead>
              <tr className="border-b border-[#1e2d42]">
                {['バージョン', '台数', '全体比率', '分布', ''].map(h => (
                  <th key={h} className="text-left px-4 py-3 text-[#7d92b0] text-xs font-medium uppercase">{h}</th>
                ))}
              </tr>
            </thead>
            <tbody>
              {agentDist.map(a => (
                <tr key={a.version} className="border-b border-[#1e2d42] hover:bg-[#070d19] transition-colors">
                  <td className="px-4 py-3">
                    <span className="text-white font-medium text-sm">v{a.version}</span>
                    {a.version === currentVer.version && (
                      <span className="ml-2 text-xs bg-green-500/20 text-green-400 px-1.5 py-0.5 rounded-sm">最新</span>
                    )}
                  </td>
                  <td className="px-4 py-3 text-[#7d92b0] text-sm">{(a.count ?? 0).toLocaleString()}台</td>
                  <td className="px-4 py-3 text-[#7d92b0] text-sm">{a.pct.toFixed(1)}%</td>
                  <td className="px-4 py-3 min-w-[160px]">
                    <div className="h-2 bg-[#1e2d42] rounded-full overflow-hidden">
                      <div
                        className="h-full rounded-full transition-all"
                        style={{
                          width: `${a.pct}%`,
                          backgroundColor: a.version === currentVer.version ? '#22c55e' : '#3b82f6',
                        }}
                      />
                    </div>
                  </td>
                  <td className="px-4 py-3">
                    {a.version !== currentVer.version && (
                      <button className="flex items-center gap-1 text-xs text-[#7d92b0] hover:text-white border border-[#1e2d42] hover:border-[#e8002d] px-2 py-1 rounded-sm transition-colors">
                        <Download className="w-3 h-3" />強制アップデート
                      </button>
                    )}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>

      {/* Schedule Modal */}
      {showSchedule && (
        <ScheduleModal
          upgrades={upgrades}
          onClose={() => setShowSchedule(false)}
          onSchedule={data => scheduleMutation.mutate(data)}
        />
      )}

      {/* Rollback Confirm */}
      {rollbackConfirm && lastCompleted && (
        <div className="fixed inset-0 bg-black/60 flex items-center justify-center z-50 p-4">
          <div className="bg-[#0d1220] border border-[#1e2d42] rounded-xl w-full max-w-sm">
            <div className="p-4 border-b border-[#1e2d42]">
              <div className="flex items-center gap-2">
                <AlertTriangle className="w-5 h-5 text-orange-400" />
                <h3 className="text-white font-semibold">ロールバックの確認</h3>
              </div>
            </div>
            <div className="p-4">
              <p className="text-[#7d92b0] text-sm">
                バージョン <span className="text-white font-medium">v{lastCompleted.version}</span> へロールバックしますか？<br /><br />
                この操作により現在のバージョン <span className="text-white font-medium">v{currentVer.version}</span> から前バージョンに戻ります。
              </p>
              <div className="mt-3 bg-orange-500/10 border border-orange-500/30 rounded-lg p-3">
                <p className="text-orange-400 text-xs">ロールバック中はサービスが一時停止します</p>
              </div>
            </div>
            <div className="flex justify-end gap-2 p-4 border-t border-[#1e2d42]">
              <button onClick={() => setRollbackConfirm(false)} className="px-4 py-2 rounded-lg border border-[#1e2d42] text-[#7d92b0] hover:text-white text-sm">キャンセル</button>
              <button onClick={() => setRollbackConfirm(false)} className="px-4 py-2 rounded-lg bg-orange-500 text-white text-sm font-semibold hover:bg-orange-400 transition-colors flex items-center gap-2">
                <RotateCcw className="w-4 h-4" />ロールバック実行
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  )
}

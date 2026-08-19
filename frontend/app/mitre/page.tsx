'use client'

import { useState, useMemo } from 'react'
import { useQuery } from '@tanstack/react-query'
import { apiFetch } from '@/lib/api'
import { Shield, Target, AlertTriangle, ChevronRight, X } from 'lucide-react'
import Link from 'next/link'

import { PageDataUnavailable } from '@/components/PageDataUnavailable'

// ── MITRE ATT&CK data ────────────────────────────────────────────────────────

const TACTICS = [
  { id: 'TA0001', name: '初期アクセス',      techniques: ['T1190','T1133','T1078','T1566'] },
  { id: 'TA0002', name: '実行',              techniques: ['T1059','T1053','T1204','T1569'] },
  { id: 'TA0003', name: '永続化',            techniques: ['T1547','T1543','T1053','T1078'] },
  { id: 'TA0004', name: '権限昇格',          techniques: ['T1548','T1055','T1134','T1068'] },
  { id: 'TA0005', name: '防御回避',          techniques: ['T1055','T1562','T1070','T1036'] },
  { id: 'TA0006', name: '認証情報アクセス',   techniques: ['T1003','T1110','T1555','T1056'] },
  { id: 'TA0007', name: '探索',              techniques: ['T1082','T1083','T1046','T1057'] },
  { id: 'TA0008', name: '横展開',            techniques: ['T1021','T1072','T1080','T1550'] },
  { id: 'TA0009', name: '収集',              techniques: ['T1005','T1039','T1025','T1113'] },
  { id: 'TA0010', name: '漏洩',              techniques: ['T1041','T1048','T1567','T1052'] },
  { id: 'TA0011', name: 'C2',               techniques: ['T1071','T1095','T1105','T1132'] },
]

const TECHNIQUE_NAMES: Record<string, string> = {
  'T1190': '脆弱性悪用 (Public)',
  'T1133': 'リモートサービス',
  'T1078': '正規アカウント',
  'T1566': 'フィッシング',
  'T1059': 'コマンドシェル',
  'T1053': 'スケジュールタスク',
  'T1204': 'ユーザー実行',
  'T1569': 'システムサービス',
  'T1547': 'スタートアップ',
  'T1543': 'サービス作成',
  'T1548': '権限昇格回避',
  'T1055': 'プロセスインジェクション',
  'T1134': 'アクセストークン',
  'T1068': '脆弱性悪用 (権限)',
  'T1562': '防御無効化',
  'T1070': '痕跡削除',
  'T1036': '偽装',
  'T1003': '認証情報ダンプ',
  'T1110': 'ブルートフォース',
  'T1555': '認証情報ストア',
  'T1056': 'インプットキャプチャ',
  'T1082': 'システム情報',
  'T1083': 'ファイル探索',
  'T1046': 'ネットワークスキャン',
  'T1057': 'プロセス探索',
  'T1021': 'リモートサービス',
  'T1072': 'リモート管理ツール',
  'T1080': '共有コンテンツ汚染',
  'T1550': '代替認証',
  'T1005': 'ローカルデータ収集',
  'T1039': 'ネットワーク共有収集',
  'T1025': 'リムーバブルメディア',
  'T1113': 'スクリーンキャプチャ',
  'T1041': 'C2経由漏洩',
  'T1048': '代替プロトコル漏洩',
  'T1567': 'クラウドサービス漏洩',
  'T1052': '物理メディア漏洩',
  'T1071': 'アプリケーション層C2',
  'T1095': 'Non-HTTP C2',
  'T1105': 'ツール転送',
  'T1132': 'データエンコーディング',
}

// ── Types ─────────────────────────────────────────────────────────────────────

interface Alert {
  id: string
  title: string
  severity: string | number
  mitre_technique?: string
  mitre_tactic?: string
  status: string
  created_at: string
  agent_id?: string
}

interface AlertsResponse {
  data?: Alert[]
  alerts?: Alert[]
}

// ── Helpers ───────────────────────────────────────────────────────────────────

const TIME_FILTERS = [
  { label: '24h', hours: 24 },
  { label: '7d',  hours: 168 },
  { label: '30d', hours: 720 },
  { label: 'All', hours: 0 },
] as const

type TimeFilter = typeof TIME_FILTERS[number]['label']

function normaliseSeverity(sev: string | number): number {
  if (typeof sev === 'number') return sev
  switch (sev.toLowerCase()) {
    case 'critical': return 4
    case 'high':     return 3
    case 'medium':   return 2
    case 'low':      return 1
    default:         return 0
  }
}

function severityLabel(sev: string | number): string {
  if (typeof sev === 'string') return sev
  if (sev >= 4) return 'Critical'
  if (sev >= 3) return 'High'
  if (sev >= 2) return 'Medium'
  return 'Low'
}

function cellColors(hits: number, maxSev: number): string {
  if (hits === 0) return 'bg-gray-800 text-gray-600 border-gray-700'
  if (maxSev >= 9 || hits >= 10) return 'bg-red-900/50 text-red-300 border-red-800 hover:bg-red-900/70'
  if (hits >= 3)  return 'bg-yellow-900/50 text-yellow-300 border-yellow-800 hover:bg-yellow-900/70'
  return 'bg-blue-900/50 text-blue-300 border-blue-800 hover:bg-blue-900/70'
}

function sevBadgeClass(sev: string | number): string {
  const n = normaliseSeverity(sev)
  if (n >= 4) return 'bg-red-900/50 text-red-300 border border-red-700'
  if (n >= 3) return 'bg-orange-900/50 text-orange-300 border border-orange-700'
  if (n >= 2) return 'bg-yellow-900/50 text-yellow-300 border border-yellow-700'
  return 'bg-blue-900/50 text-blue-300 border border-blue-700'
}

// ── Main component ────────────────────────────────────────────────────────────

interface TechStat { technique: string; count: number; max_severity: number }
interface MITREStatsResponse { techniques: TechStat[] }

export default function MITREPage() {
  const [timeFilter, setTimeFilter] = useState<TimeFilter>('All')
  const [selectedCell, setSelectedCell] = useState<{ tacticId: string; techId: string } | null>(null)

  const hours = TIME_FILTERS.find(t => t.label === timeFilter)?.hours ?? 168

  // ① ヒートマップ用：mitre-stats エンドポイントからカウントデータを取得
  const { data: statsData, isLoading, isError } = useQuery<MITREStatsResponse>({
    queryKey: ['mitre-stats', timeFilter],
    queryFn: () => apiFetch<MITREStatsResponse>(
      `/api/v1/alerts/mitre-stats?hours=${hours}`
    ),
    staleTime: 60_000,
  })

  // techId → { count, maxSev } のマップ（サブテクニックはベースIDに集約）
  const hitMap = useMemo(() => {
    const map = new Map<string, { count: number; maxSev: number }>()
    for (const ts of statsData?.techniques ?? []) {
      const base = ts.technique.split('.')[0].toUpperCase()
      const existing = map.get(base)
      if (existing) {
        existing.count += ts.count
        existing.maxSev = Math.max(existing.maxSev, ts.max_severity)
      } else {
        map.set(base, { count: ts.count, maxSev: ts.max_severity })
      }
    }
    return map
  }, [statsData])

  // ② ドリルダウン用：セル選択時のみ個別アラートを取得
  const drillUrl = selectedCell
    ? `/api/v1/alerts?mitre_technique=${encodeURIComponent(selectedCell.techId)}&per_page=50&page=1${hours > 0 ? `&from=${encodeURIComponent(new Date(Date.now() - hours * 3600_000).toISOString())}` : ''}`
    : null

  const { data: drillData } = useQuery<AlertsResponse>({
    queryKey: ['mitre-drill', selectedCell?.techId, timeFilter],
    queryFn: () => apiFetch<AlertsResponse>(drillUrl!),
    enabled: drillUrl !== null,
    staleTime: 30_000,
  })
  const selectedAlerts: Alert[] = useMemo(
    () => drillData?.data ?? drillData?.alerts ?? [],
    [drillData]
  )

  // Summary stats（ヒートマップのカウントから集計）
  const detectedTactics = useMemo(() => {
    const tacticSet = new Set<string>()
    for (const tactic of TACTICS) {
      if (tactic.techniques.some(t => (hitMap.get(t)?.count ?? 0) > 0)) {
        tacticSet.add(tactic.id)
      }
    }
    return tacticSet.size
  }, [hitMap])

  const detectedTechniques = useMemo(() => {
    let count = 0
    for (const tactic of TACTICS)
      for (const t of tactic.techniques)
        if ((hitMap.get(t)?.count ?? 0) > 0) count++
    return count
  }, [hitMap])

  const criticalHits = useMemo(() => {
    let count = 0
    for (const { maxSev } of hitMap.values())
      if (maxSev >= 9) count++
    return count
  }, [hitMap])

  // Total unique techniques in grid
  const totalTechniquesInGrid = useMemo(() => {
    const set = new Set<string>()
    for (const t of TACTICS) for (const id of t.techniques) set.add(id)
    return set.size
  }, [])

  const selectedTactic = selectedCell
    ? TACTICS.find(t => t.id === selectedCell.tacticId)
    : null

  return (
    <div className="min-h-screen bg-gray-900 text-white">
      <PageDataUnavailable />
      <div className="max-w-full px-6 py-8">

        {/* ── Header ── */}
        <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-4 mb-8">
          <div className="flex items-center gap-3">
            <Shield className="w-7 h-7 text-blue-400 shrink-0" />
            <div>
              <h1 className="text-2xl font-bold text-white">MITRE ATT&CK マトリクス</h1>
              <p className="text-sm text-gray-400 mt-0.5">
                検知済みテクニック: <span className="text-white font-semibold">{isLoading ? '…' : detectedTechniques}</span> / {totalTechniquesInGrid}
              </p>
            </div>
          </div>

          {/* Time filter */}
          <div className="flex items-center gap-1 bg-gray-800 rounded-lg p-1 border border-gray-700">
            {TIME_FILTERS.map(({ label }) => (
              <button
                key={label}
                onClick={() => setTimeFilter(label)}
                className={`px-3 py-1 text-sm rounded-md transition-colors ${
                  timeFilter === label
                    ? 'bg-blue-600 text-white'
                    : 'text-gray-400 hover:text-white hover:bg-gray-700'
                }`}
              >
                {label}
              </button>
            ))}
          </div>
        </div>

        {/* ── Summary cards ── */}
        <div className="grid grid-cols-2 sm:grid-cols-4 gap-4 mb-8">
          <div className="bg-gray-800 border border-gray-700 rounded-xl p-4">
            <div className="flex items-center gap-2 mb-2">
              <Shield className="w-4 h-4 text-blue-400" />
              <span className="text-xs text-gray-400">検知済み戦術</span>
            </div>
            <p className="text-2xl font-bold text-blue-400">
              {isLoading ? '…' : detectedTactics}
              <span className="text-sm text-gray-500 font-normal"> / {TACTICS.length}</span>
            </p>
          </div>
          <div className="bg-gray-800 border border-gray-700 rounded-xl p-4">
            <div className="flex items-center gap-2 mb-2">
              <Target className="w-4 h-4 text-purple-400" />
              <span className="text-xs text-gray-400">検知済みテクニック</span>
            </div>
            <p className="text-2xl font-bold text-purple-400">
              {isLoading ? '…' : detectedTechniques}
              <span className="text-sm text-gray-500 font-normal"> / {totalTechniquesInGrid}</span>
            </p>
          </div>
          <div className="bg-gray-800 border border-gray-700 rounded-xl p-4">
            <div className="flex items-center gap-2 mb-2">
              <AlertTriangle className="w-4 h-4 text-red-400" />
              <span className="text-xs text-gray-400">クリティカルヒット</span>
            </div>
            <p className="text-2xl font-bold text-red-400">{isLoading ? '…' : criticalHits}</p>
          </div>
          <div className="bg-gray-800 border border-gray-700 rounded-xl p-4">
            <div className="flex items-center gap-2 mb-2">
              <ChevronRight className="w-4 h-4 text-green-400" />
              <span className="text-xs text-gray-400">総アラート数</span>
            </div>
            <p className="text-2xl font-bold text-green-400">{isLoading ? '…' : Array.from(hitMap.values()).reduce((s, v) => s + v.count, 0)}</p>
          </div>
        </div>

        {/* ── Matrix ── */}
        {isLoading ? (
          <div className="text-center py-20 text-gray-500">読み込み中...</div>
        ) : isError ? (
          <div className="text-center py-20 bg-[#0d1220] rounded-xl border border-[#e8002d]/30">
            <p className="text-[#e8002d] text-sm font-medium">MITREデータの取得に失敗しました</p>
            <p className="text-gray-500 text-xs mt-1">ネットワーク接続またはサーバーの状態を確認してください</p>
          </div>
        ) : (
          <div className="overflow-x-auto">
            <div
              className="grid gap-1 min-w-max"
              style={{ gridTemplateColumns: `repeat(${TACTICS.length}, minmax(120px, 1fr))` }}
            >
              {/* Tactic column headers */}
              {TACTICS.map(tactic => {
                const tacticHits = tactic.techniques.some(t => (hitMap.get(t)?.count ?? 0) > 0)
                return (
                  <div
                    key={tactic.id}
                    className={`px-2 py-2 text-center rounded-t border-b-2 ${
                      tacticHits
                        ? 'border-blue-500 bg-gray-800'
                        : 'border-gray-700 bg-gray-800/60'
                    }`}
                  >
                    <p className={`text-xs font-bold leading-tight ${tacticHits ? 'text-white' : 'text-gray-400'}`}>
                      {tactic.name}
                    </p>
                    <p className="text-[10px] text-gray-500 mt-0.5">{tactic.id}</p>
                  </div>
                )
              })}

              {/* Technique cells — each column is one tactic */}
              {TACTICS.map(tactic => (
                <div key={tactic.id} className="flex flex-col gap-1 pt-1">
                  {tactic.techniques.map(techId => {
                    const stat = hitMap.get(techId)
                    const hits = stat?.count ?? 0
                    const maxSev = stat?.maxSev ?? 0
                    const techName = TECHNIQUE_NAMES[techId] ?? techId
                    const tooltipText = `${techId}: ${techName}\n検知数: ${hits}${hits > 0 ? `\n最高深刻度: ${severityLabel(maxSev)}` : ''}`

                    return (
                      <button
                        key={techId}
                        title={tooltipText}
                        disabled={hits === 0}
                        onClick={() => hits > 0 && setSelectedCell({ tacticId: tactic.id, techId })}
                        className={`rounded-sm border px-1.5 py-1.5 text-left transition-colors w-full ${cellColors(hits, maxSev)} ${
                          hits > 0 ? 'cursor-pointer' : 'cursor-default'
                        }`}
                      >
                        <p className="text-[10px] font-mono font-bold leading-none mb-0.5">{techId}</p>
                        <p className="text-[9px] leading-tight break-words">{techName}</p>
                        {hits > 0 && (
                          <p className="text-[10px] font-bold mt-1 text-right">
                            {hits}件
                          </p>
                        )}
                      </button>
                    )
                  })}
                </div>
              ))}
            </div>
          </div>
        )}

        {/* ── Legend ── */}
        <div className="flex items-center gap-5 mt-4 text-xs text-gray-500 flex-wrap">
          <span className="font-semibold">凡例:</span>
          {[
            { cls: 'bg-gray-800 border-gray-700',            label: '未検知' },
            { cls: 'bg-blue-900/50 border-blue-800',         label: '1-2件' },
            { cls: 'bg-yellow-900/50 border-yellow-800',     label: '3-9件' },
            { cls: 'bg-red-900/50 border-red-800',           label: '10件以上' },
          ].map(l => (
            <div key={l.label} className="flex items-center gap-1.5">
              <div className={`w-4 h-4 rounded-sm border ${l.cls}`} />
              <span>{l.label}</span>
            </div>
          ))}
          <span className="ml-auto text-gray-600">クリックでアラート詳細を表示</span>
        </div>
      </div>

      {/* ── Sidebar / Modal ── */}
      {selectedCell && (
        <>
          {/* Backdrop */}
          <div
            className="fixed inset-0 bg-black/60 z-40"
            onClick={() => setSelectedCell(null)}
          />

          {/* Slide-in panel */}
          <div className="fixed top-0 right-0 h-full w-full max-w-xl bg-gray-900 border-l border-gray-700 z-50 flex flex-col shadow-2xl">
            {/* Panel header */}
            <div className="flex items-start justify-between p-5 border-b border-gray-700">
              <div>
                <div className="flex items-center gap-2 mb-1">
                  <Target className="w-5 h-5 text-blue-400" />
                  <span className="text-xs text-gray-400 font-mono">{selectedCell.techId}</span>
                  {selectedTactic && (
                    <span className="text-xs text-gray-500">— {selectedTactic.name}</span>
                  )}
                </div>
                <h2 className="text-lg font-bold text-white">
                  {TECHNIQUE_NAMES[selectedCell.techId] ?? selectedCell.techId}
                </h2>
                <p className="text-sm text-gray-400 mt-0.5">{selectedAlerts.length}件のアラート</p>
              </div>
              <button
                onClick={() => setSelectedCell(null)}
                className="p-1.5 rounded-lg hover:bg-gray-800 transition-colors text-gray-400 hover:text-white"
              >
                <X className="w-5 h-5" />
              </button>
            </div>

            {/* Alert list */}
            <div className="flex-1 overflow-y-auto p-4 space-y-2">
              {selectedAlerts.length === 0 ? (
                <p className="text-center text-gray-500 py-8">アラートがありません</p>
              ) : (
                selectedAlerts
                  .slice()
                  .sort((a, b) => normaliseSeverity(b.severity) - normaliseSeverity(a.severity))
                  .map(alert => (
                    <Link
                      key={alert.id}
                      href={`/alerts/${alert.id}`}
                      className="block bg-gray-800 border border-gray-700 rounded-lg p-3 hover:border-blue-600 hover:bg-gray-750 transition-colors group"
                      onClick={() => setSelectedCell(null)}
                    >
                      <div className="flex items-start justify-between gap-2">
                        <p className="text-sm text-white font-medium group-hover:text-blue-300 transition-colors line-clamp-2">
                          {alert.title}
                        </p>
                        <span className={`text-xs px-2 py-0.5 rounded-sm shrink-0 ${sevBadgeClass(alert.severity)}`}>
                          {severityLabel(alert.severity)}
                        </span>
                      </div>
                      <div className="flex items-center gap-3 mt-2 text-xs text-gray-500">
                        <span>{new Date(alert.created_at).toLocaleString('ja-JP')}</span>
                        {alert.agent_id && <span>エージェント: {alert.agent_id}</span>}
                        <span className="ml-auto flex items-center gap-1 text-blue-500 group-hover:text-blue-400">
                          詳細 <ChevronRight className="w-3 h-3" />
                        </span>
                      </div>
                    </Link>
                  ))
              )}
            </div>

            {/* Footer link */}
            <div className="p-4 border-t border-gray-700">
              <Link
                href={`/alerts?mitre_technique=${selectedCell.techId}`}
                className="flex items-center justify-center gap-2 w-full py-2.5 bg-blue-600 hover:bg-blue-700 text-white text-sm font-medium rounded-lg transition-colors"
                onClick={() => setSelectedCell(null)}
              >
                アラート一覧で開く
                <ChevronRight className="w-4 h-4" />
              </Link>
            </div>
          </div>
        </>
      )}
    </div>
  )
}

'use client'

import { useState } from 'react'
import { useParams, useRouter } from 'next/navigation'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { apiFetch } from '@/lib/api'
import { displayUser } from '@/lib/display-user'
import {
  ArrowLeft,
  Download,
  FileText,
  RefreshCw,
  CheckCircle,
  Clock,
  AlertTriangle,
  User,
  Calendar,
  ExternalLink,
  Shield,
  Monitor,
  ChevronRight,
} from 'lucide-react'
import { PageDataUnavailable } from '@/components/PageDataUnavailable'

import { USE_MOCK, m, mockOr } from '@/lib/mock'

// ─── Types ────────────────────────────────────────────────────────────────────

interface Report {
  id: string
  title: string
  report_type: 'security_summary' | 'incident_report' | 'compliance' | 'executive'
  period_start: string
  period_end: string
  status: 'generating' | 'ready' | 'failed'
  created_by?: string
  created_at: string
  summary?: {
    total_alerts: number
    critical_alerts: number
    resolved_alerts: number
    avg_resolution_hours: number
    top_techniques: Array<{ technique: string; count: number }>
    severity_breakdown: Record<string, number>
  }
}

interface ReportAlert {
  id: string
  datetime: string
  title: string
  severity: 'critical' | 'high' | 'medium' | 'low'
  status: 'open' | 'investigating' | 'resolved'
  assignee: string
}

interface ReportEndpoint {
  id: string
  hostname: string
  os: string
  alert_count: number
  last_detected: string
}

// ─── Mock data ────────────────────────────────────────────────────────────────

const MOCK_ALERTS: ReportAlert[] = [
  { id: 'a1', datetime: '2026-03-10T02:14:33Z', title: 'PowerShellによる疑わしいスクリプト実行', severity: 'critical', status: 'resolved', assignee: '田中 健' },
  { id: 'a2', datetime: '2026-03-10T07:45:11Z', title: 'LSASS メモリダンプの試み', severity: 'critical', status: 'resolved', assignee: '田中 健' },
  { id: 'a3', datetime: '2026-03-11T11:22:05Z', title: '外部C2サーバーへの通信検知', severity: 'high', status: 'investigating', assignee: '佐藤 美咲' },
  { id: 'a4', datetime: '2026-03-11T14:09:47Z', title: '特権昇格の試み (UAC バイパス)', severity: 'high', status: 'resolved', assignee: '鈴木 大輔' },
  { id: 'a5', datetime: '2026-03-12T09:31:28Z', title: '横方向移動: Pass-the-Hash検知', severity: 'high', status: 'open', assignee: '未割当' },
  { id: 'a6', datetime: '2026-03-12T15:55:02Z', title: 'スケジュールタスクによる永続化', severity: 'medium', status: 'resolved', assignee: '佐藤 美咲' },
  { id: 'a7', datetime: '2026-03-13T08:17:39Z', title: 'Mimikatz 実行の疑い', severity: 'critical', status: 'investigating', assignee: '田中 健' },
  { id: 'a8', datetime: '2026-03-13T13:44:15Z', title: 'WMI 経由のリモートコード実行', severity: 'high', status: 'resolved', assignee: '鈴木 大輔' },
  { id: 'a9', datetime: '2026-03-14T10:02:58Z', title: '異常なネットワークポートスキャン', severity: 'medium', status: 'resolved', assignee: '佐藤 美咲' },
  { id: 'a10', datetime: '2026-03-14T16:28:44Z', title: 'レジストリ改ざんによる自動起動登録', severity: 'low', status: 'resolved', assignee: '鈴木 大輔' },
]

const MOCK_ENDPOINTS: ReportEndpoint[] = [
  { id: 'e1', hostname: 'WORKSTATION-042', os: 'Windows 11 Pro', alert_count: 8, last_detected: '2026-03-14T16:28:44Z' },
  { id: 'e2', hostname: 'SERVER-DC01', os: 'Windows Server 2022', alert_count: 5, last_detected: '2026-03-13T13:44:15Z' },
  { id: 'e3', hostname: 'WORKSTATION-017', os: 'Windows 10 Enterprise', alert_count: 3, last_detected: '2026-03-13T08:17:39Z' },
  { id: 'e4', hostname: 'LAPTOP-EXEC-03', os: 'macOS 14.3', alert_count: 2, last_detected: '2026-03-12T09:31:28Z' },
  { id: 'e5', hostname: 'SERVER-APP02', os: 'Ubuntu 22.04 LTS', alert_count: 1, last_detected: '2026-03-11T11:22:05Z' },
]

const MOCK_REPORT_FALLBACK: Report = {
  id: 'demo',
  title: '週次セキュリティサマリーレポート',
  report_type: 'security_summary',
  period_start: '2026-03-08T00:00:00Z',
  period_end: '2026-03-14T23:59:59Z',
  status: 'ready',
  created_by: '田中 健',
  created_at: '2026-03-15T01:00:00Z',
  summary: {
    total_alerts: 47,
    critical_alerts: 12,
    resolved_alerts: 38,
    avg_resolution_hours: 3.4,
    top_techniques: [
      { technique: 'T1059 – Command and Scripting Interpreter', count: 14 },
      { technique: 'T1003 – OS Credential Dumping', count: 9 },
      { technique: 'T1021 – Remote Services', count: 7 },
      { technique: 'T1547 – Boot or Logon Autostart Execution', count: 5 },
      { technique: 'T1078 – Valid Accounts', count: 4 },
    ],
    severity_breakdown: { critical: 12, high: 18, medium: 11, low: 6 },
  },
}

const RECOMMENDATIONS_BY_TYPE: Record<string, string[]> = {
  security_summary: [
    'PowerShell の実行ポリシーを制限付きに設定し、署名済みスクリプトのみ許可してください。',
    'LSASS プロセスの保護を有効化するため、Credential Guard を展開することを推奨します。',
    '外部通信を監視するため、次世代ファイアウォールおよびDNSフィルタリングを強化してください。',
    '横方向移動の抑制のため、ネットワークセグメンテーションとマイクロセグメンテーションを実施してください。',
    '多要素認証 (MFA) を全特権アカウントに適用し、Pass-the-Hash 攻撃のリスクを低減してください。',
    'エンドポイント検出対応 (EDR) のルールセットを週次で見直し、検知精度を維持してください。',
  ],
  incident_report: [
    '発生したインシデントの根本原因分析 (RCA) を実施し、再発防止策を文書化してください。',
    '影響を受けたシステムを隔離し、フォレンジック調査のためにメモリダンプおよびログを保全してください。',
    '侵害された資格情報をすべてリセットし、セッショントークンを無効化してください。',
    'インシデント対応プレイブックを更新し、今回の手法に対する対策手順を追加してください。',
    '社内外の関係者への報告タイムラインを確認し、コンプライアンス要件に沿った通知を行ってください。',
    '攻撃者の TTPs に基づいた脅威インテリジェンスフィードを更新し、類似攻撃の早期検知に備えてください。',
  ],
  compliance: [
    '未対応の脆弱性パッチを 72 時間以内に適用し、コンプライアンス要件の充足率を向上させてください。',
    '定期的な脆弱性スキャンを自動化し、スキャン結果を SIEM に連携してください。',
    'アクセス権限の四半期レビューを実施し、最小権限の原則を維持してください。',
    'ログ保存期間がコンプライアンス基準を満たしているか確認し、必要に応じて保存ポリシーを更新してください。',
    '従業員向けセキュリティ意識向上トレーニングの実施率を 100% に向上させてください。',
    '暗号化設定を最新の基準 (TLS 1.3, AES-256) に準拠していることを確認してください。',
  ],
  executive: [
    'セキュリティ態勢の改善に向け、年間セキュリティ予算の見直しと増額を経営層に提案してください。',
    'サードパーティリスク管理プログラムを強化し、主要ベンダーのセキュリティ評価を定期実施してください。',
    'インシデント対応チームの体制を強化し、24 時間 365 日対応可能な体制を構築してください。',
    'セキュリティメトリクスダッシュボードを経営会議で定期的に共有し、可視性を向上させてください。',
    'ゼロトラストアーキテクチャへの移行ロードマップを策定し、段階的な実装計画を立案してください。',
    'サイバーセキュリティ保険の補償範囲を見直し、現在のリスクプロファイルに合致しているか確認してください。',
  ],
}

// ─── Constants ────────────────────────────────────────────────────────────────

const SEVERITY_COLORS: Record<string, { bar: string; badge: string; text: string }> = {
  critical: { bar: 'bg-[#e8002d]',    badge: 'bg-[#e8002d]/20 text-[#e8002d]',    text: 'text-[#e8002d]' },
  high:     { bar: 'bg-orange-500',   badge: 'bg-orange-500/20 text-orange-400',  text: 'text-orange-400' },
  medium:   { bar: 'bg-yellow-500',   badge: 'bg-yellow-500/20 text-yellow-400',  text: 'text-yellow-400' },
  low:      { bar: 'bg-blue-500',     badge: 'bg-blue-500/20 text-blue-400',      text: 'text-blue-400' },
}

const SEVERITY_LABELS: Record<string, string> = {
  critical: 'Critical',
  high:     'High',
  medium:   'Medium',
  low:      'Low',
}

const STATUS_BADGES: Record<string, string> = {
  open:          'bg-[#e8002d]/20 text-[#e8002d]',
  investigating: 'bg-yellow-500/20 text-yellow-400',
  resolved:      'bg-green-500/20 text-green-400',
}

const STATUS_LABELS: Record<string, string> = {
  open:          'オープン',
  investigating: '調査中',
  resolved:      '解決済み',
}

const REPORT_TYPE_BADGES: Record<string, string> = {
  security_summary: 'bg-blue-500/20 text-blue-300',
  incident_report:  'bg-[#e8002d]/20 text-[#e8002d]',
  compliance:       'bg-purple-500/20 text-purple-300',
  executive:        'bg-amber-500/20 text-amber-300',
}

const REPORT_TYPE_LABELS: Record<string, string> = {
  security_summary: 'セキュリティサマリー',
  incident_report:  'インシデントレポート',
  compliance:       'コンプライアンス',
  executive:        'エグゼクティブ',
}

const REPORT_STATUS_CONFIG: Record<string, { label: string; cls: string; icon: React.ReactNode }> = {
  generating: {
    label: '生成中',
    cls:   'bg-yellow-500/20 text-yellow-400',
    icon:  <RefreshCw className="w-3.5 h-3.5 animate-spin" />,
  },
  ready: {
    label: '完了',
    cls:   'bg-green-500/20 text-green-400',
    icon:  <CheckCircle className="w-3.5 h-3.5" />,
  },
  failed: {
    label: '失敗',
    cls:   'bg-[#e8002d]/20 text-[#e8002d]',
    icon:  <AlertTriangle className="w-3.5 h-3.5" />,
  },
}

const TABS = ['サマリー', 'アラート詳細', 'エンドポイント', '推奨事項'] as const
type Tab = typeof TABS[number]

// ─── Helpers ──────────────────────────────────────────────────────────────────

function fmt(iso: string): string {
  return new Date(iso).toLocaleString('ja-JP', {
    year: 'numeric', month: '2-digit', day: '2-digit',
    hour: '2-digit', minute: '2-digit',
  })
}

function fmtDate(iso: string): string {
  return new Date(iso).toLocaleDateString('ja-JP', {
    year: 'numeric', month: 'long', day: 'numeric',
  })
}

// ─── Loading skeleton ─────────────────────────────────────────────────────────

function Skeleton({ className = '' }: { className?: string }) {
  return (
    <div className={`animate-pulse bg-[#1e2d42] rounded-sm ${className}`} />
  )
}

// ─── Metric Card ──────────────────────────────────────────────────────────────

function MetricCard({
  label,
  value,
  sub,
  accent = false,
}: {
  label: string
  value: string | number
  sub?: string
  accent?: boolean
}) {
  return (
    <div className="bg-[#0d1220] border border-[#1e2d42] rounded-xl p-4 flex flex-col gap-1">
      <p className="text-[#7d92b0] text-xs">{label}</p>
      <p className={`text-2xl font-bold ${accent ? 'text-[#e8002d]' : 'text-white'}`}>{value}</p>
      {sub && <p className="text-[#7d92b0] text-xs">{sub}</p>}
    </div>
  )
}

// ─── Summary Tab ──────────────────────────────────────────────────────────────

function SummaryTab({ report }: { report: Report }) {
  const s = report.summary ?? m(MOCK_REPORT_FALLBACK).summary!
  const total = Object.values(s.severity_breakdown).reduce((a, b) => a + b, 0) || 1
  const maxTechCount = s.top_techniques[0]?.count ?? 1

  const resolveRate = s.total_alerts
    ? Math.round((s.resolved_alerts / s.total_alerts) * 100)
    : 0

  return (
    <div className="space-y-6">
      {/* Key metrics */}
      <div className="grid grid-cols-2 lg:grid-cols-4 gap-4">
        <MetricCard label="総アラート数" value={s.total_alerts} sub="検知期間内合計" />
        <MetricCard label="重大アラート" value={s.critical_alerts} sub="Critical 件数" accent />
        <MetricCard
          label="解決済み"
          value={`${s.resolved_alerts} 件`}
          sub={`解決率 ${resolveRate}%`}
        />
        <MetricCard
          label="平均対応時間"
          value={`${s.avg_resolution_hours.toFixed(1)} h`}
          sub="検知から解決まで"
        />
      </div>

      {/* Severity distribution */}
      <div className="bg-[#0d1220] border border-[#1e2d42] rounded-xl p-5">
        <h3 className="text-white font-semibold mb-4 text-sm">重大度別分布</h3>
        <div className="space-y-3">
          {(['critical', 'high', 'medium', 'low'] as const).map(sev => {
            const count = s.severity_breakdown[sev] ?? 0
            const pct = Math.round((count / total) * 100)
            const cfg = SEVERITY_COLORS[sev]
            return (
              <div key={sev} className="flex items-center gap-3">
                <span className="text-xs text-[#7d92b0] w-16 shrink-0">{SEVERITY_LABELS[sev]}</span>
                <div className="flex-1 bg-[#070d19] rounded-full h-2 overflow-hidden">
                  <div
                    className={`h-2 rounded-full ${cfg.bar} transition-all duration-700`}
                    style={{ width: `${pct}%` }}
                  />
                </div>
                <span className={`text-xs font-medium w-12 text-right ${cfg.text}`}>
                  {count} <span className="text-[#7d92b0] font-normal">({pct}%)</span>
                </span>
              </div>
            )
          })}
        </div>
      </div>

      {/* Top 5 MITRE ATT&CK techniques */}
      <div className="bg-[#0d1220] border border-[#1e2d42] rounded-xl p-5">
        <h3 className="text-white font-semibold mb-4 text-sm">Top 5 MITRE ATT&CK テクニック</h3>
        <div className="space-y-3">
          {s.top_techniques.slice(0, 5).map((t, idx) => {
            const pct = Math.round((t.count / maxTechCount) * 100)
            return (
              <div key={t.technique} className="flex items-center gap-3">
                <span className="text-[#e8002d] font-bold text-sm w-5 shrink-0 text-right">
                  {idx + 1}
                </span>
                <div className="flex-1 min-w-0">
                  <p className="text-white text-xs truncate mb-1">{t.technique}</p>
                  <div className="bg-[#070d19] rounded-full h-1.5 overflow-hidden">
                    <div
                      className="h-1.5 rounded-full bg-[#e8002d]/60 transition-all duration-700"
                      style={{ width: `${pct}%` }}
                    />
                  </div>
                </div>
                <span className="text-[#7d92b0] text-xs shrink-0 w-8 text-right">{t.count}件</span>
              </div>
            )
          })}
        </div>
      </div>
    </div>
  )
}

// ─── Alerts Tab ───────────────────────────────────────────────────────────────

function AlertsTab() {
  return (
    <div className="bg-[#0d1220] border border-[#1e2d42] rounded-xl overflow-hidden">
      <div className="overflow-x-auto">
        <table className="w-full text-sm">
          <thead>
            <tr className="border-b border-[#1e2d42]">
              <th className="text-left px-4 py-3 text-[#7d92b0] font-medium text-xs">日時</th>
              <th className="text-left px-4 py-3 text-[#7d92b0] font-medium text-xs">タイトル</th>
              <th className="text-left px-4 py-3 text-[#7d92b0] font-medium text-xs">重大度</th>
              <th className="text-left px-4 py-3 text-[#7d92b0] font-medium text-xs">ステータス</th>
              <th className="text-left px-4 py-3 text-[#7d92b0] font-medium text-xs">担当者</th>
            </tr>
          </thead>
          <tbody>
            {m(MOCK_ALERTS).map((alert, i) => {
              const sevCfg = SEVERITY_COLORS[alert.severity]
              return (
                <tr
                  key={alert.id}
                  className={`border-b border-[#1e2d42]/60 hover:bg-[#1e2d42]/30 transition-colors ${
                    i === m(MOCK_ALERTS).length - 1 ? 'border-b-0' : ''
                  }`}
                >
                  <td className="px-4 py-3 text-[#7d92b0] text-xs whitespace-nowrap font-mono">
                    {fmt(alert.datetime)}
                  </td>
                  <td className="px-4 py-3 text-white text-xs max-w-[280px]">
                    <span className="line-clamp-1">{alert.title}</span>
                  </td>
                  <td className="px-4 py-3">
                    <span className={`inline-flex items-center px-2 py-0.5 rounded-full text-xs font-medium ${sevCfg.badge}`}>
                      {SEVERITY_LABELS[alert.severity]}
                    </span>
                  </td>
                  <td className="px-4 py-3">
                    <span className={`inline-flex items-center px-2 py-0.5 rounded-full text-xs font-medium ${STATUS_BADGES[alert.status]}`}>
                      {STATUS_LABELS[alert.status]}
                    </span>
                  </td>
                  <td className="px-4 py-3 text-[#7d92b0] text-xs whitespace-nowrap">
                    <span className="flex items-center gap-1.5">
                      <User className="w-3 h-3" />
                      {alert.assignee}
                    </span>
                  </td>
                </tr>
              )
            })}
          </tbody>
        </table>
      </div>
    </div>
  )
}

// ─── Endpoints Tab ────────────────────────────────────────────────────────────

function EndpointsTab() {
  return (
    <div className="bg-[#0d1220] border border-[#1e2d42] rounded-xl overflow-hidden">
      <div className="overflow-x-auto">
        <table className="w-full text-sm">
          <thead>
            <tr className="border-b border-[#1e2d42]">
              <th className="text-left px-4 py-3 text-[#7d92b0] font-medium text-xs">ホスト名</th>
              <th className="text-left px-4 py-3 text-[#7d92b0] font-medium text-xs">OS</th>
              <th className="text-left px-4 py-3 text-[#7d92b0] font-medium text-xs">アラート数</th>
              <th className="text-left px-4 py-3 text-[#7d92b0] font-medium text-xs">最終検知</th>
            </tr>
          </thead>
          <tbody>
            {m(MOCK_ENDPOINTS).map((ep, i) => (
              <tr
                key={ep.id}
                className={`border-b border-[#1e2d42]/60 hover:bg-[#1e2d42]/30 transition-colors ${
                  i === m(MOCK_ENDPOINTS).length - 1 ? 'border-b-0' : ''
                }`}
              >
                <td className="px-4 py-3">
                  <span className="flex items-center gap-2">
                    <Monitor className="w-3.5 h-3.5 text-[#7d92b0] shrink-0" />
                    <span className="text-white text-xs font-mono">{ep.hostname}</span>
                  </span>
                </td>
                <td className="px-4 py-3 text-[#7d92b0] text-xs">{ep.os}</td>
                <td className="px-4 py-3">
                  <span className={`inline-flex items-center px-2 py-0.5 rounded-full text-xs font-bold ${
                    ep.alert_count >= 5
                      ? 'bg-[#e8002d]/20 text-[#e8002d]'
                      : ep.alert_count >= 3
                        ? 'bg-orange-500/20 text-orange-400'
                        : 'bg-[#1e2d42] text-[#7d92b0]'
                  }`}>
                    {ep.alert_count} 件
                  </span>
                </td>
                <td className="px-4 py-3 text-[#7d92b0] text-xs whitespace-nowrap font-mono">
                  {fmt(ep.last_detected)}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  )
}

// ─── Recommendations Tab ──────────────────────────────────────────────────────

function RecommendationsTab({ reportType }: { reportType: Report['report_type'] }) {
  const recs = RECOMMENDATIONS_BY_TYPE[reportType] ?? RECOMMENDATIONS_BY_TYPE.security_summary

  return (
    <div className="space-y-3">
      {recs.map((rec, idx) => (
        <div
          key={idx}
          className="flex gap-4 bg-[#0d1220] border border-[#1e2d42] rounded-xl p-4 hover:border-[#e8002d]/30 transition-colors"
        >
          <div className="shrink-0 w-7 h-7 rounded-full bg-[#e8002d]/10 border border-[#e8002d]/30 flex items-center justify-center">
            <span className="text-[#e8002d] text-xs font-bold">{idx + 1}</span>
          </div>
          <div className="flex-1 min-w-0">
            <p className="text-white text-sm leading-relaxed">{rec}</p>
          </div>
          <ChevronRight className="w-4 h-4 text-[#1e2d42] shrink-0 mt-0.5" />
        </div>
      ))}

      <div className="mt-4 p-4 bg-[#070d19] border border-[#1e2d42] rounded-xl flex items-start gap-3">
        <Shield className="w-4 h-4 text-[#7d92b0] shrink-0 mt-0.5" />
        <p className="text-[#7d92b0] text-xs leading-relaxed">
          上記の推奨事項はレポートタイプおよび検知されたアラートのパターンに基づいて自動生成されています。
          実際の対応については、セキュリティチームと連携のうえ実施してください。
        </p>
      </div>
    </div>
  )
}

// ─── Main Page ────────────────────────────────────────────────────────────────

export default function ReportDetailPage() {
  const params = useParams()
  const router = useRouter()
  const qc = useQueryClient()
  const id = params?.id as string

  const [activeTab, setActiveTab] = useState<Tab>('サマリー')

  // Fetch report
  const {
    data: reportData,
    isLoading,
    isError,
    error,
  } = useQuery<Report>({
    queryKey: ['report', id],
    queryFn: () => apiFetch<Report>(`/api/v1/reports/${id}`),
    enabled: !!id,
    retry: 1,
    // fall back gracefully — the detail page renders mock data if the API is a stub
  })

  // Use API data if available, otherwise fall back to mock
  // 取得に失敗したときに作り物のレポートを出していました。レポートは
  // 外に出す前提の成果物なので、中身が作り物だと気づく機会がありません。
  const report: Report | null = reportData ?? (isError ? mockOr({ ...MOCK_REPORT_FALLBACK, id }, null) : null)

  // Regenerate mutation
  const regenMutation = useMutation({
    mutationFn: () =>
      apiFetch<Report>('/api/v1/reports', {
        method: 'POST',
        body: JSON.stringify({
          report_type: report?.report_type,
          period_start: report?.period_start,
          period_end: report?.period_end,
        }),
      }),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['report', id] })
      qc.invalidateQueries({ queryKey: ['reports'] })
    },
  })

  function handlePdfDownload() {
    window.open(`/api/v1/reports/${id}/pdf`, '_blank', 'noopener,noreferrer')
  }

  function handleCsvExport() {
    const token =
      typeof window !== 'undefined' ? localStorage.getItem('edr_token') : null
    const params = new URLSearchParams({ format: 'csv' })
    if (token) params.set('token', token)
    window.open(`/api/v1/reports/${id}/export?${params}`, '_blank', 'noopener,noreferrer')
  }

  // ── Render ─────────────────────────────────────────────────────────────────

  if (isLoading) {
    return (
      <div className="min-h-screen bg-[#070d19] p-6 space-y-6">
        <div className="flex items-center gap-3">
          <Skeleton className="w-8 h-8" />
          <Skeleton className="w-64 h-7" />
        </div>
        <Skeleton className="w-full h-16 rounded-xl" />
        <Skeleton className="w-full h-10 rounded-xl" />
        <div className="grid grid-cols-2 lg:grid-cols-4 gap-4">
          {[...Array(4)].map((_, i) => <Skeleton key={i} className="h-24 rounded-xl" />)}
        </div>
        <Skeleton className="w-full h-48 rounded-xl" />
      </div>
    )
  }

  if (!report) {
    return (
      <div className="min-h-screen bg-[#070d19] flex items-center justify-center">
        <div className="text-center space-y-3">
          <AlertTriangle className="w-10 h-10 text-[#e8002d] mx-auto" />
          <p className="text-white font-semibold">レポートが見つかりません</p>
          <p className="text-[#7d92b0] text-sm">{(error as Error)?.message}</p>
          <button
            onClick={() => router.push('/reports')}
            className="mt-4 px-4 py-2 bg-[#1e2d42] hover:bg-[#263850] text-white rounded-lg text-sm transition-colors"
          >
            レポート一覧へ戻る
          </button>
        </div>
      </div>
    )
  }

  const statusCfg = REPORT_STATUS_CONFIG[report.status]

  return (
    <div className="min-h-screen bg-[#070d19] p-4 md:p-6 space-y-5">
      <PageDataUnavailable />

      {/* ── Header ─────────────────────────────────────────────────────────── */}
      <div className="flex flex-wrap items-start gap-4">
        {/* Back + title */}
        <div className="flex items-start gap-3 flex-1 min-w-0">
          <button
            onClick={() => router.push('/reports')}
            className="mt-0.5 p-1.5 rounded-lg text-[#7d92b0] hover:text-white hover:bg-[#1e2d42] transition-colors shrink-0"
            title="レポート一覧へ"
          >
            <ArrowLeft className="w-4 h-4" />
          </button>
          <div className="min-w-0">
            <div className="flex flex-wrap items-center gap-2 mb-1">
              <h1 className="text-white text-xl font-bold truncate">{report.title}</h1>
              <span className={`inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium shrink-0 ${
                REPORT_TYPE_BADGES[report.report_type] ?? 'bg-[#1e2d42] text-[#7d92b0]'
              }`}>
                {REPORT_TYPE_LABELS[report.report_type] ?? report.report_type}
              </span>
            </div>
            <p className="text-[#7d92b0] text-xs">レポート ID: {report.id}</p>
          </div>
        </div>

        {/* Action buttons */}
        <div className="flex items-center gap-2 shrink-0">
          <button
            onClick={() => regenMutation.mutate()}
            disabled={regenMutation.isPending || report.status === 'generating'}
            title="再生成"
            className="flex items-center gap-1.5 px-3 py-2 bg-[#0d1220] border border-[#1e2d42] text-[#7d92b0] hover:text-white hover:border-[#263850] rounded-lg text-xs transition-colors disabled:opacity-40"
          >
            <RefreshCw className={`w-3.5 h-3.5 ${regenMutation.isPending ? 'animate-spin' : ''}`} />
            再生成
          </button>
          <button
            onClick={handleCsvExport}
            className="flex items-center gap-1.5 px-3 py-2 bg-[#0d1220] border border-[#1e2d42] text-[#7d92b0] hover:text-white hover:border-[#263850] rounded-lg text-xs transition-colors"
          >
            <Download className="w-3.5 h-3.5" />
            CSVエクスポート
          </button>
          <button
            onClick={handlePdfDownload}
            className="flex items-center gap-1.5 px-3 py-2 bg-[#e8002d] hover:bg-[#c4001f] text-white rounded-lg text-xs font-medium transition-colors"
          >
            <ExternalLink className="w-3.5 h-3.5" />
            PDFダウンロード
          </button>
        </div>
      </div>

      {/* ── Metadata bar ───────────────────────────────────────────────────── */}
      <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
        <div className="bg-[#0d1220] border border-[#1e2d42] rounded-xl px-4 py-3 flex items-center gap-3">
          <Calendar className="w-4 h-4 text-[#7d92b0] shrink-0" />
          <div className="min-w-0">
            <p className="text-[#7d92b0] text-xs mb-0.5">生成日時</p>
            <p className="text-white text-xs font-medium truncate">{fmt(report.created_at)}</p>
          </div>
        </div>
        <div className="bg-[#0d1220] border border-[#1e2d42] rounded-xl px-4 py-3 flex items-center gap-3">
          <Clock className="w-4 h-4 text-[#7d92b0] shrink-0" />
          <div className="min-w-0">
            <p className="text-[#7d92b0] text-xs mb-0.5">期間</p>
            <p className="text-white text-xs font-medium truncate">
              {fmtDate(report.period_start)} – {fmtDate(report.period_end)}
            </p>
          </div>
        </div>
        <div className="bg-[#0d1220] border border-[#1e2d42] rounded-xl px-4 py-3 flex items-center gap-3">
          <User className="w-4 h-4 text-[#7d92b0] shrink-0" />
          <div className="min-w-0">
            <p className="text-[#7d92b0] text-xs mb-0.5">生成者</p>
            <p className="text-white text-xs font-medium truncate">{displayUser(report.created_by)}</p>
          </div>
        </div>
        <div className="bg-[#0d1220] border border-[#1e2d42] rounded-xl px-4 py-3 flex items-center gap-3">
          <FileText className="w-4 h-4 text-[#7d92b0] shrink-0" />
          <div className="min-w-0">
            <p className="text-[#7d92b0] text-xs mb-0.5">ステータス</p>
            <span className={`inline-flex items-center gap-1.5 px-2 py-0.5 rounded-full text-xs font-medium ${statusCfg.cls}`}>
              {statusCfg.icon}
              {statusCfg.label}
            </span>
          </div>
        </div>
      </div>

      {/* Regeneration error */}
      {regenMutation.isError && (
        <div className="flex items-center gap-2 px-4 py-3 bg-[#e8002d]/10 border border-[#e8002d]/30 rounded-xl text-sm text-[#e8002d]">
          <AlertTriangle className="w-4 h-4 shrink-0" />
          再生成に失敗しました: {(regenMutation.error as Error).message}
        </div>
      )}

      {/* ── Tab bar ────────────────────────────────────────────────────────── */}
      <div className="flex gap-1 bg-[#0d1220] border border-[#1e2d42] rounded-xl p-1">
        {TABS.map(tab => (
          <button
            key={tab}
            onClick={() => setActiveTab(tab)}
            className={`flex-1 px-3 py-2 rounded-lg text-sm font-medium transition-colors ${
              activeTab === tab
                ? 'bg-[#1e2d42] text-white'
                : 'text-[#7d92b0] hover:text-white hover:bg-[#1e2d42]/50'
            }`}
          >
            {tab}
          </button>
        ))}
      </div>

      {/* ── Tab content ────────────────────────────────────────────────────── */}
      {activeTab === 'サマリー' && <SummaryTab report={report} />}
      {activeTab === 'アラート詳細' && <AlertsTab />}
      {activeTab === 'エンドポイント' && <EndpointsTab />}
      {activeTab === '推奨事項' && <RecommendationsTab reportType={report.report_type} />}
    </div>
  )
}

'use client'

import { useState } from 'react'
import { useQuery, useMutation } from '@tanstack/react-query'
import { apiFetch } from '@/lib/api'
import {
  Shield, AlertTriangle, CheckCircle, X, Loader2,
  RefreshCw, Copy, ChevronRight, Cloud, Server, Lock,
} from 'lucide-react'

// ── Types ─────────────────────────────────────────────────────────────────────

type Provider = 'aws' | 'azure' | 'gcp'
type Severity = 'critical' | 'high' | 'medium' | 'low'
type FindingStatus = 'open' | 'suppressed' | 'fixed'

interface CloudPosture {
  provider: Provider
  posture_score: number
  findings: { critical: number; high: number; medium: number; low: number }
  compliance: { cis: number; soc2: number; iso27001: number }
  misconfigurations: Misconfiguration[]
  top_risky_resources: RiskyResource[]
  resources_monitored: number
  last_scanned: string
  // CSPM のデータが 1 件でも入っているか。false のときスコアと
  // コンプライアンス率は「未計測」であって「0 点」でも「100% 準拠」でもない。
  data_available: boolean
}

interface Misconfiguration {
  id: string
  resource_type: string
  resource_id: string
  finding: string
  severity: Severity
  region: string
  status: FindingStatus
  remediation_steps: string[]
  cli_command: string
}

interface RiskyResource {
  resource_id: string
  resource_type: string
  finding_count: number
  highest_severity: Severity
  region: string
}

interface CrossProviderSummary {
  total_resources: number
  common_misconfigs: { type: string; count: number; providers: string[] }[]
  compliance_trend: number[]
}

const EMPTY_CROSS_SUMMARY: CrossProviderSummary = {
  total_resources: 0,
  common_misconfigs: [],
  compliance_trend: [],
}

const EMPTY_POSTURE: CloudPosture = {
  provider: 'aws',
  posture_score: 0,
  findings: { critical: 0, high: 0, medium: 0, low: 0 },
  compliance: { cis: 0, soc2: 0, iso27001: 0 },
  misconfigurations: [],
  top_risky_resources: [],
  resources_monitored: 0,
  last_scanned: '',
  data_available: false,
}

// ── Helpers ───────────────────────────────────────────────────────────────────

function fmtTs(d: string) {
  return new Date(d).toLocaleString('ja-JP', { month: '2-digit', day: '2-digit', hour: '2-digit', minute: '2-digit' })
}

function providerLabel(p: Provider) {
  return { aws: 'AWS', azure: 'Azure', gcp: 'GCP' }[p]
}

function grade(score: number) {
  if (score >= 90) return { label: 'A', cls: 'text-green-400' }
  if (score >= 80) return { label: 'B', cls: 'text-blue-400' }
  if (score >= 70) return { label: 'C', cls: 'text-yellow-400' }
  if (score >= 60) return { label: 'D', cls: 'text-orange-400' }
  return { label: 'F', cls: 'text-red-400' }
}

// ── Badges ────────────────────────────────────────────────────────────────────

function SeverityBadge({ severity }: { severity: Severity }) {
  const cfg: Record<Severity, { cls: string; label: string }> = {
    critical: { cls: 'bg-red-500/20 text-red-400 border-red-500/30',       label: '重大' },
    high:     { cls: 'bg-orange-500/20 text-orange-400 border-orange-500/30', label: '高' },
    medium:   { cls: 'bg-yellow-500/20 text-yellow-400 border-yellow-500/30', label: '中' },
    low:      { cls: 'bg-blue-500/20 text-blue-400 border-blue-500/30',      label: '低' },
  }
  const { cls, label } = cfg[severity]
  return <span className={`inline-flex px-2 py-0.5 rounded-sm border text-[11px] font-medium ${cls}`}>{label}</span>
}

function StatusBadge({ status }: { status: FindingStatus }) {
  const cfg: Record<FindingStatus, { cls: string; label: string }> = {
    open:       { cls: 'bg-red-500/20 text-red-400 border-red-500/30',     label: 'オープン' },
    suppressed: { cls: 'bg-falcon-border text-falcon-muted border-[#2a3f5f]',   label: '抑制済み' },
    fixed:      { cls: 'bg-green-500/20 text-green-400 border-green-500/30', label: '修正済み' },
  }
  const { cls, label } = cfg[status]
  return <span className={`inline-flex px-2 py-0.5 rounded-sm border text-[11px] font-medium ${cls}`}>{label}</span>
}

// ── Remediation Guide Modal ───────────────────────────────────────────────────

function RemediationModal({ finding, onClose }: { finding: Misconfiguration; onClose: () => void }) {
  const [copied, setCopied] = useState(false)

  const handleCopy = () => {
    navigator.clipboard.writeText(finding.cli_command).then(() => {
      setCopied(true)
      setTimeout(() => setCopied(false), 2000)
    })
  }

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/60 backdrop-blur-xs">
      <div className="bg-falcon-surface border border-falcon-border rounded-xl w-full max-w-2xl max-h-[85vh] overflow-hidden flex flex-col">
        <div className="flex items-center justify-between px-6 py-4 border-b border-falcon-border">
          <div className="flex items-center gap-3">
            <Shield className="w-5 h-5 text-falcon-red" />
            <div>
              <h2 className="text-white font-semibold">修復ガイド</h2>
              <p className="text-falcon-muted text-xs font-mono">{finding.resource_id}</p>
            </div>
          </div>
          <button onClick={onClose} className="p-1.5 rounded-sm hover:bg-falcon-border text-falcon-muted hover:text-white transition-colors"><X className="w-4 h-4" /></button>
        </div>

        <div className="flex-1 overflow-y-auto p-6 space-y-5">
          {/* Finding info */}
          <div className="flex items-center gap-2 flex-wrap">
            <SeverityBadge severity={finding.severity} />
            <StatusBadge status={finding.status} />
            <span className="text-xs text-falcon-muted">{finding.resource_type}</span>
            <span className="text-xs text-falcon-muted">—</span>
            <span className="text-xs text-falcon-muted">{finding.region}</span>
          </div>
          <div className="bg-[#070d19] rounded-lg border border-falcon-border p-3">
            <p className="text-white text-sm font-medium">{finding.finding}</p>
          </div>

          {/* Step-by-step */}
          <div>
            <h3 className="text-white font-semibold text-sm mb-3">修復手順</h3>
            <div className="space-y-2">
              {finding.remediation_steps.map((step, i) => (
                <div key={i} className="flex items-start gap-3">
                  <span className="shrink-0 w-6 h-6 rounded-full bg-falcon-red/20 border border-falcon-red/40 flex items-center justify-center text-[11px] font-bold text-falcon-red">
                    {i + 1}
                  </span>
                  <p className="text-falcon-text text-sm pt-0.5">{step}</p>
                </div>
              ))}
            </div>
          </div>

          {/* CLI command */}
          <div>
            <h3 className="text-white font-semibold text-sm mb-2">CLIコマンド</h3>
            <div className="relative bg-[#070d19] rounded-lg border border-falcon-border p-3">
              <pre className="font-mono text-xs text-green-400 whitespace-pre-wrap overflow-x-auto pr-10">{finding.cli_command}</pre>
              <button onClick={handleCopy}
                className="absolute top-2 right-2 p-1.5 rounded-sm hover:bg-falcon-border text-falcon-muted hover:text-white transition-colors"
                title="コピー">
                {copied ? <CheckCircle className="w-4 h-4 text-green-400" /> : <Copy className="w-4 h-4" />}
              </button>
            </div>
            {copied && <p className="text-xs text-green-400 mt-1">コピーしました</p>}
          </div>
        </div>

        <div className="px-6 py-4 border-t border-falcon-border">
          <button onClick={onClose} className="px-4 py-2 text-falcon-muted hover:text-white text-sm transition-colors">閉じる</button>
        </div>
      </div>
    </div>
  )
}

// ── Provider Panel ────────────────────────────────────────────────────────────

function ProviderPanel({ posture }: { posture: CloudPosture }) {
  const [selectedFinding, setSelectedFinding] = useState<Misconfiguration | null>(null)
  const [statusFilter, setStatusFilter] = useState<FindingStatus | 'all'>('all')
  const [severityFilter, setSeverityFilter] = useState<Severity | 'all'>('all')

  // 未計測のときは判定を出さない。0 点 (F 判定) と表示すると「最悪の状態」に、
  // 100 点 (A 判定) と表示すると「完全に準拠」に見えてしまい、どちらも嘘になる。
  const measured = posture.data_available
  const g = measured ? grade(posture.posture_score) : { label: '未計測', cls: 'text-falcon-muted' }
  const totalFindings = posture.findings.critical + posture.findings.high + posture.findings.medium + posture.findings.low

  const filtered = posture.misconfigurations.filter(m => {
    if (statusFilter !== 'all' && m.status !== statusFilter) return false
    if (severityFilter !== 'all' && m.severity !== severityFilter) return false
    return true
  })

  return (
    <div className="space-y-6">
      {selectedFinding && <RemediationModal finding={selectedFinding} onClose={() => setSelectedFinding(null)} />}

      {/* Posture score + findings */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
        {/* Score */}
        <div className="bg-falcon-surface border border-falcon-border rounded-xl p-5 flex items-center gap-5">
          <div className="relative w-20 h-20 shrink-0">
            <svg viewBox="0 0 80 80" className="w-full h-full -rotate-90">
              <circle cx="40" cy="40" r="34" fill="none" stroke="#1e2d42" strokeWidth="8" />
              {measured && (
                <circle cx="40" cy="40" r="34" fill="none"
                  stroke={posture.posture_score >= 80 ? '#22c55e' : posture.posture_score >= 60 ? '#f59e0b' : '#e8002d'}
                  strokeWidth="8"
                  strokeDasharray={`${(posture.posture_score / 100) * 213.6} 213.6`}
                  strokeLinecap="round" />
              )}
            </svg>
            <div className="absolute inset-0 flex items-center justify-center">
              <span className={`text-xl font-bold ${g.cls}`}>{measured ? posture.posture_score : '—'}</span>
            </div>
          </div>
          <div>
            <p className="text-falcon-muted text-xs mb-1">ポスチャースコア</p>
            <p className={`text-3xl font-bold ${g.cls}`}>{g.label}</p>
            <p className="text-falcon-muted text-xs mt-1">
              {measured ? `${totalFindings} 件の検出` : 'CSPM スキャン未実施'}
            </p>
          </div>
        </div>

        {/* Findings breakdown */}
        <div className="bg-falcon-surface border border-falcon-border rounded-xl p-5">
          <p className="text-falcon-muted text-xs font-medium mb-3">検出件数</p>
          <div className="grid grid-cols-2 gap-2">
            {[
              { label: '重大', count: posture.findings.critical, cls: 'text-red-400', bg: 'bg-red-500/10' },
              { label: '高', count: posture.findings.high, cls: 'text-orange-400', bg: 'bg-orange-500/10' },
              { label: '中', count: posture.findings.medium, cls: 'text-yellow-400', bg: 'bg-yellow-500/10' },
              { label: '低', count: posture.findings.low, cls: 'text-blue-400', bg: 'bg-blue-500/10' },
            ].map(f => (
              <div key={f.label} className={`${f.bg} rounded-lg p-2 text-center`}>
                <p className={`text-xl font-bold ${f.cls}`}>{f.count}</p>
                <p className="text-falcon-muted text-[10px]">{f.label}</p>
              </div>
            ))}
          </div>
        </div>

        {/* Compliance */}
        <div className="bg-falcon-surface border border-falcon-border rounded-xl p-5">
          <p className="text-falcon-muted text-xs font-medium mb-3">コンプライアンス</p>
          <div className="space-y-2.5">
            {[
              { label: 'CIS Benchmark', pct: posture.compliance.cis },
              { label: 'SOC 2', pct: posture.compliance.soc2 },
              { label: 'ISO 27001', pct: posture.compliance.iso27001 },
            ].map(c => (
              <div key={c.label}>
                <div className="flex items-center justify-between mb-1">
                  <span className="text-xs text-falcon-muted">{c.label}</span>
                  <span className={`text-xs font-bold ${!measured ? 'text-falcon-muted' : c.pct >= 80 ? 'text-green-400' : c.pct >= 70 ? 'text-yellow-400' : 'text-orange-400'}`}>
                    {measured ? `${c.pct}%` : '未計測'}
                  </span>
                </div>
                <div className="h-1.5 bg-falcon-border rounded-full overflow-hidden">
                  {measured && (
                    <div className={`h-full rounded-full ${c.pct >= 80 ? 'bg-green-500' : c.pct >= 70 ? 'bg-yellow-500' : 'bg-orange-500'}`}
                      style={{ width: `${c.pct}%` }} />
                  )}
                </div>
              </div>
            ))}
          </div>
        </div>
      </div>

      {/* Misconfigurations table */}
      <div className="bg-falcon-surface border border-falcon-border rounded-xl overflow-hidden">
        <div className="px-5 py-4 border-b border-falcon-border flex items-center gap-3 flex-wrap">
          <h3 className="text-white font-semibold text-sm flex-1">設定ミス一覧</h3>
          <select value={severityFilter} onChange={e => setSeverityFilter(e.target.value as Severity | 'all')}
            className="bg-[#070d19] border border-falcon-border rounded-lg px-3 py-1.5 text-xs text-white focus:outline-hidden focus:border-falcon-red/60">
            <option value="all">全深刻度</option>
            <option value="critical">重大</option>
            <option value="high">高</option>
            <option value="medium">中</option>
            <option value="low">低</option>
          </select>
          <select value={statusFilter} onChange={e => setStatusFilter(e.target.value as FindingStatus | 'all')}
            className="bg-[#070d19] border border-falcon-border rounded-lg px-3 py-1.5 text-xs text-white focus:outline-hidden focus:border-falcon-red/60">
            <option value="all">全ステータス</option>
            <option value="open">オープン</option>
            <option value="suppressed">抑制済み</option>
            <option value="fixed">修正済み</option>
          </select>
        </div>
        <div className="overflow-x-auto">
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b border-falcon-border bg-[#070d19]/50">
                {['リソースタイプ', 'リソースID', '検出内容', '深刻度', 'リージョン', 'ステータス', ''].map(h => (
                  <th key={h} className="text-left py-3 px-4 text-falcon-muted text-xs font-medium">{h}</th>
                ))}
              </tr>
            </thead>
            <tbody>
              {filtered.map(m => (
                <tr key={m.id} className={`border-b border-falcon-border/50 hover:bg-falcon-border/20 transition-colors ${m.status === 'suppressed' ? 'opacity-60' : ''}`}>
                  <td className="py-3 px-4 text-xs text-falcon-muted">{m.resource_type}</td>
                  <td className="py-3 px-4 font-mono text-xs text-white max-w-[160px]">
                    <span className="truncate block">{m.resource_id}</span>
                  </td>
                  <td className="py-3 px-4 text-xs text-falcon-muted max-w-[220px]">
                    <span className="truncate block">{m.finding}</span>
                  </td>
                  <td className="py-3 px-4"><SeverityBadge severity={m.severity} /></td>
                  <td className="py-3 px-4 text-xs text-falcon-muted whitespace-nowrap">{m.region}</td>
                  <td className="py-3 px-4"><StatusBadge status={m.status} /></td>
                  <td className="py-3 px-4">
                    <button onClick={() => setSelectedFinding(m)}
                      className="flex items-center gap-1 px-2 py-1 text-xs bg-falcon-border hover:bg-[#2a3f5f] text-falcon-text rounded-sm transition-colors border border-[#2a3f5f]">
                      <ChevronRight className="w-3 h-3" />修復
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>

      {/* Top risky resources */}
      <div className="bg-falcon-surface border border-falcon-border rounded-xl p-5">
        <h3 className="text-white font-semibold text-sm mb-4 flex items-center gap-2">
          <AlertTriangle className="w-4 h-4 text-orange-400" />
          リスク上位リソース (Top 5)
        </h3>
        <div className="space-y-2">
          {posture.top_risky_resources.map((r, i) => (
            <div key={r.resource_id} className="flex items-center gap-3 p-3 bg-[#070d19] rounded-lg border border-falcon-border">
              <span className="text-falcon-subtle text-xs w-4">{i + 1}</span>
              <div className="flex-1 min-w-0">
                <p className="font-mono text-xs text-white truncate">{r.resource_id}</p>
                <p className="text-falcon-muted text-[10px]">{r.resource_type} — {r.region}</p>
              </div>
              <div className="flex items-center gap-2">
                <SeverityBadge severity={r.highest_severity} />
                <span className="text-xs text-falcon-muted">{r.finding_count}件</span>
              </div>
            </div>
          ))}
        </div>
      </div>
    </div>
  )
}

// ── Cross-provider Summary ────────────────────────────────────────────────────

function CrossProviderSummaryPanel({ summary, postureMap }: { summary: CrossProviderSummary; postureMap: Record<Provider, CloudPosture> }) {
  const maxTrend = Math.max(...summary.compliance_trend)
  const minTrend = Math.min(...summary.compliance_trend)

  return (
    <div className="space-y-6">
      {/* Total resources */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
        <div className="bg-falcon-surface border border-falcon-border rounded-xl p-5 md:col-span-1">
          <p className="text-falcon-muted text-xs mb-1">総監視リソース数</p>
          <p className="text-3xl font-bold text-white">{(summary.total_resources ?? 0).toLocaleString()}</p>
          <div className="flex items-center gap-3 mt-3 text-xs text-falcon-muted">
            <span>AWS: {(postureMap.aws?.resources_monitored ?? 0).toLocaleString()}</span>
            <span>Azure: {(postureMap.azure?.resources_monitored ?? 0).toLocaleString()}</span>
            <span>GCP: {(postureMap.gcp?.resources_monitored ?? 0).toLocaleString()}</span>
          </div>
        </div>

        <div className="bg-falcon-surface border border-falcon-border rounded-xl p-5 md:col-span-2">
          <p className="text-falcon-muted text-xs font-medium mb-3">コンプライアンストレンド (過去30日)</p>
          <div className="flex items-end gap-0.5 h-16">
            {summary.compliance_trend.map((v, i) => (
              <div key={i} className="flex-1 relative" style={{ height: '64px' }}>
                <div
                  className="absolute bottom-0 w-full bg-blue-500/50 border-t border-blue-400 rounded-t-sm"
                  style={{ height: `${((v - minTrend) / (maxTrend - minTrend + 1)) * 100}%`, minHeight: '4px' }}
                />
              </div>
            ))}
          </div>
          <div className="flex items-center justify-between mt-1 text-xs text-falcon-subtle">
            <span>30日前 {minTrend}%</span>
            <span>本日 {summary.compliance_trend[summary.compliance_trend.length - 1]}%</span>
          </div>
        </div>
      </div>

      {/* Common misconfigs */}
      <div className="bg-falcon-surface border border-falcon-border rounded-xl overflow-hidden">
        <div className="px-5 py-4 border-b border-falcon-border">
          <h3 className="text-white font-semibold text-sm">最も多い設定ミスタイプ (全プロバイダー横断)</h3>
        </div>
        <div className="overflow-x-auto">
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b border-falcon-border bg-[#070d19]/50">
                {['設定ミスタイプ', '件数', '対象プロバイダー', '分布'].map(h => (
                  <th key={h} className="text-left py-3 px-4 text-falcon-muted text-xs font-medium">{h}</th>
                ))}
              </tr>
            </thead>
            <tbody>
              {summary.common_misconfigs.map(m => {
                const maxCount = Math.max(...summary.common_misconfigs.map(x => x.count))
                return (
                  <tr key={m.type} className="border-b border-falcon-border/50 hover:bg-falcon-border/20 transition-colors">
                    <td className="py-3 px-4 text-white text-xs font-medium">{m.type}</td>
                    <td className="py-3 px-4 text-orange-400 font-bold text-sm">{m.count}</td>
                    <td className="py-3 px-4">
                      <div className="flex gap-1">
                        {m.providers.map(p => (
                          <span key={p} className={`px-1.5 py-0.5 rounded text-[9px] font-bold ${
                            p === 'aws' ? 'bg-orange-500/20 text-orange-400' :
                            p === 'azure' ? 'bg-blue-500/20 text-blue-400' :
                            'bg-red-500/20 text-red-400'
                          }`}>
                            {p.toUpperCase()}
                          </span>
                        ))}
                      </div>
                    </td>
                    <td className="py-3 px-4">
                      <div className="h-1.5 w-28 bg-falcon-border rounded-full overflow-hidden">
                        <div className="h-full bg-orange-500 rounded-full" style={{ width: `${(m.count / maxCount) * 100}%` }} />
                      </div>
                    </td>
                  </tr>
                )
              })}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  )
}

// ── Page ──────────────────────────────────────────────────────────────────────

export default function CloudSecurityPage() {
  const [activeProvider, setActiveProvider] = useState<Provider>('aws')
  const [scanning, setScanning] = useState(false)
  const [scanResult, setScanResult] = useState<{ ok: boolean; message: string } | null>(null)

  const { data: awsData } = useQuery<CloudPosture | null>({
    queryKey: ['cloud-posture-aws'],
    queryFn: async () => {
      try { return await apiFetch<CloudPosture>('/api/v1/cloud/posture?provider=aws') }
      catch { return null }
    },
    staleTime: 120_000,
  })

  const { data: azureData } = useQuery<CloudPosture | null>({
    queryKey: ['cloud-posture-azure'],
    queryFn: async () => {
      try { return await apiFetch<CloudPosture>('/api/v1/cloud/posture?provider=azure') }
      catch { return null }
    },
    staleTime: 120_000,
  })

  const { data: gcpData } = useQuery<CloudPosture | null>({
    queryKey: ['cloud-posture-gcp'],
    queryFn: async () => {
      try { return await apiFetch<CloudPosture>('/api/v1/cloud/posture?provider=gcp') }
      catch { return null }
    },
    staleTime: 120_000,
  })

  const postureMap: Record<Provider, CloudPosture> = {
    aws: { ...EMPTY_POSTURE, provider: 'aws', ...(awsData ?? {}) },
    azure: { ...EMPTY_POSTURE, provider: 'azure', ...(azureData ?? {}) },
    gcp: { ...EMPTY_POSTURE, provider: 'gcp', ...(gcpData ?? {}) },
  }

  const activePosture = postureMap[activeProvider]

  // 進捗バーは出さない。以前はここで Math.random() の値を 100% まで進め、
  // 最後に「スキャン完了 — 全プロバイダーのポスチャーを更新しました」と
  // 緑で表示していたが、サーバは何もスキャンしていなかった。
  // 実施していない監査を実施したと報告しないよう、結果をそのまま出す。
  const handleScan = async () => {
    setScanning(true)
    setScanResult(null)
    try {
      await apiFetch('/api/v1/cloud/scan', { method: 'POST' })
      setScanResult({ ok: true, message: 'スキャンを開始しました' })
    } catch (e) {
      setScanResult({ ok: false, message: e instanceof Error ? e.message : 'スキャンを開始できませんでした' })
    } finally {
      setScanning(false)
    }
  }

  const providers: { key: Provider; label: string; color: string }[] = [
    { key: 'aws', label: 'AWS', color: 'text-orange-400' },
    { key: 'azure', label: 'Azure', color: 'text-blue-400' },
    { key: 'gcp', label: 'GCP', color: 'text-red-400' },
  ]

  return (
    <div className="min-h-screen bg-[#070d19] p-6 space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between flex-wrap gap-3">
        <div>
          <h1 className="text-2xl font-bold text-white flex items-center gap-3">
            <Shield className="w-6 h-6 text-falcon-red" />
            クラウドセキュリティ態勢 (CSPM)
          </h1>
          <p className="text-falcon-muted text-sm mt-1">
            AWS / Azure / GCP の設定ミス・コンプライアンス監視
            <span className="ml-3 text-falcon-subtle text-xs">最終スキャン: {fmtTs(activePosture.last_scanned)}</span>
          </p>
        </div>
        <button onClick={handleScan} disabled={scanning}
          className="flex items-center gap-2 px-4 py-2 bg-falcon-red hover:bg-[#c0001f] disabled:opacity-60 text-white rounded-lg text-sm font-medium transition-colors">
          {scanning ? <Loader2 className="w-4 h-4 animate-spin" /> : <RefreshCw className="w-4 h-4" />}
          スキャン実行
        </button>
      </div>

      {/* スキャン結果。成功も失敗もサーバの返答をそのまま伝える。 */}
      {scanResult && (
        <div className={`flex items-start gap-2 px-4 py-2.5 rounded-lg text-sm border ${
          scanResult.ok
            ? 'bg-green-500/15 border-green-500/30 text-green-400'
            : 'bg-amber-500/15 border-amber-500/30 text-amber-300'
        }`}>
          {scanResult.ok
            ? <CheckCircle className="w-4 h-4 shrink-0 mt-0.5" />
            : <AlertTriangle className="w-4 h-4 shrink-0 mt-0.5" />}
          <span>{scanResult.message}</span>
        </div>
      )}

      {/* Provider selector */}
      <div className="flex gap-2">
        {providers.map(p => (
          <button key={p.key} onClick={() => setActiveProvider(p.key)}
            className={`px-5 py-2.5 rounded-lg text-sm font-semibold border transition-colors ${
              activeProvider === p.key
                ? 'border-falcon-red bg-falcon-red/10 text-white'
                : 'border-falcon-border bg-falcon-surface text-falcon-muted hover:text-white hover:border-falcon-muted/40'
            }`}>
            <span className={activeProvider === p.key ? 'text-white' : p.color}>{p.label}</span>
            <span className={`ml-2 text-xs ${activeProvider === p.key ? 'text-falcon-muted' : 'text-falcon-subtle'}`}>
              {postureMap[p.key].data_available ? `${postureMap[p.key].posture_score}点` : '未計測'}
            </span>
          </button>
        ))}
      </div>

      {/* Provider panel */}
      <ProviderPanel posture={activePosture} />

      {/* Divider */}
      <div className="border-t border-falcon-border pt-6">
        <div className="flex items-center gap-2 mb-4">
          <Cloud className="w-5 h-5 text-falcon-muted" />
          <h2 className="text-white font-semibold">クロスプロバイダーサマリー</h2>
        </div>
        <CrossProviderSummaryPanel summary={EMPTY_CROSS_SUMMARY} postureMap={postureMap} />
      </div>
    </div>
  )
}

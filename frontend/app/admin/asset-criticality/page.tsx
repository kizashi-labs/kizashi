'use client'

import { useState } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { apiFetch, apiFetchList } from '@/lib/api'
import {
  Gauge, X, ChevronDown, ChevronRight,
  Monitor, Server, Laptop, AlertTriangle, Shield,
  CheckCircle, SlidersHorizontal, Info, Calculator, RotateCcw,
} from 'lucide-react'

import { PageDataUnavailable } from '@/components/PageDataUnavailable'
import { PageSaveFailed } from '@/components/PageSaveFailed'

// ─── Types ────────────────────────────────────────────────────────────────────

type OS = 'Windows Server' | 'Windows 10' | 'Windows 11' | 'macOS' | 'Ubuntu' | 'CentOS'
type Tier = 'critical' | 'high' | 'medium' | 'low'

interface ScoreFactor {
  name: string
  impact: number
  description: string
}

interface AssetCriticality {
  id: string
  hostname: string
  os: OS
  criticality_score: number
  tier: Tier
  factors: ScoreFactor[]
  manual_override: boolean
  manual_score?: number
  manual_reason?: string
  last_calculated: string
  is_online: boolean
}

// ─── Helpers ──────────────────────────────────────────────────────────────────

// 区切りはサーバの `scoreTier`（server/internal/api/handlers/
// asset_criticality_handler.go）と同じにしてあります。ここだけ 80/60 に
// なっていたので、**上書きダイアログの予告と、保存後に一覧が出す段が
// 食い違っていました**（82点は「Critical」と予告して「High」で並ぶ）。
const getTier = (score: number): Tier => {
  if (score >= 85) return 'critical'
  if (score >= 65) return 'high'
  if (score >= 40) return 'medium'
  return 'low'
}

const tierConfig = {
  critical: { label: 'Critical', cls: 'bg-red-900/40 text-red-300 border-red-700/50', scoreColor: 'text-red-400', barColor: 'bg-red-500' },
  high:     { label: 'High',     cls: 'bg-orange-900/40 text-orange-300 border-orange-700/50', scoreColor: 'text-orange-400', barColor: 'bg-orange-500' },
  medium:   { label: 'Medium',   cls: 'bg-yellow-900/40 text-yellow-300 border-yellow-700/50', scoreColor: 'text-yellow-400', barColor: 'bg-yellow-500' },
  low:      { label: 'Low',      cls: 'bg-green-900/40 text-green-300 border-green-700/50', scoreColor: 'text-green-400', barColor: 'bg-green-500' },
}

const osIcon = (os: OS) => {
  if (os.includes('Server') || os.includes('Ubuntu') || os.includes('CentOS')) return Server
  if (os.includes('macOS')) return Laptop
  return Monitor
}

const fmtDate = (iso: string) =>
  new Date(iso).toLocaleString('ja-JP', { month: '2-digit', day: '2-digit', hour: '2-digit', minute: '2-digit' })

// ─── Override Modal ───────────────────────────────────────────────────────────

function OverrideModal({
  asset,
  onClose,
  onSave,
}: {
  asset: AssetCriticality
  onClose: () => void
  onSave: (score: number, reason: string) => void
}) {
  const [score, setScore] = useState(asset.manual_override ? (asset.manual_score ?? asset.criticality_score) : asset.criticality_score)
  const [reason, setReason] = useState(asset.manual_reason ?? '')
  const tier = getTier(score)
  const tc = tierConfig[tier]

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 backdrop-blur-sm">
      <div className="bg-[#0d1220] border border-[#1e2d42] rounded-xl w-[480px] shadow-2xl">
        <div className="flex items-center justify-between px-6 py-4 border-b border-[#1e2d42]">
          <div>
            <h3 className="text-white font-semibold">スコア手動設定</h3>
            <p className="text-xs text-[#7d92b0] mt-0.5">{asset.hostname}</p>
          </div>
          <button onClick={onClose} className="text-[#7d92b0] hover:text-white transition-colors">
            <X className="w-5 h-5" />
          </button>
        </div>

        <div className="px-6 py-5 space-y-5">
          {/* Score slider */}
          <div>
            <div className="flex items-center justify-between mb-2">
              <label className="text-xs text-[#7d92b0]">重要度スコア (0-100)</label>
              <div className="flex items-center gap-2">
                <span className={`text-2xl font-bold ${tc.scoreColor}`}>{score}</span>
                <span className={`text-xs px-2 py-0.5 rounded-sm border ${tc.cls}`}>{tc.label}</span>
              </div>
            </div>
            <input
              type="range" min={0} max={100}
              value={score}
              onChange={e => setScore(Number(e.target.value))}
              className="w-full accent-[#e8002d]"
            />
            {/* Score bar preview */}
            <div className="mt-2 h-2 bg-[#070d19] rounded-full overflow-hidden border border-[#1e2d42]">
              <div
                className={`h-full rounded-full transition-all duration-300 ${tc.barColor}`}
                style={{ width: `${score}%` }}
              />
            </div>
          </div>

          {/* Reason */}
          <div>
            <label className="block text-xs text-[#7d92b0] mb-1.5">設定理由</label>
            <textarea
              className="w-full bg-[#070d19] border border-[#1e2d42] rounded-lg px-3 py-2 text-sm text-white focus:outline-hidden focus:border-[#1a6bff]/60 resize-none"
              rows={3}
              value={reason}
              onChange={e => setReason(e.target.value)}
              placeholder="手動設定の理由を記載してください..."
            />
          </div>

          {/* Tier thresholds reference */}
          <div className="bg-[#070d19] rounded-lg p-3 border border-[#1e2d42]">
            <p className="text-xs text-[#7d92b0] mb-2 font-medium">スコア閾値</p>
            <div className="grid grid-cols-4 gap-2 text-xs">
              {(['critical', 'high', 'medium', 'low'] as Tier[]).map(t => (
                <div key={t} className={`rounded-sm px-2 py-1 border text-center ${tierConfig[t].cls} ${getTier(score) === t ? 'ring-1 ring-white/20' : ''}`}>
                  <p className="font-medium">{tierConfig[t].label}</p>
                  <p className="text-[10px] opacity-70">
                    {t === 'critical' ? '80-100' : t === 'high' ? '60-79' : t === 'medium' ? '40-59' : '0-39'}
                  </p>
                </div>
              ))}
            </div>
          </div>
        </div>

        <div className="flex justify-end gap-3 px-6 py-4 border-t border-[#1e2d42]">
          <button
            onClick={onClose}
            className="px-4 py-2 text-sm text-[#7d92b0] hover:text-white border border-[#1e2d42] rounded-lg transition-colors"
          >
            キャンセル
          </button>
          <button
            onClick={() => onSave(score, reason)}
            className="px-4 py-2 text-sm bg-[#e8002d] hover:bg-[#c0001f] text-white rounded-lg transition-colors"
          >
            設定を保存
          </button>
        </div>
      </div>
    </div>
  )
}

// ─── Asset Row ────────────────────────────────────────────────────────────────

function AssetRow({
  asset,
  onOverride,
  onClearOverride,
  clearing,
}: {
  asset: AssetCriticality
  onOverride: (asset: AssetCriticality) => void
  onClearOverride: (asset: AssetCriticality) => void
  clearing: boolean
}) {
  const [expanded, setExpanded] = useState(false)
  const tc = tierConfig[asset.tier]
  const OsIcon = osIcon(asset.os)

  return (
    <>
      <tr className="border-b border-[#1e2d42]/50 hover:bg-[#131d31]/50 transition-colors">
        {/* Hostname */}
        <td className="px-4 py-3">
          <div className="flex items-center gap-2">
            <OsIcon className="w-4 h-4 text-[#3d5068] shrink-0" />
            <div>
              <div className="flex items-center gap-2">
                <span className="text-white font-medium text-sm">{asset.hostname}</span>
                {!asset.is_online && (
                  <span className="text-[10px] text-[#3d5068] border border-[#1e2d42] px-1.5 py-0.5 rounded-sm">OFFLINE</span>
                )}
                {asset.is_online && (
                  <span className="w-1.5 h-1.5 rounded-full bg-green-400 inline-block" />
                )}
              </div>
            </div>
          </div>
        </td>

        {/* OS */}
        <td className="px-4 py-3">
          <span className="text-xs text-[#7d92b0] bg-[#070d19] border border-[#1e2d42] px-2 py-0.5 rounded-sm">
            {asset.os}
          </span>
        </td>

        {/* Score */}
        <td className="px-4 py-3">
          <div className="flex items-center gap-3">
            <span className={`text-2xl font-bold ${tc.scoreColor}`}>{asset.criticality_score}</span>
            <div className="flex-1 min-w-[80px]">
              <div className="h-1.5 bg-[#070d19] rounded-full overflow-hidden border border-[#1e2d42]">
                <div
                  className={`h-full rounded-full ${tc.barColor} transition-all duration-500`}
                  style={{ width: `${asset.criticality_score}%` }}
                />
              </div>
            </div>
          </div>
        </td>

        {/* Tier */}
        <td className="px-4 py-3">
          <span className={`text-xs px-2 py-0.5 rounded-sm border ${tc.cls}`}>
            {tc.label}
          </span>
        </td>

        {/* Factors collapsible */}
        <td className="px-4 py-3">
          <button
            onClick={() => setExpanded(e => !e)}
            className="flex items-center gap-1 text-xs text-[#7d92b0] hover:text-white transition-colors"
          >
            {expanded ? <ChevronDown className="w-3.5 h-3.5" /> : <ChevronRight className="w-3.5 h-3.5" />}
            {asset.factors.length} 要因
          </button>
        </td>

        {/* Manual Override */}
        <td className="px-4 py-3">
          {asset.manual_override ? (
            <span className="inline-flex items-center gap-1 text-xs text-orange-300 bg-orange-900/20 border border-orange-700/30 px-2 py-0.5 rounded-sm">
              <SlidersHorizontal className="w-3 h-3" />
              手動設定
            </span>
          ) : (
            <span className="text-xs text-[#3d5068]">自動</span>
          )}
        </td>

        {/* Last Calculated */}
        <td className="px-4 py-3 text-xs text-[#7d92b0] whitespace-nowrap">
          {fmtDate(asset.last_calculated)}
        </td>

        {/* Actions */}
        <td className="px-4 py-3">
          <div className="flex items-center gap-2">
            <button
              onClick={() => onOverride(asset)}
              className="flex items-center gap-1.5 text-xs px-3 py-1.5 bg-[#131d31] border border-[#1e2d42] hover:border-[#7d92b0]/40 text-[#7d92b0] hover:text-white rounded-lg transition-colors"
            >
              <SlidersHorizontal className="w-3 h-3" />
              スコア設定
            </button>
            {/* **手動にしたあと、自動計算に戻す方法がありませんでした。**
                手動が効くようになるまでは「次の表示で勝手に戻る」形でしたが、
                それは解除ではなく機能していなかっただけです。 */}
            {asset.manual_override && (
              <button
                onClick={() => onClearOverride(asset)}
                disabled={clearing}
                title="手動設定を外して、自動計算のスコアに戻します"
                className="flex items-center gap-1.5 text-xs px-3 py-1.5 bg-[#131d31] border border-[#1e2d42] hover:border-[#7d92b0]/40 text-[#7d92b0] hover:text-white rounded-lg transition-colors disabled:opacity-50 disabled:cursor-not-allowed"
              >
                <RotateCcw className={`w-3 h-3 ${clearing ? 'animate-spin' : ''}`} />
                自動に戻す
              </button>
            )}
          </div>
        </td>
      </tr>

      {/* Expanded factors */}
      {expanded && (
        <tr className="bg-[#070d19]/50">
          <td colSpan={8} className="px-8 py-3">
            <div className="grid grid-cols-2 lg:grid-cols-4 gap-3">
              {asset.factors.map((f, i) => (
                <div key={i} className="bg-[#0d1220] rounded-lg px-3 py-2 border border-[#1e2d42]">
                  <div className="flex items-center justify-between mb-1">
                    <span className="text-xs text-[#7d92b0] font-medium">{f.name}</span>
                    <span className={`text-sm font-bold ${f.impact > 0 ? 'text-green-400' : f.impact < 0 ? 'text-red-400' : 'text-[#3d5068]'}`}>
                      {f.impact > 0 ? `+${f.impact}` : f.impact}
                    </span>
                  </div>
                  <p className="text-[10px] text-[#3d5068]">{f.description}</p>
                </div>
              ))}
            </div>
            {asset.manual_override && asset.manual_reason && (
              <div className="mt-2 flex items-start gap-2 text-xs text-orange-300">
                <Info className="w-3.5 h-3.5 shrink-0 mt-0.5" />
                <span>手動設定理由: {asset.manual_reason}</span>
              </div>
            )}
          </td>
        </tr>
      )}
    </>
  )
}

// ─── Main Page ────────────────────────────────────────────────────────────────

export default function AssetCriticalityPage() {
  const qc = useQueryClient()
  const [activeTab, setActiveTab] = useState<'list' | 'config'>('list')
  const [filterTier, setFilterTier] = useState<Tier | ''>('')
  const [searchHost, setSearchHost] = useState('')
  const [overrideAsset, setOverrideAsset] = useState<AssetCriticality | undefined>()

  // ── Queries ──────────────────────────────────────────────────

  // apiFetchList を使うのは、サーバが `{data, total}` で返すからです
  // （この配置の他の一覧と同じ形）。**上限に当たったかどうかを応答に
  // 載せるには、裸の配列では足りません。**
  const { data: assets = [], isLoading } = useQuery<AssetCriticality[]>({
    queryKey: ['asset-criticality'],
    queryFn: () => apiFetchList<AssetCriticality>('/api/v1/endpoints/criticality'),
    staleTime: 30_000,
    retry: false,
  })

  // ── Mutations ────────────────────────────────────────────────

  // **「一括計算」ボタンは外しました。**
  //
  // 計算値を保存しなくなったので、`POST /endpoints/criticality/bulk` は
  // `GET /endpoints/criticality` と同じものを返します —— 一覧を開くたびに
  // 計算しているので、押しても変わるものがありません。**何も変わらない
  // ボタンは、押した人に「更新された」と思わせます。**

  const setManualScore = useMutation({
    mutationFn: ({ id, score, reason }: { id: string; score: number; reason: string }) =>
      apiFetch(`/api/v1/endpoints/${id}/criticality`, {
        method: 'PUT',
        body: JSON.stringify({ manual_score: score, reason }),
      }),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['asset-criticality'] })
      setOverrideAsset(undefined)
    },
    onError: () => setOverrideAsset(undefined),
  })

  // **手動設定を外して、自動計算に戻します。**
  //
  // 行を消すだけです（`DELETE /endpoints/:id/criticality`）。応答には
  // 戻った先の点数が入っていますが、一覧はどのみち取り直すので、
  // ここでは無効化だけします。
  const clearManualScore = useMutation({
    mutationFn: (id: string) =>
      apiFetch(`/api/v1/endpoints/${id}/criticality`, { method: 'DELETE' }),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['asset-criticality'] }),
  })

  // ── Derived ──────────────────────────────────────────────────

  const displayAssets = assets

  const stats = {
    critical: displayAssets.filter(a => a.tier === 'critical').length,
    high:     displayAssets.filter(a => a.tier === 'high').length,
    medium:   displayAssets.filter(a => a.tier === 'medium').length,
    low:      displayAssets.filter(a => a.tier === 'low').length,
  }

  const filteredAssets = displayAssets
    .filter(a => {
      if (filterTier && a.tier !== filterTier) return false
      if (searchHost && !a.hostname.toLowerCase().includes(searchHost.toLowerCase())) return false
      return true
    })
    .sort((a, b) => b.criticality_score - a.criticality_score)

  // ────────────────────────────────────────────────────────────

  return (
    <div className="min-h-screen bg-[#070d19] text-white">
      <PageDataUnavailable />
      <PageSaveFailed className="mb-4" />
      <div className="max-w-[1400px] mx-auto px-6 py-6">

        {/* ── Header ── */}
        <div className="mb-6">
          <div className="flex items-center gap-3 mb-1">
            <div className="w-8 h-8 rounded-lg bg-linear-to-br from-[#1a6bff] to-[#0044cc] flex items-center justify-center shadow-lg">
              <Gauge className="w-4 h-4 text-white" />
            </div>
            <h1 className="text-2xl font-bold text-white">アセット重要度スコアリング</h1>
          </div>
          <p className="text-[#7d92b0] text-sm ml-11">
            エンドポイントのビジネス重要度を自動算出・管理します
          </p>
        </div>

        {/* ── Stats Row ── */}
        <div className="grid grid-cols-4 gap-4 mb-6">
          {([
            { key: 'critical' as Tier, label: 'Critical (≥80)', icon: AlertTriangle },
            { key: 'high'     as Tier, label: 'High (60-79)',    icon: Shield },
            { key: 'medium'   as Tier, label: 'Medium (40-59)',  icon: Monitor },
            { key: 'low'      as Tier, label: 'Low (<40)',       icon: CheckCircle },
          ] as const).map(s => {
            const tc = tierConfig[s.key]
            return (
              <button
                key={s.key}
                onClick={() => setFilterTier(filterTier === s.key ? '' : s.key)}
                className={`rounded-xl p-4 border bg-[#0d1220] text-left transition-all
                  ${filterTier === s.key ? `border-[${s.key === 'critical' ? '#e8002d' : '#1a6bff'}]/50 ring-1 ring-[#1a6bff]/30` : 'border-[#1e2d42] hover:border-[#2a3f5a]'}`}
              >
                <div className="flex items-center justify-between mb-2">
                  <span className="text-xs text-[#7d92b0]">{s.label}</span>
                  <s.icon className={`w-4 h-4 ${tc.scoreColor}`} />
                </div>
                <p className={`text-3xl font-bold ${tc.scoreColor}`}>{stats[s.key]}</p>
                <p className="text-xs text-[#3d5068] mt-1">エンドポイント</p>
              </button>
            )
          })}
        </div>

        {/* ── Tabs ── */}
        <div className="flex gap-1 mb-5 border-b border-[#1e2d42]">
          {([['list', '重要度一覧'], ['config', 'スコア設定']] as const).map(([k, label]) => (
            <button
              key={k}
              onClick={() => setActiveTab(k)}
              className={`px-5 py-2.5 text-sm font-medium transition-colors border-b-2 -mb-px
                ${activeTab === k
                  ? 'border-[#e8002d] text-white'
                  : 'border-transparent text-[#7d92b0] hover:text-white'
                }`}
            >
              {label}
            </button>
          ))}
        </div>

        {/* ══════════════════════ List Tab ═════════════════════════ */}
        {activeTab === 'list' && (
          <div>
            {/* Toolbar */}
            <div className="flex items-center justify-between mb-4 gap-4">
              <div className="flex items-center gap-3 flex-1">
                {/* Search */}
                <div className="relative max-w-[280px]">
                  <Monitor className="absolute left-3 top-1/2 -translate-y-1/2 w-3.5 h-3.5 text-[#3d5068]" />
                  <input
                    className="w-full bg-[#0d1220] border border-[#1e2d42] rounded-lg pl-8 pr-3 py-2 text-sm text-white placeholder-[#3d5068] focus:outline-hidden focus:border-[#1a6bff]/60"
                    placeholder="ホスト名で検索..."
                    value={searchHost}
                    onChange={e => setSearchHost(e.target.value)}
                  />
                </div>

                {/* Tier filter */}
                <select
                  className="bg-[#0d1220] border border-[#1e2d42] rounded-lg px-3 py-2 text-sm text-white focus:outline-hidden focus:border-[#1a6bff]/60"
                  value={filterTier}
                  onChange={e => setFilterTier(e.target.value as Tier | '')}
                >
                  <option value="">全ティア</option>
                  <option value="critical">Critical</option>
                  <option value="high">High</option>
                  <option value="medium">Medium</option>
                  <option value="low">Low</option>
                </select>

                <span className="text-xs text-[#3d5068]">{filteredAssets.length} / {displayAssets.length} 件</span>
              </div>
            </div>

            <div className="bg-[#0d1220] rounded-xl border border-[#1e2d42] overflow-hidden">
              <table className="w-full text-sm">
                <thead>
                  <tr className="border-b border-[#1e2d42]">
                    {['ホスト名', 'OS', 'スコア', 'ティア', 'スコア要因', '設定方法', '最終計算', '操作'].map(h => (
                      <th key={h} className="text-left px-4 py-3 text-xs text-[#7d92b0] font-medium">{h}</th>
                    ))}
                  </tr>
                </thead>
                <tbody>
                  {filteredAssets.map(asset => (
                    <AssetRow
                      key={asset.id}
                      asset={asset}
                      onOverride={setOverrideAsset}
                      onClearOverride={a => clearManualScore.mutate(a.id)}
                      clearing={clearManualScore.isPending && clearManualScore.variables === asset.id}
                    />
                  ))}
                  {filteredAssets.length === 0 && (
                    <tr>
                      <td colSpan={8} className="px-4 py-10 text-center text-[#3d5068]">
                        <Monitor className="w-8 h-8 mx-auto mb-2 text-[#1e2d42]" />
                        <p>条件に一致するアセットはありません</p>
                      </td>
                    </tr>
                  )}
                </tbody>
              </table>
            </div>
          </div>
        )}

        {/* ══════════════════════ Config Tab ═══════════════════════ */}
        {activeTab === 'config' && (
          <div className="max-w-3xl space-y-6">
            {/* Algorithm explanation */}
            <div className="bg-[#0d1220] rounded-xl border border-[#1e2d42] p-6">
              <div className="flex items-center gap-2 mb-4">
                <Calculator className="w-5 h-5 text-[#1a6bff]" />
                <h2 className="text-white font-semibold">スコアリングアルゴリズム</h2>
              </div>
              <p className="text-sm text-[#7d92b0] leading-relaxed mb-4">
                アセット重要度スコアは、複数の要因を組み合わせて 0〜100 点で算出します。
                各エンドポイントはベーススコアからスタートし、環境・状態に応じた加算・減算が適用されます。
                スコアは定期的に自動再計算されますが、管理者が手動でオーバーライドすることも可能です。
              </p>
              <div className="bg-[#070d19] rounded-lg p-4 border border-[#1e2d42] font-mono text-sm">
                <p className="text-[#7d92b0]">スコア計算式:</p>
                <p className="text-white mt-1">
                  Score = ベーススコア + Σ(適用要因) <span className="text-[#3d5068]">(0〜100 にクリップ)</span>
                </p>
              </div>
            </div>

            {/* Factor weights */}
            <div className="bg-[#0d1220] rounded-xl border border-[#1e2d42] p-6">
              <div className="flex items-center gap-2 mb-4">
                <SlidersHorizontal className="w-5 h-5 text-[#1a6bff]" />
                <h2 className="text-white font-semibold">要因ウェイト設定</h2>
              </div>

              <div className="space-y-3">
                {[
                  { name: 'ベーススコア', impact: 50, color: 'text-white', barColor: 'bg-blue-500', description: '全エンドポイントに共通する基準点。すべての算出の出発点です。', sign: '+' },
                  { name: 'サーバーOS', impact: 20, color: 'text-green-400', barColor: 'bg-green-500', description: 'Windows Server / Linux サーバーOSを持つエンドポイントに加算。インフラへの影響度が高いため。', sign: '+' },
                  { name: 'アクティブアラート', impact: 15, color: 'text-orange-400', barColor: 'bg-orange-500', description: '未解決の高・重大深刻度アラートがある場合に加算。リスクが高い状態であることを反映。', sign: '+' },
                  { name: '高脆弱性', impact: 10, color: 'text-yellow-400', barColor: 'bg-yellow-500', description: 'CVSSスコア 7.0以上の未修正脆弱性が存在する場合に加算。', sign: '+' },
                  { name: 'オフラインペナルティ', impact: 10, color: 'text-red-400', barColor: 'bg-red-500', description: 'エンドポイントがオフラインまたは長時間未接続の場合に減算。可視性の低下を反映。', sign: '-' },
                ].map(f => (
                  <div key={f.name} className="flex items-start gap-4 p-3 bg-[#070d19] rounded-lg border border-[#1e2d42]">
                    <div className="flex-1 min-w-0">
                      <div className="flex items-center gap-3 mb-1">
                        <span className="text-sm text-white font-medium">{f.name}</span>
                        <span className={`text-sm font-bold ${f.color}`}>
                          {f.sign}{f.impact}点
                        </span>
                      </div>
                      <p className="text-xs text-[#3d5068]">{f.description}</p>
                    </div>
                    <div className="w-24 shrink-0 mt-2">
                      <div className="h-1.5 bg-[#1e2d42] rounded-full overflow-hidden">
                        <div
                          className={`h-full rounded-full ${f.barColor}`}
                          style={{ width: `${(f.impact / 50) * 100}%` }}
                        />
                      </div>
                    </div>
                  </div>
                ))}
              </div>

              <div className="mt-4 p-3 bg-[#1a6bff]/5 border border-[#1a6bff]/20 rounded-lg">
                <div className="flex items-start gap-2">
                  <Info className="w-4 h-4 text-[#1a6bff] shrink-0 mt-0.5" />
                  <p className="text-xs text-[#7d92b0]">
                    上記の要因ウェイトは現在表示専用です。将来のバージョンで管理者によるカスタマイズが可能になります。
                    手動スコア設定は「重要度一覧」タブから各エンドポイントの「スコア設定」ボタンで行えます。
                  </p>
                </div>
              </div>
            </div>

            {/* Tier thresholds */}
            <div className="bg-[#0d1220] rounded-xl border border-[#1e2d42] p-6">
              <div className="flex items-center gap-2 mb-4">
                <Gauge className="w-5 h-5 text-[#1a6bff]" />
                <h2 className="text-white font-semibold">ティア閾値</h2>
              </div>

              <div className="grid grid-cols-2 gap-4">
                {([
                  { tier: 'critical' as Tier, range: '80 〜 100', label: 'Critical', desc: '最高レベルの保護が必要。即時対応必須。インフラの根幹を担うサーバー等が該当。' },
                  { tier: 'high'     as Tier, range: '60 〜 79',  label: 'High',     desc: '高い保護が必要。優先的に監視・対応すること。主要なアプリケーションサーバー等が該当。' },
                  { tier: 'medium'   as Tier, range: '40 〜 59',  label: 'Medium',   desc: '中程度の保護が必要。定期的な確認・対応を推奨。一般的な業務用PCが該当。' },
                  { tier: 'low'      as Tier, range: '0 〜 39',   label: 'Low',      desc: '基本的な保護で対応可能。テスト環境・キオスク端末・非重要エンドポイント等が該当。' },
                ] as const).map(t => {
                  const tc = tierConfig[t.tier]
                  return (
                    <div key={t.tier} className={`rounded-lg p-4 border ${tc.cls.split(' ').slice(0, 2).join(' ')} border-opacity-30 bg-[#070d19]`}>
                      <div className="flex items-center justify-between mb-2">
                        <span className={`text-sm font-bold ${tc.scoreColor}`}>{t.label}</span>
                        <code className="text-xs font-mono text-[#7d92b0] bg-[#0d1220] px-2 py-0.5 rounded-sm border border-[#1e2d42]">
                          {t.range}
                        </code>
                      </div>
                      <p className="text-xs text-[#3d5068] leading-relaxed">{t.desc}</p>
                    </div>
                  )
                })}
              </div>
            </div>
          </div>
        )}
      </div>

      {/* ── Override Modal ── */}
      {overrideAsset && (
        <OverrideModal
          asset={overrideAsset}
          onClose={() => setOverrideAsset(undefined)}
          onSave={(score, reason) => setManualScore.mutate({ id: overrideAsset.id, score, reason })}
        />
      )}
    </div>
  )
}

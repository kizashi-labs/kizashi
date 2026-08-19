'use client'

import { useState, useMemo, useRef } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { apiFetch } from '@/lib/api'
import {
  Package, Upload, Download, ChevronDown, ChevronRight,
  AlertTriangle, CheckCircle, RefreshCw, X, Filter,
  Shield, FileText, GitCompare, Layers,
} from 'lucide-react'


import { PageDataUnavailable } from '@/components/PageDataUnavailable'

// ─── Types ────────────────────────────────────────────────────────────────────

type ComponentType = 'library' | 'framework' | 'tool' | 'OS'
type LicenseType = 'MIT' | 'Apache-2.0' | 'GPL-3.0' | 'BSD-3-Clause' | 'LGPL-2.1' | 'Proprietary' | 'Unknown'
type SbomFormat = 'CycloneDX' | 'SPDX' | 'custom'

interface CVEEntry {
  id: string
  severity: 'critical' | 'high' | 'medium' | 'low'
  score: number
  description: string
  fix_version: string | null
}

interface SbomComponent {
  id: string
  name: string
  version: string
  type: ComponentType
  license: LicenseType
  cves: CVEEntry[]
  last_updated: string
  risk_score: number
}

interface SbomReport {
  id: string
  filename: string
  format: SbomFormat
  app_name: string
  import_date: string
  component_count: number
  vuln_count: number
}

// ─── Helpers ──────────────────────────────────────────────────────────────────

const SEV_COLORS = {
  critical: 'bg-red-500/20 text-red-300 border-red-500/40',
  high:     'bg-orange-500/20 text-orange-300 border-orange-500/40',
  medium:   'bg-yellow-500/20 text-yellow-300 border-yellow-500/40',
  low:      'bg-blue-500/20 text-blue-300 border-blue-500/40',
}

const TYPE_COLORS: Record<ComponentType, string> = {
  library:   'bg-blue-500/20 text-blue-300 border-blue-500/30',
  framework: 'bg-purple-500/20 text-purple-300 border-purple-500/30',
  tool:      'bg-cyan-500/20 text-cyan-300 border-cyan-500/30',
  OS:        'bg-emerald-500/20 text-emerald-300 border-emerald-500/30',
}

const FORMAT_COLORS: Record<SbomFormat, string> = {
  CycloneDX: 'bg-indigo-500/20 text-indigo-300 border-indigo-500/30',
  SPDX:      'bg-teal-500/20 text-teal-300 border-teal-500/30',
  custom:    'bg-slate-500/20 text-slate-300 border-slate-500/30',
}

function riskBadge(score: number) {
  if (score >= 80) return 'bg-red-500/20 text-red-300 border-red-500/30'
  if (score >= 50) return 'bg-orange-500/20 text-orange-300 border-orange-500/30'
  if (score >= 25) return 'bg-yellow-500/20 text-yellow-300 border-yellow-500/30'
  return 'bg-emerald-500/20 text-emerald-300 border-emerald-500/30'
}

function riskLabel(score: number) {
  if (score >= 80) return '重大'
  if (score >= 50) return '高'
  if (score >= 25) return '中'
  return '低'
}

// ─── Compare Modal ─────────────────────────────────────────────────────────────

function CompareModal({ sboms, onClose }: { sboms: SbomReport[]; onClose: () => void }) {
  const [a, setA] = useState(sboms[0]?.id ?? '')
  const [b, setB] = useState(sboms[1]?.id ?? '')

  const added   = ['lodash@4.17.21', 'axios@1.3.0', 'moment@2.29.4']
  const removed = ['jquery@3.5.1', 'underscore@1.13.1']
  const changed = [{ name: 'react', from: '17.0.1', to: '18.2.0' }, { name: 'webpack', from: '5.60.0', to: '5.75.0' }]

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 backdrop-blur-sm p-4">
      <div className="bg-[#0d1220] border border-[#1e2d42] rounded-xl w-full max-w-xl shadow-2xl">
        <div className="flex items-center justify-between px-5 py-4 border-b border-[#1e2d42]">
          <div className="flex items-center gap-2">
            <GitCompare className="w-4 h-4 text-[#e8002d]" />
            <h2 className="text-white font-semibold text-sm">SBOM比較</h2>
          </div>
          <button onClick={onClose} className="text-[#7d92b0] hover:text-white transition-colors">
            <X className="w-4 h-4" />
          </button>
        </div>

        <div className="px-5 py-4 space-y-4">
          <div className="grid grid-cols-2 gap-3">
            <div>
              <label className="block text-xs text-[#7d92b0] mb-1.5">比較元</label>
              <select className="w-full bg-[#070d19] border border-[#1e2d42] rounded-lg px-3 py-2 text-xs text-white focus:outline-hidden"
                value={a} onChange={e => setA(e.target.value)}>
                {sboms.map(s => <option key={s.id} value={s.id}>{s.filename}</option>)}
              </select>
            </div>
            <div>
              <label className="block text-xs text-[#7d92b0] mb-1.5">比較先</label>
              <select className="w-full bg-[#070d19] border border-[#1e2d42] rounded-lg px-3 py-2 text-xs text-white focus:outline-hidden"
                value={b} onChange={e => setB(e.target.value)}>
                {sboms.map(s => <option key={s.id} value={s.id}>{s.filename}</option>)}
              </select>
            </div>
          </div>

          <div className="space-y-3">
            <div className="rounded-lg border border-emerald-700/40 bg-emerald-900/20 p-3">
              <p className="text-xs font-semibold text-emerald-300 mb-2">追加 ({added.length}件)</p>
              <div className="space-y-1">
                {added.map(c => (
                  <div key={c} className="flex items-center gap-2 text-xs text-emerald-200">
                    <span className="text-emerald-500">+</span>{c}
                  </div>
                ))}
              </div>
            </div>
            <div className="rounded-lg border border-red-700/40 bg-red-900/20 p-3">
              <p className="text-xs font-semibold text-red-300 mb-2">削除 ({removed.length}件)</p>
              <div className="space-y-1">
                {removed.map(c => (
                  <div key={c} className="flex items-center gap-2 text-xs text-red-200">
                    <span className="text-red-500">-</span>{c}
                  </div>
                ))}
              </div>
            </div>
            <div className="rounded-lg border border-yellow-700/40 bg-yellow-900/20 p-3">
              <p className="text-xs font-semibold text-yellow-300 mb-2">変更 ({changed.length}件)</p>
              <div className="space-y-1">
                {changed.map(c => (
                  <div key={c.name} className="flex items-center gap-2 text-xs text-yellow-200">
                    <span className="text-yellow-500">~</span>
                    <span>{c.name}</span>
                    <span className="text-[#3d5068]">{c.from} → {c.to}</span>
                  </div>
                ))}
              </div>
            </div>
          </div>
        </div>

        <div className="px-5 py-3 border-t border-[#1e2d42] flex justify-end">
          <button onClick={onClose}
            className="px-4 py-2 rounded-lg bg-[#1e2d42] hover:bg-[#1e2d42]/80 text-white text-sm transition-all">
            閉じる
          </button>
        </div>
      </div>
    </div>
  )
}

// ─── Main Page ────────────────────────────────────────────────────────────────

export default function SupplyChainPage() {
  const qc = useQueryClient()
  const fileRef = useRef<HTMLInputElement>(null)
  const [activeTab, setActiveTab] = useState<'components' | 'sbom'>('components')
  const [expandedRow, setExpandedRow] = useState<string | null>(null)
  const [filterType, setFilterType] = useState<string>('all')
  const [filterLicense, setFilterLicense] = useState<string>('all')
  const [filterVuln, setFilterVuln] = useState(false)
  const [selected, setSelected] = useState<Set<string>>(new Set())
  const [importing, setImporting] = useState(false)
  const [showCompare, setShowCompare] = useState(false)
  const [toastMsg, setToastMsg] = useState<string | null>(null)

  const showToast = (msg: string) => {
    setToastMsg(msg)
    setTimeout(() => setToastMsg(null), 3000)
  }

  const { data: compData, isError: compErr } = useQuery<{ components: SbomComponent[] }>({
    queryKey: ['sbom-components'],
    queryFn: () => apiFetch('/api/v1/admin/sbom/components'),
    retry: 1,
  })

  const { data: sbomData, isError: sbomErr } = useQuery<{ reports: SbomReport[] }>({
    queryKey: ['sbom-reports'],
    queryFn: () => apiFetch('/api/v1/admin/sbom/reports'),
    retry: 1,
  })

  const components: SbomComponent[] = useMemo(() => {
    if (compErr || !compData) return []
return compData.components ?? []
  }, [compData, compErr])

  const sboms: SbomReport[] = useMemo(() => {
    if (sbomErr || !sbomData) return []
return sbomData.reports ?? []
  }, [sbomData, sbomErr])

  const filtered = useMemo(() => {
    let list = [...components]
    if (filterType !== 'all') list = list.filter(c => c.type === filterType)
    if (filterLicense !== 'all') list = list.filter(c => c.license === filterLicense)
    if (filterVuln) list = list.filter(c => c.cves.length > 0)
    return list
  }, [components, filterType, filterLicense, filterVuln])

  const handleFileChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0]
    if (!file) return
    setImporting(true)
    showToast('解析中...')
    setTimeout(() => {
      setImporting(false)
      showToast(`${file.name} のインポートが完了しました`)
      qc.invalidateQueries({ queryKey: ['sbom-reports'] })
    }, 2000)
    e.target.value = ''
  }

  const handleDownloadCsv = (sbom: SbomReport) => {
    const csv = 'filename,format,app_name,import_date,component_count,vuln_count\n' +
      `${sbom.filename},${sbom.format},${sbom.app_name},${sbom.import_date},${sbom.component_count},${sbom.vuln_count}`
    const blob = new Blob([csv], { type: 'text/csv' })
    const url = URL.createObjectURL(blob)
    const a = document.createElement('a')
    a.href = url; a.download = sbom.filename.replace(/\.[^.]+$/, '.csv')
    a.click(); URL.revokeObjectURL(url)
  }

  const toggleSelect = (id: string) => {
    setSelected(prev => {
      const next = new Set(prev)
      if (next.has(id)) next.delete(id); else next.add(id)
      return next
    })
  }

  const handleBulkUpdate = () => {
    if (selected.size === 0) return
    showToast(`${selected.size}件のアップデートを確認中...`)
    setSelected(new Set())
  }

  const totalComponents = components.length
  const vulnComponents = components.filter(c => c.cves.length > 0).length
  const criticalCves = components.reduce((sum, c) => sum + c.cves.filter(cv => cv.severity === 'critical').length, 0)
  const outdated = components.filter(c => new Date(c.last_updated) < new Date('2024-01-01')).length

  return (
    <div className="min-h-screen bg-[#070d19] p-6">
      <PageDataUnavailable />
      {/* Toast */}
      {toastMsg && (
        <div className="fixed top-4 right-4 z-50 px-4 py-2.5 rounded-lg bg-[#0d1220] border border-[#1e2d42] text-white text-sm shadow-xl">
          {toastMsg}
        </div>
      )}

      {/* Header */}
      <div className="flex items-center justify-between mb-6">
        <div className="flex items-center gap-3">
          <div className="w-9 h-9 rounded-lg bg-linear-to-br from-[#e8002d] to-[#a80020] flex items-center justify-center">
            <Package className="w-5 h-5 text-white" />
          </div>
          <div>
            <h1 className="text-xl font-bold text-white">サプライチェーンセキュリティ</h1>
            <p className="text-xs text-[#7d92b0] mt-0.5">SBOM管理・コンポーネント脆弱性トラッキング</p>
          </div>
        </div>
        <div className="flex items-center gap-2">
          <input ref={fileRef} type="file" accept=".json,.xml" className="hidden" onChange={handleFileChange} />
          <button
            onClick={() => fileRef.current?.click()}
            disabled={importing}
            className="flex items-center gap-2 px-4 py-2 rounded-lg bg-[#1e2d42] hover:bg-[#1e2d42]/80 text-white text-sm font-medium transition-all disabled:opacity-60"
          >
            {importing ? <RefreshCw className="w-4 h-4 animate-spin" /> : <Upload className="w-4 h-4" />}
            SBOMアップロード
          </button>
        </div>
      </div>

      {/* Summary cards */}
      <div className="grid grid-cols-2 lg:grid-cols-4 gap-4 mb-6">
        {[
          { label: '総コンポーネント', value: totalComponents, icon: Layers,        color: 'text-white',       icon_bg: 'bg-blue-500/20' },
          { label: '脆弱コンポーネント', value: vulnComponents, icon: AlertTriangle, color: 'text-orange-400', icon_bg: 'bg-orange-500/20' },
          { label: 'クリティカルCVE',   value: criticalCves,   icon: Shield,         color: 'text-red-400',    icon_bg: 'bg-red-500/20' },
          { label: '古いパッケージ',     value: outdated,       icon: RefreshCw,     color: 'text-yellow-400', icon_bg: 'bg-yellow-500/20' },
        ].map(stat => (
          <div key={stat.label} className="bg-[#0d1220] border border-[#1e2d42] rounded-xl p-4 flex items-center gap-4">
            <div className={`w-10 h-10 rounded-lg ${stat.icon_bg} flex items-center justify-center shrink-0`}>
              <stat.icon className={`w-5 h-5 ${stat.color}`} />
            </div>
            <div>
              <div className={`text-2xl font-bold ${stat.color}`}>{stat.value}</div>
              <div className="text-xs text-[#7d92b0] mt-0.5">{stat.label}</div>
            </div>
          </div>
        ))}
      </div>

      {/* Tabs */}
      <div className="flex gap-1 mb-5 bg-[#0d1220] border border-[#1e2d42] rounded-xl p-1 w-fit">
        {(['components', 'sbom'] as const).map(tab => (
          <button
            key={tab}
            onClick={() => setActiveTab(tab)}
            className={`px-5 py-2 rounded-lg text-sm font-medium transition-all ${
              activeTab === tab
                ? 'bg-[#1e2d42] text-white'
                : 'text-[#7d92b0] hover:text-white'
            }`}
          >
            {tab === 'components' ? 'コンポーネント' : 'SBOM'}
          </button>
        ))}
      </div>

      {/* Components Tab */}
      {activeTab === 'components' && (
        <div className="bg-[#0d1220] border border-[#1e2d42] rounded-xl">
          {/* Toolbar */}
          <div className="flex flex-wrap items-center justify-between gap-3 px-5 py-4 border-b border-[#1e2d42]">
            <div className="flex flex-wrap items-center gap-2">
              <Filter className="w-3.5 h-3.5 text-[#7d92b0]" />
              <select
                className="bg-[#070d19] border border-[#1e2d42] rounded-lg px-2.5 py-1.5 text-xs text-[#7d92b0] focus:outline-hidden"
                value={filterType} onChange={e => setFilterType(e.target.value)}
              >
                <option value="all">全タイプ</option>
                {(['library', 'framework', 'tool', 'OS'] as ComponentType[]).map(t => (
                  <option key={t} value={t}>{t}</option>
                ))}
              </select>
              <select
                className="bg-[#070d19] border border-[#1e2d42] rounded-lg px-2.5 py-1.5 text-xs text-[#7d92b0] focus:outline-hidden"
                value={filterLicense} onChange={e => setFilterLicense(e.target.value)}
              >
                <option value="all">全ライセンス</option>
                {['MIT', 'Apache-2.0', 'GPL-3.0', 'BSD-3-Clause', 'LGPL-2.1', 'Proprietary', 'Unknown'].map(l => (
                  <option key={l} value={l}>{l}</option>
                ))}
              </select>
              <label className="flex items-center gap-1.5 cursor-pointer">
                <input
                  type="checkbox"
                  checked={filterVuln}
                  onChange={e => setFilterVuln(e.target.checked)}
                  className="w-3.5 h-3.5 accent-[#e8002d]"
                />
                <span className="text-xs text-[#7d92b0]">脆弱性あり</span>
              </label>
            </div>
            {selected.size > 0 && (
              <button
                onClick={handleBulkUpdate}
                className="flex items-center gap-2 px-3 py-1.5 rounded-lg bg-[#e8002d] hover:bg-[#c0001f] text-white text-xs font-medium transition-all"
              >
                <RefreshCw className="w-3.5 h-3.5" />
                アップデート確認 ({selected.size}件)
              </button>
            )}
          </div>

          <div className="overflow-x-auto">
            <table className="w-full text-sm min-w-[900px]">
              <thead>
                <tr className="border-b border-[#1e2d42]">
                  <th className="px-4 py-3 w-10">
                    <input type="checkbox" className="w-3.5 h-3.5 accent-[#e8002d]"
                      checked={selected.size === filtered.length && filtered.length > 0}
                      onChange={e => setSelected(e.target.checked ? new Set(filtered.map(c => c.id)) : new Set())}
                    />
                  </th>
                  {['名前', 'バージョン', 'タイプ', 'ライセンス', 'CVE', '最終更新', 'リスク'].map(h => (
                    <th key={h} className="px-4 py-3 text-left text-xs text-[#7d92b0] font-medium">{h}</th>
                  ))}
                  <th className="px-4 py-3 w-8" />
                </tr>
              </thead>
              <tbody>
                {filtered.map(comp => (
                  <>
                    <tr
                      key={comp.id}
                      className={`border-b border-[#1e2d42]/60 hover:bg-[#070d19]/60 transition-colors cursor-pointer ${
                        expandedRow === comp.id ? 'bg-[#070d19]/40' : ''
                      }`}
                      onClick={() => setExpandedRow(expandedRow === comp.id ? null : comp.id)}
                    >
                      <td className="px-4 py-3" onClick={e => e.stopPropagation()}>
                        <input type="checkbox" className="w-3.5 h-3.5 accent-[#e8002d]"
                          checked={selected.has(comp.id)}
                          onChange={() => toggleSelect(comp.id)}
                        />
                      </td>
                      <td className="px-4 py-3 text-white text-xs font-medium font-mono">{comp.name}</td>
                      <td className="px-4 py-3 text-xs text-[#7d92b0] font-mono">{comp.version}</td>
                      <td className="px-4 py-3">
                        <span className={`text-[10px] px-1.5 py-0.5 rounded-sm border ${TYPE_COLORS[comp.type]}`}>{comp.type}</span>
                      </td>
                      <td className="px-4 py-3">
                        <span className="text-[10px] px-1.5 py-0.5 rounded-sm border bg-slate-500/20 text-slate-300 border-slate-500/30">
                          {comp.license}
                        </span>
                      </td>
                      <td className="px-4 py-3">
                        {comp.cves.length > 0 ? (
                          <span className="text-xs font-bold px-2 py-0.5 rounded-full bg-red-500/20 text-red-300 border border-red-500/30">
                            {comp.cves.length} CVE
                          </span>
                        ) : (
                          <span className="text-xs px-2 py-0.5 rounded-full bg-emerald-500/20 text-emerald-300 border border-emerald-500/30">
                            なし
                          </span>
                        )}
                      </td>
                      <td className="px-4 py-3 text-xs text-[#7d92b0]">{comp.last_updated}</td>
                      <td className="px-4 py-3">
                        <span className={`text-[10px] font-bold px-2 py-0.5 rounded-full border ${riskBadge(comp.risk_score)}`}>
                          {riskLabel(comp.risk_score)} ({comp.risk_score})
                        </span>
                      </td>
                      <td className="px-4 py-3">
                        {expandedRow === comp.id
                          ? <ChevronDown className="w-4 h-4 text-[#7d92b0]" />
                          : <ChevronRight className="w-4 h-4 text-[#3d5068]" />}
                      </td>
                    </tr>
                    {expandedRow === comp.id && (
                      <tr key={`${comp.id}-detail`} className="bg-[#070d19]/80">
                        <td colSpan={9} className="px-6 py-4">
                          {comp.cves.length === 0 ? (
                            <div className="flex items-center gap-2 text-emerald-400 text-sm">
                              <CheckCircle className="w-4 h-4" />
                              既知の脆弱性はありません
                            </div>
                          ) : (
                            <div className="space-y-2">
                              <p className="text-xs font-semibold text-[#7d92b0] mb-2">関連CVE</p>
                              {comp.cves.map(cve => (
                                <div key={cve.id} className="flex items-center gap-3 px-3 py-2.5 rounded-lg bg-[#0d1220] border border-[#1e2d42]">
                                  <span className="text-xs font-mono font-bold text-white w-28">{cve.id}</span>
                                  <span className={`text-[10px] px-1.5 py-0.5 rounded-sm border ${SEV_COLORS[cve.severity]}`}>
                                    {cve.severity.toUpperCase()}
                                  </span>
                                  <span className="text-xs font-bold text-white w-8">{cve.score}</span>
                                  <span className="flex-1 text-xs text-[#7d92b0] truncate">{cve.description}</span>
                                  <span className="text-[10px] text-[#3d5068] whitespace-nowrap">
                                    修正: {cve.fix_version ?? '未定'}
                                  </span>
                                  <button
                                    onClick={() => showToast(`${cve.id} の修正を確認しました`)}
                                    className="text-[10px] px-2 py-1 rounded-sm bg-[#e8002d]/20 hover:bg-[#e8002d]/40 text-[#e8002d] border border-[#e8002d]/30 transition-all whitespace-nowrap"
                                  >
                                    修正確認
                                  </button>
                                </div>
                              ))}
                            </div>
                          )}
                        </td>
                      </tr>
                    )}
                  </>
                ))}
              </tbody>
            </table>
            {filtered.length === 0 && (
              <div className="text-center py-12 text-[#3d5068] text-sm">
                条件に合うコンポーネントが見つかりません
              </div>
            )}
          </div>
        </div>
      )}

      {/* SBOM Tab */}
      {activeTab === 'sbom' && (
        <div className="bg-[#0d1220] border border-[#1e2d42] rounded-xl">
          <div className="flex items-center justify-between px-5 py-4 border-b border-[#1e2d42]">
            <h2 className="text-white font-semibold text-sm">インポート済みSBOM</h2>
            <button
              onClick={() => setShowCompare(true)}
              className="flex items-center gap-2 px-3 py-1.5 rounded-lg bg-[#1e2d42] hover:bg-[#1e2d42]/80 text-white text-xs font-medium transition-all"
            >
              <GitCompare className="w-3.5 h-3.5" />
              SBOM比較
            </button>
          </div>

          <div className="p-4 space-y-3">
            {sboms.map(sbom => (
              <div key={sbom.id} className="flex flex-wrap items-center gap-4 px-4 py-4 rounded-xl bg-[#070d19] border border-[#1e2d42] hover:border-[#2a3d57] transition-all">
                <div className="flex items-center gap-3 flex-1 min-w-0">
                  <div className="w-8 h-8 rounded-lg bg-[#1e2d42] flex items-center justify-center shrink-0">
                    <FileText className="w-4 h-4 text-[#7d92b0]" />
                  </div>
                  <div className="min-w-0">
                    <p className="text-white text-sm font-medium font-mono truncate">{sbom.filename}</p>
                    <p className="text-xs text-[#3d5068] mt-0.5">{sbom.app_name}</p>
                  </div>
                </div>

                <div className="flex flex-wrap items-center gap-3 text-xs">
                  <span className={`px-2 py-0.5 rounded-sm border ${FORMAT_COLORS[sbom.format]}`}>{sbom.format}</span>
                  <span className="text-[#7d92b0]">{sbom.import_date}</span>
                  <span className="text-white font-medium">{sbom.component_count}件</span>
                  {sbom.vuln_count > 0 ? (
                    <span className="px-2 py-0.5 rounded-sm border bg-red-500/20 text-red-300 border-red-500/30">
                      脆弱性 {sbom.vuln_count}件
                    </span>
                  ) : (
                    <span className="px-2 py-0.5 rounded-sm border bg-emerald-500/20 text-emerald-300 border-emerald-500/30">
                      脆弱性なし
                    </span>
                  )}
                </div>

                <button
                  onClick={() => handleDownloadCsv(sbom)}
                  className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-[#1e2d42] hover:bg-[#1e2d42]/80 text-white text-xs transition-all"
                >
                  <Download className="w-3.5 h-3.5" />
                  ダウンロード
                </button>
              </div>
            ))}
          </div>
        </div>
      )}

      {showCompare && <CompareModal sboms={sboms} onClose={() => setShowCompare(false)} />}
    </div>
  )
}

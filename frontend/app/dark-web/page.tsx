'use client'

import { useState } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { apiFetch } from '@/lib/api'
import {
  Key, MessageSquare, Database, Globe, AlertTriangle,
  Plus, X, Eye, EyeOff, Shield, Search, Filter,
  CheckCircle2, Clock, AlertCircle, RefreshCw,
  ToggleLeft, ToggleRight, Settings, ChevronDown, ChevronUp,
} from 'lucide-react'
import { USE_MOCK, m } from '@/lib/mock'

// ── Types ──────────────────────────────────────────────────────────────────

type FindingType = 'credential' | 'mention' | 'data_leak' | 'domain_spoof'
type Severity = 'critical' | 'high' | 'medium' | 'low'
type FindingStatus = 'new' | 'investigating' | 'resolved'
type KeywordCategory = 'domain' | 'email' | 'brand' | 'executive'
type ScanFrequency = 'daily' | 'weekly' | 'realtime'

interface DarkWebFinding {
  id: string
  type: FindingType
  title: string
  source: string
  severity: Severity
  preview: string
  discovered_at: string
  status: FindingStatus
}

interface MonitoredKeyword {
  id: string
  keyword: string
  category: KeywordCategory
  enabled: boolean
  last_match_date: string | null
  match_count: number
}

interface ApiIntegration {
  id: string
  name: string
  description: string
  configured: boolean
}

// ── Mock Data ──────────────────────────────────────────────────────────────

const MOCK_FINDINGS: DarkWebFinding[] = [
  {
    id: 'f1',
    type: 'credential',
    title: '企業メールアドレスとパスワードの漏洩',
    source: 'BreachForums (mirror)',
    severity: 'critical',
    preview: 'admin@company.com:P@ssw0rd123 などの認証情報が約450件含まれるデータセットがフォーラムに投稿されました。2024年のデータ侵害と思われます。',
    discovered_at: '2026-03-15T08:23:00Z',
    status: 'new',
  },
  {
    id: 'f2',
    type: 'credential',
    title: 'VPNアカウント認証情報の流出',
    source: 'RaidForums (TOR)',
    severity: 'critical',
    preview: '社内VPN用と思われるアカウント情報15件が検出されました。ユーザー名にcompany.comドメインが含まれています。',
    discovered_at: '2026-03-12T14:05:00Z',
    status: 'investigating',
  },
  {
    id: 'f3',
    type: 'credential',
    title: 'Slackワークスペーストークンの漏洩',
    source: 'PasteSite (onion)',
    severity: 'high',
    preview: 'xoxb-で始まるSlackBotトークンが公開されたペーストに含まれていました。該当ワークスペースの確認が必要です。',
    discovered_at: '2026-03-10T22:41:00Z',
    status: 'resolved',
  },
  {
    id: 'f4',
    type: 'mention',
    title: 'ハッカーフォーラムでの企業名言及',
    source: 'XSS.is (TOR)',
    severity: 'medium',
    preview: '攻撃計画を示唆するスレッドで企業名が5回言及されました。内容はSQL Injectionの脆弱性に関する議論です。',
    discovered_at: '2026-03-14T11:30:00Z',
    status: 'new',
  },
  {
    id: 'f5',
    type: 'mention',
    title: 'Telegramチャンネルでの標的リストへの掲載',
    source: 'Telegram (private channel)',
    severity: 'high',
    preview: 'ランサムウェアグループが運営するTelegramチャンネルにて、企業が次のターゲットリストに含まれていることが確認されました。',
    discovered_at: '2026-03-08T03:15:00Z',
    status: 'investigating',
  },
  {
    id: 'f6',
    type: 'data_leak',
    title: '顧客データベースの一部流出',
    source: 'Exploit.in (TOR)',
    severity: 'critical',
    preview: '顧客と思われる個人情報(氏名・メール・電話番号)が約1,200件含まれるCSVファイルが販売されています。価格は0.5 BTC。',
    discovered_at: '2026-03-16T07:50:00Z',
    status: 'new',
  },
  {
    id: 'f7',
    type: 'data_leak',
    title: 'ソースコードリポジトリの流出疑い',
    source: 'BreachForums (mirror)',
    severity: 'high',
    preview: '内部ツールのソースコードと思われるアーカイブファイルが投稿されています。READMEにcompany.comのURLが記載されています。',
    discovered_at: '2026-03-11T16:20:00Z',
    status: 'investigating',
  },
  {
    id: 'f8',
    type: 'domain_spoof',
    title: 'フィッシング用ドメインの登録',
    source: 'PhishTank (TOR mirror)',
    severity: 'medium',
    preview: 'company-login.com および company-secure.net が本日登録され、フィッシングサイトとして悪用されている可能性があります。',
    discovered_at: '2026-03-17T09:05:00Z',
    status: 'new',
  },
]

const MOCK_KEYWORDS: MonitoredKeyword[] = [
  { id: 'k1', keyword: 'company.com', category: 'domain', enabled: true, last_match_date: '2026-03-17', match_count: 23 },
  { id: 'k2', keyword: '@company.com', category: 'email', enabled: true, last_match_date: '2026-03-15', match_count: 47 },
  { id: 'k3', keyword: 'Kizashi', category: 'brand', enabled: true, last_match_date: '2026-03-10', match_count: 8 },
  { id: 'k4', keyword: 'FalconEDR', category: 'brand', enabled: true, last_match_date: null, match_count: 0 },
  { id: 'k5', keyword: 'Tanaka Hiroshi CEO', category: 'executive', enabled: false, last_match_date: null, match_count: 0 },
  { id: 'k6', keyword: 'company-internal.com', category: 'domain', enabled: true, last_match_date: '2026-03-08', match_count: 3 },
]

const MOCK_INTEGRATIONS: ApiIntegration[] = [
  { id: 'hibp', name: 'Have I Been Pwned', description: '漏洩メールアドレス・パスワードのデータベース検索サービス', configured: false },
  { id: 'spycloud', name: 'SpyCloud', description: '企業向け認証情報流出検知・アカウントテイクオーバー防止', configured: false },
  { id: 'digital-shadows', name: 'Digital Shadows', description: 'デジタルリスク保護・ダークウェブ監視プラットフォーム', configured: false },
  { id: 'intelx', name: 'IntelX', description: 'ダークウェブ・データ漏洩の包括的インテリジェンス検索', configured: false },
]

// ── Helpers ────────────────────────────────────────────────────────────────

const TYPE_CONFIG: Record<FindingType, { label: string; icon: React.ElementType; color: string }> = {
  credential: { label: '認証情報', icon: Key, color: 'text-red-400 bg-red-900/30 border-red-700/50' },
  mention: { label: 'メンション', icon: MessageSquare, color: 'text-yellow-400 bg-yellow-900/30 border-yellow-700/50' },
  data_leak: { label: 'データ流出', icon: Database, color: 'text-purple-400 bg-purple-900/30 border-purple-700/50' },
  domain_spoof: { label: 'ドメイン詐称', icon: Globe, color: 'text-blue-400 bg-blue-900/30 border-blue-700/50' },
}

const SEV_CONFIG: Record<Severity, { label: string; badge: string }> = {
  critical: { label: 'Critical', badge: 'bg-red-900/60 border-red-700 text-red-300' },
  high: { label: 'High', badge: 'bg-orange-900/60 border-orange-700 text-orange-300' },
  medium: { label: 'Medium', badge: 'bg-yellow-900/60 border-yellow-700 text-yellow-300' },
  low: { label: 'Low', badge: 'bg-blue-900/60 border-blue-700 text-blue-300' },
}

const STATUS_CONFIG: Record<FindingStatus, { label: string; badge: string; icon: React.ElementType }> = {
  new: { label: '新規', badge: 'bg-red-900/60 border-red-700 text-red-300', icon: AlertCircle },
  investigating: { label: '調査中', badge: 'bg-yellow-900/60 border-yellow-700 text-yellow-300', icon: Clock },
  resolved: { label: '解決済み', badge: 'bg-green-900/60 border-green-700 text-green-300', icon: CheckCircle2 },
}

const CAT_CONFIG: Record<KeywordCategory, { label: string; badge: string }> = {
  domain: { label: 'ドメイン', badge: 'bg-blue-900/40 text-blue-300 border-blue-700/50' },
  email: { label: 'メール', badge: 'bg-green-900/40 text-green-300 border-green-700/50' },
  brand: { label: 'ブランド', badge: 'bg-purple-900/40 text-purple-300 border-purple-700/50' },
  executive: { label: '役員', badge: 'bg-yellow-900/40 text-yellow-300 border-yellow-700/50' },
}

function fmtDate(iso: string) {
  return new Date(iso).toLocaleDateString('ja-JP', { year: 'numeric', month: '2-digit', day: '2-digit', hour: '2-digit', minute: '2-digit' })
}

// ── Main Page ──────────────────────────────────────────────────────────────

export default function DarkWebMonitoringPage() {
  const qc = useQueryClient()
  const [activeTab, setActiveTab] = useState<'findings' | 'keywords' | 'settings'>('findings')

  // Filters
  const [typeFilter, setTypeFilter] = useState<string>('all')
  const [sevFilter, setSevFilter] = useState<string>('all')
  const [expandedFindings, setExpandedFindings] = useState<Set<string>>(new Set())

  // Modals
  const [showAddKeyword, setShowAddKeyword] = useState(false)
  const [keywordForm, setKeywordForm] = useState({ keyword: '', category: 'domain' as KeywordCategory })
  const [showApiConfig, setShowApiConfig] = useState<string | null>(null)
  const [apiKeyInput, setApiKeyInput] = useState('')
  const [scanFreq, setScanFreq] = useState<ScanFrequency>('daily')
  const [emailNotify, setEmailNotify] = useState(true)

  const { data: keywordsData } = useQuery<MonitoredKeyword[]>({
    queryKey: ['dark-web-keywords'],
    queryFn: () => apiFetch<MonitoredKeyword[]>('/api/v1/dark-web/keywords').catch(() => []),
    staleTime: 30_000,
  })
  const { data: integrationsData } = useQuery<ApiIntegration[]>({
    queryKey: ['dark-web-integrations'],
    queryFn: () => apiFetch<ApiIntegration[]>('/api/v1/dark-web/integrations').catch(() => []),
    staleTime: 60_000,
  })
  const [keywords, setKeywords] = useState<MonitoredKeyword[]>([])
  // sync API keywords into local editable state
  const [keywordsSynced, setKeywordsSynced] = useState(false)
  if (!keywordsSynced && keywordsData && keywordsData.length > 0) {
    setKeywords(keywordsData)
    setKeywordsSynced(true)
  }

  // API calls
  const { data: findingsData } = useQuery<DarkWebFinding[]>({
    queryKey: ['dark-web-findings'],
    queryFn: () => apiFetch<DarkWebFinding[]>('/api/v1/dark-web/findings').catch(() => []),
    staleTime: 30_000,
  })

  const createAlertMutation = useMutation({
    mutationFn: (finding: DarkWebFinding) =>
      apiFetch('/api/v1/alerts', {
        method: 'POST',
        body: JSON.stringify({
          title: `[ダークウェブ] ${finding.title}`,
          severity: finding.severity,
          description: finding.preview,
          source: 'dark_web_monitor',
        }),
      }).catch(() => ({ id: `mock-${Date.now()}`, message: 'アラートを作成しました（モック）' })),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['alert-stats-sidebar'] })
    },
  })

  const updateFindingStatus = useMutation({
    mutationFn: ({ id, status }: { id: string; status: FindingStatus }) =>
      apiFetch(`/api/v1/dark-web/findings/${id}`, {
        method: 'PATCH',
        body: JSON.stringify({ status }),
      }).catch(() => ({ id, status })),
  })

  const findings = findingsData ?? []

  const filteredFindings = findings.filter(f => {
    if (typeFilter !== 'all' && f.type !== typeFilter) return false
    if (sevFilter !== 'all' && f.severity !== sevFilter) return false
    return true
  })

  const stats = {
    keywords: keywords.length,
    findingsThisMonth: findings.filter(f => new Date(f.discovered_at) > new Date(new Date().getFullYear(), new Date().getMonth(), 1)).length,
    leakedCredentials: findings.filter(f => f.type === 'credential').length,
    lastScan: findings.length > 0
      ? new Date(Math.max(...findings.map(f => new Date(f.discovered_at).getTime()))).toLocaleString('ja-JP', { year: 'numeric', month: '2-digit', day: '2-digit', hour: '2-digit', minute: '2-digit' })
      : '—',
  }

  const toggleExpand = (id: string) => {
    setExpandedFindings(prev => {
      const next = new Set(prev)
      if (next.has(id)) next.delete(id)
      else next.add(id)
      return next
    })
  }

  const toggleKeyword = (id: string) => {
    setKeywords(prev => prev.map(k => k.id === id ? { ...k, enabled: !k.enabled } : k))
  }

  const addKeyword = () => {
    if (!keywordForm.keyword.trim()) return
    const newKw: MonitoredKeyword = {
      id: `k${Date.now()}`,
      keyword: keywordForm.keyword.trim(),
      category: keywordForm.category,
      enabled: true,
      last_match_date: null,
      match_count: 0,
    }
    setKeywords(prev => [...prev, newKw])
    setKeywordForm({ keyword: '', category: 'domain' })
    setShowAddKeyword(false)
  }

  return (
    <div className="min-h-screen bg-[#070d19] text-[#e2e8f4]">
      <div className="max-w-7xl mx-auto px-6 py-6 space-y-6">

        {/* Header */}
        <div>
          <h1 className="text-2xl font-bold text-white">ダークウェブ監視</h1>
          <p className="text-[#7d92b0] mt-1">漏洩認証情報・メンション・データ流出の監視</p>
        </div>

        {/* Warning Banner */}
        {findings.length === 0 && keywords.length === 0 && (
          <div className="flex items-start gap-3 px-4 py-3 rounded-lg border border-yellow-700/50 bg-yellow-900/20">
            <AlertTriangle className="w-5 h-5 text-yellow-400 flex-shrink-0 mt-0.5" />
            <p className="text-yellow-300 text-sm">
              検出データがありません。外部脅威インテリジェンスAPIを設定するか、監視キーワードを追加してください。
            </p>
          </div>
        )}

        {/* Stats Row */}
        <div className="grid grid-cols-2 lg:grid-cols-4 gap-4">
          {[
            { label: '監視キーワード数', value: stats.keywords, icon: Search, color: 'text-blue-400', bold: false },
            { label: '今月の検出数', value: stats.findingsThisMonth, icon: Shield, color: stats.findingsThisMonth > 0 ? 'text-red-400' : 'text-green-400', bold: stats.findingsThisMonth > 0 },
            { label: '漏洩認証情報', value: stats.leakedCredentials, icon: Key, color: stats.leakedCredentials > 0 ? 'text-red-400' : 'text-green-400', bold: stats.leakedCredentials > 0 },
            { label: '最終スキャン', value: stats.lastScan, icon: RefreshCw, color: 'text-green-400', bold: false, isText: true },
          ].map(({ label, value, icon: Icon, color, bold, isText }) => (
            <div key={label} className="bg-[#0d1220] border border-[#1e2d42] rounded-lg p-4">
              <div className="flex items-center gap-2 mb-2">
                <Icon className={`w-4 h-4 ${color}`} />
                <span className="text-[#7d92b0] text-xs">{label}</span>
              </div>
              <p className={`text-2xl font-bold ${color} ${bold ? 'animate-pulse' : ''} ${isText ? 'text-base' : ''}`}>
                {value}
              </p>
            </div>
          ))}
        </div>

        {/* Tabs */}
        <div className="flex gap-1 border-b border-[#1e2d42]">
          {([
            { id: 'findings', label: '検出結果' },
            { id: 'keywords', label: '監視キーワード' },
            { id: 'settings', label: 'スキャン設定' },
          ] as const).map(tab => (
            <button
              key={tab.id}
              onClick={() => setActiveTab(tab.id)}
              className={`px-4 py-2 text-sm font-medium border-b-2 transition-colors ${
                activeTab === tab.id
                  ? 'border-[#e8002d] text-white'
                  : 'border-transparent text-[#7d92b0] hover:text-[#e2e8f4]'
              }`}
            >
              {tab.label}
            </button>
          ))}
        </div>

        {/* ── Tab: 検出結果 ─────────────────────────────────────── */}
        {activeTab === 'findings' && (
          <div className="space-y-4">
            {/* Filters */}
            <div className="flex flex-wrap gap-3 items-center">
              <Filter className="w-4 h-4 text-[#7d92b0]" />
              <select
                value={typeFilter}
                onChange={e => setTypeFilter(e.target.value)}
                className="bg-[#0d1220] border border-[#1e2d42] text-[#e2e8f4] rounded px-3 py-1.5 text-sm"
              >
                <option value="all">種別: すべて</option>
                <option value="credential">認証情報</option>
                <option value="mention">メンション</option>
                <option value="data_leak">データ流出</option>
                <option value="domain_spoof">ドメイン詐称</option>
              </select>
              <select
                value={sevFilter}
                onChange={e => setSevFilter(e.target.value)}
                className="bg-[#0d1220] border border-[#1e2d42] text-[#e2e8f4] rounded px-3 py-1.5 text-sm"
              >
                <option value="all">深刻度: すべて</option>
                <option value="critical">Critical</option>
                <option value="high">High</option>
                <option value="medium">Medium</option>
                <option value="low">Low</option>
              </select>
              <span className="text-[#7d92b0] text-sm ml-auto">{filteredFindings.length} 件</span>
            </div>

            {/* Finding Cards */}
            <div className="space-y-3">
              {filteredFindings.map(finding => {
                const typeConf = TYPE_CONFIG[finding.type]
                const sevConf = SEV_CONFIG[finding.severity]
                const statusConf = STATUS_CONFIG[finding.status]
                const TypeIcon = typeConf.icon
                const StatusIcon = statusConf.icon
                const isExpanded = expandedFindings.has(finding.id)

                return (
                  <div key={finding.id} className="bg-[#0d1220] border border-[#1e2d42] rounded-lg p-4 space-y-3">
                    <div className="flex items-start gap-3">
                      {/* Type Icon */}
                      <div className={`w-10 h-10 rounded-lg flex items-center justify-center border flex-shrink-0 ${typeConf.color}`}>
                        <TypeIcon className="w-5 h-5" />
                      </div>

                      {/* Main Content */}
                      <div className="flex-1 min-w-0">
                        <div className="flex items-start justify-between gap-2 flex-wrap">
                          <div className="space-y-1">
                            <h3 className="text-white font-medium text-sm">{finding.title}</h3>
                            <p className="text-[#7d92b0] text-xs">ソース: {finding.source}</p>
                          </div>
                          <div className="flex items-center gap-2 flex-wrap">
                            <span className={`px-2 py-0.5 rounded text-xs border font-medium ${sevConf.badge}`}>
                              {sevConf.label}
                            </span>
                            <span className={`px-2 py-0.5 rounded text-xs border font-medium flex items-center gap-1 ${statusConf.badge}`}>
                              <StatusIcon className="w-3 h-3" />
                              {statusConf.label}
                            </span>
                          </div>
                        </div>

                        {/* Preview */}
                        <p className={`text-[#7d92b0] text-xs mt-2 ${isExpanded ? '' : 'line-clamp-2'}`}>
                          {finding.preview}
                        </p>
                        <button
                          onClick={() => toggleExpand(finding.id)}
                          className="text-[#e8002d] text-xs mt-1 hover:underline flex items-center gap-1"
                        >
                          {isExpanded ? <><ChevronUp className="w-3 h-3" />閉じる</> : <><ChevronDown className="w-3 h-3" />詳細</>}
                        </button>

                        <p className="text-[#3d5068] text-xs mt-2">発見: {fmtDate(finding.discovered_at)}</p>
                      </div>
                    </div>

                    {/* Actions */}
                    <div className="flex items-center gap-2 flex-wrap pt-1 border-t border-[#1e2d42]">
                      {finding.status === 'new' && (
                        <button
                          onClick={() => updateFindingStatus.mutate({ id: finding.id, status: 'investigating' })}
                          className="px-3 py-1 text-xs rounded border border-yellow-700/50 text-yellow-300 hover:bg-yellow-900/20 transition-colors"
                        >
                          調査中にする
                        </button>
                      )}
                      {finding.status !== 'resolved' && (
                        <button
                          onClick={() => updateFindingStatus.mutate({ id: finding.id, status: 'resolved' })}
                          className="px-3 py-1 text-xs rounded border border-green-700/50 text-green-300 hover:bg-green-900/20 transition-colors"
                        >
                          解決済みにする
                        </button>
                      )}
                      <button
                        onClick={() => createAlertMutation.mutate(finding)}
                        className="px-3 py-1 text-xs rounded border border-[#e8002d]/50 text-red-300 hover:bg-red-900/20 transition-colors flex items-center gap-1"
                      >
                        <Plus className="w-3 h-3" />
                        アラート作成
                      </button>
                    </div>
                  </div>
                )
              })}
            </div>
          </div>
        )}

        {/* ── Tab: 監視キーワード ────────────────────────────────── */}
        {activeTab === 'keywords' && (
          <div className="space-y-4">
            <div className="flex items-center justify-between">
              <p className="text-[#7d92b0] text-sm">
                監視中のキーワード・フレーズ ({keywords.filter(k => k.enabled).length}/{keywords.length} 有効)
              </p>
              <button
                onClick={() => setShowAddKeyword(true)}
                className="flex items-center gap-2 px-4 py-2 text-sm rounded bg-[#e8002d] hover:bg-[#c8001d] text-white transition-colors"
              >
                <Plus className="w-4 h-4" />
                キーワード追加
              </button>
            </div>

            <div className="bg-[#0d1220] border border-[#1e2d42] rounded-lg overflow-hidden">
              <table className="w-full text-sm">
                <thead>
                  <tr className="border-b border-[#1e2d42]">
                    <th className="text-left px-4 py-3 text-[#7d92b0] font-medium">キーワード</th>
                    <th className="text-left px-4 py-3 text-[#7d92b0] font-medium">カテゴリ</th>
                    <th className="text-left px-4 py-3 text-[#7d92b0] font-medium">有効</th>
                    <th className="text-left px-4 py-3 text-[#7d92b0] font-medium">最終マッチ</th>
                    <th className="text-left px-4 py-3 text-[#7d92b0] font-medium">マッチ数</th>
                  </tr>
                </thead>
                <tbody>
                  {keywords.map(kw => {
                    const catConf = CAT_CONFIG[kw.category]
                    return (
                      <tr key={kw.id} className="border-b border-[#1e2d42] hover:bg-[#161f33] transition-colors">
                        <td className="px-4 py-3 font-mono text-[#e2e8f4]">{kw.keyword}</td>
                        <td className="px-4 py-3">
                          <span className={`px-2 py-0.5 rounded text-xs border ${catConf.badge}`}>
                            {catConf.label}
                          </span>
                        </td>
                        <td className="px-4 py-3">
                          <button onClick={() => toggleKeyword(kw.id)} className="transition-colors">
                            {kw.enabled
                              ? <ToggleRight className="w-6 h-6 text-green-400" />
                              : <ToggleLeft className="w-6 h-6 text-[#3d5068]" />
                            }
                          </button>
                        </td>
                        <td className="px-4 py-3 text-[#7d92b0] text-xs">
                          {kw.last_match_date ?? '—'}
                        </td>
                        <td className="px-4 py-3">
                          <span className={`font-medium ${kw.match_count > 0 ? 'text-[#e8002d]' : 'text-[#7d92b0]'}`}>
                            {kw.match_count}
                          </span>
                        </td>
                      </tr>
                    )
                  })}
                </tbody>
              </table>
            </div>

            <div className="flex items-center gap-2 px-4 py-3 rounded-lg border border-blue-700/40 bg-blue-900/10">
              <AlertCircle className="w-4 h-4 text-blue-400 flex-shrink-0" />
              <p className="text-blue-300 text-sm">実際の監視はAPIキー設定後に有効になります</p>
            </div>
          </div>
        )}

        {/* ── Tab: スキャン設定 ──────────────────────────────────── */}
        {activeTab === 'settings' && (
          <div className="space-y-6">
            {/* API Integrations */}
            <div>
              <h2 className="text-white font-semibold mb-3">API連携</h2>
              <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
                {(integrationsData ?? []).map(svc => (
                  <div key={svc.id} className="bg-[#0d1220] border border-[#1e2d42] rounded-lg p-4 flex items-start justify-between gap-3">
                    <div className="flex items-start gap-3">
                      <div className="w-2 h-2 rounded-full mt-2 flex-shrink-0 bg-red-500" />
                      <div>
                        <p className="text-white font-medium text-sm">{svc.name}</p>
                        <p className="text-[#7d92b0] text-xs mt-0.5">{svc.description}</p>
                        <span className="inline-block mt-1 px-2 py-0.5 rounded text-xs border border-red-700/50 bg-red-900/30 text-red-300">
                          未設定
                        </span>
                      </div>
                    </div>
                    <button
                      onClick={() => { setShowApiConfig(svc.id); setApiKeyInput('') }}
                      className="flex items-center gap-1.5 px-3 py-1.5 text-xs rounded border border-[#1e2d42] text-[#7d92b0] hover:text-white hover:border-[#7d92b0]/40 transition-colors flex-shrink-0"
                    >
                      <Settings className="w-3 h-3" />
                      設定
                    </button>
                  </div>
                ))}
              </div>
            </div>

            {/* Scan Frequency */}
            <div className="bg-[#0d1220] border border-[#1e2d42] rounded-lg p-4 space-y-3">
              <h2 className="text-white font-semibold">スキャン頻度</h2>
              <div className="flex flex-col gap-2">
                {([
                  { id: 'daily', label: '毎日 (推奨)' },
                  { id: 'weekly', label: '毎週' },
                  { id: 'realtime', label: 'リアルタイム (APIキー必要)' },
                ] as const).map(opt => (
                  <label key={opt.id} className="flex items-center gap-3 cursor-pointer">
                    <input
                      type="radio"
                      name="scan_freq"
                      value={opt.id}
                      checked={scanFreq === opt.id}
                      onChange={() => setScanFreq(opt.id)}
                      className="accent-[#e8002d]"
                    />
                    <span className="text-[#e2e8f4] text-sm">{opt.label}</span>
                  </label>
                ))}
              </div>
            </div>

            {/* Notifications */}
            <div className="bg-[#0d1220] border border-[#1e2d42] rounded-lg p-4 space-y-3">
              <h2 className="text-white font-semibold">通知設定</h2>
              <label className="flex items-center gap-3 cursor-pointer">
                <button
                  onClick={() => setEmailNotify(p => !p)}
                  className="transition-colors"
                >
                  {emailNotify
                    ? <ToggleRight className="w-6 h-6 text-green-400" />
                    : <ToggleLeft className="w-6 h-6 text-[#3d5068]" />
                  }
                </button>
                <span className="text-[#e2e8f4] text-sm">新規検出時にメール通知</span>
              </label>
            </div>
          </div>
        )}
      </div>

      {/* ── Modal: キーワード追加 ────────────────────────────────── */}
      {showAddKeyword && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 backdrop-blur-sm">
          <div className="bg-[#0d1220] border border-[#1e2d42] rounded-lg p-6 w-full max-w-md shadow-xl">
            <div className="flex items-center justify-between mb-4">
              <h2 className="text-white font-semibold">監視キーワード追加</h2>
              <button onClick={() => setShowAddKeyword(false)} className="text-[#7d92b0] hover:text-white">
                <X className="w-5 h-5" />
              </button>
            </div>
            <div className="space-y-4">
              <div>
                <label className="block text-[#7d92b0] text-xs mb-1">キーワード / フレーズ</label>
                <input
                  type="text"
                  value={keywordForm.keyword}
                  onChange={e => setKeywordForm(p => ({ ...p, keyword: e.target.value }))}
                  placeholder="例: company.com, @example.com"
                  className="w-full bg-[#070d19] border border-[#1e2d42] rounded px-3 py-2 text-[#e2e8f4] text-sm focus:outline-none focus:border-[#e8002d]/50"
                />
              </div>
              <div>
                <label className="block text-[#7d92b0] text-xs mb-1">カテゴリ</label>
                <select
                  value={keywordForm.category}
                  onChange={e => setKeywordForm(p => ({ ...p, category: e.target.value as KeywordCategory }))}
                  className="w-full bg-[#070d19] border border-[#1e2d42] rounded px-3 py-2 text-[#e2e8f4] text-sm focus:outline-none focus:border-[#e8002d]/50"
                >
                  <option value="domain">ドメイン</option>
                  <option value="email">メール</option>
                  <option value="brand">ブランド</option>
                  <option value="executive">役員</option>
                </select>
              </div>
            </div>
            <div className="flex gap-3 mt-6">
              <button
                onClick={() => setShowAddKeyword(false)}
                className="flex-1 px-4 py-2 rounded border border-[#1e2d42] text-[#7d92b0] hover:text-white text-sm transition-colors"
              >
                キャンセル
              </button>
              <button
                onClick={addKeyword}
                disabled={!keywordForm.keyword.trim()}
                className="flex-1 px-4 py-2 rounded bg-[#e8002d] hover:bg-[#c8001d] text-white text-sm transition-colors disabled:opacity-40"
              >
                追加
              </button>
            </div>
          </div>
        </div>
      )}

      {/* ── Modal: API設定 ───────────────────────────────────────── */}
      {showApiConfig && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 backdrop-blur-sm">
          <div className="bg-[#0d1220] border border-[#1e2d42] rounded-lg p-6 w-full max-w-md shadow-xl">
            <div className="flex items-center justify-between mb-4">
              <h2 className="text-white font-semibold">
                API設定 — {(integrationsData ?? []).find(s => s.id === showApiConfig)?.name}
              </h2>
              <button onClick={() => setShowApiConfig(null)} className="text-[#7d92b0] hover:text-white">
                <X className="w-5 h-5" />
              </button>
            </div>
            <div className="space-y-4">
              <div>
                <label className="block text-[#7d92b0] text-xs mb-1">APIキー</label>
                <div className="relative">
                  <input
                    type="password"
                    value={apiKeyInput}
                    onChange={e => setApiKeyInput(e.target.value)}
                    placeholder="APIキーを入力してください"
                    className="w-full bg-[#070d19] border border-[#1e2d42] rounded px-3 py-2 text-[#e2e8f4] text-sm focus:outline-none focus:border-[#e8002d]/50 pr-10"
                  />
                </div>
              </div>
              <div className="flex items-start gap-2 px-3 py-2 rounded bg-yellow-900/10 border border-yellow-700/30">
                <AlertTriangle className="w-4 h-4 text-yellow-400 flex-shrink-0 mt-0.5" />
                <p className="text-yellow-300 text-xs">
                  これはデモ環境です。実際のAPIキーは保存されません。
                </p>
              </div>
            </div>
            <div className="flex gap-3 mt-6">
              <button
                onClick={() => setShowApiConfig(null)}
                className="flex-1 px-4 py-2 rounded border border-[#1e2d42] text-[#7d92b0] hover:text-white text-sm transition-colors"
              >
                キャンセル
              </button>
              <button
                onClick={() => setShowApiConfig(null)}
                className="flex-1 px-4 py-2 rounded bg-[#e8002d] hover:bg-[#c8001d] text-white text-sm transition-colors"
              >
                保存 (デモ)
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  )
}

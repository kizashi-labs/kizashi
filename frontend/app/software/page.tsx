'use client'

import { useState, useEffect, useMemo, useRef, Suspense } from 'react'
import { useQuery } from '@tanstack/react-query'
import { useSearchParams } from 'next/navigation'
import { apiFetch } from '@/lib/api'
import {
  Package, Search, Download, AlertTriangle, Server,
  CheckCircle, RefreshCw, ChevronUp, ChevronDown, X,
  Shield, ExternalLink, Clock, Tag, Filter, GitCompare,
  Plus, Minus, ArrowUp,
} from 'lucide-react'
import Link from 'next/link'
import { USE_MOCK, m } from '@/lib/mock'

import { PageDataUnavailable } from '@/components/PageDataUnavailable'

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------
interface SoftwareEntry {
  id: string
  agent_id: string
  name: string
  version?: string
  vendor?: string
  install_date?: string
  install_path?: string
  reported_at?: string
}

interface Agent {
  id: string
  hostname: string
}

interface VulnEntry {
  software_name: string
  version: string
  cve_id: string
  cvss: number
  severity: 'Critical' | 'High' | 'Medium' | 'Low'
  endpoint_count: number
  patch_available?: boolean
}

// ---------------------------------------------------------------------------
// Mock data for fallback
// ---------------------------------------------------------------------------
const MOCK_VULNS: VulnEntry[] = [
  { software_name: 'OpenSSL', version: '1.1.1', cve_id: 'CVE-2022-0778', cvss: 7.5, severity: 'High', endpoint_count: 12, patch_available: true },
  { software_name: 'Log4j', version: '2.14.1', cve_id: 'CVE-2021-44228', cvss: 10.0, severity: 'Critical', endpoint_count: 5, patch_available: true },
  { software_name: 'Apache HTTP Server', version: '2.4.49', cve_id: 'CVE-2021-41773', cvss: 9.8, severity: 'Critical', endpoint_count: 3, patch_available: true },
  { software_name: 'Spring Framework', version: '5.3.16', cve_id: 'CVE-2022-22965', cvss: 9.8, severity: 'Critical', endpoint_count: 8, patch_available: true },
  { software_name: 'curl', version: '7.79.1', cve_id: 'CVE-2023-23916', cvss: 6.5, severity: 'Medium', endpoint_count: 20, patch_available: true },
  { software_name: 'libssl', version: '1.0.2k', cve_id: 'CVE-2021-3711', cvss: 9.8, severity: 'Critical', endpoint_count: 7, patch_available: true },
  { software_name: 'Python', version: '3.9.2', cve_id: 'CVE-2023-24329', cvss: 7.5, severity: 'High', endpoint_count: 15, patch_available: false },
  { software_name: 'nginx', version: '1.18.0', cve_id: 'CVE-2021-23017', cvss: 7.7, severity: 'High', endpoint_count: 4, patch_available: true },
  { software_name: 'Git', version: '2.30.0', cve_id: 'CVE-2023-22490', cvss: 5.5, severity: 'Medium', endpoint_count: 11, patch_available: false },
  { software_name: 'zlib', version: '1.2.11', cve_id: 'CVE-2022-37434', cvss: 9.8, severity: 'Critical', endpoint_count: 9, patch_available: false },
]

const LICENSE_MAP: Record<string, string> = {
  'Microsoft': 'Commercial',
  'Adobe': 'Commercial',
  'Oracle': 'Commercial',
  'VMware': 'Commercial',
  'Mozilla Foundation': 'Open Source',
  'Apache Software Foundation': 'Open Source',
  'Python Software Foundation': 'Open Source',
  'The OpenSSL Project': 'Open Source',
  'GNU': 'Open Source',
  'Free Software Foundation': 'Open Source',
}

function inferLicense(vendor?: string): 'Commercial' | 'Open Source' | 'Unknown' {
  if (!vendor) return 'Unknown'
  for (const [key, lic] of Object.entries(LICENSE_MAP)) {
    if (vendor.includes(key)) return lic as 'Commercial' | 'Open Source' | 'Unknown'
  }
  const lv = vendor.toLowerCase()
  if (lv.includes('microsoft') || lv.includes('adobe') || lv.includes('oracle') || lv.includes('vmware')) return 'Commercial'
  if (lv.includes('apache') || lv.includes('gnu') || lv.includes('open') || lv.includes('mozilla')) return 'Open Source'
  return 'Unknown'
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------
const CVE_KEYWORDS = ['openssl', 'log4j', 'struts', 'spring', 'apache']

function hasCveRisk(name: string): boolean {
  const lower = name.toLowerCase()
  return CVE_KEYWORDS.some(k => lower.includes(k))
}

function useDebounce<T>(value: T, delay: number): T {
  const [debounced, setDebounced] = useState(value)
  useEffect(() => {
    const id = setTimeout(() => setDebounced(value), delay)
    return () => clearTimeout(id)
  }, [value, delay])
  return debounced
}

function isOlderThan6Months(dateStr?: string): boolean {
  if (!dateStr) return false
  const d = new Date(dateStr)
  if (isNaN(d.getTime())) return false
  const sixMonthsAgo = new Date()
  sixMonthsAgo.setMonth(sixMonthsAgo.getMonth() - 6)
  return d < sixMonthsAgo
}

const PAGE_SIZE = 50

const SEVERITY_COLORS: Record<string, string> = {
  Critical: 'bg-red-900/40 text-red-300 border-red-700/50',
  High: 'bg-orange-900/40 text-orange-300 border-orange-700/50',
  Medium: 'bg-yellow-900/40 text-yellow-300 border-yellow-700/50',
  Low: 'bg-blue-900/40 text-blue-300 border-blue-700/50',
}

const SEVERITY_LABELS: Record<string, string> = {
  Critical: 'クリティカル',
  High: '高',
  Medium: '中',
  Low: '低',
}

const LICENSE_COLORS: Record<string, string> = {
  Commercial: 'bg-purple-900/40 text-purple-300 border-purple-700/50',
  'Open Source': 'bg-green-900/40 text-green-300 border-green-700/50',
  Unknown: 'bg-[#1e2d42] text-[#7d92b0] border-[#2a3a52]',
}

const LICENSE_LABELS: Record<string, string> = {
  Commercial: '商用',
  'Open Source': 'オープンソース',
  Unknown: '不明',
}

type TabId = 'installed' | 'vulnerabilities' | 'outdated' | 'licenses' | 'changes'

type ChangeType = 'installed' | 'removed' | 'updated'
interface SoftwareChange {
  name: string
  hostname: string
  change: ChangeType
  old_version?: string
  new_version?: string
  detected_at: string
  risk?: 'low' | 'medium' | 'high'
}

const MOCK_CHANGES: SoftwareChange[] = [
  { name: 'OpenSSL', hostname: 'ws-001', change: 'updated', old_version: '1.1.1k', new_version: '3.0.8', detected_at: '2026-03-21T09:12:00Z', risk: 'low' },
  { name: 'Python 3.9', hostname: 'srv-db01', change: 'installed', new_version: '3.9.18', detected_at: '2026-03-21T08:45:00Z', risk: 'medium' },
  { name: 'TeamViewer', hostname: 'ws-042', change: 'installed', new_version: '15.50.4', detected_at: '2026-03-20T17:33:00Z', risk: 'high' },
  { name: 'Adobe Acrobat Reader', hostname: 'ws-015', change: 'updated', old_version: '23.001.20064', new_version: '23.006.20320', detected_at: '2026-03-20T14:22:00Z', risk: 'low' },
  { name: 'PuTTY', hostname: 'srv-app01', change: 'removed', old_version: '0.78', detected_at: '2026-03-20T11:05:00Z', risk: 'low' },
  { name: 'Wireshark', hostname: 'ws-008', change: 'installed', new_version: '4.2.3', detected_at: '2026-03-19T16:48:00Z', risk: 'high' },
  { name: 'curl', hostname: 'srv-web02', change: 'updated', old_version: '7.88.1', new_version: '8.5.0', detected_at: '2026-03-19T09:30:00Z', risk: 'low' },
  { name: 'Node.js', hostname: 'srv-app02', change: 'installed', new_version: '20.11.1', detected_at: '2026-03-18T15:17:00Z', risk: 'medium' },
  { name: 'Git', hostname: 'ws-023', change: 'updated', old_version: '2.42.0', new_version: '2.44.0', detected_at: '2026-03-18T10:02:00Z', risk: 'low' },
  { name: 'Chrome', hostname: 'ws-031', change: 'removed', old_version: '122.0.6261.112', detected_at: '2026-03-17T14:55:00Z', risk: 'low' },
]

// ---------------------------------------------------------------------------
// Inner component (requires useSearchParams → wrapped in Suspense)
// ---------------------------------------------------------------------------
function SoftwarePageInner() {
  const searchParams = useSearchParams()

  // ── tab state ─────────────────────────────────────────────────────────────
  const [activeTab, setActiveTab] = useState<TabId>('installed')

  // ── installed tab state ───────────────────────────────────────────────────
  const [inputVal, setInputVal] = useState(searchParams.get('q') ?? '')
  const [agentId, setAgentId]   = useState('')
  const [sortKey, setSortKey]   = useState<'name' | 'install_date'>('name')
  const [sortAsc, setSortAsc]   = useState(true)
  const [page, setPage]         = useState(1)
  const prevAgentId             = useRef('')

  // ── vulnerabilities tab state ─────────────────────────────────────────────
  const [vulnSeverityFilter, setVulnSeverityFilter] = useState<string>('')
  const [vulnSearch, setVulnSearch] = useState('')

  // ── licenses tab state ────────────────────────────────────────────────────
  const [licenseFilter, setLicenseFilter] = useState<string>('')

  // reset page when filters change
  useEffect(() => { setPage(1) }, [agentId])
  useEffect(() => { setPage(1) }, [sortKey, sortAsc])
  useEffect(() => { prevAgentId.current = agentId }, [agentId])

  const debouncedQuery = useDebounce(inputVal.trim(), 300)

  // ── data fetching ─────────────────────────────────────────────────────────
  const { data: agentsData } = useQuery<{ agents?: Agent[]; data?: Agent[] }>({
    queryKey: ['agents-list-sw'],
    queryFn: () => apiFetch('/api/v1/agents?limit=200'),
    staleTime: 60_000,
  })
  const agents: Agent[] = agentsData?.agents ?? agentsData?.data ?? []

  // global search (no agent selected, query present)
  const { data: searchData, isLoading: searchLoading, refetch: refetchSearch } =
    useQuery<{ data: SoftwareEntry[]; total: number }>({
      queryKey: ['software-search', debouncedQuery],
      queryFn: () => apiFetch(`/api/v1/software?q=${encodeURIComponent(debouncedQuery)}`),
      enabled: !agentId && debouncedQuery.length > 0,
      staleTime: 30_000,
    })

  // agent-scoped list
  const { data: agentData, isLoading: agentLoading, refetch: refetchAgent } =
    useQuery<{ data: SoftwareEntry[]; total: number }>({
      queryKey: ['software-agent', agentId],
      queryFn: () => apiFetch(`/api/v1/agents/${agentId}/software`),
      enabled: !!agentId,
      staleTime: 30_000,
    })

  // vulnerabilities data
  const { data: vulnData, isLoading: vulnLoading, refetch: refetchVulns } =
    useQuery<{ vulns?: VulnEntry[] }>({
      queryKey: ['software-vulns'],
      queryFn: () => apiFetch('/api/v1/software/vulnerabilities'),
      staleTime: 60_000,
    })

  const allVulns: VulnEntry[] = vulnData?.vulns ?? (USE_MOCK ? MOCK_VULNS : [])

  // all software for outdated + license tabs
  const { data: allSwData, isLoading: allSwLoading } =
    useQuery<{ data?: SoftwareEntry[]; software?: SoftwareEntry[] }>({
      queryKey: ['software-all'],
      queryFn: () => apiFetch('/api/v1/software?limit=5000'),
      staleTime: 60_000,
    })
  const allSoftware: SoftwareEntry[] = allSwData?.data ?? allSwData?.software ?? []

  const isLoading = agentId ? agentLoading : searchLoading
  const refetch   = agentId ? refetchAgent : refetchSearch

  // ── derived data (installed) ──────────────────────────────────────────────
  const rawItems: SoftwareEntry[] = useMemo(() => {
    if (agentId) {
      const base = agentData?.data ?? []
      return debouncedQuery
        ? base.filter(s => s.name.toLowerCase().includes(debouncedQuery.toLowerCase()))
        : base
    }
    return searchData?.data ?? []
  }, [agentId, agentData, searchData, debouncedQuery])

  const sortedItems = useMemo(() => {
    return [...rawItems].sort((a, b) => {
      const av = sortKey === 'name' ? (a.name ?? '') : (a.install_date ?? '')
      const bv = sortKey === 'name' ? (b.name ?? '') : (b.install_date ?? '')
      const cmp = av.localeCompare(bv)
      return sortAsc ? cmp : -cmp
    })
  }, [rawItems, sortKey, sortAsc])

  const totalItems  = sortedItems.length
  const totalPages  = Math.max(1, Math.ceil(totalItems / PAGE_SIZE))
  const safePage    = Math.min(page, totalPages)
  const pageItems   = sortedItems.slice((safePage - 1) * PAGE_SIZE, safePage * PAGE_SIZE)

  const uniqueNames    = useMemo(() => new Set(rawItems.map(s => s.name)).size, [rawItems])
  const totalInstalls  = rawItems.length
  const agentsWithData = useMemo(() => new Set(rawItems.map(s => s.agent_id)).size, [rawItems])

  const hostnameMap = useMemo(
    () => Object.fromEntries(agents.map(a => [a.id, a.hostname])),
    [agents],
  )

  // ── derived data (vulnerabilities) ───────────────────────────────────────
  const filteredVulns = useMemo(() => {
    let v = allVulns
    if (vulnSeverityFilter) v = v.filter(x => x.severity === vulnSeverityFilter)
    if (vulnSearch.trim()) {
      const q = vulnSearch.toLowerCase()
      v = v.filter(x => x.software_name.toLowerCase().includes(q) || x.cve_id.toLowerCase().includes(q))
    }
    return v
  }, [allVulns, vulnSeverityFilter, vulnSearch])

  const vulnStats = useMemo(() => {
    const counts = { Critical: 0, High: 0, Medium: 0, Low: 0 }
    for (const v of allVulns) counts[v.severity] = (counts[v.severity] ?? 0) + 1
    return counts
  }, [allVulns])

  // ── derived data (outdated) ───────────────────────────────────────────────
  const outdatedItems = useMemo(
    () => allSoftware.filter(s => isOlderThan6Months(s.install_date)),
    [allSoftware],
  )

  // ── derived data (licenses) ───────────────────────────────────────────────
  const licenseGroups = useMemo(() => {
    const groups: Record<string, SoftwareEntry[]> = {
      'Commercial': [],
      'Open Source': [],
      'Unknown': [],
    }
    for (const sw of allSoftware) {
      const lic = inferLicense(sw.vendor)
      groups[lic].push(sw)
    }
    return groups
  }, [allSoftware])

  const filteredLicenseItems = useMemo(() => {
    if (!licenseFilter) return allSoftware
    return licenseGroups[licenseFilter] ?? []
  }, [allSoftware, licenseFilter, licenseGroups])

  // ── sort toggle ───────────────────────────────────────────────────────────
  function toggleSort(key: 'name' | 'install_date') {
    if (sortKey === key) {
      setSortAsc(p => !p)
    } else {
      setSortKey(key)
      setSortAsc(true)
    }
  }

  // ── CSV export ────────────────────────────────────────────────────────────
  function exportCSV() {
    if (sortedItems.length === 0) return
    const headers = ['name', 'version', 'vendor', 'hostname', 'install_date', 'install_path']
    const rows = sortedItems.map(sw => [
      sw.name,
      sw.version ?? '',
      sw.vendor ?? '',
      hostnameMap[sw.agent_id] ?? sw.agent_id,
      sw.install_date ?? '',
      sw.install_path ?? '',
    ])
    const csv = [headers, ...rows]
      .map(r => r.map(v => `"${String(v).replace(/"/g, '""')}"`).join(','))
      .join('\n')
    const blob = new Blob(['\uFEFF' + csv], { type: 'text/csv;charset=utf-8' })
    const url  = URL.createObjectURL(blob)
    const a    = document.createElement('a')
    a.href     = url
    a.download = `software-inventory-${new Date().toISOString().slice(0, 10)}.csv`
    a.click()
    URL.revokeObjectURL(url)
  }

  function exportVulnsCSV() {
    if (filteredVulns.length === 0) return
    const headers = ['software_name', 'version', 'cve_id', 'cvss', 'severity', 'endpoint_count', 'patch_available']
    const rows = filteredVulns.map(v => [
      v.software_name, v.version, v.cve_id, v.cvss, v.severity, v.endpoint_count, v.patch_available ? 'Yes' : 'No',
    ])
    const csv = [headers, ...rows]
      .map(r => r.map(val => `"${String(val).replace(/"/g, '""')}"`).join(','))
      .join('\n')
    const blob = new Blob(['\uFEFF' + csv], { type: 'text/csv;charset=utf-8' })
    const url  = URL.createObjectURL(blob)
    const a    = document.createElement('a')
    a.href = url
    a.download = `vulnerabilities-${new Date().toISOString().slice(0, 10)}.csv`
    a.click()
    URL.revokeObjectURL(url)
  }

  // ── sort indicator helper ─────────────────────────────────────────────────
  function SortIcon({ col }: { col: 'name' | 'install_date' }) {
    if (sortKey !== col) return <ChevronUp className="w-3 h-3 opacity-20" />
    return sortAsc
      ? <ChevronUp className="w-3 h-3 text-teal-400" />
      : <ChevronDown className="w-3 h-3 text-teal-400" />
  }

  const showResults  = !!agentId || debouncedQuery.length > 0
  const selectedHost = agentId ? (hostnameMap[agentId] ?? agentId) : null

  const TABS: { id: TabId; label: string; icon: React.ReactNode; badge?: number }[] = [
    { id: 'installed',       label: 'インストール済み', icon: <Package className="w-4 h-4" /> },
    { id: 'vulnerabilities', label: '脆弱性 (CVE)',   icon: <Shield className="w-4 h-4" />, badge: allVulns.length },
    { id: 'outdated',        label: '古いソフトウェア', icon: <Clock className="w-4 h-4" />, badge: outdatedItems.length },
    { id: 'licenses',        label: 'ライセンス追跡',  icon: <Tag className="w-4 h-4" /> },
    { id: 'changes',         label: '変更差分',         icon: <GitCompare className="w-4 h-4" />, badge: (USE_MOCK ? MOCK_CHANGES : []).filter(c => c.risk === 'high').length },
  ]

  // ── render ────────────────────────────────────────────────────────────────
  return (
    <div className="bg-[#070d19] min-h-screen text-white">
      <div className="max-w-7xl mx-auto px-6 py-8 space-y-6">
        <PageDataUnavailable />

        {/* ── Header ─────────────────────────────────────────────────────── */}
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-3">
            <div className="w-10 h-10 bg-teal-700 rounded-xl flex items-center justify-center shrink-0">
              <Package className="w-5 h-5 text-white" />
            </div>
            <div>
              <h1 className="text-2xl font-bold text-white">ソフトウェアインベントリ</h1>
              <p className="text-sm text-[#7d92b0] mt-0.5">エンドポイントにインストールされたソフトウェアを管理・分析</p>
            </div>
          </div>
          <button
            onClick={() => {
              refetch()
              refetchVulns()
            }}
            disabled={isLoading || vulnLoading}
            title="再読み込み"
            className="p-2 rounded-lg text-[#5a6a7a] hover:text-white hover:bg-[#0d1220] transition-colors disabled:opacity-40"
          >
            <RefreshCw className={`w-4 h-4 ${isLoading || vulnLoading ? 'animate-spin' : ''}`} />
          </button>
        </div>

        {/* ── Tabs ────────────────────────────────────────────────────────── */}
        <div className="border-b border-[#1e2d42]">
          <div className="flex gap-1">
            {TABS.map(tab => (
              <button
                key={tab.id}
                onClick={() => setActiveTab(tab.id)}
                className={`flex items-center gap-2 px-4 py-3 text-sm font-medium border-b-2 transition-colors -mb-px ${
                  activeTab === tab.id
                    ? 'border-[#e8002d] text-white'
                    : 'border-transparent text-[#7d92b0] hover:text-white hover:border-[#2d4a6e]'
                }`}
              >
                {tab.icon}
                {tab.label}
                {tab.badge !== undefined && tab.badge > 0 && (
                  <span className={`text-xs px-1.5 py-0.5 rounded-full font-mono ${
                    activeTab === tab.id ? 'bg-[#e8002d]/20 text-[#e8002d]' : 'bg-[#1e2d42] text-[#7d92b0]'
                  }`}>
                    {tab.badge}
                  </span>
                )}
              </button>
            ))}
          </div>
        </div>

        {/* ══════════════════════════════════════════════════════════════════
            TAB: INSTALLED
        ══════════════════════════════════════════════════════════════════ */}
        {activeTab === 'installed' && (
          <>
            {/* ── Search / Filter bar ─────────────────────────────────────── */}
            <div className="bg-[#0d1220] rounded-xl border border-[#1e2d42] p-4">
              <div className="flex flex-wrap items-center gap-3">
                <div className="relative flex-1 min-w-[220px]">
                  <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-[#5a6a7a]" />
                  <input
                    value={inputVal}
                    onChange={e => { setInputVal(e.target.value); setPage(1) }}
                    placeholder="ソフトウェア名で検索..."
                    className="w-full pl-9 pr-8 py-2 text-sm border border-[#1e2d42] rounded-lg bg-[#070d19] text-white placeholder-[#5a6a7a] focus:outline-hidden focus:border-teal-500 transition-colors"
                  />
                  {inputVal && (
                    <button
                      onClick={() => { setInputVal(''); setPage(1) }}
                      className="absolute right-2 top-1/2 -translate-y-1/2 text-[#5a6a7a] hover:text-white"
                    >
                      <X className="w-3.5 h-3.5" />
                    </button>
                  )}
                </div>
                <div className="relative">
                  <Server className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-[#5a6a7a] pointer-events-none" />
                  <select
                    value={agentId}
                    onChange={e => { setAgentId(e.target.value); setPage(1) }}
                    className="pl-9 pr-8 py-2 text-sm border border-[#1e2d42] rounded-lg bg-[#070d19] text-[#e2e8f4] focus:outline-hidden focus:border-teal-500 appearance-none cursor-pointer transition-colors min-w-[180px]"
                  >
                    <option value="">全エンドポイント</option>
                    {agents.map(a => (
                      <option key={a.id} value={a.id}>{a.hostname}</option>
                    ))}
                  </select>
                </div>
                <button
                  onClick={exportCSV}
                  disabled={sortedItems.length === 0}
                  className="flex items-center gap-1.5 px-4 py-2 text-sm border border-[#1e2d42] bg-[#0d1220] hover:bg-[#1d2f4a] text-[#e2e8f4] rounded-lg transition-colors disabled:opacity-40 ml-auto"
                >
                  <Download className="w-4 h-4" />
                  CSVエクスポート
                </button>
              </div>
              {selectedHost && (
                <div className="mt-2.5 flex items-center gap-2 text-xs text-[#8899aa]">
                  <Server className="w-3.5 h-3.5 text-teal-400" />
                  <Link href={`/endpoints/${agentId}`} className="text-teal-400 hover:underline">
                    {selectedHost}
                  </Link>
                  <span>のソフトウェア一覧</span>
                  <button
                    onClick={() => { setAgentId(''); setPage(1) }}
                    className="ml-1 text-[#5a6a7a] hover:text-white"
                  >
                    <X className="w-3 h-3" />
                  </button>
                </div>
              )}
            </div>

            {/* ── Stats cards ─────────────────────────────────────────────── */}
            {showResults && !isLoading && rawItems.length > 0 && (
              <div className="grid grid-cols-3 gap-4">
                <div className="bg-[#0d1220] border border-[#1e2d42] rounded-xl p-4 flex items-center gap-3">
                  <div className="w-9 h-9 rounded-lg bg-teal-900/50 flex items-center justify-center shrink-0">
                    <Package className="w-4 h-4 text-teal-400" />
                  </div>
                  <div>
                    <p className="text-2xl font-bold text-white">{uniqueNames.toLocaleString()}</p>
                    <p className="text-xs text-[#5a6a7a]">ユニークなソフトウェア名</p>
                  </div>
                </div>
                <div className="bg-[#0d1220] border border-[#1e2d42] rounded-xl p-4 flex items-center gap-3">
                  <div className="w-9 h-9 rounded-lg bg-blue-900/50 flex items-center justify-center shrink-0">
                    <CheckCircle className="w-4 h-4 text-blue-400" />
                  </div>
                  <div>
                    <p className="text-2xl font-bold text-white">{totalInstalls.toLocaleString()}</p>
                    <p className="text-xs text-[#5a6a7a]">合計インストール数</p>
                  </div>
                </div>
                <div className="bg-[#0d1220] border border-[#1e2d42] rounded-xl p-4 flex items-center gap-3">
                  <div className="w-9 h-9 rounded-lg bg-purple-900/50 flex items-center justify-center shrink-0">
                    <Server className="w-4 h-4 text-purple-400" />
                  </div>
                  <div>
                    <p className="text-2xl font-bold text-white">{agentsWithData.toLocaleString()}</p>
                    <p className="text-xs text-[#5a6a7a]">インベントリ保有エージェント</p>
                  </div>
                </div>
              </div>
            )}

            {/* ── Main content area ───────────────────────────────────────── */}
            {!showResults ? (
              <div className="flex flex-col items-center justify-center py-24 bg-[#0d1220] rounded-xl border border-[#1e2d42] text-[#5a6a7a]">
                <Package className="w-14 h-14 mb-4 opacity-20" />
                <p className="text-sm">エンドポイントを選択するか、ソフトウェア名を入力して検索してください</p>
              </div>
            ) : isLoading ? (
              <div className="flex justify-center py-24">
                <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-teal-500" />
              </div>
            ) : rawItems.length === 0 ? (
              <div className="flex flex-col items-center justify-center py-24 bg-[#0d1220] rounded-xl border border-[#1e2d42] text-[#5a6a7a]">
                <Package className="w-12 h-12 mb-3 opacity-20" />
                <p className="text-sm">該当するソフトウェアが見つかりません</p>
                {debouncedQuery && (
                  <button
                    onClick={() => setInputVal('')}
                    className="mt-3 text-xs text-teal-400 hover:underline"
                  >
                    検索をクリア
                  </button>
                )}
              </div>
            ) : (
              <div className="bg-[#0d1220] rounded-xl border border-[#1e2d42] overflow-hidden">
                <div className="px-5 py-3 border-b border-[#1e2d42] flex items-center justify-between gap-3 flex-wrap">
                  <span className="text-sm text-[#8899aa]">
                    {totalItems.toLocaleString()}件
                    {totalPages > 1 && (
                      <span className="ml-1 text-[#5a6a7a]">
                        (ページ {safePage} / {totalPages})
                      </span>
                    )}
                  </span>
                  <span className="flex items-center gap-1.5 text-xs text-orange-400">
                    <AlertTriangle className="w-3.5 h-3.5" />
                    オレンジバッジ = CVE確認推奨ソフトウェア
                  </span>
                </div>
                <div className="overflow-x-auto">
                  <table className="w-full text-sm">
                    <thead>
                      <tr className="border-b border-[#1e2d42] text-xs text-[#8899aa] bg-[#070d19]">
                        <th className="px-4 py-3 text-left">
                          <button
                            onClick={() => toggleSort('name')}
                            className="flex items-center gap-1 hover:text-white transition-colors"
                          >
                            ソフトウェア名
                            <SortIcon col="name" />
                          </button>
                        </th>
                        <th className="px-4 py-3 text-left">バージョン</th>
                        <th className="px-4 py-3 text-left">ベンダー</th>
                        <th className="px-4 py-3 text-left">
                          <button
                            onClick={() => toggleSort('install_date')}
                            className="flex items-center gap-1 hover:text-white transition-colors"
                          >
                            インストール日
                            <SortIcon col="install_date" />
                          </button>
                        </th>
                        {!agentId && (
                          <th className="px-4 py-3 text-left">エンドポイント</th>
                        )}
                        <th className="px-4 py-3 text-left">インストールパス</th>
                      </tr>
                    </thead>
                    <tbody>
                      {pageItems.map(sw => {
                        const cveRisk = hasCveRisk(sw.name)
                        return (
                          <tr
                            key={sw.id}
                            className="border-b border-[#1e2d42]/50 hover:bg-[#161f33]/40 transition-colors"
                          >
                            <td className="px-4 py-2.5">
                              <div className="flex items-center gap-2 flex-wrap">
                                <Package className="w-3.5 h-3.5 text-teal-400 shrink-0" />
                                <span className="text-[#e2e8f4] font-medium">{sw.name}</span>
                                {cveRisk && (
                                  <span className="inline-flex items-center gap-1 px-1.5 py-0.5 rounded-sm text-[10px] font-semibold leading-none bg-orange-900/50 text-orange-300 border border-orange-700/60">
                                    <AlertTriangle className="w-2.5 h-2.5" />
                                    CVE確認推奨
                                  </span>
                                )}
                              </div>
                            </td>
                            <td className="px-4 py-2.5 font-mono text-xs text-[#8899aa]">
                              {sw.version || <span className="text-[#3d4f63]">—</span>}
                            </td>
                            <td className="px-4 py-2.5 text-xs text-[#8899aa]">
                              {sw.vendor || <span className="text-[#3d4f63]">—</span>}
                            </td>
                            <td className="px-4 py-2.5 text-xs text-[#8899aa] whitespace-nowrap">
                              {sw.install_date || <span className="text-[#3d4f63]">—</span>}
                            </td>
                            {!agentId && (
                              <td className="px-4 py-2.5">
                                <Link
                                  href={`/endpoints/${sw.agent_id}`}
                                  className="flex items-center gap-1.5 text-xs text-blue-400 hover:text-blue-300 transition-colors"
                                >
                                  <Server className="w-3 h-3 shrink-0" />
                                  {hostnameMap[sw.agent_id] ?? sw.agent_id.slice(0, 8)}
                                </Link>
                              </td>
                            )}
                            <td className="px-4 py-2.5 font-mono text-xs text-[#5a6a7a] max-w-xs">
                              {sw.install_path ? (
                                <span className="block truncate" title={sw.install_path}>
                                  {sw.install_path}
                                </span>
                              ) : (
                                <span className="text-[#3d4f63]">—</span>
                              )}
                            </td>
                          </tr>
                        )
                      })}
                    </tbody>
                  </table>
                </div>
                {totalPages > 1 && (
                  <div className="flex items-center justify-center gap-2 px-5 py-3 border-t border-[#1e2d42]">
                    <button
                      onClick={() => setPage(1)}
                      disabled={safePage === 1}
                      className="px-2.5 py-1.5 text-xs rounded-sm bg-[#070d19] text-[#8899aa] hover:bg-[#19253d] disabled:opacity-30 transition-colors"
                    >
                      «
                    </button>
                    <button
                      onClick={() => setPage(p => Math.max(1, p - 1))}
                      disabled={safePage === 1}
                      className="px-3 py-1.5 text-xs rounded-sm bg-[#070d19] text-[#8899aa] hover:bg-[#19253d] disabled:opacity-30 transition-colors"
                    >
                      前へ
                    </button>
                    {Array.from({ length: Math.min(7, totalPages) }, (_, i) => {
                      const half  = 3
                      let start   = Math.max(1, safePage - half)
                      const end   = Math.min(totalPages, start + 6)
                      start       = Math.max(1, end - 6)
                      return start + i
                    })
                      .filter(n => n >= 1 && n <= totalPages)
                      .map(n => (
                        <button
                          key={n}
                          onClick={() => setPage(n)}
                          className={`w-8 h-7 text-xs rounded-sm transition-colors ${
                            n === safePage
                              ? 'bg-teal-700 text-white font-semibold'
                              : 'bg-[#070d19] text-[#8899aa] hover:bg-[#19253d]'
                          }`}
                        >
                          {n}
                        </button>
                      ))}
                    <button
                      onClick={() => setPage(p => Math.min(totalPages, p + 1))}
                      disabled={safePage === totalPages}
                      className="px-3 py-1.5 text-xs rounded-sm bg-[#070d19] text-[#8899aa] hover:bg-[#19253d] disabled:opacity-30 transition-colors"
                    >
                      次へ
                    </button>
                    <button
                      onClick={() => setPage(totalPages)}
                      disabled={safePage === totalPages}
                      className="px-2.5 py-1.5 text-xs rounded-sm bg-[#070d19] text-[#8899aa] hover:bg-[#19253d] disabled:opacity-30 transition-colors"
                    >
                      »
                    </button>
                  </div>
                )}
              </div>
            )}
          </>
        )}

        {/* ══════════════════════════════════════════════════════════════════
            TAB: VULNERABILITIES
        ══════════════════════════════════════════════════════════════════ */}
        {activeTab === 'vulnerabilities' && (
          <>
            {/* Severity summary cards */}
            <div className="grid grid-cols-4 gap-4">
              {(['Critical', 'High', 'Medium', 'Low'] as const).map(sev => (
                <div
                  key={sev}
                  onClick={() => setVulnSeverityFilter(vulnSeverityFilter === sev ? '' : sev)}
                  className={`bg-[#0d1220] border rounded-xl p-4 cursor-pointer transition-all ${
                    vulnSeverityFilter === sev
                      ? 'border-[#e8002d] ring-1 ring-[#e8002d]/30'
                      : 'border-[#1e2d42] hover:border-[#2d4a6e]'
                  }`}
                >
                  <div className="flex items-center justify-between mb-2">
                    <span className={`text-xs px-2 py-0.5 rounded-sm border font-semibold ${SEVERITY_COLORS[sev]}`}>
                      {sev}
                    </span>
                    <Shield className="w-4 h-4 text-[#5a6a7a]" />
                  </div>
                  <p className="text-3xl font-bold text-white font-mono">{vulnStats[sev]}</p>
                  <p className="text-xs text-[#7d92b0] mt-1">CVE検出数</p>
                </div>
              ))}
            </div>

            {/* Filter bar */}
            <div className="bg-[#0d1220] rounded-xl border border-[#1e2d42] p-4">
              <div className="flex flex-wrap items-center gap-3">
                <div className="relative flex-1 min-w-[220px]">
                  <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-[#5a6a7a]" />
                  <input
                    value={vulnSearch}
                    onChange={e => setVulnSearch(e.target.value)}
                    placeholder="ソフトウェア名またはCVE IDで検索..."
                    className="w-full pl-9 pr-8 py-2 text-sm border border-[#1e2d42] rounded-lg bg-[#070d19] text-white placeholder-[#5a6a7a] focus:outline-hidden focus:border-[#e8002d] transition-colors"
                  />
                  {vulnSearch && (
                    <button
                      onClick={() => setVulnSearch('')}
                      className="absolute right-2 top-1/2 -translate-y-1/2 text-[#5a6a7a] hover:text-white"
                    >
                      <X className="w-3.5 h-3.5" />
                    </button>
                  )}
                </div>
                <div className="relative">
                  <Filter className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-[#5a6a7a] pointer-events-none" />
                  <select
                    value={vulnSeverityFilter}
                    onChange={e => setVulnSeverityFilter(e.target.value)}
                    className="pl-9 pr-8 py-2 text-sm border border-[#1e2d42] rounded-lg bg-[#070d19] text-[#e2e8f4] focus:outline-hidden focus:border-[#e8002d] appearance-none cursor-pointer transition-colors min-w-[160px]"
                  >
                    <option value="">全深刻度</option>
                    <option value="Critical">クリティカル</option>
                    <option value="High">高</option>
                    <option value="Medium">中</option>
                    <option value="Low">低</option>
                  </select>
                </div>
                <button
                  onClick={exportVulnsCSV}
                  disabled={filteredVulns.length === 0}
                  className="flex items-center gap-1.5 px-4 py-2 text-sm border border-[#1e2d42] bg-[#0d1220] hover:bg-[#1d2f4a] text-[#e2e8f4] rounded-lg transition-colors disabled:opacity-40 ml-auto"
                >
                  <Download className="w-4 h-4" />
                  CSVエクスポート
                </button>
              </div>
            </div>

            {/* Vulnerabilities table */}
            {vulnLoading ? (
              <div className="flex justify-center py-24">
                <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-[#e8002d]" />
              </div>
            ) : filteredVulns.length === 0 ? (
              <div className="flex flex-col items-center justify-center py-24 bg-[#0d1220] rounded-xl border border-[#1e2d42] text-[#5a6a7a]">
                <Shield className="w-12 h-12 mb-3 opacity-20" />
                <p className="text-sm">脆弱性が見つかりませんでした</p>
              </div>
            ) : (
              <div className="bg-[#0d1220] rounded-xl border border-[#1e2d42] overflow-hidden">
                <div className="px-5 py-3 border-b border-[#1e2d42]">
                  <span className="text-sm text-[#8899aa]">{(filteredVulns.length ?? 0).toLocaleString()}件の脆弱性</span>
                </div>
                <div className="overflow-x-auto">
                  <table className="w-full text-sm">
                    <thead>
                      <tr className="border-b border-[#1e2d42] text-xs text-[#8899aa] bg-[#070d19]">
                        <th className="px-4 py-3 text-left">ソフトウェア名</th>
                        <th className="px-4 py-3 text-left">バージョン</th>
                        <th className="px-4 py-3 text-left">CVE ID</th>
                        <th className="px-4 py-3 text-left">CVSSスコア</th>
                        <th className="px-4 py-3 text-left">深刻度</th>
                        <th className="px-4 py-3 text-left">影響エンドポイント数</th>
                        <th className="px-4 py-3 text-left">パッチ</th>
                        <th className="px-4 py-3 text-left">リンク</th>
                      </tr>
                    </thead>
                    <tbody>
                      {filteredVulns.map((vuln, idx) => (
                        <tr
                          key={`${vuln.cve_id}-${idx}`}
                          className="border-b border-[#1e2d42]/50 hover:bg-[#161f33]/40 transition-colors"
                        >
                          <td className="px-4 py-2.5">
                            <div className="flex items-center gap-2">
                              <Package className="w-3.5 h-3.5 text-[#5a6a7a] shrink-0" />
                              <span className="text-[#e2e8f4] font-medium">{vuln.software_name}</span>
                            </div>
                          </td>
                          <td className="px-4 py-2.5 font-mono text-xs text-[#8899aa]">
                            {vuln.version}
                          </td>
                          <td className="px-4 py-2.5 font-mono text-xs text-blue-300 font-semibold">
                            {vuln.cve_id}
                          </td>
                          <td className="px-4 py-2.5">
                            <span className={`font-mono font-bold text-sm ${
                              vuln.cvss >= 9 ? 'text-red-400' :
                              vuln.cvss >= 7 ? 'text-orange-400' :
                              vuln.cvss >= 4 ? 'text-yellow-400' : 'text-green-400'
                            }`}>
                              {vuln.cvss.toFixed(1)}
                            </span>
                          </td>
                          <td className="px-4 py-2.5">
                            <span className={`text-xs px-2 py-0.5 rounded-sm border font-semibold ${SEVERITY_COLORS[vuln.severity] ?? ''}`}>
                              {SEVERITY_LABELS[vuln.severity] ?? vuln.severity}
                            </span>
                          </td>
                          <td className="px-4 py-2.5">
                            <div className="flex items-center gap-1.5 text-sm">
                              <Server className="w-3 h-3 text-[#5a6a7a]" />
                              <span className="text-[#e2e8f4] font-mono">{vuln.endpoint_count}</span>
                            </div>
                          </td>
                          <td className="px-4 py-2.5">
                            {vuln.patch_available ? (
                              <span className="text-xs px-2 py-0.5 rounded-sm border bg-green-900/30 text-green-300 border-green-700/50">
                                利用可能
                              </span>
                            ) : (
                              <span className="text-xs px-2 py-0.5 rounded-sm border bg-[#1e2d42] text-[#7d92b0] border-[#2a3a52]">
                                未提供
                              </span>
                            )}
                          </td>
                          <td className="px-4 py-2.5">
                            <a
                              href={`https://nvd.nist.gov/vuln/detail/${vuln.cve_id}`}
                              target="_blank"
                              rel="noopener noreferrer"
                              className="flex items-center gap-1 text-xs text-blue-400 hover:text-blue-300 transition-colors"
                            >
                              CVE参照
                              <ExternalLink className="w-3 h-3" />
                            </a>
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              </div>
            )}
          </>
        )}

        {/* ══════════════════════════════════════════════════════════════════
            TAB: OUTDATED SOFTWARE
        ══════════════════════════════════════════════════════════════════ */}
        {activeTab === 'outdated' && (
          <>
            <div className="bg-[#0d1220] border border-[#1e2d42] rounded-xl p-4 flex items-start gap-3">
              <div className="w-9 h-9 rounded-lg bg-orange-900/40 flex items-center justify-center shrink-0 mt-0.5">
                <Clock className="w-4 h-4 text-orange-400" />
              </div>
              <div>
                <p className="text-sm font-medium text-white">インストールから6ヶ月以上経過したソフトウェア</p>
                <p className="text-xs text-[#7d92b0] mt-1">
                  古いバージョンのソフトウェアは既知の脆弱性を含む可能性があります。定期的なアップデートを推奨します。
                </p>
              </div>
            </div>

            {allSwLoading ? (
              <div className="flex justify-center py-24">
                <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-orange-500" />
              </div>
            ) : outdatedItems.length === 0 ? (
              <div className="flex flex-col items-center justify-center py-24 bg-[#0d1220] rounded-xl border border-[#1e2d42] text-[#5a6a7a]">
                <CheckCircle className="w-12 h-12 mb-3 opacity-30 text-green-400" />
                <p className="text-sm text-[#7d92b0]">古いソフトウェアは検出されていません</p>
                <p className="text-xs text-[#5a6a7a] mt-1">データが存在しない場合は、まず全エンドポイントのインベントリを収集してください</p>
              </div>
            ) : (
              <div className="bg-[#0d1220] rounded-xl border border-[#1e2d42] overflow-hidden">
                <div className="px-5 py-3 border-b border-[#1e2d42] flex items-center justify-between">
                  <span className="text-sm text-[#8899aa]">
                    {(outdatedItems.length ?? 0).toLocaleString()}件の古いソフトウェア
                  </span>
                  <span className="text-xs text-orange-400 flex items-center gap-1.5">
                    <Clock className="w-3.5 h-3.5" />
                    インストール日から6ヶ月以上経過
                  </span>
                </div>
                <div className="overflow-x-auto">
                  <table className="w-full text-sm">
                    <thead>
                      <tr className="border-b border-[#1e2d42] text-xs text-[#8899aa] bg-[#070d19]">
                        <th className="px-4 py-3 text-left">ソフトウェア名</th>
                        <th className="px-4 py-3 text-left">バージョン</th>
                        <th className="px-4 py-3 text-left">ベンダー</th>
                        <th className="px-4 py-3 text-left">インストール日</th>
                        <th className="px-4 py-3 text-left">経過日数</th>
                        <th className="px-4 py-3 text-left">エンドポイント</th>
                      </tr>
                    </thead>
                    <tbody>
                      {outdatedItems.map((sw, idx) => {
                        const installDate = sw.install_date ? new Date(sw.install_date) : null
                        const daysOld = installDate
                          ? Math.floor((Date.now() - installDate.getTime()) / (1000 * 60 * 60 * 24))
                          : null
                        return (
                          <tr
                            key={`${sw.id}-${idx}`}
                            className="border-b border-[#1e2d42]/50 hover:bg-[#161f33]/40 transition-colors"
                          >
                            <td className="px-4 py-2.5">
                              <div className="flex items-center gap-2">
                                <Package className="w-3.5 h-3.5 text-orange-400 shrink-0" />
                                <span className="text-[#e2e8f4] font-medium">{sw.name}</span>
                              </div>
                            </td>
                            <td className="px-4 py-2.5 font-mono text-xs text-[#8899aa]">
                              {sw.version || <span className="text-[#3d4f63]">—</span>}
                            </td>
                            <td className="px-4 py-2.5 text-xs text-[#8899aa]">
                              {sw.vendor || <span className="text-[#3d4f63]">—</span>}
                            </td>
                            <td className="px-4 py-2.5 text-xs text-orange-400 whitespace-nowrap">
                              {sw.install_date || <span className="text-[#3d4f63]">—</span>}
                            </td>
                            <td className="px-4 py-2.5">
                              {daysOld !== null ? (
                                <span className={`text-xs font-mono font-semibold ${
                                  daysOld > 365 ? 'text-red-400' : 'text-orange-400'
                                }`}>
                                  {daysOld}日
                                </span>
                              ) : (
                                <span className="text-[#3d4f63]">—</span>
                              )}
                            </td>
                            <td className="px-4 py-2.5">
                              <Link
                                href={`/endpoints/${sw.agent_id}`}
                                className="flex items-center gap-1.5 text-xs text-blue-400 hover:text-blue-300 transition-colors"
                              >
                                <Server className="w-3 h-3 shrink-0" />
                                {hostnameMap[sw.agent_id] ?? sw.agent_id.slice(0, 8)}
                              </Link>
                            </td>
                          </tr>
                        )
                      })}
                    </tbody>
                  </table>
                </div>
              </div>
            )}
          </>
        )}

        {/* ══════════════════════════════════════════════════════════════════
            TAB: LICENSE TRACKING
        ══════════════════════════════════════════════════════════════════ */}
        {activeTab === 'licenses' && (
          <>
            {/* License summary cards */}
            <div className="grid grid-cols-3 gap-4">
              {(['Commercial', 'Open Source', 'Unknown'] as const).map(lic => {
                const count = licenseGroups[lic]?.length ?? 0
                return (
                  <div
                    key={lic}
                    onClick={() => setLicenseFilter(licenseFilter === lic ? '' : lic)}
                    className={`bg-[#0d1220] border rounded-xl p-4 cursor-pointer transition-all ${
                      licenseFilter === lic
                        ? 'border-[#e8002d] ring-1 ring-[#e8002d]/30'
                        : 'border-[#1e2d42] hover:border-[#2d4a6e]'
                    }`}
                  >
                    <div className="flex items-center justify-between mb-3">
                      <span className={`text-xs px-2 py-0.5 rounded-sm border font-semibold ${LICENSE_COLORS[lic]}`}>
                        {LICENSE_LABELS[lic] ?? lic}
                      </span>
                      <Tag className="w-4 h-4 text-[#5a6a7a]" />
                    </div>
                    <p className="text-3xl font-bold text-white font-mono">{count.toLocaleString()}</p>
                    <p className="text-xs text-[#7d92b0] mt-1">インストール</p>
                    {allSoftware.length > 0 && (
                      <div className="mt-2 h-1.5 bg-[#1e2d42] rounded-full overflow-hidden">
                        <div
                          className={`h-full rounded-full transition-all duration-700 ${
                            lic === 'Commercial' ? 'bg-purple-500' :
                            lic === 'Open Source' ? 'bg-green-500' : 'bg-[#5a6a7a]'
                          }`}
                          style={{ width: `${allSoftware.length > 0 ? Math.round((count / allSoftware.length) * 100) : 0}%` }}
                        />
                      </div>
                    )}
                  </div>
                )
              })}
            </div>

            {/* Filter chips */}
            {licenseFilter && (
              <div className="flex items-center gap-2">
                <span className="text-xs text-[#7d92b0]">フィルター:</span>
                <span className={`text-xs px-2 py-0.5 rounded-sm border font-semibold ${LICENSE_COLORS[licenseFilter]}`}>
                  {LICENSE_LABELS[licenseFilter] ?? licenseFilter}
                </span>
                <button
                  onClick={() => setLicenseFilter('')}
                  className="text-[#5a6a7a] hover:text-white transition-colors"
                >
                  <X className="w-3.5 h-3.5" />
                </button>
              </div>
            )}

            {allSwLoading ? (
              <div className="flex justify-center py-24">
                <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-teal-500" />
              </div>
            ) : filteredLicenseItems.length === 0 ? (
              <div className="flex flex-col items-center justify-center py-24 bg-[#0d1220] rounded-xl border border-[#1e2d42] text-[#5a6a7a]">
                <Tag className="w-12 h-12 mb-3 opacity-20" />
                <p className="text-sm">ソフトウェアデータがありません</p>
              </div>
            ) : (
              <div className="bg-[#0d1220] rounded-xl border border-[#1e2d42] overflow-hidden">
                <div className="px-5 py-3 border-b border-[#1e2d42]">
                  <span className="text-sm text-[#8899aa]">
                    {(filteredLicenseItems.length ?? 0).toLocaleString()}件
                    {licenseFilter && ` (${licenseFilter})`}
                  </span>
                </div>
                <div className="overflow-x-auto">
                  <table className="w-full text-sm">
                    <thead>
                      <tr className="border-b border-[#1e2d42] text-xs text-[#8899aa] bg-[#070d19]">
                        <th className="px-4 py-3 text-left">ソフトウェア名</th>
                        <th className="px-4 py-3 text-left">バージョン</th>
                        <th className="px-4 py-3 text-left">ベンダー</th>
                        <th className="px-4 py-3 text-left">ライセンス種別</th>
                        <th className="px-4 py-3 text-left">エンドポイント</th>
                      </tr>
                    </thead>
                    <tbody>
                      {filteredLicenseItems.slice(0, 200).map((sw, idx) => {
                        const lic = inferLicense(sw.vendor)
                        return (
                          <tr
                            key={`${sw.id}-${idx}`}
                            className="border-b border-[#1e2d42]/50 hover:bg-[#161f33]/40 transition-colors"
                          >
                            <td className="px-4 py-2.5">
                              <div className="flex items-center gap-2">
                                <Package className="w-3.5 h-3.5 text-teal-400 shrink-0" />
                                <span className="text-[#e2e8f4] font-medium">{sw.name}</span>
                              </div>
                            </td>
                            <td className="px-4 py-2.5 font-mono text-xs text-[#8899aa]">
                              {sw.version || <span className="text-[#3d4f63]">—</span>}
                            </td>
                            <td className="px-4 py-2.5 text-xs text-[#8899aa]">
                              {sw.vendor || <span className="text-[#3d4f63]">—</span>}
                            </td>
                            <td className="px-4 py-2.5">
                              <span className={`text-xs px-2 py-0.5 rounded-sm border font-semibold ${LICENSE_COLORS[lic]}`}>
                                {LICENSE_LABELS[lic] ?? lic}
                              </span>
                            </td>
                            <td className="px-4 py-2.5">
                              <Link
                                href={`/endpoints/${sw.agent_id}`}
                                className="flex items-center gap-1.5 text-xs text-blue-400 hover:text-blue-300 transition-colors"
                              >
                                <Server className="w-3 h-3 shrink-0" />
                                {hostnameMap[sw.agent_id] ?? sw.agent_id.slice(0, 8)}
                              </Link>
                            </td>
                          </tr>
                        )
                      })}
                    </tbody>
                  </table>
                  {filteredLicenseItems.length > 200 && (
                    <div className="px-4 py-2.5 border-t border-[#1e2d42] text-xs text-[#7d92b0] text-center bg-[#070d19]">
                      200 / {(filteredLicenseItems.length ?? 0).toLocaleString()} 件を表示
                    </div>
                  )}
                </div>
              </div>
            )}
          </>
        )}

        {/* ══════════════════════════════════════════════════════════════════
            TAB: CHANGES / DIFF
        ══════════════════════════════════════════════════════════════════ */}
        {activeTab === 'changes' && (
          <>
            {/* Summary */}
            <div className="grid grid-cols-3 gap-4">
              {([
                ['installed', 'インストール', (USE_MOCK ? MOCK_CHANGES : []).filter(c => c.change === 'installed').length, 'text-green-400 bg-green-900/20 border-green-700/40'],
                ['removed',   '削除',         (USE_MOCK ? MOCK_CHANGES : []).filter(c => c.change === 'removed').length,   'text-red-400 bg-red-900/20 border-red-700/40'],
                ['updated',   '更新',         (USE_MOCK ? MOCK_CHANGES : []).filter(c => c.change === 'updated').length,   'text-yellow-400 bg-yellow-900/20 border-yellow-700/40'],
              ] as const).map(([, label, count, cls]) => (
                <div key={label} className={`rounded-xl border px-5 py-4 ${cls}`}>
                  <p className="text-xs font-medium uppercase tracking-wide opacity-70">{label}</p>
                  <p className="text-3xl font-bold mt-1">{count}</p>
                  <p className="text-xs opacity-60 mt-1">過去7日間</p>
                </div>
              ))}
            </div>

            {/* Risk legend */}
            <div className="flex items-center gap-4 text-xs text-[#5a6a7a]">
              <span className="flex items-center gap-1.5"><span className="w-2 h-2 rounded-full bg-red-500" />高リスク（管理外ソフト等）</span>
              <span className="flex items-center gap-1.5"><span className="w-2 h-2 rounded-full bg-yellow-500" />中リスク</span>
              <span className="flex items-center gap-1.5"><span className="w-2 h-2 rounded-full bg-[#3d5068]" />低リスク</span>
            </div>

            {/* Changes table */}
            <div className="bg-[#0d1220] rounded-xl border border-[#1e2d42] overflow-hidden">
              <table className="w-full text-sm">
                <thead>
                  <tr className="border-b border-[#1e2d42] bg-[#070d19]/60">
                    <th className="text-left px-4 py-3 text-[#5a6a7a] text-xs font-medium uppercase tracking-wide">変更</th>
                    <th className="text-left px-4 py-3 text-[#5a6a7a] text-xs font-medium uppercase tracking-wide">ソフトウェア</th>
                    <th className="text-left px-4 py-3 text-[#5a6a7a] text-xs font-medium uppercase tracking-wide">バージョン</th>
                    <th className="text-left px-4 py-3 text-[#5a6a7a] text-xs font-medium uppercase tracking-wide">エンドポイント</th>
                    <th className="text-left px-4 py-3 text-[#5a6a7a] text-xs font-medium uppercase tracking-wide">検出日時</th>
                    <th className="text-left px-4 py-3 text-[#5a6a7a] text-xs font-medium uppercase tracking-wide">リスク</th>
                  </tr>
                </thead>
                <tbody>
                  {(USE_MOCK ? MOCK_CHANGES : []).map((ch, i) => (
                    <tr key={i} className="border-b border-[#1e2d42]/50 last:border-0 hover:bg-[#1e2d42]/20 transition-colors">
                      <td className="px-4 py-3">
                        {ch.change === 'installed' && (
                          <span className="flex items-center gap-1 text-xs font-semibold text-green-400">
                            <Plus className="w-3.5 h-3.5" /> インストール
                          </span>
                        )}
                        {ch.change === 'removed' && (
                          <span className="flex items-center gap-1 text-xs font-semibold text-red-400">
                            <Minus className="w-3.5 h-3.5" /> 削除
                          </span>
                        )}
                        {ch.change === 'updated' && (
                          <span className="flex items-center gap-1 text-xs font-semibold text-yellow-400">
                            <ArrowUp className="w-3.5 h-3.5" /> 更新
                          </span>
                        )}
                      </td>
                      <td className="px-4 py-3 font-medium text-white">{ch.name}</td>
                      <td className="px-4 py-3 font-mono text-xs text-[#7d92b0]">
                        {ch.change === 'updated'
                          ? <><span className="line-through text-[#3d5068]">{ch.old_version}</span> → <span className="text-yellow-300">{ch.new_version}</span></>
                          : ch.change === 'installed'
                          ? <span className="text-green-300">{ch.new_version}</span>
                          : <span className="text-red-300">{ch.old_version}</span>
                        }
                      </td>
                      <td className="px-4 py-3 text-xs text-[#7d92b0] font-mono">{ch.hostname}</td>
                      <td className="px-4 py-3 text-xs text-[#5a6a7a]">
                        {new Date(ch.detected_at).toLocaleString('ja-JP', { month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit' })}
                      </td>
                      <td className="px-4 py-3">
                        <span className={`w-2 h-2 rounded-full inline-block ${
                          ch.risk === 'high' ? 'bg-red-500' : ch.risk === 'medium' ? 'bg-yellow-500' : 'bg-[#3d5068]'
                        }`} />
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </>
        )}

      </div>
    </div>
  )
}

// ---------------------------------------------------------------------------
// Export (Suspense boundary for useSearchParams)
// ---------------------------------------------------------------------------
export default function SoftwarePage() {
  return (
    <Suspense
      fallback={
        <div className="flex justify-center py-24">
          <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-teal-500" />
        </div>
      }
    >
      <SoftwarePageInner />
    </Suspense>
  )
}

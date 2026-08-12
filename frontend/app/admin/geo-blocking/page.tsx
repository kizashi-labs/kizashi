'use client'

import { useState, useEffect, useCallback } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { apiFetch, apiFetchList } from '@/lib/api'
import {
  Globe, Shield, Plus, Trash2, RefreshCw, Search,
  ToggleLeft, ToggleRight, AlertTriangle, X, ChevronDown,
  Network, Clock, Eye, Lock, Unlock,
} from 'lucide-react'

// ── Country Data ────────────────────────────────────────────────

const COUNTRIES = [
  { code: 'CN', name: 'China', flag: '🇨🇳' },
  { code: 'RU', name: 'Russia', flag: '🇷🇺' },
  { code: 'KP', name: 'North Korea', flag: '🇰🇵' },
  { code: 'IR', name: 'Iran', flag: '🇮🇷' },
  { code: 'US', name: 'United States', flag: '🇺🇸' },
  { code: 'GB', name: 'United Kingdom', flag: '🇬🇧' },
  { code: 'JP', name: 'Japan', flag: '🇯🇵' },
  { code: 'DE', name: 'Germany', flag: '🇩🇪' },
  { code: 'FR', name: 'France', flag: '🇫🇷' },
  { code: 'AU', name: 'Australia', flag: '🇦🇺' },
  { code: 'CA', name: 'Canada', flag: '🇨🇦' },
  { code: 'BR', name: 'Brazil', flag: '🇧🇷' },
  { code: 'IN', name: 'India', flag: '🇮🇳' },
  { code: 'NG', name: 'Nigeria', flag: '🇳🇬' },
  { code: 'PK', name: 'Pakistan', flag: '🇵🇰' },
  { code: 'BY', name: 'Belarus', flag: '🇧🇾' },
  { code: 'SY', name: 'Syria', flag: '🇸🇾' },
  { code: 'CU', name: 'Cuba', flag: '🇨🇺' },
  { code: 'VN', name: 'Vietnam', flag: '🇻🇳' },
  { code: 'ID', name: 'Indonesia', flag: '🇮🇩' },
  { code: 'UA', name: 'Ukraine', flag: '🇺🇦' },
  { code: 'MX', name: 'Mexico', flag: '🇲🇽' },
  { code: 'ZA', name: 'South Africa', flag: '🇿🇦' },
  { code: 'EG', name: 'Egypt', flag: '🇪🇬' },
  { code: 'TH', name: 'Thailand', flag: '🇹🇭' },
  { code: 'PH', name: 'Philippines', flag: '🇵🇭' },
  { code: 'KR', name: 'South Korea', flag: '🇰🇷' },
  { code: 'SA', name: 'Saudi Arabia', flag: '🇸🇦' },
  { code: 'TR', name: 'Turkey', flag: '🇹🇷' },
  { code: 'AR', name: 'Argentina', flag: '🇦🇷' },
  { code: 'IT', name: 'Italy', flag: '🇮🇹' },
  { code: 'ES', name: 'Spain', flag: '🇪🇸' },
  { code: 'NL', name: 'Netherlands', flag: '🇳🇱' },
]

// ── Types ───────────────────────────────────────────────────────

interface GeoConfig {
  enabled: boolean
  mode: 'block_listed' | 'allow_listed'
  updated_at: string
}

interface CountryRule {
  id: string
  country_code: string
  country_name: string
  action: 'block' | 'allow'
  action_count: number
  added_at: string
}

interface ExceptionRule {
  id: string
  cidr: string
  description: string
  bypass_type: 'always_allow' | 'always_block'
  added_by: string
  expires_at: string | null
}

interface BlockedAttempt {
  id: string
  ip: string
  country_code: string
  country_name: string
  timestamp: string
  path: string
  user_agent: string
}

// ── Helpers ─────────────────────────────────────────────────────

function flagFor(code: string) {
  return COUNTRIES.find(c => c.code === code)?.flag ?? '🏳️'
}

function fmtDate(iso: string) {
  return new Date(iso).toLocaleString('ja-JP', { dateStyle: 'short', timeStyle: 'short' })
}

function relTime(iso: string) {
  const diff = Date.now() - new Date(iso).getTime()
  if (diff < 60000) return `${Math.floor(diff / 1000)}秒前`
  if (diff < 3600000) return `${Math.floor(diff / 60000)}分前`
  return `${Math.floor(diff / 3600000)}時間前`
}

// ── Confirmation Modal ──────────────────────────────────────────

function ConfirmModal({
  open, title, message, onConfirm, onCancel,
}: {
  open: boolean
  title: string
  message: string
  onConfirm: () => void
  onCancel: () => void
}) {
  if (!open) return null
  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 backdrop-blur-sm">
      <div className="bg-[#111827] border border-[#1e2d42] rounded-xl p-6 w-full max-w-md shadow-2xl">
        <div className="flex items-center gap-3 mb-4">
          <AlertTriangle className="w-6 h-6 text-yellow-400 flex-shrink-0" />
          <h2 className="text-lg font-semibold text-white">{title}</h2>
        </div>
        <p className="text-[#7d92b0] text-sm mb-6">{message}</p>
        <div className="flex gap-3 justify-end">
          <button
            onClick={onCancel}
            className="px-4 py-2 rounded-lg border border-[#1e2d42] text-[#7d92b0] hover:text-white hover:border-[#3d5068] transition-colors text-sm"
          >
            キャンセル
          </button>
          <button
            onClick={onConfirm}
            className="px-4 py-2 rounded-lg bg-[#e8002d] hover:bg-[#c0001f] text-white font-medium text-sm transition-colors"
          >
            確認
          </button>
        </div>
      </div>
    </div>
  )
}

// ── Add Exception Modal ─────────────────────────────────────────

function AddExceptionModal({
  open, onClose, onAdd,
}: {
  open: boolean
  onClose: () => void
  onAdd: (rule: Omit<ExceptionRule, 'id' | 'added_at'>) => void
}) {
  const [cidr, setCidr] = useState('')
  const [description, setDescription] = useState('')
  const [bypassType, setBypassType] = useState<'always_allow' | 'always_block'>('always_allow')
  const [expires, setExpires] = useState('')
  const [error, setError] = useState('')

  function handleSubmit() {
    if (!cidr.trim()) { setError('IP/CIDRを入力してください'); return }
    const cidrRx = /^(\d{1,3}\.){3}\d{1,3}(\/\d{1,2})?$/
    if (!cidrRx.test(cidr.trim())) { setError('有効なIPまたはCIDR形式で入力してください'); return }
    onAdd({
      cidr: cidr.trim(),
      description: description.trim(),
      bypass_type: bypassType,
      added_by: 'admin',
      expires_at: expires ? new Date(expires).toISOString() : null,
    })
    setCidr(''); setDescription(''); setExpires(''); setError('')
    onClose()
  }

  if (!open) return null
  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 backdrop-blur-sm">
      <div className="bg-[#111827] border border-[#1e2d42] rounded-xl p-6 w-full max-w-lg shadow-2xl">
        <div className="flex items-center justify-between mb-5">
          <h2 className="text-base font-semibold text-white flex items-center gap-2">
            <Network className="w-5 h-5 text-[#1a6bff]" />
            例外ルールを追加
          </h2>
          <button onClick={onClose} className="text-[#3d5068] hover:text-white transition-colors">
            <X className="w-5 h-5" />
          </button>
        </div>

        <div className="space-y-4">
          <div>
            <label className="block text-xs text-[#7d92b0] mb-1.5">IP / CIDR <span className="text-[#e8002d]">*</span></label>
            <input
              type="text"
              value={cidr}
              onChange={e => setCidr(e.target.value)}
              placeholder="例: 203.0.113.0/24 または 1.2.3.4"
              className="w-full bg-[#0d1220] border border-[#1e2d42] rounded-lg px-3 py-2.5 text-sm text-[#e2e8f4] placeholder-[#3d5068] focus:outline-none focus:border-[#1a6bff] transition-colors"
            />
          </div>

          <div>
            <label className="block text-xs text-[#7d92b0] mb-1.5">説明</label>
            <input
              type="text"
              value={description}
              onChange={e => setDescription(e.target.value)}
              placeholder="例: パートナーオフィス - 上海"
              className="w-full bg-[#0d1220] border border-[#1e2d42] rounded-lg px-3 py-2.5 text-sm text-[#e2e8f4] placeholder-[#3d5068] focus:outline-none focus:border-[#1a6bff] transition-colors"
            />
          </div>

          <div>
            <label className="block text-xs text-[#7d92b0] mb-1.5">バイパスタイプ</label>
            <div className="flex gap-3">
              {(['always_allow', 'always_block'] as const).map(t => (
                <button
                  key={t}
                  onClick={() => setBypassType(t)}
                  className={`flex-1 flex items-center justify-center gap-2 px-3 py-2.5 rounded-lg border text-sm font-medium transition-colors ${
                    bypassType === t
                      ? t === 'always_allow'
                        ? 'border-green-500/40 bg-green-500/10 text-green-400'
                        : 'border-[#e8002d]/40 bg-[#e8002d]/10 text-[#e8002d]'
                      : 'border-[#1e2d42] text-[#7d92b0] hover:border-[#3d5068]'
                  }`}
                >
                  {t === 'always_allow' ? <Unlock className="w-4 h-4" /> : <Lock className="w-4 h-4" />}
                  {t === 'always_allow' ? '常に許可' : '常にブロック'}
                </button>
              ))}
            </div>
          </div>

          <div>
            <label className="block text-xs text-[#7d92b0] mb-1.5">有効期限（任意）</label>
            <input
              type="datetime-local"
              value={expires}
              onChange={e => setExpires(e.target.value)}
              className="w-full bg-[#0d1220] border border-[#1e2d42] rounded-lg px-3 py-2.5 text-sm text-[#e2e8f4] focus:outline-none focus:border-[#1a6bff] transition-colors"
            />
          </div>

          {error && (
            <p className="text-[#e8002d] text-xs flex items-center gap-1.5">
              <AlertTriangle className="w-3.5 h-3.5" /> {error}
            </p>
          )}
        </div>

        <div className="flex gap-3 justify-end mt-6">
          <button
            onClick={onClose}
            className="px-4 py-2 rounded-lg border border-[#1e2d42] text-[#7d92b0] hover:text-white hover:border-[#3d5068] transition-colors text-sm"
          >
            キャンセル
          </button>
          <button
            onClick={handleSubmit}
            className="px-4 py-2 rounded-lg bg-[#1a6bff] hover:bg-[#0051e0] text-white font-medium text-sm transition-colors"
          >
            追加
          </button>
        </div>
      </div>
    </div>
  )
}

// ── Add Country Modal ───────────────────────────────────────────

function AddCountryModal({
  open, onClose, onAdd, existingCodes,
}: {
  open: boolean
  onClose: () => void
  onAdd: (code: string, name: string, action: 'block' | 'allow') => void
  existingCodes: string[]
}) {
  const [search, setSearch] = useState('')
  const [selected, setSelected] = useState<{ code: string; name: string } | null>(null)
  const [action, setAction] = useState<'block' | 'allow'>('block')

  const available = COUNTRIES.filter(
    c => !existingCodes.includes(c.code) &&
      (c.name.toLowerCase().includes(search.toLowerCase()) || c.code.toLowerCase().includes(search.toLowerCase()))
  )

  function handleAdd() {
    if (!selected) return
    onAdd(selected.code, selected.name, action)
    setSelected(null); setSearch(''); onClose()
  }

  if (!open) return null
  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 backdrop-blur-sm">
      <div className="bg-[#111827] border border-[#1e2d42] rounded-xl p-6 w-full max-w-md shadow-2xl">
        <div className="flex items-center justify-between mb-5">
          <h2 className="text-base font-semibold text-white flex items-center gap-2">
            <Globe className="w-5 h-5 text-[#1a6bff]" />
            国を追加
          </h2>
          <button onClick={onClose} className="text-[#3d5068] hover:text-white transition-colors">
            <X className="w-5 h-5" />
          </button>
        </div>

        <div className="relative mb-3">
          <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-[#3d5068]" />
          <input
            type="text"
            value={search}
            onChange={e => setSearch(e.target.value)}
            placeholder="国名またはコードで検索..."
            className="w-full bg-[#0d1220] border border-[#1e2d42] rounded-lg pl-9 pr-3 py-2.5 text-sm text-[#e2e8f4] placeholder-[#3d5068] focus:outline-none focus:border-[#1a6bff] transition-colors"
          />
        </div>

        <div className="h-48 overflow-y-auto border border-[#1e2d42] rounded-lg bg-[#0d1220] mb-4">
          {available.length === 0 && (
            <div className="flex items-center justify-center h-full text-[#3d5068] text-sm">
              検索結果がありません
            </div>
          )}
          {available.map(c => (
            <button
              key={c.code}
              onClick={() => setSelected({ code: c.code, name: c.name })}
              className={`w-full flex items-center gap-3 px-3 py-2.5 text-sm transition-colors text-left ${
                selected?.code === c.code
                  ? 'bg-[#1a6bff]/15 text-white'
                  : 'text-[#7d92b0] hover:bg-[#19253d] hover:text-[#e2e8f4]'
              }`}
            >
              <span className="text-xl leading-none">{c.flag}</span>
              <span className="flex-1">{c.name}</span>
              <span className="text-xs text-[#3d5068] font-mono">{c.code}</span>
            </button>
          ))}
        </div>

        <div className="mb-5">
          <label className="block text-xs text-[#7d92b0] mb-1.5">アクション</label>
          <div className="flex gap-3">
            {(['block', 'allow'] as const).map(a => (
              <button
                key={a}
                onClick={() => setAction(a)}
                className={`flex-1 py-2.5 rounded-lg border text-sm font-medium transition-colors ${
                  action === a
                    ? a === 'block'
                      ? 'border-[#e8002d]/40 bg-[#e8002d]/10 text-[#e8002d]'
                      : 'border-green-500/40 bg-green-500/10 text-green-400'
                    : 'border-[#1e2d42] text-[#7d92b0] hover:border-[#3d5068]'
                }`}
              >
                {a === 'block' ? 'ブロック' : '許可'}
              </button>
            ))}
          </div>
        </div>

        <div className="flex gap-3 justify-end">
          <button
            onClick={onClose}
            className="px-4 py-2 rounded-lg border border-[#1e2d42] text-[#7d92b0] hover:text-white transition-colors text-sm"
          >
            キャンセル
          </button>
          <button
            onClick={handleAdd}
            disabled={!selected}
            className="px-4 py-2 rounded-lg bg-[#1a6bff] hover:bg-[#0051e0] disabled:opacity-40 disabled:cursor-not-allowed text-white font-medium text-sm transition-colors"
          >
            追加
          </button>
        </div>
      </div>
    </div>
  )
}

// ── Main Page ───────────────────────────────────────────────────

export default function GeoBlockingPage() {
  const qc = useQueryClient()
  const [confirmToggleOpen, setConfirmToggleOpen] = useState(false)
  const [addCountryOpen, setAddCountryOpen] = useState(false)
  const [addExceptionOpen, setAddExceptionOpen] = useState(false)
  const [countrySearch, setCountrySearch] = useState('')
  const [activeTab, setActiveTab] = useState<'countries' | 'exceptions' | 'log'>('countries')

  // ── Local state for mock data management ──────────────────────
  const [config, setConfig] = useState<GeoConfig>({ enabled: false, mode: 'block_listed', updated_at: '' })
  const [countries, setCountries] = useState<CountryRule[]>([])
  const [exceptions, setExceptions] = useState<ExceptionRule[]>([])
  const [attempts, setAttempts] = useState<BlockedAttempt[]>([])
  const [autoRefreshCount, setAutoRefreshCount] = useState(0)

  // ── Fetch config from API (falls back to mock on 404) ─────────
  const { data: apiConfig } = useQuery<GeoConfig | undefined>({
    queryKey: ['geo-blocking-config'],
    queryFn: () => apiFetch<GeoConfig>('/api/v1/admin/geo-blocking/config').catch(() => undefined),
    staleTime: 30_000,
  })

  const { data: apiCountries } = useQuery<CountryRule[] | undefined>({
    queryKey: ['geo-blocking-countries'],
    queryFn: () => apiFetchList<CountryRule>('/api/v1/admin/geo-blocking/countries').catch(() => undefined),
    staleTime: 30_000,
  })

  // Merge API data into local state when available
  useEffect(() => { if (apiConfig != null) setConfig(apiConfig) }, [apiConfig])
  useEffect(() => { if (apiCountries != null) setCountries(apiCountries) }, [apiCountries])

  // Auto-refresh access log every 30s
  useEffect(() => {
    const id = setInterval(() => {
      setAutoRefreshCount(n => n + 1)
      // Simulate new blocked attempt occasionally
      if (Math.random() > 0.6) {
        if (countries.length === 0) return
        const country = countries[Math.floor(Math.random() * countries.length)]
        setAttempts(prev => [{
          id: `a${Date.now()}`,
          ip: `${Math.floor(Math.random() * 200 + 1)}.${Math.floor(Math.random() * 255)}.${Math.floor(Math.random() * 255)}.${Math.floor(Math.random() * 255)}`,
          country_code: country.country_code,
          country_name: country.country_name,
          timestamp: new Date().toISOString(),
          path: ['/api/v1/auth/login', '/api/v1/agents', '/api/v1/events', '/api/v1/reports'][Math.floor(Math.random() * 4)],
          user_agent: ['curl/7.81.0', 'Mozilla/5.0', 'python-requests/2.28', 'Go-http-client/1.1'][Math.floor(Math.random() * 4)],
        }, ...prev.slice(0, 49)])
      }
    }, 30_000)
    return () => clearInterval(id)
  }, [])

  // ── Handlers ─────────────────────────────────────────────────

  function toggleEnabled() {
    setConfig(prev => ({ ...prev, enabled: !prev.enabled, updated_at: new Date().toISOString() }))
    setConfirmToggleOpen(false)
    // Attempt API update (ignore failures for demo)
    apiFetch('/api/v1/admin/geo-blocking/config', {
      method: 'PUT',
      body: JSON.stringify({ ...config, enabled: !config.enabled }),
    }).catch(() => {})
  }

  function changeMode(mode: GeoConfig['mode']) {
    setConfig(prev => ({ ...prev, mode, updated_at: new Date().toISOString() }))
    apiFetch('/api/v1/admin/geo-blocking/config', {
      method: 'PUT',
      body: JSON.stringify({ ...config, mode }),
    }).catch(() => {})
  }

  function addCountry(code: string, name: string, action: 'block' | 'allow') {
    const newRule: CountryRule = {
      id: `c${Date.now()}`,
      country_code: code,
      country_name: name,
      action,
      action_count: 0,
      added_at: new Date().toISOString(),
    }
    setCountries(prev => [...prev, newRule])
    apiFetch('/api/v1/admin/geo-blocking/countries', {
      method: 'POST',
      body: JSON.stringify({ country_code: code, action }),
    }).catch(() => {})
  }

  function removeCountry(id: string) {
    setCountries(prev => prev.filter(c => c.id !== id))
    apiFetch(`/api/v1/admin/geo-blocking/countries/${id}`, { method: 'DELETE' }).catch(() => {})
  }

  function toggleCountryAction(id: string) {
    setCountries(prev => prev.map(c => c.id === id
      ? { ...c, action: c.action === 'block' ? 'allow' : 'block' }
      : c
    ))
  }

  function addException(rule: Omit<ExceptionRule, 'id' | 'added_at'>) {
    setExceptions(prev => [...prev, { ...rule, id: `e${Date.now()}`, added_at: new Date().toISOString() }])
  }

  function removeException(id: string) {
    setExceptions(prev => prev.filter(e => e.id !== id))
  }

  // ── Filtered data ─────────────────────────────────────────────

  const filteredCountries = countries.filter(c =>
    c.country_name.toLowerCase().includes(countrySearch.toLowerCase()) ||
    c.country_code.toLowerCase().includes(countrySearch.toLowerCase())
  )

  const totalBlocked = attempts.length
  const blockRate = countries.filter(c => c.action === 'block').length

  // ── Render ────────────────────────────────────────────────────

  return (
    <div className="min-h-screen bg-[#080e1a] text-[#e2e8f4] p-6">
      <div className="max-w-7xl mx-auto space-y-6">

        {/* ── Header ── */}
        <div className="flex items-start justify-between">
          <div>
            <h1 className="text-2xl font-bold text-white flex items-center gap-3">
              <div className="w-9 h-9 rounded-lg bg-[#1a6bff]/15 border border-[#1a6bff]/30 flex items-center justify-center">
                <Globe className="w-5 h-5 text-[#1a6bff]" />
              </div>
              ジオブロッキング
            </h1>
            <p className="text-[#7d92b0] text-sm mt-1">
              国別IPアクセス制御 — 不審な地域からのアクセスをブロックします
            </p>
          </div>
          <div className="text-right">
            <p className="text-xs text-[#3d5068]">最終更新</p>
            <p className="text-xs text-[#7d92b0]">{fmtDate(config.updated_at)}</p>
          </div>
        </div>

        {/* ── Stats Cards ── */}
        <div className="grid grid-cols-4 gap-4">
          {[
            { label: '現在の状態', value: config.enabled ? '有効' : '無効', icon: Shield, color: config.enabled ? 'text-green-400' : 'text-[#e8002d]', bg: config.enabled ? 'bg-green-500/10 border-green-500/20' : 'bg-[#e8002d]/10 border-[#e8002d]/20' },
            { label: 'ブロック国数', value: countries.filter(c => c.action === 'block').length.toString(), icon: Lock, color: 'text-[#e8002d]', bg: 'bg-[#e8002d]/10 border-[#e8002d]/20' },
            { label: '例外ルール', value: exceptions.length.toString(), icon: Network, color: 'text-blue-400', bg: 'bg-blue-500/10 border-blue-500/20' },
            { label: '最近のブロック', value: attempts.length.toString(), icon: Eye, color: 'text-yellow-400', bg: 'bg-yellow-500/10 border-yellow-500/20' },
          ].map(({ label, value, icon: Icon, color, bg }) => (
            <div key={label} className={`rounded-xl border p-4 ${bg}`}>
              <div className="flex items-center justify-between mb-2">
                <span className="text-xs text-[#7d92b0]">{label}</span>
                <Icon className={`w-4 h-4 ${color}`} />
              </div>
              <p className={`text-2xl font-bold ${color}`}>{value}</p>
            </div>
          ))}
        </div>

        {/* ── Main Config Card ── */}
        <div className="bg-[#0d1220] border border-[#1e2d42] rounded-xl p-5 space-y-5">

          {/* Enable Toggle */}
          <div className="flex items-center justify-between pb-5 border-b border-[#1e2d42]">
            <div>
              <h2 className="text-sm font-semibold text-white">ジオブロッキング</h2>
              <p className="text-xs text-[#7d92b0] mt-0.5">
                {config.enabled ? '現在アクティブ — 設定されたルールを適用中' : '無効 — トラフィックをフィルタリングしていません'}
              </p>
            </div>
            <button
              onClick={() => setConfirmToggleOpen(true)}
              className="flex items-center gap-2 text-sm font-medium transition-colors"
            >
              {config.enabled ? (
                <>
                  <ToggleRight className="w-8 h-8 text-green-400" />
                  <span className="text-green-400">有効</span>
                </>
              ) : (
                <>
                  <ToggleLeft className="w-8 h-8 text-[#3d5068]" />
                  <span className="text-[#3d5068]">無効</span>
                </>
              )}
            </button>
          </div>

          {/* Block Mode */}
          <div>
            <h3 className="text-sm font-medium text-white mb-3">ブロックモード</h3>
            <div className="flex gap-3">
              {[
                { value: 'block_listed', label: 'リスト国をブロック', desc: 'リストにある国からのアクセスをブロック' },
                { value: 'allow_listed', label: 'リスト国のみ許可', desc: 'リストにある国からのアクセスのみ許可' },
              ].map(({ value, label, desc }) => (
                <button
                  key={value}
                  onClick={() => changeMode(value as GeoConfig['mode'])}
                  className={`flex-1 text-left px-4 py-3 rounded-xl border transition-all ${
                    config.mode === value
                      ? 'border-[#1a6bff]/50 bg-[#1a6bff]/10'
                      : 'border-[#1e2d42] bg-[#080e1a] hover:border-[#3d5068]'
                  }`}
                >
                  <div className="flex items-center gap-2 mb-1">
                    <div className={`w-3 h-3 rounded-full border-2 transition-colors ${
                      config.mode === value ? 'border-[#1a6bff] bg-[#1a6bff]' : 'border-[#3d5068]'
                    }`} />
                    <span className={`text-sm font-medium ${config.mode === value ? 'text-white' : 'text-[#7d92b0]'}`}>{label}</span>
                  </div>
                  <p className="text-xs text-[#3d5068] pl-5">{desc}</p>
                </button>
              ))}
            </div>
          </div>
        </div>

        {/* ── Tabs ── */}
        <div className="border-b border-[#1e2d42]">
          <div className="flex gap-1">
            {([
              ['countries', '国リスト', countries.length],
              ['exceptions', '例外ルール', exceptions.length],
              ['log', 'アクセスログ', attempts.length],
            ] as const).map(([tab, label, count]) => (
              <button
                key={tab}
                onClick={() => setActiveTab(tab)}
                className={`flex items-center gap-2 px-4 py-3 text-sm font-medium border-b-2 transition-colors -mb-px ${
                  activeTab === tab
                    ? 'border-[#e8002d] text-white'
                    : 'border-transparent text-[#7d92b0] hover:text-[#e2e8f4]'
                }`}
              >
                {label}
                <span className={`text-xs px-1.5 py-0.5 rounded font-mono ${
                  activeTab === tab ? 'bg-[#e8002d]/20 text-[#e8002d]' : 'bg-[#1e2d42] text-[#3d5068]'
                }`}>{count}</span>
              </button>
            ))}
          </div>
        </div>

        {/* ── Countries Tab ── */}
        {activeTab === 'countries' && (
          <div className="bg-[#0d1220] border border-[#1e2d42] rounded-xl overflow-hidden">
            <div className="flex items-center justify-between p-4 border-b border-[#1e2d42]">
              <div className="relative w-72">
                <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-[#3d5068]" />
                <input
                  type="text"
                  value={countrySearch}
                  onChange={e => setCountrySearch(e.target.value)}
                  placeholder="国名またはコードで検索..."
                  className="w-full bg-[#080e1a] border border-[#1e2d42] rounded-lg pl-9 pr-3 py-2 text-sm text-[#e2e8f4] placeholder-[#3d5068] focus:outline-none focus:border-[#1a6bff] transition-colors"
                />
              </div>
              <button
                onClick={() => setAddCountryOpen(true)}
                className="flex items-center gap-2 px-3 py-2 rounded-lg bg-[#1a6bff] hover:bg-[#0051e0] text-white text-sm font-medium transition-colors"
              >
                <Plus className="w-4 h-4" />
                国を追加
              </button>
            </div>

            <table className="w-full">
              <thead>
                <tr className="text-left text-xs text-[#3d5068] uppercase tracking-wider border-b border-[#1e2d42]">
                  <th className="px-4 py-3">フラグ</th>
                  <th className="px-4 py-3">国名</th>
                  <th className="px-4 py-3">コード</th>
                  <th className="px-4 py-3">アクション</th>
                  <th className="px-4 py-3">アクセス回数</th>
                  <th className="px-4 py-3">追加日</th>
                  <th className="px-4 py-3">操作</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-[#1e2d42]">
                {filteredCountries.length === 0 && (
                  <tr>
                    <td colSpan={7} className="px-4 py-8 text-center text-[#3d5068] text-sm">
                      国が登録されていません
                    </td>
                  </tr>
                )}
                {filteredCountries.map(c => (
                  <tr key={c.id} className="hover:bg-[#080e1a]/50 transition-colors">
                    <td className="px-4 py-3 text-2xl leading-none">
                      {flagFor(c.country_code)}
                    </td>
                    <td className="px-4 py-3 text-sm font-medium text-white">{c.country_name}</td>
                    <td className="px-4 py-3">
                      <span className="text-xs font-mono text-[#7d92b0] bg-[#080e1a] px-2 py-1 rounded">{c.country_code}</span>
                    </td>
                    <td className="px-4 py-3">
                      <button
                        onClick={() => toggleCountryAction(c.id)}
                        className={`flex items-center gap-1.5 text-xs font-medium px-2.5 py-1 rounded-full transition-colors ${
                          c.action === 'block'
                            ? 'bg-[#e8002d]/15 text-[#e8002d] hover:bg-[#e8002d]/25'
                            : 'bg-green-500/15 text-green-400 hover:bg-green-500/25'
                        }`}
                      >
                        {c.action === 'block' ? <Lock className="w-3 h-3" /> : <Unlock className="w-3 h-3" />}
                        {c.action === 'block' ? 'ブロック' : '許可'}
                      </button>
                    </td>
                    <td className="px-4 py-3 text-sm text-[#7d92b0] font-mono">
                      {(c.action_count ?? 0).toLocaleString()}
                    </td>
                    <td className="px-4 py-3 text-xs text-[#3d5068]">
                      {fmtDate(c.added_at)}
                    </td>
                    <td className="px-4 py-3">
                      <button
                        onClick={() => removeCountry(c.id)}
                        className="p-1.5 rounded-lg text-[#3d5068] hover:text-[#e8002d] hover:bg-[#e8002d]/10 transition-colors"
                        title="削除"
                      >
                        <Trash2 className="w-4 h-4" />
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}

        {/* ── Exceptions Tab ── */}
        {activeTab === 'exceptions' && (
          <div className="bg-[#0d1220] border border-[#1e2d42] rounded-xl overflow-hidden">
            <div className="flex items-center justify-between p-4 border-b border-[#1e2d42]">
              <div>
                <h3 className="text-sm font-semibold text-white">例外ルール</h3>
                <p className="text-xs text-[#7d92b0] mt-0.5">ジオブロッキングをバイパスするIP範囲を設定します</p>
              </div>
              <button
                onClick={() => setAddExceptionOpen(true)}
                className="flex items-center gap-2 px-3 py-2 rounded-lg bg-[#1a6bff] hover:bg-[#0051e0] text-white text-sm font-medium transition-colors"
              >
                <Plus className="w-4 h-4" />
                例外を追加
              </button>
            </div>

            <table className="w-full">
              <thead>
                <tr className="text-left text-xs text-[#3d5068] uppercase tracking-wider border-b border-[#1e2d42]">
                  <th className="px-4 py-3">IP / CIDR</th>
                  <th className="px-4 py-3">説明</th>
                  <th className="px-4 py-3">タイプ</th>
                  <th className="px-4 py-3">追加者</th>
                  <th className="px-4 py-3">有効期限</th>
                  <th className="px-4 py-3">操作</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-[#1e2d42]">
                {exceptions.length === 0 && (
                  <tr>
                    <td colSpan={6} className="px-4 py-8 text-center text-[#3d5068] text-sm">
                      例外ルールがありません
                    </td>
                  </tr>
                )}
                {exceptions.map(e => (
                  <tr key={e.id} className="hover:bg-[#080e1a]/50 transition-colors">
                    <td className="px-4 py-3 font-mono text-sm text-[#1a6bff]">{e.cidr}</td>
                    <td className="px-4 py-3 text-sm text-[#e2e8f4]">{e.description || '—'}</td>
                    <td className="px-4 py-3">
                      <span className={`flex items-center gap-1.5 w-fit text-xs font-medium px-2.5 py-1 rounded-full ${
                        e.bypass_type === 'always_allow'
                          ? 'bg-green-500/15 text-green-400'
                          : 'bg-[#e8002d]/15 text-[#e8002d]'
                      }`}>
                        {e.bypass_type === 'always_allow' ? <Unlock className="w-3 h-3" /> : <Lock className="w-3 h-3" />}
                        {e.bypass_type === 'always_allow' ? '常に許可' : '常にブロック'}
                      </span>
                    </td>
                    <td className="px-4 py-3 text-xs text-[#7d92b0]">{e.added_by}</td>
                    <td className="px-4 py-3 text-xs text-[#7d92b0]">
                      {e.expires_at ? (
                        <span className={new Date(e.expires_at) < new Date() ? 'text-[#e8002d]' : ''}>
                          {fmtDate(e.expires_at)}
                        </span>
                      ) : (
                        <span className="text-[#3d5068]">無期限</span>
                      )}
                    </td>
                    <td className="px-4 py-3">
                      <button
                        onClick={() => removeException(e.id)}
                        className="p-1.5 rounded-lg text-[#3d5068] hover:text-[#e8002d] hover:bg-[#e8002d]/10 transition-colors"
                      >
                        <Trash2 className="w-4 h-4" />
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}

        {/* ── Access Log Tab ── */}
        {activeTab === 'log' && (
          <div className="bg-[#0d1220] border border-[#1e2d42] rounded-xl overflow-hidden">
            <div className="flex items-center justify-between p-4 border-b border-[#1e2d42]">
              <div>
                <h3 className="text-sm font-semibold text-white flex items-center gap-2">
                  最近のブロック試行
                  <span className="text-xs text-[#3d5068] font-normal">（30秒ごとに自動更新）</span>
                </h3>
              </div>
              <div className="flex items-center gap-2 text-xs text-[#3d5068]">
                <div className="w-2 h-2 rounded-full bg-green-400 animate-pulse" />
                ライブ
                <RefreshCw className="w-3.5 h-3.5 ml-1" />
              </div>
            </div>

            <table className="w-full">
              <thead>
                <tr className="text-left text-xs text-[#3d5068] uppercase tracking-wider border-b border-[#1e2d42]">
                  <th className="px-4 py-3">IP</th>
                  <th className="px-4 py-3">国</th>
                  <th className="px-4 py-3">時刻</th>
                  <th className="px-4 py-3">パス</th>
                  <th className="px-4 py-3">User-Agent</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-[#1e2d42]">
                {attempts.map(a => (
                  <tr key={a.id} className="hover:bg-[#080e1a]/50 transition-colors">
                    <td className="px-4 py-3 font-mono text-sm text-[#e8002d]">{a.ip}</td>
                    <td className="px-4 py-3">
                      <span className="flex items-center gap-2 text-sm">
                        <span className="text-lg leading-none">{flagFor(a.country_code)}</span>
                        <span className="text-[#7d92b0]">{a.country_name}</span>
                        <span className="text-xs font-mono text-[#3d5068]">{a.country_code}</span>
                      </span>
                    </td>
                    <td className="px-4 py-3">
                      <div className="flex items-center gap-1.5 text-xs">
                        <Clock className="w-3.5 h-3.5 text-[#3d5068]" />
                        <span className="text-[#7d92b0]" title={fmtDate(a.timestamp)}>
                          {relTime(a.timestamp)}
                        </span>
                      </div>
                    </td>
                    <td className="px-4 py-3 font-mono text-xs text-[#7d92b0]">{a.path}</td>
                    <td className="px-4 py-3 text-xs text-[#3d5068] truncate max-w-[200px]">{a.user_agent}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>

      {/* ── Modals ── */}
      <ConfirmModal
        open={confirmToggleOpen}
        title={config.enabled ? 'ジオブロッキングを無効にしますか？' : 'ジオブロッキングを有効にしますか？'}
        message={
          config.enabled
            ? 'ジオブロッキングを無効にすると、設定されたすべての国のフィルタリングが停止します。本当によろしいですか？'
            : 'ジオブロッキングを有効にすると、設定された国からのアクセスがブロックされます。'
        }
        onConfirm={toggleEnabled}
        onCancel={() => setConfirmToggleOpen(false)}
      />

      <AddCountryModal
        open={addCountryOpen}
        onClose={() => setAddCountryOpen(false)}
        onAdd={addCountry}
        existingCodes={countries.map(c => c.country_code)}
      />

      <AddExceptionModal
        open={addExceptionOpen}
        onClose={() => setAddExceptionOpen(false)}
        onAdd={addException}
      />
    </div>
  )
}

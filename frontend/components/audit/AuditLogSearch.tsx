'use client'

import { useState, useCallback } from 'react'
import { Search, Filter, X, ChevronDown, ChevronUp } from 'lucide-react'

// ─── Types ────────────────────────────────────────────────────────────────────

export interface AuditFilters {
  search?: string
  from_date?: string
  to_date?: string
  actions?: string[]
  user?: string
  ip_address?: string
  resource_type?: string
  severities?: string[]
}

interface Props {
  onSearch: (filters: AuditFilters) => void
}

// ─── Constants ───────────────────────────────────────────────────────────────

const ACTION_OPTIONS = [
  { value: 'login',              label: 'ログイン' },
  { value: 'logout',             label: 'ログアウト' },
  { value: 'create',             label: '作成' },
  { value: 'update',             label: '更新' },
  { value: 'delete',             label: '削除' },
  { value: 'export',             label: 'エクスポート' },
  { value: 'view',               label: '閲覧' },
  { value: 'alert_status_change', label: 'アラートステータス変更' },
  { value: 'rule_change',        label: 'ルール変更' },
  { value: 'user_management',    label: 'ユーザー管理' },
  { value: 'mfa_enable',         label: 'MFA有効化' },
  { value: 'mfa_disable',        label: 'MFA無効化' },
  { value: 'api_key_create',     label: 'APIキー作成' },
]

const RESOURCE_TYPE_OPTIONS = [
  { value: '',         label: '-- すべて --' },
  { value: 'alert',    label: 'アラート' },
  { value: 'agent',    label: 'エージェント' },
  { value: 'incident', label: 'インシデント' },
  { value: 'rule',     label: 'ルール' },
  { value: 'user',     label: 'ユーザー' },
  { value: 'settings', label: '設定' },
  { value: 'backup',   label: 'バックアップ' },
  { value: 'report',   label: 'レポート' },
]

const SEVERITY_OPTIONS = [
  { value: 'info',     label: 'Info',     color: 'text-blue-400  bg-blue-900/30  border-blue-700/50' },
  { value: 'warning',  label: 'Warning',  color: 'text-yellow-400 bg-yellow-900/30 border-yellow-700/50' },
  { value: 'critical', label: 'Critical', color: 'text-red-400   bg-red-900/30   border-red-700/50' },
]

// ─── Helpers ─────────────────────────────────────────────────────────────────

function countActiveFilters(f: AuditFilters): number {
  let n = 0
  if (f.search)        n++
  if (f.from_date)     n++
  if (f.to_date)       n++
  if (f.user)          n++
  if (f.ip_address)    n++
  if (f.resource_type) n++
  if (f.actions?.length)    n += f.actions.length
  if (f.severities?.length) n += f.severities.length
  return n
}

function toggleArrayItem(arr: string[], item: string): string[] {
  return arr.includes(item) ? arr.filter(v => v !== item) : [...arr, item]
}

// ─── Sub-components ──────────────────────────────────────────────────────────

function FilterLabel({ children }: { children: React.ReactNode }) {
  return (
    <label className="block text-xs font-medium text-gray-400 mb-1.5 uppercase tracking-wide">
      {children}
    </label>
  )
}

function TextInput({
  value,
  onChange,
  placeholder,
  hint,
}: {
  value: string
  onChange: (v: string) => void
  placeholder?: string
  hint?: string
}) {
  return (
    <div>
      <input
        type="text"
        value={value}
        onChange={e => onChange(e.target.value)}
        placeholder={placeholder}
        className="w-full bg-gray-900 border border-gray-600 rounded-lg px-3 py-2 text-sm
                   text-gray-200 placeholder-gray-600 focus:outline-hidden focus:border-blue-500
                   focus:ring-1 focus:ring-blue-500/30 transition-colors"
      />
      {hint && <p className="text-xs text-gray-600 mt-1">{hint}</p>}
    </div>
  )
}

// ─── Active filter chip ───────────────────────────────────────────────────────

function FilterChip({
  label,
  onRemove,
}: {
  label: string
  onRemove: () => void
}) {
  return (
    <span className="inline-flex items-center gap-1 px-2.5 py-1 rounded-full text-xs
                     bg-blue-900/30 text-blue-300 border border-blue-700/50">
      {label}
      <button
        onClick={onRemove}
        className="ml-0.5 text-blue-400 hover:text-white transition-colors"
        aria-label="フィルター削除"
      >
        <X className="w-3 h-3" />
      </button>
    </span>
  )
}

// ─── Main component ───────────────────────────────────────────────────────────

export function AuditLogSearch({ onSearch }: Props) {
  const [expanded, setExpanded] = useState(false)

  const [filters, setFilters] = useState<AuditFilters>({
    search:        '',
    from_date:     '',
    to_date:       '',
    actions:       [],
    user:          '',
    ip_address:    '',
    resource_type: '',
    severities:    [],
  })

  // ── Mutators ──────────────────────────────────────────────────────────────

  const set = useCallback(<K extends keyof AuditFilters>(key: K, value: AuditFilters[K]) => {
    setFilters(prev => ({ ...prev, [key]: value }))
  }, [])

  const toggleAction = useCallback((action: string) => {
    setFilters(prev => ({
      ...prev,
      actions: toggleArrayItem(prev.actions ?? [], action),
    }))
  }, [])

  const toggleSeverity = useCallback((severity: string) => {
    setFilters(prev => ({
      ...prev,
      severities: toggleArrayItem(prev.severities ?? [], severity),
    }))
  }, [])

  const clearFilters = useCallback(() => {
    setFilters({
      search:        '',
      from_date:     '',
      to_date:       '',
      actions:       [],
      user:          '',
      ip_address:    '',
      resource_type: '',
      severities:    [],
    })
  }, [])

  const handleSearch = useCallback(() => {
    // Strip empty strings before sending
    const clean: AuditFilters = {}
    if (filters.search)        clean.search        = filters.search
    if (filters.from_date)     clean.from_date     = filters.from_date
    if (filters.to_date)       clean.to_date       = filters.to_date
    if (filters.user)          clean.user          = filters.user
    if (filters.ip_address)    clean.ip_address    = filters.ip_address
    if (filters.resource_type) clean.resource_type = filters.resource_type
    if (filters.actions?.length)    clean.actions    = filters.actions
    if (filters.severities?.length) clean.severities = filters.severities
    onSearch(clean)
  }, [filters, onSearch])

  // ── Derived values ────────────────────────────────────────────────────────

  const activeCount = countActiveFilters(filters)
  const hasFilters  = activeCount > 0

  // Build chip list for active filters
  const chips: Array<{ key: string; label: string; remove: () => void }> = []

  if (filters.search)
    chips.push({ key: 'search', label: `検索: "${filters.search}"`, remove: () => set('search', '') })
  if (filters.from_date)
    chips.push({ key: 'from', label: `From: ${filters.from_date.replace('T', ' ')}`, remove: () => set('from_date', '') })
  if (filters.to_date)
    chips.push({ key: 'to', label: `To: ${filters.to_date.replace('T', ' ')}`, remove: () => set('to_date', '') })
  if (filters.user)
    chips.push({ key: 'user', label: `ユーザー: ${filters.user}`, remove: () => set('user', '') })
  if (filters.ip_address)
    chips.push({ key: 'ip', label: `IP: ${filters.ip_address}`, remove: () => set('ip_address', '') })
  if (filters.resource_type)
    chips.push({ key: 'rt', label: `リソース: ${filters.resource_type}`, remove: () => set('resource_type', '') })
  ;(filters.actions ?? []).forEach(a => {
    const opt = ACTION_OPTIONS.find(o => o.value === a)
    chips.push({ key: `action-${a}`, label: `アクション: ${opt?.label ?? a}`, remove: () => toggleAction(a) })
  })
  ;(filters.severities ?? []).forEach(s => {
    chips.push({ key: `sev-${s}`, label: `重大度: ${s}`, remove: () => toggleSeverity(s) })
  })

  // ── Render ────────────────────────────────────────────────────────────────

  return (
    <div className="bg-gray-800 rounded-xl border border-gray-700 overflow-hidden">

      {/* ── Top bar: simple search + toggle ──────────────────────────────── */}
      <div className="flex items-center gap-3 px-4 py-3">

        {/* Full-text search */}
        <div className="relative flex-1">
          <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-gray-500 pointer-events-none" />
          <input
            type="text"
            value={filters.search ?? ''}
            onChange={e => set('search', e.target.value)}
            onKeyDown={e => e.key === 'Enter' && !e.nativeEvent.isComposing && handleSearch()}
            placeholder="アクション、リソースID、IPアドレスを検索..."
            className="w-full bg-gray-900 border border-gray-600 rounded-lg pl-10 pr-4 py-2.5 text-sm
                       text-gray-200 placeholder-gray-600 focus:outline-hidden focus:border-blue-500
                       focus:ring-1 focus:ring-blue-500/30 transition-colors"
          />
        </div>

        {/* Advanced toggle button */}
        <button
          onClick={() => setExpanded(v => !v)}
          className={`flex items-center gap-2 px-4 py-2.5 rounded-lg border text-sm font-medium
                      transition-colors whitespace-nowrap ${
                        expanded
                          ? 'bg-blue-700 border-blue-600 text-white'
                          : 'bg-gray-700 border-gray-600 text-gray-300 hover:bg-gray-600 hover:text-white'
                      }`}
        >
          <Filter className="w-4 h-4" />
          詳細フィルター
          {hasFilters && !expanded && (
            <span className="ml-0.5 inline-flex items-center justify-center w-5 h-5 rounded-full
                             bg-blue-600 text-white text-[10px] font-bold leading-none">
              {activeCount}
            </span>
          )}
          {expanded ? <ChevronUp className="w-3.5 h-3.5" /> : <ChevronDown className="w-3.5 h-3.5" />}
        </button>

        {/* Search button */}
        <button
          onClick={handleSearch}
          className="flex items-center gap-2 px-5 py-2.5 bg-blue-600 hover:bg-blue-700
                     text-white text-sm font-medium rounded-lg transition-colors whitespace-nowrap"
        >
          <Search className="w-4 h-4" />
          検索
        </button>
      </div>

      {/* ── Active filter chips ───────────────────────────────────────────── */}
      {chips.length > 0 && (
        <div className="flex flex-wrap items-center gap-2 px-4 pb-3 border-t border-gray-700/50 pt-3">
          <span className="text-xs text-gray-500 mr-1">適用中:</span>
          {chips.map(chip => (
            <FilterChip key={chip.key} label={chip.label} onRemove={chip.remove} />
          ))}
          <button
            onClick={clearFilters}
            className="ml-auto text-xs text-gray-500 hover:text-white transition-colors
                       flex items-center gap-1 px-2 py-1 rounded hover:bg-gray-700"
          >
            <X className="w-3 h-3" />
            すべてクリア
          </button>
        </div>
      )}

      {/* ── Expanded filter panel ─────────────────────────────────────────── */}
      {expanded && (
        <div className="border-t border-gray-700 px-4 py-5 space-y-6">

          {/* Row 1: Date range */}
          <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
            <div>
              <FilterLabel>開始日時 (From)</FilterLabel>
              <input
                type="datetime-local"
                value={filters.from_date ?? ''}
                onChange={e => set('from_date', e.target.value)}
                className="w-full bg-gray-900 border border-gray-600 rounded-lg px-3 py-2 text-sm
                           text-gray-200 focus:outline-hidden focus:border-blue-500
                           focus:ring-1 focus:ring-blue-500/30 transition-colors scheme-dark"
              />
            </div>
            <div>
              <FilterLabel>終了日時 (To)</FilterLabel>
              <input
                type="datetime-local"
                value={filters.to_date ?? ''}
                onChange={e => set('to_date', e.target.value)}
                className="w-full bg-gray-900 border border-gray-600 rounded-lg px-3 py-2 text-sm
                           text-gray-200 focus:outline-hidden focus:border-blue-500
                           focus:ring-1 focus:ring-blue-500/30 transition-colors scheme-dark"
              />
            </div>
          </div>

          {/* Row 2: User / IP */}
          <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
            <div>
              <FilterLabel>ユーザー</FilterLabel>
              <TextInput
                value={filters.user ?? ''}
                onChange={v => set('user', v)}
                placeholder="ユーザー名またはメール"
              />
            </div>
            <div>
              <FilterLabel>IPアドレス</FilterLabel>
              <TextInput
                value={filters.ip_address ?? ''}
                onChange={v => set('ip_address', v)}
                placeholder="192.168.1.0/24"
                hint="単一IPまたはCIDR表記で入力"
              />
            </div>
          </div>

          {/* Row 3: Resource type / Severity */}
          <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
            <div>
              <FilterLabel>リソースタイプ</FilterLabel>
              <select
                value={filters.resource_type ?? ''}
                onChange={e => set('resource_type', e.target.value)}
                className="w-full bg-gray-900 border border-gray-600 rounded-lg px-3 py-2 text-sm
                           text-gray-200 focus:outline-hidden focus:border-blue-500
                           focus:ring-1 focus:ring-blue-500/30 transition-colors scheme-dark"
              >
                {RESOURCE_TYPE_OPTIONS.map(opt => (
                  <option key={opt.value} value={opt.value}>{opt.label}</option>
                ))}
              </select>
            </div>
            <div>
              <FilterLabel>重大度</FilterLabel>
              <div className="flex flex-wrap gap-2 pt-0.5">
                {SEVERITY_OPTIONS.map(sev => {
                  const selected = (filters.severities ?? []).includes(sev.value)
                  return (
                    <button
                      key={sev.value}
                      onClick={() => toggleSeverity(sev.value)}
                      className={`inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg border text-xs
                                  font-semibold transition-colors ${
                                    selected
                                      ? sev.color
                                      : 'bg-gray-700 border-gray-600 text-gray-400 hover:text-gray-200 hover:bg-gray-600'
                                  }`}
                    >
                      {selected && <span className="w-1.5 h-1.5 rounded-full bg-current inline-block" />}
                      {sev.label}
                    </button>
                  )
                })}
              </div>
            </div>
          </div>

          {/* Row 4: Action types (full width) */}
          <div>
            <FilterLabel>アクションタイプ</FilterLabel>
            <div className="flex flex-wrap gap-2">
              {ACTION_OPTIONS.map(opt => {
                const selected = (filters.actions ?? []).includes(opt.value)
                return (
                  <button
                    key={opt.value}
                    onClick={() => toggleAction(opt.value)}
                    className={`px-3 py-1.5 rounded-lg border text-xs font-medium transition-colors ${
                      selected
                        ? 'bg-blue-700 border-blue-600 text-white'
                        : 'bg-gray-700 border-gray-600 text-gray-400 hover:text-gray-200 hover:bg-gray-600'
                    }`}
                  >
                    {opt.label}
                  </button>
                )
              })}
            </div>
          </div>

          {/* Bottom actions */}
          <div className="flex items-center justify-between pt-1 border-t border-gray-700">
            <button
              onClick={clearFilters}
              className="flex items-center gap-1.5 text-sm text-gray-400 hover:text-white
                         transition-colors px-3 py-2 rounded-lg hover:bg-gray-700"
            >
              <X className="w-4 h-4" />
              フィルタークリア
            </button>
            <button
              onClick={handleSearch}
              className="flex items-center gap-2 px-6 py-2 bg-blue-600 hover:bg-blue-700
                         text-white text-sm font-medium rounded-lg transition-colors"
            >
              <Search className="w-4 h-4" />
              検索
            </button>
          </div>

        </div>
      )}

    </div>
  )
}

'use client'

// AdminDrawer — right-side sheet that provides full CRUD over every
// capacity-planning table. Kept separate from page.tsx so the read-only
// rendering code stays ~700 lines of mostly JSX while the write path has
// its own mental model (forms, mutations, validation) in this file.
//
// Each section has its own editor with inline row editing. The drawer
// invalidates the parent page's queries via queryClient so changes show
// up on close without a manual refresh.

import { useState, useEffect } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { apiFetch } from '@/lib/api'
import { X, Plus, Trash2, Save } from 'lucide-react'

type SectionKey =
  | 'planning-targets'
  | 'storage'
  | 'workforce'
  | 'resources'
  | 'budget'
  | 'planned-hires'
  | 'tech-debt'
  | 'oncall-shifts'
  | 'roi'

const SECTIONS: { key: SectionKey; label: string }[] = [
  { key: 'planning-targets', label: '計画目標値' },
  { key: 'storage',          label: 'ストレージ' },
  { key: 'roi',              label: 'ROI入力' },
  { key: 'workforce',        label: 'アナリスト' },
  { key: 'resources',        label: 'ライセンス' },
  { key: 'budget',           label: '予算カテゴリ' },
  { key: 'planned-hires',    label: '採用計画' },
  { key: 'tech-debt',        label: '技術的負債' },
  { key: 'oncall-shifts',    label: 'オンコール' },
]

// ── JSON helpers ──────────────────────────────────────────────────

function postJSON(path: string, body: unknown) {
  return apiFetch(path, { method: 'POST', body: JSON.stringify(body) })
}
function putJSON(path: string, body: unknown) {
  return apiFetch(path, { method: 'PUT', body: JSON.stringify(body) })
}
function del(path: string) {
  return apiFetch(path, { method: 'DELETE' })
}

// Shared invalidation set — covers every query key used on the parent page.
const QUERY_KEYS = [
  'capacity-planning-overview',
  'capacity-planning-workforce',
  'capacity-planning-resources',
  'capacity-planning-storage',
  'capacity-planning-budget',
  'capacity-planning-planned-hires',
  'capacity-planning-tech-debt',
  'capacity-planning-oncall',
  'capacity-planning-roi',
]

// ── Form primitives ───────────────────────────────────────────────

function TextField({ label, value, onChange, type = 'text' }: {
  label: string
  value: string | number
  onChange: (v: string) => void
  type?: string
}) {
  return (
    <label className="block">
      <span className="text-falcon-muted text-xs">{label}</span>
      <input
        type={type}
        value={value}
        onChange={e => onChange(e.target.value)}
        className="mt-1 w-full bg-[#070d19] border border-falcon-border rounded-sm px-2 py-1 text-white text-sm focus:outline-hidden focus:border-falcon-red"
      />
    </label>
  )
}

function SelectField({ label, value, onChange, options }: {
  label: string
  value: string
  onChange: (v: string) => void
  options: string[]
}) {
  return (
    <label className="block">
      <span className="text-falcon-muted text-xs">{label}</span>
      <select
        value={value}
        onChange={e => onChange(e.target.value)}
        className="mt-1 w-full bg-[#070d19] border border-falcon-border rounded-sm px-2 py-1 text-white text-sm focus:outline-hidden focus:border-falcon-red"
      >
        {options.map(o => <option key={o} value={o}>{o}</option>)}
      </select>
    </label>
  )
}

// SaveButton + Delete icon — reused by every editor row.
// `error` surfaces mutation failures that would otherwise be silent (400s,
// server 500s). Without this, save/delete failures vanish because React Query
// only tracks errors internally.
function ActionRow({ onSave, onDelete, saving, error }: {
  onSave: () => void
  onDelete?: () => void
  saving?: boolean
  error?: string | null
}) {
  return (
    <div className="pt-2 space-y-1">
      <div className="flex items-center gap-2">
        <button
          onClick={onSave}
          disabled={saving}
          className="flex items-center gap-1 px-3 py-1 bg-falcon-red hover:bg-[#c0001f] disabled:opacity-50 text-white text-xs rounded-sm"
        >
          <Save className="w-3 h-3" />
          {saving ? '保存中…' : '保存'}
        </button>
        {onDelete && (
          <button
            onClick={onDelete}
            className="flex items-center gap-1 px-3 py-1 bg-falcon-border hover:bg-red-500/30 text-red-300 text-xs rounded-sm border border-red-500/30"
          >
            <Trash2 className="w-3 h-3" />
            削除
          </button>
        )}
      </div>
      {error && (
        <p className="text-red-400 text-[11px]">エラー: {error}</p>
      )}
    </div>
  )
}

// mutErr extracts a user-readable message from a React Query mutation error.
function mutErr(e: unknown): string | null {
  if (!e) return null
  if (e instanceof Error) return e.message
  return String(e)
}

// ── Planning Targets editor (singleton) ───────────────────────────

function PlanningTargetsEditor() {
  const qc = useQueryClient()
  const { data } = useQuery({
    queryKey: ['cp-edit-targets'],
    queryFn: () => apiFetch<{ cost_per_endpoint_target: number; analyst_headroom: number; alerts_per_day: number }>('/api/v1/admin/capacity-planning/overview'),
    staleTime: 0,
  })
  const [cost, setCost] = useState('')
  const [headroom, setHeadroom] = useState('')
  useEffect(() => {
    if (data) {
      setCost(String(data.cost_per_endpoint_target))
      setHeadroom(String(data.analyst_headroom))
    }
  }, [data])

  const save = useMutation({
    mutationFn: () => putJSON('/api/v1/admin/capacity-planning/planning-targets', {
      cost_per_endpoint_target: Number(cost) || 0,
      analyst_headroom: Number(headroom) || 0,
    }),
    onSuccess: () => QUERY_KEYS.forEach(k => qc.invalidateQueries({ queryKey: [k] })),
  })

  return (
    <div className="space-y-3">
      <p className="text-falcon-muted text-xs">エンドポイント単価目標値と、アナリスト必要余裕人数を設定します。</p>
      <TextField label="エンドポイント単価目標 (円/台)" value={cost} onChange={setCost} type="number" />
      <TextField label="アナリスト余裕人数" value={headroom} onChange={setHeadroom} type="number" />
      <ActionRow onSave={() => save.mutate()} saving={save.isPending} error={mutErr(save.error)} />
    </div>
  )
}

// ── Storage editor (singleton) ────────────────────────────────────

function StorageEditor() {
  const qc = useQueryClient()
  const { data } = useQuery({
    queryKey: ['cp-edit-storage'],
    queryFn: () => apiFetch<{ used_tb: number; total_tb: number; projected_6m_tb: number; projected_12m_tb: number }>('/api/v1/admin/capacity-planning/storage'),
    staleTime: 0,
  })
  const [used, setUsed] = useState('')
  const [total, setTotal] = useState('')
  const [p6, setP6] = useState('')
  const [p12, setP12] = useState('')
  useEffect(() => {
    if (data) {
      setUsed(String(data.used_tb))
      setTotal(String(data.total_tb))
      setP6(String(data.projected_6m_tb))
      setP12(String(data.projected_12m_tb))
    }
  }, [data])

  const save = useMutation({
    mutationFn: () => putJSON('/api/v1/admin/capacity-planning/storage', {
      used_tb: Number(used) || 0,
      total_tb: Number(total) || 0,
      projected_6m_tb: Number(p6) || 0,
      projected_12m_tb: Number(p12) || 0,
    }),
    onSuccess: () => QUERY_KEYS.forEach(k => qc.invalidateQueries({ queryKey: [k] })),
  })

  return (
    <div className="space-y-3">
      <div className="grid grid-cols-2 gap-3">
        <TextField label="使用中 (TB)" value={used} onChange={setUsed} type="number" />
        <TextField label="上限 (TB)" value={total} onChange={setTotal} type="number" />
        <TextField label="6ヶ月後予測 (TB)" value={p6} onChange={setP6} type="number" />
        <TextField label="12ヶ月後予測 (TB)" value={p12} onChange={setP12} type="number" />
      </div>
      <ActionRow onSave={() => save.mutate()} saving={save.isPending} error={mutErr(save.error)} />
    </div>
  )
}

// ── Generic list editor helper ────────────────────────────────────
// Keeps each row's form state local so typing in one row doesn't re-render
// others, and so "delete" on one row doesn't wipe the edit buffer on another.

type Field<T> = {
  key: keyof T
  label: string
  type?: 'text' | 'number'
  options?: string[]
}

function Row<T extends Record<string, unknown>>({ item, fields, path, idKey, onChanged }: {
  item: T
  fields: Field<T>[]
  path: string          // PUT path with :id replaced
  idKey: keyof T
  onChanged: () => void
}) {
  const [draft, setDraft] = useState<T>(item)
  useEffect(() => setDraft(item), [item])

  const save = useMutation({
    mutationFn: () => putJSON(path, draft),
    onSuccess: onChanged,
  })
  const remove = useMutation({
    mutationFn: () => del(path),
    onSuccess: onChanged,
  })

  return (
    <div className="bg-[#070d19] border border-falcon-border rounded-lg p-3 space-y-2">
      <div className="grid grid-cols-2 gap-2">
        {fields.map(f => {
          const v = draft[f.key]
          if (f.options) {
            return (
              <SelectField
                key={String(f.key)}
                label={f.label}
                value={String(v ?? '')}
                onChange={val => setDraft(d => ({ ...d, [f.key]: val }) as T)}
                options={f.options}
              />
            )
          }
          return (
            <TextField
              key={String(f.key)}
              label={f.label}
              value={String(v ?? '')}
              onChange={val =>
                setDraft(d => ({
                  ...d,
                  [f.key]: f.type === 'number' ? Number(val) : val,
                }) as T)
              }
              type={f.type === 'number' ? 'number' : 'text'}
            />
          )
        })}
      </div>
      <ActionRow
        onSave={() => save.mutate()}
        onDelete={() => {
          if (confirm('このレコードを削除しますか？')) remove.mutate()
        }}
        saving={save.isPending || remove.isPending}
        error={mutErr(save.error) || mutErr(remove.error)}
      />
      <p className="text-falcon-subtle text-[10px]">id: {String(item[idKey])}</p>
    </div>
  )
}

function AddRow<T extends Record<string, unknown>>({ fields, initial, path, onAdded }: {
  fields: Field<T>[]
  initial: T
  path: string
  onAdded: () => void
}) {
  const [draft, setDraft] = useState<T>(initial)
  const [open, setOpen] = useState(false)
  const add = useMutation({
    mutationFn: () => postJSON(path, draft),
    onSuccess: () => {
      setDraft(initial)
      setOpen(false)
      onAdded()
    },
  })
  if (!open) {
    return (
      <button
        onClick={() => setOpen(true)}
        className="flex items-center gap-1 px-3 py-2 text-xs text-falcon-red border border-dashed border-falcon-border rounded-sm hover:bg-falcon-surface w-full justify-center"
      >
        <Plus className="w-3 h-3" /> 新規追加
      </button>
    )
  }
  return (
    <div className="bg-[#070d19] border border-falcon-red/30 rounded-lg p-3 space-y-2">
      <p className="text-white text-xs font-medium">新規レコード</p>
      <div className="grid grid-cols-2 gap-2">
        {fields.map(f => {
          const v = draft[f.key]
          if (f.options) {
            return (
              <SelectField
                key={String(f.key)}
                label={f.label}
                value={String(v ?? '')}
                onChange={val => setDraft(d => ({ ...d, [f.key]: val }) as T)}
                options={f.options}
              />
            )
          }
          return (
            <TextField
              key={String(f.key)}
              label={f.label}
              value={String(v ?? '')}
              onChange={val =>
                setDraft(d => ({
                  ...d,
                  [f.key]: f.type === 'number' ? Number(val) : val,
                }) as T)
              }
              type={f.type === 'number' ? 'number' : 'text'}
            />
          )
        })}
      </div>
      <div className="flex gap-2">
        <button
          onClick={() => add.mutate()}
          disabled={add.isPending}
          className="px-3 py-1 bg-falcon-red hover:bg-[#c0001f] disabled:opacity-50 text-white text-xs rounded-sm"
        >
          {add.isPending ? '追加中…' : '追加'}
        </button>
        <button
          onClick={() => { setOpen(false); setDraft(initial) }}
          className="px-3 py-1 bg-falcon-border text-falcon-muted text-xs rounded-sm"
        >
          キャンセル
        </button>
      </div>
      {add.error && (
        <p className="text-red-400 text-[11px]">エラー: {mutErr(add.error)}</p>
      )}
    </div>
  )
}

// ── Collection editors ────────────────────────────────────────────

// Analysts — skills JSONB is edited as raw JSON text for simplicity.
// Going fancier (5 per-skill selects) triples the form code; raw JSON is
// honest about what the column is and round-trips cleanly.
function AnalystsEditor() {
  const qc = useQueryClient()
  const { data, refetch } = useQuery({
    queryKey: ['cp-edit-analysts'],
    queryFn: () => apiFetch<Array<{ id: string; name: string; role: string; skills: Record<string, string>; alerts_handled_per_day: number; hire_date: string }>>('/api/v1/admin/capacity-planning/workforce'),
    staleTime: 0,
  })
  type Row = { id: string; name: string; role: string; skills: string; alerts_handled_per_day: number; hire_date: string }
  const rows: Row[] = (data ?? []).map(a => ({ ...a, skills: JSON.stringify(a.skills) }))
  const onChanged = () => { refetch(); QUERY_KEYS.forEach(k => qc.invalidateQueries({ queryKey: [k] })) }
  const roles = ['L1 Analyst', 'L2 Analyst', 'L3 Analyst', 'Threat Hunter', 'Incident Responder', 'Engineer', 'Manager', 'Cloud Analyst']
  const fields: Field<Row>[] = [
    { key: 'name', label: '氏名' },
    { key: 'role', label: '役割', options: roles },
    { key: 'alerts_handled_per_day', label: '処理可能アラート数/日', type: 'number' },
    { key: 'hire_date', label: '入社日 (YYYY-MM-DD)' },
    { key: 'skills', label: 'スキル (JSON)' },
  ]
  // Reject invalid JSON at serialize time instead of silently swallowing it.
  // Throwing here flips React Query into `error` state, which ActionRow renders
  // — users see the parse error instead of a quiet zero-out.
  const parseSkillsOrThrow = (s: string): unknown => {
    try { return JSON.parse(s) }
    catch (e) { throw new Error('スキル欄の JSON が不正です: ' + (e instanceof Error ? e.message : '')) }
  }
  return (
    <div className="space-y-3">
      <p className="text-falcon-muted text-xs">スキルは JSON 形式（例: {'{"DFIR":"full","Malware":"partial","Network":"full","Cloud":"none","Compliance":"partial"}'}）</p>
      {rows.map(r => {
        const serialized = (d: Row) => ({ ...d, skills: parseSkillsOrThrow(d.skills) })
        return (
          <SerializingRow
            key={r.id}
            item={r}
            fields={fields}
            serialize={serialized}
            path={`/api/v1/admin/capacity-planning/workforce/${r.id}`}
            idKey="id"
            onChanged={onChanged}
          />
        )
      })}
      <SerializingAddRow<Row>
        fields={fields}
        initial={{ id: '', name: '', role: 'L1 Analyst', alerts_handled_per_day: 0, hire_date: '', skills: '{"DFIR":"none","Malware":"none","Network":"none","Cloud":"none","Compliance":"none"}' }}
        serialize={d => ({ ...d, skills: parseSkillsOrThrow(d.skills) })}
        path="/api/v1/admin/capacity-planning/workforce"
        onAdded={onChanged}
      />
    </div>
  )
}

// SerializingRow/AddRow — variants that transform the draft before sending.
function SerializingRow<T extends Record<string, unknown>>({ item, fields, path, idKey, onChanged, serialize }: {
  item: T
  fields: Field<T>[]
  path: string
  idKey: keyof T
  onChanged: () => void
  serialize: (d: T) => unknown
}) {
  const [draft, setDraft] = useState<T>(item)
  useEffect(() => setDraft(item), [item])
  const save = useMutation({
    mutationFn: () => putJSON(path, serialize(draft)),
    onSuccess: onChanged,
  })
  const remove = useMutation({ mutationFn: () => del(path), onSuccess: onChanged })

  return (
    <div className="bg-[#070d19] border border-falcon-border rounded-lg p-3 space-y-2">
      <div className="grid grid-cols-2 gap-2">
        {fields.map(f => {
          const v = draft[f.key]
          if (f.options) {
            return (
              <SelectField key={String(f.key)} label={f.label} value={String(v ?? '')}
                onChange={val => setDraft(d => ({ ...d, [f.key]: val }) as T)} options={f.options} />
            )
          }
          return (
            <TextField key={String(f.key)} label={f.label} value={String(v ?? '')}
              onChange={val => setDraft(d => ({ ...d, [f.key]: f.type === 'number' ? Number(val) : val }) as T)}
              type={f.type === 'number' ? 'number' : 'text'} />
          )
        })}
      </div>
      <ActionRow
        onSave={() => save.mutate()}
        onDelete={() => { if (confirm('このレコードを削除しますか？')) remove.mutate() }}
        saving={save.isPending || remove.isPending}
        error={mutErr(save.error) || mutErr(remove.error)}
      />
      <p className="text-falcon-subtle text-[10px]">id: {String(item[idKey])}</p>
    </div>
  )
}

function SerializingAddRow<T extends Record<string, unknown>>({ fields, initial, path, onAdded, serialize }: {
  fields: Field<T>[]
  initial: T
  path: string
  onAdded: () => void
  serialize: (d: T) => unknown
}) {
  const [draft, setDraft] = useState<T>(initial)
  const [open, setOpen] = useState(false)
  const add = useMutation({
    mutationFn: () => postJSON(path, serialize(draft)),
    onSuccess: () => { setDraft(initial); setOpen(false); onAdded() },
  })
  if (!open) {
    return (
      <button
        onClick={() => setOpen(true)}
        className="flex items-center gap-1 px-3 py-2 text-xs text-falcon-red border border-dashed border-falcon-border rounded-sm hover:bg-falcon-surface w-full justify-center"
      >
        <Plus className="w-3 h-3" /> 新規追加
      </button>
    )
  }
  return (
    <div className="bg-[#070d19] border border-falcon-red/30 rounded-lg p-3 space-y-2">
      <p className="text-white text-xs font-medium">新規レコード</p>
      <div className="grid grid-cols-2 gap-2">
        {fields.map(f => {
          const v = draft[f.key]
          if (f.options) {
            return (
              <SelectField key={String(f.key)} label={f.label} value={String(v ?? '')}
                onChange={val => setDraft(d => ({ ...d, [f.key]: val }) as T)} options={f.options} />
            )
          }
          return (
            <TextField key={String(f.key)} label={f.label} value={String(v ?? '')}
              onChange={val => setDraft(d => ({ ...d, [f.key]: f.type === 'number' ? Number(val) : val }) as T)}
              type={f.type === 'number' ? 'number' : 'text'} />
          )
        })}
      </div>
      <div className="flex gap-2">
        <button onClick={() => add.mutate()} disabled={add.isPending}
          className="px-3 py-1 bg-falcon-red hover:bg-[#c0001f] disabled:opacity-50 text-white text-xs rounded-sm">
          {add.isPending ? '追加中…' : '追加'}
        </button>
        <button onClick={() => { setOpen(false); setDraft(initial) }}
          className="px-3 py-1 bg-falcon-border text-falcon-muted text-xs rounded-sm">
          キャンセル
        </button>
      </div>
      {add.error && (
        <p className="text-red-400 text-[11px]">エラー: {mutErr(add.error)}</p>
      )}
    </div>
  )
}

function LicensesEditor() {
  const qc = useQueryClient()
  const { data, refetch } = useQuery({
    queryKey: ['cp-edit-licenses'],
    queryFn: () => apiFetch<Array<{ id: string; tool_name: string; category: string; purchased: number; used: number; price_per_unit: number; renewal_date: string }>>('/api/v1/admin/capacity-planning/resources'),
    staleTime: 0,
  })
  type Row = { id: string; tool_name: string; category: string; purchased: number; used: number; price_per_unit: number; renewal_date: string; sort_order: number }
  const rows: Row[] = (data ?? []).map((r, i) => ({ ...r, sort_order: i + 1 }))
  const onChanged = () => { refetch(); QUERY_KEYS.forEach(k => qc.invalidateQueries({ queryKey: [k] })) }
  const fields: Field<Row>[] = [
    { key: 'tool_name', label: 'ツール名' },
    { key: 'category', label: 'カテゴリ' },
    { key: 'purchased', label: '購入数', type: 'number' },
    { key: 'used', label: '使用数', type: 'number' },
    { key: 'price_per_unit', label: '単価 (円)', type: 'number' },
    { key: 'renewal_date', label: '更新日 (YYYY-MM-DD)' },
    { key: 'sort_order', label: '並び順', type: 'number' },
  ]
  return (
    <div className="space-y-3">
      {rows.map(r => (
        <Row key={r.id} item={r} fields={fields} idKey="id"
          path={`/api/v1/admin/capacity-planning/resources/${r.id}`}
          onChanged={onChanged} />
      ))}
      <AddRow<Row> fields={fields}
        initial={{ id: '', tool_name: '', category: '', purchased: 0, used: 0, price_per_unit: 0, renewal_date: '', sort_order: 0 }}
        path="/api/v1/admin/capacity-planning/resources" onAdded={onChanged} />
    </div>
  )
}

function BudgetEditor() {
  const qc = useQueryClient()
  const { data, refetch } = useQuery({
    queryKey: ['cp-edit-budget'],
    queryFn: () => apiFetch<Array<{ label: string; current_year: number; next_year: number; year3: number }>>('/api/v1/admin/capacity-planning/budget'),
    staleTime: 0,
  })
  type Row = { label: string; current_year: number; next_year: number; year3: number; sort_order: number }
  const rows: Row[] = (data ?? []).map((r, i) => ({ ...r, sort_order: i + 1 }))
  const onChanged = () => { refetch(); QUERY_KEYS.forEach(k => qc.invalidateQueries({ queryKey: [k] })) }
  const fields: Field<Row>[] = [
    { key: 'label', label: 'カテゴリ' },
    { key: 'current_year', label: '当年度 (円)', type: 'number' },
    { key: 'next_year', label: '来年度 (円)', type: 'number' },
    { key: 'year3', label: '3年目 (円)', type: 'number' },
    { key: 'sort_order', label: '並び順', type: 'number' },
  ]
  return (
    <div className="space-y-3">
      {rows.map(r => (
        <Row key={r.label} item={r} fields={fields} idKey="label"
          path={`/api/v1/admin/capacity-planning/budget/${encodeURIComponent(r.label)}`}
          onChanged={onChanged} />
      ))}
      <AddRow<Row> fields={fields}
        initial={{ label: '', current_year: 0, next_year: 0, year3: 0, sort_order: 0 }}
        path="/api/v1/admin/capacity-planning/budget" onAdded={onChanged} />
    </div>
  )
}

function PlannedHiresEditor() {
  const qc = useQueryClient()
  const { data, refetch } = useQuery({
    queryKey: ['cp-edit-hires'],
    queryFn: () => apiFetch<Array<{ id: string; role: string; planned_quarter: string; estimated_annual_cost: number; priority: string }>>('/api/v1/admin/capacity-planning/planned-hires'),
    staleTime: 0,
  })
  type Row = { id: string; role: string; planned_quarter: string; estimated_annual_cost: number; priority: string; sort_order: number }
  const rows: Row[] = (data ?? []).map((r, i) => ({ ...r, sort_order: i + 1 }))
  const onChanged = () => { refetch(); QUERY_KEYS.forEach(k => qc.invalidateQueries({ queryKey: [k] })) }
  const fields: Field<Row>[] = [
    { key: 'role', label: '役割' },
    { key: 'planned_quarter', label: '計画四半期 (例: FY2027 Q1)' },
    { key: 'estimated_annual_cost', label: '推定年間コスト (円)', type: 'number' },
    { key: 'priority', label: '優先度', options: ['high', 'medium', 'low'] },
    { key: 'sort_order', label: '並び順', type: 'number' },
  ]
  return (
    <div className="space-y-3">
      {rows.map(r => (
        <Row key={r.id} item={r} fields={fields} idKey="id"
          path={`/api/v1/admin/capacity-planning/planned-hires/${r.id}`}
          onChanged={onChanged} />
      ))}
      <AddRow<Row> fields={fields}
        initial={{ id: '', role: '', planned_quarter: '', estimated_annual_cost: 0, priority: 'medium', sort_order: 0 }}
        path="/api/v1/admin/capacity-planning/planned-hires" onAdded={onChanged} />
    </div>
  )
}

function TechDebtEditor() {
  const qc = useQueryClient()
  const { data, refetch } = useQuery({
    queryKey: ['cp-edit-techdebt'],
    queryFn: () => apiFetch<Array<{ id: string; title: string; impact: string; severity: string }>>('/api/v1/admin/capacity-planning/tech-debt'),
    staleTime: 0,
  })
  type Row = { id: string; title: string; impact: string; severity: string; sort_order: number }
  const rows: Row[] = (data ?? []).map((r, i) => ({ ...r, sort_order: i + 1 }))
  const onChanged = () => { refetch(); QUERY_KEYS.forEach(k => qc.invalidateQueries({ queryKey: [k] })) }
  const fields: Field<Row>[] = [
    { key: 'title', label: 'タイトル' },
    { key: 'impact', label: '影響' },
    { key: 'severity', label: '重大度', options: ['high', 'medium', 'low'] },
    { key: 'sort_order', label: '並び順', type: 'number' },
  ]
  return (
    <div className="space-y-3">
      {rows.map(r => (
        <Row key={r.id} item={r} fields={fields} idKey="id"
          path={`/api/v1/admin/capacity-planning/tech-debt/${r.id}`}
          onChanged={onChanged} />
      ))}
      <AddRow<Row> fields={fields}
        initial={{ id: '', title: '', impact: '', severity: 'medium', sort_order: 0 }}
        path="/api/v1/admin/capacity-planning/tech-debt" onAdded={onChanged} />
    </div>
  )
}

function OncallEditor() {
  const qc = useQueryClient()
  const { data, refetch } = useQuery({
    queryKey: ['cp-edit-oncall'],
    queryFn: () => apiFetch<Array<{ id: string; shift: string; start: string; end: string; mon: string; tue: string; wed: string; thu: string; fri: string; sat: string; sun: string }>>('/api/v1/admin/capacity-planning/oncall-shifts'),
    staleTime: 0,
  })
  type Row = { id: string; shift: string; start_h: string; end_h: string; mon: string; tue: string; wed: string; thu: string; fri: string; sat: string; sun: string; sort_order: number }
  // GET returns `start`/`end` but table columns are start_h/end_h — normalize.
  const rows: Row[] = (data ?? []).map((r, i) => ({
    id: r.id, shift: r.shift, start_h: r.start, end_h: r.end,
    mon: r.mon, tue: r.tue, wed: r.wed, thu: r.thu, fri: r.fri, sat: r.sat, sun: r.sun,
    sort_order: i + 1,
  }))
  const onChanged = () => { refetch(); QUERY_KEYS.forEach(k => qc.invalidateQueries({ queryKey: [k] })) }
  const fields: Field<Row>[] = [
    { key: 'shift', label: 'シフト名' },
    { key: 'start_h', label: '開始 (HH:MM)' },
    { key: 'end_h', label: '終了 (HH:MM)' },
    { key: 'mon', label: '月' }, { key: 'tue', label: '火' },
    { key: 'wed', label: '水' }, { key: 'thu', label: '木' },
    { key: 'fri', label: '金' }, { key: 'sat', label: '土' }, { key: 'sun', label: '日' },
    { key: 'sort_order', label: '並び順', type: 'number' },
  ]
  return (
    <div className="space-y-3">
      <p className="text-falcon-muted text-xs">担当者未割当セルは「—」と入力してください。</p>
      {rows.map(r => (
        <Row key={r.id} item={r} fields={fields} idKey="id"
          path={`/api/v1/admin/capacity-planning/oncall-shifts/${r.id}`}
          onChanged={onChanged} />
      ))}
      <AddRow<Row> fields={fields}
        initial={{ id: '', shift: '', start_h: '', end_h: '', mon: '—', tue: '—', wed: '—', thu: '—', fri: '—', sat: '—', sun: '—', sort_order: 0 }}
        path="/api/v1/admin/capacity-planning/oncall-shifts" onAdded={onChanged} />
    </div>
  )
}

function ROIEditor() {
  const qc = useQueryClient()
  const { data, refetch } = useQuery({
    queryKey: ['cp-edit-roi'],
    queryFn: () => apiFetch<Array<{
      category: string; label: string; sub_label: string;
      annual_investment: number; annual_benefit: number; roi_pct: number;
      breach_prevention_value: number; operational_savings: number; compliance_value: number
    }>>('/api/v1/admin/capacity-planning/roi'),
    staleTime: 0,
  })
  // Filter out the synthesized "overall" row — it has no DB backing.
  const rows = (data ?? []).filter(r => r.category !== 'overall')
  const onChanged = () => { refetch(); QUERY_KEYS.forEach(k => qc.invalidateQueries({ queryKey: [k] })) }
  type Row = {
    category: string; label: string; sub_label: string;
    annual_investment: number; breach_prevention_value: number;
    operational_savings: number; compliance_value: number; sort_order: number
  }
  // Read the real breakdown values from the API so saving doesn't zero them out.
  const editRows: Row[] = rows.map((r, i) => ({
    category: r.category,
    label: r.label,
    sub_label: r.sub_label,
    annual_investment: r.annual_investment,
    breach_prevention_value: r.breach_prevention_value ?? 0,
    operational_savings: r.operational_savings ?? 0,
    compliance_value: r.compliance_value ?? 0,
    sort_order: i + 1,
  }))
  const fields: Field<Row>[] = [
    { key: 'category', label: 'カテゴリキー' },
    { key: 'label', label: 'ラベル' },
    { key: 'sub_label', label: 'サブラベル' },
    { key: 'annual_investment', label: '年間投資 (円)', type: 'number' },
    { key: 'breach_prevention_value', label: '侵害防止価値 (円)', type: 'number' },
    { key: 'operational_savings', label: '運用効率化 (円)', type: 'number' },
    { key: 'compliance_value', label: 'コンプライアンス価値 (円)', type: 'number' },
    { key: 'sort_order', label: '並び順', type: 'number' },
  ]
  return (
    <div className="space-y-3">
      <p className="text-falcon-muted text-xs">
        ROI% = (侵害防止 + 運用効率化 + コンプラ) × 100 / 年間投資。
        カテゴリキーに <code>overall</code> は使用できません（集計用の予約キー）。
      </p>
      {editRows.map(r => (
        <Row key={r.category} item={r} fields={fields} idKey="category"
          path={`/api/v1/admin/capacity-planning/roi/${encodeURIComponent(r.category)}`}
          onChanged={onChanged} />
      ))}
      <AddRow<Row> fields={fields}
        initial={{ category: '', label: '', sub_label: '', annual_investment: 0, breach_prevention_value: 0, operational_savings: 0, compliance_value: 0, sort_order: 0 }}
        path="/api/v1/admin/capacity-planning/roi" onAdded={onChanged} />
    </div>
  )
}

// ── Drawer shell ──────────────────────────────────────────────────

export default function AdminDrawer({ open, onClose }: { open: boolean; onClose: () => void }) {
  const [section, setSection] = useState<SectionKey>('planning-targets')
  if (!open) return null

  return (
    <div className="fixed inset-0 z-50 flex" onClick={onClose}>
      <div className="flex-1 bg-black/60 backdrop-blur-xs" />
      <div
        className="w-full max-w-2xl h-full bg-falcon-surface border-l border-falcon-border shadow-2xl flex flex-col"
        onClick={e => e.stopPropagation()}
      >
        <div className="flex items-center justify-between px-5 py-4 border-b border-falcon-border">
          <h2 className="text-white font-semibold">キャパシティ計画データ管理</h2>
          <button onClick={onClose} className="p-1.5 rounded-sm hover:bg-falcon-border text-falcon-muted">
            <X className="w-4 h-4" />
          </button>
        </div>

        <div className="flex gap-1 px-5 pt-3 border-b border-falcon-border overflow-x-auto">
          {SECTIONS.map(s => (
            <button
              key={s.key}
              onClick={() => setSection(s.key)}
              className={`px-3 py-2 text-xs whitespace-nowrap border-b-2 ${section === s.key ? 'border-falcon-red text-white' : 'border-transparent text-falcon-muted hover:text-white'}`}
            >
              {s.label}
            </button>
          ))}
        </div>

        <div className="flex-1 overflow-y-auto p-5">
          {section === 'planning-targets' && <PlanningTargetsEditor />}
          {section === 'storage'          && <StorageEditor />}
          {section === 'roi'              && <ROIEditor />}
          {section === 'workforce'        && <AnalystsEditor />}
          {section === 'resources'        && <LicensesEditor />}
          {section === 'budget'           && <BudgetEditor />}
          {section === 'planned-hires'    && <PlannedHiresEditor />}
          {section === 'tech-debt'        && <TechDebtEditor />}
          {section === 'oncall-shifts'    && <OncallEditor />}
        </div>
      </div>
    </div>
  )
}

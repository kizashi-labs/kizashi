'use client'

import { useState } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { useRouter } from 'next/navigation'
import { apiFetch } from '@/lib/api'
import {
  Plus,
  ChevronRight,
  FileText,
  Pencil,
  Trash2,
  Eye,
  PlayCircle,
  Loader2,
  XCircle,
  CheckCircle2,
  GripVertical,
  X,
  ChevronDown,
} from 'lucide-react'

// ─── Types ────────────────────────────────────────────────────────────────────

type ReportFormat = 'pdf' | 'html' | 'csv'

interface TemplateSection {
  type: string
  title: string
  config: Record<string, unknown>
}

interface ReportTemplate {
  id: string
  name: string
  description: string
  sections: TemplateSection[]
  variables: Record<string, unknown>
  format: ReportFormat
  enabled: boolean
  created_at: string
  updated_at: string
}

interface PreviewSection {
  type: string
  title: string
  content: unknown
}

interface PreviewResult {
  template_id: string
  template_name: string
  format: string
  generated_at: string
  sections: PreviewSection[]
  note: string
}

// ─── Section types available in the builder ──────────────────────────────────

const SECTION_TYPES: { value: string; label: string; description: string }[] = [
  { value: 'summary',           label: 'Executive Summary',   description: 'High-level metrics overview' },
  { value: 'alert_table',       label: 'Alert Table',         description: 'Tabular list of security alerts' },
  { value: 'incident_list',     label: 'Incident List',       description: 'Open and recent incidents' },
  { value: 'agent_overview',    label: 'Agent Overview',      description: 'Endpoint health and coverage' },
  { value: 'threat_stats',      label: 'Threat Statistics',   description: 'Top threats and MITRE coverage' },
  { value: 'compliance_status', label: 'Compliance Status',   description: 'Framework compliance scores' },
  { value: 'chart',             label: 'Alert Trend Chart',   description: 'Time-series alert chart' },
  { value: 'custom_text',       label: 'Custom Text',         description: 'Custom narrative block' },
]

const FORMAT_COLORS: Record<ReportFormat, string> = {
  pdf:  'bg-red-500/10  text-red-400  border-red-500/20',
  html: 'bg-blue-500/10 text-blue-400 border-blue-500/20',
  csv:  'bg-emerald-500/10 text-emerald-400 border-emerald-500/20',
}

// ─── Helpers ──────────────────────────────────────────────────────────────────

function formatDate(iso: string): string {
  try {
    return new Date(iso).toLocaleDateString('en-US', { month: 'short', day: 'numeric', year: 'numeric' })
  } catch {
    return iso
  }
}

// ─── Shared UI ────────────────────────────────────────────────────────────────

function FieldLabel({ children }: { children: React.ReactNode }) {
  return (
    <label className="block text-xs font-medium text-[#7d92b0] mb-1.5 uppercase tracking-wide">
      {children}
    </label>
  )
}

function TextInput({
  value,
  onChange,
  placeholder,
  disabled = false,
}: {
  value: string
  onChange: (v: string) => void
  placeholder?: string
  disabled?: boolean
}) {
  return (
    <input
      type="text"
      value={value}
      onChange={e => onChange(e.target.value)}
      placeholder={placeholder}
      disabled={disabled}
      className="w-full bg-[#070d19] border border-[#1e2d42] rounded-lg px-3 py-2.5 text-sm
                 text-[#e2e8f4] placeholder-[#3d5068]
                 focus:outline-none focus:border-[#e8002d]/60 focus:ring-1 focus:ring-[#e8002d]/20
                 disabled:opacity-40 transition-colors"
    />
  )
}

function TextArea({
  value,
  onChange,
  placeholder,
  rows = 3,
}: {
  value: string
  onChange: (v: string) => void
  placeholder?: string
  rows?: number
}) {
  return (
    <textarea
      value={value}
      onChange={e => onChange(e.target.value)}
      placeholder={placeholder}
      rows={rows}
      className="w-full bg-[#070d19] border border-[#1e2d42] rounded-lg px-3 py-2.5 text-sm
                 text-[#e2e8f4] placeholder-[#3d5068] resize-none
                 focus:outline-none focus:border-[#e8002d]/60 focus:ring-1 focus:ring-[#e8002d]/20
                 transition-colors"
    />
  )
}

// ─── Template Card ────────────────────────────────────────────────────────────

function TemplateCard({
  template,
  onEdit,
  onDelete,
  onPreview,
  onGenerate,
}: {
  template: ReportTemplate
  onEdit: () => void
  onDelete: () => void
  onPreview: () => void
  onGenerate: () => void
}) {
  return (
    <div className="bg-[#0d1220] rounded-xl border border-[#1e2d42] overflow-hidden hover:border-[#2a3d5a] transition-colors group">
      <div className="p-5">
        {/* Header row */}
        <div className="flex items-start justify-between gap-3 mb-3">
          <div className="flex items-start gap-3">
            <div className="w-9 h-9 rounded-lg bg-[#070d19] border border-[#1e2d42] flex items-center justify-center flex-shrink-0 mt-0.5">
              <FileText className="w-4 h-4 text-[#7d92b0]" />
            </div>
            <div>
              <h3 className="text-sm font-semibold text-white group-hover:text-[#e8002d] transition-colors">
                {template.name}
              </h3>
              {template.description && (
                <p className="text-xs text-[#7d92b0] mt-0.5 line-clamp-2">{template.description}</p>
              )}
            </div>
          </div>
          <span
            className={`text-xs font-medium px-2 py-0.5 rounded border uppercase flex-shrink-0 ${
              FORMAT_COLORS[template.format] ?? FORMAT_COLORS.pdf
            }`}
          >
            {template.format}
          </span>
        </div>

        {/* Meta */}
        <div className="flex items-center gap-4 text-xs text-[#7d92b0] mb-4">
          <span>{template.sections.length} section{template.sections.length !== 1 ? 's' : ''}</span>
          <span>·</span>
          <span>Updated {formatDate(template.updated_at)}</span>
        </div>

        {/* Section pills */}
        {template.sections.length > 0 && (
          <div className="flex flex-wrap gap-1.5 mb-4">
            {template.sections.slice(0, 4).map((sec, idx) => (
              <span
                key={idx}
                className="text-xs px-2 py-0.5 rounded-full bg-[#070d19] border border-[#1e2d42] text-[#7d92b0]"
              >
                {sec.title}
              </span>
            ))}
            {template.sections.length > 4 && (
              <span className="text-xs px-2 py-0.5 rounded-full bg-[#070d19] border border-[#1e2d42] text-[#7d92b0]">
                +{template.sections.length - 4} more
              </span>
            )}
          </div>
        )}

        {/* Actions */}
        <div className="flex items-center gap-2 pt-2 border-t border-[#1e2d42]">
          <button
            onClick={onPreview}
            className="flex items-center gap-1.5 px-3 py-1.5 text-xs font-medium rounded-lg
                       bg-[#070d19] border border-[#1e2d42] text-[#7d92b0]
                       hover:border-[#7d92b0]/50 hover:text-[#e2e8f4] transition-all"
          >
            <Eye className="w-3.5 h-3.5" />
            Preview
          </button>
          <button
            onClick={onGenerate}
            className="flex items-center gap-1.5 px-3 py-1.5 text-xs font-medium rounded-lg
                       bg-[#e8002d]/10 border border-[#e8002d]/30 text-[#e8002d]
                       hover:bg-[#e8002d]/20 hover:border-[#e8002d]/50 transition-all"
          >
            <PlayCircle className="w-3.5 h-3.5" />
            Generate
          </button>
          <div className="ml-auto flex items-center gap-1">
            <button
              onClick={onEdit}
              className="p-1.5 rounded-lg text-[#7d92b0] hover:text-[#e2e8f4] hover:bg-[#1e2d42] transition-all"
            >
              <Pencil className="w-3.5 h-3.5" />
            </button>
            <button
              onClick={onDelete}
              className="p-1.5 rounded-lg text-[#7d92b0] hover:text-red-400 hover:bg-red-900/10 transition-all"
            >
              <Trash2 className="w-3.5 h-3.5" />
            </button>
          </div>
        </div>
      </div>
    </div>
  )
}

// ─── Section Builder Row ──────────────────────────────────────────────────────

function SectionRow({
  section,
  index,
  total,
  onChange,
  onRemove,
  onMoveUp,
  onMoveDown,
}: {
  section: TemplateSection
  index: number
  total: number
  onChange: (s: TemplateSection) => void
  onRemove: () => void
  onMoveUp: () => void
  onMoveDown: () => void
}) {
  const typeInfo = SECTION_TYPES.find(t => t.value === section.type)

  return (
    <div className="flex items-center gap-2 bg-[#070d19] border border-[#1e2d42] rounded-lg px-3 py-2.5 group">
      <GripVertical className="w-4 h-4 text-[#3d5068] flex-shrink-0 cursor-grab" />
      <div className="flex-1 min-w-0">
        <p className="text-sm font-medium text-[#e2e8f4] truncate">
          {typeInfo?.label ?? section.type}
        </p>
        <p className="text-xs text-[#7d92b0] truncate">{section.title}</p>
      </div>
      <div className="flex items-center gap-1 opacity-0 group-hover:opacity-100 transition-opacity">
        <button
          onClick={onMoveUp}
          disabled={index === 0}
          className="p-1 rounded text-[#7d92b0] hover:text-[#e2e8f4] disabled:opacity-30 disabled:cursor-not-allowed"
        >
          ▲
        </button>
        <button
          onClick={onMoveDown}
          disabled={index === total - 1}
          className="p-1 rounded text-[#7d92b0] hover:text-[#e2e8f4] disabled:opacity-30 disabled:cursor-not-allowed"
        >
          ▼
        </button>
        <button
          onClick={onRemove}
          className="p-1 rounded text-[#7d92b0] hover:text-red-400 transition-colors"
        >
          <X className="w-3.5 h-3.5" />
        </button>
      </div>
    </div>
  )
}

// ─── Template Editor Modal ────────────────────────────────────────────────────

function TemplateEditorModal({
  initial,
  onClose,
  onSaved,
}: {
  initial?: ReportTemplate
  onClose: () => void
  onSaved: () => void
}) {
  const isEditing = !!initial

  const [name, setName] = useState(initial?.name ?? '')
  const [description, setDescription] = useState(initial?.description ?? '')
  const [format, setFormat] = useState<ReportFormat>(initial?.format ?? 'pdf')
  const [sections, setSections] = useState<TemplateSection[]>(initial?.sections ?? [])
  const [addTypeOpen, setAddTypeOpen] = useState(false)
  const [error, setError] = useState<string | null>(null)

  const saveMutation = useMutation({
    mutationFn: () => {
      const body = { name, description, format, sections, variables: {}, enabled: true }
      if (isEditing) {
        return apiFetch(`/api/v1/report-templates/${initial!.id}`, {
          method: 'PUT',
          body: JSON.stringify(body),
        })
      }
      return apiFetch('/api/v1/report-templates', {
        method: 'POST',
        body: JSON.stringify(body),
      })
    },
    onSuccess: () => onSaved(),
    onError: (err: unknown) => {
      setError(err instanceof Error ? err.message : 'Failed to save template')
    },
  })

  const addSection = (type: string) => {
    const typeInfo = SECTION_TYPES.find(t => t.value === type)
    setSections(prev => [
      ...prev,
      { type, title: typeInfo?.label ?? type, config: {} },
    ])
    setAddTypeOpen(false)
  }

  const removeSection = (idx: number) =>
    setSections(prev => prev.filter((_, i) => i !== idx))

  const moveSection = (idx: number, dir: -1 | 1) => {
    const target = idx + dir
    if (target < 0 || target >= sections.length) return
    const copy = [...sections]
    ;[copy[idx], copy[target]] = [copy[target], copy[idx]]
    setSections(copy)
  }

  const updateSection = (idx: number, s: TemplateSection) =>
    setSections(prev => prev.map((item, i) => (i === idx ? s : item)))

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4">
      <div className="absolute inset-0 bg-black/70 backdrop-blur-sm" onClick={onClose} />
      <div className="relative bg-[#0d1220] border border-[#1e2d42] rounded-2xl w-full max-w-2xl max-h-[90vh] overflow-hidden flex flex-col">
        {/* Header */}
        <div className="flex items-center justify-between px-6 py-4 border-b border-[#1e2d42]">
          <h2 className="text-base font-semibold text-white">
            {isEditing ? 'Edit Template' : 'Create Template'}
          </h2>
          <button
            onClick={onClose}
            className="p-1.5 rounded-lg text-[#7d92b0] hover:text-white hover:bg-[#1e2d42] transition-all"
          >
            <X className="w-4 h-4" />
          </button>
        </div>

        {/* Body */}
        <div className="flex-1 overflow-y-auto p-6 space-y-5">
          {/* Name */}
          <div>
            <FieldLabel>Template Name *</FieldLabel>
            <TextInput value={name} onChange={setName} placeholder="e.g. Weekly Security Report" />
          </div>

          {/* Description */}
          <div>
            <FieldLabel>説明</FieldLabel>
            <TextArea
              value={description}
              onChange={setDescription}
              placeholder="このレポートテンプレートの説明..."
            />
          </div>

          {/* Format */}
          <div>
            <FieldLabel>出力フォーマット</FieldLabel>
            <div className="flex gap-2">
              {(['pdf', 'html', 'csv'] as ReportFormat[]).map(f => (
                <button
                  key={f}
                  onClick={() => setFormat(f)}
                  className={`px-4 py-2 rounded-lg text-sm font-medium border uppercase transition-all ${
                    format === f
                      ? FORMAT_COLORS[f]
                      : 'bg-[#070d19] border-[#1e2d42] text-[#7d92b0] hover:border-[#7d92b0]/40'
                  }`}
                >
                  {f}
                </button>
              ))}
            </div>
          </div>

          {/* Section Builder */}
          <div>
            <FieldLabel>Sections ({sections.length})</FieldLabel>
            <div className="space-y-2 mb-3">
              {sections.length === 0 && (
                <p className="text-xs text-[#3d5068] text-center py-4 border border-dashed border-[#1e2d42] rounded-lg">
                  No sections yet. Add sections below.
                </p>
              )}
              {sections.map((sec, idx) => (
                <SectionRow
                  key={`${sec.type}-${idx}`}
                  section={sec}
                  index={idx}
                  total={sections.length}
                  onChange={s => updateSection(idx, s)}
                  onRemove={() => removeSection(idx)}
                  onMoveUp={() => moveSection(idx, -1)}
                  onMoveDown={() => moveSection(idx, 1)}
                />
              ))}
            </div>

            {/* Add section dropdown */}
            <div className="relative">
              <button
                onClick={() => setAddTypeOpen(prev => !prev)}
                className="flex items-center gap-2 text-sm font-medium px-3 py-2 rounded-lg w-full
                           border border-dashed border-[#1e2d42] text-[#7d92b0]
                           hover:border-[#7d92b0]/50 hover:text-[#e2e8f4] transition-all justify-center"
              >
                <Plus className="w-4 h-4" />
                Add Section
                <ChevronDown className={`w-4 h-4 transition-transform ${addTypeOpen ? 'rotate-180' : ''}`} />
              </button>
              {addTypeOpen && (
                <div className="absolute top-full left-0 right-0 mt-1 z-10 bg-[#0d1220] border border-[#1e2d42] rounded-xl overflow-hidden shadow-2xl">
                  {SECTION_TYPES.map(t => (
                    <button
                      key={t.value}
                      onClick={() => addSection(t.value)}
                      className="w-full flex items-start gap-3 px-4 py-2.5 hover:bg-[#1e2d42] transition-colors text-left"
                    >
                      <div>
                        <p className="text-sm font-medium text-[#e2e8f4]">{t.label}</p>
                        <p className="text-xs text-[#7d92b0]">{t.description}</p>
                      </div>
                    </button>
                  ))}
                </div>
              )}
            </div>
          </div>

          {/* Error */}
          {error && (
            <div className="flex items-center gap-2 bg-red-900/20 border border-red-700/40 rounded-lg px-4 py-3">
              <XCircle className="w-4 h-4 text-red-400 flex-shrink-0" />
              <p className="text-sm text-red-300">{error}</p>
            </div>
          )}
        </div>

        {/* Footer */}
        <div className="px-6 py-4 border-t border-[#1e2d42] flex items-center justify-end gap-3">
          <button
            onClick={onClose}
            className="px-4 py-2 text-sm text-[#7d92b0] hover:text-[#e2e8f4] transition-colors"
          >
            Cancel
          </button>
          <button
            onClick={() => saveMutation.mutate()}
            disabled={!name.trim() || saveMutation.isPending}
            className="flex items-center gap-2 px-5 py-2 text-sm font-medium rounded-lg
                       bg-[#e8002d] text-white hover:bg-[#e8002d]/90
                       disabled:opacity-40 disabled:cursor-not-allowed transition-all"
          >
            {saveMutation.isPending ? (
              <Loader2 className="w-4 h-4 animate-spin" />
            ) : (
              <CheckCircle2 className="w-4 h-4" />
            )}
            {saveMutation.isPending ? 'Saving...' : isEditing ? 'Save Changes' : 'Create Template'}
          </button>
        </div>
      </div>
    </div>
  )
}

// ─── Preview Modal ────────────────────────────────────────────────────────────

function PreviewModal({
  template,
  onClose,
}: {
  template: ReportTemplate
  onClose: () => void
}) {
  const { data, isLoading, isError } = useQuery({
    queryKey: ['report-template-preview', template.id],
    queryFn: () =>
      apiFetch(`/api/v1/report-templates/${template.id}/preview`, {
        method: 'POST',
        body: '{}',
      }) as Promise<PreviewResult>,
  })

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4">
      <div className="absolute inset-0 bg-black/70 backdrop-blur-sm" onClick={onClose} />
      <div className="relative bg-[#0d1220] border border-[#1e2d42] rounded-2xl w-full max-w-3xl max-h-[90vh] overflow-hidden flex flex-col">
        {/* Header */}
        <div className="flex items-center justify-between px-6 py-4 border-b border-[#1e2d42]">
          <div>
            <h2 className="text-base font-semibold text-white">Preview: {template.name}</h2>
            <p className="text-xs text-[#7d92b0] mt-0.5">Mock data — actual content generated at runtime</p>
          </div>
          <button
            onClick={onClose}
            className="p-1.5 rounded-lg text-[#7d92b0] hover:text-white hover:bg-[#1e2d42] transition-all"
          >
            <X className="w-4 h-4" />
          </button>
        </div>

        {/* Body */}
        <div className="flex-1 overflow-y-auto p-6">
          {isLoading && (
            <div className="flex items-center justify-center py-16">
              <Loader2 className="w-6 h-6 animate-spin text-[#7d92b0]" />
            </div>
          )}
          {isError && (
            <div className="flex items-center gap-2 bg-red-900/20 border border-red-700/40 rounded-lg px-4 py-3">
              <XCircle className="w-4 h-4 text-red-400 flex-shrink-0" />
              <p className="text-sm text-red-300">Failed to load preview. Check server connection.</p>
            </div>
          )}
          {data && (
            <div className="space-y-5">
              {/* Meta bar */}
              <div className="flex items-center gap-4 text-xs text-[#7d92b0] bg-[#070d19] border border-[#1e2d42] rounded-lg px-4 py-2.5">
                <span>Format: <span className="text-[#e2e8f4] uppercase">{data.format}</span></span>
                <span>·</span>
                <span>Sections: <span className="text-[#e2e8f4]">{data.sections.length}</span></span>
                <span>·</span>
                <span>Generated: <span className="text-[#e2e8f4]">{new Date(data.generated_at).toLocaleTimeString()}</span></span>
              </div>

              {/* Sections */}
              {data.sections.map((sec, idx) => (
                <div key={idx} className="bg-[#070d19] border border-[#1e2d42] rounded-xl overflow-hidden">
                  <div className="px-4 py-3 border-b border-[#1e2d42] flex items-center gap-2">
                    <span className="w-5 h-5 flex items-center justify-center rounded bg-[#1e2d42] text-xs text-[#7d92b0] font-mono">
                      {idx + 1}
                    </span>
                    <span className="text-sm font-medium text-white">{sec.title}</span>
                    <span className="ml-auto text-xs text-[#3d5068]">{sec.type}</span>
                  </div>
                  <div className="p-4">
                    <pre className="text-xs text-[#7d92b0] overflow-auto max-h-48 leading-relaxed">
                      {JSON.stringify(sec.content, null, 2)}
                    </pre>
                  </div>
                </div>
              ))}

              {/* Note */}
              {data.note && (
                <p className="text-xs text-[#3d5068] text-center">{data.note}</p>
              )}
            </div>
          )}
        </div>
      </div>
    </div>
  )
}

// ─── Delete Confirm ───────────────────────────────────────────────────────────

function DeleteConfirmModal({
  template,
  onClose,
  onDeleted,
}: {
  template: ReportTemplate
  onClose: () => void
  onDeleted: () => void
}) {
  const deleteMutation = useMutation({
    mutationFn: () =>
      apiFetch(`/api/v1/report-templates/${template.id}`, { method: 'DELETE' }),
    onSuccess: () => onDeleted(),
  })

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4">
      <div className="absolute inset-0 bg-black/70 backdrop-blur-sm" onClick={onClose} />
      <div className="relative bg-[#0d1220] border border-[#1e2d42] rounded-2xl w-full max-w-md p-6">
        <h2 className="text-base font-semibold text-white mb-2">Delete Template</h2>
        <p className="text-sm text-[#7d92b0] mb-6">
          Are you sure you want to delete <span className="text-[#e2e8f4] font-medium">{template.name}</span>?
          This action cannot be undone.
        </p>
        {deleteMutation.isError && (
          <div className="mb-4 flex items-center gap-2 bg-red-900/20 border border-red-700/40 rounded-lg px-3 py-2.5">
            <XCircle className="w-4 h-4 text-red-400" />
            <p className="text-xs text-red-300">Failed to delete template.</p>
          </div>
        )}
        <div className="flex items-center justify-end gap-3">
          <button
            onClick={onClose}
            className="px-4 py-2 text-sm text-[#7d92b0] hover:text-[#e2e8f4] transition-colors"
          >
            Cancel
          </button>
          <button
            onClick={() => deleteMutation.mutate()}
            disabled={deleteMutation.isPending}
            className="flex items-center gap-2 px-4 py-2 text-sm font-medium rounded-lg
                       bg-red-600 text-white hover:bg-red-700
                       disabled:opacity-40 disabled:cursor-not-allowed transition-all"
          >
            {deleteMutation.isPending ? <Loader2 className="w-4 h-4 animate-spin" /> : <Trash2 className="w-4 h-4" />}
            {deleteMutation.isPending ? 'Deleting...' : 'Delete'}
          </button>
        </div>
      </div>
    </div>
  )
}

// ─── Page ─────────────────────────────────────────────────────────────────────

export default function ReportTemplatesPage() {
  const queryClient = useQueryClient()
  const router = useRouter()

  const [editorOpen, setEditorOpen]     = useState(false)
  const [editTarget, setEditTarget]     = useState<ReportTemplate | undefined>()
  const [previewTarget, setPreviewTarget] = useState<ReportTemplate | null>(null)
  const [deleteTarget, setDeleteTarget] = useState<ReportTemplate | null>(null)

  const { data, isLoading, isError } = useQuery({
    queryKey: ['report-templates'],
    queryFn: () =>
      apiFetch('/api/v1/report-templates') as Promise<{ data: ReportTemplate[]; total: number }>,
  })

  const templates = data?.data ?? []

  const handleSaved = () => {
    queryClient.invalidateQueries({ queryKey: ['report-templates'] })
    setEditorOpen(false)
    setEditTarget(undefined)
  }

  const handleDeleted = () => {
    queryClient.invalidateQueries({ queryKey: ['report-templates'] })
    setDeleteTarget(null)
  }

  const openCreate = () => {
    setEditTarget(undefined)
    setEditorOpen(true)
  }

  const openEdit = (t: ReportTemplate) => {
    setEditTarget(t)
    setEditorOpen(true)
  }

  const navigateToGenerate = (t: ReportTemplate) => {
    router.push(`/reports?template=${t.id}`)
  }

  return (
    <div className="min-h-screen bg-[#070d19] p-6">
      {/* Header */}
      <div className="mb-8">
        <div className="flex items-center gap-1.5 text-xs text-[#7d92b0] mb-4">
          <span>レポート</span>
          <ChevronRight className="w-3.5 h-3.5" />
          <span className="text-[#e2e8f4]">テンプレート</span>
        </div>

        <div className="flex items-start justify-between gap-4">
          <div>
            <h1 className="text-xl font-bold text-white">Report Templates</h1>
            <p className="text-sm text-[#7d92b0] mt-1">
              Create and manage reusable report templates with configurable sections
            </p>
          </div>
          <button
            onClick={openCreate}
            className="flex items-center gap-2 px-4 py-2 text-sm font-medium rounded-lg
                       bg-[#e8002d] text-white hover:bg-[#e8002d]/90 transition-all flex-shrink-0"
          >
            <Plus className="w-4 h-4" />
            New Template
          </button>
        </div>
      </div>

      {/* Content */}
      {isLoading && (
        <div className="flex items-center justify-center py-20">
          <Loader2 className="w-6 h-6 animate-spin text-[#7d92b0]" />
        </div>
      )}

      {isError && (
        <div className="flex items-center gap-3 bg-red-900/20 border border-red-700/40 rounded-xl px-5 py-4 max-w-lg">
          <XCircle className="w-5 h-5 text-red-400 flex-shrink-0" />
          <div>
            <p className="text-sm font-medium text-red-300">Failed to load templates</p>
            <p className="text-xs text-[#7d92b0] mt-0.5">Check server connection and try again.</p>
          </div>
        </div>
      )}

      {!isLoading && !isError && templates.length === 0 && (
        <div className="flex flex-col items-center justify-center py-20 text-center">
          <div className="w-14 h-14 rounded-2xl bg-[#0d1220] border border-[#1e2d42] flex items-center justify-center mb-4">
            <FileText className="w-6 h-6 text-[#7d92b0]" />
          </div>
          <p className="text-sm font-medium text-[#e2e8f4] mb-1">No templates yet</p>
          <p className="text-xs text-[#7d92b0] mb-6 max-w-xs">
            Create your first report template to start generating structured security reports.
          </p>
          <button
            onClick={openCreate}
            className="flex items-center gap-2 px-4 py-2 text-sm font-medium rounded-lg
                       bg-[#e8002d] text-white hover:bg-[#e8002d]/90 transition-all"
          >
            <Plus className="w-4 h-4" />
            Create Template
          </button>
        </div>
      )}

      {!isLoading && !isError && templates.length > 0 && (
        <div className="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-3 gap-4">
          {templates.map(t => (
            <TemplateCard
              key={t.id}
              template={t}
              onEdit={() => openEdit(t)}
              onDelete={() => setDeleteTarget(t)}
              onPreview={() => setPreviewTarget(t)}
              onGenerate={() => navigateToGenerate(t)}
            />
          ))}
        </div>
      )}

      {/* Modals */}
      {editorOpen && (
        <TemplateEditorModal
          initial={editTarget}
          onClose={() => { setEditorOpen(false); setEditTarget(undefined) }}
          onSaved={handleSaved}
        />
      )}
      {previewTarget && (
        <PreviewModal template={previewTarget} onClose={() => setPreviewTarget(null)} />
      )}
      {deleteTarget && (
        <DeleteConfirmModal
          template={deleteTarget}
          onClose={() => setDeleteTarget(null)}
          onDeleted={handleDeleted}
        />
      )}
    </div>
  )
}

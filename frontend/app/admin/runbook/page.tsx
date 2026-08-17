'use client'

import { useState, useMemo, useRef, useEffect } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { apiFetch } from '@/lib/api'
import {
  BookOpen, Search, Plus, Edit2, Eye, Download, ChevronRight,
  ChevronDown, X, Save, Send, Tag, Clock, User, Hash,
  FileText, ArrowUp, ArrowDown, Trash2, CheckSquare, Square,
  RotateCcw, GitBranch, AlertTriangle, Shield, Wrench, Users,
  GraduationCap, Zap, List, AlignLeft
} from 'lucide-react'


// ── Types ──────────────────────────────────────────────────────────────────────

interface RunbookSection {
  id: string
  heading: string
  content: string
  steps?: string[]
}

interface RunbookVersion {
  version: string
  updated_at: string
  author: string
  changes: string
}

interface Runbook {
  id: string
  title: string
  category: 'incident_response' | 'threat_hunting' | 'maintenance' | 'onboarding' | 'emergency'
  description: string
  author: string
  author_initials: string
  version: string
  last_updated: string
  tags: string[]
  sections: RunbookSection[]
  versions: RunbookVersion[]
  related_ids?: string[]
  status: 'published' | 'draft'
}

// ── Constants ──────────────────────────────────────────────────────────────────

const CATEGORIES = [
  { key: 'all', label: 'すべて', icon: List },
  { key: 'incident_response', label: 'Incident Response', icon: AlertTriangle },
  { key: 'threat_hunting', label: 'Threat Hunting', icon: Search },
  { key: 'maintenance', label: 'Maintenance', icon: Wrench },
  { key: 'onboarding', label: 'Onboarding', icon: GraduationCap },
  { key: 'emergency', label: 'Emergency', icon: Zap },
] as const

const CATEGORY_COLORS: Record<string, string> = {
  incident_response: 'bg-red-900/40 text-red-400 border-red-800/50',
  threat_hunting: 'bg-purple-900/40 text-purple-400 border-purple-800/50',
  maintenance: 'bg-blue-900/40 text-blue-400 border-blue-800/50',
  onboarding: 'bg-green-900/40 text-green-400 border-green-800/50',
  emergency: 'bg-orange-900/40 text-orange-400 border-orange-800/50',
}

const CATEGORY_LABELS: Record<string, string> = {
  incident_response: 'Incident Response',
  threat_hunting: 'Threat Hunting',
  maintenance: 'Maintenance',
  onboarding: 'Onboarding',
  emergency: 'Emergency',
}

type ViewMode = 'list' | 'view' | 'edit'

// ── Sub-components ─────────────────────────────────────────────────────────────

function StepItem({ step, index }: { step: string; index: number }) {
  const [checked, setChecked] = useState(false)
  return (
    <li
      className={`flex items-start gap-3 p-3 rounded border cursor-pointer transition-all
        ${checked ? 'bg-green-900/20 border-green-800/40 opacity-70' : 'bg-falcon-surface border-falcon-border hover:border-[#2e4060]'}`}
      onClick={() => setChecked(!checked)}
    >
      <span className="shrink-0 mt-0.5">
        {checked
          ? <CheckSquare className="w-4 h-4 text-green-400" />
          : <Square className="w-4 h-4 text-falcon-subtle" />}
      </span>
      <span className="flex items-start gap-2">
        <span className="shrink-0 w-5 h-5 rounded-full bg-falcon-red/20 text-falcon-red text-[11px] font-bold flex items-center justify-center mt-0.5">
          {index + 1}
        </span>
        <span className={`text-sm ${checked ? 'line-through text-falcon-subtle' : 'text-[#c8d6e8]'}`}>{step}</span>
      </span>
    </li>
  )
}

function ArticleViewer({
  article,
  allArticles,
  onEdit,
}: {
  article: Runbook
  allArticles: Runbook[]
  onEdit: () => void
}) {
  const [activeVersion, setActiveVersion] = useState<string | null>(null)
  const [showVersionHistory, setShowVersionHistory] = useState(false)
  const sectionRefs = useRef<Record<string, HTMLElement | null>>({})

  const tocItems = article.sections.map(s => ({ id: s.id, heading: s.heading }))

  const related = allArticles.filter(a => article.related_ids?.includes(a.id))

  const scrollToSection = (id: string) => {
    sectionRefs.current[id]?.scrollIntoView({ behavior: 'smooth', block: 'start' })
  }

  return (
    <div className="flex gap-4 h-full">
      {/* Main content */}
      <div className="flex-1 overflow-y-auto space-y-6">
        {/* Header */}
        <div className="bg-falcon-surface border border-falcon-border rounded-lg p-5">
          <div className="flex items-start justify-between gap-4 mb-3">
            <h1 className="text-xl font-bold text-white">{article.title}</h1>
            <div className="flex gap-2 shrink-0">
              <button
                onClick={() => alert('PDF生成中... (モック)')}
                className="flex items-center gap-1.5 px-3 py-1.5 rounded-sm bg-falcon-border text-falcon-muted hover:bg-[#2e3d52] hover:text-white text-xs transition-colors"
              >
                <Download className="w-3.5 h-3.5" /> PDFでエクスポート
              </button>
              <button
                onClick={onEdit}
                className="flex items-center gap-1.5 px-3 py-1.5 rounded-sm bg-falcon-red/10 text-falcon-red hover:bg-falcon-red/20 text-xs transition-colors"
              >
                <Edit2 className="w-3.5 h-3.5" /> 編集
              </button>
            </div>
          </div>
          <div className="flex flex-wrap gap-3 text-xs text-falcon-muted">
            <span className={`px-2 py-0.5 rounded-sm border text-xs font-medium ${CATEGORY_COLORS[article.category]}`}>
              {CATEGORY_LABELS[article.category]}
            </span>
            <span className="flex items-center gap-1"><User className="w-3 h-3" /> {article.author}</span>
            <span className="flex items-center gap-1"><Hash className="w-3 h-3" /> v{article.version}</span>
            <span className="flex items-center gap-1"><Clock className="w-3 h-3" /> {article.last_updated}</span>
          </div>
          <p className="mt-3 text-sm text-falcon-muted">{article.description}</p>
          <div className="flex flex-wrap gap-1 mt-3">
            {article.tags.map(tag => (
              <span key={tag} className="px-2 py-0.5 bg-falcon-border text-falcon-muted rounded-sm text-xs">#{tag}</span>
            ))}
          </div>
        </div>

        {/* Sections */}
        {article.sections.map(section => (
          <div
            key={section.id}
            ref={el => { sectionRefs.current[section.id] = el }}
            className="bg-falcon-surface border border-falcon-border rounded-lg p-5"
          >
            <h2 className="text-base font-semibold text-white mb-3 flex items-center gap-2">
              <span className="w-1 h-4 bg-falcon-red rounded-full inline-block" />
              {section.heading}
            </h2>
            <p className="text-sm text-falcon-muted mb-3">{section.content}</p>
            {section.steps && (
              <ul className="space-y-2">
                {section.steps.map((step, i) => (
                  <StepItem key={i} step={step} index={i} />
                ))}
              </ul>
            )}
          </div>
        ))}

        {/* Version history */}
        <div className="bg-falcon-surface border border-falcon-border rounded-lg p-5">
          <button
            onClick={() => setShowVersionHistory(!showVersionHistory)}
            className="flex items-center gap-2 text-sm font-semibold text-white w-full"
          >
            <GitBranch className="w-4 h-4 text-falcon-red" />
            バージョン履歴
            {showVersionHistory ? <ChevronDown className="w-4 h-4 ml-auto" /> : <ChevronRight className="w-4 h-4 ml-auto" />}
          </button>
          {showVersionHistory && (
            <div className="mt-4 space-y-2">
              {article.versions.map(v => (
                <div
                  key={v.version}
                  onClick={() => setActiveVersion(activeVersion === v.version ? null : v.version)}
                  className={`p-3 rounded-sm border cursor-pointer transition-colors ${activeVersion === v.version ? 'border-falcon-red/40 bg-falcon-red/5' : 'border-falcon-border hover:border-[#2e4060]'}`}
                >
                  <div className="flex items-center justify-between">
                    <span className="text-xs font-mono font-bold text-falcon-red">v{v.version}</span>
                    <span className="text-xs text-falcon-subtle">{v.updated_at}</span>
                    <span className="text-xs text-falcon-muted">{v.author}</span>
                  </div>
                  {activeVersion === v.version && (
                    <p className="mt-2 text-xs text-[#c8d6e8] border-t border-falcon-border pt-2">{v.changes}</p>
                  )}
                </div>
              ))}
            </div>
          )}
        </div>

        {/* Related articles */}
        {related.length > 0 && (
          <div className="bg-falcon-surface border border-falcon-border rounded-lg p-5">
            <h3 className="text-sm font-semibold text-white mb-3 flex items-center gap-2">
              <FileText className="w-4 h-4 text-falcon-red" /> 関連手順書
            </h3>
            <div className="space-y-2">
              {related.map(r => (
                <div key={r.id} className="flex items-center gap-3 p-2 rounded-sm border border-falcon-border hover:border-[#2e4060]">
                  <span className={`px-1.5 py-0.5 rounded-sm border text-[10px] ${CATEGORY_COLORS[r.category]}`}>
                    {CATEGORY_LABELS[r.category]}
                  </span>
                  <span className="text-sm text-[#c8d6e8]">{r.title}</span>
                  <span className="ml-auto text-xs text-falcon-subtle">v{r.version}</span>
                </div>
              ))}
            </div>
          </div>
        )}
      </div>

      {/* Table of contents sidebar */}
      <div className="w-48 shrink-0">
        <div className="sticky top-0 bg-falcon-surface border border-falcon-border rounded-lg p-3">
          <p className="text-xs font-semibold text-falcon-muted uppercase tracking-wider mb-3">目次</p>
          <ul className="space-y-1">
            {tocItems.map(item => (
              <li key={item.id}>
                <button
                  onClick={() => scrollToSection(item.id)}
                  className="w-full text-left text-xs text-falcon-muted hover:text-white py-1 px-2 rounded-sm hover:bg-falcon-border transition-colors"
                >
                  {item.heading}
                </button>
              </li>
            ))}
          </ul>
        </div>
      </div>
    </div>
  )
}

function ArticleEditor({
  article,
  onSave,
  onCancel,
}: {
  article: Runbook | null
  onSave: (data: Partial<Runbook>) => void
  onCancel: () => void
}) {
  const [title, setTitle] = useState(article?.title ?? '')
  const [description, setDescription] = useState(article?.description ?? '')
  const [category, setCategory] = useState<Runbook['category']>(article?.category ?? 'incident_response')
  const [tags, setTags] = useState(article?.tags.join(', ') ?? '')
  const [sections, setSections] = useState<RunbookSection[]>(article?.sections ?? [
    { id: 'new-1', heading: '概要', content: '' },
  ])
  const [preview, setPreview] = useState(false)
  const [tagInput, setTagInput] = useState('')

  const addSection = () => {
    setSections(prev => [...prev, { id: `s-${Date.now()}`, heading: '新しいセクション', content: '' }])
  }

  const removeSection = (id: string) => {
    setSections(prev => prev.filter(s => s.id !== id))
  }

  const moveSection = (id: string, dir: 'up' | 'down') => {
    setSections(prev => {
      const idx = prev.findIndex(s => s.id === id)
      if (dir === 'up' && idx === 0) return prev
      if (dir === 'down' && idx === prev.length - 1) return prev
      const next = [...prev]
      const swap = dir === 'up' ? idx - 1 : idx + 1
      ;[next[idx], next[swap]] = [next[swap], next[idx]]
      return next
    })
  }

  const updateSection = (id: string, field: keyof RunbookSection, value: string) => {
    setSections(prev => prev.map(s => s.id === id ? { ...s, [field]: value } : s))
  }

  const addStepToSection = (id: string) => {
    setSections(prev => prev.map(s => s.id === id ? { ...s, steps: [...(s.steps ?? []), '新しい手順'] } : s))
  }

  const updateStep = (sectionId: string, stepIdx: number, value: string) => {
    setSections(prev => prev.map(s => {
      if (s.id !== sectionId || !s.steps) return s
      const steps = [...s.steps]
      steps[stepIdx] = value
      return { ...s, steps }
    }))
  }

  const removeStep = (sectionId: string, stepIdx: number) => {
    setSections(prev => prev.map(s => {
      if (s.id !== sectionId || !s.steps) return s
      return { ...s, steps: s.steps.filter((_, i) => i !== stepIdx) }
    }))
  }

  return (
    <div className="flex flex-col h-full">
      {/* Editor toolbar */}
      <div className="flex items-center gap-3 mb-4 pb-4 border-b border-falcon-border">
        <button
          onClick={() => setPreview(!preview)}
          className={`flex items-center gap-1.5 px-3 py-1.5 rounded-sm text-xs transition-colors ${preview ? 'bg-falcon-border text-white' : 'text-falcon-muted hover:text-white'}`}
        >
          {preview ? <Edit2 className="w-3.5 h-3.5" /> : <Eye className="w-3.5 h-3.5" />}
          {preview ? '編集モード' : 'プレビュー'}
        </button>
        <div className="flex-1" />
        <button
          onClick={() => onSave({ title, description, category, tags: tags.split(',').map(t => t.trim()).filter(Boolean), sections, status: 'draft' })}
          className="flex items-center gap-1.5 px-4 py-1.5 rounded-sm bg-falcon-border text-falcon-muted hover:bg-[#2e3d52] hover:text-white text-xs transition-colors"
        >
          <Save className="w-3.5 h-3.5" /> 下書き保存
        </button>
        <button
          onClick={() => onSave({ title, description, category, tags: tags.split(',').map(t => t.trim()).filter(Boolean), sections, status: 'published' })}
          className="flex items-center gap-1.5 px-4 py-1.5 rounded-sm bg-falcon-red text-white hover:bg-[#c00025] text-xs transition-colors"
        >
          <Send className="w-3.5 h-3.5" /> 公開
        </button>
        <button onClick={onCancel} className="p-1.5 rounded-sm text-falcon-muted hover:text-white hover:bg-falcon-border transition-colors">
          <X className="w-4 h-4" />
        </button>
      </div>

      <div className="flex-1 overflow-y-auto space-y-4">
        {/* Metadata */}
        <div className="bg-falcon-surface border border-falcon-border rounded-lg p-4 space-y-3">
          <h3 className="text-xs font-semibold text-falcon-muted uppercase tracking-wider">メタデータ</h3>
          <div>
            <label className="text-xs text-falcon-muted mb-1 block">タイトル</label>
            <input
              value={title}
              onChange={e => setTitle(e.target.value)}
              className="w-full bg-[#070d19] border border-falcon-border rounded-sm px-3 py-2 text-white text-sm focus:outline-hidden focus:border-falcon-red/50"
              placeholder="手順書タイトル"
            />
          </div>
          <div className="grid grid-cols-2 gap-3">
            <div>
              <label className="text-xs text-falcon-muted mb-1 block">カテゴリ</label>
              <select
                value={category}
                onChange={e => setCategory(e.target.value as Runbook['category'])}
                className="w-full bg-[#070d19] border border-falcon-border rounded-sm px-3 py-2 text-white text-sm focus:outline-hidden focus:border-falcon-red/50"
              >
                <option value="incident_response">Incident Response</option>
                <option value="threat_hunting">Threat Hunting</option>
                <option value="maintenance">Maintenance</option>
                <option value="onboarding">Onboarding</option>
                <option value="emergency">Emergency</option>
              </select>
            </div>
            <div>
              <label className="text-xs text-falcon-muted mb-1 block">タグ（カンマ区切り）</label>
              <input
                value={tags}
                onChange={e => setTags(e.target.value)}
                className="w-full bg-[#070d19] border border-falcon-border rounded-sm px-3 py-2 text-white text-sm focus:outline-hidden focus:border-falcon-red/50"
                placeholder="tag1, tag2"
              />
            </div>
          </div>
          <div>
            <label className="text-xs text-falcon-muted mb-1 block">説明</label>
            <textarea
              value={description}
              onChange={e => setDescription(e.target.value)}
              rows={2}
              className="w-full bg-[#070d19] border border-falcon-border rounded-sm px-3 py-2 text-white text-sm focus:outline-hidden focus:border-falcon-red/50 resize-none"
              placeholder="手順書の概要..."
            />
          </div>
        </div>

        {/* Sections */}
        {sections.map((section, idx) => (
          <div key={section.id} className="bg-falcon-surface border border-falcon-border rounded-lg p-4 space-y-3">
            <div className="flex items-center gap-2">
              <span className="text-xs font-mono text-falcon-subtle">§{idx + 1}</span>
              <input
                value={section.heading}
                onChange={e => updateSection(section.id, 'heading', e.target.value)}
                className="flex-1 bg-transparent border-b border-falcon-border text-white text-sm font-semibold py-0.5 focus:outline-hidden focus:border-falcon-red/50"
              />
              <button onClick={() => moveSection(section.id, 'up')} className="p-1 text-falcon-subtle hover:text-falcon-muted"><ArrowUp className="w-3.5 h-3.5" /></button>
              <button onClick={() => moveSection(section.id, 'down')} className="p-1 text-falcon-subtle hover:text-falcon-muted"><ArrowDown className="w-3.5 h-3.5" /></button>
              <button onClick={() => removeSection(section.id)} className="p-1 text-falcon-subtle hover:text-red-400"><Trash2 className="w-3.5 h-3.5" /></button>
            </div>
            <textarea
              value={section.content}
              onChange={e => updateSection(section.id, 'content', e.target.value)}
              rows={3}
              className="w-full bg-[#070d19] border border-falcon-border rounded-sm px-3 py-2 text-[#c8d6e8] text-sm focus:outline-hidden focus:border-falcon-red/50 resize-y"
              placeholder="セクション内容..."
            />
            {/* Steps */}
            {section.steps && (
              <div className="space-y-2">
                <p className="text-xs text-falcon-muted font-semibold">手順ステップ</p>
                {section.steps.map((step, i) => (
                  <div key={i} className="flex items-center gap-2">
                    <span className="text-xs text-falcon-red font-bold w-5 text-center">{i + 1}</span>
                    <input
                      value={step}
                      onChange={e => updateStep(section.id, i, e.target.value)}
                      className="flex-1 bg-[#070d19] border border-falcon-border rounded-sm px-2 py-1 text-[#c8d6e8] text-xs focus:outline-hidden focus:border-falcon-red/50"
                    />
                    <button onClick={() => removeStep(section.id, i)} className="p-1 text-falcon-subtle hover:text-red-400"><X className="w-3 h-3" /></button>
                  </div>
                ))}
              </div>
            )}
            <button
              onClick={() => addStepToSection(section.id)}
              className="flex items-center gap-1 text-xs text-falcon-subtle hover:text-falcon-muted transition-colors"
            >
              <Plus className="w-3 h-3" /> ステップを追加
            </button>
          </div>
        ))}

        <button
          onClick={addSection}
          className="w-full flex items-center justify-center gap-2 p-3 rounded-sm border border-dashed border-falcon-border text-falcon-subtle hover:border-falcon-red/40 hover:text-falcon-red transition-colors text-sm"
        >
          <Plus className="w-4 h-4" /> セクションを追加
        </button>
      </div>
    </div>
  )
}

// ── Main Page ──────────────────────────────────────────────────────────────────

export default function RunbookPage() {
  const queryClient = useQueryClient()
  const [selectedCategory, setSelectedCategory] = useState<string>('all')
  const [searchQuery, setSearchQuery] = useState('')
  const [selectedArticle, setSelectedArticle] = useState<Runbook | null>(null)
  const [viewMode, setViewMode] = useState<ViewMode>('list')

  const { data: runbooks } = useQuery<Runbook[]>({
    queryKey: ['runbooks'],
    queryFn: () => apiFetch('/api/v1/admin/runbooks'),
    staleTime: 30_000,
    select: d => d ?? [],
  })

  const articles = runbooks ?? []

  const saveMutation = useMutation({
    mutationFn: (data: Partial<Runbook>) => {
      if (selectedArticle?.id) {
        return apiFetch(`/api/v1/admin/runbooks/${selectedArticle.id}`, {
          method: 'PUT',
          body: JSON.stringify(data),
        })
      }
      return apiFetch('/api/v1/admin/runbooks', { method: 'POST', body: JSON.stringify(data) })
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['runbooks'] })
      setViewMode('list')
    },
    onError: () => setViewMode('list'),
  })

  const filteredArticles = useMemo(() => {
    return articles.filter(a => {
      const catMatch = selectedCategory === 'all' || a.category === selectedCategory
      const q = searchQuery.toLowerCase()
      const textMatch = !q || a.title.toLowerCase().includes(q) || a.tags.some(t => t.includes(q)) || a.description.toLowerCase().includes(q)
      return catMatch && textMatch
    })
  }, [articles, selectedCategory, searchQuery])

  const categoryCounts = useMemo(() => {
    const counts: Record<string, number> = { all: articles.length }
    articles.forEach(a => { counts[a.category] = (counts[a.category] ?? 0) + 1 })
    return counts
  }, [articles])

  return (
    <div className="min-h-screen bg-[#070d19] text-white flex flex-col">
      {/* Header */}
      <div className="border-b border-falcon-border px-6 py-4 flex items-center justify-between shrink-0">
        <div className="flex items-center gap-3">
          <div className="w-8 h-8 rounded-sm bg-falcon-red/10 border border-falcon-red/30 flex items-center justify-center">
            <BookOpen className="w-4 h-4 text-falcon-red" />
          </div>
          <div>
            <h1 className="text-lg font-bold text-white">セキュリティ運用手順書</h1>
            <p className="text-xs text-falcon-muted">Security Operations Runbook — SOP管理</p>
          </div>
        </div>
        <button
          onClick={() => { setSelectedArticle(null); setViewMode('edit') }}
          className="flex items-center gap-2 px-4 py-2 rounded-sm bg-falcon-red text-white hover:bg-[#c00025] text-sm font-medium transition-colors"
        >
          <Plus className="w-4 h-4" /> 新規作成
        </button>
      </div>

      <div className="flex flex-1 overflow-hidden">
        {/* Left Sidebar */}
        <aside className="w-56 shrink-0 border-r border-falcon-border flex flex-col">
          <div className="p-3 border-b border-falcon-border">
            <div className="relative">
              <Search className="absolute left-2.5 top-1/2 -translate-y-1/2 w-3.5 h-3.5 text-falcon-subtle" />
              <input
                value={searchQuery}
                onChange={e => setSearchQuery(e.target.value)}
                placeholder="手順書を検索..."
                className="w-full bg-falcon-surface border border-falcon-border rounded-sm pl-8 pr-3 py-2 text-sm text-white placeholder-falcon-subtle focus:outline-hidden focus:border-falcon-red/50"
              />
            </div>
          </div>
          <nav className="flex-1 overflow-y-auto p-2">
            {CATEGORIES.map(({ key, label, icon: Icon }) => (
              <button
                key={key}
                onClick={() => setSelectedCategory(key)}
                className={`w-full flex items-center gap-2.5 px-3 py-2 rounded text-sm transition-colors mb-0.5
                  ${selectedCategory === key ? 'bg-falcon-active text-white' : 'text-falcon-muted hover:bg-falcon-hover hover:text-white'}`}
              >
                <Icon className={`w-4 h-4 shrink-0 ${selectedCategory === key ? 'text-falcon-red' : 'text-falcon-subtle'}`} />
                <span className="flex-1 text-left">{label}</span>
                <span className="text-xs text-falcon-subtle bg-falcon-surface px-1.5 py-0.5 rounded-sm">
                  {categoryCounts[key] ?? 0}
                </span>
              </button>
            ))}
          </nav>
        </aside>

        {/* Main content */}
        <main className="flex-1 overflow-hidden flex flex-col">
          {viewMode === 'edit' ? (
            <div className="flex-1 overflow-hidden p-6">
              <ArticleEditor
                article={selectedArticle}
                onSave={data => saveMutation.mutate(data)}
                onCancel={() => setViewMode(selectedArticle ? 'view' : 'list')}
              />
            </div>
          ) : viewMode === 'view' && selectedArticle ? (
            <div className="flex-1 overflow-hidden flex flex-col p-6">
              <button
                onClick={() => { setSelectedArticle(null); setViewMode('list') }}
                className="flex items-center gap-1.5 text-xs text-falcon-muted hover:text-white mb-4 transition-colors"
              >
                <ChevronRight className="w-3.5 h-3.5 rotate-180" /> 一覧に戻る
              </button>
              <div className="flex-1 overflow-hidden">
                <ArticleViewer
                  article={selectedArticle}
                  allArticles={articles}
                  onEdit={() => setViewMode('edit')}
                />
              </div>
            </div>
          ) : (
            <div className="flex-1 overflow-y-auto p-6">
              <div className="flex items-center justify-between mb-4">
                <p className="text-sm text-falcon-muted">
                  {filteredArticles.length} 件の手順書
                </p>
              </div>
              <div className="space-y-3">
                {filteredArticles.map(article => (
                  <div
                    key={article.id}
                    className="bg-falcon-surface border border-falcon-border rounded-lg p-4 hover:border-[#2e4060] transition-colors"
                  >
                    <div className="flex items-start gap-4">
                      <div className="flex-1 min-w-0">
                        <div className="flex items-center gap-2 mb-1 flex-wrap">
                          <span className={`px-2 py-0.5 rounded-sm border text-xs font-medium ${CATEGORY_COLORS[article.category]}`}>
                            {CATEGORY_LABELS[article.category]}
                          </span>
                          <span className="text-xs text-falcon-subtle">v{article.version}</span>
                          {article.status === 'draft' && (
                            <span className="px-1.5 py-0.5 bg-yellow-900/30 text-yellow-400 rounded-sm text-xs border border-yellow-800/40">下書き</span>
                          )}
                        </div>
                        <h3 className="text-sm font-semibold text-white mb-1">{article.title}</h3>
                        <p className="text-xs text-falcon-muted line-clamp-1">{article.description}</p>
                        <div className="flex items-center gap-4 mt-2 text-xs text-falcon-subtle">
                          <span className="flex items-center gap-1">
                            <div className="w-5 h-5 rounded-full bg-linear-to-br from-falcon-blue to-[#0044cc] flex items-center justify-center text-[9px] font-bold text-white">
                              {article.author_initials}
                            </div>
                            {article.author}
                          </span>
                          <span className="flex items-center gap-1"><Clock className="w-3 h-3" /> {article.last_updated}</span>
                        </div>
                        <div className="flex flex-wrap gap-1 mt-2">
                          {article.tags.map(tag => (
                            <span key={tag} className="px-1.5 py-0.5 bg-falcon-border text-falcon-muted rounded-sm text-[10px]">#{tag}</span>
                          ))}
                        </div>
                      </div>
                      <div className="flex gap-2 shrink-0">
                        <button
                          onClick={() => { setSelectedArticle(article); setViewMode('view') }}
                          className="flex items-center gap-1.5 px-3 py-1.5 rounded-sm bg-falcon-border text-falcon-muted hover:bg-[#2e3d52] hover:text-white text-xs transition-colors"
                        >
                          <Eye className="w-3.5 h-3.5" /> 閲覧
                        </button>
                        <button
                          onClick={() => { setSelectedArticle(article); setViewMode('edit') }}
                          className="flex items-center gap-1.5 px-3 py-1.5 rounded-sm bg-falcon-red/10 text-falcon-red hover:bg-falcon-red/20 text-xs transition-colors"
                        >
                          <Edit2 className="w-3.5 h-3.5" /> 編集
                        </button>
                      </div>
                    </div>
                  </div>
                ))}
                {filteredArticles.length === 0 && (
                  <div className="text-center py-16 text-falcon-subtle">
                    <BookOpen className="w-10 h-10 mx-auto mb-3 opacity-40" />
                    <p>手順書が見つかりません</p>
                  </div>
                )}
              </div>
            </div>
          )}
        </main>
      </div>
    </div>
  )
}

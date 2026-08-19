'use client'

import { useState, useEffect, useCallback, useRef } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { apiFetch } from '@/lib/api'
import { useAuth } from '@/lib/auth'
import {
  BookOpen, Search, X, Plus, Eye, ThumbsUp, ThumbsDown,
  Calendar, Tag, Loader2, ChevronRight, Edit, Trash2,
  Globe, Shield, CheckSquare, Wrench, List, HelpCircle,
  SortDesc, LayoutGrid, LayoutList, ArrowLeft,
} from 'lucide-react'
import { PageDataUnavailable } from '@/components/PageDataUnavailable'

// ─── Types ────────────────────────────────────────────────────────────────────

type ArticleCategory = 'incident_response' | 'threat_hunting' | 'compliance' | 'tools' | 'procedures' | 'faq'
type SortOrder = 'newest' | 'most_viewed' | 'most_helpful'

interface Article {
  id: string
  title: string
  category: ArticleCategory
  content: string
  tags: string[]
  author: string
  view_count: number
  helpful_votes: number
  unhelpful_votes: number
  published: boolean
  created_at: string
  updated_at: string
}

interface KBStats {
  total_articles: number
  total_views: number
  categories: Record<ArticleCategory, number>
}


// ─── Category Config ──────────────────────────────────────────────────────────

const CATEGORY_CONFIG: Record<ArticleCategory, { label: string; icon: React.ElementType; color: string; bg: string; border: string }> = {
  incident_response: { label: 'インシデント対応', icon: Shield, color: 'text-red-300', bg: 'bg-red-900/20', border: 'border-red-700/30' },
  threat_hunting: { label: '脅威ハンティング', icon: Search, color: 'text-purple-300', bg: 'bg-purple-900/20', border: 'border-purple-700/30' },
  compliance: { label: 'コンプライアンス', icon: CheckSquare, color: 'text-green-300', bg: 'bg-green-900/20', border: 'border-green-700/30' },
  tools: { label: 'ツール', icon: Wrench, color: 'text-blue-300', bg: 'bg-blue-900/20', border: 'border-blue-700/30' },
  procedures: { label: '手順書', icon: List, color: 'text-yellow-300', bg: 'bg-yellow-900/20', border: 'border-yellow-700/30' },
  faq: { label: 'FAQ', icon: HelpCircle, color: 'text-[#7d92b0]', bg: 'bg-[#1e2d42]/50', border: 'border-[#2a3f5c]' },
}

// ─── Markdown-like Renderer ───────────────────────────────────────────────────

function renderMarkdown(content: string): React.ReactNode {
  const lines = content.split('\n')
  return lines.map((line, i) => {
    // Headers
    if (line.startsWith('# ')) return <h1 key={i} className="text-xl font-bold text-white mt-4 mb-2">{line.slice(2)}</h1>
    if (line.startsWith('## ')) return <h2 key={i} className="text-base font-semibold text-[#e2e8f4] mt-4 mb-2 border-b border-[#1e2d42] pb-1">{line.slice(3)}</h2>
    if (line.startsWith('### ')) return <h3 key={i} className="text-sm font-semibold text-[#c4d4e8] mt-3 mb-1">{line.slice(4)}</h3>

    // Code block markers
    if (line.startsWith('```')) return <div key={i} className="hidden" />

    // Checkbox list
    if (line.startsWith('- [ ]')) return (
      <div key={i} className="flex items-start gap-2 text-sm text-[#b0c4de] my-0.5">
        <span className="mt-0.5 w-4 h-4 rounded-sm border border-[#2a3f5c] shrink-0" />
        <span>{renderInline(line.slice(5))}</span>
      </div>
    )
    if (line.startsWith('- [x]') || line.startsWith('- [X]')) return (
      <div key={i} className="flex items-start gap-2 text-sm text-green-300 my-0.5">
        <span className="mt-0.5 w-4 h-4 rounded-sm border border-green-700/50 bg-green-900/30 shrink-0 flex items-center justify-center text-[10px]">✓</span>
        <span>{renderInline(line.slice(5))}</span>
      </div>
    )

    // Bullet list
    if (line.startsWith('- ')) return (
      <div key={i} className="flex items-start gap-2 text-sm text-[#b0c4de] my-0.5">
        <span className="mt-2 w-1.5 h-1.5 rounded-full bg-[#3d5068] shrink-0" />
        <span>{renderInline(line.slice(2))}</span>
      </div>
    )

    // Numbered list
    const numMatch = line.match(/^(\d+)\.\s(.+)/)
    if (numMatch) return (
      <div key={i} className="flex items-start gap-2 text-sm text-[#b0c4de] my-0.5">
        <span className="text-[#7d92b0] font-mono text-xs mt-0.5 shrink-0">{numMatch[1]}.</span>
        <span>{renderInline(numMatch[2])}</span>
      </div>
    )

    // Empty line
    if (line.trim() === '') return <div key={i} className="h-2" />

    // Normal paragraph
    return <p key={i} className="text-sm text-[#b0c4de] leading-relaxed">{renderInline(line)}</p>
  })
}

function renderInline(text: string): React.ReactNode {
  // Very simple inline: **bold**, *italic*, `code`
  const parts: React.ReactNode[] = []
  const regex = /(\*\*[^*]+\*\*|\*[^*]+\*|`[^`]+`)/g
  let last = 0
  let m: RegExpExecArray | null
  let idx = 0
  while ((m = regex.exec(text)) !== null) {
    if (m.index > last) parts.push(<span key={idx++}>{text.slice(last, m.index)}</span>)
    const raw = m[0]
    if (raw.startsWith('**')) parts.push(<strong key={idx++} className="text-white font-semibold">{raw.slice(2, -2)}</strong>)
    else if (raw.startsWith('*')) parts.push(<em key={idx++} className="text-[#c4d4e8] italic">{raw.slice(1, -1)}</em>)
    else parts.push(<code key={idx++} className="px-1.5 py-0.5 bg-[#0d1220] border border-[#1e2d42] rounded-sm text-xs font-mono text-green-300">{raw.slice(1, -1)}</code>)
    last = m.index + raw.length
  }
  if (last < text.length) parts.push(<span key={idx++}>{text.slice(last)}</span>)
  return parts.length === 1 ? parts[0] : <>{parts}</>
}

// ─── Category Badge ───────────────────────────────────────────────────────────

function CategoryBadge({ category }: { category: ArticleCategory }) {
  const cfg = CATEGORY_CONFIG[category]
  return (
    <span className={`px-2 py-0.5 rounded-sm text-[11px] font-medium ${cfg.bg} ${cfg.color} border ${cfg.border}`}>
      {cfg.label}
    </span>
  )
}

// ─── Article Editor Modal ─────────────────────────────────────────────────────

function ArticleEditorModal({
  article,
  onClose,
  onSubmit,
  loading,
}: {
  article?: Article | null
  onClose: () => void
  onSubmit: (data: Partial<Article>) => void
  loading: boolean
}) {
  const [form, setForm] = useState({
    title: article?.title ?? '',
    category: article?.category ?? 'incident_response' as ArticleCategory,
    content: article?.content ?? '',
    tags: article?.tags.join(', ') ?? '',
    published: article?.published ?? false,
  })

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 backdrop-blur-sm">
      <div className="bg-[#0d1220] border border-[#1e2d42] rounded-xl w-full max-w-2xl shadow-2xl mx-4 max-h-[90vh] flex flex-col">
        <div className="flex items-center justify-between px-6 py-4 border-b border-[#1e2d42] shrink-0">
          <h2 className="text-white font-semibold text-base">{article ? '記事編集' : '記事作成'}</h2>
          <button onClick={onClose} className="text-[#7d92b0] hover:text-white"><X className="w-5 h-5" /></button>
        </div>
        <div className="p-6 space-y-4 overflow-y-auto flex-1">
          <div>
            <label className="block text-xs text-[#7d92b0] mb-1.5">タイトル *</label>
            <input
              required
              value={form.title}
              onChange={e => setForm(f => ({ ...f, title: e.target.value }))}
              className="w-full bg-[#070d19] border border-[#1e2d42] rounded-lg px-3 py-2 text-sm text-white placeholder-[#3d5068] focus:outline-hidden focus:border-[#1a6bff] transition-colors"
              placeholder="記事タイトル"
            />
          </div>
          <div>
            <label className="block text-xs text-[#7d92b0] mb-1.5">カテゴリー</label>
            <select
              value={form.category}
              onChange={e => setForm(f => ({ ...f, category: e.target.value as ArticleCategory }))}
              className="w-full bg-[#070d19] border border-[#1e2d42] rounded-lg px-3 py-2 text-sm text-white focus:outline-hidden focus:border-[#1a6bff] transition-colors"
            >
              {(Object.entries(CATEGORY_CONFIG) as [ArticleCategory, typeof CATEGORY_CONFIG[ArticleCategory]][]).map(([key, cfg]) => (
                <option key={key} value={key}>{cfg.label}</option>
              ))}
            </select>
          </div>
          <div>
            <label className="block text-xs text-[#7d92b0] mb-1.5">コンテンツ (Markdown対応)</label>
            <textarea
              value={form.content}
              onChange={e => setForm(f => ({ ...f, content: e.target.value }))}
              rows={12}
              className="w-full bg-[#070d19] border border-[#1e2d42] rounded-lg px-3 py-2 text-sm text-white placeholder-[#3d5068] focus:outline-hidden focus:border-[#1a6bff] transition-colors resize-none font-mono"
              placeholder="# 記事タイトル&#10;&#10;## 概要&#10;ここに内容を記述..."
            />
          </div>
          <div>
            <label className="block text-xs text-[#7d92b0] mb-1.5">タグ (カンマ区切り)</label>
            <input
              value={form.tags}
              onChange={e => setForm(f => ({ ...f, tags: e.target.value }))}
              className="w-full bg-[#070d19] border border-[#1e2d42] rounded-lg px-3 py-2 text-sm text-white placeholder-[#3d5068] focus:outline-hidden focus:border-[#1a6bff] transition-colors"
              placeholder="tag1, tag2, tag3"
            />
          </div>
          <label className="flex items-center gap-2 cursor-pointer">
            <div
              onClick={() => setForm(f => ({ ...f, published: !f.published }))}
              className={`relative w-10 h-5 rounded-full transition-colors ${form.published ? 'bg-green-600' : 'bg-[#1e2d42]'}`}
            >
              <span className={`absolute top-0.5 w-4 h-4 rounded-full bg-[#e2e8f4] transition-transform ${form.published ? 'translate-x-5' : 'translate-x-0.5'}`} />
            </div>
            <span className="text-sm text-[#7d92b0]">公開する</span>
          </label>
        </div>
        <div className="flex justify-end gap-3 px-6 py-4 border-t border-[#1e2d42] shrink-0">
          <button onClick={onClose} className="px-4 py-2 text-sm text-[#7d92b0] hover:text-white transition-colors">キャンセル</button>
          <button
            disabled={!form.title || loading}
            onClick={() => onSubmit({ ...form, tags: form.tags.split(',').map(s => s.trim()).filter(Boolean) })}
            className="px-5 py-2 bg-[#1a6bff] hover:bg-[#1557d4] text-white text-sm font-medium rounded-lg transition-colors disabled:opacity-50 flex items-center gap-2"
          >
            {loading && <Loader2 className="w-3.5 h-3.5 animate-spin" />}
            {article ? '保存' : '作成'}
          </button>
        </div>
      </div>
    </div>
  )
}

// ─── Article Detail View ──────────────────────────────────────────────────────

function ArticleDetail({
  article,
  relatedArticles,
  onBack,
  onVote,
  isAdmin,
  onEdit,
  onDelete,
  votingId,
}: {
  article: Article
  relatedArticles: Article[]
  onBack: () => void
  onVote: (id: string, vote: 'helpful' | 'unhelpful') => void
  isAdmin: boolean
  onEdit: (a: Article) => void
  onDelete: (id: string) => void
  votingId: string | null
}) {
  const cfg = CATEGORY_CONFIG[article.category]

  return (
    <div className="grid grid-cols-1 lg:grid-cols-4 gap-6">
      {/* Main content */}
      <div className="lg:col-span-3 space-y-4">
        <button onClick={onBack} className="flex items-center gap-1.5 text-sm text-[#7d92b0] hover:text-white transition-colors">
          <ArrowLeft className="w-4 h-4" />
          ナレッジベースに戻る
        </button>
        <div className="bg-[#0d1220] border border-[#1e2d42] rounded-xl p-6 space-y-4">
          {/* Header */}
          <div className="flex items-start justify-between gap-4">
            <div className="flex-1">
              <div className="flex items-center gap-2 mb-2">
                <CategoryBadge category={article.category} />
              </div>
              <h1 className="text-xl font-bold text-white leading-tight">{article.title}</h1>
            </div>
            {isAdmin && (
              <div className="flex items-center gap-2 shrink-0">
                <button onClick={() => onEdit(article)} className="flex items-center gap-1.5 px-3 py-1.5 bg-[#1e2d42] hover:bg-[#253650] text-[#7d92b0] hover:text-white text-xs rounded-lg transition-colors">
                  <Edit className="w-3.5 h-3.5" />編集
                </button>
                <button onClick={() => onDelete(article.id)} className="flex items-center gap-1.5 px-3 py-1.5 bg-red-900/20 hover:bg-red-900/30 text-red-400 text-xs rounded-lg transition-colors border border-red-700/30">
                  <Trash2 className="w-3.5 h-3.5" />削除
                </button>
              </div>
            )}
          </div>

          {/* Meta */}
          <div className="flex flex-wrap items-center gap-4 text-xs text-[#7d92b0] border-b border-[#1e2d42] pb-4">
            <span className="flex items-center gap-1"><Globe className="w-3.5 h-3.5" />{article.author}</span>
            <span className="flex items-center gap-1"><Calendar className="w-3.5 h-3.5" />{new Date(article.updated_at).toLocaleDateString('ja-JP')}</span>
            <span className="flex items-center gap-1"><Eye className="w-3.5 h-3.5" />{(article.view_count ?? 0).toLocaleString()} 閲覧</span>
          </div>

          {/* Content */}
          <div className="prose prose-invert max-w-none space-y-1">
            {renderMarkdown(article.content)}
          </div>

          {/* Tags */}
          {article.tags.length > 0 && (
            <div className="flex flex-wrap gap-1.5 pt-4 border-t border-[#1e2d42]">
              {article.tags.map(tag => (
                <span key={tag} className="flex items-center gap-1 px-2 py-0.5 bg-[#1e2d42] text-[#7d92b0] rounded-sm text-xs">
                  <Tag className="w-3 h-3" />{tag}
                </span>
              ))}
            </div>
          )}

          {/* Voting */}
          <div className="flex items-center gap-3 pt-4 border-t border-[#1e2d42]">
            <span className="text-sm text-[#7d92b0]">この記事は役に立ちましたか？</span>
            <button
              onClick={() => onVote(article.id, 'helpful')}
              disabled={votingId === article.id}
              className="flex items-center gap-1.5 px-3 py-1.5 bg-green-900/20 hover:bg-green-900/30 text-green-300 text-sm rounded-lg transition-colors border border-green-700/30 disabled:opacity-50"
            >
              <ThumbsUp className="w-4 h-4" />{article.helpful_votes}
            </button>
            <button
              onClick={() => onVote(article.id, 'unhelpful')}
              disabled={votingId === article.id}
              className="flex items-center gap-1.5 px-3 py-1.5 bg-[#1e2d42] hover:bg-[#253650] text-[#7d92b0] text-sm rounded-lg transition-colors disabled:opacity-50"
            >
              <ThumbsDown className="w-4 h-4" />{article.unhelpful_votes}
            </button>
          </div>
        </div>
      </div>

      {/* Related articles sidebar */}
      <div className="space-y-3">
        <h3 className="text-sm font-semibold text-[#7d92b0] uppercase tracking-wider">関連記事</h3>
        {relatedArticles.length === 0 ? (
          <p className="text-xs text-[#3d5068]">関連記事がありません</p>
        ) : relatedArticles.map(rel => (
          <div key={rel.id} className="bg-[#0d1220] border border-[#1e2d42] rounded-lg p-3 hover:border-[#2a3f5c] transition-colors cursor-pointer" onClick={onBack}>
            <p className="text-sm text-white font-medium leading-tight line-clamp-2">{rel.title}</p>
            <div className="flex items-center gap-2 mt-2 text-xs text-[#7d92b0]">
              <Eye className="w-3 h-3" />{rel.view_count}
              <ThumbsUp className="w-3 h-3 ml-1" />{rel.helpful_votes}
            </div>
          </div>
        ))}
      </div>
    </div>
  )
}

// ─── Main Page ────────────────────────────────────────────────────────────────

export default function KnowledgeBasePage() {
  const qc = useQueryClient()
  const { user } = useAuth()
  const isAdmin = user?.role === 'admin'

  const [view, setView] = useState<'categories' | 'articles'>('categories')
  const [selectedCategory, setSelectedCategory] = useState<ArticleCategory | null>(null)
  const [searchQuery, setSearchQuery] = useState('')
  const [debouncedQuery, setDebouncedQuery] = useState('')
  const [sortOrder, setSortOrder] = useState<SortOrder>('newest')
  const [selectedArticle, setSelectedArticle] = useState<Article | null>(null)
  const [showEditor, setShowEditor] = useState(false)
  const [editingArticle, setEditingArticle] = useState<Article | null>(null)
  const [votingId, setVotingId] = useState<string | null>(null)
  const debounceRef = useRef<NodeJS.Timeout | null>(null)

  // Debounce search
  useEffect(() => {
    if (debounceRef.current) clearTimeout(debounceRef.current)
    debounceRef.current = setTimeout(() => setDebouncedQuery(searchQuery), 300)
    return () => { if (debounceRef.current) clearTimeout(debounceRef.current) }
  }, [searchQuery])

  // Articles
  const { data: articlesData } = useQuery<{ articles?: Article[]; data?: Article[] }>({
    queryKey: ['knowledge-base'],
    queryFn: () => apiFetch('/api/v1/knowledge-base'),
    retry: false,
  })
  const allArticles: Article[] = articlesData?.articles ?? articlesData?.data ?? []

  // Search
  const { data: searchData } = useQuery<{ articles?: Article[]; data?: Article[]; results?: Article[] }>({
    queryKey: ['kb-search', debouncedQuery],
    queryFn: () => apiFetch(`/api/v1/knowledge-base/search?q=${encodeURIComponent(debouncedQuery)}`),
    enabled: debouncedQuery.length >= 2,
    retry: false,
  })

  // Stats
  const { data: statsData } = useQuery<KBStats>({
    queryKey: ['kb-stats'],
    queryFn: () => apiFetch('/api/v1/knowledge-base/stats'),
    retry: false,
  })
  const EMPTY_STATS: KBStats = { total_articles: 0, total_views: 0, categories: {} as Record<ArticleCategory, number> }
  const stats = statsData ?? EMPTY_STATS

  // Compute displayed articles
  const baseArticles = debouncedQuery.length >= 2
    ? (searchData?.articles ?? searchData?.data ?? searchData?.results ?? allArticles.filter(a =>
        a.title.toLowerCase().includes(debouncedQuery.toLowerCase()) ||
        a.content.toLowerCase().includes(debouncedQuery.toLowerCase()) ||
        a.tags.some(t => t.toLowerCase().includes(debouncedQuery.toLowerCase()))
      ))
    : allArticles

  const filteredArticles = selectedCategory
    ? baseArticles.filter(a => a.category === selectedCategory)
    : baseArticles

  const sortedArticles = [...filteredArticles].sort((a, b) => {
    if (sortOrder === 'newest') return new Date(b.created_at).getTime() - new Date(a.created_at).getTime()
    if (sortOrder === 'most_viewed') return b.view_count - a.view_count
    return b.helpful_votes - a.helpful_votes
  })

  // Category article counts (from mock/real data)
  const categoryArticles = (cat: ArticleCategory) => allArticles.filter(a => a.category === cat)
  const latestInCategory = (cat: ArticleCategory) => {
    const arts = categoryArticles(cat)
    if (arts.length === 0) return null
    return arts.sort((a, b) => new Date(b.created_at).getTime() - new Date(a.created_at).getTime())[0]
  }

  // Related articles
  const relatedArticles = selectedArticle
    ? allArticles.filter(a => a.id !== selectedArticle.id && a.category === selectedArticle.category).slice(0, 3)
    : []

  // Mutations
  const createMutation = useMutation({
    mutationFn: (data: Partial<Article>) => apiFetch('/api/v1/knowledge-base', { method: 'POST', body: JSON.stringify(data) }),
    onSuccess: () => { qc.invalidateQueries({ queryKey: ['knowledge-base'] }); setShowEditor(false) },
    onError: () => setShowEditor(false),
  })

  const updateMutation = useMutation({
    mutationFn: ({ id, data }: { id: string; data: Partial<Article> }) =>
      apiFetch(`/api/v1/knowledge-base/${id}`, { method: 'PUT', body: JSON.stringify(data) }),
    onSuccess: () => { qc.invalidateQueries({ queryKey: ['knowledge-base'] }); setShowEditor(false); setEditingArticle(null) },
    onError: () => { setShowEditor(false); setEditingArticle(null) },
  })

  const deleteMutation = useMutation({
    mutationFn: (id: string) => apiFetch(`/api/v1/knowledge-base/${id}`, { method: 'DELETE' }),
    onSuccess: () => { qc.invalidateQueries({ queryKey: ['knowledge-base'] }); setSelectedArticle(null) },
    onError: () => {},
  })

  const voteMutation = useMutation({
    mutationFn: ({ id, vote }: { id: string; vote: string }) =>
      apiFetch(`/api/v1/knowledge-base/${id}/vote`, { method: 'POST', body: JSON.stringify({ vote }) }),
    onSuccess: () => { qc.invalidateQueries({ queryKey: ['knowledge-base'] }); setVotingId(null) },
    onError: () => setVotingId(null),
  })

  const handleVote = (id: string, vote: 'helpful' | 'unhelpful') => {
    setVotingId(id)
    voteMutation.mutate({ id, vote })
  }

  const handleEditorSubmit = (data: Partial<Article>) => {
    if (editingArticle) {
      updateMutation.mutate({ id: editingArticle.id, data })
    } else {
      createMutation.mutate(data)
    }
  }

  // If viewing an article detail
  if (selectedArticle) {
    return (
      <div className="min-h-screen bg-[#070d19] p-6">
        <ArticleDetail
          article={selectedArticle}
          relatedArticles={relatedArticles}
          onBack={() => setSelectedArticle(null)}
          onVote={handleVote}
          isAdmin={isAdmin}
          onEdit={(a) => { setEditingArticle(a); setShowEditor(true) }}
          onDelete={(id) => { if (confirm('この記事を削除しますか？')) deleteMutation.mutate(id) }}
          votingId={votingId}
        />
        {showEditor && (
          <ArticleEditorModal
            article={editingArticle}
            onClose={() => { setShowEditor(false); setEditingArticle(null) }}
            onSubmit={handleEditorSubmit}
            loading={createMutation.isPending || updateMutation.isPending}
          />
        )}
      </div>
    )
  }

  return (
    <div className="min-h-screen bg-[#070d19] p-6 space-y-6">
      <PageDataUnavailable />
      {/* Header */}
      <div className="flex items-start justify-between gap-4">
        <div>
          <h1 className="text-2xl font-bold text-white tracking-tight flex items-center gap-2">
            <BookOpen className="w-6 h-6 text-[#e8002d]" />
            ナレッジベース
          </h1>
          <p className="text-[#7d92b0] text-sm mt-1">インシデント対応手順・セキュリティガイド・FAQ</p>
        </div>
        {isAdmin && (
          <button
            onClick={() => { setEditingArticle(null); setShowEditor(true) }}
            className="flex items-center gap-2 px-4 py-2 bg-[#e8002d] hover:bg-[#c00025] text-white text-sm font-medium rounded-lg transition-colors shadow-lg shadow-red-900/20"
          >
            <Plus className="w-4 h-4" />記事作成
          </button>
        )}
      </div>

      {/* Search Bar */}
      <div className="relative">
        <Search className="absolute left-4 top-1/2 -translate-y-1/2 w-5 h-5 text-[#3d5068]" />
        <input
          type="text"
          value={searchQuery}
          onChange={e => setSearchQuery(e.target.value)}
          placeholder="記事を検索... (タイトル、コンテンツ、タグ)"
          className="w-full bg-[#0d1220] border border-[#1e2d42] rounded-xl pl-12 pr-12 py-3.5 text-sm text-white placeholder-[#3d5068] focus:outline-hidden focus:border-[#1a6bff] transition-colors shadow-lg"
        />
        {searchQuery && (
          <button onClick={() => setSearchQuery('')} className="absolute right-4 top-1/2 -translate-y-1/2 text-[#7d92b0] hover:text-white">
            <X className="w-4 h-4" />
          </button>
        )}
      </div>

      {/* View Toggle + Sort */}
      <div className="flex items-center justify-between gap-4">
        <div className="flex gap-1 bg-[#0d1220] border border-[#1e2d42] rounded-lg p-1">
          <button
            onClick={() => { setView('categories'); setSelectedCategory(null) }}
            className={`flex items-center gap-1.5 px-3 py-1.5 rounded-md text-sm font-medium transition-all ${view === 'categories' && !selectedCategory ? 'bg-[#1e2d42] text-white' : 'text-[#7d92b0] hover:text-white'}`}
          >
            <LayoutGrid className="w-4 h-4" />カテゴリー
          </button>
          <button
            onClick={() => { setView('articles'); setSelectedCategory(null) }}
            className={`flex items-center gap-1.5 px-3 py-1.5 rounded-md text-sm font-medium transition-all ${view === 'articles' || selectedCategory ? 'bg-[#1e2d42] text-white' : 'text-[#7d92b0] hover:text-white'}`}
          >
            <LayoutList className="w-4 h-4" />全記事
          </button>
        </div>
        {(view === 'articles' || selectedCategory || debouncedQuery) && (
          <div className="flex items-center gap-2">
            <SortDesc className="w-4 h-4 text-[#7d92b0]" />
            <select
              value={sortOrder}
              onChange={e => setSortOrder(e.target.value as SortOrder)}
              className="bg-[#0d1220] border border-[#1e2d42] rounded-lg px-3 py-1.5 text-sm text-white focus:outline-hidden focus:border-[#1a6bff] transition-colors"
            >
              <option value="newest">最新順</option>
              <option value="most_viewed">閲覧数順</option>
              <option value="most_helpful">役立ち順</option>
            </select>
          </div>
        )}
      </div>

      {/* Searching indicator */}
      {debouncedQuery.length >= 2 && (
        <div className="flex items-center gap-2 text-sm text-[#7d92b0]">
          <Search className="w-4 h-4" />
          <span>&ldquo;{debouncedQuery}&rdquo; の検索結果: {sortedArticles.length}件</span>
          <button onClick={() => setSearchQuery('')} className="ml-2 text-[#1a6bff] hover:text-blue-300 text-xs">クリア</button>
        </div>
      )}

      {/* Category view */}
      {view === 'categories' && !selectedCategory && !debouncedQuery && (
        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-4">
          {(Object.entries(CATEGORY_CONFIG) as [ArticleCategory, typeof CATEGORY_CONFIG[ArticleCategory]][]).map(([cat, cfg]) => {
            const count = categoryArticles(cat).length
            const latest = latestInCategory(cat)
            return (
              <button
                key={cat}
                onClick={() => { setSelectedCategory(cat); setView('articles') }}
                className={`bg-[#0d1220] border rounded-xl p-5 text-left hover:border-[#2a3f5c] transition-all group hover:shadow-lg ${cfg.border}`}
              >
                <div className={`w-10 h-10 rounded-lg ${cfg.bg} border ${cfg.border} flex items-center justify-center mb-3 group-hover:scale-110 transition-transform`}>
                  <cfg.icon className={`w-5 h-5 ${cfg.color}`} />
                </div>
                <h3 className="text-white font-semibold text-sm">{cfg.label}</h3>
                <p className="text-[#7d92b0] text-xs mt-1">{count} 記事</p>
                {latest && (
                  <p className="text-[#3d5068] text-xs mt-2 line-clamp-1">{latest.title}</p>
                )}
                <div className="flex items-center gap-1 mt-3 text-[#7d92b0] text-xs group-hover:text-white transition-colors">
                  <span>記事を見る</span>
                  <ChevronRight className="w-3.5 h-3.5" />
                </div>
              </button>
            )
          })}
        </div>
      )}

      {/* Articles list view */}
      {(view === 'articles' || selectedCategory || debouncedQuery.length >= 2) && (
        <div className="space-y-3">
          {selectedCategory && (
            <div className="flex items-center gap-2">
              <button
                onClick={() => { setSelectedCategory(null); setView('categories') }}
                className="flex items-center gap-1.5 text-sm text-[#7d92b0] hover:text-white transition-colors"
              >
                <ArrowLeft className="w-4 h-4" />
                カテゴリーに戻る
              </button>
              <span className="text-[#3d5068]">/</span>
              <CategoryBadge category={selectedCategory} />
            </div>
          )}

          {sortedArticles.length === 0 ? (
            <div className="flex flex-col items-center justify-center py-16 text-[#7d92b0]">
              <BookOpen className="w-12 h-12 mb-3 opacity-30" />
              <p className="text-base">記事が見つかりませんでした</p>
              <p className="text-sm mt-1 opacity-60">検索条件を変更してみてください</p>
            </div>
          ) : sortedArticles.map(article => {
            const cfg = CATEGORY_CONFIG[article.category]
            return (
              <div
                key={article.id}
                className="bg-[#0d1220] border border-[#1e2d42] rounded-xl p-4 hover:border-[#2a3f5c] transition-colors cursor-pointer group"
                onClick={() => setSelectedArticle(article)}
              >
                <div className="flex items-start justify-between gap-4">
                  <div className="flex-1 min-w-0">
                    <div className="flex items-center gap-2 mb-1.5 flex-wrap">
                      <CategoryBadge category={article.category} />
                      {!article.published && isAdmin && (
                        <span className="px-2 py-0.5 rounded-sm text-[11px] font-medium bg-[#1e2d42] text-[#7d92b0] border border-[#2a3f5c]">非公開</span>
                      )}
                    </div>
                    <h3 className="text-white font-semibold text-sm group-hover:text-blue-300 transition-colors">{article.title}</h3>
                    <div className="flex flex-wrap gap-1.5 mt-2">
                      {article.tags.slice(0, 3).map(tag => (
                        <span key={tag} className="flex items-center gap-0.5 px-1.5 py-0.5 bg-[#1e2d42] text-[#7d92b0] rounded-sm text-[10px]">
                          <Tag className="w-2.5 h-2.5" />{tag}
                        </span>
                      ))}
                      {article.tags.length > 3 && (
                        <span className="px-1.5 py-0.5 bg-[#1e2d42] text-[#7d92b0] rounded-sm text-[10px]">+{article.tags.length - 3}</span>
                      )}
                    </div>
                  </div>
                  <div className="flex flex-col items-end gap-2 shrink-0">
                    <div className="flex items-center gap-3 text-xs text-[#7d92b0]">
                      <span className="flex items-center gap-1"><Eye className="w-3.5 h-3.5" />{(article.view_count ?? 0).toLocaleString()}</span>
                      <span className="flex items-center gap-1"><ThumbsUp className="w-3.5 h-3.5" />{article.helpful_votes}</span>
                      <span className="flex items-center gap-1"><Calendar className="w-3.5 h-3.5" />{new Date(article.created_at).toLocaleDateString('ja-JP', { month: 'short', day: 'numeric' })}</span>
                    </div>
                    <div className="flex items-center gap-1.5">
                      {isAdmin && (
                        <>
                          <button
                            onClick={e => { e.stopPropagation(); setEditingArticle(article); setShowEditor(true) }}
                            className="flex items-center gap-1 px-2 py-1 bg-[#1e2d42] hover:bg-[#253650] text-[#7d92b0] hover:text-white text-xs rounded-sm transition-colors"
                          >
                            <Edit className="w-3 h-3" />編集
                          </button>
                          <button
                            onClick={e => { e.stopPropagation(); if (confirm('削除しますか？')) deleteMutation.mutate(article.id) }}
                            className="flex items-center gap-1 px-2 py-1 bg-red-900/20 hover:bg-red-900/30 text-red-400 text-xs rounded-sm transition-colors"
                          >
                            <Trash2 className="w-3 h-3" />削除
                          </button>
                        </>
                      )}
                      <button className="flex items-center gap-1 px-3 py-1 bg-[#1a6bff]/20 hover:bg-[#1a6bff]/30 text-[#1a6bff] hover:text-blue-300 text-xs rounded-sm transition-colors border border-[#1a6bff]/30">
                        読む <ChevronRight className="w-3 h-3" />
                      </button>
                    </div>
                  </div>
                </div>
              </div>
            )
          })}
        </div>
      )}

      {/* Editor Modal */}
      {showEditor && (
        <ArticleEditorModal
          article={editingArticle}
          onClose={() => { setShowEditor(false); setEditingArticle(null) }}
          onSubmit={handleEditorSubmit}
          loading={createMutation.isPending || updateMutation.isPending}
        />
      )}
    </div>
  )
}

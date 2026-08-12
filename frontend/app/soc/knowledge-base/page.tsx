'use client'

import { useState } from 'react'
import { useQuery } from '@tanstack/react-query'
import { apiFetch, apiFetchList } from '@/lib/api'
import {
  BookOpen, Search, Plus, Star, Eye, Clock, Tag, ChevronRight,
  FileText, TrendingUp, Edit, Bookmark, BarChart2
} from 'lucide-react'

// ─── 型定義 ──────────────────────────────────────────────────────────────────

interface Article {
  id: string
  title: string
  category: string
  category_color: string
  author: string
  last_updated: string
  view_count: number
  tags: string[]
  summary: string
  content?: ArticleSection[]
  related?: string[]
}

interface ArticleSection {
  heading: string
  body: string
}

interface CategoryNode {
  icon: string
  name: string
  count: number
  children?: { name: string; count: number }[]
}

// ─── モックデータ ─────────────────────────────────────────────────────────────

const CATEGORIES: CategoryNode[] = [
  { icon: '🔴', name: 'インシデント対応', count: 45, children: [
    { name: 'フィッシング対応手順', count: 12 },
    { name: 'マルウェア対応手順', count: 18 },
    { name: 'ランサムウェア対応', count: 8 },
    { name: 'データ侵害対応', count: 7 },
  ]},
  { icon: '🟡', name: '脅威インテリジェンス', count: 38, children: [
    { name: 'APTプロファイル', count: 15 },
    { name: 'IOC管理', count: 13 },
    { name: 'TTP解析', count: 10 },
  ]},
  { icon: '🟢', name: 'ツール・手順', count: 52, children: [
    { name: 'SIEM操作ガイド', count: 20 },
    { name: 'フォレンジックツール', count: 18 },
    { name: '自動化スクリプト', count: 14 },
  ]},
  { icon: '🔵', name: 'コンプライアンス', count: 35, children: [] },
  { icon: '⚪', name: 'その他', count: 77, children: [] },
]

const RANSOMWARE_CONTENT: ArticleSection[] = [
  { heading: '1. 初動対応 (0〜15分)', body: '感染を検知したら即座にネットワークから隔離する。対象エンドポイントのNICを無効化し、Wi-Fiも切断すること。VLANの隔離ポリシーを適用し、横展開を防ぐ。EDRコンソールからエージェントの「ネットワーク隔離」機能を使用できる。' },
  { heading: '2. 証拠保全', body: 'メモリダンプを最優先で取得する。FTK Imagerまたは WinPmem を使用。次にディスクイメージを取得する。実行中プロセス、ネットワーク接続、レジストリのスナップショットも記録すること。ログは改ざんされる前に外部ストレージへ転送する。' },
  { heading: '3. 影響範囲の特定', body: 'SIEMで同一IOCを持つホストを横断検索する。ファイル拡張子の変化をモニタリングし、暗号化の範囲を特定する。バックアップシステムへの感染有無を確認する。ビジネス影響度評価を実施しインシデント重大度を決定する。' },
  { heading: '4. 封じ込め・駆除', body: '感染ホストのセグメント分離を維持する。バックアップからの復旧可否を確認する。身代金支払いは原則禁止(法的リスク・データ復旧保証なし)。クリーンなイメージからOSを再インストールする。IOCをSIEM・EDRに登録し再感染を防ぐ。' },
  { heading: '5. 復旧・事後対応', body: '検証済みバックアップから段階的に復旧する。エンドポイントをセキュリティ強化設定で再参加させる。インシデントレポートを24時間以内に作成し関係者へ報告する。CSIRT/CERTへの報告義務を確認する。再発防止策を30日以内に実施する。' },
]
const FEATURED = [
  { id: '1', title: 'ランサムウェア対応プレイブック 2024年版', badge: '最も閲覧', badgeCls: 'bg-red-900/40 text-red-300', views: 1247, icon: TrendingUp },
  { id: '2', title: 'Cobalt Strike 検出・対応ガイド', badge: '最近更新', badgeCls: 'bg-blue-900/40 text-blue-300', views: 892, icon: Clock },
  { id: '3', title: 'MITRE ATT&CK マッピング手順', badge: '必読', badgeCls: 'bg-purple-900/40 text-purple-300', views: 743, icon: BookOpen },
]

// ─── メインページ ─────────────────────────────────────────────────────────────

export default function KnowledgeBasePage() {
  const [searchQuery, setSearchQuery] = useState('')
  const [expandedCats, setExpandedCats] = useState<string[]>(['インシデント対応'])
  const [selectedArticle, setSelectedArticle] = useState<Article | null>(null)
  const [favorited, setFavorited] = useState<string[]>([])

  const { data: articles = [] } = useQuery<Article[]>({
    queryKey: ['kb-articles'],
    queryFn: () => apiFetchList<Article>('/api/kb/articles').catch(() => [] as Article[]),
  })

  const stats = [
    { label: '記事数',     value: 247,    icon: FileText,   color: 'text-blue-400' },
    { label: 'カテゴリ',   value: 12,     icon: Tag,        color: 'text-green-400' },
    { label: '今月閲覧',   value: '1,847', icon: Eye,        color: 'text-purple-400' },
    { label: '最近更新',   value: '8件',   icon: Clock,      color: 'text-orange-400' },
  ]

  const filteredArticles = articles.filter(a =>
    a.title.toLowerCase().includes(searchQuery.toLowerCase()) ||
    a.tags.some(t => t.toLowerCase().includes(searchQuery.toLowerCase()))
  )

  const toggleCat = (name: string) =>
    setExpandedCats(prev => prev.includes(name) ? prev.filter(c => c !== name) : [...prev, name])

  const toggleFav = (id: string) =>
    setFavorited(prev => prev.includes(id) ? prev.filter(f => f !== id) : [...prev, id])

  return (
    <div className="min-h-screen bg-[#070d19] text-white">
      {/* ヘッダー */}
      <div className="border-b border-[#1e2d42] px-6 py-4">
        <div className="flex items-center justify-between mb-4">
          <div className="flex items-center gap-3">
            <BookOpen className="w-7 h-7 text-[#e8002d]" />
            <h1 className="text-2xl font-bold">SOCナレッジベース</h1>
          </div>
          <button className="flex items-center gap-2 px-4 py-2 bg-[#e8002d] hover:bg-[#c0001f] rounded-lg text-sm font-medium transition-colors">
            <Plus className="w-4 h-4" /> 新規記事
          </button>
        </div>
        {/* 統計 */}
        <div className="grid grid-cols-4 gap-4">
          {stats.map(s => (
            <div key={s.label} className="bg-[#0d1220] border border-[#1e2d42] rounded-lg p-3 flex items-center gap-3">
              <s.icon className={`w-6 h-6 ${s.color} flex-shrink-0`} />
              <div>
                <div className="text-base font-bold">{s.value}</div>
                <div className="text-xs text-[#7d92b0]">{s.label}</div>
              </div>
            </div>
          ))}
        </div>
      </div>

      {/* フィーチャード */}
      <div className="px-6 py-4 border-b border-[#1e2d42]">
        <div className="grid grid-cols-3 gap-4">
          {FEATURED.map(f => {
            const art = articles.find(a => a.id === f.id)
            return (
              <button key={f.id} onClick={() => art && setSelectedArticle(art)}
                className="bg-[#0d1220] border border-[#1e2d42] hover:border-[#e8002d]/50 rounded-xl p-4 text-left transition-colors group">
                <div className="flex items-center justify-between mb-2">
                  <span className={`text-xs px-2 py-0.5 rounded-full ${f.badgeCls}`}>{f.badge}</span>
                  <f.icon className="w-4 h-4 text-[#7d92b0] group-hover:text-[#e8002d] transition-colors" />
                </div>
                <p className="text-sm font-medium leading-snug mb-2">{f.title}</p>
                <div className="flex items-center gap-1 text-xs text-[#7d92b0]">
                  <Eye className="w-3 h-3" /> {(f.views ?? 0).toLocaleString()}回
                </div>
              </button>
            )
          })}
        </div>
      </div>

      {/* メインレイアウト */}
      <div className="flex" style={{ minHeight: 'calc(100vh - 260px)' }}>
        {/* サイドバー (30%) */}
        <aside className="w-[30%] border-r border-[#1e2d42] p-4 flex-shrink-0">
          {/* 検索 */}
          <div className="relative mb-4">
            <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-[#7d92b0]" />
            <input
              value={searchQuery}
              onChange={e => setSearchQuery(e.target.value)}
              placeholder="記事を検索..."
              className="w-full bg-[#0d1220] border border-[#1e2d42] rounded-lg pl-9 pr-3 py-2 text-sm text-white placeholder-[#7d92b0] focus:outline-none focus:border-[#e8002d]/60"
            />
          </div>

          {/* カテゴリツリー */}
          <div className="space-y-1">
            {CATEGORIES.map(cat => (
              <div key={cat.name}>
                <button onClick={() => toggleCat(cat.name)}
                  className="w-full flex items-center justify-between px-3 py-2 rounded-lg hover:bg-[#1e2d42]/40 transition-colors text-sm">
                  <span className="flex items-center gap-2">
                    <span>{cat.icon}</span>
                    <span className="font-medium">{cat.name}</span>
                    <span className="text-xs text-[#7d92b0]">({cat.count})</span>
                  </span>
                  {cat.children && cat.children.length > 0 && (
                    expandedCats.includes(cat.name)
                      ? <ChevronRight className="w-3.5 h-3.5 text-[#7d92b0] rotate-90 transition-transform" />
                      : <ChevronRight className="w-3.5 h-3.5 text-[#7d92b0] transition-transform" />
                  )}
                </button>
                {expandedCats.includes(cat.name) && cat.children && cat.children.length > 0 && (
                  <div className="ml-4 mt-1 space-y-0.5 pl-3 border-l border-[#1e2d42]">
                    {cat.children.map(child => (
                      <button key={child.name}
                        className="w-full flex items-center justify-between px-2 py-1.5 rounded hover:bg-[#1e2d42]/40 transition-colors text-xs text-[#7d92b0] hover:text-white">
                        <span>{child.name}</span>
                        <span className="text-[#4a5a6e]">{child.count}</span>
                      </button>
                    ))}
                  </div>
                )}
              </div>
            ))}
          </div>
        </aside>

        {/* メインコンテンツ (70%) */}
        <main className="flex-1 p-6 overflow-auto">
          {!selectedArticle ? (
            /* 記事グリッド表示 */
            <div>
              <h2 className="text-sm font-semibold text-[#7d92b0] uppercase tracking-wide mb-4">
                {searchQuery ? `"${searchQuery}" の検索結果 (${filteredArticles.length}件)` : '最近の記事'}
              </h2>
              <div className="grid grid-cols-2 gap-4">
                {filteredArticles.map(article => (
                  <button key={article.id} onClick={() => setSelectedArticle(article)}
                    className="bg-[#0d1220] border border-[#1e2d42] hover:border-[#e8002d]/40 rounded-xl p-4 text-left transition-colors group">
                    <div className="flex items-start justify-between mb-2">
                      <span className={`text-xs px-2 py-0.5 rounded-full border ${article.category_color}`}>{article.category}</span>
                      <div className="flex items-center gap-1 text-xs text-[#7d92b0]">
                        <Eye className="w-3 h-3" /> {article.view_count}
                      </div>
                    </div>
                    <h3 className="text-sm font-semibold mb-1.5 leading-snug group-hover:text-[#e8002d] transition-colors">{article.title}</h3>
                    <p className="text-xs text-[#7d92b0] mb-3 line-clamp-2">{article.summary}</p>
                    <div className="flex items-center justify-between">
                      <div className="flex flex-wrap gap-1">
                        {article.tags.slice(0, 2).map(t => (
                          <span key={t} className="text-xs px-1.5 py-0.5 bg-[#1e2d42] text-[#7d92b0] rounded">{t}</span>
                        ))}
                      </div>
                      <div className="flex items-center gap-1 text-xs text-[#7d92b0]">
                        <Clock className="w-3 h-3" /> {article.last_updated}
                      </div>
                    </div>
                    <div className="mt-2 text-xs text-[#4a5a6e]">by {article.author}</div>
                  </button>
                ))}
              </div>
            </div>
          ) : (
            /* 記事リーダー */
            <div>
              <button onClick={() => setSelectedArticle(null)}
                className="flex items-center gap-1.5 text-sm text-[#7d92b0] hover:text-white mb-5 transition-colors">
                <ChevronRight className="w-4 h-4 rotate-180" /> 記事一覧に戻る
              </button>

              {/* 記事ヘッダー */}
              <div className="mb-6">
                <div className="flex items-center gap-2 mb-3 flex-wrap">
                  <span className={`text-xs px-2 py-0.5 rounded-full border ${selectedArticle.category_color}`}>{selectedArticle.category}</span>
                  {selectedArticle.tags.map(t => (
                    <span key={t} className="text-xs px-2 py-0.5 bg-[#1e2d42] text-[#7d92b0] rounded-full">{t}</span>
                  ))}
                </div>
                <h2 className="text-xl font-bold mb-3">{selectedArticle.title}</h2>
                <div className="flex items-center gap-4 text-xs text-[#7d92b0]">
                  <span>by {selectedArticle.author}</span>
                  <span className="flex items-center gap-1"><Clock className="w-3 h-3" /> {selectedArticle.last_updated}</span>
                  <span className="flex items-center gap-1"><Eye className="w-3 h-3" /> {(selectedArticle.view_count ?? 0).toLocaleString()}回閲覧</span>
                  <div className="ml-auto flex items-center gap-2">
                    <button className="flex items-center gap-1.5 px-3 py-1 bg-[#1e2d42] hover:bg-[#2a3f5f] rounded-lg transition-colors">
                      <Edit className="w-3.5 h-3.5" /> 編集
                    </button>
                    <button onClick={() => toggleFav(selectedArticle.id)}
                      className={`flex items-center gap-1.5 px-3 py-1 rounded-lg transition-colors ${favorited.includes(selectedArticle.id) ? 'bg-yellow-900/40 text-yellow-300 border border-yellow-700/40' : 'bg-[#1e2d42] hover:bg-[#2a3f5f]'}`}>
                      <Bookmark className={`w-3.5 h-3.5 ${favorited.includes(selectedArticle.id) ? 'fill-yellow-300' : ''}`} /> お気に入り
                    </button>
                  </div>
                </div>
              </div>

              {/* 記事コンテンツ */}
              <div className="bg-[#0d1220] border border-[#1e2d42] rounded-xl p-6 mb-6">
                <p className="text-sm text-[#7d92b0] mb-5 leading-relaxed border-l-2 border-[#e8002d] pl-4">{selectedArticle.summary}</p>
                {selectedArticle.content ? (
                  <div className="space-y-5">
                    {selectedArticle.content.map((section, i) => (
                      <div key={i}>
                        <h3 className="text-base font-semibold mb-2 text-white">{section.heading}</h3>
                        <p className="text-sm text-[#7d92b0] leading-relaxed">{section.body}</p>
                      </div>
                    ))}
                  </div>
                ) : (
                  <p className="text-sm text-[#7d92b0] italic">コンテンツは準備中です。</p>
                )}
              </div>

              {/* 関連記事 */}
              {selectedArticle.related && selectedArticle.related.length > 0 && (
                <div>
                  <h3 className="text-sm font-semibold text-[#7d92b0] uppercase tracking-wide mb-3">関連記事</h3>
                  <div className="space-y-2">
                    {selectedArticle.related.map(rel => {
                      const relArt = articles.find(a => a.title === rel)
                      return (
                        <button key={rel} onClick={() => relArt && setSelectedArticle(relArt)}
                          className="w-full flex items-center gap-3 p-3 bg-[#0d1220] border border-[#1e2d42] hover:border-[#e8002d]/40 rounded-lg text-left transition-colors group">
                          <FileText className="w-4 h-4 text-[#7d92b0] group-hover:text-[#e8002d] transition-colors flex-shrink-0" />
                          <span className="text-sm">{rel}</span>
                          <ChevronRight className="w-4 h-4 text-[#7d92b0] ml-auto" />
                        </button>
                      )
                    })}
                  </div>
                </div>
              )}
            </div>
          )}
        </main>
      </div>
    </div>
  )
}

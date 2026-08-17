'use client'

import { useState, useMemo } from 'react'
import Link from 'next/link'
import { useQuery } from '@tanstack/react-query'
import { apiFetch } from '@/lib/api'
import {
  HelpCircle,
  Search,
  Compass,
  ShieldAlert,
  Monitor,
  Brain,
  BarChart3,
  Settings,
  ChevronDown,
  ChevronRight,
  ExternalLink,
  Mail,
  Github,
  Info,
  BookOpen,
  Keyboard,
} from 'lucide-react'

// ─── Types ────────────────────────────────────────────────────────────────────

interface HealthDetailed {
  version?: string
  build?: string
  api_version?: string
  uptime_seconds?: number
  environment?: string
}

// ─── Static Data ──────────────────────────────────────────────────────────────

const CATEGORIES = [
  {
    id: 'getting-started',
    label: 'はじめに',
    href: '/agents/deploy',
    icon: Compass,
    color: 'text-blue-400',
    bg: 'bg-blue-900/20',
    border: 'border-blue-800/40',
    description: 'インストール・初期設定・クイックスタートガイド',
  },
  {
    id: 'alerts',
    label: 'アラート対応',
    href: '/alerts',
    icon: ShieldAlert,
    color: 'text-falcon-red',
    bg: 'bg-falcon-red/10',
    border: 'border-falcon-red/30',
    description: 'アラートのトリアージ・調査・クローズ手順',
  },
  {
    id: 'endpoints',
    label: 'エンドポイント管理',
    href: '/endpoints',
    icon: Monitor,
    color: 'text-emerald-400',
    bg: 'bg-emerald-900/20',
    border: 'border-emerald-800/40',
    description: 'エージェント配布・グループ管理・ポリシー適用',
  },
  {
    id: 'intel',
    label: '脅威インテリジェンス',
    href: '/threat-intel',
    icon: Brain,
    color: 'text-purple-400',
    bg: 'bg-purple-900/20',
    border: 'border-purple-800/40',
    description: 'IOC管理・脅威フィード・MITRE ATT&CKマッピング',
  },
  {
    id: 'reports',
    label: 'レポート & 分析',
    href: '/reports',
    icon: BarChart3,
    color: 'text-orange-400',
    bg: 'bg-orange-900/20',
    border: 'border-orange-800/40',
    description: 'レポート生成・スケジュール設定・SOCメトリクス',
  },
  {
    id: 'admin',
    label: '管理者設定',
    href: '/settings',
    icon: Settings,
    color: 'text-falcon-muted',
    bg: 'bg-falcon-border/30',
    border: 'border-falcon-border',
    description: 'ユーザー管理・SIEM連携・バックアップ・SSO設定',
  },
]

const KEYBOARD_SHORTCUTS = [
  { keys: ['Ctrl', 'K'],    description: 'コマンドパレットを開く' },
  { keys: ['Ctrl', '/'],    description: 'ヘルプを開く' },
  { keys: ['G', 'D'],       description: 'ダッシュボードへ移動' },
  { keys: ['G', 'A'],       description: 'アラート一覧へ移動' },
  { keys: ['G', 'E'],       description: 'エンドポイント一覧へ移動' },
  { keys: ['Esc'],          description: 'モーダル / パネルを閉じる' },
]

const FAQ_ITEMS = [
  {
    question: 'エージェントのインストール方法は？',
    answer:
      'サイドバーの「エージェント配布」ページからインストーラーをダウンロードできます。Windows・macOS・Linux（Debian/RPM系）に対応したパッケージを用意しています。インストール後、エージェントは自動的にサーバーへ登録され、「エンドポイント」一覧に表示されます。グループポリシーを利用した一括配布も可能です。',
  },
  {
    question: 'アラートの重大度はどう決まりますか？',
    answer:
      'アラートの重大度（Critical / High / Medium / Low / Info）は、検知ルールに設定されたスコア、脅威インテリジェンスのコンテキスト、エンドポイントのリスクスコアを組み合わせて自動算出されます。MITRE ATT&CK フレームワークの技術IDとも紐付けられ、攻撃フェーズに基づいた優先度付けが行われます。',
  },
  {
    question: '誤検知を抑制するにはどうすればいいですか？',
    answer:
      'サイドバーの「アラート抑制」ページから抑制ルールを作成できます。特定のエンドポイント・プロセス・ファイルハッシュ・IPアドレスなどの条件を指定してアラートを抑制することが可能です。抑制ルールには有効期限を設定でき、期限切れ後は自動的に再検知が有効になります。',
  },
  {
    question: 'ダッシュボードのウィジェットをカスタマイズできますか？',
    answer:
      'ダッシュボード右上の「カスタマイズ」ボタンから各ウィジェットの表示/非表示・配置を変更できます。設定はユーザーごとに保存されます。管理者はデフォルトレイアウトを全ユーザー向けに適用することも可能です。',
  },
  {
    question: 'SIEMやSlackへの通知連携方法を教えてください。',
    answer:
      '管理者設定の「通知チャンネル」ページからSlack / Microsoft Teams / 汎用Webhookを設定できます。SIEM連携（Syslog / CEF / LEEF形式）は「SIEM連携」ページで設定します。また「Webhookテスター」ツールを使って送信前に設定を確認することをお勧めします。',
  },
]

// ─── Sub-components ───────────────────────────────────────────────────────────

function KbdKey({ children }: { children: string }) {
  return (
    <kbd
      className="inline-flex items-center px-2 py-0.5 rounded border border-falcon-border
                 bg-[#070d19] text-falcon-text text-[11px] font-mono font-semibold
                 shadow-[0_1px_0_#1e2d42]"
    >
      {children}
    </kbd>
  )
}

function FaqItem({ question, answer }: { question: string; answer: string }) {
  const [open, setOpen] = useState(false)
  return (
    <div className="border border-falcon-border rounded-lg overflow-hidden">
      <button
        type="button"
        onClick={() => setOpen((v) => !v)}
        className="w-full flex items-center justify-between gap-4 px-5 py-4
                   bg-falcon-surface hover:bg-falcon-card transition-colors text-left"
      >
        <span className="text-sm font-medium text-falcon-text">{question}</span>
        {open ? (
          <ChevronDown className="w-4 h-4 text-falcon-muted shrink-0" />
        ) : (
          <ChevronRight className="w-4 h-4 text-falcon-muted shrink-0" />
        )}
      </button>
      {open && (
        <div className="px-5 py-4 bg-[#070d19] border-t border-falcon-border">
          <p className="text-sm text-falcon-muted leading-relaxed">{answer}</p>
        </div>
      )}
    </div>
  )
}

// ─── Main Page ────────────────────────────────────────────────────────────────

export default function HelpPage() {
  const [searchQuery, setSearchQuery] = useState('')

  const { data: healthData } = useQuery<HealthDetailed>({
    queryKey: ['health-detailed'],
    queryFn: () => apiFetch<HealthDetailed>('/api/v1/health/detailed'),
    staleTime: 60_000,
    retry: false,
  })

  // Filter FAQ by search
  const filteredFaq = useMemo(() => {
    if (!searchQuery.trim()) return FAQ_ITEMS
    const q = searchQuery.toLowerCase()
    return FAQ_ITEMS.filter(
      (item) =>
        item.question.toLowerCase().includes(q) ||
        item.answer.toLowerCase().includes(q)
    )
  }, [searchQuery])

  // Filter categories by search
  const filteredCategories = useMemo(() => {
    if (!searchQuery.trim()) return CATEGORIES
    const q = searchQuery.toLowerCase()
    return CATEGORIES.filter(
      (cat) =>
        cat.label.toLowerCase().includes(q) ||
        cat.description.toLowerCase().includes(q)
    )
  }, [searchQuery])

  const hasSearchResults =
    filteredFaq.length > 0 || filteredCategories.length > 0

  return (
    <div className="p-6 space-y-8 min-h-screen bg-[#070d19]">

      {/* ── Header ───────────────────────────────────────────────────────── */}
      <div className="flex flex-col sm:flex-row sm:items-center gap-4">
        <div className="flex items-center gap-3 flex-1">
          <div className="w-9 h-9 rounded-lg bg-falcon-red/10 border border-falcon-red/30
                          flex items-center justify-center shrink-0">
            <HelpCircle className="w-5 h-5 text-falcon-red" />
          </div>
          <div>
            <h1 className="text-xl font-bold text-white">ヘルプ &amp; ドキュメント</h1>
            <p className="text-xs text-falcon-muted mt-0.5">Kizashi の使い方・リファレンス</p>
          </div>
        </div>

        {/* Search */}
        <div className="relative w-full sm:w-72">
          <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-falcon-subtle pointer-events-none" />
          <input
            type="text"
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
            placeholder="ドキュメントを検索..."
            className="w-full pl-9 pr-4 py-2 text-sm bg-falcon-surface border border-falcon-border rounded-lg
                       text-falcon-text placeholder-falcon-subtle
                       focus:outline-hidden focus:border-falcon-red/60 transition-colors"
          />
        </div>
      </div>

      {/* No results state */}
      {searchQuery.trim() && !hasSearchResults && (
        <div className="flex flex-col items-center justify-center py-16 text-falcon-subtle">
          <Search className="w-10 h-10 mb-3 opacity-30" />
          <p className="text-sm">「{searchQuery}」に一致する結果が見つかりませんでした</p>
          <button
            type="button"
            onClick={() => setSearchQuery('')}
            className="mt-3 text-xs text-falcon-red hover:underline"
          >
            検索をクリア
          </button>
        </div>
      )}

      {/* ── Quick Navigation ──────────────────────────────────────────────── */}
      {filteredCategories.length > 0 && (
        <section className="space-y-3">
          <h2 className="text-sm font-semibold text-falcon-muted uppercase tracking-wider flex items-center gap-2">
            <BookOpen className="w-4 h-4" />
            クイックナビゲーション
          </h2>
          <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-3">
            {filteredCategories.map((cat) => {
              const Icon = cat.icon
              return (
                <Link
                  key={cat.id}
                  href={cat.href}
                  className={`flex items-start gap-3 p-4 rounded-xl border cursor-pointer
                              transition-all hover:scale-[1.01] hover:brightness-110
                              ${cat.bg} ${cat.border}`}
                >
                  <div className={`mt-0.5 shrink-0 ${cat.color}`}>
                    <Icon className="w-5 h-5" />
                  </div>
                  <div className="min-w-0">
                    <p className={`text-sm font-semibold ${cat.color}`}>{cat.label}</p>
                    <p className="text-xs text-falcon-muted mt-0.5 leading-relaxed">{cat.description}</p>
                  </div>
                </Link>
              )
            })}
          </div>
        </section>
      )}

      <div className="grid grid-cols-1 xl:grid-cols-3 gap-6">

        {/* ── Left/Center columns ─────────────────────────────────────────── */}
        <div className="xl:col-span-2 space-y-6">

          {/* FAQ Accordion */}
          {(!searchQuery.trim() || filteredFaq.length > 0) && (
            <section className="space-y-3">
              <h2 className="text-sm font-semibold text-falcon-muted uppercase tracking-wider flex items-center gap-2">
                <HelpCircle className="w-4 h-4" />
                よくある質問 (FAQ)
              </h2>
              <div className="space-y-2">
                {filteredFaq.map((item, i) => (
                  <FaqItem key={i} question={item.question} answer={item.answer} />
                ))}
              </div>
            </section>
          )}

          {/* Keyboard Shortcuts */}
          {!searchQuery.trim() && (
            <section className="space-y-3">
              <h2 className="text-sm font-semibold text-falcon-muted uppercase tracking-wider flex items-center gap-2">
                <Keyboard className="w-4 h-4" />
                キーボードショートカット
              </h2>
              <div className="bg-falcon-surface border border-falcon-border rounded-xl overflow-hidden">
                <table className="w-full">
                  <thead>
                    <tr className="border-b border-falcon-border">
                      <th className="px-5 py-3 text-left text-xs font-semibold text-falcon-muted uppercase tracking-wide">
                        ショートカット
                      </th>
                      <th className="px-5 py-3 text-left text-xs font-semibold text-falcon-muted uppercase tracking-wide">
                        動作
                      </th>
                    </tr>
                  </thead>
                  <tbody>
                    {KEYBOARD_SHORTCUTS.map((sc, i) => (
                      <tr
                        key={i}
                        className="border-b border-falcon-border last:border-0 hover:bg-[#070d19] transition-colors"
                      >
                        <td className="px-5 py-3">
                          <div className="flex items-center gap-1.5 flex-wrap">
                            {sc.keys.map((k, ki) => (
                              <span key={ki} className="flex items-center gap-1">
                                <KbdKey>{k}</KbdKey>
                                {ki < sc.keys.length - 1 && (
                                  <span className="text-xs text-falcon-subtle">
                                    {sc.keys.length === 2 && sc.keys[0].length === 1 ? 'then' : '+'}
                                  </span>
                                )}
                              </span>
                            ))}
                          </div>
                        </td>
                        <td className="px-5 py-3 text-sm text-falcon-text">{sc.description}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </section>
          )}
        </div>

        {/* ── Right column: utility cards ───────────────────────────────── */}
        <div className="space-y-4">

          {/* API Documentation */}
          <div className="bg-falcon-surface border border-falcon-border rounded-xl p-5 space-y-3">
            <h3 className="text-sm font-semibold text-white flex items-center gap-2">
              <BookOpen className="w-4 h-4 text-blue-400" />
              APIドキュメント
            </h3>
            <p className="text-xs text-falcon-muted leading-relaxed">
              REST API の全エンドポイント仕様を Swagger UI で確認できます。
              認証・リクエスト例・レスポンス形式が網羅されています。
            </p>
            <a
              href="/api/docs"
              target="_blank"
              rel="noopener noreferrer"
              className="flex items-center gap-2 px-4 py-2 rounded-lg text-sm font-medium
                         bg-blue-900/30 border border-blue-800/50 text-blue-300
                         hover:bg-blue-900/50 hover:text-white transition-colors"
            >
              <ExternalLink className="w-3.5 h-3.5" />
              Swagger UI を開く
            </a>
          </div>

          {/* Support */}
          <div className="bg-falcon-surface border border-falcon-border rounded-xl p-5 space-y-3">
            <h3 className="text-sm font-semibold text-white flex items-center gap-2">
              <Mail className="w-4 h-4 text-falcon-red" />
              サポート &amp; お問い合わせ
            </h3>
            <p className="text-xs text-falcon-muted leading-relaxed">
              バグ報告・機能要望・技術的な質問はサポートチームまたは GitHub リポジトリへ。
            </p>
            <div className="space-y-2">
              <a
                href="mailto:support@kizashi-edr.example.com"
                className="flex items-center gap-2 px-4 py-2 rounded-lg text-sm
                           bg-[#070d19] border border-falcon-border text-falcon-muted
                           hover:border-falcon-red/40 hover:text-falcon-text transition-colors"
              >
                <Mail className="w-3.5 h-3.5 text-falcon-red" />
                support@kizashi-edr.example.com
              </a>
              <a
                href="https://github.com/your-org/kizashi-edr/issues"
                target="_blank"
                rel="noopener noreferrer"
                className="flex items-center gap-2 px-4 py-2 rounded-lg text-sm
                           bg-[#070d19] border border-falcon-border text-falcon-muted
                           hover:border-falcon-muted/40 hover:text-falcon-text transition-colors"
              >
                <Github className="w-3.5 h-3.5" />
                GitHub Issues
              </a>
            </div>
          </div>

          {/* Version Info */}
          <div className="bg-falcon-surface border border-falcon-border rounded-xl p-5 space-y-3">
            <h3 className="text-sm font-semibold text-white flex items-center gap-2">
              <Info className="w-4 h-4 text-falcon-muted" />
              バージョン情報
            </h3>
            {healthData ? (
              <dl className="space-y-2">
                {[
                  { label: 'バージョン', value: healthData.version ?? '—' },
                  { label: 'ビルド', value: healthData.build ?? '—' },
                  { label: 'API バージョン', value: healthData.api_version ?? '—' },
                  { label: '環境', value: healthData.environment ?? '—' },
                  {
                    label: '稼働時間',
                    value: healthData.uptime_seconds != null
                      ? formatUptime(healthData.uptime_seconds)
                      : '—',
                  },
                ].map(({ label, value }) => (
                  <div key={label} className="flex items-center justify-between gap-2">
                    <dt className="text-xs text-falcon-muted">{label}</dt>
                    <dd className="text-xs font-mono text-falcon-text text-right">{value}</dd>
                  </div>
                ))}
              </dl>
            ) : (
              <div className="flex items-center gap-2 text-xs text-falcon-subtle">
                <div className="w-3 h-3 border border-falcon-subtle border-t-transparent rounded-full animate-spin" />
                取得中...
              </div>
            )}
          </div>
        </div>
      </div>
    </div>
  )
}

// ─── Helpers ──────────────────────────────────────────────────────────────────

function formatUptime(seconds: number): string {
  const d = Math.floor(seconds / 86400)
  const h = Math.floor((seconds % 86400) / 3600)
  const m = Math.floor((seconds % 3600) / 60)
  const parts: string[] = []
  if (d > 0) parts.push(`${d}日`)
  if (h > 0) parts.push(`${h}時間`)
  if (m > 0 || parts.length === 0) parts.push(`${m}分`)
  return parts.join(' ')
}

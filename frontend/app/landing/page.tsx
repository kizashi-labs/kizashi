'use client'

import { useRouter } from 'next/navigation'
import { Shield, Activity, Eye, Lock, Zap, Globe, ChevronRight, Check, ArrowRight, Server, Users, BarChart3, AlertTriangle } from 'lucide-react'

// ── Feature cards data ──────────────────────────────────────────
const FEATURES = [
  {
    icon: Eye,
    title: 'リアルタイム脅威検知',
    description: 'Sigma/YARAルール + MLベースの行動分析により、既知・未知の脅威をリアルタイムで検知します。',
  },
  {
    icon: Activity,
    title: 'UEBA & 異常検知',
    description: 'ユーザー・エンドポイントの行動ベースラインを自動構築し、逸脱を即座に検出します。',
  },
  {
    icon: Zap,
    title: 'AI自動インシデント対応',
    description: 'Claude AIによるアラート自動分類・調査レポート生成・プレイブック実行で平均対応時間を90%削減。',
  },
  {
    icon: Lock,
    title: 'ゼロトラスト & PAM',
    description: '特権アクセス管理とゼロトラストポリシーでラテラルムーブメントをブロックします。',
  },
  {
    icon: Globe,
    title: '脅威インテリジェンス',
    description: 'MITRE ATT&CK連携・IOC自動エンリッチメント・TAXII 2.1フィードで最新の脅威情報を常時反映。',
  },
  {
    icon: BarChart3,
    title: 'コンプライアンス自動評価',
    description: 'CIS Benchmark / NIST CSF / ISO 27001 / SOC2に対応した自動スコアリングとレポート生成。',
  },
]

// ── Stats ───────────────────────────────────────────────────────
const STATS = [
  { value: '99.9%', label: '検知精度' },
  { value: '<1ms', label: 'アラートレイテンシ' },
  { value: '500+', label: '組み込み検知ルール' },
  { value: '10M+', label: 'イベント/日 処理能力' },
]

// ── Pricing plans ───────────────────────────────────────────────
const PLANS = [
  {
    name: 'Starter',
    price: '¥29,800',
    period: '/月',
    description: '小規模チーム向けの基本的なEDR機能',
    features: [
      'エンドポイント最大50台',
      'リアルタイム脅威検知',
      'アラート管理・通知',
      'コンプライアンスレポート',
      'メールサポート',
    ],
    cta: '無料トライアル開始',
    highlighted: false,
  },
  {
    name: 'Professional',
    price: '¥89,800',
    period: '/月',
    description: '成長企業のセキュリティ運用に必要なすべて',
    features: [
      'エンドポイント最大500台',
      'AIインシデント対応',
      'UEBA & 行動分析',
      '脅威インテリジェンス連携',
      'SIEM / SOAR連携',
      'ライブレスポンス機能',
      '優先サポート',
    ],
    cta: '無料トライアル開始',
    highlighted: true,
  },
  {
    name: 'Enterprise',
    price: 'お問い合わせ',
    period: '',
    description: '大規模組織向けのフルマネージドセキュリティ',
    features: [
      'エンドポイント無制限',
      'マルチテナント対応',
      'カスタム検知ルール開発',
      '専任セキュリティエンジニア',
      'SLA 99.99%保証',
      'オンプレミス/ハイブリッド対応',
    ],
    cta: '営業に問い合わせる',
    highlighted: false,
  },
]

// ── Testimonials ────────────────────────────────────────────────
const TESTIMONIALS = [
  {
    quote: 'Kizashiを導入してから、ランサムウェア攻撃の試みを100%ブロックできています。AIによる自動対応が特に優秀です。',
    author: '田中 健一',
    role: 'CTO, 製造業A社',
    initials: 'TK',
  },
  {
    quote: 'SOCチームの対応時間が平均4時間から15分に短縮されました。プレイブック自動実行の効果は絶大です。',
    author: '鈴木 美香',
    role: 'CISO, 金融機関B社',
    initials: 'SM',
  },
  {
    quote: 'MITRE ATT&CKマッピングとコンプライアンス自動レポートで監査対応工数が80%削減できました。',
    author: '佐藤 雄二',
    role: 'セキュリティマネージャー, IT企業C社',
    initials: 'SY',
  },
]

export default function LandingPage() {
  const router = useRouter()

  return (
    <div className="min-h-screen bg-[#060d1a] text-white overflow-x-hidden">
      {/* ── Navigation ─────────────────────────────────────────── */}
      <nav className="sticky top-0 z-50 border-b border-falcon-border/80 backdrop-blur-md bg-[#060d1a]/90">
        <div className="max-w-7xl mx-auto px-6 h-16 flex items-center justify-between">
          <div className="flex items-center gap-2.5">
            <div className="w-8 h-8 bg-falcon-red rounded-lg flex items-center justify-center shrink-0">
              <span className="text-white font-bold text-sm">V</span>
            </div>
            <span className="text-lg font-bold text-white tracking-tight">Kizashi</span>
          </div>
          <div className="hidden md:flex items-center gap-8 text-sm text-falcon-muted">
            <a href="#features" className="hover:text-white transition-colors">機能</a>
            <a href="#stats" className="hover:text-white transition-colors">実績</a>
            <a href="#pricing" className="hover:text-white transition-colors">料金</a>
            <a href="#testimonials" className="hover:text-white transition-colors">導入事例</a>
          </div>
          <div className="flex items-center gap-3">
            <button
              onClick={() => router.push('/login')}
              className="text-sm text-falcon-muted hover:text-white transition-colors px-4 py-2"
            >
              ログイン
            </button>
            <button
              onClick={() => router.push('/login')}
              className="text-sm bg-falcon-red hover:bg-[#c4001f] text-white px-4 py-2 rounded-lg font-semibold transition-colors"
            >
              無料トライアル
            </button>
          </div>
        </div>
      </nav>

      {/* ── Hero ───────────────────────────────────────────────── */}
      <section className="relative pt-24 pb-32 px-6 overflow-hidden">
        {/* Background glow */}
        <div className="absolute inset-0 pointer-events-none">
          <div className="absolute top-0 left-1/2 -translate-x-1/2 w-[800px] h-[600px] bg-falcon-red/5 rounded-full blur-[120px]" />
          <div className="absolute top-20 left-1/4 w-[400px] h-[400px] bg-blue-500/5 rounded-full blur-[100px]" />
        </div>

        <div className="relative max-w-5xl mx-auto text-center">
          {/* Badge */}
          <div className="inline-flex items-center gap-2 bg-falcon-red/10 border border-falcon-red/30 text-falcon-red text-xs font-semibold px-3 py-1.5 rounded-full mb-8">
            <span className="w-1.5 h-1.5 bg-falcon-red rounded-full animate-pulse" />
            次世代エンドポイント検知・対応プラットフォーム
          </div>

          <h1 className="text-5xl md:text-7xl font-bold text-white leading-tight mb-6 tracking-tight">
            脅威を<span className="text-falcon-red">検知</span>し、<br />
            即座に<span className="text-falcon-red">対応</span>する
          </h1>

          <p className="text-xl text-falcon-muted max-w-2xl mx-auto mb-10 leading-relaxed">
            Kizashiは、AIと機械学習を活用した次世代EDRプラットフォームです。
            リアルタイム脅威検知から自動インシデント対応まで、
            SOCチームの運用効率を10倍に高めます。
          </p>

          <div className="flex flex-col sm:flex-row gap-4 justify-center">
            <button
              onClick={() => router.push('/login')}
              className="inline-flex items-center justify-center gap-2 bg-falcon-red hover:bg-[#c4001f] text-white px-8 py-4 rounded-xl font-bold text-base transition-all hover:scale-105 shadow-lg shadow-falcon-red/20"
            >
              14日間無料トライアル
              <ArrowRight className="w-4 h-4" />
            </button>
            <button
              onClick={() => router.push('/login')}
              className="inline-flex items-center justify-center gap-2 bg-[#0d1829] hover:bg-[#1a2840] border border-falcon-border text-white px-8 py-4 rounded-xl font-semibold text-base transition-colors"
            >
              デモを見る
              <ChevronRight className="w-4 h-4" />
            </button>
          </div>

          <p className="text-xs text-falcon-subtle mt-6">クレジットカード不要 • セットアップ5分 • 即日利用開始可能</p>
        </div>

        {/* Dashboard preview */}
        <div className="relative max-w-5xl mx-auto mt-16">
          <div className="bg-[#0a1628] border border-falcon-border rounded-2xl overflow-hidden shadow-2xl">
            {/* Mock browser bar */}
            <div className="flex items-center gap-2 px-4 py-3 bg-[#060d1a] border-b border-falcon-border">
              <div className="flex gap-1.5">
                <div className="w-3 h-3 bg-[#ff5f57] rounded-full" />
                <div className="w-3 h-3 bg-[#ffbd2e] rounded-full" />
                <div className="w-3 h-3 bg-[#28c840] rounded-full" />
              </div>
              <div className="flex-1 bg-[#0d1829] rounded-md px-3 py-1 text-xs text-falcon-subtle text-center">
                kizashi-edr.example.com/dashboard
              </div>
            </div>
            {/* Mock dashboard content */}
            <div className="p-6 grid grid-cols-2 md:grid-cols-4 gap-4">
              {[
                { label: 'アクティブアラート', value: '24', color: '#e8002d', icon: AlertTriangle },
                { label: 'オンラインエンドポイント', value: '1,247', color: '#22c55e', icon: Server },
                { label: '本日の検知', value: '156', color: '#3b82f6', icon: Eye },
                { label: '対応済みインシデント', value: '98.2%', color: '#f59e0b', icon: Users },
              ].map(({ label, value, color, icon: Icon }) => (
                <div key={label} className="bg-[#060d1a] rounded-xl p-4 border border-falcon-border">
                  <div className="flex items-center justify-between mb-2">
                    <span className="text-xs text-falcon-subtle">{label}</span>
                    <Icon className="w-4 h-4" style={{ color }} />
                  </div>
                  <div className="text-2xl font-bold" style={{ color }}>{value}</div>
                </div>
              ))}
            </div>
            <div className="px-6 pb-6">
              <div className="bg-[#060d1a] rounded-xl border border-falcon-border p-4">
                <div className="flex items-center justify-between mb-3">
                  <span className="text-xs font-semibold text-falcon-muted">最近のアラート</span>
                  <span className="text-xs text-falcon-red">リアルタイム</span>
                </div>
                {[
                  { rule: 'Ransomware - ファイル暗号化活動検知', host: 'WIN-SERVER-01', severity: 'critical', time: '今すぐ' },
                  { rule: 'Lateral Movement - PSExec実行', host: 'WORKSTATION-42', severity: 'high', time: '2分前' },
                  { rule: 'Credential Dumping - LSASS Access', host: 'DC-PRIMARY', severity: 'high', time: '5分前' },
                ].map((alert, i) => (
                  <div key={i} className="flex items-center gap-3 py-2 border-t border-falcon-border first:border-0">
                    <div className={`w-2 h-2 rounded-full shrink-0 ${alert.severity === 'critical' ? 'bg-falcon-red animate-pulse' : 'bg-orange-500'}`} />
                    <div className="flex-1 min-w-0">
                      <p className="text-xs text-falcon-text truncate">{alert.rule}</p>
                      <p className="text-[10px] text-falcon-subtle">{alert.host}</p>
                    </div>
                    <span className="text-[10px] text-falcon-subtle shrink-0">{alert.time}</span>
                  </div>
                ))}
              </div>
            </div>
          </div>
        </div>
      </section>

      {/* ── Stats ──────────────────────────────────────────────── */}
      <section id="stats" className="py-16 border-y border-falcon-border bg-[#060d1a]">
        <div className="max-w-5xl mx-auto px-6">
          <div className="grid grid-cols-2 md:grid-cols-4 gap-8">
            {STATS.map(({ value, label }) => (
              <div key={label} className="text-center">
                <div className="text-4xl font-bold text-white mb-2">{value}</div>
                <div className="text-sm text-falcon-muted">{label}</div>
              </div>
            ))}
          </div>
        </div>
      </section>

      {/* ── Features ───────────────────────────────────────────── */}
      <section id="features" className="py-24 px-6">
        <div className="max-w-5xl mx-auto">
          <div className="text-center mb-16">
            <h2 className="text-4xl font-bold text-white mb-4">エンタープライズグレードの機能</h2>
            <p className="text-lg text-falcon-muted max-w-2xl mx-auto">
              CrowdStrike・SentinelOneと同等のセキュリティ機能を、より手頃なコストで提供します。
            </p>
          </div>
          <div className="grid md:grid-cols-3 gap-6">
            {FEATURES.map(({ icon: Icon, title, description }) => (
              <div
                key={title}
                className="bg-[#0a1628] border border-falcon-border rounded-xl p-6 hover:border-falcon-red/30 transition-colors group"
              >
                <div className="w-10 h-10 bg-falcon-red/10 rounded-lg flex items-center justify-center mb-4 group-hover:bg-falcon-red/20 transition-colors">
                  <Icon className="w-5 h-5 text-falcon-red" />
                </div>
                <h3 className="text-base font-semibold text-white mb-2">{title}</h3>
                <p className="text-sm text-falcon-muted leading-relaxed">{description}</p>
              </div>
            ))}
          </div>
        </div>
      </section>

      {/* ── Pricing ─────────────────────────────────────────────── */}
      <section id="pricing" className="py-24 px-6 bg-[#060d1a]">
        <div className="max-w-5xl mx-auto">
          <div className="text-center mb-16">
            <h2 className="text-4xl font-bold text-white mb-4">シンプルな料金プラン</h2>
            <p className="text-lg text-falcon-muted">規模に合わせて選べる3つのプラン。すべて14日間無料トライアル付き。</p>
          </div>
          <div className="grid md:grid-cols-3 gap-6">
            {PLANS.map(({ name, price, period, description, features, cta, highlighted }) => (
              <div
                key={name}
                className={`relative rounded-2xl border p-8 flex flex-col ${
                  highlighted
                    ? 'bg-[#0d1829] border-falcon-red shadow-lg shadow-falcon-red/10'
                    : 'bg-[#0a1628] border-falcon-border'
                }`}
              >
                {highlighted && (
                  <div className="absolute -top-3 left-1/2 -translate-x-1/2 bg-falcon-red text-white text-xs font-bold px-3 py-1 rounded-full">
                    最も人気
                  </div>
                )}
                <div className="mb-6">
                  <h3 className="text-lg font-bold text-white mb-1">{name}</h3>
                  <p className="text-sm text-falcon-muted mb-4">{description}</p>
                  <div className="flex items-baseline gap-1">
                    <span className="text-3xl font-bold text-white">{price}</span>
                    <span className="text-sm text-falcon-muted">{period}</span>
                  </div>
                </div>
                <ul className="space-y-3 flex-1 mb-8">
                  {features.map(f => (
                    <li key={f} className="flex items-start gap-2 text-sm text-falcon-muted">
                      <Check className="w-4 h-4 text-[#22c55e] shrink-0 mt-0.5" />
                      {f}
                    </li>
                  ))}
                </ul>
                <button
                  onClick={() => router.push('/login')}
                  className={`w-full py-3 rounded-xl font-semibold text-sm transition-colors ${
                    highlighted
                      ? 'bg-falcon-red hover:bg-[#c4001f] text-white'
                      : 'bg-falcon-border hover:bg-[#243650] text-white'
                  }`}
                >
                  {cta}
                </button>
              </div>
            ))}
          </div>
        </div>
      </section>

      {/* ── Testimonials ────────────────────────────────────────── */}
      <section id="testimonials" className="py-24 px-6">
        <div className="max-w-5xl mx-auto">
          <div className="text-center mb-16">
            <h2 className="text-4xl font-bold text-white mb-4">導入企業の声</h2>
            <p className="text-lg text-falcon-muted">業種を問わず多くの企業で採用されています。</p>
          </div>
          <div className="grid md:grid-cols-3 gap-6">
            {TESTIMONIALS.map(({ quote, author, role, initials }) => (
              <div key={author} className="bg-[#0a1628] border border-falcon-border rounded-xl p-6">
                <p className="text-sm text-falcon-muted leading-relaxed mb-6">&ldquo;{quote}&rdquo;</p>
                <div className="flex items-center gap-3">
                  <div className="w-10 h-10 bg-falcon-red/20 rounded-full flex items-center justify-center text-falcon-red font-bold text-sm shrink-0">
                    {initials}
                  </div>
                  <div>
                    <div className="text-sm font-semibold text-white">{author}</div>
                    <div className="text-xs text-falcon-subtle">{role}</div>
                  </div>
                </div>
              </div>
            ))}
          </div>
        </div>
      </section>

      {/* ── CTA ─────────────────────────────────────────────────── */}
      <section className="py-24 px-6 bg-[#060d1a] border-t border-falcon-border">
        <div className="max-w-3xl mx-auto text-center">
          <h2 className="text-4xl font-bold text-white mb-4">今すぐセキュリティを強化する</h2>
          <p className="text-lg text-falcon-muted mb-10">
            14日間の無料トライアルで、Kizashiのすべての機能をご体験ください。
            クレジットカード不要、5分でセットアップ完了。
          </p>
          <button
            onClick={() => router.push('/login')}
            className="inline-flex items-center gap-2 bg-falcon-red hover:bg-[#c4001f] text-white px-10 py-4 rounded-xl font-bold text-base transition-all hover:scale-105 shadow-lg shadow-falcon-red/20"
          >
            無料トライアルを開始する
            <ArrowRight className="w-5 h-5" />
          </button>
        </div>
      </section>

      {/* ── Footer ──────────────────────────────────────────────── */}
      <footer className="border-t border-falcon-border py-10 px-6">
        <div className="max-w-5xl mx-auto flex flex-col md:flex-row items-center justify-between gap-4">
          <div className="flex items-center gap-2.5">
            <div className="w-6 h-6 bg-falcon-red rounded-sm flex items-center justify-center">
              <span className="text-white font-bold text-xs">V</span>
            </div>
            <span className="text-sm font-semibold text-white">Kizashi</span>
          </div>
          <p className="text-xs text-falcon-subtle">
            © 2026 Kizashi. All rights reserved.
          </p>
          <div className="flex items-center gap-6 text-xs text-falcon-subtle">
            <a href="#" className="hover:text-falcon-muted transition-colors">プライバシーポリシー</a>
            <a href="#" className="hover:text-falcon-muted transition-colors">利用規約</a>
            <a href="#" className="hover:text-falcon-muted transition-colors">セキュリティ</a>
          </div>
        </div>
      </footer>
    </div>
  )
}

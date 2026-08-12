'use client'

import { useRef, useState } from 'react'
import Link from 'next/link'
import {
  BookOpen, Download, Terminal, Shield, Settings, AlertTriangle,
  CheckCircle, Copy, Check, ChevronRight, HelpCircle, Server,
  Users, Key, Bell, RefreshCw, Database, Lock,
} from 'lucide-react'

// ─── Copy Button ─────────────────────────────────────────────────────────────

function CopyBtn({ text }: { text: string }) {
  const [copied, setCopied] = useState(false)
  const handle = async () => {
    await navigator.clipboard.writeText(text)
    setCopied(true)
    setTimeout(() => setCopied(false), 2000)
  }
  return (
    <button
      onClick={handle}
      className="p-1.5 rounded text-[#5a6a7a] hover:text-[#e2e8f4] hover:bg-[#1e2d42] transition-colors"
    >
      {copied ? <Check className="w-3.5 h-3.5 text-[#22c55e]" /> : <Copy className="w-3.5 h-3.5" />}
    </button>
  )
}

// ─── Code Block ──────────────────────────────────────────────────────────────

function Code({ children, lang = 'bash' }: { children: string; lang?: string }) {
  return (
    <div className="relative group rounded-lg bg-[#070d19] border border-[#1e2d42] overflow-hidden mb-4">
      <div className="flex items-center justify-between px-3 py-1.5 border-b border-[#1e2d42] bg-[#0d1220]">
        <span className="text-[10px] font-mono text-[#5a6a7a] uppercase">{lang}</span>
        <CopyBtn text={children} />
      </div>
      <pre className="p-4 text-xs font-mono text-[#e2e8f4] overflow-x-auto leading-relaxed whitespace-pre-wrap">
        {children}
      </pre>
    </div>
  )
}

// ─── Callout ─────────────────────────────────────────────────────────────────

function Callout({ type, children }: { type: 'info' | 'warn' | 'tip'; children: React.ReactNode }) {
  const styles = {
    info: { bg: 'bg-[#3b82f6]/10 border-[#3b82f6]/30', icon: <Shield className="w-4 h-4 text-[#3b82f6] flex-shrink-0 mt-0.5" /> },
    warn: { bg: 'bg-[#f59e0b]/10 border-[#f59e0b]/30', icon: <AlertTriangle className="w-4 h-4 text-[#f59e0b] flex-shrink-0 mt-0.5" /> },
    tip:  { bg: 'bg-[#22c55e]/10 border-[#22c55e]/30', icon: <CheckCircle className="w-4 h-4 text-[#22c55e] flex-shrink-0 mt-0.5" /> },
  }
  const s = styles[type]
  return (
    <div className={`flex gap-3 p-3 rounded-lg border mb-4 ${s.bg}`}>
      {s.icon}
      <div className="text-xs text-[#8899aa] leading-relaxed">{children}</div>
    </div>
  )
}

// ─── Section ─────────────────────────────────────────────────────────────────

function Section({ id, title, icon, children }: {
  id: string; title: string; icon: React.ReactNode; children: React.ReactNode
}) {
  return (
    <section id={id} className="mb-12 scroll-mt-6">
      <div className="flex items-center gap-3 mb-5 pb-3 border-b border-[#1e2d42]">
        <div className="w-8 h-8 rounded-lg bg-[#1e2d42] flex items-center justify-center text-[#e8002d]">
          {icon}
        </div>
        <h2 className="text-lg font-semibold text-[#e2e8f4]">{title}</h2>
      </div>
      <div className="text-sm text-[#8899aa] leading-relaxed space-y-4">
        {children}
      </div>
    </section>
  )
}

function H3({ children }: { children: React.ReactNode }) {
  return <h3 className="text-sm font-semibold text-[#e2e8f4] mt-6 mb-2">{children}</h3>
}

// ─── 目次 ─────────────────────────────────────────────────────────────────────

const TOC = [
  { id: 'install',       label: 'システム要件とインストール', icon: <Download className="w-4 h-4" /> },
  { id: 'initial',       label: '初期設定',                   icon: <Settings className="w-4 h-4" /> },
  { id: 'agents',        label: 'エージェント管理',           icon: <Terminal className="w-4 h-4" /> },
  { id: 'users',         label: 'ユーザー・権限管理',         icon: <Users className="w-4 h-4" /> },
  { id: 'detection',     label: '検知ルール設定',             icon: <Shield className="w-4 h-4" /> },
  { id: 'alerts',        label: 'アラート・インシデント対応', icon: <Bell className="w-4 h-4" /> },
  { id: 'backup',        label: 'バックアップ・復元',         icon: <Database className="w-4 h-4" /> },
  { id: 'integrations',  label: '外部連携',                   icon: <RefreshCw className="w-4 h-4" /> },
  { id: 'troubleshoot',  label: 'トラブルシューティング',     icon: <HelpCircle className="w-4 h-4" /> },
]

// ─── Page ─────────────────────────────────────────────────────────────────────

export default function AdminGuidePage() {
  const [activeId, setActiveId] = useState('install')
  const refs = useRef<Record<string, HTMLElement | null>>({})

  const scrollTo = (id: string) => {
    setActiveId(id)
    refs.current[id]?.scrollIntoView({ behavior: 'smooth', block: 'start' })
  }

  return (
    <div className="flex h-full bg-[#080c14] text-[#e2e8f4]">

      {/* ── 左サイドバー ─────────────────────────────────────────── */}
      <aside className="w-56 flex-shrink-0 border-r border-[#1e2d42] sticky top-0 h-screen overflow-y-auto">
        <div className="p-4 border-b border-[#1e2d42]">
          <div className="flex items-center gap-2">
            <BookOpen className="w-4 h-4 text-[#e8002d]" />
            <span className="text-sm font-semibold">管理者ガイド</span>
          </div>
          <p className="text-[10px] text-[#5a6a7a] mt-1">Kizashi v2.x</p>
        </div>
        <nav className="p-3 space-y-0.5">
          {TOC.map(item => (
            <button
              key={item.id}
              onClick={() => scrollTo(item.id)}
              className={`w-full flex items-center gap-2 px-3 py-2 rounded text-xs transition-colors ${
                activeId === item.id
                  ? 'bg-[#1e2d42] text-[#e2e8f4]'
                  : 'text-[#5a6a7a] hover:bg-[#111827] hover:text-[#8899aa]'
              }`}
            >
              <span className="flex-shrink-0 w-4">{item.icon}</span>
              {item.label}
            </button>
          ))}
        </nav>
        <div className="p-4 border-t border-[#1e2d42] mt-auto">
          <Link href="/admin/api-docs" className="flex items-center gap-2 text-xs text-[#5a6a7a] hover:text-[#8899aa]">
            <ChevronRight className="w-3 h-3" />
            APIリファレンス
          </Link>
          <Link href="/support" className="flex items-center gap-2 text-xs text-[#5a6a7a] hover:text-[#8899aa] mt-2">
            <ChevronRight className="w-3 h-3" />
            サポートチケット
          </Link>
        </div>
      </aside>

      {/* ── メインコンテンツ ──────────────────────────────────────── */}
      <main className="flex-1 overflow-y-auto">
        {/* ヘッダー */}
        <div className="border-b border-[#1e2d42] p-6 bg-[#0d1220]">
          <h1 className="text-2xl font-bold text-[#e2e8f4] mb-1">管理者ガイド</h1>
          <p className="text-sm text-[#5a6a7a]">Kizashi の導入・設定・運用に関するリファレンスガイド</p>
        </div>

        <div className="max-w-3xl mx-auto p-6 space-y-0">

          {/* ── 1. システム要件とインストール ────────────────────── */}
          <div ref={el => { refs.current['install'] = el }}>
          <Section id="install" title="システム要件とインストール" icon={<Download className="w-4 h-4" />}>
            <H3>サーバー要件</H3>
            <div className="overflow-x-auto mb-4">
              <table className="w-full text-xs border-collapse">
                <thead>
                  <tr className="border-b border-[#1e2d42]">
                    <th className="text-left py-2 pr-4 text-[#5a6a7a]">項目</th>
                    <th className="text-left py-2 pr-4 text-[#5a6a7a]">最小要件</th>
                    <th className="text-left py-2 text-[#5a6a7a]">推奨</th>
                  </tr>
                </thead>
                <tbody>
                  {[
                    ['CPU',    '4 コア',   '8 コア以上'],
                    ['RAM',    '8 GB',     '16 GB 以上'],
                    ['ストレージ', '100 GB SSD', '500 GB NVMe SSD'],
                    ['OS',     'Ubuntu 22.04 / Debian 12', 'Ubuntu 22.04 LTS'],
                    ['Docker', '24.x',     '最新安定版'],
                  ].map(([item, min, rec]) => (
                    <tr key={item} className="border-b border-[#1e2d42]/50">
                      <td className="py-2 pr-4 text-[#e2e8f4] font-medium">{item}</td>
                      <td className="py-2 pr-4">{min}</td>
                      <td className="py-2">{rec}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>

            <H3>Docker Compose によるデプロイ</H3>
            <p>本番環境では <code className="text-[#e8002d] font-mono text-xs">docker-compose.prod.yml</code> を使用します。</p>
            <Code lang="bash">{`# リポジトリをクローン
git clone https://github.com/your-org/edr-platform.git
cd edr-platform/deploy

# 環境変数ファイルを作成
cp .env.prod.example .env.prod

# .env.prod を編集（必須項目を設定）
vi .env.prod

# 起動
docker compose -f docker-compose.prod.yml up -d

# ログ確認
docker compose -f docker-compose.prod.yml logs -f api`}</Code>

            <H3>必須環境変数</H3>
            <div className="overflow-x-auto mb-4">
              <table className="w-full text-xs border-collapse">
                <thead>
                  <tr className="border-b border-[#1e2d42]">
                    <th className="text-left py-2 pr-4 text-[#5a6a7a]">変数名</th>
                    <th className="text-left py-2 text-[#5a6a7a]">説明</th>
                  </tr>
                </thead>
                <tbody>
                  {[
                    ['EDR_DOMAIN',          'サービスのドメイン名（例: edr.example.com）'],
                    ['DATABASE_URL',        'PostgreSQL接続文字列'],
                    ['JWT_SECRET',          'JWT署名秘密鍵（32文字以上のランダム文字列）'],
                    ['NEXTAUTH_SECRET',     'Next.js認証秘密鍵'],
                    ['ADMIN_EMAIL',         '初期管理者のメールアドレス'],
                    ['ADMIN_PASSWORD',      '初期管理者パスワード'],
                    ['ENROLLMENT_TOKEN',    'エージェント登録トークン（hex文字列）'],
                  ].map(([k, v]) => (
                    <tr key={k} className="border-b border-[#1e2d42]/50">
                      <td className="py-2 pr-4"><code className="text-[#e8002d] font-mono text-xs">{k}</code></td>
                      <td className="py-2">{v}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>

            <Callout type="warn">
              <strong>セキュリティ:</strong> <code className="font-mono text-xs">.env.prod</code> はバージョン管理に含めないでください。
              本番環境では <code className="font-mono text-xs">ADMIN_PASSWORD</code> を初回ログイン後に変更してください。
            </Callout>

            <H3>TLS証明書の設定</H3>
            <p>Caddy はドメインに対して自動でLet&apos;s Encrypt証明書を取得します。ドメインのDNSが正しく向いている必要があります。</p>
            <Code lang="bash">{`# DNS確認
nslookup edr.example.com

# Caddy証明書のステータス確認
docker exec edr-caddy caddy trust`}</Code>
          </Section>
          </div>

          {/* ── 2. 初期設定 ──────────────────────────────────────── */}
          <div ref={el => { refs.current['initial'] = el }}>
          <Section id="initial" title="初期設定" icon={<Settings className="w-4 h-4" />}>
            <H3>管理者アカウントへのログイン</H3>
            <p>初回起動後、<code className="text-[#e8002d] font-mono text-xs">ADMIN_EMAIL</code> / <code className="text-[#e8002d] font-mono text-xs">ADMIN_PASSWORD</code> でログインします。</p>
            <ol className="list-decimal pl-5 space-y-1">
              <li><code className="text-[#e2e8f4] font-mono text-xs">https://&#123;EDR_DOMAIN&#125;/login</code> にアクセス</li>
              <li>メールアドレスとパスワードを入力してログイン</li>
              <li>セットアップウィザード（<code className="text-[#e2e8f4] font-mono text-xs">/admin/onboarding</code>）を完了</li>
            </ol>

            <H3>ライセンスキーの有効化</H3>
            <p>商用利用には有効なライセンスキーが必要です。</p>
            <ol className="list-decimal pl-5 space-y-1">
              <li>左サイドバー → <strong className="text-[#e2e8f4]">システム</strong> → <strong className="text-[#e2e8f4]">ライセンス</strong> を開く</li>
              <li>発行されたライセンスキーを貼り付けて「有効化」をクリック</li>
              <li>エンドポイント数とプランが表示されることを確認</li>
            </ol>

            <Callout type="info">
              ライセンスキーの発行は、サポートチケット（<Link href="/support" className="text-[#3b82f6] hover:underline">/support</Link>）からお申し込みください。
            </Callout>

            <H3>テナント設定</H3>
            <p>マルチテナント環境では、<strong className="text-[#e2e8f4]">テナント管理</strong> からテナントを作成し、各テナントにユーザーを割り当てます。</p>
            <Code lang="bash">{`# テナントID の確認（APIから）
curl -H "Authorization: Bearer $TOKEN" \\
  https://edr.example.com/api/v1/admin/tenants | jq '.'`}</Code>
          </Section>
          </div>

          {/* ── 3. エージェント管理 ──────────────────────────────── */}
          <div ref={el => { refs.current['agents'] = el }}>
          <Section id="agents" title="エージェント管理" icon={<Terminal className="w-4 h-4" />}>
            <H3>エージェントのインストール</H3>
            <p>エージェントをエンドポイントにインストールするには、以下のコマンドを管理者権限で実行します。<code className="text-[#e8002d] font-mono text-xs">ENROLLMENT_TOKEN</code> と <code className="text-[#e8002d] font-mono text-xs">SERVER_URL</code> は環境に合わせて変更してください。</p>

            <Code lang="bash">{`# Linux / macOS
curl -fsSL https://edr.example.com/api/v1/install/linux \\
  | sudo EDR_TOKEN=your-enrollment-token bash

# Windows (PowerShell as Administrator)
[System.Net.ServicePointManager]::SecurityProtocol = [System.Net.SecurityProtocolType]::Tls12
$env:EDR_TOKEN = "your-enrollment-token"
$env:EDR_SERVER = "https://edr.example.com"
iex (irm https://edr.example.com/api/v1/install/windows)`}</Code>

            <H3>エージェントステータスの確認</H3>
            <p>エージェントは定期的にサーバーへハートビートを送信します。以下のステータスがあります：</p>
            <div className="overflow-x-auto mb-4">
              <table className="w-full text-xs border-collapse">
                <thead>
                  <tr className="border-b border-[#1e2d42]">
                    <th className="text-left py-2 pr-4 text-[#5a6a7a]">ステータス</th>
                    <th className="text-left py-2 text-[#5a6a7a]">意味</th>
                  </tr>
                </thead>
                <tbody>
                  {[
                    ['online (緑)',   '最後のハートビートから5分以内 — 正常稼働中'],
                    ['offline (灰)',  '最後のハートビートから5〜60分 — 一時的な切断'],
                    ['inactive (赤)', '最後のハートビートから60分以上 — 要確認'],
                  ].map(([s, d]) => (
                    <tr key={s} className="border-b border-[#1e2d42]/50">
                      <td className="py-2 pr-4 text-[#e2e8f4] font-mono font-medium text-xs">{s}</td>
                      <td className="py-2">{d}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>

            <H3>エージェントのアップデート</H3>
            <Code lang="bash">{`# サーバー側: 最新バージョンを配布設定
# deploy/.env.prod に記述
AGENT_LATEST_VERSION=2.2.0
AGENT_LATEST_URL=https://edr.example.com/downloads/agent-2.2.0

# エージェント側は自動アップデートポリシーに従い適用`}</Code>

            <H3>エージェントのアンインストール</H3>
            <Code lang="bash">{`# Linux
sudo systemctl stop kizashi-agent
sudo apt remove kizashi-agent  # または
sudo /opt/kizashi/uninstall.sh

# Windows (管理者PowerShell)
& "C:/Program Files/Kizashi/uninstall.exe" /S`}</Code>
          </Section>
          </div>

          {/* ── 4. ユーザー・権限管理 ────────────────────────────── */}
          <div ref={el => { refs.current['users'] = el }}>
          <Section id="users" title="ユーザー・権限管理" icon={<Users className="w-4 h-4" />}>
            <H3>ロール一覧</H3>
            <div className="overflow-x-auto mb-4">
              <table className="w-full text-xs border-collapse">
                <thead>
                  <tr className="border-b border-[#1e2d42]">
                    <th className="text-left py-2 pr-4 text-[#5a6a7a]">ロール</th>
                    <th className="text-left py-2 text-[#5a6a7a]">権限</th>
                  </tr>
                </thead>
                <tbody>
                  {[
                    ['admin',   '全機能へのフルアクセス。ユーザー管理・システム設定・ライセンス管理を含む'],
                    ['analyst', 'アラート・インシデント・レポートの閲覧・操作。ルール管理を含む'],
                    ['viewer',  '読み取り専用。アラート・ダッシュボード・レポートの閲覧のみ'],
                  ].map(([r, d]) => (
                    <tr key={r} className="border-b border-[#1e2d42]/50">
                      <td className="py-2 pr-4"><code className="text-[#e8002d] font-mono text-xs">{r}</code></td>
                      <td className="py-2">{d}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>

            <H3>ユーザーの招待</H3>
            <ol className="list-decimal pl-5 space-y-1">
              <li><strong className="text-[#e2e8f4]">設定</strong> → <strong className="text-[#e2e8f4]">ユーザー管理</strong> に移動</li>
              <li>「ユーザーを招待」ボタンをクリック</li>
              <li>メールアドレスとロールを設定して送信</li>
              <li>招待メールのリンクからアカウントを有効化</li>
            </ol>

            <H3>MFAの強制</H3>
            <p>管理者はシステム設定からテナント全体のMFA強制を有効化できます。</p>
            <Callout type="tip">
              <strong>推奨:</strong> 本番環境では全ユーザーにMFA（TOTP）を強制することを推奨します。
              <strong className="text-[#e2e8f4]">設定</strong> → <strong className="text-[#e2e8f4]">セキュリティ</strong> → 「MFAを強制」をONにしてください。
            </Callout>

            <H3>APIキーの管理</H3>
            <p>外部システム（SIEM連携等）には専用のAPIキーを発行し、最小権限の原則に従ってください。</p>
            <Code lang="bash">{`# APIキーを使ったリクエスト例
curl -H "X-API-Key: edr_live_xxxxx..." \\
     https://edr.example.com/api/v1/alerts`}</Code>
          </Section>
          </div>

          {/* ── 5. 検知ルール設定 ────────────────────────────────── */}
          <div ref={el => { refs.current['detection'] = el }}>
          <Section id="detection" title="検知ルール設定" icon={<Shield className="w-4 h-4" />}>
            <H3>組み込みルールセット</H3>
            <p>プラットフォームには以下のルールセットが組み込まれています：</p>
            <ul className="list-disc pl-5 space-y-1">
              <li><strong className="text-[#e2e8f4]">Sigma ルール</strong>: ATT&CK フレームワークに対応した汎用検知ルール（140+件）</li>
              <li><strong className="text-[#e2e8f4]">YARA ルール</strong>: マルウェアファミリーのファイルシグネチャマッチング（87+件）</li>
              <li><strong className="text-[#e2e8f4]">プロセス系譜ルール</strong>: ATT&CK テクニックに対応したプロセスチェーン分析（17件）</li>
              <li><strong className="text-[#e2e8f4]">ML/UEBA ルール</strong>: 機械学習によるベースライン逸脱検知</li>
            </ul>

            <H3>カスタムSigmaルールの追加</H3>
            <Code lang="yaml">{`title: カスタムルール - 不審なnetsh実行
status: stable
description: ネットワーク設定変更の検出
logsource:
  category: process_creation
  product: windows
detection:
  selection:
    Image|endswith: '\\netsh.exe'
    CommandLine|contains: 'firewall'
  condition: selection
level: high
tags:
  - attack.defense_evasion
  - attack.t1562.004`}</Code>

            <H3>アラートしきい値の調整</H3>
            <p>誤検知が多い場合は、<strong className="text-[#e2e8f4]">検知ルール</strong> → ルールを選択 → 「サプレッション」を追加して特定の条件を除外できます。</p>
            <Callout type="warn">
              ルールを無効化する前に、サプレッションの追加を検討してください。完全無効化は検知漏れのリスクがあります。
            </Callout>
          </Section>
          </div>

          {/* ── 6. アラート・インシデント対応 ───────────────────── */}
          <div ref={el => { refs.current['alerts'] = el }}>
          <Section id="alerts" title="アラート・インシデント対応" icon={<Bell className="w-4 h-4" />}>
            <H3>アラートのライフサイクル</H3>
            <div className="flex items-center gap-2 flex-wrap mb-4 text-xs">
              {['open', '→ in_progress', '→ resolved', '→ closed'].map((s, i) => (
                <span key={i} className={`px-2 py-1 rounded font-mono ${i === 0 ? 'bg-[#3b82f6]/20 text-[#3b82f6]' : i === 3 ? 'bg-[#5a6a7a]/20 text-[#5a6a7a]' : 'bg-[#1e2d42] text-[#8899aa]'}`}>
                  {s}
                </span>
              ))}
            </div>
            <ol className="list-decimal pl-5 space-y-1">
              <li><strong className="text-[#e2e8f4]">トリアージ</strong>: アラートを開いてClaude AIの分析結果を確認</li>
              <li><strong className="text-[#e2e8f4]">調査</strong>: タイムラインとプロセスツリーでイベントの文脈を把握</li>
              <li><strong className="text-[#e2e8f4]">対応</strong>: ライブレスポンス機能でエンドポイントを分離またはプロセスを終了</li>
              <li><strong className="text-[#e2e8f4]">記録</strong>: インシデントとしてエスカレーションしてコメント・根本原因を記録</li>
              <li><strong className="text-[#e2e8f4]">クローズ</strong>: 対応完了後にアラートをresolvedに変更</li>
            </ol>

            <H3>通知設定</H3>
            <p>重大アラート（深刻度7以上）はSlackやメールへリアルタイム通知できます。</p>
            <Code lang="bash">{`# Slack Webhook設定例 (deploy/.env.prod)
GRAFANA_SLACK_WEBHOOK=https://hooks.slack.com/services/T00000/B00000/xxxx`}</Code>
          </Section>
          </div>

          {/* ── 7. バックアップ・復元 ────────────────────────────── */}
          <div ref={el => { refs.current['backup'] = el }}>
          <Section id="backup" title="バックアップ・復元" icon={<Database className="w-4 h-4" />}>
            <H3>自動バックアップ</H3>
            <p>本番環境ではOfeliaスケジューラーが毎日深夜2時にPostgreSQLのバックアップを自動実行します。</p>
            <Code lang="bash">{`# バックアップファイルの確認
ls -la /backups/

# 手動バックアップ実行
docker exec edr-backup /scripts/backup.sh`}</Code>

            <H3>バックアップ先の設定</H3>
            <Code lang="bash">{`# S3へのバックアップ (deploy/.env.prod)
BACKUP_DEST=s3
S3_BUCKET=my-edr-backups
S3_PREFIX=edr-backups
AWS_ACCESS_KEY_ID=AKIA...
AWS_SECRET_ACCESS_KEY=...
AWS_DEFAULT_REGION=ap-northeast-1
RETENTION_DAYS=30`}</Code>

            <H3>データの復元</H3>
            <Code lang="bash">{`# バックアップからの復元
docker exec -i edr-postgres pg_restore \\
  -U edr -d edrplatform \\
  < /backups/edrplatform_20260321_0200.dump`}</Code>

            <Callout type="tip">
              復元前に現在のDBをバックアップしてから行うことを強く推奨します。本番環境では復元操作をメンテナンス時間帯に実施してください。
            </Callout>
          </Section>
          </div>

          {/* ── 8. 外部連携 ──────────────────────────────────────── */}
          <div ref={el => { refs.current['integrations'] = el }}>
          <Section id="integrations" title="外部連携" icon={<RefreshCw className="w-4 h-4" />}>
            <H3>SIEM連携（Splunk/QRadar/Elastic）</H3>
            <p>アラートやイベントをSIEMへ転送できます。CEF/LEEF/JSON形式に対応しています。</p>
            <Code lang="json">{`// POST /api/v1/siem/connectors
{
  "name": "Splunk本番",
  "type": "splunk",
  "url": "https://splunk.example.com:8088/services/collector",
  "token": "Splunk xxxx-xxxx",
  "format": "cef",
  "enabled": true
}`}</Code>

            <H3>Stripe課金連携</H3>
            <p>サブスクリプション管理にはStripeを使用します。</p>
            <Code lang="bash">{`# deploy/.env.prod
STRIPE_SECRET_KEY=sk_live_...
STRIPE_WEBHOOK_SECRET=whsec_...
STRIPE_PRICE_STARTER=price_...
STRIPE_PRICE_BUSINESS=price_...`}</Code>

            <H3>Claude AI連携</H3>
            <p>AIアシスタント機能（アラート解析・脅威説明）にはAnthropic Claude APIを使用します。</p>
            <Code lang="bash">{`# deploy/.env.prod
CLAUDE_API_KEY=sk-ant-...
CLAUDE_MODEL=claude-opus-4-6
AI_ANALYSIS_ENABLED=true
AI_MIN_SEVERITY=5   # 深刻度5以上のアラートのみ自動解析`}</Code>

            <H3>VirusTotal連携</H3>
            <Code lang="bash">{`# deploy/.env.prod
VIRUSTOTAL_API_KEY=your-vt-api-key`}</Code>
          </Section>
          </div>

          {/* ── 9. トラブルシューティング ────────────────────────── */}
          <div ref={el => { refs.current['troubleshoot'] = el }}>
          <Section id="troubleshoot" title="トラブルシューティング" icon={<HelpCircle className="w-4 h-4" />}>
            <H3>コンテナログの確認</H3>
            <Code lang="bash">{`# 全サービスのログ
docker compose -f docker-compose.prod.yml logs -f

# 特定サービスのログ
docker compose -f docker-compose.prod.yml logs -f api
docker compose -f docker-compose.prod.yml logs -f postgres`}</Code>

            <H3>よくある問題</H3>
            <div className="space-y-3">
              {[
                {
                  q: 'エージェントが接続されない',
                  a: '1) ENROLLMENTトークンが正しいか確認\n2) サーバーのgRPCポート(50051)がファイアウォールで許可されているか確認\n3) TLS証明書が有効か確認 (caddy logs)',
                },
                {
                  q: 'ログインできない / JWT無効エラー',
                  a: 'JWT_SECRETとNEXTAUTH_SECRETが一致しているか確認。変更した場合は全コンテナを再起動してください。',
                },
                {
                  q: 'アラートが発生しない',
                  a: '1) エージェントがonlineか確認\n2) 検知ルールが有効になっているか確認\n3) ingestionサービスのログでエラーがないか確認',
                },
                {
                  q: 'DBマイグレーションエラー',
                  a: 'APIコンテナ起動時に自動マイグレーションが実行されます。`docker logs edr-api`でエラーを確認し、migrations/フォルダの最新ファイルを確認してください。',
                },
              ].map(item => (
                <div key={item.q} className="bg-[#0d1220] border border-[#1e2d42] rounded-lg p-4">
                  <p className="text-[#e2e8f4] font-medium text-xs mb-2 flex items-center gap-2">
                    <HelpCircle className="w-3.5 h-3.5 text-[#f59e0b]" />
                    {item.q}
                  </p>
                  <p className="text-[#8899aa] text-xs whitespace-pre-line">{item.a}</p>
                </div>
              ))}
            </div>

            <H3>サポートへのお問い合わせ</H3>
            <p>
              解決しない場合は{' '}
              <Link href="/support" className="text-[#3b82f6] hover:underline">サポートチケット</Link>
              {' '}を作成してください。以下の情報を添付していただくと対応がスムーズです：
            </p>
            <ul className="list-disc pl-5 space-y-1">
              <li>エラーメッセージ（スクリーンショットまたはテキスト）</li>
              <li>関連コンテナのログ（<code className="font-mono text-xs text-[#e2e8f4]">{'docker logs edr-api 2>&1 | tail -100'}</code>）</li>
              <li>プラットフォームバージョン（<code className="font-mono text-xs text-[#e2e8f4]">GET /api/v1/health</code> のレスポンス）</li>
              <li>再現手順</li>
            </ul>
          </Section>
          </div>

        </div>

        {/* フッター */}
        <div className="border-t border-[#1e2d42] p-6 text-center">
          <p className="text-xs text-[#5a6a7a]">
            Kizashi 管理者ガイド v2.x &mdash; 最終更新: 2026年3月21日
          </p>
        </div>
      </main>
    </div>
  )
}

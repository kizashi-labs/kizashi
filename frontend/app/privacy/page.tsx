import Link from 'next/link'
import { Shield } from 'lucide-react'

export const metadata = {
  title: 'プライバシーポリシー | Kizashi',
}

export default function PrivacyPage() {
  return (
    <div className="min-h-screen bg-[#080c14] text-[#e2e8f4]">
      <header className="border-b border-[#1e2d42] px-6 py-4 flex items-center gap-3">
        <Shield className="w-5 h-5 text-[#e8002d]" />
        <span className="font-semibold text-sm text-[#e2e8f4]">Kizashi</span>
        <Link href="/login" className="ml-auto text-xs text-[#5a6a7a] hover:text-[#8899aa]">
          ログインに戻る
        </Link>
      </header>

      <main className="max-w-3xl mx-auto px-6 py-12">
        <h1 className="text-2xl font-bold text-[#e2e8f4] mb-2">プライバシーポリシー</h1>
        <p className="text-xs text-[#5a6a7a] mb-8">最終更新日: 2026年3月21日</p>

        <div className="space-y-8 text-[#8899aa] leading-relaxed text-sm">

          <Section title="1. 収集する情報">
            <p>当社は、本サービスの提供にあたり、以下の情報を収集します：</p>
            <SubSection title="(1) お客様から直接取得する情報">
              <ul className="list-disc pl-5 space-y-1">
                <li>アカウント情報（メールアドレス、氏名、組織名）</li>
                <li>課金情報（Stripe を通じた支払い情報 — カード番号は当社サーバーに保存しません）</li>
                <li>サポートチケットに記載された情報</li>
              </ul>
            </SubSection>
            <SubSection title="(2) 本サービスの利用を通じて収集する情報">
              <ul className="list-disc pl-5 space-y-1">
                <li>エンドポイントのセキュリティイベント（プロセス、ネットワーク接続、ファイル操作等）</li>
                <li>アラートおよびインシデント情報</li>
                <li>システムログ、監査ログ</li>
                <li>エンドポイントのメタデータ（ホスト名、IPアドレス、OS情報）</li>
              </ul>
            </SubSection>
          </Section>

          <Section title="2. 情報の利用目的">
            <p>収集した情報は以下の目的で利用します：</p>
            <ul className="list-disc pl-5 space-y-1">
              <li>本サービスの提供・運営・改善</li>
              <li>セキュリティ脅威の検知・分析・対応支援</li>
              <li>お客様へのサポート提供</li>
              <li>請求・料金管理</li>
              <li>法令上の義務の履行</li>
            </ul>
          </Section>

          <Section title="3. 情報の保管とセキュリティ">
            <p>当社は、収集した情報を安全に保護するため、以下の措置を講じます：</p>
            <ul className="list-disc pl-5 space-y-1">
              <li>通信の暗号化（TLS 1.2 以上）</li>
              <li>データベースの暗号化</li>
              <li>テナントごとのデータ分離（行レベルセキュリティ）</li>
              <li>アクセスログの記録と定期的な監査</li>
              <li>定期的なセキュリティ評価の実施</li>
            </ul>
            <p className="mt-2">セキュリティイベントデータは、原則としてお客様のテナント内にのみ保存され、契約終了後90日以内に削除します。</p>
          </Section>

          <Section title="4. 第三者への提供">
            <p>当社は、以下の場合を除き、お客様の情報を第三者に提供しません：</p>
            <ul className="list-disc pl-5 space-y-1">
              <li>お客様の同意がある場合</li>
              <li>法令に基づく開示が必要な場合</li>
              <li>人の生命・身体・財産の保護のために必要な場合</li>
            </ul>
            <p className="mt-2">当社は以下のサービスプロバイダーを利用します：</p>
            <div className="mt-2 space-y-2">
              {[
                { name: 'Stripe', purpose: '決済処理', policy: 'https://stripe.com/privacy' },
                { name: 'Amazon Web Services', purpose: 'インフラストラクチャ', policy: 'https://aws.amazon.com/privacy/' },
                { name: 'Anthropic (Claude)', purpose: 'AI アシスタント機能', policy: 'https://www.anthropic.com/privacy' },
              ].map(p => (
                <div key={p.name} className="flex items-start gap-3 bg-[#0d1220] border border-[#1e2d42] rounded p-3">
                  <div className="flex-1">
                    <p className="text-[#e2e8f4] text-xs font-medium">{p.name}</p>
                    <p className="text-[#5a6a7a] text-xs">{p.purpose}</p>
                  </div>
                </div>
              ))}
            </div>
          </Section>

          <Section title="5. Cookieの使用">
            <p>本サービスは、セッション管理のためにHTTPOnly Cookieを使用します。トラッキングや広告目的のCookieは使用しません。</p>
          </Section>

          <Section title="6. お客様の権利">
            <p>お客様は以下の権利を有します：</p>
            <ul className="list-disc pl-5 space-y-1">
              <li>保有する個人情報の開示請求</li>
              <li>個人情報の訂正・追加・削除の請求</li>
              <li>個人情報の利用停止・消去の請求</li>
              <li>データのポータビリティ（機械可読形式でのエクスポート）</li>
            </ul>
            <p className="mt-2">これらの請求はサポートチケットまたは下記連絡先からお申し込みください。30日以内に対応します。</p>
          </Section>

          <Section title="7. 未成年者のプライバシー">
            <p>本サービスは16歳未満の方を対象としていません。16歳未満の方の個人情報を意図せず収集した場合、速やかに削除します。</p>
          </Section>

          <Section title="8. ポリシーの変更">
            <p>当社は本ポリシーを変更することがあります。重要な変更は本サービス上またはメールで通知します。</p>
          </Section>

          <Section title="9. お問い合わせ">
            <p>個人情報の取り扱いに関するお問い合わせは、本サービス内のサポートチケットにてお受けします。</p>
          </Section>

        </div>

        <div className="mt-12 pt-6 border-t border-[#1e2d42] flex gap-4 text-xs text-[#5a6a7a]">
          <Link href="/terms" className="hover:text-[#8899aa]">利用規約</Link>
          <Link href="/login" className="hover:text-[#8899aa]">ログイン</Link>
        </div>
      </main>
    </div>
  )
}

function Section({ title, children }: { title: string; children: React.ReactNode }) {
  return (
    <section>
      <h2 className="text-base font-semibold text-[#e2e8f4] mb-3">{title}</h2>
      <div className="space-y-2">{children}</div>
    </section>
  )
}

function SubSection({ title, children }: { title: string; children: React.ReactNode }) {
  return (
    <div className="mt-2">
      <p className="text-[#e2e8f4] text-xs font-medium mb-1">{title}</p>
      {children}
    </div>
  )
}

import Link from 'next/link'
import { Shield } from 'lucide-react'

export const metadata = {
  title: '利用規約 | Kizashi',
}

export default function TermsPage() {
  return (
    <div className="min-h-screen bg-[#080c14] text-[#e2e8f4]">
      {/* ヘッダー */}
      <header className="border-b border-[#1e2d42] px-6 py-4 flex items-center gap-3">
        <Shield className="w-5 h-5 text-[#e8002d]" />
        <span className="font-semibold text-sm text-[#e2e8f4]">Kizashi</span>
        <Link href="/login" className="ml-auto text-xs text-[#5a6a7a] hover:text-[#8899aa]">
          ログインに戻る
        </Link>
      </header>

      <main className="max-w-3xl mx-auto px-6 py-12">
        <h1 className="text-2xl font-bold text-[#e2e8f4] mb-2">利用規約</h1>
        <p className="text-xs text-[#5a6a7a] mb-8">最終更新日: 2026年3月21日</p>

        <div className="prose prose-sm max-w-none space-y-8 text-[#8899aa] leading-relaxed">

          <Section title="第1条（適用）">
            <p>本利用規約（以下「本規約」）は、当社が提供するエンドポイント検知・対応プラットフォーム「Kizashi」（以下「本サービス」）の利用に関する条件を定めるものです。お客様が本サービスを利用することにより、本規約に同意したものとみなします。</p>
          </Section>

          <Section title="第2条（定義）">
            <ul className="list-disc pl-5 space-y-1">
              <li>「当社」とは、本サービスを提供する事業者をいいます。</li>
              <li>「お客様」とは、本規約に同意のうえ本サービスを利用する法人または個人をいいます。</li>
              <li>「エンドポイント」とは、本サービスのエージェントをインストールした端末をいいます。</li>
              <li>「テナント」とは、お客様が本サービス上に作成する組織単位をいいます。</li>
            </ul>
          </Section>

          <Section title="第3条（サービスの内容）">
            <p>本サービスは以下の機能を提供します：</p>
            <ul className="list-disc pl-5 space-y-1">
              <li>エンドポイントへの脅威検知エージェントの配布および管理</li>
              <li>セキュリティイベントの収集・分析・アラート通知</li>
              <li>インシデント対応支援およびフォレンジクス機能</li>
              <li>コンプライアンスレポートの生成</li>
              <li>その他当社が別途定める付加機能</li>
            </ul>
          </Section>

          <Section title="第4条（ライセンスおよび料金）">
            <p>本サービスの利用には有効なライセンスが必要です。料金プランは以下のとおりです：</p>
            <ul className="list-disc pl-5 space-y-1">
              <li><strong className="text-[#e2e8f4]">Starter プラン</strong>：¥1,800/エンドポイント/月（50〜500エンドポイント）</li>
              <li><strong className="text-[#e2e8f4]">Professional プラン</strong>：¥2,800/エンドポイント/月（200〜5,000エンドポイント）</li>
              <li><strong className="text-[#e2e8f4]">Enterprise プラン</strong>：個別見積もり（1,000エンドポイント以上）</li>
            </ul>
            <p className="mt-2">料金は月次で請求し、前払いとします。ライセンスの有効期限が切れた場合、一部の機能が制限されます。</p>
          </Section>

          <Section title="第5条（禁止事項）">
            <p>お客様は以下の行為を行ってはなりません：</p>
            <ul className="list-disc pl-5 space-y-1">
              <li>本サービスを第三者に無断で転売・再頒布すること</li>
              <li>本サービスを利用して不正アクセスまたはサイバー攻撃を行うこと</li>
              <li>本サービスのリバースエンジニアリングまたは改ざんを行うこと</li>
              <li>ライセンスキーを複製または第三者と共有すること</li>
              <li>法令または公序良俗に反する目的での利用</li>
            </ul>
          </Section>

          <Section title="第6条（データの取り扱い）">
            <p>当社は、本サービスの提供に必要な範囲で、お客様のエンドポイントから収集されたセキュリティデータを処理します。データの取り扱いの詳細については、別途定めるプライバシーポリシーをご参照ください。</p>
            <p className="mt-2">お客様のデータは、お客様のテナント内に隔離され、他のお客様からアクセスできません。</p>
          </Section>

          <Section title="第7条（サービスレベル）">
            <p>当社は、本サービスの月間稼働率99.5%以上を目標として努力します。ただし、以下の場合は稼働率の計算から除外します：</p>
            <ul className="list-disc pl-5 space-y-1">
              <li>定期メンテナンス（事前通知あり）</li>
              <li>お客様側の設定ミスまたはネットワーク障害</li>
              <li>天災・不可抗力による障害</li>
            </ul>
          </Section>

          <Section title="第8条（免責事項）">
            <p>当社は、本サービスの利用により生じた損害（サイバー攻撃による被害、データ損失等）について、当社の故意または重大な過失による場合を除き、責任を負いません。当社の賠償責任は、損害発生月の月額利用料を上限とします。</p>
          </Section>

          <Section title="第9条（知的財産権）">
            <p>本サービスに関するすべての知的財産権は当社に帰属します。本規約はお客様に対して本サービスを利用するための限定的なライセンスを付与するものであり、権利の譲渡ではありません。</p>
          </Section>

          <Section title="第10条（契約期間と解約）">
            <p>本サービスの利用契約は、ライセンス有効期間中存続します。お客様は、有効期間中いつでも解約を申し出ることができますが、既払いの料金は返金しません。</p>
          </Section>

          <Section title="第11条（規約の変更）">
            <p>当社は、本規約を変更する場合があります。重要な変更については、本サービス上またはメールにて30日前までに通知します。変更後も本サービスの利用を継続した場合、変更後の規約に同意したものとみなします。</p>
          </Section>

          <Section title="第12条（準拠法・管轄裁判所）">
            <p>本規約は日本法に準拠します。本サービスに関する紛争については、東京地方裁判所を第一審の専属的合意管轄裁判所とします。</p>
          </Section>

        </div>

        <div className="mt-12 pt-6 border-t border-[#1e2d42] flex gap-4 text-xs text-[#5a6a7a]">
          <Link href="/privacy" className="hover:text-[#8899aa]">プライバシーポリシー</Link>
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

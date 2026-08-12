'use client'

import { useState } from 'react'
import { ChevronDown, ChevronUp, Shield, HelpCircle, ArrowRight } from 'lucide-react'
import Link from 'next/link'
import { usePlan } from '@/lib/usePlan'

const FAQS = [
  {
    category: 'はじめ方',
    questions: [
      {
        q: 'まず何をすればいいですか？',
        a: 'エージェントをPCやサーバーにインストールするだけです。インストール後、30秒以内にダッシュボードに端末が表示されます。\n\n→ メニュー「管理」→「エージェント配布」からインストーラーをダウンロードしてください。',
        link: { label: 'エージェント配布ページへ', href: '/admin/agent-deployment' },
      },
      {
        q: 'インストールに専門知識は必要ですか？',
        a: 'いいえ。インストーラーをダウンロードして実行するだけです。Windows・macOS・Linuxに対応しています。管理者権限は必要ですが、コマンドライン知識は不要です。',
      },
      {
        q: 'Freeプランでどこまでできますか？',
        a: '最大5台のエンドポイントで以下が利用できます：\n・リアルタイムプロセス監視\n・マルウェア検知・アラート\n・セキュリティダッシュボード（閲覧）\n\nAI調査・SIEM連携・レポート生成・MDMはLite/Starter以上が必要です。',
      },
    ],
  },
  {
    category: 'アラート対応',
    questions: [
      {
        q: 'アラートが表示されました。どうすればいいですか？',
        a: 'SOCワークキュー（/soc-queue）を開いてください。アラートが「今すぐ対応」「今日中」「今週中」の3レーンに自動分類されています。\n\n「今すぐ対応」のアラートをクリックして詳細を確認し、AIの推奨対応を参考に処理してください。',
        link: { label: 'SOCワークキューへ', href: '/soc-queue' },
      },
      {
        q: 'アラートが多すぎて対応しきれません。',
        a: '繰り返し発生するノイズアラートは「抑制ルール」で自動無視できます。SOCワークキューページ下部の「抑制候補」セクションに表示されているアラートをクリックするだけで設定できます。\n\n※ Professionalプラン以上ではAIが誤検知を自動クローズします。',
      },
      {
        q: '誤検知だと思いますが、どう処理しますか？',
        a: 'アラート詳細画面でステータスを「false_positive（誤検知）」に変更してください。同じルールの誤検知が続く場合は抑制ルールの作成を検討してください。',
      },
    ],
  },
  {
    category: 'セキュリティ・データ',
    questions: [
      {
        q: 'データはどこに保存されますか？',
        a: '御社のサーバー（またはお客様が指定したクラウド環境）に保存されます。外部のKizashiサーバーには送信されません。エアギャップ環境（インターネット非接続）でも動作します。',
      },
      {
        q: 'AI機能を使うと情報が外部に漏れますか？',
        a: 'AI機能（Claude/GPT等）を使用する場合、アラートの内容をAIプロバイダーに送信します。ただし、送信前にホスト名・IPアドレス・メールアドレス等の個人情報は自動的にマスキングされます。\n\nAI機能はオプトイン制（管理者が明示的に有効化）で、Professionalプラン以上の機能です。',
      },
      {
        q: 'アンチウイルスと共存できますか？',
        a: 'はい。Kizashiはアンチウイルスの上位層で動作します。競合は発生しません。AVが「入口の門番」ならEDRは「侵入後の監視カメラ」として機能します。',
      },
    ],
  },
  {
    category: 'プラン・料金',
    questions: [
      {
        q: '5台を超えたらどうなりますか？',
        a: 'Freeプランは最大5台の制限があります。5台を超えて追加するにはLiteプラン（¥500/台/月・5〜45台）へのアップグレードが必要です。\n\nアップグレードしても既存のエージェント・設定・データはすべて引き継がれます。',
        link: { label: 'プランを確認する', href: '/admin/license' },
      },
      {
        q: 'LiteプランとFreeプランの違いは？',
        a: '主な追加機能：\n・基本レポート（月次サマリー・アラート集計）\n・メールサポート（48時間以内返信）\n・5〜45台まで5台刻みで拡張可能\n\nAI調査・SIEM連携・MDM等はStarter以上の機能です。',
      },
      {
        q: 'クレジットカードなしで試せますか？',
        a: 'はい。Freeプランはクレジットカード不要・登録費用ゼロです。有料プランへのアップグレードをしない限り費用は一切発生しません。',
      },
    ],
  },
  {
    category: 'トラブルシューティング',
    questions: [
      {
        q: 'エージェントをインストールしたのにダッシュボードに表示されません。',
        a: '以下を確認してください：\n1. エージェントサービスが起動しているか（Windows: タスクマネージャー → サービス → EDRAgent）\n2. ファイアウォールが8080・9091ポートをブロックしていないか\n3. インストール時に入力したサーバーURLが正しいか\n\n詳細はトラブルシューティングガイドを参照してください。',
        link: { label: 'トラブルシューティングを確認', href: '/admin/guide' },
      },
      {
        q: 'ログインできなくなりました。',
        a: 'パスワードをお忘れの場合は、ログイン画面の「パスワードを忘れた方」から再設定できます。\n\nadminアカウントでログインできない場合は、サーバーの管理者にADMIN_PASSWORDの確認を依頼してください。',
      },
    ],
  },
]

function FAQItem({ q, a, link }: { q: string; a: string; link?: { label: string; href: string } }) {
  const [open, setOpen] = useState(false)
  return (
    <div className="border-b border-[#1e2d42] last:border-0">
      <button
        onClick={() => setOpen(v => !v)}
        className="w-full flex items-center justify-between px-5 py-4 text-left hover:bg-[#111827] transition-colors"
      >
        <span className="text-sm font-medium text-[#e2e8f4] pr-4">{q}</span>
        {open
          ? <ChevronUp className="w-4 h-4 text-[#e8002d] flex-shrink-0" />
          : <ChevronDown className="w-4 h-4 text-[#3d5068] flex-shrink-0" />
        }
      </button>
      {open && (
        <div className="px-5 pb-4">
          <p className="text-sm text-[#7d92b0] leading-relaxed whitespace-pre-line">{a}</p>
          {link && (
            <Link
              href={link.href}
              className="inline-flex items-center gap-1.5 mt-3 text-xs text-[#e8002d] hover:text-[#ff4060] transition-colors"
            >
              {link.label}
              <ArrowRight className="w-3 h-3" />
            </Link>
          )}
        </div>
      )}
    </div>
  )
}

export default function FAQPage() {
  const { plan, agentUsed, agentLimit } = usePlan()
  const [activeCategory, setActiveCategory] = useState<string | null>(null)

  const displayed = activeCategory
    ? FAQS.filter(f => f.category === activeCategory)
    : FAQS

  return (
    <div className="min-h-screen bg-[#070d19] p-6 max-w-3xl mx-auto">
      {/* ヘッダー */}
      <div className="flex items-center gap-3 mb-8">
        <div className="p-2 bg-[#e8002d]/10 rounded-lg border border-[#e8002d]/20">
          <HelpCircle className="w-5 h-5 text-[#e8002d]" />
        </div>
        <div>
          <h1 className="text-xl font-bold text-white">よくある質問（FAQ）</h1>
          <p className="text-xs text-[#3d5068] mt-0.5">Kizashiの使い方・よくあるお問い合わせ</p>
        </div>
      </div>

      {/* Freeプランステータスカード */}
      {plan === 'free' && (
        <div className="mb-6 bg-[#0d1220] border border-[#1e2d42] rounded-xl p-4 flex items-center gap-4">
          <Shield className="w-5 h-5 text-[#e8002d] flex-shrink-0" />
          <div className="flex-1 min-w-0">
            <p className="text-sm font-medium text-white">現在: Freeプラン</p>
            <p className="text-xs text-[#3d5068] mt-0.5">
              エージェント {agentUsed}/{agentLimit}台使用中
            </p>
          </div>
          <Link
            href="/admin/license"
            className="flex items-center gap-1.5 px-3 py-1.5 bg-[#e8002d]/10 border border-[#e8002d]/30
                       text-[#e8002d] text-xs font-medium rounded-lg hover:bg-[#e8002d]/20 transition-colors flex-shrink-0"
          >
            プランを確認
            <ArrowRight className="w-3 h-3" />
          </Link>
        </div>
      )}

      {/* カテゴリフィルター */}
      <div className="flex flex-wrap gap-2 mb-6">
        <button
          onClick={() => setActiveCategory(null)}
          className={`px-3 py-1.5 text-xs font-medium rounded-full border transition-colors ${
            activeCategory === null
              ? 'bg-[#e8002d]/20 border-[#e8002d]/50 text-[#e8002d]'
              : 'bg-[#0d1220] border-[#1e2d42] text-[#3d5068] hover:text-white'
          }`}
        >
          すべて
        </button>
        {FAQS.map(f => (
          <button
            key={f.category}
            onClick={() => setActiveCategory(f.category)}
            className={`px-3 py-1.5 text-xs font-medium rounded-full border transition-colors ${
              activeCategory === f.category
                ? 'bg-[#e8002d]/20 border-[#e8002d]/50 text-[#e8002d]'
                : 'bg-[#0d1220] border-[#1e2d42] text-[#3d5068] hover:text-white'
            }`}
          >
            {f.category}
          </button>
        ))}
      </div>

      {/* FAQ一覧 */}
      <div className="space-y-4">
        {displayed.map(section => (
          <div key={section.category} className="bg-[#0d1220] border border-[#1e2d42] rounded-xl overflow-hidden">
            <div className="px-5 py-3 border-b border-[#1e2d42] bg-[#080c14]">
              <p className="text-xs font-bold text-[#7d92b0] uppercase tracking-wide">{section.category}</p>
            </div>
            {section.questions.map(item => (
              <FAQItem key={item.q} {...item} />
            ))}
          </div>
        ))}
      </div>

      {/* 解決しない場合 */}
      <div className="mt-8 bg-[#0d1220] border border-[#1e2d42] rounded-xl p-5 text-center">
        <p className="text-sm text-[#7d92b0] mb-3">解決しない場合は詳細ガイドをご覧ください</p>
        <Link
          href="/admin/guide"
          className="inline-flex items-center gap-2 px-4 py-2 bg-[#1d2f4a] hover:bg-[#253d5e]
                     border border-[#2a3f60] text-sm text-white rounded-lg transition-colors"
        >
          管理者向け詳細ガイドを開く
          <ArrowRight className="w-4 h-4" />
        </Link>
      </div>
    </div>
  )
}

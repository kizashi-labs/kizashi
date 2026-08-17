'use client'

import { useState, useEffect } from 'react'
import { usePlan } from '@/lib/usePlan'
import {
  X, ChevronRight, ChevronLeft, CheckCircle2,
  Monitor, Shield, Bell, Zap, ExternalLink,
} from 'lucide-react'
import Link from 'next/link'

const STORAGE_KEY = 'onboarding_completed_v1'

interface Step {
  id: number
  icon: React.ElementType
  title: string
  description: string
  action?: { label: string; href: string }
  tip?: string
}

const STEPS: Step[] = [
  {
    id: 1,
    icon: Shield,
    title: 'Kizashi へようこそ！',
    description:
      'Freeプランでは最大5台のエンドポイントを無料で監視できます。\nまずはPCやサーバーにエージェントをインストールしましょう。',
    action: { label: 'エージェントをインストール', href: '/admin/agent-deployment' },
    tip: 'インストールはコマンド1行で完了します。既存の設定はそのまま引き継がれます。',
  },
  {
    id: 2,
    icon: Monitor,
    title: 'ダッシュボードを確認する',
    description:
      'エージェントをインストールすると、ダッシュボードにエンドポイントが表示されます。\nSOCワークキューで未対応のアラートを優先度別に確認できます。',
    action: { label: 'ダッシュボードを開く', href: '/' },
    tip: 'SOCワークキュー（/soc-queue）を毎朝確認するだけで日常運用は完結します。',
  },
  {
    id: 3,
    icon: Bell,
    title: 'Slack通知を設定する（任意）',
    description:
      '脅威を検知したときにSlackへ即時通知する設定ができます。\nデイリーブリーフィングも毎朝8時にSlackへ配信できます。',
    action: { label: '通知設定を開く', href: '/settings/notifications' },
    tip: 'Slack Incoming Webhook URLを設定するだけで有効になります。',
  },
  {
    id: 4,
    icon: Zap,
    title: '5台で足りなくなったら',
    description:
      'Freeプランは最大5台です。\n5〜45台はLiteプラン（¥500/台/月〜）で対応できます。\nデータ・設定・エージェントはすべて引き継がれます。',
    tip: '「5台超過しそう」と感じたらいつでも画面上部のバナーからアップグレードできます。',
  },
]

export function OnboardingWizard() {
  const { plan, isLoading } = usePlan()
  const [show, setShow] = useState(false)
  const [step, setStep] = useState(0)

  useEffect(() => {
    if (isLoading) return
    // Freeプランかつ初回のみ表示
    if (plan === 'free' && !localStorage.getItem(STORAGE_KEY)) {
      const timer = setTimeout(() => setShow(true), 1500) // ページ表示後少し待つ
      return () => clearTimeout(timer)
    }
  }, [plan, isLoading])

  const complete = () => {
    localStorage.setItem(STORAGE_KEY, '1')
    setShow(false)
  }

  if (!show) return null

  const current = STEPS[step]
  const Icon = current.icon
  const isLast = step === STEPS.length - 1

  return (
    <>
      {/* オーバーレイ */}
      <div className="fixed inset-0 bg-black/60 backdrop-blur-xs z-50 flex items-center justify-center p-4">
        <div className="relative w-full max-w-lg bg-falcon-surface rounded-2xl border border-falcon-border shadow-2xl overflow-hidden">

          {/* 上部カラーバー */}
          <div className="h-1 bg-linear-to-r from-falcon-red via-[#ff6b35] to-falcon-blue" />

          {/* ヘッダー */}
          <div className="flex items-center justify-between px-6 py-4 border-b border-falcon-border">
            <span className="text-xs text-falcon-subtle font-medium">
              スタートガイド {step + 1} / {STEPS.length}
            </span>
            <button onClick={complete} className="text-falcon-subtle hover:text-white transition-colors">
              <X className="w-4 h-4" />
            </button>
          </div>

          {/* プログレスバー */}
          <div className="flex gap-1 px-6 pt-4">
            {STEPS.map((s, i) => (
              <div
                key={s.id}
                className={`h-1 flex-1 rounded-full transition-colors ${
                  i <= step ? 'bg-falcon-red' : 'bg-falcon-border'
                }`}
              />
            ))}
          </div>

          {/* コンテンツ */}
          <div className="px-6 py-6">
            <div className="flex items-center gap-4 mb-5">
              <div className="w-12 h-12 rounded-xl bg-falcon-red/15 border border-falcon-red/30 flex items-center justify-center shrink-0">
                <Icon className="w-6 h-6 text-falcon-red" />
              </div>
              <div>
                <h2 className="text-lg font-bold text-white">{current.title}</h2>
              </div>
            </div>

            <p className="text-sm text-falcon-muted leading-relaxed whitespace-pre-line mb-5">
              {current.description}
            </p>

            {current.tip && (
              <div className="bg-falcon-raised border border-falcon-border rounded-lg px-4 py-3 mb-5">
                <p className="text-xs text-falcon-muted">
                  <span className="text-falcon-red font-bold mr-1.5">💡 ヒント:</span>
                  {current.tip}
                </p>
              </div>
            )}

            {current.action && (
              <Link
                href={current.action.href}
                onClick={complete}
                className="flex items-center gap-2 w-full px-4 py-2.5 bg-falcon-active hover:bg-[#253d5e]
                           border border-[#2a3f60] rounded-lg text-sm text-white transition-colors mb-2"
              >
                <ExternalLink className="w-3.5 h-3.5 text-falcon-red" />
                {current.action.label}
                <ChevronRight className="w-3.5 h-3.5 ml-auto text-falcon-subtle" />
              </Link>
            )}
          </div>

          {/* フッター */}
          <div className="flex items-center justify-between px-6 pb-5">
            <button
              onClick={() => setStep(s => Math.max(0, s - 1))}
              disabled={step === 0}
              className="flex items-center gap-1.5 px-3 py-2 text-sm text-falcon-subtle hover:text-white
                         disabled:opacity-30 disabled:cursor-not-allowed transition-colors"
            >
              <ChevronLeft className="w-4 h-4" />
              戻る
            </button>

            <button
              onClick={complete}
              className="text-xs text-falcon-subtle hover:text-falcon-muted transition-colors"
            >
              スキップ
            </button>

            {isLast ? (
              <button
                onClick={complete}
                className="flex items-center gap-1.5 px-4 py-2 bg-falcon-red hover:bg-[#c8001f]
                           text-white text-sm font-medium rounded-lg transition-colors"
              >
                <CheckCircle2 className="w-4 h-4" />
                はじめる
              </button>
            ) : (
              <button
                onClick={() => setStep(s => s + 1)}
                className="flex items-center gap-1.5 px-4 py-2 bg-falcon-red hover:bg-[#c8001f]
                           text-white text-sm font-medium rounded-lg transition-colors"
              >
                次へ
                <ChevronRight className="w-4 h-4" />
              </button>
            )}
          </div>
        </div>
      </div>
    </>
  )
}

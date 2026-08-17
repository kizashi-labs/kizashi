'use client'

import React, { useState, useEffect } from 'react'
import {
  LayoutDashboard, Plus, Trash2, ChevronUp, ChevronDown, RotateCcw, Save,
  BarChart2, Activity, Shield, AlertTriangle, List, Heart,
  Brain, Globe2, CheckSquare, Layers, Bell, CheckCircle,
} from 'lucide-react'

// ─── Types ────────────────────────────────────────────────────────────────────

type WidgetSize = 'small' | 'medium' | 'large'

interface Widget {
  id: string
  name: string
  description: string
  icon: React.ElementType
  color: string
  // 並び替えプレビュー用の淡色版。Tailwind v4 で bg-opacity-* が廃止され、
  // 不透明度は色ユーティリティのスラッシュ記法に統合された。`${widget.color}/30`
  // と補間してもソース上にリテラルが現れず、スキャナがクラスを見つけられない
  // ので、生成させたい文字列をそのままここに置く。
  colorDim: string
}

interface LayoutItem {
  widget_id: string
  position: number
  size: WidgetSize
}

// ─── Widget Catalog ───────────────────────────────────────────────────────────

const WIDGET_CATALOG: Widget[] = [
  { id: 'alert-trend', name: 'アラートトレンドチャート', description: '7日/30日のアラート時系列グラフ', icon: BarChart2, color: 'bg-blue-700', colorDim: 'bg-blue-700/30' },
  { id: 'agent-status', name: 'エージェントステータス', description: 'オンライン/オフライン/停滞エージェント数', icon: Activity, color: 'bg-green-700', colorDim: 'bg-green-700/30' },
  { id: 'top-threats', name: '上位脅威', description: '今週検出された上位10脅威タイプ', icon: AlertTriangle, color: 'bg-red-700', colorDim: 'bg-red-700/30' },
  { id: 'detection-stats', name: '検知統計', description: 'ルールマッチ数と検知率', icon: Shield, color: 'bg-purple-700', colorDim: 'bg-purple-700/30' },
  { id: 'recent-alerts', name: '最近のアラート', description: '最新10件の高/重大アラート', icon: List, color: 'bg-orange-700', colorDim: 'bg-orange-700/30' },
  { id: 'system-health', name: 'システムヘルス', description: 'CPU・メモリ・キュー深度', icon: Heart, color: 'bg-teal-700', colorDim: 'bg-teal-700/30' },
  { id: 'ueba-risk', name: 'UEBAリスクスコア', description: '行動リスクスコア上位ユーザー', icon: Brain, color: 'bg-violet-700', colorDim: 'bg-violet-700/30' },
  { id: 'threat-map', name: '脅威マッププレビュー', description: '脅威発生源を示すミニワールドマップ', icon: Globe2, color: 'bg-cyan-700', colorDim: 'bg-cyan-700/30' },
  { id: 'compliance-score', name: 'コンプライアンススコア', description: 'コンプライアンス態勢の概要', icon: CheckSquare, color: 'bg-lime-700', colorDim: 'bg-lime-700/30' },
  { id: 'incident-count', name: 'インシデント数', description: 'オープン/進行中/解決済みインシデント', icon: Layers, color: 'bg-amber-700', colorDim: 'bg-amber-700/30' },
  { id: 'alert-digest', name: 'アラートダイジェスト', description: '全アラートの日次サマリー', icon: Bell, color: 'bg-pink-700', colorDim: 'bg-pink-700/30' },
  { id: 'sla-status', name: 'SLAステータス', description: '対応SLA準拠率', icon: CheckCircle, color: 'bg-emerald-700', colorDim: 'bg-emerald-700/30' },
]

const DEFAULT_LAYOUT: LayoutItem[] = [
  { widget_id: 'alert-trend', position: 0, size: 'large' },
  { widget_id: 'agent-status', position: 1, size: 'medium' },
  { widget_id: 'top-threats', position: 2, size: 'medium' },
  { widget_id: 'recent-alerts', position: 3, size: 'large' },
  { widget_id: 'system-health', position: 4, size: 'small' },
]

const STORAGE_KEY = 'edr_dashboard_layout'

function loadLayout(): LayoutItem[] {
  if (typeof window === 'undefined') return DEFAULT_LAYOUT
  try {
    const saved = localStorage.getItem(STORAGE_KEY)
    if (saved) return JSON.parse(saved)
  } catch {}
  return DEFAULT_LAYOUT
}

function saveLayout(layout: LayoutItem[]) {
  if (typeof window !== 'undefined') {
    localStorage.setItem(STORAGE_KEY, JSON.stringify(layout))
  }
}

function getWidget(id: string): Widget | undefined {
  return WIDGET_CATALOG.find(w => w.id === id)
}

const SIZE_LABELS: Record<WidgetSize, string> = {
  small: '小 (1列)',
  medium: '中 (2列)',
  large: '大 (全幅)',
}

// ─── Page ─────────────────────────────────────────────────────────────────────

export default function DashboardSettingsPage() {
  const [layout, setLayout] = useState<LayoutItem[]>(DEFAULT_LAYOUT)
  const [saved, setSaved] = useState(false)
  const [search, setSearch] = useState('')

  useEffect(() => {
    setLayout(loadLayout())
  }, [])

  const layoutWidgetIds = new Set(layout.map(l => l.widget_id))

  const filteredCatalog = WIDGET_CATALOG.filter(w =>
    w.name.toLowerCase().includes(search.toLowerCase()) ||
    w.description.toLowerCase().includes(search.toLowerCase())
  )

  function addWidget(widgetId: string) {
    const newItem: LayoutItem = {
      widget_id: widgetId,
      position: layout.length,
      size: 'medium',
    }
    setLayout(prev => [...prev, newItem].map((l, i) => ({ ...l, position: i })))
    setSaved(false)
  }

  function removeWidget(widgetId: string) {
    setLayout(prev => prev.filter(l => l.widget_id !== widgetId).map((l, i) => ({ ...l, position: i })))
    setSaved(false)
  }

  function moveWidget(widgetId: string, direction: 'up' | 'down') {
    const sorted = [...layout].sort((a, b) => a.position - b.position)
    const idx = sorted.findIndex(l => l.widget_id === widgetId)
    if (direction === 'up' && idx === 0) return
    if (direction === 'down' && idx === sorted.length - 1) return
    const swapIdx = direction === 'up' ? idx - 1 : idx + 1
    const newArr = [...sorted]
    const temp = newArr[idx].position
    newArr[idx] = { ...newArr[idx], position: newArr[swapIdx].position }
    newArr[swapIdx] = { ...newArr[swapIdx], position: temp }
    setLayout(newArr)
    setSaved(false)
  }

  function updateSize(widgetId: string, size: WidgetSize) {
    setLayout(prev => prev.map(l => l.widget_id === widgetId ? { ...l, size } : l))
    setSaved(false)
  }

  function handleSave() {
    saveLayout(layout)
    setSaved(true)
    setTimeout(() => setSaved(false), 2000)
  }

  function handleReset() {
    if (!confirm('デフォルトレイアウトにリセットしますか？')) return
    setLayout(DEFAULT_LAYOUT)
    saveLayout(DEFAULT_LAYOUT)
    setSaved(true)
    setTimeout(() => setSaved(false), 2000)
  }

  const sortedLayout = [...layout].sort((a, b) => a.position - b.position)

  return (
    <div className="min-h-screen bg-zinc-950 text-zinc-100 p-6">
      {/* Header */}
      <div className="flex items-center justify-between mb-6">
        <div className="flex items-center gap-3">
          <div className="p-2 bg-blue-600 rounded-lg">
            <LayoutDashboard className="w-6 h-6 text-white" />
          </div>
          <div>
            <h1 className="text-2xl font-bold text-zinc-100">ダッシュボード設定</h1>
            <p className="text-sm text-zinc-400">ダッシュボードのレイアウトとウィジェットをカスタマイズ</p>
          </div>
        </div>
        <div className="flex gap-2">
          <button
            onClick={handleReset}
            className="flex items-center gap-2 px-4 py-2 bg-zinc-800 hover:bg-zinc-700 rounded-lg text-sm border border-zinc-700"
          >
            <RotateCcw className="w-4 h-4 text-zinc-400" />
            デフォルトに戻す
          </button>
          <button
            onClick={handleSave}
            className={`flex items-center gap-2 px-4 py-2 rounded-lg text-sm transition-all ${
              saved ? 'bg-green-700 text-white' : 'bg-blue-600 hover:bg-blue-700'
            }`}
          >
            {saved ? <><CheckCircle className="w-4 h-4" /> 保存済み！</> : <><Save className="w-4 h-4" /> レイアウトを保存</>}
          </button>
        </div>
      </div>

      <div className="grid grid-cols-5 gap-6">
        {/* Widget Catalog */}
        <div className="col-span-3">
          <div className="flex items-center justify-between mb-3">
            <h2 className="text-sm font-semibold text-zinc-300 uppercase tracking-wide">ウィジェットカタログ</h2>
            <span className="text-xs text-zinc-600">{WIDGET_CATALOG.length} 個のウィジェット</span>
          </div>
          <div className="relative mb-3">
            <input
              value={search}
              onChange={e => setSearch(e.target.value)}
              placeholder="ウィジェットを検索..."
              className="w-full bg-zinc-900 border border-zinc-700 rounded-lg pl-3 pr-3 py-2 text-sm text-zinc-100 placeholder-zinc-500 focus:outline-hidden focus:border-blue-500"
            />
          </div>
          <div className="grid grid-cols-3 gap-3">
            {filteredCatalog.map(widget => {
              const inLayout = layoutWidgetIds.has(widget.id)
              return (
                <div
                  key={widget.id}
                  className={`bg-zinc-900 border rounded-xl p-4 flex flex-col gap-3 ${
                    inLayout ? 'border-blue-700 opacity-60' : 'border-zinc-800 hover:border-zinc-600'
                  }`}
                >
                  {/* Thumbnail */}
                  <div className={`${widget.color} rounded-lg p-3 flex items-center justify-center gap-2`}>
                    <widget.icon className="w-6 h-6 text-white opacity-80" />
                    <span className="text-xs text-white font-medium truncate">{widget.name}</span>
                  </div>
                  <p className="text-xs text-zinc-500 leading-relaxed flex-1">{widget.description}</p>
                  <button
                    onClick={() => !inLayout && addWidget(widget.id)}
                    disabled={inLayout}
                    className={`flex items-center justify-center gap-1 py-1.5 rounded-lg text-xs transition-all ${
                      inLayout
                        ? 'bg-zinc-800 text-zinc-600 cursor-not-allowed'
                        : 'bg-blue-600 hover:bg-blue-700 text-white'
                    }`}
                  >
                    {inLayout ? (
                      <><CheckCircle className="w-3.5 h-3.5" /> 追加済み</>
                    ) : (
                      <><Plus className="w-3.5 h-3.5" /> ダッシュボードに追加</>
                    )}
                  </button>
                </div>
              )
            })}
            {filteredCatalog.length === 0 && (
              <div className="col-span-3 text-center py-8 text-zinc-600 text-sm">検索に一致するウィジェットがありません。</div>
            )}
          </div>
        </div>

        {/* Current Layout */}
        <div className="col-span-2">
          <div className="flex items-center justify-between mb-3">
            <h2 className="text-sm font-semibold text-zinc-300 uppercase tracking-wide">現在のレイアウト</h2>
            <span className="text-xs text-zinc-600">{layout.length} 個</span>
          </div>
          <div className="space-y-2">
            {sortedLayout.length === 0 && (
              <div className="text-center py-8 text-zinc-600 text-sm bg-zinc-900 border border-zinc-800 rounded-xl">
                <LayoutDashboard className="w-8 h-8 mx-auto mb-2 opacity-20" />
                <p>レイアウトにウィジェットがありません。</p>
                <p className="text-xs mt-1">カタログからウィジェットを追加してください。</p>
              </div>
            )}
            {sortedLayout.map((item, idx) => {
              const widget = getWidget(item.widget_id)
              if (!widget) return null
              return (
                <div
                  key={item.widget_id}
                  className="bg-zinc-900 border border-zinc-700 rounded-xl p-3 flex items-center gap-3"
                >
                  {/* Position badge */}
                  <div className="w-6 h-6 bg-zinc-800 rounded-full flex items-center justify-center text-xs text-zinc-500 shrink-0">
                    {idx + 1}
                  </div>
                  {/* Widget icon */}
                  <div className={`${widget.color} rounded-lg p-1.5 shrink-0`}>
                    <widget.icon className="w-4 h-4 text-white" />
                  </div>
                  {/* Name + size select */}
                  <div className="flex-1 min-w-0">
                    <p className="text-sm font-medium text-zinc-200 truncate">{widget.name}</p>
                    <select
                      value={item.size}
                      onChange={e => updateSize(item.widget_id, e.target.value as WidgetSize)}
                      className="mt-1 bg-zinc-800 border border-zinc-700 rounded-lg px-2 py-0.5 text-xs text-zinc-400 focus:outline-hidden w-full"
                    >
                      {(Object.keys(SIZE_LABELS) as WidgetSize[]).map(s => (
                        <option key={s} value={s}>{SIZE_LABELS[s]}</option>
                      ))}
                    </select>
                  </div>
                  {/* Move buttons */}
                  <div className="flex flex-col gap-0.5">
                    <button
                      onClick={() => moveWidget(item.widget_id, 'up')}
                      disabled={idx === 0}
                      className="p-1 hover:bg-zinc-700 disabled:opacity-20 rounded-sm"
                    >
                      <ChevronUp className="w-3.5 h-3.5 text-zinc-400" />
                    </button>
                    <button
                      onClick={() => moveWidget(item.widget_id, 'down')}
                      disabled={idx === sortedLayout.length - 1}
                      className="p-1 hover:bg-zinc-700 disabled:opacity-20 rounded-sm"
                    >
                      <ChevronDown className="w-3.5 h-3.5 text-zinc-400" />
                    </button>
                  </div>
                  {/* Remove */}
                  <button
                    onClick={() => removeWidget(item.widget_id)}
                    className="p-1.5 hover:bg-zinc-700 rounded-sm text-zinc-600 hover:text-red-400"
                  >
                    <Trash2 className="w-3.5 h-3.5" />
                  </button>
                </div>
              )
            })}
          </div>

          {layout.length > 0 && (
            <div className="mt-4 bg-zinc-900 border border-zinc-800 rounded-xl p-4">
              <h3 className="text-xs text-zinc-500 uppercase font-semibold tracking-wide mb-3">プレビュー</h3>
              <div className="space-y-1.5">
                {sortedLayout.map((item, idx) => {
                  const widget = getWidget(item.widget_id)
                  if (!widget) return null
                  const widthClass = item.size === 'large' ? 'w-full' : item.size === 'medium' ? 'w-3/4' : 'w-1/2'
                  return (
                    <div key={item.widget_id} className="flex items-center gap-2">
                      <span className="text-xs text-zinc-700 w-4">{idx + 1}</span>
                      <div className={`${widthClass} ${widget.colorDim} rounded-sm px-2 py-1 flex items-center gap-1.5`}>
                        <widget.icon className="w-3 h-3 text-white opacity-60" />
                        <span className="text-xs text-white opacity-70 truncate">{widget.name}</span>
                      </div>
                    </div>
                  )
                })}
              </div>
            </div>
          )}
        </div>
      </div>
    </div>
  )
}

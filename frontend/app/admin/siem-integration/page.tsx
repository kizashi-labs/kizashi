'use client'

import { useState } from 'react'
import { useQuery } from '@tanstack/react-query'
import { apiFetch, apiFetchList } from '@/lib/api'
import {
  Send, Plus, X, ToggleLeft, ToggleRight, CheckCircle, XCircle,
  Loader2, Activity, AlertTriangle, Code2, Zap,
} from 'lucide-react'


import { PageDataUnavailable } from '@/components/PageDataUnavailable'
import { usePersist, SaveFailed } from '@/lib/persist'

// ─── Types ────────────────────────────────────────────────────────────────────

type SIEMType = 'splunk' | 'qradar' | 'elastic' | 'webhook'
type EventFormat = 'json' | 'cef' | 'leef'

interface SIEMConfig {
  id: string
  name: string
  type: SIEMType
  url: string
  api_key: string
  index_channel: string
  format: EventFormat
  batch_size: number
  enabled: boolean
  sent_count: number
  last_sent: string | null
  failed_count: number
}

interface SIEMStats {
  active: number
  sent_24h: number
  last_sent: string | null
  failed: number
}

interface TestResult {
  success: boolean
  latency_ms: number
  message: string
}

// ─── Helpers ──────────────────────────────────────────────────────────────────

function typeStyle(type: SIEMType): string {
  const map: Record<SIEMType, string> = {
    splunk: 'bg-blue-900 text-blue-300 border border-blue-700',
    qradar: 'bg-red-900 text-red-300 border border-red-700',
    elastic: 'bg-green-900 text-green-300 border border-green-700',
    webhook: 'bg-purple-900 text-purple-300 border border-purple-700',
  }
  return map[type]
}

function typeLabel(type: SIEMType): string {
  const map: Record<SIEMType, string> = {
    splunk: 'Splunk HEC',
    qradar: 'QRadar',
    elastic: 'Elastic',
    webhook: 'Webhook',
  }
  return map[type]
}

function fmtDate(iso: string | null): string {
  if (!iso) return '—'
  return new Date(iso).toLocaleTimeString('ja-JP', { hour: '2-digit', minute: '2-digit', month: 'short', day: 'numeric' })
}

function truncateUrl(url: string): string {
  try {
    const u = new URL(url)
    const path = u.pathname.length > 20 ? u.pathname.slice(0, 20) + '...' : u.pathname
    return `${u.hostname}${path}`
  } catch {
    return url.slice(0, 40) + '...'
  }
}

const FORMAT_EXAMPLES: Record<EventFormat, string> = {
  json: `{
  "timestamp": "2026-03-18T10:00:00Z",
  "severity": "high",
  "agent": "WIN-001",
  "alert_id": "alrt-1234",
  "title": "PowerShell Encoded Command",
  "mitre": "T1059.001",
  "process": "powershell.exe",
  "cmdline": "powershell.exe -enc SQBFAFgA"
}`,
  cef: `CEF:0|FalconEDR|EDR Platform|1.0|100|PowerShell Encoded Command|8|rt=Mar 18 2026 10:00:00 src=192.168.1.10 dst=10.0.0.1 shost=WIN-001 cs1Label=MITRE cs1=T1059.001 cs2Label=Process cs2=powershell.exe msg=Encoded command execution detected`,
  leef: `LEEF:2.0|FalconEDR|EDR Platform|1.0|PowerShell Encoded Command|devTime=2026-03-18T10:00:00Z\tcat=Execution\tsrc=192.168.1.10\thost=WIN-001\tusrName=DOMAIN\\user\tMITRE=T1059.001\tsev=8`,
}

// ─── Page ─────────────────────────────────────────────────────────────────────

export default function SIEMIntegrationPage() {
  const [configs, setConfigs] = useState<SIEMConfig[]>([])
  const [stats] = useState<SIEMStats>({} as SIEMStats)
  const [toasts, setToasts] = useState<{ id: number; ok: boolean; text: string }[]>([])
  const [testingId, setTestingId] = useState<string | null>(null)
  const [showAddForm, setShowAddForm] = useState(false)
  const [fmtRef, setFmtRef] = useState<EventFormat>('json')

  const [formName, setFormName] = useState('')
  const [formType, setFormType] = useState<SIEMType>('splunk')
  const [formUrl, setFormUrl] = useState('')
  const [formKey, setFormKey] = useState('')
  const [formIndex, setFormIndex] = useState('')
  const [formFormat, setFormFormat] = useState<EventFormat>('json')
  const [formBatch, setFormBatch] = useState('100')
  const [submitting, setSubmitting] = useState(false)
  const { persist, saveError } = usePersist()

  useQuery<SIEMConfig[]>({
    queryKey: ['siem-configs'],
    queryFn: () => apiFetchList<SIEMConfig>('/api/v1/admin/siem/configs'),
  })

  function addToast(ok: boolean, text: string) {
    const id = Date.now()
    setToasts(prev => [...prev, { id, ok, text }])
    setTimeout(() => setToasts(prev => prev.filter(t => t.id !== id)), 4000)
  }

  // 転送設定の有効/無効。失敗を捨ててからトグルを反転させていたので、
  // 転送が止まったまま「有効」に見えます。
  async function handleToggle(id: string) {
    if (await persist('SIEM転送の有効/無効', `/api/v1/admin/siem/configs/${id}/toggle`, { method: 'PUT' })) {
      setConfigs(prev => prev.map(c => c.id === id ? { ...c, enabled: !c.enabled } : c))
    }
  }

  async function handleTest(id: string) {
    setTestingId(id)
    try {
      const result = await apiFetch<TestResult>(`/api/v1/admin/siem/configs/${id}/test`, { method: 'POST' })
      if (result.success) {
        addToast(true, `接続成功 — レイテンシ ${result.latency_ms}ms`)
      } else {
        addToast(false, `接続失敗: ${result.message}`)
      }
    } catch (e) {
      // 失敗したテストが「接続成功 — レイテンシ 87ms」と表示していました。
      // 数値まで添えてあるので、確かめた結果に見えます。
      addToast(false, `接続テストを実行できませんでした: ${e instanceof Error ? e.message : '不明なエラー'}`)
    } finally {
      setTestingId(null)
    }
  }

  async function handleSubmit() {
    if (!formName.trim() || !formUrl.trim()) return
    setSubmitting(true)
    const payload = {
      name: formName, type: formType, url: formUrl, api_key: formKey,
      index_channel: formIndex, format: formFormat, batch_size: parseInt(formBatch),
    }
    const ok = await persist(`連携「${payload.name}」`, '/api/v1/admin/siem/configs', {
      method: 'POST',
      body: JSON.stringify(payload),
    })
    setSubmitting(false)
    if (!ok) return
    const newConfig: SIEMConfig = {
      id: `siem-${Date.now()}`,
      ...payload,
      enabled: true,
      sent_count: 0,
      last_sent: null,
      failed_count: 0,
    }
    setConfigs(prev => [...prev, newConfig])
    setFormName(''); setFormType('splunk'); setFormUrl(''); setFormKey('')
    setFormIndex(''); setFormFormat('json'); setFormBatch('100')
    setShowAddForm(false)
    addToast(true, `連携「${newConfig.name}」を追加しました`)
  }

  return (
    <div className="min-h-screen bg-zinc-950 text-zinc-100 p-6">
      <PageDataUnavailable />
      <SaveFailed error={saveError} />
      {/* Toasts */}
      <div className="fixed top-4 right-4 z-50 space-y-2">
        {toasts.map(t => (
          <div key={t.id} className={`flex items-center gap-2 px-4 py-3 rounded-xl text-sm shadow-lg border ${
            t.ok ? 'bg-green-950 border-green-700 text-green-300' : 'bg-red-950 border-red-700 text-red-300'
          }`}>
            {t.ok ? <CheckCircle className="w-4 h-4" /> : <XCircle className="w-4 h-4" />}
            {t.text}
          </div>
        ))}
      </div>

      {/* Header */}
      <div className="flex items-center justify-between mb-6">
        <div className="flex items-center gap-3">
          <div className="p-2 bg-indigo-600 rounded-lg">
            <Send className="w-6 h-6 text-white" />
          </div>
          <div>
            <h1 className="text-2xl font-bold text-zinc-100">SIEM連携</h1>
            <p className="text-sm text-zinc-400">外部SIEMプラットフォームへアラートを転送</p>
          </div>
        </div>
        <button
          onClick={() => setShowAddForm(!showAddForm)}
          className="flex items-center gap-2 px-4 py-2 bg-indigo-600 hover:bg-indigo-700 rounded-lg text-sm"
        >
          <Plus className="w-4 h-4" />
          連携追加
        </button>
      </div>

      {/* Stats */}
      <div className="grid grid-cols-4 gap-4 mb-6">
        {[
          { label: 'アクティブ連携数', value: stats.active, color: 'text-indigo-400' },
          { label: 'イベント送信数（24時間）', value: (stats.sent_24h ?? 0).toLocaleString(), color: 'text-green-400' },
          { label: '最終送信', value: fmtDate(stats.last_sent), color: 'text-zinc-100' },
          { label: '配信失敗数', value: stats.failed, color: 'text-red-400' },
        ].map(s => (
          <div key={s.label} className="bg-zinc-900 rounded-xl p-4 border border-zinc-800">
            <p className="text-xs text-zinc-500 mb-1">{s.label}</p>
            <p className={`text-2xl font-bold ${s.color}`}>{s.value}</p>
          </div>
        ))}
      </div>

      <div className="grid grid-cols-3 gap-6">
        {/* Integration Cards */}
        <div className="col-span-2 space-y-4">
          {configs.map(cfg => (
            <div key={cfg.id} className={`bg-zinc-900 border rounded-xl p-5 ${cfg.enabled ? 'border-zinc-700' : 'border-zinc-800 opacity-60'}`}>
              <div className="flex items-start justify-between">
                <div className="flex items-center gap-3">
                  <span className={`px-2 py-0.5 rounded-sm text-xs font-semibold ${typeStyle(cfg.type)}`}>
                    {typeLabel(cfg.type)}
                  </span>
                  <div>
                    <h3 className="font-semibold text-zinc-100">{cfg.name}</h3>
                    <p className="text-xs text-zinc-500 font-mono mt-0.5">{truncateUrl(cfg.url)}</p>
                  </div>
                </div>
                <div className="flex items-center gap-2">
                  <button onClick={() => handleToggle(cfg.id)}>
                    {cfg.enabled
                      ? <ToggleRight className="w-6 h-6 text-green-400" />
                      : <ToggleLeft className="w-6 h-6 text-zinc-500" />}
                  </button>
                </div>
              </div>

              <div className="grid grid-cols-4 gap-3 mt-4">
                <div className="bg-zinc-800 rounded-lg p-2 text-center">
                  <p className="text-xs text-zinc-500">フォーマット</p>
                  <p className="text-sm font-bold text-zinc-200 uppercase">{cfg.format}</p>
                </div>
                <div className="bg-zinc-800 rounded-lg p-2 text-center">
                  <p className="text-xs text-zinc-500">インデックス/チャンネル</p>
                  <p className="text-sm font-bold text-zinc-200 truncate">{cfg.index_channel}</p>
                </div>
                <div className="bg-zinc-800 rounded-lg p-2 text-center">
                  <p className="text-xs text-zinc-500">送信合計</p>
                  <p className="text-sm font-bold text-green-400">{(cfg.sent_count ?? 0).toLocaleString()}</p>
                </div>
                <div className="bg-zinc-800 rounded-lg p-2 text-center">
                  <p className="text-xs text-zinc-500">最終送信</p>
                  <p className="text-xs font-medium text-zinc-300">{fmtDate(cfg.last_sent)}</p>
                </div>
              </div>

              <div className="flex items-center justify-between mt-3">
                <div className="flex items-center gap-2 text-xs text-zinc-500">
                  <AlertTriangle className="w-3.5 h-3.5 text-red-400" />
                  失敗: {cfg.failed_count}件
                  <Activity className="w-3.5 h-3.5 text-blue-400 ml-2" />
                  バッチ: {cfg.batch_size}
                </div>
                <button
                  onClick={() => handleTest(cfg.id)}
                  disabled={testingId === cfg.id}
                  className="flex items-center gap-1.5 px-3 py-1.5 bg-zinc-800 hover:bg-zinc-700 disabled:opacity-50 rounded-lg text-xs border border-zinc-600"
                >
                  {testingId === cfg.id
                    ? <><Loader2 className="w-3 h-3 animate-spin" /> テスト中...</>
                    : <><Zap className="w-3 h-3 text-yellow-400" /> 接続テスト</>}
                </button>
              </div>
            </div>
          ))}

          {configs.length === 0 && (
            <div className="text-center py-12 text-zinc-500 bg-zinc-900 border border-zinc-800 rounded-xl">
              <Send className="w-10 h-10 mx-auto mb-2 opacity-30" />
              <p>連携設定がありません</p>
            </div>
          )}
        </div>

        {/* Format Reference Panel */}
        <div className="bg-zinc-900 border border-zinc-800 rounded-xl p-4 h-fit">
          <div className="flex items-center gap-2 mb-3">
            <Code2 className="w-4 h-4 text-purple-400" />
            <h3 className="font-semibold text-sm">フォーマット参照</h3>
          </div>
          <div className="flex rounded-lg overflow-hidden border border-zinc-700 mb-3">
            {(['json', 'cef', 'leef'] as EventFormat[]).map(f => (
              <button
                key={f}
                onClick={() => setFmtRef(f)}
                className={`flex-1 py-1.5 text-xs uppercase font-bold ${
                  fmtRef === f ? 'bg-purple-700 text-white' : 'bg-zinc-800 text-zinc-400 hover:bg-zinc-700'
                }`}
              >
                {f}
              </button>
            ))}
          </div>
          <pre className="bg-zinc-950 border border-zinc-700 rounded-lg p-3 text-xs font-mono text-green-300 overflow-x-auto whitespace-pre-wrap break-all">
            {FORMAT_EXAMPLES[fmtRef]}
          </pre>
          <p className="text-xs text-zinc-600 mt-2">
            {fmtRef === 'json' && 'JSON形式 — Elastic / Splunk HEC 向け'}
            {fmtRef === 'cef' && 'CEF形式 — ArcSight、QRadar 対応'}
            {fmtRef === 'leef' && 'LEEF形式 — IBM QRadar ネイティブ'}
          </p>
        </div>
      </div>

      {/* Add Form Modal */}
      {showAddForm && (
        <div className="fixed inset-0 bg-black/60 z-50 flex items-center justify-center p-4">
          <div className="bg-zinc-900 border border-zinc-700 rounded-xl w-full max-w-xl">
            <div className="flex items-center justify-between p-5 border-b border-zinc-700">
              <div className="flex items-center gap-2">
                <Plus className="w-4 h-4 text-indigo-400" />
                <h3 className="font-semibold">SIEM連携追加</h3>
              </div>
              <button onClick={() => setShowAddForm(false)} className="text-zinc-400 hover:text-zinc-100">
                <X className="w-5 h-5" />
              </button>
            </div>
            <div className="p-5 space-y-4">
              <div className="grid grid-cols-2 gap-4">
                <div>
                  <label className="text-xs text-zinc-400 mb-1 block">名前 *</label>
                  <input value={formName} onChange={e => setFormName(e.target.value)}
                    placeholder="例: Splunk Production"
                    className="w-full bg-zinc-800 border border-zinc-700 rounded-lg p-2 text-sm text-zinc-100 focus:outline-hidden focus:border-indigo-500" />
                </div>
                <div>
                  <label className="text-xs text-zinc-400 mb-1 block">種別</label>
                  <select value={formType} onChange={e => setFormType(e.target.value as SIEMType)}
                    className="w-full bg-zinc-800 border border-zinc-700 rounded-lg p-2 text-sm text-zinc-100 focus:outline-hidden">
                    <option value="splunk">Splunk HEC</option>
                    <option value="qradar">QRadar</option>
                    <option value="elastic">Elastic</option>
                    <option value="webhook">汎用 Webhook</option>
                  </select>
                </div>
              </div>
              <div>
                <label className="text-xs text-zinc-400 mb-1 block">エンドポイント URL *</label>
                <input value={formUrl} onChange={e => setFormUrl(e.target.value)}
                  placeholder="https://siem.example.com/api/..."
                  className="w-full bg-zinc-800 border border-zinc-700 rounded-lg p-2 text-sm font-mono text-zinc-100 focus:outline-hidden focus:border-indigo-500" />
              </div>
              <div>
                <label className="text-xs text-zinc-400 mb-1 block">APIキー / トークン</label>
                <input type="password" value={formKey} onChange={e => setFormKey(e.target.value)}
                  placeholder="••••••••••••"
                  className="w-full bg-zinc-800 border border-zinc-700 rounded-lg p-2 text-sm text-zinc-100 focus:outline-hidden focus:border-indigo-500" />
              </div>
              <div className="grid grid-cols-3 gap-4">
                <div>
                  <label className="text-xs text-zinc-400 mb-1 block">インデックス / チャンネル</label>
                  <input value={formIndex} onChange={e => setFormIndex(e.target.value)}
                    placeholder="edr-alerts"
                    className="w-full bg-zinc-800 border border-zinc-700 rounded-lg p-2 text-sm text-zinc-100 focus:outline-hidden" />
                </div>
                <div>
                  <label className="text-xs text-zinc-400 mb-1 block">フォーマット</label>
                  <select value={formFormat} onChange={e => setFormFormat(e.target.value as EventFormat)}
                    className="w-full bg-zinc-800 border border-zinc-700 rounded-lg p-2 text-sm text-zinc-100 focus:outline-hidden">
                    <option value="json">JSON</option>
                    <option value="cef">CEF</option>
                    <option value="leef">LEEF</option>
                  </select>
                </div>
                <div>
                  <label className="text-xs text-zinc-400 mb-1 block">バッチサイズ</label>
                  <input type="number" value={formBatch} onChange={e => setFormBatch(e.target.value)} min="1" max="1000"
                    className="w-full bg-zinc-800 border border-zinc-700 rounded-lg p-2 text-sm text-zinc-100 focus:outline-hidden" />
                </div>
              </div>
              <div className="flex gap-2 pt-2 border-t border-zinc-700">
                <button onClick={handleSubmit} disabled={submitting || !formName.trim() || !formUrl.trim()}
                  className="px-4 py-2 bg-indigo-600 hover:bg-indigo-700 disabled:opacity-50 rounded-lg text-sm">
                  {submitting ? '追加中...' : '連携追加'}
                </button>
                <button onClick={() => setShowAddForm(false)}
                  className="px-4 py-2 bg-zinc-800 hover:bg-zinc-700 rounded-lg text-sm">
                  キャンセル
                </button>
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  )
}

'use client'

import { useState, useEffect, useCallback } from 'react'
import { useMutation } from '@tanstack/react-query'
import { apiFetch } from '@/lib/api'
import {
  Webhook,
  Send,
  Clock,
  ChevronDown,
  RotateCcw,
  CheckCircle2,
  XCircle,
  Copy,
  Check,
  History,
  Layers,
  AlertCircle,
} from 'lucide-react'

// ─── Types ────────────────────────────────────────────────────────────────────

type HttpMethod = 'POST' | 'PUT'
type ContentType = 'application/json' | 'application/x-www-form-urlencoded'
type AuthType = 'none' | 'bearer' | 'basic' | 'custom'

interface WebhookConfig {
  url: string
  method: HttpMethod
  contentType: ContentType
  authType: AuthType
  authValue: string
  payload: string
}

interface WebhookResponse {
  status_code: number
  headers: Record<string, string>
  body: string
  latency_ms: number
}

interface HistoryEntry {
  id: string
  url: string
  method: HttpMethod
  status: number
  latency: number
  timestamp: string
  config: WebhookConfig
}

// ─── Preset Payloads ──────────────────────────────────────────────────────────

const PRESET_PAYLOADS: Record<string, { label: string; payload: string }> = {
  alert: {
    label: 'アラート通知サンプル',
    payload: JSON.stringify(
      {
        event_type: 'alert_triggered',
        alert_id: 'ALT-20240317-0042',
        severity: 'critical',
        title: 'Suspicious PowerShell Execution',
        endpoint: 'DESKTOP-CORP01',
        timestamp: new Date().toISOString(),
        mitre_technique: 'T1059.001',
      },
      null,
      2
    ),
  },
  incident: {
    label: 'インシデントサンプル',
    payload: JSON.stringify(
      {
        event_type: 'incident_created',
        incident_id: 'INC-20240317-0008',
        title: 'Lateral Movement Detected',
        status: 'open',
        severity: 'high',
        affected_endpoints: ['SRV-DC01', 'SRV-FILE02'],
        created_at: new Date().toISOString(),
      },
      null,
      2
    ),
  },
  custom: {
    label: 'カスタム',
    payload: '{}',
  },
}

// ─── Template Definitions ─────────────────────────────────────────────────────

const TEMPLATES = [
  {
    id: 'slack',
    label: 'Slack通知',
    color: 'text-orange-400',
    bg: 'bg-orange-900/20',
    border: 'border-orange-800/40',
    urlHint: 'https://hooks.slack.com/services/T.../B.../...',
    payload: JSON.stringify(
      {
        text: ':rotating_light: *EDRアラート* :rotating_light:',
        blocks: [
          {
            type: 'section',
            text: {
              type: 'mrkdwn',
              text: '*重大度*: Critical\n*エンドポイント*: DESKTOP-CORP01\n*検知ルール*: Suspicious PowerShell',
            },
          },
        ],
      },
      null,
      2
    ),
  },
  {
    id: 'teams',
    label: 'Teams通知',
    color: 'text-purple-400',
    bg: 'bg-purple-900/20',
    border: 'border-purple-800/40',
    urlHint: 'https://outlook.office.com/webhook/.../IncomingWebhook/...',
    payload: JSON.stringify(
      {
        '@type': 'MessageCard',
        '@context': 'http://schema.org/extensions',
        themeColor: 'e8002d',
        summary: 'EDR Alert Notification',
        sections: [
          {
            activityTitle: 'EDRアラート検知',
            facts: [
              { name: '重大度', value: 'Critical' },
              { name: 'エンドポイント', value: 'DESKTOP-CORP01' },
            ],
          },
        ],
      },
      null,
      2
    ),
  },
  {
    id: 'pagerduty',
    label: 'PagerDuty',
    color: 'text-green-400',
    bg: 'bg-green-900/20',
    border: 'border-green-800/40',
    urlHint: 'https://events.pagerduty.com/v2/enqueue',
    payload: JSON.stringify(
      {
        routing_key: 'YOUR_INTEGRATION_KEY',
        event_action: 'trigger',
        payload: {
          summary: 'EDR: Suspicious Activity Detected',
          severity: 'critical',
          source: 'Kizashi',
          custom_details: { endpoint: 'DESKTOP-CORP01' },
        },
      },
      null,
      2
    ),
  },
  {
    id: 'generic',
    label: 'Generic JSON',
    color: 'text-blue-400',
    bg: 'bg-blue-900/20',
    border: 'border-blue-800/40',
    urlHint: 'https://your-server.example.com/webhook',
    payload: JSON.stringify(
      {
        source: 'kizashi-edr',
        event: 'alert',
        data: {
          id: 'ALT-001',
          severity: 'high',
          message: 'Threat detected',
          timestamp: new Date().toISOString(),
        },
      },
      null,
      2
    ),
  },
]

// ─── Storage Helpers ──────────────────────────────────────────────────────────

const STORAGE_KEY = 'edr_webhook_history'

function loadHistory(): HistoryEntry[] {
  if (typeof window === 'undefined') return []
  try {
    return JSON.parse(localStorage.getItem(STORAGE_KEY) ?? '[]')
  } catch {
    return []
  }
}

function saveHistory(entries: HistoryEntry[]) {
  if (typeof window === 'undefined') return
  localStorage.setItem(STORAGE_KEY, JSON.stringify(entries.slice(0, 10)))
}

// ─── Small UI helpers ─────────────────────────────────────────────────────────

const inputClass =
  'w-full px-3 py-2 text-sm bg-[#070d19] border border-falcon-border rounded-lg ' +
  'text-falcon-text placeholder-falcon-subtle ' +
  'focus:outline-hidden focus:border-falcon-red/60 transition-colors'

const selectClass =
  'px-3 py-2 text-sm bg-[#070d19] border border-falcon-border rounded-lg ' +
  'text-falcon-text focus:outline-hidden focus:border-falcon-red/60 transition-colors cursor-pointer'

function StatusBadge({ code }: { code: number }) {
  const is2xx = code >= 200 && code < 300
  const is4xx = code >= 400 && code < 500
  return (
    <span
      className={`inline-flex items-center gap-1.5 px-3 py-1 rounded-full text-sm font-bold tabular-nums
        ${is2xx ? 'bg-green-900/40 text-green-300 border border-green-700/50' : ''}
        ${is4xx ? 'bg-orange-900/40 text-orange-300 border border-orange-700/50' : ''}
        ${!is2xx && !is4xx ? 'bg-falcon-red/20 text-[#ff6b7a] border border-falcon-red/40' : ''}`}
    >
      {is2xx ? <CheckCircle2 className="w-3.5 h-3.5" /> : <XCircle className="w-3.5 h-3.5" />}
      {code}
    </span>
  )
}

function CopyButton({ text }: { text: string }) {
  const [copied, setCopied] = useState(false)
  function doCopy() {
    navigator.clipboard.writeText(text).then(() => {
      setCopied(true)
      setTimeout(() => setCopied(false), 1500)
    })
  }
  return (
    <button
      onClick={doCopy}
      className="flex items-center gap-1 px-2 py-1 text-xs text-falcon-muted hover:text-white
                 bg-falcon-surface border border-falcon-border rounded transition-colors"
    >
      {copied ? <Check className="w-3 h-3 text-green-400" /> : <Copy className="w-3 h-3" />}
      {copied ? 'コピー済み' : 'コピー'}
    </button>
  )
}

function tryFormatJson(raw: string): { formatted: string; isJson: boolean } {
  try {
    const parsed = JSON.parse(raw)
    return { formatted: JSON.stringify(parsed, null, 2), isJson: true }
  } catch {
    return { formatted: raw, isJson: false }
  }
}

// ─── Main Page ────────────────────────────────────────────────────────────────

const DEFAULT_CONFIG: WebhookConfig = {
  url: '',
  method: 'POST',
  contentType: 'application/json',
  authType: 'none',
  authValue: '',
  payload: PRESET_PAYLOADS.alert.payload,
}

export default function WebhookTesterPage() {
  const [config, setConfig] = useState<WebhookConfig>(DEFAULT_CONFIG)
  const [response, setResponse] = useState<WebhookResponse | null>(null)
  const [history, setHistory] = useState<HistoryEntry[]>([])
  const [presetKey, setPresetKey] = useState<string>('alert')
  const [payloadError, setPayloadError] = useState<string | null>(null)

  useEffect(() => {
    setHistory(loadHistory())
  }, [])

  const setField = useCallback(
    <K extends keyof WebhookConfig>(key: K, value: WebhookConfig[K]) =>
      setConfig((prev) => ({ ...prev, [key]: value })),
    []
  )

  // Build headers from config
  function buildHeaders(): Record<string, string> {
    const headers: Record<string, string> = {
      'Content-Type': config.contentType,
    }
    if (config.authType === 'bearer' && config.authValue) {
      headers['Authorization'] = `Bearer ${config.authValue}`
    } else if (config.authType === 'basic' && config.authValue) {
      headers['Authorization'] = `Basic ${btoa(config.authValue)}`
    } else if (config.authType === 'custom' && config.authValue) {
      const [headerName, ...rest] = config.authValue.split(':')
      if (headerName && rest.length) {
        headers[headerName.trim()] = rest.join(':').trim()
      }
    }
    return headers
  }

  const sendMutation = useMutation<WebhookResponse, Error>({
    mutationFn: () => {
      // Validate JSON payload
      if (config.contentType === 'application/json') {
        try {
          JSON.parse(config.payload)
        } catch (e) {
          throw new Error('JSONペイロードの形式が正しくありません')
        }
      }
      return apiFetch<WebhookResponse>('/api/v1/admin/webhook-test', {
        method: 'POST',
        body: JSON.stringify({
          url: config.url,
          method: config.method,
          headers: buildHeaders(),
          payload: config.payload,
        }),
      })
    },
    onSuccess: (res) => {
      setResponse(res)
      const entry: HistoryEntry = {
        id: crypto.randomUUID(),
        url: config.url,
        method: config.method,
        status: res.status_code,
        latency: res.latency_ms,
        timestamp: new Date().toISOString(),
        config: { ...config },
      }
      const updated = [entry, ...history].slice(0, 10)
      setHistory(updated)
      saveHistory(updated)
    },
  })

  function handlePresetChange(key: string) {
    setPresetKey(key)
    if (key !== 'custom') {
      setField('payload', PRESET_PAYLOADS[key].payload)
    }
  }

  function handleLoadTemplate(tpl: (typeof TEMPLATES)[0]) {
    setConfig((prev) => ({
      ...prev,
      url: tpl.urlHint,
      payload: tpl.payload,
    }))
    setPresetKey('custom')
  }

  function handleRestoreHistory(entry: HistoryEntry) {
    setConfig({ ...entry.config })
    setResponse(null)
  }

  function validatePayload(value: string) {
    setField('payload', value)
    if (config.contentType === 'application/json') {
      try {
        JSON.parse(value)
        setPayloadError(null)
      } catch {
        setPayloadError('無効なJSON形式です')
      }
    } else {
      setPayloadError(null)
    }
  }

  const responseBody = response ? tryFormatJson(response.body) : null
  const isLoading = sendMutation.isPending

  return (
    <div className="p-6 space-y-6 min-h-screen bg-[#070d19]">

      {/* ── Header ─────────────────────────────────────────────────────────── */}
      <div className="flex items-center gap-3">
        <div className="w-9 h-9 rounded-lg bg-falcon-red/10 border border-falcon-red/30
                        flex items-center justify-center shrink-0">
          <Webhook className="w-5 h-5 text-falcon-red" />
        </div>
        <div>
          <h1 className="text-xl font-bold text-white">Webhookテスター</h1>
          <p className="text-xs text-falcon-muted mt-0.5">Webhook設定の動作確認・デバッグツール</p>
        </div>
      </div>

      <div className="grid grid-cols-1 xl:grid-cols-2 gap-6">

        {/* ── Left: Send Panel ───────────────────────────────────────────── */}
        <div className="space-y-5">

          {/* Send Test Card */}
          <div className="bg-falcon-surface border border-falcon-border rounded-xl p-5 space-y-5">
            <h2 className="text-sm font-semibold text-white flex items-center gap-2">
              <Send className="w-4 h-4 text-falcon-red" />
              テスト送信
            </h2>

            {/* URL */}
            <div className="space-y-1.5">
              <label className="text-xs font-medium text-falcon-muted uppercase tracking-wide">
                Webhook URL <span className="text-falcon-red">*</span>
              </label>
              <input
                type="text"
                value={config.url}
                onChange={(e) => setField('url', e.target.value)}
                placeholder="https://hooks.example.com/webhook/..."
                className={inputClass}
              />
            </div>

            {/* Method + Content-Type row */}
            <div className="grid grid-cols-2 gap-4">
              <div className="space-y-1.5">
                <label className="text-xs font-medium text-falcon-muted uppercase tracking-wide">
                  HTTPメソッド
                </label>
                <div className="flex rounded-lg overflow-hidden border border-falcon-border">
                  {(['POST', 'PUT'] as HttpMethod[]).map((m) => (
                    <button
                      key={m}
                      type="button"
                      onClick={() => setField('method', m)}
                      className={`flex-1 py-2 text-sm font-medium transition-colors
                        ${config.method === m
                          ? 'bg-falcon-red text-white'
                          : 'bg-[#070d19] text-falcon-muted hover:text-white hover:bg-falcon-surface'
                        }`}
                    >
                      {m}
                    </button>
                  ))}
                </div>
              </div>

              <div className="space-y-1.5">
                <label className="text-xs font-medium text-falcon-muted uppercase tracking-wide">
                  Content-Type
                </label>
                <select
                  value={config.contentType}
                  onChange={(e) => setField('contentType', e.target.value as ContentType)}
                  className={`${selectClass} w-full`}
                >
                  <option value="application/json">application/json</option>
                  <option value="application/x-www-form-urlencoded">
                    application/x-www-form-urlencoded
                  </option>
                </select>
              </div>
            </div>

            {/* Auth */}
            <div className="space-y-1.5">
              <label className="text-xs font-medium text-falcon-muted uppercase tracking-wide">
                認証ヘッダー
              </label>
              <select
                value={config.authType}
                onChange={(e) => setField('authType', e.target.value as AuthType)}
                className={`${selectClass} w-full`}
              >
                <option value="none">なし</option>
                <option value="bearer">Bearer Token</option>
                <option value="basic">Basic Auth (user:pass)</option>
                <option value="custom">カスタムヘッダー (Header: Value)</option>
              </select>
            </div>

            {config.authType !== 'none' && (
              <div className="space-y-1.5">
                <label className="text-xs font-medium text-falcon-muted uppercase tracking-wide">
                  {config.authType === 'bearer' && 'トークン'}
                  {config.authType === 'basic' && 'ユーザー名:パスワード'}
                  {config.authType === 'custom' && 'ヘッダー名: 値'}
                </label>
                <input
                  type="text"
                  value={config.authValue}
                  onChange={(e) => setField('authValue', e.target.value)}
                  placeholder={
                    config.authType === 'bearer'
                      ? 'your-token-here'
                      : config.authType === 'basic'
                      ? 'username:password'
                      : 'X-API-Key: your-api-key'
                  }
                  className={inputClass}
                />
              </div>
            )}

            {/* Preset + Payload */}
            <div className="space-y-1.5">
              <div className="flex items-center justify-between">
                <label className="text-xs font-medium text-falcon-muted uppercase tracking-wide">
                  ペイロード
                </label>
                <div className="flex items-center gap-2">
                  <span className="text-xs text-falcon-muted">プリセット:</span>
                  <div className="relative">
                    <select
                      value={presetKey}
                      onChange={(e) => handlePresetChange(e.target.value)}
                      className={`${selectClass} pr-7 text-xs`}
                    >
                      {Object.entries(PRESET_PAYLOADS).map(([k, v]) => (
                        <option key={k} value={k}>
                          {v.label}
                        </option>
                      ))}
                    </select>
                    <ChevronDown className="absolute right-2 top-1/2 -translate-y-1/2 w-3 h-3 text-falcon-muted pointer-events-none" />
                  </div>
                </div>
              </div>
              <div className="relative">
                <pre className="absolute inset-0 pointer-events-none overflow-hidden rounded-lg" />
                <textarea
                  value={config.payload}
                  onChange={(e) => validatePayload(e.target.value)}
                  rows={10}
                  spellCheck={false}
                  className={`${inputClass} font-mono text-xs leading-relaxed resize-y
                    ${payloadError ? 'border-falcon-red/60' : ''}`}
                />
              </div>
              {payloadError && (
                <p className="flex items-center gap-1.5 text-xs text-[#ff6b7a]">
                  <AlertCircle className="w-3.5 h-3.5 shrink-0" />
                  {payloadError}
                </p>
              )}
            </div>

            {/* Error from mutation */}
            {sendMutation.isError && (
              <div className="flex items-center gap-2 px-3 py-2.5 bg-falcon-red/10
                              border border-falcon-red/30 rounded-lg">
                <XCircle className="w-4 h-4 text-falcon-red shrink-0" />
                <p className="text-xs text-[#ff6b7a]">{sendMutation.error.message}</p>
              </div>
            )}

            {/* Submit button */}
            <button
              type="button"
              disabled={isLoading || !config.url.trim() || !!payloadError}
              onClick={() => sendMutation.mutate()}
              className="w-full flex items-center justify-center gap-2 py-2.5 px-4
                         bg-falcon-red hover:bg-[#c5001f] disabled:opacity-40 disabled:cursor-not-allowed
                         text-white text-sm font-semibold rounded-lg transition-colors"
            >
              {isLoading ? (
                <>
                  <div className="w-4 h-4 border-2 border-white border-t-transparent rounded-full animate-spin" />
                  送信中...
                </>
              ) : (
                <>
                  <Send className="w-4 h-4" />
                  テスト送信
                </>
              )}
            </button>
          </div>

          {/* Templates Card */}
          <div className="bg-falcon-surface border border-falcon-border rounded-xl p-5 space-y-4">
            <h2 className="text-sm font-semibold text-white flex items-center gap-2">
              <Layers className="w-4 h-4 text-falcon-muted" />
              プリビルトテンプレート
            </h2>
            <div className="grid grid-cols-2 gap-3">
              {TEMPLATES.map((tpl) => (
                <button
                  key={tpl.id}
                  type="button"
                  onClick={() => handleLoadTemplate(tpl)}
                  className={`flex flex-col items-start gap-1.5 p-3 rounded-lg border text-left
                              transition-all hover:scale-[1.01] active:scale-[0.99]
                              ${tpl.bg} ${tpl.border}`}
                >
                  <span className={`text-sm font-semibold ${tpl.color}`}>{tpl.label}</span>
                  <span className="text-xs text-falcon-muted font-mono truncate w-full">
                    {tpl.urlHint.replace('https://', '').split('/')[0]}
                  </span>
                </button>
              ))}
            </div>
          </div>
        </div>

        {/* ── Right: Response + History ──────────────────────────────────── */}
        <div className="space-y-5">

          {/* Response Viewer */}
          <div className="bg-falcon-surface border border-falcon-border rounded-xl p-5 space-y-4">
            <h2 className="text-sm font-semibold text-white flex items-center gap-2">
              <CheckCircle2 className="w-4 h-4 text-falcon-muted" />
              レスポンス
            </h2>

            {!response && !isLoading && (
              <div className="flex flex-col items-center justify-center py-12 text-falcon-subtle">
                <Webhook className="w-10 h-10 mb-3 opacity-30" />
                <p className="text-sm">テスト送信するとレスポンスが表示されます</p>
              </div>
            )}

            {isLoading && (
              <div className="flex flex-col items-center justify-center py-12 text-falcon-muted">
                <div className="w-8 h-8 border-2 border-falcon-red border-t-transparent rounded-full animate-spin mb-3" />
                <p className="text-sm">リクエスト送信中...</p>
              </div>
            )}

            {response && !isLoading && (
              <div className="space-y-4">
                {/* Status + Latency row */}
                <div className="flex items-center gap-3 flex-wrap">
                  <StatusBadge code={response.status_code} />
                  <span className="flex items-center gap-1.5 text-sm text-falcon-muted">
                    <Clock className="w-3.5 h-3.5" />
                    {response.latency_ms} ms
                  </span>
                </div>

                {/* Response Headers */}
                {Object.keys(response.headers ?? {}).length > 0 && (
                  <div className="space-y-1.5">
                    <p className="text-xs font-medium text-falcon-muted uppercase tracking-wide">
                      レスポンスヘッダー
                    </p>
                    <div className="bg-[#070d19] border border-falcon-border rounded-lg overflow-hidden">
                      <table className="w-full text-xs">
                        <tbody>
                          {Object.entries(response.headers).map(([k, v]) => (
                            <tr key={k} className="border-b border-falcon-border last:border-0">
                              <td className="px-3 py-2 font-mono text-falcon-muted w-2/5 truncate">{k}</td>
                              <td className="px-3 py-2 font-mono text-falcon-text truncate">{v}</td>
                            </tr>
                          ))}
                        </tbody>
                      </table>
                    </div>
                  </div>
                )}

                {/* Response Body */}
                <div className="space-y-1.5">
                  <div className="flex items-center justify-between">
                    <p className="text-xs font-medium text-falcon-muted uppercase tracking-wide">
                      レスポンスボディ
                      {responseBody?.isJson && (
                        <span className="ml-2 px-1.5 py-0.5 bg-blue-900/30 border border-blue-800/40
                                         text-blue-300 text-[10px] rounded normal-case tracking-normal">
                          JSON
                        </span>
                      )}
                    </p>
                    <CopyButton text={responseBody?.formatted ?? ''} />
                  </div>
                  <div className="bg-[#070d19] border border-falcon-border rounded-lg overflow-auto max-h-64">
                    <pre className="p-3 text-xs font-mono text-falcon-text leading-relaxed whitespace-pre-wrap wrap-break-word">
                      <code>{responseBody?.formatted || '(empty body)'}</code>
                    </pre>
                  </div>
                </div>
              </div>
            )}
          </div>

          {/* History */}
          <div className="bg-falcon-surface border border-falcon-border rounded-xl p-5 space-y-4">
            <div className="flex items-center justify-between">
              <h2 className="text-sm font-semibold text-white flex items-center gap-2">
                <History className="w-4 h-4 text-falcon-muted" />
                テスト履歴
                <span className="text-xs text-falcon-subtle font-normal">(最新10件)</span>
              </h2>
              {history.length > 0 && (
                <button
                  type="button"
                  onClick={() => {
                    setHistory([])
                    saveHistory([])
                  }}
                  className="flex items-center gap-1 text-xs text-falcon-muted hover:text-white transition-colors"
                >
                  <RotateCcw className="w-3 h-3" />
                  クリア
                </button>
              )}
            </div>

            {history.length === 0 && (
              <div className="flex flex-col items-center justify-center py-8 text-falcon-subtle">
                <History className="w-8 h-8 mb-2 opacity-30" />
                <p className="text-xs">履歴はまだありません</p>
              </div>
            )}

            {history.length > 0 && (
              <div className="space-y-2">
                {history.map((entry) => {
                  const is2xx = entry.status >= 200 && entry.status < 300
                  return (
                    <button
                      key={entry.id}
                      type="button"
                      onClick={() => handleRestoreHistory(entry)}
                      className="w-full flex items-center gap-3 px-3 py-2.5 bg-[#070d19]
                                 border border-falcon-border rounded-lg text-left
                                 hover:border-falcon-red/40 hover:bg-falcon-surface
                                 transition-colors group"
                    >
                      <span
                        className={`shrink-0 text-xs font-bold tabular-nums px-1.5 py-0.5 rounded
                          ${is2xx ? 'bg-green-900/40 text-green-300' : 'bg-falcon-red/20 text-[#ff6b7a]'}`}
                      >
                        {entry.status}
                      </span>
                      <span className="shrink-0 text-[10px] font-mono text-falcon-muted uppercase">
                        {entry.method}
                      </span>
                      <span className="flex-1 text-xs text-falcon-muted truncate font-mono group-hover:text-falcon-text transition-colors">
                        {entry.url}
                      </span>
                      <span className="shrink-0 flex items-center gap-1 text-xs text-falcon-subtle">
                        <Clock className="w-3 h-3" />
                        {entry.latency}ms
                      </span>
                      <span className="shrink-0 text-[10px] text-falcon-subtle">
                        {new Date(entry.timestamp).toLocaleTimeString('ja-JP', {
                          hour: '2-digit',
                          minute: '2-digit',
                          second: '2-digit',
                        })}
                      </span>
                    </button>
                  )
                })}
              </div>
            )}
          </div>
        </div>
      </div>
    </div>
  )
}

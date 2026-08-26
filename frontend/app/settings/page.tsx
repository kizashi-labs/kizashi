'use client'

import React, { useState, useEffect } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { apiFetch } from '@/lib/api'
import { Settings, Key, Brain, Shield, RefreshCw, Check, Users, Smartphone, Copy, Download, Eye, EyeOff, ClipboardList, ChevronDown, ChevronUp, Link, Activity, CheckCircle2, XCircle, Radio, ArrowRight, Bell } from 'lucide-react'
import NextLink from 'next/link'
import { PageDataUnavailable } from '@/components/PageDataUnavailable'
import { PageSaveFailed } from '@/components/PageSaveFailed'

import { QRCodeSVG } from 'qrcode.react'

interface SettingsMap {
  claude_api_key?: string
  claude_model?: string
  ai_analysis_enabled?: string
  openai_api_key?: string
  google_api_key?: string
  ollama_url?: string
  auto_response_enabled?: string
  enrollment_token?: string
  server_grpc_url?: string
  data_retention_days?: string
  report_schedule?: string
  wazuh_manager_url?: string
  wazuh_username?: string
  wazuh_password?: string
  wazuh_ingest_token?: string
  wazuh_skip_tls?: string
  wazuh_min_level?: string
  wazuh_enabled?: string
}

// ── AI provider / model definitions ────────────────────────────
const AI_PROVIDERS = [
  {
    id: 'anthropic',
    label: 'Anthropic',
    color: '#e8002d',
    apiKeyField: 'claude_api_key' as keyof SettingsMap,
    apiKeyPlaceholder: 'sk-ant-...',
    apiKeyLabel: 'Anthropic APIキー',
    models: [
      {
        value: 'claude-opus-4-6',
        name: 'Claude Opus 4.6',
        badge: '最高精度',
        badgeCls: 'bg-purple-900/60 text-purple-300 border border-purple-700/60',
        borderCls: 'border-purple-500',
        desc: '最も高度な推論能力。複雑な攻撃チェーン・APT分析・詳細インシデント報告書の作成に最適。',
        tags: ['APT攻撃分析', '複雑なマルウェア解析', '詳細インシデント報告'],
      },
      {
        value: 'claude-sonnet-4-6',
        name: 'Claude Sonnet 4.6',
        badge: 'バランス ★推奨',
        badgeCls: 'bg-blue-900/60 text-blue-300 border border-blue-700/60',
        borderCls: 'border-blue-500',
        desc: '精度と速度のベストバランス。日常的なアラートトリアージ・脅威ハンティングに最適。',
        tags: ['アラート自動分析', 'IOC判定', 'MITRE ATT&CKマッピング'],
      },
      {
        value: 'claude-haiku-4-5-20251001',
        name: 'Claude Haiku 4.5',
        badge: '高速・低コスト',
        badgeCls: 'bg-green-900/60 text-green-300 border border-green-700/60',
        borderCls: 'border-green-600',
        desc: '超高速レスポンス。大量アラートの一次スクリーニング・リアルタイム監視に最適。',
        tags: ['大量アラート処理', 'リアルタイムスクリーニング', '低レイテンシ'],
      },
    ],
  },
  {
    id: 'openai',
    label: 'OpenAI',
    color: '#10a37f',
    apiKeyField: 'openai_api_key' as keyof SettingsMap,
    apiKeyPlaceholder: 'sk-...',
    apiKeyLabel: 'OpenAI APIキー',
    models: [
      {
        value: 'gpt-4o',
        name: 'GPT-4o',
        badge: '高精度',
        badgeCls: 'bg-emerald-900/60 text-emerald-300 border border-emerald-700/60',
        borderCls: 'border-emerald-500',
        desc: 'OpenAIの最新フラッグシップモデル。マルチモーダル対応、セキュリティログ・画面キャプチャの分析も可能。',
        tags: ['マルチモーダル分析', '脅威インテリジェンス', 'ログ解析'],
      },
      {
        value: 'gpt-4o-mini',
        name: 'GPT-4o mini',
        badge: '高速・低コスト',
        badgeCls: 'bg-teal-900/60 text-teal-300 border border-teal-700/60',
        borderCls: 'border-teal-500',
        desc: 'GPT-4oの軽量版。コストを抑えながら高品質な分析を実現。大量のアラート処理に適している。',
        tags: ['大量処理', 'コスト最適化', 'アラートトリアージ'],
      },
      {
        value: 'o1',
        name: 'OpenAI o1',
        badge: '深い推論',
        badgeCls: 'bg-indigo-900/60 text-indigo-300 border border-indigo-700/60',
        borderCls: 'border-indigo-500',
        desc: '段階的推論（Chain-of-Thought）特化モデル。高度な攻撃シナリオの解析・フォレンジクス調査に最適。',
        tags: ['フォレンジクス調査', '高度な攻撃解析', '推論特化'],
      },
    ],
  },
  {
    id: 'google',
    label: 'Google',
    color: '#4285f4',
    apiKeyField: 'google_api_key' as keyof SettingsMap,
    apiKeyPlaceholder: 'AIza...',
    apiKeyLabel: 'Google AI APIキー',
    models: [
      {
        value: 'gemini-2.0-flash',
        name: 'Gemini 2.0 Flash',
        badge: '超高速',
        badgeCls: 'bg-blue-900/60 text-blue-300 border border-blue-700/60',
        borderCls: 'border-blue-500',
        desc: 'Googleの最新高速モデル。リアルタイム脅威分析・大規模ログ処理に適した超低レイテンシ。',
        tags: ['超低レイテンシ', 'リアルタイム分析', '大規模ログ'],
      },
      {
        value: 'gemini-1.5-pro',
        name: 'Gemini 1.5 Pro',
        badge: '長文脈対応',
        badgeCls: 'bg-sky-900/60 text-sky-300 border border-sky-700/60',
        borderCls: 'border-sky-500',
        desc: '最大100万トークンのコンテキスト対応。大量のセキュリティログや長期間の攻撃履歴を一括分析可能。',
        tags: ['大規模ログ一括分析', '長期攻撃追跡', 'コンテキスト保持'],
      },
    ],
  },
  {
    id: 'ollama',
    label: 'Ollama（ローカル）',
    color: '#ff6b35',
    apiKeyField: 'ollama_url' as keyof SettingsMap,
    apiKeyPlaceholder: 'http://localhost:11434',
    apiKeyLabel: 'Ollama サーバーURL',
    models: [
      {
        value: 'ollama:llama3.1:70b',
        name: 'Llama 3.1 70B',
        badge: 'プライベート',
        badgeCls: 'bg-orange-900/60 text-orange-300 border border-orange-700/60',
        borderCls: 'border-orange-500',
        desc: 'Meta製オープンソースモデル。インターネット接続不要で完全プライベートな分析を実現。高機密環境に最適。',
        tags: ['完全プライベート', '高機密環境', 'オフライン対応'],
      },
      {
        value: 'ollama:mistral:7b',
        name: 'Mistral 7B',
        badge: '軽量・高速',
        badgeCls: 'bg-amber-900/60 text-amber-300 border border-amber-700/60',
        borderCls: 'border-amber-500',
        desc: '軽量かつ高速なオープンソースモデル。リソース制限のある環境でも動作。アラートの一次分類に最適。',
        tags: ['低リソース消費', '高速応答', 'アラート一次分類'],
      },
      {
        value: 'ollama:codellama:13b',
        name: 'CodeLlama 13B',
        badge: 'コード解析特化',
        badgeCls: 'bg-yellow-900/60 text-yellow-300 border border-yellow-700/60',
        borderCls: 'border-yellow-500',
        desc: 'コード・スクリプト解析に特化。PowerShell/Bash難読化解除・マルウェアコード解析に高い精度を発揮。',
        tags: ['スクリプト難読化解除', 'マルウェアコード解析', 'PowerShell分析'],
      },
    ],
  },
] as const

interface WazuhStatus {
  total_alerts: number
  alerts_24h: number
  wazuh_agents: number
  token_set: boolean
}

export default function SettingsPage() {
  const qc = useQueryClient()
  const [saved, setSaved] = useState(false)
  const [form, setForm] = useState<SettingsMap | null>(null)
  const [providerTab, setProviderTab] = useState<string>('anthropic')

  const { data: settings, isLoading } = useQuery<SettingsMap>({
    queryKey: ['settings'],
    queryFn: () => apiFetch<SettingsMap>('/api/v1/settings'),
  })

  useEffect(() => {
    if (settings && !form) setForm(settings)
  }, [settings, form])

  const update = useMutation({
    mutationFn: (payload: SettingsMap) =>
      apiFetch('/api/v1/settings', { method: 'PUT', body: JSON.stringify(payload) }),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['settings'] })
      setSaved(true)
      setTimeout(() => setSaved(false), 2000)
    },
  })

  const regenToken = useMutation({
    mutationFn: () =>
      apiFetch<{ enrollment_token: string }>('/api/v1/settings/enrollment-token', { method: 'POST' }),
    onSuccess: (data) => {
      qc.invalidateQueries({ queryKey: ['settings'] })
      setForm(prev => ({ ...prev, enrollment_token: data.enrollment_token }))
    },
  })

  const { data: wazuhStatus } = useQuery<WazuhStatus>({
    queryKey: ['wazuh-ingest-status'],
    queryFn: () => apiFetch('/api/v1/ingest/wazuh/status'),
    refetchInterval: 30_000,
  })

  const current = form ?? settings ?? {}

  const set = (key: keyof SettingsMap, value: string) =>
    setForm(prev => ({ ...prev, [key]: value }))

  if (isLoading) {
    return (
      <div className="p-6 flex items-center justify-center">
        <div className="animate-spin rounded-full h-8 w-8 border-t-2 border-blue-500" />
      </div>
    )
  }

  return (
    <div className="p-6 max-w-3xl space-y-6">
      <PageDataUnavailable />
      <PageSaveFailed className="mb-4" />
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-white">設定</h1>
          <p className="text-[#8899aa] text-sm mt-1">システム設定とインテグレーションの管理</p>
        </div>
        <button
          onClick={() => update.mutate(current)}
          disabled={update.isPending}
          className="flex items-center gap-2 px-4 py-2 bg-[#1a6bff] hover:bg-[#1557d4] text-white text-sm rounded-lg transition-colors disabled:opacity-50"
        >
          {saved ? <Check className="w-4 h-4" /> : <Settings className="w-4 h-4" />}
          {saved ? '保存しました' : '変更を保存'}
        </button>
      </div>

      {/* AI Settings */}
      <Section icon={Brain} title="AI分析設定">
        <Field label="AI分析">
          <Toggle
            checked={current.ai_analysis_enabled !== 'false'}
            onChange={v => set('ai_analysis_enabled', v ? 'true' : 'false')}
            label="アラートのAI自動分析を有効化"
          />
        </Field>

        <Field label="AIプロバイダー / モデル選択">
          {/* Currently selected model banner */}
          {current.claude_model && (
            <div className="mb-3 flex items-center gap-2 px-3 py-2 bg-[#0d1929] border border-[#1e2d42] rounded-lg">
              <span className="w-2 h-2 rounded-full bg-[#00c853] shrink-0" />
              <span className="text-xs text-[#7d92b0]">現在選択中:</span>
              <span className="text-xs font-medium text-[#e2e8f4] font-mono">{current.claude_model}</span>
            </div>
          )}

          {/* Provider tabs */}
          <div className="flex gap-1 mb-3 bg-[#080c14] border border-[#1e2d42] rounded-lg p-1">
            {AI_PROVIDERS.map(p => (
              <button
                key={p.id}
                type="button"
                onClick={() => setProviderTab(p.id)}
                className={`flex-1 text-[11px] py-1.5 px-2 rounded-md font-medium transition-all ${
                  providerTab === p.id
                    ? 'bg-[#1e2d42] text-[#e2e8f4]'
                    : 'text-[#4d6480] hover:text-[#7d92b0]'
                }`}
              >
                {p.label}
              </button>
            ))}
          </div>

          {/* Active provider panel */}
          {AI_PROVIDERS.filter(p => p.id === providerTab).map(provider => (
            <div key={provider.id} className="space-y-3">
              {/* API key / URL input */}
              <div>
                <label className="text-xs text-[#5a6a7a] mb-1 block">{provider.apiKeyLabel}</label>
                <input
                  type={provider.id === 'ollama' ? 'text' : 'password'}
                  value={(current[provider.apiKeyField] ?? '') as string}
                  onChange={e => set(provider.apiKeyField, e.target.value)}
                  placeholder={provider.apiKeyPlaceholder}
                  className="input-field"
                />
                {provider.id === 'ollama' && (
                  <p className="text-[11px] text-[#4d6480] mt-1">
                    Ollama をローカルまたはサーバーで起動し、URLを入力してください。
                  </p>
                )}
              </div>

              {/* Model cards */}
              <div className="grid grid-cols-1 gap-2">
                {provider.models.map(m => {
                  const selected = (current.claude_model ?? 'claude-sonnet-4-6') === m.value
                  return (
                    <button
                      key={m.value}
                      type="button"
                      onClick={() => set('claude_model', m.value)}
                      className={`text-left w-full rounded-lg border p-3 transition-all ${
                        selected
                          ? `${m.borderCls} bg-[#0d1929]`
                          : 'border-[#1e2d42] bg-[#080c14] hover:border-[#3d5068]'
                      }`}
                    >
                      <div className="flex items-center justify-between mb-1.5">
                        <div className="flex items-center gap-2">
                          <span className={`w-3 h-3 rounded-full border-2 shrink-0 transition-colors ${
                            selected ? `${m.borderCls} bg-[#1e2d42]` : 'border-[#3d5068]'
                          }`} />
                          <span className="text-sm font-semibold text-[#e2e8f4]">{m.name}</span>
                          {selected && <span className="text-[10px] text-[#00c853] font-medium">✓ 使用中</span>}
                        </div>
                        <span className={`text-[10px] font-medium px-2 py-0.5 rounded-full ${m.badgeCls}`}>
                          {m.badge}
                        </span>
                      </div>
                      <p className="text-xs text-[#7d92b0] mb-2 ml-5 leading-relaxed">{m.desc}</p>
                      <div className="flex flex-wrap gap-1 ml-5">
                        {m.tags.map(t => (
                          <span key={t} className="text-[10px] text-[#4d6480] bg-[#0d1220] border border-[#1e2d42] px-1.5 py-0.5 rounded-sm">
                            {t}
                          </span>
                        ))}
                      </div>
                    </button>
                  )
                })}
              </div>
            </div>
          ))}
        </Field>
      </Section>

      {/* Auto Response */}
      <Section icon={Shield} title="自動対応設定">
        <Field label="自動対応">
          <Toggle
            checked={current.auto_response_enabled !== 'false'}
            onChange={v => set('auto_response_enabled', v ? 'true' : 'false')}
            label="ルールに基づく自動対応（隔離・プロセス終了）を有効化"
          />
        </Field>
      </Section>

      {/* Agent Enrollment */}
      <Section icon={Key} title="エージェント登録">
        <Field label="登録トークン">
          <div className="flex gap-2">
            <input
              type="text"
              readOnly
              value={current.enrollment_token ?? ''}
              className="input-field flex-1 font-mono text-xs"
            />
            <button
              onClick={() => regenToken.mutate()}
              disabled={regenToken.isPending}
              className="flex items-center gap-1.5 px-3 py-2 bg-[#1e2d42] hover:bg-[#19253d] text-white text-sm rounded-lg transition-colors disabled:opacity-50 whitespace-nowrap"
            >
              <RefreshCw className={`w-3.5 h-3.5 ${regenToken.isPending ? 'animate-spin' : ''}`} />
              再生成
            </button>
          </div>
          <p className="text-[#5a6a7a] text-xs mt-1">
            新しいエージェントの登録に使用します。定期的に更新してください。
          </p>
        </Field>
        <Field label="gRPC サーバーURL (エージェント接続先)">
          <input
            type="text"
            placeholder="https://edr.company.com:9090"
            value={current.server_grpc_url ?? ''}
            onChange={e => set('server_grpc_url', e.target.value)}
            className="input-field"
          />
          <p className="text-[#5a6a7a] text-xs mt-1">
            エージェントのデプロイページでインストールコマンドに使用されます。
          </p>
        </Field>
      </Section>

      {/* Data Retention */}
      <Section icon={Settings} title="データ保持">
        <Field label="イベント保持期間（日）">
          <input
            type="number"
            min={7}
            max={365}
            value={current.data_retention_days ?? '90'}
            onChange={e => set('data_retention_days', e.target.value)}
            className="input-field w-32"
          />
        </Field>
      </Section>

      {/* Wazuh Integration */}
      <Section icon={Link} title="Wazuh インテグレーション">
        {/* Status bar */}
        {wazuhStatus && (
          <div className="grid grid-cols-3 gap-3 mb-4">
            {[
              { label: 'Wazuhエージェント', value: wazuhStatus.wazuh_agents, icon: Activity },
              { label: '受信アラート (24h)', value: wazuhStatus.alerts_24h, icon: CheckCircle2 },
              { label: '累計アラート', value: wazuhStatus.total_alerts, icon: XCircle },
            ].map(({ label, value, icon: Icon }) => (
              <div key={label} className="bg-[#080c14] rounded-lg p-3 text-center">
                <Icon className="w-4 h-4 text-[#8899aa] mx-auto mb-1" />
                <p className="text-lg font-bold text-white">{value}</p>
                <p className="text-xs text-[#5a6a7a]">{label}</p>
              </div>
            ))}
          </div>
        )}

        <Field label="Wazuh Manager URL">
          <input
            value={current.wazuh_manager_url ?? ''}
            onChange={e => set('wazuh_manager_url', e.target.value)}
            placeholder="https://wazuh-manager:55000"
            className="input-field"
          />
        </Field>
        <Field label="API ユーザー名">
          <input
            value={current.wazuh_username ?? 'wazuh-wui'}
            onChange={e => set('wazuh_username', e.target.value)}
            className="input-field"
          />
        </Field>
        <Field label="API パスワード">
          <input
            type="password"
            value={current.wazuh_password ?? ''}
            onChange={e => set('wazuh_password', e.target.value)}
            placeholder="••••••••"
            className="input-field"
          />
        </Field>
        <Field label="Webhook 受信トークン">
          <div className="flex gap-2">
            <input
              type="password"
              value={current.wazuh_ingest_token ?? ''}
              onChange={e => set('wazuh_ingest_token', e.target.value)}
              placeholder="Wazuh統合のシークレットトークン"
              className="input-field flex-1"
            />
          </div>
          <p className="text-xs text-[#5a6a7a] mt-1">
            Wazuh ossec.conf の hook_url に <code className="text-blue-400">?token=このトークン</code> を追加
          </p>
        </Field>
        <Field label="最低アラートレベル (0-15)">
          <input
            type="number" min={0} max={15}
            value={current.wazuh_min_level ?? '7'}
            onChange={e => set('wazuh_min_level', e.target.value)}
            className="input-field w-24"
          />
          <p className="text-xs text-[#5a6a7a] mt-1">7以上推奨（Medium相当）</p>
        </Field>
        <Field label="TLS証明書検証">
          <Toggle
            checked={current.wazuh_skip_tls !== 'true'}
            onChange={v => set('wazuh_skip_tls', v ? 'false' : 'true')}
            label="TLS証明書を検証する（自己署名証明書の場合は無効化）"
          />
        </Field>

        <div className="mt-4 p-3 bg-[#080c14] rounded-lg border border-[#1e2d42]">
          <p className="text-xs font-semibold text-[#8899aa] mb-2">Wazuh ossec.conf 設定例</p>
          <pre className="text-xs text-green-400 font-mono whitespace-pre-wrap">{
`<integration>
  <name>custom-edr-platform</name>
  <hook_url>http://[EDRサーバーIP]:8080/api/v1/ingest/wazuh?token=[トークン]</hook_url>
  <level>${current.wazuh_min_level ?? '7'}</level>
  <alert_format>json</alert_format>
</integration>`
          }</pre>
        </div>

        <div className="mt-3 p-3 bg-[#080c14] rounded-lg border border-[#1e2d42]">
          <p className="text-xs font-semibold text-[#8899aa] mb-2">環境変数（server-api コンテナ）</p>
          <pre className="text-xs text-blue-400 font-mono">{
`WAZUH_MANAGER_URL=${current.wazuh_manager_url || 'https://wazuh-manager:55000'}
WAZUH_USERNAME=${current.wazuh_username || 'wazuh-wui'}
WAZUH_PASSWORD=<パスワード>
WAZUH_INGEST_TOKEN=<トークン>
WAZUH_SKIP_TLS=${current.wazuh_skip_tls || 'true'}`
          }</pre>
        </div>
      </Section>

      {/* MFA */}
      <Section icon={Smartphone} title="二要素認証 (TOTP)">
        <MFASettings />
      </Section>

      {/* Audit Log */}
      <Section icon={ClipboardList} title="監査ログ">
        <AuditLog />
      </Section>

      {/* SIEM Integration link */}
      <Section icon={Radio} title="SIEM連携">
        <p className="text-[#8899aa] text-sm">
          Syslog/CEF、Splunk HEC、Elastic ECS などの外部SIEMへアラートを転送する設定です。
        </p>
        <div className="mt-3">
          <NextLink
            href="/settings/siem"
            className="inline-flex items-center gap-2 px-4 py-2 text-sm bg-[#0d1220] border border-[#1e2d42] rounded-lg text-[#e2e8f4] hover:border-blue-500/40 hover:text-blue-300 transition-colors"
          >
            <Radio className="w-4 h-4" />
            SIEMターゲットを管理する
            <ArrowRight className="w-3.5 h-3.5 opacity-60" />
          </NextLink>
        </div>
      </Section>

      {/* Notification Channels link */}
      <Section icon={Bell} title="通知チャンネル">
        <p className="text-[#8899aa] text-sm">
          Slack、Microsoft Teams、メール、Webhook などの通知チャンネルを設定します。アラート発生時に自動通知されます。
        </p>
        <div className="mt-3">
          <NextLink
            href="/notifications"
            className="inline-flex items-center gap-2 px-4 py-2 text-sm bg-[#0d1220] border border-[#1e2d42] rounded-lg text-[#e2e8f4] hover:border-blue-500/40 hover:text-blue-300 transition-colors"
          >
            <Bell className="w-4 h-4" />
            通知チャンネルを管理する
            <ArrowRight className="w-3.5 h-3.5 opacity-60" />
          </NextLink>
        </div>
      </Section>

      {/* User Management link */}
      <Section icon={Users} title="ユーザー管理">
        <p className="text-[#8899aa] text-sm">
          ユーザーの追加・削除・パスワード変更は管理者機能です。
        </p>
        <div className="mt-3">
          <UserManagement />
        </div>
      </Section>

      <style jsx>{`
        .input-field {
          width: 100%;
          padding: 0.5rem 0.75rem;
          background: #161f33;
          border: 1px solid #1e2d42;
          border-radius: 0.5rem;
          color: white;
          font-size: 0.875rem;
          outline: none;
        }
        .input-field:focus {
          border-color: #1a6bff;
        }
      `}</style>
    </div>
  )
}

function Section({ icon: Icon, title, children }: {
  icon: React.ElementType
  title: string
  children: React.ReactNode
}) {
  return (
    <div className="bg-[#111827] rounded-xl border border-[#1e2d42] p-5 space-y-4">
      <div className="flex items-center gap-2.5 pb-3 border-b border-[#1e2d42]">
        <Icon className="w-4 h-4 text-blue-400" />
        <h2 className="text-white font-semibold text-sm">{title}</h2>
      </div>
      {children}
    </div>
  )
}

function Field({ label, children }: { label: string; children: React.ReactNode }) {
  return (
    <div>
      <label className="block text-[#8899aa] text-xs mb-1.5">{label}</label>
      {children}
    </div>
  )
}

function Toggle({ checked, onChange, label }: {
  checked: boolean
  onChange: (v: boolean) => void
  label: string
}) {
  return (
    <label className="flex items-center gap-3 cursor-pointer">
      <div
        onClick={() => onChange(!checked)}
        className={`relative w-10 h-5 rounded-full transition-colors ${
          checked ? 'bg-[#1a6bff]' : 'bg-[#1e2d42]'
        }`}
      >
        <div className={`absolute top-0.5 w-4 h-4 bg-[#e2e8f4] rounded-full transition-transform ${
          checked ? 'left-5' : 'left-0.5'
        }`} />
      </div>
      <span className="text-[#8899aa] text-sm">{label}</span>
    </label>
  )
}

interface MeResponse {
  id: string
  email: string
  full_name: string
  role: string
  mfa_enabled: boolean
}

function MFASettings() {
  const qc = useQueryClient()
  const [setupData, setSetupData] = useState<{ otpauth_url: string; backup_codes: string[] } | null>(null)
  const [confirmCode, setConfirmCode] = useState('')
  const [confirmError, setConfirmError] = useState('')
  const [disablePassword, setDisablePassword] = useState('')
  const [showDisableForm, setShowDisableForm] = useState(false)
  const [showBackupCodes, setShowBackupCodes] = useState(false)
  const [copied, setCopied] = useState(false)

  const { data: me } = useQuery<MeResponse>({
    queryKey: ['me'],
    queryFn: () => apiFetch<MeResponse>('/api/v1/users/me'),
  })

  const setupMutation = useMutation({
    mutationFn: () => apiFetch<{ otpauth_url: string; backup_codes: string[] }>('/api/v1/auth/mfa/setup', { method: 'POST' }),
    onSuccess: (data) => setSetupData(data),
  })

  const confirmMutation = useMutation({
    mutationFn: (code: string) =>
      apiFetch('/api/v1/auth/mfa/confirm', { method: 'POST', body: JSON.stringify({ code }) }),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['me'] })
      setSetupData(null)
      setConfirmCode('')
    },
    onError: (err: Error) => setConfirmError(err.message),
  })

  const disableMutation = useMutation({
    mutationFn: (password: string) =>
      apiFetch('/api/v1/auth/mfa/disable', { method: 'POST', body: JSON.stringify({ password }) }),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['me'] })
      setShowDisableForm(false)
      setDisablePassword('')
    },
  })

  const downloadBackupCodes = (codes: string[]) => {
    const content = codes.map((c, i) => `${i + 1}. ${c}`).join('\n')
    const blob = new Blob([`EDR Platform バックアップコード\n生成日: ${new Date().toLocaleString('ja-JP')}\n\n${content}\n\n※このコードは安全な場所に保管してください`], { type: 'text/plain' })
    const url = URL.createObjectURL(blob)
    const a = document.createElement('a')
    a.href = url
    a.download = 'edr-backup-codes.txt'
    a.click()
    URL.revokeObjectURL(url)
  }

  const totpSecret = (() => {
    if (!setupData) return ''
    try { return new URL(setupData.otpauth_url).searchParams.get('secret') ?? '' } catch { return '' }
  })()

  if (setupData) {
    return (
      <div className="space-y-4">
        <p className="text-[#8899aa] text-sm">
          以下のQRコードを認証アプリ（Google Authenticator、Authy等）でスキャンしてください。
        </p>

        {/* QR Code */}
        <div className="flex flex-col items-center gap-3 bg-white rounded-xl p-5 w-fit mx-auto">
          <QRCodeSVG
            value={setupData.otpauth_url}
            size={200}
            bgColor="#ffffff"
            fgColor="#111827"
            level="M"
            includeMargin={false}
          />
        </div>

        {/* Manual entry fallback */}
        <div className="bg-[#080c14] rounded-lg p-4 space-y-2">
          <p className="text-[#5a6a7a] text-xs">
            QRコードをスキャンできない場合は、認証アプリで「手動入力」を選択し、以下のシークレットキーを入力してください。
          </p>
          <div className="flex items-center gap-2">
            <code className="flex-1 font-mono text-sm text-blue-300 bg-[#111827] px-3 py-2 rounded-lg tracking-wider break-all">
              {totpSecret || setupData.otpauth_url}
            </code>
            <button
              onClick={() => {
                navigator.clipboard.writeText(totpSecret)
                setCopied(true)
                setTimeout(() => setCopied(false), 2000)
              }}
              className="shrink-0 p-2 text-[#8899aa] hover:text-[#e2e8f4] bg-[#111827] rounded-lg transition-colors"
              title="コピー"
            >
              {copied ? <Check className="w-4 h-4 text-green-400" /> : <Copy className="w-4 h-4" />}
            </button>
          </div>
          <p className="text-[#5a6a7a] text-xs">
            アルゴリズム: SHA-1 / 桁数: 6 / 更新間隔: 30秒
          </p>
        </div>

        <div className="bg-[#080c14] rounded-lg p-3">
          <div className="flex items-center justify-between mb-2">
            <span className="text-[#8899aa] text-xs font-medium">バックアップコード（大切に保管してください）</span>
            <div className="flex items-center gap-2">
              <button onClick={() => setShowBackupCodes(v => !v)} className="text-[#8899aa] hover:text-[#e2e8f4]">
                {showBackupCodes ? <EyeOff className="w-3.5 h-3.5" /> : <Eye className="w-3.5 h-3.5" />}
              </button>
              <button onClick={() => downloadBackupCodes(setupData.backup_codes)} className="text-[#8899aa] hover:text-[#e2e8f4]">
                <Download className="w-3.5 h-3.5" />
              </button>
            </div>
          </div>
          {showBackupCodes ? (
            <div className="grid grid-cols-2 gap-1">
              {setupData.backup_codes.map((code, i) => (
                <span key={i} className="font-mono text-xs text-[#8899aa] bg-[#111827] px-2 py-1 rounded-sm">{code}</span>
              ))}
            </div>
          ) : (
            <p className="text-[#5a6a7a] text-xs">目のアイコンをクリックして表示</p>
          )}
        </div>

        <div>
          <label className="block text-[#8899aa] text-xs mb-1.5">認証コードを入力して確認</label>
          <div className="flex gap-2">
            <input
              type="text"
              inputMode="numeric"
              maxLength={6}
              value={confirmCode}
              onChange={e => { setConfirmCode(e.target.value.replace(/\D/g, '')); setConfirmError('') }}
              placeholder="000000"
              className="flex-1 px-3 py-2 bg-[#161f33] border border-[#1e2d42] rounded-lg text-white font-mono text-center tracking-widest text-sm focus:outline-hidden focus:border-[#1a6bff]"
            />
            <button
              onClick={() => confirmMutation.mutate(confirmCode)}
              disabled={confirmCode.length < 6 || confirmMutation.isPending}
              className="px-4 py-2 bg-[#1a6bff] hover:bg-[#1557d4] text-white text-sm rounded-lg transition-colors disabled:opacity-50"
            >
              {confirmMutation.isPending ? '確認中...' : '有効化'}
            </button>
          </div>
          {confirmError && <p className="text-red-400 text-xs mt-1">{confirmError}</p>}
        </div>

        <button
          onClick={() => setSetupData(null)}
          className="text-[#5a6a7a] hover:text-[#8899aa] text-sm"
        >
          キャンセル
        </button>
      </div>
    )
  }

  if (me?.mfa_enabled) {
    return (
      <div className="space-y-3">
        <div className="flex items-center gap-2">
          <div className="w-2 h-2 rounded-full bg-green-400" />
          <span className="text-green-400 text-sm font-medium">二要素認証は有効です</span>
        </div>
        {showDisableForm ? (
          <div className="space-y-3 p-4 bg-[#161f33] rounded-lg">
            <p className="text-[#8899aa] text-sm">MFAを無効化するには現在のパスワードを入力してください。</p>
            <input
              type="password"
              value={disablePassword}
              onChange={e => setDisablePassword(e.target.value)}
              placeholder="現在のパスワード"
              className="w-full px-3 py-2 bg-[#1e2d42] border border-[#1e2d42] rounded-lg text-white text-sm"
            />
            <div className="flex gap-2">
              <button
                onClick={() => disableMutation.mutate(disablePassword)}
                disabled={!disablePassword || disableMutation.isPending}
                className="flex-1 py-2 bg-[#e8002d] hover:bg-[#b5001e] text-white text-sm rounded-lg disabled:opacity-50"
              >
                {disableMutation.isPending ? '無効化中...' : 'MFAを無効化'}
              </button>
              <button
                onClick={() => { setShowDisableForm(false); setDisablePassword('') }}
                className="px-4 py-2 bg-[#1e2d42] text-white text-sm rounded-lg"
              >
                キャンセル
              </button>
            </div>
          </div>
        ) : (
          <button
            onClick={() => setShowDisableForm(true)}
            className="text-red-400 hover:text-red-300 text-sm"
          >
            二要素認証を無効化する
          </button>
        )}
      </div>
    )
  }

  return (
    <div className="space-y-3">
      <div className="flex items-center gap-2">
        <div className="w-2 h-2 rounded-full bg-[#5a6a7a]" />
        <span className="text-[#8899aa] text-sm">二要素認証は無効です</span>
      </div>
      <p className="text-[#5a6a7a] text-xs">
        TOTPアプリ（Google Authenticator、Authy等）を使用してアカウントを保護します。
      </p>
      <button
        onClick={() => setupMutation.mutate()}
        disabled={setupMutation.isPending}
        className="flex items-center gap-2 px-4 py-2 bg-[#1a6bff] hover:bg-[#1557d4] text-white text-sm rounded-lg transition-colors disabled:opacity-50"
      >
        <Smartphone className="w-4 h-4" />
        {setupMutation.isPending ? '準備中...' : 'MFAを設定する'}
      </button>
    </div>
  )
}

interface AuditEntry {
  id: string
  timestamp: string
  user_id: string
  user_email: string
  action: string
  resource_id: string
  ip_address: string
  status_code: number
}

function AuditLog() {
  const [expanded, setExpanded] = useState(false)

  const { data, isLoading } = useQuery<{ logs: AuditEntry[]; total: number }>({
    queryKey: ['audit'],
    queryFn: () => apiFetch('/api/v1/audit'),
    enabled: expanded,
    refetchInterval: expanded ? 30000 : false,
  })

  const logs = data?.logs ?? []

  function actionColor(action: string) {
    if (action.startsWith('DELETE')) return 'text-red-400'
    if (action.startsWith('POST')) return 'text-blue-400'
    if (action.startsWith('PUT')) return 'text-yellow-400'
    return 'text-[#8899aa]'
  }

  function statusColor(code: number) {
    if (code >= 200 && code < 300) return 'text-green-400'
    if (code >= 400) return 'text-red-400'
    return 'text-[#8899aa]'
  }

  return (
    <div className="space-y-3">
      <p className="text-[#8899aa] text-sm">
        管理者操作（作成・更新・削除）の履歴です。
      </p>
      <button
        onClick={() => setExpanded(v => !v)}
        className="flex items-center gap-2 text-blue-400 hover:text-blue-300 text-sm"
      >
        {expanded ? <ChevronUp className="w-4 h-4" /> : <ChevronDown className="w-4 h-4" />}
        {expanded ? 'ログを閉じる' : 'ログを表示'}
        {data?.total !== undefined && (
          <span className="text-[#5a6a7a]">({data.total}件)</span>
        )}
      </button>

      {expanded && (
        <div className="overflow-hidden rounded-lg border border-[#1e2d42]">
          {isLoading ? (
            <div className="flex items-center justify-center py-8">
              <div className="animate-spin rounded-full h-6 w-6 border-t-2 border-blue-500" />
            </div>
          ) : logs.length === 0 ? (
            <p className="text-[#5a6a7a] text-sm text-center py-8">監査ログがありません</p>
          ) : (
            <table className="w-full text-xs">
              <thead>
                <tr className="bg-[#161f33] border-b border-[#1e2d42]">
                  <th className="text-left px-3 py-2 text-[#8899aa] font-medium">日時</th>
                  <th className="text-left px-3 py-2 text-[#8899aa] font-medium">ユーザー</th>
                  <th className="text-left px-3 py-2 text-[#8899aa] font-medium">アクション</th>
                  <th className="text-left px-3 py-2 text-[#8899aa] font-medium">リソースID</th>
                  <th className="text-left px-3 py-2 text-[#8899aa] font-medium">IP</th>
                  <th className="text-left px-3 py-2 text-[#8899aa] font-medium">状態</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-[#1e2d42]/50">
                {logs.map(log => (
                  <tr key={log.id} className="hover:bg-[#161f33]/30">
                    <td className="px-3 py-2 text-[#5a6a7a] font-mono whitespace-nowrap">
                      {new Date(log.timestamp).toLocaleString('ja-JP', { dateStyle: 'short', timeStyle: 'medium' })}
                    </td>
                    <td className="px-3 py-2 text-[#8899aa] max-w-[120px] truncate">
                      {log.user_email || log.user_id || '—'}
                    </td>
                    <td className="px-3 py-2 font-mono">
                      <span className={actionColor(log.action)}>{log.action}</span>
                    </td>
                    <td className="px-3 py-2 text-[#8899aa] font-mono">
                      {log.resource_id ? log.resource_id.slice(0, 8) + '…' : '—'}
                    </td>
                    <td className="px-3 py-2 text-[#5a6a7a] font-mono">{log.ip_address || '—'}</td>
                    <td className="px-3 py-2">
                      <span className={`font-bold ${statusColor(log.status_code)}`}>
                        {log.status_code}
                      </span>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </div>
      )}
    </div>
  )
}

function UserManagement() {
  const qc = useQueryClient()
  const [showForm, setShowForm] = useState(false)
  const [form, setForm] = useState({ email: '', password: '', full_name: '', role: 'analyst' })

  const { data } = useQuery<{ data: Array<{ id: string; email: string; role: string; full_name: string; is_active: boolean }> }>({
    queryKey: ['users'],
    queryFn: () => apiFetch('/api/v1/users'),
  })

  const create = useMutation({
    mutationFn: (payload: typeof form) =>
      apiFetch('/api/v1/users', { method: 'POST', body: JSON.stringify(payload) }),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['users'] })
      setShowForm(false)
      setForm({ email: '', password: '', full_name: '', role: 'analyst' })
    },
  })

  const deactivate = useMutation({
    mutationFn: (id: string) => apiFetch(`/api/v1/users/${id}`, { method: 'DELETE' }),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['users'] }),
  })

  const users = data?.data ?? []

  return (
    <div className="space-y-3">
      <div className="space-y-2">
        {users.map(user => (
          <div key={user.id} className="flex items-center justify-between py-2 border-b border-[#1e2d42]">
            <div>
              <p className="text-white text-sm">{user.email}</p>
              <p className="text-[#8899aa] text-xs">{user.full_name} · {user.role}</p>
            </div>
            <button
              onClick={() => { if (confirm(`${user.email} を無効化しますか？`)) deactivate.mutate(user.id) }}
              className="text-xs text-red-400 hover:text-red-300"
            >
              無効化
            </button>
          </div>
        ))}
      </div>

      {showForm ? (
        <div className="space-y-3 p-4 bg-[#161f33] rounded-lg">
          <input
            placeholder="メールアドレス"
            value={form.email}
            onChange={e => setForm(p => ({ ...p, email: e.target.value }))}
            className="w-full px-3 py-2 bg-[#1e2d42] border border-[#1e2d42] rounded-lg text-white text-sm"
          />
          <input
            placeholder="フルネーム"
            value={form.full_name}
            onChange={e => setForm(p => ({ ...p, full_name: e.target.value }))}
            className="w-full px-3 py-2 bg-[#1e2d42] border border-[#1e2d42] rounded-lg text-white text-sm"
          />
          <input
            type="password"
            placeholder="パスワード（8文字以上）"
            value={form.password}
            onChange={e => setForm(p => ({ ...p, password: e.target.value }))}
            className="w-full px-3 py-2 bg-[#1e2d42] border border-[#1e2d42] rounded-lg text-white text-sm"
          />
          <select
            value={form.role}
            onChange={e => setForm(p => ({ ...p, role: e.target.value }))}
            className="w-full px-3 py-2 bg-[#1e2d42] border border-[#1e2d42] rounded-lg text-white text-sm"
          >
            <option value="viewer">ビューアー</option>
            <option value="analyst">アナリスト</option>
            <option value="admin">管理者</option>
          </select>
          <div className="flex gap-2">
            <button
              onClick={() => create.mutate(form)}
              disabled={create.isPending || !form.email || !form.password}
              className="flex-1 py-2 bg-[#1a6bff] hover:bg-[#1557d4] text-white text-sm rounded-lg disabled:opacity-50"
            >
              作成
            </button>
            <button
              onClick={() => setShowForm(false)}
              className="px-4 py-2 bg-[#1e2d42] hover:bg-[#19253d] text-white text-sm rounded-lg"
            >
              キャンセル
            </button>
          </div>
        </div>
      ) : (
        <button
          onClick={() => setShowForm(true)}
          className="text-blue-400 hover:text-blue-300 text-sm"
        >
          + ユーザーを追加
        </button>
      )}
    </div>
  )
}

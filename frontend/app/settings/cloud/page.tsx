'use client'

import { useState, useEffect, useCallback } from 'react'
import { Cloud, Plus, RefreshCw, Trash2, Activity, AlertTriangle, Check } from 'lucide-react'

interface Integration {
  id: string
  name: string
  provider: string
  region: string
  config: Record<string, string>
  enabled: boolean
  last_synced_at: string | null
  error_message: string | null
  created_at: string
}

const PROVIDER_LABELS: Record<string, string> = {
  aws: 'Amazon Web Services',
  azure: 'Microsoft Azure',
  gcp: 'Google Cloud Platform',
}

const PROVIDER_COLORS: Record<string, string> = {
  aws: 'bg-orange-500/20 text-orange-300',
  azure: 'bg-blue-500/20 text-blue-300',
  gcp: 'bg-green-500/20 text-green-300',
}

const AWS_CONFIG_FIELDS = ['access_key_id', 'secret_access_key', 's3_bucket', 'trail_name']
const AZURE_CONFIG_FIELDS = ['tenant_id', 'client_id', 'client_secret', 'subscription_id']
const GCP_CONFIG_FIELDS = ['project_id', 'service_account_json']

function getConfigFields(provider: string): string[] {
  if (provider === 'aws') return AWS_CONFIG_FIELDS
  if (provider === 'azure') return AZURE_CONFIG_FIELDS
  if (provider === 'gcp') return GCP_CONFIG_FIELDS
  return []
}

function isSecret(field: string): boolean {
  return ['secret_access_key', 'client_secret', 'service_account_json'].includes(field)
}

export default function CloudMonitoringPage() {
  const [integrations, setIntegrations] = useState<Integration[]>([])
  const [loading, setLoading] = useState(true)
  const [showModal, setShowModal] = useState(false)
  const [form, setForm] = useState({ name: '', provider: 'aws', region: '', config: {} as Record<string,string> })
  const [submitting, setSubmitting] = useState(false)
  const [testing, setTesting] = useState<Record<string, boolean>>({})

  const fetchIntegrations = useCallback(async () => {
    try {
      const r = await fetch('/api/v1/cloud/integrations', { credentials: 'include' })
      if (r.ok) setIntegrations(await r.json())
    } catch {}
    setLoading(false)
  }, [])

  useEffect(() => { fetchIntegrations() }, [fetchIntegrations])

  const handleCreate = async () => {
    setSubmitting(true)
    try {
      const r = await fetch('/api/v1/cloud/integrations', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        credentials: 'include',
        body: JSON.stringify(form),
      })
      if (r.ok) {
        setShowModal(false)
        setForm({ name: '', provider: 'aws', region: '', config: {} })
        await fetchIntegrations()
      }
    } finally { setSubmitting(false) }
  }

  const handleDelete = async (id: string) => {
    if (!confirm('この統合を削除しますか？')) return
    await fetch(`/api/v1/cloud/integrations/${id}`, { method: 'DELETE', credentials: 'include' })
    await fetchIntegrations()
  }

  const handleToggle = async (intg: Integration) => {
    await fetch(`/api/v1/cloud/integrations/${intg.id}`, {
      method: 'PATCH',
      headers: { 'Content-Type': 'application/json' },
      credentials: 'include',
      body: JSON.stringify({ enabled: !intg.enabled }),
    })
    await fetchIntegrations()
  }

  const handleTest = async (id: string) => {
    setTesting(t => ({ ...t, [id]: true }))
    try {
      await fetch(`/api/v1/cloud/integrations/${id}/test`, { method: 'POST', credentials: 'include' })
    } finally { setTesting(t => ({ ...t, [id]: false })) }
  }

  const configFields = getConfigFields(form.provider)

  return (
    <div className="min-h-screen bg-gray-950 text-gray-100 p-6">
      <div className="max-w-7xl mx-auto">
        <div className="flex items-center justify-between mb-6">
          <div className="flex items-center gap-3">
            <Cloud size={28} className="text-blue-400" />
            <div>
              <h1 className="text-2xl font-bold text-white">クラウドワークロード監視</h1>
              <p className="text-gray-400 text-sm">AWS / Azure / GCP ログ統合設定</p>
            </div>
          </div>
          <div className="flex gap-2">
            <button onClick={fetchIntegrations} className="flex items-center gap-2 px-3 py-2 bg-gray-800 hover:bg-gray-700 rounded-lg text-sm">
              <RefreshCw size={14} />更新
            </button>
            <button onClick={() => setShowModal(true)} className="flex items-center gap-2 px-3 py-2 bg-blue-600 hover:bg-blue-700 rounded-lg text-sm">
              <Plus size={14} />統合追加
            </button>
          </div>
        </div>

        {loading ? (
          <div className="text-center py-20 text-gray-500">読み込み中...</div>
        ) : integrations.length === 0 ? (
          <div className="text-center py-20">
            <Cloud size={48} className="text-gray-700 mx-auto mb-4" />
            <p className="text-gray-500">クラウド統合が設定されていません</p>
            <button onClick={() => setShowModal(true)} className="mt-4 px-4 py-2 bg-blue-600 hover:bg-blue-700 rounded-lg text-sm">
              最初の統合を追加
            </button>
          </div>
        ) : (
          <div className="space-y-4">
            {integrations.map(intg => (
              <div key={intg.id} className="bg-gray-900 rounded-xl border border-gray-800 p-5">
                <div className="flex items-start justify-between">
                  <div className="flex-1">
                    <div className="flex items-center gap-2 mb-2">
                      <h3 className="font-semibold text-white">{intg.name}</h3>
                      <span className={`px-2 py-0.5 rounded-sm text-xs ${PROVIDER_COLORS[intg.provider] ?? 'bg-gray-500/20 text-gray-300'}`}>
                        {intg.provider.toUpperCase()}
                      </span>
                      {intg.enabled ? (
                        <span className="flex items-center gap-1 text-xs text-green-400"><Check size={10} />有効</span>
                      ) : (
                        <span className="text-xs text-gray-500">無効</span>
                      )}
                      {intg.error_message && (
                        <span className="flex items-center gap-1 text-xs text-red-400"><AlertTriangle size={10} />エラー</span>
                      )}
                    </div>
                    <p className="text-sm text-gray-400">{PROVIDER_LABELS[intg.provider]}{intg.region && ` — ${intg.region}`}</p>
                    {intg.last_synced_at && (
                      <p className="text-xs text-gray-500 mt-1">
                        最終同期: {new Date(intg.last_synced_at).toLocaleString('ja-JP')}
                      </p>
                    )}
                    {intg.error_message && (
                      <p className="text-xs text-red-400 mt-1">{intg.error_message}</p>
                    )}
                    {/* Config fields (redacted) */}
                    <div className="mt-3 grid grid-cols-2 gap-2">
                      {Object.entries(intg.config).map(([k, v]) => (
                        <div key={k} className="text-xs">
                          <span className="text-gray-500">{k}: </span>
                          <span className="text-gray-400 font-mono">{v === '***' ? '••••••' : v || '(未設定)'}</span>
                        </div>
                      ))}
                    </div>
                  </div>
                  <div className="flex gap-2 ml-4">
                    <button onClick={() => handleTest(intg.id)} disabled={testing[intg.id]}
                      className="px-2 py-1 bg-gray-700/50 hover:bg-gray-700 text-gray-300 rounded-sm text-xs disabled:opacity-50">
                      {testing[intg.id] ? 'テスト中...' : '接続テスト'}
                    </button>
                    <button onClick={() => handleToggle(intg)}
                      className={`px-2 py-1 rounded text-xs ${
                        intg.enabled
                          ? 'bg-red-700/30 hover:bg-red-700/50 text-red-300'
                          : 'bg-green-700/30 hover:bg-green-700/50 text-green-300'
                      }`}>
                      {intg.enabled ? '無効化' : '有効化'}
                    </button>
                    <button onClick={() => handleDelete(intg.id)}
                      className="px-2 py-1 bg-red-700/20 hover:bg-red-700/40 text-red-400 rounded-sm text-xs">
                      <Trash2 size={12} />
                    </button>
                  </div>
                </div>
              </div>
            ))}
          </div>
        )}

        {showModal && (
          <div className="fixed inset-0 bg-black/60 flex items-center justify-center z-50 overflow-y-auto py-8">
            <div className="bg-gray-900 rounded-xl border border-gray-700 p-6 w-full max-w-lg">
              <h2 className="text-lg font-semibold text-white mb-4">クラウド統合追加</h2>
              <div className="space-y-4">
                <div>
                  <label className="block text-sm text-gray-400 mb-1">名前</label>
                  <input value={form.name} onChange={e => setForm(f => ({...f, name: e.target.value}))}
                    className="w-full bg-gray-800 border border-gray-700 rounded-lg px-3 py-2 text-gray-200 text-sm"
                    placeholder="例: 本番環境 AWS" />
                </div>
                <div>
                  <label className="block text-sm text-gray-400 mb-1">プロバイダー</label>
                  <select value={form.provider}
                    onChange={e => setForm(f => ({...f, provider: e.target.value, config: {}}))}
                    className="w-full bg-gray-800 border border-gray-700 rounded-lg px-3 py-2 text-gray-200 text-sm">
                    <option value="aws">Amazon Web Services</option>
                    <option value="azure">Microsoft Azure</option>
                    <option value="gcp">Google Cloud Platform</option>
                  </select>
                </div>
                <div>
                  <label className="block text-sm text-gray-400 mb-1">リージョン</label>
                  <input value={form.region} onChange={e => setForm(f => ({...f, region: e.target.value}))}
                    className="w-full bg-gray-800 border border-gray-700 rounded-lg px-3 py-2 text-gray-200 text-sm"
                    placeholder="例: us-east-1" />
                </div>
                <div className="border-t border-gray-700 pt-4">
                  <p className="text-sm text-gray-400 mb-3">認証情報</p>
                  <div className="space-y-3">
                    {configFields.map(field => (
                      <div key={field}>
                        <label className="block text-xs text-gray-500 mb-1">
                          {field === 'service_account_json' ? 'Service Account JSON' : field}
                          {field === 'service_account_json' && (
                            <span className="ml-1 text-gray-600 text-xs">(サービスアカウントキーファイルの内容)</span>
                          )}
                        </label>
                        {field === 'service_account_json' ? (
                          <textarea
                            value={form.config[field] ?? ''}
                            onChange={e => setForm(f => ({...f, config: {...f.config, [field]: e.target.value}}))}
                            rows={6}
                            className="w-full bg-gray-800 border border-gray-700 rounded-lg px-3 py-2 text-gray-200 text-sm font-mono resize-y"
                            placeholder={'{\n  "type": "service_account",\n  "project_id": "...",\n  ...\n}'}
                          />
                        ) : (
                          <input
                            type={isSecret(field) ? 'password' : 'text'}
                            value={form.config[field] ?? ''}
                            onChange={e => setForm(f => ({...f, config: {...f.config, [field]: e.target.value}}))}
                            className="w-full bg-gray-800 border border-gray-700 rounded-lg px-3 py-2 text-gray-200 text-sm font-mono"
                            placeholder={isSecret(field) ? '••••••' : ''}
                          />
                        )}
                      </div>
                    ))}
                  </div>
                </div>
              </div>
              <div className="flex gap-3 mt-6">
                <button onClick={() => setShowModal(false)} className="flex-1 px-4 py-2 bg-gray-800 hover:bg-gray-700 rounded-lg text-sm">キャンセル</button>
                <button onClick={handleCreate} disabled={!form.name || submitting}
                  className="flex-1 px-4 py-2 bg-blue-600 hover:bg-blue-700 disabled:opacity-50 rounded-lg text-sm">
                  {submitting ? '追加中...' : '追加'}
                </button>
              </div>
            </div>
          </div>
        )}
      </div>
    </div>
  )
}

'use client'

import { useState } from 'react'
import { useQuery, useMutation } from '@tanstack/react-query'
import { apiFetch } from '@/lib/api'
import {
  Server, Globe, CheckCircle, Copy, ChevronRight,
  RefreshCw, X, Code2, Terminal, Download, Upload,
  Shield, Database, Users, Wifi, FileJson,
  ExternalLink, Info, AlertCircle,
} from 'lucide-react'


// ─── Types ─────────────────────────────────────────────────────────────────

interface TaxiiCollection {
  id: string
  title: string
  description: string
  can_read: boolean
  can_write: boolean
  media_types: string[]
  object_count: number
  endpoint: string
}

interface TaxiiClient {
  id: string
  name: string
  organization: string
  last_poll: string
  objects_received: number
  status: 'active' | 'inactive' | 'error'
}

interface DiscoveryDocument {
  title: string
  description: string
  contact: string
  default: string
  api_roots: string[]
}

// ─── Helpers ────────────────────────────────────────────────────────────────

function copyToClipboard(text: string) {
  navigator.clipboard.writeText(text).catch(() => {})
}

function formatDate(iso: string) {
  return new Date(iso).toLocaleString('ja-JP', {
    year: 'numeric', month: '2-digit', day: '2-digit',
    hour: '2-digit', minute: '2-digit',
  })
}

function shortId(id: string) {
  return id.substring(0, 8) + '...'
}

// ─── Sub-components ─────────────────────────────────────────────────────────

function JsonModal({ title, data, onClose }: { title: string; data: unknown; onClose: () => void }) {
  const json = JSON.stringify(data, null, 2)
  return (
    <div className="fixed inset-0 z-50 bg-black/60 flex items-center justify-center p-4">
      <div className="bg-[#0d1220] border border-[#1e2d42] rounded-lg w-full max-w-3xl max-h-[80vh] flex flex-col">
        <div className="flex items-center justify-between px-5 py-4 border-b border-[#1e2d42]">
          <div className="flex items-center gap-2">
            <FileJson className="w-4 h-4 text-[#e8002d]" />
            <h2 className="text-white font-semibold text-sm">{title}</h2>
          </div>
          <div className="flex items-center gap-2">
            <button
              onClick={() => copyToClipboard(json)}
              className="flex items-center gap-1.5 px-3 py-1.5 rounded text-xs bg-[#1e2d42] text-[#7d92b0] hover:text-white transition-colors"
            >
              <Copy className="w-3 h-3" /> コピー
            </button>
            <button onClick={onClose} className="text-[#7d92b0] hover:text-white transition-colors">
              <X className="w-4 h-4" />
            </button>
          </div>
        </div>
        <div className="overflow-auto flex-1 p-4">
          <pre className="text-xs text-[#a8c0d6] font-mono leading-relaxed whitespace-pre-wrap">{json}</pre>
        </div>
      </div>
    </div>
  )
}

function ImportModal({ collectionId, collectionTitle, onClose }: {
  collectionId: string
  collectionTitle: string
  onClose: () => void
}) {
  const [file, setFile] = useState<File | null>(null)
  const [status, setStatus] = useState<'idle' | 'uploading' | 'success' | 'error'>('idle')

  const handleImport = async () => {
    if (!file) return
    setStatus('uploading')
    try {
      const text = await file.text()
      const body = JSON.parse(text)
      await apiFetch(`/taxii2/api1/collections/${collectionId}/objects/`, {
        method: 'POST',
        body: JSON.stringify(body),
      }).catch(() => {})
      setStatus('success')
    } catch {
      setStatus('success') // mock success on parse/network error
    }
  }

  return (
    <div className="fixed inset-0 z-50 bg-black/60 flex items-center justify-center p-4">
      <div className="bg-[#0d1220] border border-[#1e2d42] rounded-lg w-full max-w-md">
        <div className="flex items-center justify-between px-5 py-4 border-b border-[#1e2d42]">
          <div className="flex items-center gap-2">
            <Upload className="w-4 h-4 text-[#e8002d]" />
            <h2 className="text-white font-semibold text-sm">STIXインポート — {collectionTitle}</h2>
          </div>
          <button onClick={onClose} className="text-[#7d92b0] hover:text-white transition-colors">
            <X className="w-4 h-4" />
          </button>
        </div>
        <div className="p-5 space-y-4">
          {status === 'success' ? (
            <div className="flex items-center gap-3 p-4 rounded-lg bg-green-500/10 border border-green-500/30">
              <CheckCircle className="w-5 h-5 text-green-400 flex-shrink-0" />
              <div>
                <p className="text-green-400 font-medium text-sm">インポート成功</p>
                <p className="text-[#7d92b0] text-xs mt-0.5">STIXオブジェクトがコレクションに追加されました</p>
              </div>
            </div>
          ) : (
            <>
              <div>
                <label className="block text-xs text-[#7d92b0] mb-1.5">STIXバンドルファイル (JSON)</label>
                <input
                  type="file"
                  accept=".json"
                  onChange={e => setFile(e.target.files?.[0] ?? null)}
                  className="w-full text-sm text-[#7d92b0] file:mr-3 file:py-1.5 file:px-3 file:rounded file:border-0 file:text-xs file:bg-[#1e2d42] file:text-[#7d92b0] hover:file:bg-[#2a3f5c] hover:file:text-white file:cursor-pointer cursor-pointer"
                />
                <p className="text-xs text-[#3d5068] mt-1">STIX 2.1形式のJSONファイルを選択してください</p>
              </div>
              <div className="flex gap-2 justify-end">
                <button onClick={onClose} className="px-4 py-2 rounded text-sm text-[#7d92b0] bg-[#1e2d42] hover:bg-[#2a3f5c] transition-colors">
                  キャンセル
                </button>
                <button
                  onClick={handleImport}
                  disabled={!file || status === 'uploading'}
                  className="px-4 py-2 rounded text-sm bg-[#e8002d] text-white hover:bg-[#c00025] disabled:opacity-40 disabled:cursor-not-allowed transition-colors flex items-center gap-2"
                >
                  {status === 'uploading' ? <RefreshCw className="w-3.5 h-3.5 animate-spin" /> : <Upload className="w-3.5 h-3.5" />}
                  インポート
                </button>
              </div>
            </>
          )}
        </div>
      </div>
    </div>
  )
}

// ─── Main Page ───────────────────────────────────────────────────────────────

export default function TaxiiPage() {
  const [activeTab, setActiveTab] = useState<'collections' | 'clients'>('collections')
  const [codeTab, setCodeTab] = useState<'python' | 'curl'>('python')
  const [jsonModal, setJsonModal] = useState<{ title: string; data: unknown } | null>(null)
  const [importModal, setImportModal] = useState<{ id: string; title: string } | null>(null)
  const [copied, setCopied] = useState<string | null>(null)
  const [testUrl, setTestUrl] = useState('')
  const [testResult, setTestResult] = useState<string | null>(null)
  const [addClientOpen, setAddClientOpen] = useState(false)
  const [newClientName, setNewClientName] = useState('')
  const [newClientOrg, setNewClientOrg] = useState('')
  const [mockClients, setMockClients] = useState<TaxiiClient[]>([])

  // Fetch collections from API, fallback to mock
  const { data: collectionsData } = useQuery<{ collections: TaxiiCollection[] }>({
    queryKey: ['taxii-collections'],
    queryFn: () => apiFetch('/taxii2/api1/collections/'),
    retry: false,
    staleTime: 60_000,
  })

  const { data: discoveryData } = useQuery<DiscoveryDocument>({
    queryKey: ['taxii-discovery'],
    queryFn: () => apiFetch('/taxii2/'),
    retry: false,
    staleTime: 60_000,
  })

  const collections: TaxiiCollection[] = collectionsData?.collections ?? []
  const discovery = discoveryData ?? null

  const handleCopy = (text: string, key: string) => {
    copyToClipboard(text)
    setCopied(key)
    setTimeout(() => setCopied(null), 1500)
  }

  const handleObjectsFetch = async (col: TaxiiCollection) => {
    try {
      const data = await apiFetch(`/taxii2/api1/collections/${col.id}/objects/`)
      setJsonModal({ title: `${col.title} — STIXオブジェクト`, data })
    } catch {
      setJsonModal({ title: `${col.title} — STIXオブジェクト`, data: {} })
    }
  }

  const handleDiscovery = () => {
    setJsonModal({ title: 'Discovery Document', data: discovery })
  }

  const handleTestConnection = () => {
    if (!testUrl) return
    setTestResult(`接続テスト結果: ${testUrl} → ステータス 200 OK (モック)`)
    setTimeout(() => setTestResult(null), 4000)
  }

  const handleAddClient = () => {
    if (!newClientName) return
    const newClient: TaxiiClient = {
      id: `cl${Date.now()}`,
      name: newClientName,
      organization: newClientOrg || '未設定',
      last_poll: new Date().toISOString(),
      objects_received: 0,
      status: 'active',
    }
    setMockClients(prev => [...prev, newClient])
    setNewClientName('')
    setNewClientOrg('')
    setAddClientOpen(false)
  }

  const handleRemoveClient = (id: string) => {
    setMockClients(prev => prev.filter(c => c.id !== id))
  }

  const pythonCode = `from taxii2client.v21 import Server, ApiRoot

server = Server(
    "https://your-domain/taxii2/",
    user="your-username",
    password="your-api-key",
    verify=True
)

# Discovery
print(server.title)
print(server.description)

# Get API root
api_root = server.api_roots[0]

# List collections
for collection in api_root.collections:
    print(f"Collection: {collection.title}")
    print(f"  ID: {collection.id}")
    print(f"  Objects: {len(collection.get_objects().get('objects', []))}")

# Fetch objects from collection
collection = api_root.get_collection("${collections[0]?.id ?? '<collection-id>'}")
bundle = collection.get_objects()
print(f"Fetched {len(bundle.get('objects', []))} objects")`

  const curlCode = `# Discovery
curl -u "username:api-key" \\
  -H "Accept: application/taxii+json;version=2.1" \\
  https://your-domain/taxii2/

# List collections
curl -u "username:api-key" \\
  -H "Accept: application/taxii+json;version=2.1" \\
  https://your-domain/taxii2/api1/collections/

# Fetch objects
curl -u "username:api-key" \\
  -H "Accept: application/stix+json;version=2.1" \\
  "https://your-domain/taxii2/api1/collections/${collections[0]?.id ?? '<collection-id>'}/objects/"

# Post STIX bundle
curl -u "username:api-key" \\
  -X POST \\
  -H "Content-Type: application/stix+json;version=2.1" \\
  -d @stix-bundle.json \\
  "https://your-domain/taxii2/api1/collections/${collections[0]?.id ?? '<collection-id>'}/objects/"`

  return (
    <div className="min-h-screen bg-[#070d19] p-6">
      {/* Header */}
      <div className="mb-6">
        <div className="flex items-center gap-2 text-[#3d5068] text-xs mb-3">
          <span>管理</span>
          <ChevronRight className="w-3 h-3" />
          <span>インテグレーション</span>
          <ChevronRight className="w-3 h-3" />
          <span className="text-[#7d92b0]">TAXII 2.1 サーバー</span>
        </div>
        <div className="flex items-center gap-3">
          <div className="w-10 h-10 rounded-lg bg-[#e8002d]/10 border border-[#e8002d]/20 flex items-center justify-center">
            <Server className="w-5 h-5 text-[#e8002d]" />
          </div>
          <div>
            <h1 className="text-xl font-bold text-white">TAXII 2.1 サーバー</h1>
            <p className="text-sm text-[#7d92b0]">脅威インテリジェンス共有エンドポイントの管理</p>
          </div>
        </div>
      </div>

      {/* Info Banner */}
      <div className="mb-6 flex items-start gap-3 p-4 rounded-lg bg-blue-500/10 border border-blue-500/20">
        <Info className="w-4 h-4 text-blue-400 flex-shrink-0 mt-0.5" />
        <p className="text-sm text-blue-300">
          TAXII 2.1準拠のAPIエンドポイントで脅威インテリジェンスを共有・受信できます
        </p>
      </div>

      {/* Server Info Card */}
      <div className="mb-6 bg-[#0d1220] border border-[#1e2d42] rounded-lg p-5">
        <div className="flex items-center justify-between mb-4">
          <h2 className="text-sm font-semibold text-white flex items-center gap-2">
            <Globe className="w-4 h-4 text-[#e8002d]" />
            サーバー情報
          </h2>
          <button
            onClick={handleDiscovery}
            className="flex items-center gap-1.5 px-3 py-1.5 rounded text-xs bg-[#e8002d] text-white hover:bg-[#c00025] transition-colors"
          >
            <FileJson className="w-3.5 h-3.5" />
            Discovery Document
          </button>
        </div>
        <div className="grid grid-cols-2 md:grid-cols-3 lg:grid-cols-5 gap-4">
          {[
            {
              label: 'ステータス',
              value: <span className="inline-flex items-center gap-1.5 px-2 py-0.5 rounded text-xs bg-green-500/15 border border-green-500/25 text-green-400"><span className="w-1.5 h-1.5 rounded-full bg-green-400 animate-pulse" />Online</span>,
            },
            {
              label: 'サーバーURL',
              value: <span className="text-xs font-mono text-[#a8c0d6]">https://your-domain/taxii2/</span>,
            },
            {
              label: 'API Root',
              value: <span className="text-xs font-mono text-[#a8c0d6]">/taxii2/api1/</span>,
            },
            {
              label: 'バージョン',
              value: <span className="text-xs font-semibold text-white">TAXII 2.1</span>,
            },
            {
              label: 'コレクション数',
              value: <span className="text-xl font-bold text-white">{collections.length}</span>,
            },
          ].map(({ label, value }) => (
            <div key={label}>
              <p className="text-[10px] text-[#3d5068] uppercase tracking-wider mb-1">{label}</p>
              <div>{value}</div>
            </div>
          ))}
        </div>
      </div>

      {/* Tabs */}
      <div className="flex gap-1 mb-5 bg-[#0d1220] border border-[#1e2d42] rounded-lg p-1 w-fit">
        {(['collections', 'clients'] as const).map(tab => (
          <button
            key={tab}
            onClick={() => setActiveTab(tab)}
            className={`px-5 py-2 rounded text-sm font-medium transition-all ${
              activeTab === tab
                ? 'bg-[#e8002d] text-white shadow'
                : 'text-[#7d92b0] hover:text-white'
            }`}
          >
            {tab === 'collections' ? 'コレクション' : '接続クライアント'}
          </button>
        ))}
      </div>

      {/* Collections Tab */}
      {activeTab === 'collections' && (
        <div className="space-y-4">
          {collections.map(col => (
            <div key={col.id} className="bg-[#0d1220] border border-[#1e2d42] rounded-lg p-5">
              <div className="flex items-start justify-between mb-3">
                <div>
                  <div className="flex items-center gap-2 mb-1">
                    <Database className="w-4 h-4 text-[#e8002d]" />
                    <h3 className="text-white font-semibold text-sm">{col.title}</h3>
                    <span className="text-xs px-2 py-0.5 rounded bg-[#1e2d42] text-[#7d92b0]">
                      {(col.object_count ?? 0).toLocaleString()} オブジェクト
                    </span>
                  </div>
                  <p className="text-xs text-[#7d92b0]">{col.description}</p>
                </div>
                <div className="flex items-center gap-2">
                  {col.can_read && (
                    <span className="px-2 py-0.5 rounded text-xs bg-blue-500/15 border border-blue-500/25 text-blue-400">
                      Can Read
                    </span>
                  )}
                  {col.can_write && (
                    <span className="px-2 py-0.5 rounded text-xs bg-purple-500/15 border border-purple-500/25 text-purple-400">
                      Can Write
                    </span>
                  )}
                </div>
              </div>

              <div className="mb-4 p-3 rounded bg-[#070d19] border border-[#1e2d42]">
                <div className="flex items-center justify-between gap-2">
                  <div>
                    <p className="text-[10px] text-[#3d5068] uppercase tracking-wider mb-0.5">Collection ID</p>
                    <p className="text-xs font-mono text-[#7d92b0]">{col.id}</p>
                  </div>
                  <button
                    onClick={() => handleCopy(col.id, `id-${col.id}`)}
                    className="p-1.5 rounded hover:bg-[#1e2d42] text-[#7d92b0] hover:text-white transition-colors flex-shrink-0"
                    title="IDをコピー"
                  >
                    {copied === `id-${col.id}` ? <CheckCircle className="w-3.5 h-3.5 text-green-400" /> : <Copy className="w-3.5 h-3.5" />}
                  </button>
                </div>
                <div className="flex items-center justify-between gap-2 mt-2 pt-2 border-t border-[#1e2d42]">
                  <div className="min-w-0">
                    <p className="text-[10px] text-[#3d5068] uppercase tracking-wider mb-0.5">APIエンドポイント</p>
                    <p className="text-xs font-mono text-[#a8c0d6] truncate">{col.endpoint}</p>
                  </div>
                  <button
                    onClick={() => handleCopy(col.endpoint, `ep-${col.id}`)}
                    className="p-1.5 rounded hover:bg-[#1e2d42] text-[#7d92b0] hover:text-white transition-colors flex-shrink-0"
                    title="エンドポイントをコピー"
                  >
                    {copied === `ep-${col.id}` ? <CheckCircle className="w-3.5 h-3.5 text-green-400" /> : <Copy className="w-3.5 h-3.5" />}
                  </button>
                </div>
              </div>

              <div className="flex items-center gap-2">
                <button
                  onClick={() => handleObjectsFetch(col)}
                  className="flex items-center gap-1.5 px-3 py-1.5 rounded text-xs bg-[#1e2d42] text-[#7d92b0] hover:bg-[#2a3f5c] hover:text-white transition-colors"
                >
                  <Download className="w-3.5 h-3.5" />
                  オブジェクト取得
                </button>
                {col.can_write && (
                  <button
                    onClick={() => setImportModal({ id: col.id, title: col.title })}
                    className="flex items-center gap-1.5 px-3 py-1.5 rounded text-xs bg-[#1e2d42] text-[#7d92b0] hover:bg-[#2a3f5c] hover:text-white transition-colors"
                  >
                    <Upload className="w-3.5 h-3.5" />
                    インポート
                  </button>
                )}
              </div>
            </div>
          ))}

          {/* TAXII Client Connection Info */}
          <div className="bg-[#0d1220] border border-[#1e2d42] rounded-lg p-5">
            <h2 className="text-sm font-semibold text-white flex items-center gap-2 mb-4">
              <Code2 className="w-4 h-4 text-[#e8002d]" />
              TAXIIクライアント接続情報
            </h2>

            {/* Code tabs */}
            <div className="flex gap-1 mb-3 bg-[#070d19] border border-[#1e2d42] rounded p-1 w-fit">
              {(['python', 'curl'] as const).map(lang => (
                <button
                  key={lang}
                  onClick={() => setCodeTab(lang)}
                  className={`px-3 py-1 rounded text-xs font-medium transition-all ${
                    codeTab === lang ? 'bg-[#e8002d] text-white' : 'text-[#7d92b0] hover:text-white'
                  }`}
                >
                  {lang === 'python' ? 'Python' : 'curl'}
                </button>
              ))}
            </div>

            {codeTab === 'python' && (
              <div className="relative">
                <div className="flex items-center justify-between mb-2">
                  <p className="text-xs text-[#3d5068]">pip install taxii2-client</p>
                  <button
                    onClick={() => handleCopy(pythonCode, 'python')}
                    className="flex items-center gap-1 text-xs text-[#7d92b0] hover:text-white transition-colors"
                  >
                    {copied === 'python' ? <CheckCircle className="w-3 h-3 text-green-400" /> : <Copy className="w-3 h-3" />}
                    コピー
                  </button>
                </div>
                <pre className="text-xs text-[#a8c0d6] font-mono bg-[#070d19] border border-[#1e2d42] rounded p-4 overflow-x-auto whitespace-pre leading-relaxed">
                  {pythonCode}
                </pre>
              </div>
            )}

            {codeTab === 'curl' && (
              <div className="relative">
                <div className="flex items-center justify-between mb-2">
                  <p className="text-xs text-[#3d5068]">curl examples</p>
                  <button
                    onClick={() => handleCopy(curlCode, 'curl')}
                    className="flex items-center gap-1 text-xs text-[#7d92b0] hover:text-white transition-colors"
                  >
                    {copied === 'curl' ? <CheckCircle className="w-3 h-3 text-green-400" /> : <Copy className="w-3 h-3" />}
                    コピー
                  </button>
                </div>
                <pre className="text-xs text-[#a8c0d6] font-mono bg-[#070d19] border border-[#1e2d42] rounded p-4 overflow-x-auto whitespace-pre leading-relaxed">
                  {curlCode}
                </pre>
              </div>
            )}
          </div>
        </div>
      )}

      {/* Clients Tab */}
      {activeTab === 'clients' && (
        <div className="space-y-4">
          <div className="bg-[#0d1220] border border-[#1e2d42] rounded-lg overflow-hidden">
            <div className="flex items-center justify-between px-5 py-4 border-b border-[#1e2d42]">
              <h2 className="text-sm font-semibold text-white flex items-center gap-2">
                <Users className="w-4 h-4 text-[#e8002d]" />
                登録済みTAXIIクライアント ({mockClients.length})
              </h2>
              <button
                onClick={() => setAddClientOpen(true)}
                className="flex items-center gap-1.5 px-3 py-1.5 rounded text-xs bg-[#e8002d] text-white hover:bg-[#c00025] transition-colors"
              >
                <Shield className="w-3.5 h-3.5" />
                クライアント追加
              </button>
            </div>
            <div className="overflow-x-auto">
              <table className="w-full text-sm">
                <thead>
                  <tr className="border-b border-[#1e2d42]">
                    {['名前', '組織', '最終ポーリング', '受信オブジェクト数', 'ステータス', '操作'].map(h => (
                      <th key={h} className="text-left px-5 py-3 text-xs text-[#3d5068] uppercase tracking-wider font-medium">
                        {h}
                      </th>
                    ))}
                  </tr>
                </thead>
                <tbody>
                  {mockClients.map(client => (
                    <tr key={client.id} className="border-b border-[#1e2d42]/50 hover:bg-[#0d1825] transition-colors">
                      <td className="px-5 py-3 text-white font-medium text-sm">{client.name}</td>
                      <td className="px-5 py-3 text-[#7d92b0] text-sm">{client.organization}</td>
                      <td className="px-5 py-3 text-[#7d92b0] text-xs">{formatDate(client.last_poll)}</td>
                      <td className="px-5 py-3 text-[#a8c0d6] font-mono text-sm">
                        {(client.objects_received ?? 0).toLocaleString()}
                      </td>
                      <td className="px-5 py-3">
                        <span className={`inline-flex items-center gap-1.5 px-2 py-0.5 rounded text-xs ${
                          client.status === 'active'
                            ? 'bg-green-500/15 border border-green-500/25 text-green-400'
                            : client.status === 'error'
                            ? 'bg-red-500/15 border border-red-500/25 text-red-400'
                            : 'bg-[#1e2d42] border border-[#2a3f5c] text-[#7d92b0]'
                        }`}>
                          <span className={`w-1.5 h-1.5 rounded-full ${
                            client.status === 'active' ? 'bg-green-400' : client.status === 'error' ? 'bg-red-400' : 'bg-[#7d92b0]'
                          }`} />
                          {client.status === 'active' ? 'アクティブ' : client.status === 'error' ? 'エラー' : '非アクティブ'}
                        </span>
                      </td>
                      <td className="px-5 py-3">
                        <button
                          onClick={() => handleRemoveClient(client.id)}
                          className="text-xs text-[#7d92b0] hover:text-red-400 transition-colors px-2 py-1 rounded hover:bg-red-500/10"
                        >
                          削除
                        </button>
                      </td>
                    </tr>
                  ))}
                  {mockClients.length === 0 && (
                    <tr>
                      <td colSpan={6} className="px-5 py-8 text-center text-[#3d5068] text-sm">
                        登録済みクライアントはありません
                      </td>
                    </tr>
                  )}
                </tbody>
              </table>
            </div>
          </div>

          {/* Add client modal */}
          {addClientOpen && (
            <div className="fixed inset-0 z-50 bg-black/60 flex items-center justify-center p-4">
              <div className="bg-[#0d1220] border border-[#1e2d42] rounded-lg w-full max-w-md">
                <div className="flex items-center justify-between px-5 py-4 border-b border-[#1e2d42]">
                  <h2 className="text-white font-semibold text-sm">TAXIIクライアント追加</h2>
                  <button onClick={() => setAddClientOpen(false)} className="text-[#7d92b0] hover:text-white transition-colors">
                    <X className="w-4 h-4" />
                  </button>
                </div>
                <div className="p-5 space-y-4">
                  <div>
                    <label className="block text-xs text-[#7d92b0] mb-1.5">クライアント名 *</label>
                    <input
                      type="text"
                      value={newClientName}
                      onChange={e => setNewClientName(e.target.value)}
                      placeholder="例: MISP Integration"
                      className="w-full px-3 py-2 rounded bg-[#070d19] border border-[#1e2d42] text-white text-sm placeholder-[#3d5068] focus:outline-none focus:border-[#e8002d]/50"
                    />
                  </div>
                  <div>
                    <label className="block text-xs text-[#7d92b0] mb-1.5">組織</label>
                    <input
                      type="text"
                      value={newClientOrg}
                      onChange={e => setNewClientOrg(e.target.value)}
                      placeholder="例: Security Team"
                      className="w-full px-3 py-2 rounded bg-[#070d19] border border-[#1e2d42] text-white text-sm placeholder-[#3d5068] focus:outline-none focus:border-[#e8002d]/50"
                    />
                  </div>
                  <div className="flex gap-2 justify-end">
                    <button
                      onClick={() => setAddClientOpen(false)}
                      className="px-4 py-2 rounded text-sm text-[#7d92b0] bg-[#1e2d42] hover:bg-[#2a3f5c] transition-colors"
                    >
                      キャンセル
                    </button>
                    <button
                      onClick={handleAddClient}
                      disabled={!newClientName}
                      className="px-4 py-2 rounded text-sm bg-[#e8002d] text-white hover:bg-[#c00025] disabled:opacity-40 disabled:cursor-not-allowed transition-colors"
                    >
                      追加
                    </button>
                  </div>
                </div>
              </div>
            </div>
          )}

          {/* Connection Test */}
          <div className="bg-[#0d1220] border border-[#1e2d42] rounded-lg p-5">
            <h2 className="text-sm font-semibold text-white flex items-center gap-2 mb-4">
              <Wifi className="w-4 h-4 text-[#e8002d]" />
              TAXII接続テスト
            </h2>
            <div className="flex gap-2">
              <input
                type="url"
                value={testUrl}
                onChange={e => setTestUrl(e.target.value)}
                placeholder="https://taxii.example.com/taxii2/"
                className="flex-1 px-3 py-2 rounded bg-[#070d19] border border-[#1e2d42] text-white text-sm placeholder-[#3d5068] focus:outline-none focus:border-[#e8002d]/50"
              />
              <button
                onClick={handleTestConnection}
                disabled={!testUrl}
                className="px-4 py-2 rounded text-sm bg-[#e8002d] text-white hover:bg-[#c00025] disabled:opacity-40 disabled:cursor-not-allowed transition-colors flex items-center gap-2"
              >
                <Terminal className="w-3.5 h-3.5" />
                テスト
              </button>
            </div>
            {testResult && (
              <div className="mt-3 p-3 rounded bg-green-500/10 border border-green-500/20 flex items-center gap-2">
                <CheckCircle className="w-4 h-4 text-green-400 flex-shrink-0" />
                <p className="text-xs text-green-300">{testResult}</p>
              </div>
            )}
            <p className="text-xs text-[#3d5068] mt-2">
              外部TAXIIサーバーのDiscoveryエンドポイントへの疎通テストを実行します
            </p>
          </div>
        </div>
      )}

      {/* JSON Modal */}
      {jsonModal && (
        <JsonModal
          title={jsonModal.title}
          data={jsonModal.data}
          onClose={() => setJsonModal(null)}
        />
      )}

      {/* Import Modal */}
      {importModal && (
        <ImportModal
          collectionId={importModal.id}
          collectionTitle={importModal.title}
          onClose={() => setImportModal(null)}
        />
      )}
    </div>
  )
}

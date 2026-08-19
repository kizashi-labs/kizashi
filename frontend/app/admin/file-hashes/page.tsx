'use client'

import { useState, useMemo } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { apiFetch } from '@/lib/api'
import {
  FileCode, Plus, Trash2, X, ExternalLink, Upload,
  ShieldOff, Shield, Zap,
} from 'lucide-react'

import { PageDataUnavailable } from '@/components/PageDataUnavailable'
import { PageSaveFailed } from '@/components/PageSaveFailed'

interface FileHashEntry {
  id: string
  hash_value: string
  hash_type: 'md5' | 'sha1' | 'sha256'
  file_name?: string
  description?: string
  list_type: 'blocklist' | 'allowlist'
  match_count: number
  created_at: string
}

interface FileHashResponse {
  data: FileHashEntry[]
  total: number
}

// ── Placeholder data ──────────────────────────────────────────────────────────
const PLACEHOLDER_ALL: FileHashResponse = {
  total: 10,
  data: [
    { id: '1', hash_value: '44d88612fea8a8f36de82e1278abb02f', hash_type: 'md5', file_name: 'eicar.com', description: 'EICARテストファイル', list_type: 'blocklist', match_count: 23, created_at: '2026-03-01T09:00:00Z' },
    { id: '2', hash_value: '3395856ce81f2b7382dee72602f798b642f14d0', hash_type: 'sha1', file_name: 'malware_dropper.exe', description: 'ドロッパーマルウェア', list_type: 'blocklist', match_count: 7, created_at: '2026-03-05T11:30:00Z' },
    { id: '3', hash_value: '275a021bbfb6489e54d471899f7db9d1663fc695e2ac4ae927dbc31a37f6a08f', hash_type: 'sha256', file_name: 'ransomware.bin', description: 'ランサムウェアペイロード', list_type: 'blocklist', match_count: 2, created_at: '2026-03-10T14:00:00Z' },
    { id: '4', hash_value: 'a3f5c2b1d9e84f726a1c3b5d7e9f2a4c', hash_type: 'md5', file_name: 'miner.exe', description: '暗号通貨マイナー', list_type: 'blocklist', match_count: 41, created_at: '2026-02-28T08:15:00Z' },
    { id: '5', hash_value: 'b4c88b2f77d1f9e9ab63a4eff5d7f6a2192c5e3b', hash_type: 'sha1', file_name: 'keylogger.dll', description: 'キーロガーDLL', list_type: 'blocklist', match_count: 5, created_at: '2026-03-12T17:45:00Z' },
    { id: '6', hash_value: 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855', hash_type: 'sha256', file_name: 'chrome.exe', description: 'Google Chrome 正規バイナリ', list_type: 'allowlist', match_count: 14320, created_at: '2026-01-10T06:00:00Z' },
    { id: '7', hash_value: 'd41d8cd98f00b204e9800998ecf8427e', hash_type: 'md5', file_name: 'svchost.exe', description: 'Windows svchost 正規', list_type: 'allowlist', match_count: 88420, created_at: '2026-01-01T00:00:00Z' },
    { id: '8', hash_value: 'da39a3ee5e6b4b0d3255bfef95601890afd80709', hash_type: 'sha1', file_name: 'notepad.exe', description: 'Windows Notepad', list_type: 'allowlist', match_count: 4523, created_at: '2026-01-01T00:00:00Z' },
    { id: '9', hash_value: 'cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce', hash_type: 'sha256', file_name: 'teams.exe', description: 'Microsoft Teams 正規バイナリ', list_type: 'allowlist', match_count: 22100, created_at: '2026-02-01T10:00:00Z' },
    { id: '10', hash_value: '9b74c9897bac770ffc029102a200c5de', hash_type: 'md5', file_name: 'psexec.exe', description: 'PsExec ツール — 要注意', list_type: 'blocklist', match_count: 3, created_at: '2026-03-15T12:00:00Z' },
  ],
}

function formatDate(iso: string) {
  try {
    return new Date(iso).toLocaleString('ja-JP', {
      year: 'numeric', month: '2-digit', day: '2-digit',
      hour: '2-digit', minute: '2-digit',
    })
  } catch { return iso }
}

function truncateHash(hash: string) {
  if (hash.length <= 16) return hash
  return hash.slice(0, 8) + '…' + hash.slice(-8)
}

const HASH_TYPE_COLORS: Record<string, string> = {
  md5: 'bg-blue-500/10 text-blue-400 border-blue-500/20',
  sha1: 'bg-purple-500/10 text-purple-400 border-purple-500/20',
  sha256: 'bg-cyan-500/10 text-cyan-400 border-cyan-500/20',
}

export default function FileHashesPage() {
  const queryClient = useQueryClient()

  const [activeTab, setActiveTab] = useState<'blocklist' | 'allowlist'>('blocklist')
  const [showAddModal, setShowAddModal] = useState(false)
  const [showBulkModal, setShowBulkModal] = useState(false)
  const [deleteConfirm, setDeleteConfirm] = useState<string | null>(null)
  const [copiedId, setCopiedId] = useState<string | null>(null)

  const [form, setForm] = useState({
    hash_value: '',
    hash_type: 'sha256' as 'md5' | 'sha1' | 'sha256',
    file_name: '',
    description: '',
    list_type: activeTab as 'blocklist' | 'allowlist',
  })

  const [bulkCsv, setBulkCsv] = useState('')

  const { data, isLoading } = useQuery<FileHashResponse>({
    queryKey: ['file-hashes'],
    queryFn: () => apiFetch('/api/v1/ioc/file-hashes'),
    placeholderData: PLACEHOLDER_ALL,
  })

  const allEntries = data?.data ?? []

  const stats = useMemo(() => ({
    allowlist: allEntries.filter(e => e.list_type === 'allowlist').length,
    blocklist: allEntries.filter(e => e.list_type === 'blocklist').length,
    recentMatches: allEntries.reduce((sum, e) => sum + e.match_count, 0),
  }), [allEntries])

  const tabEntries = useMemo(
    () => allEntries.filter(e => e.list_type === activeTab),
    [allEntries, activeTab]
  )

  const addMutation = useMutation({
    mutationFn: (body: typeof form) =>
      apiFetch('/api/v1/ioc/file-hashes', {
        method: 'POST',
        body: JSON.stringify(body),
      }),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['file-hashes'] })
      setShowAddModal(false)
      setForm({ hash_value: '', hash_type: 'sha256', file_name: '', description: '', list_type: activeTab })
    },
  })

  const deleteMutation = useMutation({
    mutationFn: (id: string) =>
      apiFetch(`/api/v1/ioc/file-hashes/${id}`, { method: 'DELETE' }),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['file-hashes'] })
      setDeleteConfirm(null)
    },
  })

  const handleBulkImport = () => {
    const lines = bulkCsv.split('\n').map(l => l.trim()).filter(Boolean)
    Promise.all(
      lines.map(line => {
        const [hash_value, hash_type = 'sha256', file_name = ''] = line.split(',').map(s => s.trim())
        return apiFetch('/api/v1/ioc/file-hashes', {
          method: 'POST',
          body: JSON.stringify({ hash_value, hash_type, file_name, list_type: activeTab }),
        })
      })
    ).then(() => {
      queryClient.invalidateQueries({ queryKey: ['file-hashes'] })
      setShowBulkModal(false)
      setBulkCsv('')
    })
  }

  const openVirusTotal = (hash: string) => {
    window.open(`https://www.virustotal.com/gui/file/${hash}`, '_blank', 'noopener,noreferrer')
  }

  const copyHash = (id: string, hash: string) => {
    navigator.clipboard.writeText(hash).then(() => {
      setCopiedId(id)
      setTimeout(() => setCopiedId(null), 1500)
    })
  }

  const openAddModal = () => {
    setForm(f => ({ ...f, list_type: activeTab }))
    setShowAddModal(true)
  }

  return (
    <div className="min-h-screen bg-[#070d19] p-6">
      <PageDataUnavailable />
      <PageSaveFailed className="mb-4" />

      {/* Header */}
      <div className="flex items-start justify-between mb-6">
        <div>
          <div className="flex items-center gap-3 mb-1">
            <div className="w-8 h-8 rounded-sm bg-[#e8002d]/10 border border-[#e8002d]/30 flex items-center justify-center">
              <FileCode className="w-4 h-4 text-[#e8002d]" />
            </div>
            <h1 className="text-xl font-bold text-white">ファイルハッシュ管理</h1>
          </div>
          <p className="text-[#7d92b0] text-sm ml-11">MD5 / SHA1 / SHA256 によるファイル許可・拒否リスト</p>
        </div>
        <div className="flex items-center gap-2">
          <button
            onClick={() => setShowBulkModal(true)}
            className="flex items-center gap-2 px-3 py-2 text-sm text-[#7d92b0] border border-[#1e2d42] rounded-sm hover:bg-[#0d1220] hover:text-white transition-colors"
          >
            <Upload className="w-4 h-4" />
            CSV インポート
          </button>
          <button
            onClick={openAddModal}
            className="flex items-center gap-2 px-4 py-2 bg-[#e8002d] hover:bg-[#c8001f] text-white text-sm font-medium rounded-sm transition-colors"
          >
            <Plus className="w-4 h-4" />
            ハッシュを追加
          </button>
        </div>
      </div>

      {/* Stats */}
      <div className="grid grid-cols-3 gap-4 mb-6">
        {[
          { label: '許可ハッシュ', value: stats.allowlist, icon: Shield, color: 'text-green-400' },
          { label: '拒否ハッシュ', value: stats.blocklist, icon: ShieldOff, color: 'text-[#e8002d]' },
          { label: '最近マッチ', value: (stats.recentMatches ?? 0).toLocaleString(), icon: Zap, color: 'text-orange-400' },
        ].map(({ label, value, icon: Icon, color }) => (
          <div key={label} className="bg-[#0d1220] border border-[#1e2d42] rounded-lg p-4 flex items-center gap-3">
            <Icon className={`w-5 h-5 shrink-0 ${color}`} />
            <div>
              <p className="text-[#7d92b0] text-xs mb-0.5">{label}</p>
              <p className="text-2xl font-bold text-white">{value}</p>
            </div>
          </div>
        ))}
      </div>

      {/* Tabs */}
      <div className="flex gap-1 mb-4 bg-[#0d1220] border border-[#1e2d42] rounded-lg p-1 w-fit">
        {(['blocklist', 'allowlist'] as const).map(tab => (
          <button
            key={tab}
            onClick={() => setActiveTab(tab)}
            className={`px-4 py-2 text-sm rounded-sm font-medium transition-colors ${
              activeTab === tab
                ? 'bg-[#e8002d] text-white'
                : 'text-[#7d92b0] hover:text-white'
            }`}
          >
            {tab === 'blocklist' ? '拒否リスト (Blocklist)' : '許可リスト (Allowlist)'}
          </button>
        ))}
      </div>

      {/* Table */}
      <div className="bg-[#0d1220] border border-[#1e2d42] rounded-lg overflow-hidden">
        <div className="px-4 py-3 border-b border-[#1e2d42] flex items-center justify-between">
          <h2 className="text-sm font-semibold text-white">
            {activeTab === 'blocklist' ? '拒否リスト' : '許可リスト'}
          </h2>
          <span className="text-xs text-[#7d92b0]">{tabEntries.length} 件</span>
        </div>

        {isLoading ? (
          <div className="p-10 text-center text-[#7d92b0] text-sm">読み込み中...</div>
        ) : tabEntries.length === 0 ? (
          <div className="p-10 text-center text-[#7d92b0] text-sm">エントリがありません</div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full">
              <thead>
                <tr className="border-b border-[#1e2d42]">
                  {['ハッシュ', 'ファイル名', '説明', 'マッチ数', '追加日', 'VirusTotal', '操作'].map(h => (
                    <th key={h} className="px-4 py-3 text-left text-xs font-medium text-[#7d92b0] uppercase tracking-wider whitespace-nowrap">
                      {h}
                    </th>
                  ))}
                </tr>
              </thead>
              <tbody className="divide-y divide-[#1e2d42]">
                {tabEntries.map(entry => (
                  <tr key={entry.id} className="hover:bg-[#0a1628] transition-colors">
                    <td className="px-4 py-3">
                      <div className="flex items-center gap-2">
                        <span
                          className={`inline-block px-1.5 py-0.5 rounded-sm text-[10px] font-medium border uppercase ${HASH_TYPE_COLORS[entry.hash_type]}`}
                        >
                          {entry.hash_type}
                        </span>
                        <button
                          onClick={() => copyHash(entry.id, entry.hash_value)}
                          className="font-mono text-xs text-[#7d92b0] hover:text-white transition-colors"
                          title={entry.hash_value}
                        >
                          {copiedId === entry.id ? (
                            <span className="text-green-400">コピー済み</span>
                          ) : (
                            truncateHash(entry.hash_value)
                          )}
                        </button>
                      </div>
                    </td>
                    <td className="px-4 py-3 text-xs text-[#e2e8f4] max-w-[140px] truncate">
                      {entry.file_name ?? <span className="text-[#3d5068]">—</span>}
                    </td>
                    <td className="px-4 py-3 text-xs text-[#7d92b0] max-w-[180px] truncate">
                      {entry.description ?? <span className="text-[#3d5068]">—</span>}
                    </td>
                    <td className="px-4 py-3">
                      <span className={`text-sm font-bold ${entry.match_count > 1000 ? 'text-[#e8002d]' : entry.match_count > 100 ? 'text-orange-400' : 'text-white'}`}>
                        {(entry.match_count ?? 0).toLocaleString()}
                      </span>
                    </td>
                    <td className="px-4 py-3 text-xs text-[#7d92b0] whitespace-nowrap">
                      {formatDate(entry.created_at)}
                    </td>
                    <td className="px-4 py-3">
                      <button
                        onClick={() => openVirusTotal(entry.hash_value)}
                        className="inline-flex items-center gap-1 px-2 py-1 rounded-sm text-xs text-[#7d92b0] hover:text-white hover:bg-[#1e2d42] transition-colors"
                        title="VirusTotalで検索"
                      >
                        <ExternalLink className="w-3 h-3" />
                        VT
                      </button>
                    </td>
                    <td className="px-4 py-3">
                      <button
                        onClick={() => setDeleteConfirm(entry.id)}
                        className="p-1.5 rounded-sm text-[#7d92b0] hover:text-[#e8002d] hover:bg-[#e8002d]/10 transition-colors"
                        title="削除"
                      >
                        <Trash2 className="w-3.5 h-3.5" />
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>

      {/* Add Modal */}
      {showAddModal && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 backdrop-blur-sm">
          <div className="bg-[#0d1220] border border-[#1e2d42] rounded-xl w-full max-w-md mx-4 shadow-2xl">
            <div className="flex items-center justify-between px-5 py-4 border-b border-[#1e2d42]">
              <h2 className="text-base font-semibold text-white flex items-center gap-2">
                <FileCode className="w-4 h-4 text-[#e8002d]" />
                ハッシュを追加
              </h2>
              <button onClick={() => setShowAddModal(false)} className="p-1 rounded-sm text-[#7d92b0] hover:text-white hover:bg-[#1e2d42] transition-colors">
                <X className="w-4 h-4" />
              </button>
            </div>
            <div className="px-5 py-4 space-y-4">
              <div>
                <label className="block text-xs font-medium text-[#7d92b0] mb-1.5">ハッシュ値 <span className="text-[#e8002d]">*</span></label>
                <input
                  type="text"
                  value={form.hash_value}
                  onChange={e => setForm(f => ({ ...f, hash_value: e.target.value }))}
                  placeholder="例: 44d88612fea8a8f36de82e1278abb02f"
                  className="w-full bg-[#070d19] border border-[#1e2d42] rounded-sm px-3 py-2 text-sm text-white placeholder-[#3d5068] focus:outline-hidden focus:border-[#e8002d]/50 font-mono"
                />
              </div>
              <div>
                <label className="block text-xs font-medium text-[#7d92b0] mb-1.5">ハッシュタイプ</label>
                <div className="flex gap-2">
                  {(['md5', 'sha1', 'sha256'] as const).map(t => (
                    <button
                      key={t}
                      onClick={() => setForm(f => ({ ...f, hash_type: t }))}
                      className={`px-3 py-1.5 rounded-sm text-xs font-medium uppercase transition-colors border ${
                        form.hash_type === t
                          ? 'bg-[#e8002d] text-white border-[#e8002d]'
                          : 'text-[#7d92b0] border-[#1e2d42] hover:border-[#7d92b0]/40 hover:text-white'
                      }`}
                    >
                      {t}
                    </button>
                  ))}
                </div>
              </div>
              <div>
                <label className="block text-xs font-medium text-[#7d92b0] mb-1.5">ファイル名</label>
                <input
                  type="text"
                  value={form.file_name}
                  onChange={e => setForm(f => ({ ...f, file_name: e.target.value }))}
                  placeholder="例: malware.exe"
                  className="w-full bg-[#070d19] border border-[#1e2d42] rounded-sm px-3 py-2 text-sm text-white placeholder-[#3d5068] focus:outline-hidden focus:border-[#e8002d]/50"
                />
              </div>
              <div>
                <label className="block text-xs font-medium text-[#7d92b0] mb-1.5">説明</label>
                <input
                  type="text"
                  value={form.description}
                  onChange={e => setForm(f => ({ ...f, description: e.target.value }))}
                  placeholder="例: ランサムウェアペイロード"
                  className="w-full bg-[#070d19] border border-[#1e2d42] rounded-sm px-3 py-2 text-sm text-white placeholder-[#3d5068] focus:outline-hidden focus:border-[#e8002d]/50"
                />
              </div>
              <div>
                <label className="block text-xs font-medium text-[#7d92b0] mb-1.5">リストタイプ</label>
                <div className="flex gap-2">
                  {(['blocklist', 'allowlist'] as const).map(t => (
                    <button
                      key={t}
                      onClick={() => setForm(f => ({ ...f, list_type: t }))}
                      className={`px-3 py-1.5 rounded-sm text-xs font-medium transition-colors border ${
                        form.list_type === t
                          ? 'bg-[#e8002d] text-white border-[#e8002d]'
                          : 'text-[#7d92b0] border-[#1e2d42] hover:border-[#7d92b0]/40 hover:text-white'
                      }`}
                    >
                      {t === 'blocklist' ? '拒否リスト' : '許可リスト'}
                    </button>
                  ))}
                </div>
              </div>
            </div>
            <div className="flex justify-end gap-3 px-5 py-4 border-t border-[#1e2d42]">
              <button
                onClick={() => setShowAddModal(false)}
                className="px-4 py-2 text-sm text-[#7d92b0] hover:text-white rounded-sm border border-[#1e2d42] transition-colors"
              >
                キャンセル
              </button>
              <button
                onClick={() => addMutation.mutate(form)}
                disabled={!form.hash_value.trim() || addMutation.isPending}
                className="px-4 py-2 text-sm bg-[#e8002d] hover:bg-[#c8001f] text-white rounded-sm font-medium transition-colors disabled:opacity-50"
              >
                {addMutation.isPending ? '追加中...' : '追加'}
              </button>
            </div>
          </div>
        </div>
      )}

      {/* Bulk CSV Modal */}
      {showBulkModal && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 backdrop-blur-sm">
          <div className="bg-[#0d1220] border border-[#1e2d42] rounded-xl w-full max-w-lg mx-4 shadow-2xl">
            <div className="flex items-center justify-between px-5 py-4 border-b border-[#1e2d42]">
              <h2 className="text-base font-semibold text-white flex items-center gap-2">
                <Upload className="w-4 h-4 text-[#e8002d]" />
                CSV インポート
              </h2>
              <button onClick={() => setShowBulkModal(false)} className="p-1 rounded-sm text-[#7d92b0] hover:text-white hover:bg-[#1e2d42] transition-colors">
                <X className="w-4 h-4" />
              </button>
            </div>
            <div className="px-5 py-4 space-y-4">
              <p className="text-xs text-[#7d92b0]">
                形式: <code className="font-mono bg-[#070d19] px-1 py-0.5 rounded-sm text-[#e2e8f4]">hash_value,hash_type,file_name</code>（hash_type・file_name は任意）
              </p>
              <textarea
                value={bulkCsv}
                onChange={e => setBulkCsv(e.target.value)}
                rows={10}
                placeholder={'44d88612fea8a8f36de82e1278abb02f,md5,eicar.com\n3395856ce81f2b7382dee72602f798b642f14d0,sha1,dropper.exe\ne3b0c44298fc1c149afbf4c8996fb924'}
                className="w-full bg-[#070d19] border border-[#1e2d42] rounded-sm px-3 py-2 text-sm text-white placeholder-[#3d5068] focus:outline-hidden focus:border-[#e8002d]/50 font-mono resize-none"
              />
              <p className="text-xs text-[#7d92b0]">
                インポート先: <span className="text-white">{activeTab === 'blocklist' ? '拒否リスト' : '許可リスト'}</span> （{bulkCsv.split('\n').filter(l => l.trim()).length} 件）
              </p>
            </div>
            <div className="flex justify-end gap-3 px-5 py-4 border-t border-[#1e2d42]">
              <button
                onClick={() => setShowBulkModal(false)}
                className="px-4 py-2 text-sm text-[#7d92b0] hover:text-white rounded-sm border border-[#1e2d42] transition-colors"
              >
                キャンセル
              </button>
              <button
                onClick={handleBulkImport}
                disabled={!bulkCsv.trim()}
                className="px-4 py-2 text-sm bg-[#e8002d] hover:bg-[#c8001f] text-white rounded-sm font-medium transition-colors disabled:opacity-50"
              >
                インポート
              </button>
            </div>
          </div>
        </div>
      )}

      {/* Delete Confirm Modal */}
      {deleteConfirm && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 backdrop-blur-sm">
          <div className="bg-[#0d1220] border border-[#1e2d42] rounded-xl w-full max-w-sm mx-4 shadow-2xl p-5">
            <h2 className="text-base font-semibold text-white mb-2">ハッシュを削除しますか？</h2>
            <p className="text-sm text-[#7d92b0] mb-5">この操作は取り消せません。</p>
            <div className="flex justify-end gap-3">
              <button
                onClick={() => setDeleteConfirm(null)}
                className="px-4 py-2 text-sm text-[#7d92b0] hover:text-white rounded-sm border border-[#1e2d42] transition-colors"
              >
                キャンセル
              </button>
              <button
                onClick={() => deleteMutation.mutate(deleteConfirm)}
                disabled={deleteMutation.isPending}
                className="px-4 py-2 text-sm bg-[#e8002d] hover:bg-[#c8001f] text-white rounded-sm font-medium transition-colors disabled:opacity-50"
              >
                {deleteMutation.isPending ? '削除中...' : '削除'}
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  )
}

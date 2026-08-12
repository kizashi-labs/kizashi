'use client'

import { useState } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import {
  Share2, Plus, Trash2, RefreshCw, Download, Upload,
  CheckCircle, XCircle, AlertTriangle, Loader2,
  Globe, Shield, Clock, BarChart3, Database, ChevronRight,
  Copy, ExternalLink, Eye,
} from 'lucide-react'
import { apiFetch } from '@/lib/api'
import { USE_MOCK, m } from '@/lib/mock'

// ─── Types ────────────────────────────────────────────────────────────────────

interface TrustGroup {
  id: string
  name: string
  description: string
  members_count: number
  tlp_level: 'WHITE' | 'GREEN' | 'AMBER' | 'RED'
  auto_share: boolean
  last_shared: string | null
}

interface TrustGroupMember {
  id: string
  name: string
  email: string
  organization: string
}

interface TAXIIPartner {
  id: string
  name: string
  url: string
  api_root: string
  collection_id: string
  auth_type: 'none' | 'basic' | 'token'
  status: 'connected' | 'error' | 'disconnected'
  last_pull: string | null
  objects_received: number
  enabled: boolean
}

interface ExportRecord {
  id: string
  filename: string
  format: 'stix' | 'csv' | 'json' | 'misp'
  objects_count: number
  date: string
  downloaded_by: string
  tlp_level: string
}

interface ImportRecord {
  id: string
  source_name: string
  format: string
  objects_imported: number
  new_count: number
  updated_count: number
  duplicate_count: number
  status: 'success' | 'partial' | 'error'
  imported_at: string
}

interface FeedHealth {
  id: string
  name: string
  last_update: string
  status: 'ok' | 'error' | 'warning'
  latency_ms: number
  error_message?: string
}

// ─── Mock Data ────────────────────────────────────────────────────────────────

const MOCK_TRUST_GROUPS: TrustGroup[] = [
  { id: 'tg1', name: 'アジアPacific ISAC', description: 'アジア太平洋地域の金融機関セクター', members_count: 18, tlp_level: 'GREEN', auto_share: true, last_shared: '2026-03-17T09:23:00Z' },
  { id: 'tg2', name: '国内金融CERT', description: '国内金融機関のCERT連携グループ', members_count: 7, tlp_level: 'AMBER', auto_share: false, last_shared: '2026-03-15T14:10:00Z' },
  { id: 'tg3', name: 'グローバル脅威共有', description: 'グローバルサイバーセキュリティ情報共有', members_count: 34, tlp_level: 'WHITE', auto_share: true, last_shared: '2026-03-18T06:00:00Z' },
]

const MOCK_PARTNERS: TAXIIPartner[] = [
  { id: 'p1', name: 'MITRE ATT&CK TAXII', url: 'https://cti-taxii.mitre.org/taxii/', api_root: 'enterprise-attack', collection_id: '95ecc380-afe9-11e4-9b6c-751b66dd541e', auth_type: 'none', status: 'connected', last_pull: '2026-03-18T05:00:00Z', objects_received: 12847, enabled: true },
  { id: 'p2', name: '政府CERT フィード', url: 'https://taxii.cert.gov.jp/taxii/', api_root: 'default', collection_id: 'cert-jp-ioc', auth_type: 'token', status: 'connected', last_pull: '2026-03-18T04:30:00Z', objects_received: 3421, enabled: true },
  { id: 'p3', name: 'FS-ISAC Intelligence', url: 'https://taxii.fsisac.com/taxii2/', api_root: 'fs-isac', collection_id: 'stix2-intelligence', auth_type: 'basic', status: 'error', last_pull: '2026-03-16T12:00:00Z', objects_received: 8102, enabled: false },
  { id: 'p4', name: 'AlienVault OTX TAXII', url: 'https://otx.alienvault.com/taxii/', api_root: 'default', collection_id: 'user-indicators', auth_type: 'token', status: 'connected', last_pull: '2026-03-18T05:45:00Z', objects_received: 45231, enabled: true },
]

const MOCK_EXPORTS: ExportRecord[] = [
  { id: 'ex1', filename: 'ioc-export-20260318.stix2', format: 'stix', objects_count: 243, date: '2026-03-18T08:00:00Z', downloaded_by: 'admin@example.com', tlp_level: 'GREEN' },
  { id: 'ex2', filename: 'malware-hashes-20260317.csv', format: 'csv', objects_count: 891, date: '2026-03-17T15:30:00Z', downloaded_by: 'analyst1@example.com', tlp_level: 'WHITE' },
  { id: 'ex3', filename: 'threat-actors-q1.json', format: 'json', objects_count: 47, date: '2026-03-16T10:15:00Z', downloaded_by: 'admin@example.com', tlp_level: 'AMBER' },
  { id: 'ex4', filename: 'c2-domains-march.misp', format: 'misp', objects_count: 312, date: '2026-03-15T09:00:00Z', downloaded_by: 'soc1@example.com', tlp_level: 'GREEN' },
  { id: 'ex5', filename: 'ioc-export-20260314.stix2', format: 'stix', objects_count: 188, date: '2026-03-14T14:00:00Z', downloaded_by: 'analyst2@example.com', tlp_level: 'GREEN' },
  { id: 'ex6', filename: 'phishing-urls-march.csv', format: 'csv', objects_count: 567, date: '2026-03-13T11:30:00Z', downloaded_by: 'admin@example.com', tlp_level: 'WHITE' },
  { id: 'ex7', filename: 'vulnerability-intel.json', format: 'json', objects_count: 73, date: '2026-03-12T09:45:00Z', downloaded_by: 'analyst1@example.com', tlp_level: 'AMBER' },
  { id: 'ex8', filename: 'apt-campaign-q1.stix2', format: 'stix', objects_count: 128, date: '2026-03-11T16:20:00Z', downloaded_by: 'admin@example.com', tlp_level: 'RED' },
  { id: 'ex9', filename: 'ransomware-iocs.csv', format: 'csv', objects_count: 445, date: '2026-03-10T08:00:00Z', downloaded_by: 'soc2@example.com', tlp_level: 'WHITE' },
  { id: 'ex10', filename: 'mitre-techniques.json', format: 'json', objects_count: 201, date: '2026-03-09T13:00:00Z', downloaded_by: 'admin@example.com', tlp_level: 'WHITE' },
]

const MOCK_IMPORTS: ImportRecord[] = [
  { id: 'im1', source_name: 'MITRE ATT&CK TAXII', format: 'STIX 2.1', objects_imported: 1243, new_count: 18, updated_count: 34, duplicate_count: 1191, status: 'success', imported_at: '2026-03-18T05:00:00Z' },
  { id: 'im2', source_name: '政府CERT フィード', format: 'STIX 2.1', objects_imported: 87, new_count: 54, updated_count: 21, duplicate_count: 12, status: 'success', imported_at: '2026-03-18T04:30:00Z' },
  { id: 'im3', source_name: 'AlienVault OTX', format: 'STIX 2.1', objects_imported: 312, new_count: 198, updated_count: 87, duplicate_count: 27, status: 'success', imported_at: '2026-03-18T03:45:00Z' },
  { id: 'im4', source_name: 'FS-ISAC Intelligence', format: 'STIX 2.0', objects_imported: 0, new_count: 0, updated_count: 0, duplicate_count: 0, status: 'error', imported_at: '2026-03-16T12:00:00Z' },
  { id: 'im5', source_name: 'アジアPacific ISAC', format: 'JSON', objects_imported: 45, new_count: 32, updated_count: 11, duplicate_count: 2, status: 'success', imported_at: '2026-03-15T14:10:00Z' },
  { id: 'im6', source_name: 'MITRE ATT&CK TAXII', format: 'STIX 2.1', objects_imported: 1198, new_count: 5, updated_count: 21, duplicate_count: 1172, status: 'success', imported_at: '2026-03-17T05:00:00Z' },
  { id: 'im7', source_name: 'Custom CSV Feed', format: 'CSV', objects_imported: 523, new_count: 401, updated_count: 88, duplicate_count: 34, status: 'partial', imported_at: '2026-03-14T11:20:00Z' },
  { id: 'im8', source_name: 'AlienVault OTX', format: 'STIX 2.1', objects_imported: 287, new_count: 156, updated_count: 92, duplicate_count: 39, status: 'success', imported_at: '2026-03-17T03:45:00Z' },
]

const MOCK_FEED_HEALTH: FeedHealth[] = [
  { id: 'fh1', name: 'MITRE ATT&CK TAXII', last_update: '2026-03-18T05:00:00Z', status: 'ok', latency_ms: 234 },
  { id: 'fh2', name: '政府CERT フィード', last_update: '2026-03-18T04:30:00Z', status: 'ok', latency_ms: 891 },
  { id: 'fh3', name: 'AlienVault OTX', last_update: '2026-03-18T03:45:00Z', status: 'ok', latency_ms: 1243 },
  { id: 'fh4', name: 'FS-ISAC Intelligence', last_update: '2026-03-16T12:00:00Z', status: 'error', latency_ms: 0, error_message: 'Authentication failed: token expired' },
  { id: 'fh5', name: 'Custom CSV Feed', last_update: '2026-03-17T11:00:00Z', status: 'warning', latency_ms: 3210, error_message: 'Slow response, some records skipped' },
]

const SAMPLE_STIX = `{
  "type": "bundle",
  "id": "bundle--fcaf-0001",
  "spec_version": "2.1",
  "objects": [
    {
      "type": "indicator",
      "id": "indicator--a441e318",
      "spec_version": "2.1",
      "name": "Malicious IP 192.0.2.1",
      "pattern_type": "stix",
      "pattern": "[ipv4-addr:value = '192.0.2.1']",
      "valid_from": "2026-03-01T00:00:00Z",
      "labels": ["malicious-activity"],
      "object_marking_refs": ["marking-definition--34098fce"]
    }
  ]
}`

// ─── TLP Badge ────────────────────────────────────────────────────────────────

function TLPBadge({ level }: { level: string }) {
  const cfg: Record<string, string> = {
    WHITE: 'bg-white/10 text-white border-white/30',
    GREEN: 'bg-[#00c853]/20 text-[#00c853] border-[#00c853]/40',
    AMBER: 'bg-yellow-500/20 text-yellow-400 border-yellow-500/40',
    RED: 'bg-[#e8002d]/20 text-[#e8002d] border-[#e8002d]/40',
  }
  return (
    <span className={`text-[10px] font-bold px-2 py-0.5 rounded border whitespace-nowrap ${cfg[level] ?? 'bg-[#1e2d42] text-[#7d92b0]'}`}>
      TLP:{level}
    </span>
  )
}

function StatusBadge({ status }: { status: string }) {
  const cfg: Record<string, { cls: string; label: string }> = {
    connected: { cls: 'bg-[#00c853]/20 text-[#00c853]', label: '接続中' },
    error: { cls: 'bg-[#e8002d]/20 text-[#e8002d]', label: 'エラー' },
    disconnected: { cls: 'bg-[#7d92b0]/20 text-[#7d92b0]', label: '切断' },
    success: { cls: 'bg-[#00c853]/20 text-[#00c853]', label: '成功' },
    partial: { cls: 'bg-yellow-500/20 text-yellow-400', label: '一部' },
    ok: { cls: 'bg-[#00c853]/20 text-[#00c853]', label: 'OK' },
    warning: { cls: 'bg-yellow-500/20 text-yellow-400', label: '警告' },
  }
  const c = cfg[status] ?? { cls: 'bg-[#1e2d42] text-[#7d92b0]', label: status }
  return (
    <span className={`text-[10px] font-bold px-2 py-0.5 rounded ${c.cls}`}>{c.label}</span>
  )
}

function FormatBadge({ fmt }: { fmt: string }) {
  const colors: Record<string, string> = {
    stix: 'bg-[#1a6bff]/20 text-[#1a6bff]',
    csv: 'bg-purple-500/20 text-purple-400',
    json: 'bg-teal-500/20 text-teal-400',
    misp: 'bg-orange-500/20 text-orange-400',
  }
  return (
    <span className={`text-[10px] font-bold px-2 py-0.5 rounded uppercase ${colors[fmt] ?? 'bg-[#1e2d42] text-[#7d92b0]'}`}>
      {fmt}
    </span>
  )
}

function Toggle({ checked, onChange }: { checked: boolean; onChange: (v: boolean) => void }) {
  return (
    <button
      onClick={() => onChange(!checked)}
      className={`relative inline-flex h-5 w-9 items-center rounded-full transition-colors ${checked ? 'bg-[#e8002d]' : 'bg-[#1e2d42]'}`}
    >
      <span className={`inline-block h-3.5 w-3.5 transform rounded-full bg-[#e2e8f4] transition-transform ${checked ? 'translate-x-4' : 'translate-x-1'}`} />
    </button>
  )
}

// ─── Tab: 共有設定 ─────────────────────────────────────────────────────────────

function SharingSettingsTab() {
  const [groups, setGroups] = useState<TrustGroup[]>(m(MOCK_TRUST_GROUPS))
  const [partners, setPartners] = useState<TAXIIPartner[]>(m(MOCK_PARTNERS))
  const [showAddGroup, setShowAddGroup] = useState(false)
  const [showAddPartner, setShowAddPartner] = useState(false)
  const [newGroup, setNewGroup] = useState({ name: '', description: '', tlp_level: 'GREEN', auto_share: false })
  const [newPartner, setNewPartner] = useState({ name: '', url: '', api_root: '', collection_id: '', auth_type: 'none', username: '', password: '', token: '' })
  const [expandedGroup, setExpandedGroup] = useState<string | null>(null)

  const handleAddGroup = () => {
    const g: TrustGroup = {
      id: `tg${Date.now()}`,
      name: newGroup.name,
      description: newGroup.description,
      members_count: 0,
      tlp_level: newGroup.tlp_level as TrustGroup['tlp_level'],
      auto_share: newGroup.auto_share,
      last_shared: null,
    }
    setGroups(prev => [...prev, g])
    setNewGroup({ name: '', description: '', tlp_level: 'GREEN', auto_share: false })
    setShowAddGroup(false)
  }

  const handleAddPartner = () => {
    const p: TAXIIPartner = {
      id: `p${Date.now()}`,
      name: newPartner.name,
      url: newPartner.url,
      api_root: newPartner.api_root,
      collection_id: newPartner.collection_id,
      auth_type: newPartner.auth_type as TAXIIPartner['auth_type'],
      status: 'disconnected',
      last_pull: null,
      objects_received: 0,
      enabled: true,
    }
    setPartners(prev => [...prev, p])
    setShowAddPartner(false)
  }

  return (
    <div className="space-y-6">

      {/* Trust Groups */}
      <div>
        <div className="flex items-center justify-between mb-3">
          <h3 className="text-white font-semibold">トラストグループ</h3>
          <button
            onClick={() => setShowAddGroup(true)}
            className="flex items-center gap-2 px-3 py-1.5 rounded-lg bg-[#e8002d] text-white text-xs hover:bg-[#c0001f] transition-colors"
          >
            <Plus className="w-3 h-3" /> グループ追加
          </button>
        </div>

        <div className="bg-[#0d1220] border border-[#1e2d42] rounded-xl overflow-hidden">
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b border-[#1e2d42] text-[#3d5068] text-xs">
                <th className="text-left px-4 py-3">グループ名</th>
                <th className="text-left px-4 py-3">メンバー数</th>
                <th className="text-left px-4 py-3">TLPレベル</th>
                <th className="text-left px-4 py-3">自動共有</th>
                <th className="text-left px-4 py-3">最終共有</th>
                <th className="px-4 py-3"></th>
              </tr>
            </thead>
            <tbody>
              {groups.map(g => (
                <>
                  <tr key={g.id} className="border-b border-[#1e2d42] last:border-0 hover:bg-[#19253d] transition-colors">
                    <td className="px-4 py-3">
                      <div>
                        <p className="text-white font-medium">{g.name}</p>
                        <p className="text-[#3d5068] text-xs mt-0.5">{g.description}</p>
                      </div>
                    </td>
                    <td className="px-4 py-3">
                      <span className="text-white">{g.members_count}</span>
                      <span className="text-[#3d5068] text-xs ml-1">名</span>
                    </td>
                    <td className="px-4 py-3"><TLPBadge level={g.tlp_level} /></td>
                    <td className="px-4 py-3">
                      <Toggle
                        checked={g.auto_share}
                        onChange={v => setGroups(prev => prev.map(x => x.id === g.id ? { ...x, auto_share: v } : x))}
                      />
                    </td>
                    <td className="px-4 py-3 text-xs text-[#7d92b0]">
                      {g.last_shared ? new Date(g.last_shared).toLocaleString('ja-JP') : '—'}
                    </td>
                    <td className="px-4 py-3">
                      <button
                        onClick={() => setExpandedGroup(expandedGroup === g.id ? null : g.id)}
                        className="text-xs px-3 py-1 rounded bg-[#1e2d42] text-[#7d92b0] hover:text-white transition-colors flex items-center gap-1"
                      >
                        メンバー <ChevronRight className={`w-3 h-3 transition-transform ${expandedGroup === g.id ? 'rotate-90' : ''}`} />
                      </button>
                    </td>
                  </tr>
                  {expandedGroup === g.id && (
                    <tr key={`${g.id}-members`} className="border-b border-[#1e2d42] bg-[#070d19]">
                      <td colSpan={6} className="px-4 py-3">
                        <div className="text-xs text-[#7d92b0] space-y-1">
                          {Array.from({ length: Math.min(g.members_count, 5) }, (_, i) => (
                            <div key={i} className="flex items-center justify-between py-1 border-b border-[#1e2d42] last:border-0">
                              <span className="text-white">member{i + 1}@organization{i + 1}.jp</span>
                              <button className="text-[#e8002d] hover:underline text-xs">削除</button>
                            </div>
                          ))}
                          {g.members_count > 5 && (
                            <p className="text-[#3d5068]">...他 {g.members_count - 5} 名</p>
                          )}
                          <button className="mt-2 flex items-center gap-1 text-[#1a6bff] hover:text-white transition-colors">
                            <Plus className="w-3 h-3" /> メンバー追加
                          </button>
                        </div>
                      </td>
                    </tr>
                  )}
                </>
              ))}
            </tbody>
          </table>
        </div>
      </div>

      {/* Add Group Modal */}
      {showAddGroup && (
        <div className="fixed inset-0 bg-black/60 flex items-center justify-center z-50">
          <div className="bg-[#0d1220] border border-[#1e2d42] rounded-xl p-6 w-[480px] space-y-4">
            <h3 className="text-white font-semibold">トラストグループ追加</h3>
            <div className="space-y-3">
              <div>
                <label className="text-xs text-[#7d92b0] block mb-1">グループ名</label>
                <input
                  className="w-full bg-[#070d19] border border-[#1e2d42] rounded-lg px-3 py-2 text-white text-sm focus:outline-none focus:border-[#1a6bff]"
                  value={newGroup.name}
                  onChange={e => setNewGroup(p => ({ ...p, name: e.target.value }))}
                  placeholder="例: 金融ISAC グループ"
                />
              </div>
              <div>
                <label className="text-xs text-[#7d92b0] block mb-1">説明</label>
                <textarea
                  className="w-full bg-[#070d19] border border-[#1e2d42] rounded-lg px-3 py-2 text-white text-sm focus:outline-none focus:border-[#1a6bff] resize-none"
                  rows={2}
                  value={newGroup.description}
                  onChange={e => setNewGroup(p => ({ ...p, description: e.target.value }))}
                />
              </div>
              <div>
                <label className="text-xs text-[#7d92b0] block mb-1">TLPレベル</label>
                <select
                  className="w-full bg-[#070d19] border border-[#1e2d42] rounded-lg px-3 py-2 text-white text-sm focus:outline-none focus:border-[#1a6bff]"
                  value={newGroup.tlp_level}
                  onChange={e => setNewGroup(p => ({ ...p, tlp_level: e.target.value }))}
                >
                  <option value="WHITE">TLP:WHITE</option>
                  <option value="GREEN">TLP:GREEN</option>
                  <option value="AMBER">TLP:AMBER</option>
                  <option value="RED">TLP:RED</option>
                </select>
              </div>
              <div className="flex items-center gap-3">
                <Toggle checked={newGroup.auto_share} onChange={v => setNewGroup(p => ({ ...p, auto_share: v }))} />
                <span className="text-sm text-[#7d92b0]">自動共有を有効にする</span>
              </div>
            </div>
            <div className="flex gap-3 pt-2">
              <button
                onClick={handleAddGroup}
                disabled={!newGroup.name}
                className="flex-1 py-2 rounded-lg bg-[#e8002d] text-white text-sm font-medium hover:bg-[#c0001f] disabled:opacity-50 transition-colors"
              >
                追加
              </button>
              <button onClick={() => setShowAddGroup(false)} className="flex-1 py-2 rounded-lg border border-[#1e2d42] text-[#7d92b0] text-sm hover:text-white transition-colors">
                キャンセル
              </button>
            </div>
          </div>
        </div>
      )}

      {/* Partner Connections */}
      <div>
        <div className="flex items-center justify-between mb-3">
          <h3 className="text-white font-semibold">TAXIIパートナー接続</h3>
          <button
            onClick={() => setShowAddPartner(true)}
            className="flex items-center gap-2 px-3 py-1.5 rounded-lg bg-[#1a6bff] text-white text-xs hover:bg-blue-600 transition-colors"
          >
            <Plus className="w-3 h-3" /> 接続追加
          </button>
        </div>

        <div className="bg-[#0d1220] border border-[#1e2d42] rounded-xl overflow-hidden">
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b border-[#1e2d42] text-[#3d5068] text-xs">
                <th className="text-left px-4 py-3">名前 / URL</th>
                <th className="text-left px-4 py-3">認証</th>
                <th className="text-left px-4 py-3">ステータス</th>
                <th className="text-right px-4 py-3">受信オブジェクト</th>
                <th className="text-left px-4 py-3">最終取得</th>
                <th className="text-left px-4 py-3">有効</th>
              </tr>
            </thead>
            <tbody>
              {partners.map(p => (
                <tr key={p.id} className="border-b border-[#1e2d42] last:border-0 hover:bg-[#19253d] transition-colors">
                  <td className="px-4 py-3">
                    <p className="text-white font-medium">{p.name}</p>
                    <p className="text-[#3d5068] text-xs font-mono mt-0.5">{p.url}</p>
                  </td>
                  <td className="px-4 py-3">
                    <span className="text-xs bg-[#1e2d42] text-[#7d92b0] px-2 py-0.5 rounded uppercase">{p.auth_type}</span>
                  </td>
                  <td className="px-4 py-3"><StatusBadge status={p.status} /></td>
                  <td className="px-4 py-3 text-right text-white font-mono text-xs">{(p.objects_received ?? 0).toLocaleString()}</td>
                  <td className="px-4 py-3 text-xs text-[#7d92b0]">
                    {p.last_pull ? new Date(p.last_pull).toLocaleString('ja-JP') : '—'}
                  </td>
                  <td className="px-4 py-3">
                    <Toggle
                      checked={p.enabled}
                      onChange={v => setPartners(prev => prev.map(x => x.id === p.id ? { ...x, enabled: v } : x))}
                    />
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>

      {/* Add Partner Modal */}
      {showAddPartner && (
        <div className="fixed inset-0 bg-black/60 flex items-center justify-center z-50">
          <div className="bg-[#0d1220] border border-[#1e2d42] rounded-xl p-6 w-[520px] space-y-4">
            <h3 className="text-white font-semibold">TAXIIサーバー接続追加</h3>
            <div className="space-y-3">
              {[
                { key: 'name', label: 'サーバー名', ph: '例: MITRE ATT&CK' },
                { key: 'url', label: 'TAXII URL', ph: 'https://taxii.example.com/taxii/' },
                { key: 'api_root', label: 'API Root', ph: 'default' },
                { key: 'collection_id', label: 'Collection ID', ph: 'collection-uuid' },
              ].map(f => (
                <div key={f.key}>
                  <label className="text-xs text-[#7d92b0] block mb-1">{f.label}</label>
                  <input
                    className="w-full bg-[#070d19] border border-[#1e2d42] rounded-lg px-3 py-2 text-white text-sm focus:outline-none focus:border-[#1a6bff]"
                    value={(newPartner as Record<string, string>)[f.key]}
                    onChange={e => setNewPartner(p => ({ ...p, [f.key]: e.target.value }))}
                    placeholder={f.ph}
                  />
                </div>
              ))}
              <div>
                <label className="text-xs text-[#7d92b0] block mb-1">認証タイプ</label>
                <select
                  className="w-full bg-[#070d19] border border-[#1e2d42] rounded-lg px-3 py-2 text-white text-sm focus:outline-none focus:border-[#1a6bff]"
                  value={newPartner.auth_type}
                  onChange={e => setNewPartner(p => ({ ...p, auth_type: e.target.value }))}
                >
                  <option value="none">なし</option>
                  <option value="basic">Basic認証</option>
                  <option value="token">トークン</option>
                </select>
              </div>
              {newPartner.auth_type === 'basic' && (
                <div className="grid grid-cols-2 gap-3">
                  <div>
                    <label className="text-xs text-[#7d92b0] block mb-1">ユーザー名</label>
                    <input className="w-full bg-[#070d19] border border-[#1e2d42] rounded-lg px-3 py-2 text-white text-sm focus:outline-none focus:border-[#1a6bff]" value={newPartner.username} onChange={e => setNewPartner(p => ({ ...p, username: e.target.value }))} />
                  </div>
                  <div>
                    <label className="text-xs text-[#7d92b0] block mb-1">パスワード</label>
                    <input type="password" className="w-full bg-[#070d19] border border-[#1e2d42] rounded-lg px-3 py-2 text-white text-sm focus:outline-none focus:border-[#1a6bff]" value={newPartner.password} onChange={e => setNewPartner(p => ({ ...p, password: e.target.value }))} />
                  </div>
                </div>
              )}
              {newPartner.auth_type === 'token' && (
                <div>
                  <label className="text-xs text-[#7d92b0] block mb-1">APIトークン</label>
                  <input type="password" className="w-full bg-[#070d19] border border-[#1e2d42] rounded-lg px-3 py-2 text-white text-sm focus:outline-none focus:border-[#1a6bff]" value={newPartner.token} onChange={e => setNewPartner(p => ({ ...p, token: e.target.value }))} />
                </div>
              )}
            </div>
            <div className="flex gap-3 pt-2">
              <button onClick={handleAddPartner} disabled={!newPartner.name || !newPartner.url} className="flex-1 py-2 rounded-lg bg-[#1a6bff] text-white text-sm font-medium hover:bg-blue-600 disabled:opacity-50 transition-colors">追加</button>
              <button onClick={() => setShowAddPartner(false)} className="flex-1 py-2 rounded-lg border border-[#1e2d42] text-[#7d92b0] text-sm hover:text-white transition-colors">キャンセル</button>
            </div>
          </div>
        </div>
      )}

      {/* Sharing Policies */}
      <div className="bg-[#0d1220] border border-[#1e2d42] rounded-xl p-5">
        <h3 className="text-white font-semibold mb-4">共有ポリシー</h3>
        <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
          <div>
            <p className="text-xs text-[#7d92b0] mb-3">アラート閾値 (自動共有)</p>
            <div className="space-y-2">
              {['Critical', 'High'].map(sev => (
                <label key={sev} className="flex items-center gap-3 cursor-pointer group">
                  <input type="checkbox" defaultChecked className="accent-[#e8002d]" />
                  <span className="text-sm text-[#7d92b0] group-hover:text-white transition-colors">{sev} アラートを自動共有</span>
                </label>
              ))}
              {['Medium', 'Low'].map(sev => (
                <label key={sev} className="flex items-center gap-3 cursor-pointer group">
                  <input type="checkbox" className="accent-[#e8002d]" />
                  <span className="text-sm text-[#7d92b0] group-hover:text-white transition-colors">{sev} アラートを自動共有</span>
                </label>
              ))}
            </div>
          </div>
          <div>
            <p className="text-xs text-[#7d92b0] mb-3">IOCタイプ (自動エクスポート)</p>
            <div className="space-y-2">
              {[
                { label: 'IPアドレス', checked: true },
                { label: 'ドメイン', checked: true },
                { label: 'ファイルハッシュ (MD5/SHA256)', checked: true },
                { label: 'URL', checked: false },
                { label: 'メールアドレス', checked: false },
                { label: 'User-Agent', checked: false },
              ].map(item => (
                <label key={item.label} className="flex items-center gap-3 cursor-pointer group">
                  <input type="checkbox" defaultChecked={item.checked} className="accent-[#1a6bff]" />
                  <span className="text-sm text-[#7d92b0] group-hover:text-white transition-colors">{item.label}</span>
                </label>
              ))}
            </div>
          </div>
        </div>
      </div>
    </div>
  )
}

// ─── Tab: エクスポート ─────────────────────────────────────────────────────────

function ExportTab() {
  const [step, setStep] = useState(1)
  const [iocTypes, setIocTypes] = useState({ ip: true, domain: true, hash: true, url: false, email: false })
  const [dateRange, setDateRange] = useState({ from: '2026-03-01', to: '2026-03-18' })
  const [format, setFormat] = useState<'stix' | 'csv' | 'json' | 'misp'>('stix')
  const [tlp, setTlp] = useState('GREEN')
  const [exporting, setExporting] = useState(false)
  const [exportDone, setExportDone] = useState(false)

  const estimatedCount = Object.values(iocTypes).filter(Boolean).length * 61

  const handleExport = () => {
    setExporting(true)
    setTimeout(() => {
      setExporting(false)
      setExportDone(true)
      setTimeout(() => { setExportDone(false); setStep(1) }, 3000)
    }, 2000)
  }

  const stepTitles = ['コンテンツ選択', 'フォーマット選択', 'TLPマーキング', 'プレビュー']

  return (
    <div className="space-y-6">

      {/* Export Wizard */}
      <div className="bg-[#0d1220] border border-[#1e2d42] rounded-xl p-6">
        <div className="flex items-center justify-between mb-6">
          <h3 className="text-white font-semibold">エクスポートウィザード</h3>
          <div className="flex items-center gap-1">
            {[1, 2, 3, 4].map(s => (
              <div key={s} className="flex items-center gap-1">
                <div
                  className={`w-7 h-7 rounded-full flex items-center justify-center text-xs font-bold cursor-pointer transition-colors ${
                    s < step ? 'bg-[#00c853] text-white' :
                    s === step ? 'bg-[#e8002d] text-white' :
                    'bg-[#1e2d42] text-[#3d5068]'
                  }`}
                  onClick={() => s < step && setStep(s)}
                >
                  {s < step ? <CheckCircle className="w-4 h-4" /> : s}
                </div>
                {s < 4 && <div className={`w-8 h-0.5 ${s < step ? 'bg-[#00c853]' : 'bg-[#1e2d42]'}`} />}
              </div>
            ))}
          </div>
        </div>

        <p className="text-xs text-[#3d5068] mb-4">ステップ {step}: {stepTitles[step - 1]}</p>

        {/* Step 1: Content */}
        {step === 1 && (
          <div className="space-y-4">
            <div>
              <p className="text-sm text-[#7d92b0] mb-3">IOCタイプを選択</p>
              <div className="grid grid-cols-3 gap-3">
                {(Object.entries(iocTypes) as [keyof typeof iocTypes, boolean][]).map(([k, v]) => {
                  const labels = { ip: 'IPアドレス', domain: 'ドメイン', hash: 'ハッシュ', url: 'URL', email: 'メール' }
                  return (
                    <label key={k} className="flex items-center gap-2 cursor-pointer">
                      <input type="checkbox" checked={v} onChange={e => setIocTypes(p => ({ ...p, [k]: e.target.checked }))} className="accent-[#e8002d]" />
                      <span className="text-sm text-[#7d92b0]">{labels[k]}</span>
                    </label>
                  )
                })}
              </div>
            </div>
            <div className="grid grid-cols-2 gap-4">
              <div>
                <label className="text-xs text-[#7d92b0] block mb-1">開始日</label>
                <input type="date" className="w-full bg-[#070d19] border border-[#1e2d42] rounded-lg px-3 py-2 text-white text-sm focus:outline-none focus:border-[#1a6bff]" value={dateRange.from} onChange={e => setDateRange(p => ({ ...p, from: e.target.value }))} />
              </div>
              <div>
                <label className="text-xs text-[#7d92b0] block mb-1">終了日</label>
                <input type="date" className="w-full bg-[#070d19] border border-[#1e2d42] rounded-lg px-3 py-2 text-white text-sm focus:outline-none focus:border-[#1a6bff]" value={dateRange.to} onChange={e => setDateRange(p => ({ ...p, to: e.target.value }))} />
              </div>
            </div>
            <p className="text-xs text-[#3d5068]">推定オブジェクト数: <span className="text-white font-bold">{estimatedCount}</span></p>
          </div>
        )}

        {/* Step 2: Format */}
        {step === 2 && (
          <div className="grid grid-cols-2 gap-4">
            {(['stix', 'csv', 'json', 'misp'] as const).map(f => {
              const labels = { stix: 'STIX 2.1 Bundle', csv: 'CSV形式', json: 'JSON形式', misp: 'MISP形式' }
              const descs = { stix: '標準STIX/TAXII互換', csv: 'スプレッドシート向け', json: 'REST API向け', misp: 'MISP連携向け' }
              return (
                <button
                  key={f}
                  onClick={() => setFormat(f)}
                  className={`p-4 rounded-lg border text-left transition-all ${format === f ? 'border-[#e8002d] bg-[#e8002d]/10' : 'border-[#1e2d42] hover:border-[#7d92b0]/40'}`}
                >
                  <FormatBadge fmt={f} />
                  <p className="text-white font-medium mt-2 text-sm">{labels[f]}</p>
                  <p className="text-[#3d5068] text-xs mt-1">{descs[f]}</p>
                </button>
              )
            })}
          </div>
        )}

        {/* Step 3: TLP */}
        {step === 3 && (
          <div className="space-y-3">
            {(['WHITE', 'GREEN', 'AMBER', 'RED'] as const).map(t => {
              const descs: Record<string, string> = {
                WHITE: '無制限共有可能',
                GREEN: 'コミュニティ内共有',
                AMBER: '組織内・必要者のみ',
                RED: '指定受信者のみ',
              }
              return (
                <button
                  key={t}
                  onClick={() => setTlp(t)}
                  className={`w-full p-3 rounded-lg border text-left flex items-center gap-3 transition-all ${tlp === t ? 'border-[#e8002d] bg-[#e8002d]/5' : 'border-[#1e2d42] hover:border-[#7d92b0]/40'}`}
                >
                  <TLPBadge level={t} />
                  <span className="text-sm text-[#7d92b0]">{descs[t]}</span>
                  {tlp === t && <CheckCircle className="w-4 h-4 text-[#e8002d] ml-auto" />}
                </button>
              )
            })}
          </div>
        )}

        {/* Step 4: Preview */}
        {step === 4 && (
          <div className="space-y-4">
            <div className="grid grid-cols-3 gap-4 text-sm">
              <div className="bg-[#070d19] rounded-lg p-3 border border-[#1e2d42]">
                <p className="text-[#3d5068] text-xs">推定オブジェクト数</p>
                <p className="text-white font-bold text-xl mt-1">{estimatedCount}</p>
              </div>
              <div className="bg-[#070d19] rounded-lg p-3 border border-[#1e2d42]">
                <p className="text-[#3d5068] text-xs">フォーマット</p>
                <div className="mt-1"><FormatBadge fmt={format} /></div>
              </div>
              <div className="bg-[#070d19] rounded-lg p-3 border border-[#1e2d42]">
                <p className="text-[#3d5068] text-xs">TLPマーキング</p>
                <div className="mt-1"><TLPBadge level={tlp} /></div>
              </div>
            </div>
            {format === 'stix' && (
              <div>
                <p className="text-xs text-[#7d92b0] mb-2">サンプル STIX オブジェクト</p>
                <pre className="bg-[#070d19] border border-[#1e2d42] rounded-lg p-3 text-xs text-[#00c853] font-mono overflow-auto max-h-48">
                  {SAMPLE_STIX}
                </pre>
              </div>
            )}
            {exportDone ? (
              <div className="flex items-center gap-2 p-3 rounded-lg bg-[#00c853]/10 border border-[#00c853]/30 text-[#00c853]">
                <CheckCircle className="w-4 h-4" />
                <span className="text-sm font-medium">エクスポート完了: {estimatedCount}件のオブジェクト</span>
              </div>
            ) : (
              <button
                onClick={handleExport}
                disabled={exporting}
                className="w-full py-3 rounded-lg bg-[#e8002d] text-white font-medium hover:bg-[#c0001f] disabled:opacity-60 transition-colors flex items-center justify-center gap-2"
              >
                {exporting ? <><Loader2 className="w-4 h-4 animate-spin" /> エクスポート中...</> : <><Download className="w-4 h-4" /> エクスポート実行</>}
              </button>
            )}
          </div>
        )}

        <div className="flex gap-3 mt-6">
          {step > 1 && (
            <button onClick={() => setStep(s => s - 1)} className="px-4 py-2 rounded-lg border border-[#1e2d42] text-[#7d92b0] text-sm hover:text-white transition-colors">
              戻る
            </button>
          )}
          {step < 4 && (
            <button onClick={() => setStep(s => s + 1)} className="px-4 py-2 rounded-lg bg-[#1a6bff] text-white text-sm font-medium hover:bg-blue-600 transition-colors ml-auto">
              次へ
            </button>
          )}
        </div>
      </div>

      {/* Statistics */}
      <div className="grid grid-cols-2 gap-4">
        <div className="bg-[#0d1220] border border-[#1e2d42] rounded-xl p-4 flex items-center gap-4">
          <div className="w-10 h-10 rounded-lg bg-[#1a6bff]/10 flex items-center justify-center">
            <Share2 className="w-5 h-5 text-[#1a6bff]" />
          </div>
          <div>
            <p className="text-[#7d92b0] text-xs">今月の共有オブジェクト</p>
            <p className="text-white font-bold text-2xl">2,847</p>
          </div>
        </div>
        <div className="bg-[#0d1220] border border-[#1e2d42] rounded-xl p-4 flex items-center gap-4">
          <div className="w-10 h-10 rounded-lg bg-[#00c853]/10 flex items-center justify-center">
            <Download className="w-5 h-5 text-[#00c853]" />
          </div>
          <div>
            <p className="text-[#7d92b0] text-xs">消費パートナーフィード</p>
            <p className="text-white font-bold text-2xl">69,601</p>
          </div>
        </div>
      </div>

      {/* Recent Exports */}
      <div>
        <h3 className="text-white font-semibold mb-3">最近のエクスポート</h3>
        <div className="bg-[#0d1220] border border-[#1e2d42] rounded-xl overflow-hidden">
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b border-[#1e2d42] text-[#3d5068] text-xs">
                <th className="text-left px-4 py-3">ファイル名</th>
                <th className="text-left px-4 py-3">フォーマット</th>
                <th className="text-right px-4 py-3">オブジェクト数</th>
                <th className="text-left px-4 py-3">TLP</th>
                <th className="text-left px-4 py-3">日時</th>
                <th className="text-left px-4 py-3">実行者</th>
              </tr>
            </thead>
            <tbody>
              {m(MOCK_EXPORTS).map(ex => (
                <tr key={ex.id} className="border-b border-[#1e2d42] last:border-0 hover:bg-[#19253d] transition-colors">
                  <td className="px-4 py-3">
                    <span className="text-[#1a6bff] font-mono text-xs hover:underline cursor-pointer">{ex.filename}</span>
                  </td>
                  <td className="px-4 py-3"><FormatBadge fmt={ex.format} /></td>
                  <td className="px-4 py-3 text-right text-white font-mono">{(ex.objects_count ?? 0).toLocaleString()}</td>
                  <td className="px-4 py-3"><TLPBadge level={ex.tlp_level} /></td>
                  <td className="px-4 py-3 text-xs text-[#7d92b0]">{new Date(ex.date).toLocaleString('ja-JP')}</td>
                  <td className="px-4 py-3 text-xs text-[#7d92b0]">{ex.downloaded_by}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  )
}

// ─── Tab: インポートログ ───────────────────────────────────────────────────────

function ImportLogTab() {
  return (
    <div className="space-y-6">

      {/* Enrichment Stats */}
      <div className="grid grid-cols-3 gap-4">
        <div className="bg-[#0d1220] border border-[#1e2d42] rounded-xl p-4 flex items-center gap-4">
          <div className="w-10 h-10 rounded-lg bg-[#e8002d]/10 flex items-center justify-center">
            <Shield className="w-5 h-5 text-[#e8002d]" />
          </div>
          <div>
            <p className="text-[#7d92b0] text-xs">TI強化されたアラート (今月)</p>
            <p className="text-white font-bold text-2xl">1,482</p>
          </div>
        </div>
        <div className="bg-[#0d1220] border border-[#1e2d42] rounded-xl p-4 flex items-center gap-4">
          <div className="w-10 h-10 rounded-lg bg-[#1a6bff]/10 flex items-center justify-center">
            <Database className="w-5 h-5 text-[#1a6bff]" />
          </div>
          <div>
            <p className="text-[#7d92b0] text-xs">インポートオブジェクト総数</p>
            <p className="text-white font-bold text-2xl">69,601</p>
          </div>
        </div>
        <div className="bg-[#0d1220] border border-[#1e2d42] rounded-xl p-4 flex items-center gap-4">
          <div className="w-10 h-10 rounded-lg bg-[#00c853]/10 flex items-center justify-center">
            <CheckCircle className="w-5 h-5 text-[#00c853]" />
          </div>
          <div>
            <p className="text-[#7d92b0] text-xs">アクティブフィード数</p>
            <p className="text-white font-bold text-2xl">4</p>
          </div>
        </div>
      </div>

      {/* Import History */}
      <div>
        <h3 className="text-white font-semibold mb-3">インポート履歴</h3>
        <div className="bg-[#0d1220] border border-[#1e2d42] rounded-xl overflow-hidden">
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b border-[#1e2d42] text-[#3d5068] text-xs">
                <th className="text-left px-4 py-3">ソース</th>
                <th className="text-left px-4 py-3">フォーマット</th>
                <th className="text-right px-4 py-3">インポート数</th>
                <th className="text-right px-4 py-3">新規</th>
                <th className="text-right px-4 py-3">更新</th>
                <th className="text-right px-4 py-3">重複</th>
                <th className="text-left px-4 py-3">ステータス</th>
                <th className="text-left px-4 py-3">日時</th>
              </tr>
            </thead>
            <tbody>
              {m(MOCK_IMPORTS).map(im => (
                <tr key={im.id} className="border-b border-[#1e2d42] last:border-0 hover:bg-[#19253d] transition-colors">
                  <td className="px-4 py-3 text-white font-medium">{im.source_name}</td>
                  <td className="px-4 py-3">
                    <span className="text-xs bg-[#1e2d42] text-[#7d92b0] px-2 py-0.5 rounded">{im.format}</span>
                  </td>
                  <td className="px-4 py-3 text-right text-white font-mono">{(im.objects_imported ?? 0).toLocaleString()}</td>
                  <td className="px-4 py-3 text-right text-[#00c853] font-mono">{im.new_count}</td>
                  <td className="px-4 py-3 text-right text-[#1a6bff] font-mono">{im.updated_count}</td>
                  <td className="px-4 py-3 text-right text-[#3d5068] font-mono">{im.duplicate_count}</td>
                  <td className="px-4 py-3"><StatusBadge status={im.status} /></td>
                  <td className="px-4 py-3 text-xs text-[#7d92b0]">{new Date(im.imported_at).toLocaleString('ja-JP')}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>

      {/* Feed Health */}
      <div>
        <h3 className="text-white font-semibold mb-3">フィードヘルス</h3>
        <div className="bg-[#0d1220] border border-[#1e2d42] rounded-xl overflow-hidden">
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b border-[#1e2d42] text-[#3d5068] text-xs">
                <th className="text-left px-4 py-3">フィード名</th>
                <th className="text-left px-4 py-3">最終更新</th>
                <th className="text-left px-4 py-3">ステータス</th>
                <th className="text-right px-4 py-3">レイテンシ</th>
                <th className="text-left px-4 py-3">詳細</th>
              </tr>
            </thead>
            <tbody>
              {m(MOCK_FEED_HEALTH).map(f => (
                <tr key={f.id} className={`border-b border-[#1e2d42] last:border-0 hover:bg-[#19253d] transition-colors ${f.status === 'error' ? 'bg-[#e8002d]/5' : ''}`}>
                  <td className="px-4 py-3 text-white font-medium">{f.name}</td>
                  <td className="px-4 py-3 text-xs text-[#7d92b0]">{new Date(f.last_update).toLocaleString('ja-JP')}</td>
                  <td className="px-4 py-3"><StatusBadge status={f.status} /></td>
                  <td className="px-4 py-3 text-right">
                    {f.status === 'error' ? (
                      <span className="text-[#e8002d] text-xs">—</span>
                    ) : (
                      <span className={`text-xs font-mono ${f.latency_ms > 2000 ? 'text-[#ff9800]' : 'text-[#00c853]'}`}>
                        {f.latency_ms}ms
                      </span>
                    )}
                  </td>
                  <td className="px-4 py-3 text-xs text-[#7d92b0]">
                    {f.error_message ?? '—'}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  )
}

// ─── Main Page ────────────────────────────────────────────────────────────────

export default function ThreatIntelSharingPage() {
  const [activeTab, setActiveTab] = useState<'settings' | 'export' | 'import'>('settings')

  const tabs = [
    { id: 'settings' as const, label: '共有設定' },
    { id: 'export' as const, label: 'エクスポート' },
    { id: 'import' as const, label: 'インポートログ' },
  ]

  return (
    <div className="min-h-screen bg-[#070d19] text-[#7d92b0]">
      {/* Header */}
      <div className="border-b border-[#1e2d42] bg-[#0d1220] px-6 py-4">
        <div className="flex items-center gap-3">
          <div className="w-9 h-9 rounded-lg bg-gradient-to-br from-[#1a6bff] to-[#0044cc] flex items-center justify-center">
            <Share2 className="w-5 h-5 text-white" />
          </div>
          <div>
            <h1 className="text-xl font-bold text-white">脅威インテリジェンス共有</h1>
            <p className="text-xs text-[#3d5068] mt-0.5">STIX/TAXII — 信頼グループ・パートナー接続・エクスポート管理</p>
          </div>
        </div>
      </div>

      {/* Tabs */}
      <div className="border-b border-[#1e2d42] bg-[#0d1220] px-6">
        <div className="flex gap-0">
          {tabs.map(t => (
            <button
              key={t.id}
              onClick={() => setActiveTab(t.id)}
              className={`px-5 py-3 text-sm font-medium border-b-2 transition-all ${
                activeTab === t.id
                  ? 'border-[#e8002d] text-white'
                  : 'border-transparent text-[#7d92b0] hover:text-[#e2e8f4] hover:border-[#1e2d42]'
              }`}
            >
              {t.label}
            </button>
          ))}
        </div>
      </div>

      {/* Content */}
      <div className="p-6">
        {activeTab === 'settings' && <SharingSettingsTab />}
        {activeTab === 'export' && <ExportTab />}
        {activeTab === 'import' && <ImportLogTab />}
      </div>
    </div>
  )
}

'use client'

import { useState } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { apiFetch } from '@/lib/api'
import { Plus, X, Shield, AlertTriangle, Zap, Eye } from 'lucide-react'

// ── Types ──────────────────────────────────────────────────────────────────────

type AssetType = 'honeypot' | 'honeytoken' | 'honeyfile' | 'honeycred'
type AssetStatus = 'active' | 'triggered' | 'inactive'

interface DeceptionAsset {
  id: string
  name: string
  type: AssetType
  emulated_service: string
  port: number
  status: AssetStatus
  trigger_count: number
  alert_on_access: boolean
  last_triggered: string | null
  created_at: string
}

interface DeceptionEvent {
  id: string
  asset_name: string
  attacker_ip: string
  event_type: string
  alert_generated: boolean
  timestamp: string
}

interface DeceptionStats {
  total_assets: number
  active: number
  triggered: number
  total_events: number
}

interface DeployForm {
  name: string
  type: AssetType
  emulated_service: string
  listen_port: string
  alert_on_access: boolean
}

// ── Helpers ────────────────────────────────────────────────────────────────────

const TYPE_BADGE: Record<AssetType, string> = {
  honeypot: 'bg-red-500/20 text-red-400',
  honeytoken: 'bg-orange-500/20 text-orange-400',
  honeyfile: 'bg-yellow-500/20 text-yellow-400',
  honeycred: 'bg-purple-500/20 text-purple-400',
}

function formatDate(ts: string | null) {
  if (!ts) return '—'
  return new Date(ts).toLocaleString()
}

// ── Main Component ─────────────────────────────────────────────────────────────

export default function DeceptionTechnologyPage() {
  const queryClient = useQueryClient()
  const [activeTab, setActiveTab] = useState<'assets' | 'events'>('assets')
  const [showDeployModal, setShowDeployModal] = useState(false)
  const [deployForm, setDeployForm] = useState<DeployForm>({
    name: '', type: 'honeypot', emulated_service: '', listen_port: '', alert_on_access: true,
  })

  // ── Queries ──────────────────────────────────────────────────────────────────

  const { data: stats, isLoading: statsLoading } = useQuery<DeceptionStats>({
    queryKey: ['deception-stats'],
    queryFn: () => apiFetch<DeceptionStats>('/api/v1/admin/deception/stats').catch(() => ({ total_assets: 0, active: 0, triggered: 0, total_events: 0 } as DeceptionStats)),
  })

  const { data: assetsData, isLoading: assetsLoading } = useQuery<{ assets: DeceptionAsset[] }>({
    queryKey: ['deception-assets'],
    queryFn: () => apiFetch<{ assets: DeceptionAsset[] }>('/api/v1/admin/deception/assets').catch(() => ({ assets: [] })),
  })

  const { data: eventsData, isLoading: eventsLoading } = useQuery<{ events: DeceptionEvent[] }>({
    queryKey: ['deception-events'],
    queryFn: () => apiFetch<{ events: DeceptionEvent[] }>('/api/v1/admin/deception/events').catch(() => ({ events: [] })),
  })

  const deployMutation = useMutation({
    mutationFn: (data: DeployForm) =>
      apiFetch('/api/v1/admin/deception/assets', {
        method: 'POST',
        body: JSON.stringify({
          ...data,
          listen_port: Number(data.listen_port),
        }),
      }),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['deception-assets'] })
      queryClient.invalidateQueries({ queryKey: ['deception-stats'] })
      setShowDeployModal(false)
      setDeployForm({ name: '', type: 'honeypot', emulated_service: '', listen_port: '', alert_on_access: true })
    },
  })

  const toggleMutation = useMutation({
    mutationFn: ({ id, status }: { id: string; status: AssetStatus }) =>
      apiFetch(`/api/v1/admin/deception/assets/${id}`, {
        method: 'PATCH',
        body: JSON.stringify({ status }),
      }),
    onSuccess: () => queryClient.invalidateQueries({ queryKey: ['deception-assets'] }),
  })

  // ── Render ───────────────────────────────────────────────────────────────────

  const intrusions24h = eventsData?.events.filter((e) => {
    const ts = new Date(e.timestamp).getTime()
    return Date.now() - ts < 86_400_000
  }).length ?? 0

  return (
    <div className="min-h-screen bg-[#070d19] text-white p-6">
      {/* Header */}
      <div className="flex items-center justify-between mb-6">
        <div>
          <h1 className="text-2xl font-bold flex items-center gap-2">
            <Shield className="w-7 h-7 text-falcon-red" />
            Deception Technology
          </h1>
          <p className="text-falcon-muted text-sm mt-0.5">Honeypots &amp; Honeytokens</p>
        </div>
        <button
          onClick={() => setShowDeployModal(true)}
          className="flex items-center gap-2 px-4 py-2 bg-falcon-red hover:bg-[#c0001f] rounded-lg text-sm font-medium transition-colors"
        >
          <Plus className="w-4 h-4" /> Deploy Asset
        </button>
      </div>

      {/* Stats Row */}
      <div className="grid grid-cols-4 gap-4 mb-5">
        {[
          { label: 'Total Assets', value: stats?.total_assets ?? 0, color: 'text-white' },
          { label: 'Active', value: stats?.active ?? 0, color: 'text-green-400' },
          { label: 'Triggered', value: stats?.triggered ?? 0, color: 'text-orange-400' },
          { label: 'Total Events', value: stats?.total_events ?? 0, color: 'text-red-400' },
        ].map((s) => (
          <div key={s.label} className="bg-falcon-surface border border-falcon-border rounded-xl p-4">
            <p className="text-falcon-muted text-xs mb-1">{s.label}</p>
            <p className={`text-2xl font-bold ${s.color}`}>{statsLoading ? '…' : s.value}</p>
          </div>
        ))}
      </div>

      {/* Threat Intelligence Banner */}
      <div className="mb-5 bg-red-900/20 border border-red-500/40 rounded-xl px-4 py-3 flex items-center gap-3">
        <AlertTriangle className="w-5 h-5 text-red-400 shrink-0" />
        <p className="text-sm">
          <span className="text-red-400 font-bold">{intrusions24h} intrusion attempt{intrusions24h !== 1 ? 's' : ''}</span>
          <span className="text-falcon-muted"> detected in last 24h across your deception assets</span>
        </p>
        <Zap className="w-4 h-4 text-orange-400 ml-auto shrink-0" />
      </div>

      {/* Tabs */}
      <div className="flex gap-1 mb-4 bg-falcon-surface border border-falcon-border rounded-xl p-1 w-fit">
        {(['assets', 'events'] as const).map((tab) => (
          <button
            key={tab}
            onClick={() => setActiveTab(tab)}
            className={`px-4 py-2 rounded-lg text-sm font-medium capitalize transition-colors ${
              activeTab === tab ? 'bg-falcon-red text-white' : 'text-falcon-muted hover:text-white'
            }`}
          >
            {tab === 'assets' ? 'Deception Assets' : 'Triggered Events'}
          </button>
        ))}
      </div>

      {/* Assets Tab */}
      {activeTab === 'assets' && (
        <div className="bg-falcon-surface border border-falcon-border rounded-xl overflow-hidden">
          {assetsLoading ? (
            <div className="p-8 text-center text-falcon-muted">Loading assets…</div>
          ) : (
            <div className="overflow-x-auto">
              <table className="w-full text-sm">
                <thead>
                  <tr className="border-b border-falcon-border">
                    {['Name', 'Type', 'Emulated Service', 'Port', 'Status', 'Triggers', 'Alert', 'Last Triggered', 'Actions'].map((h) => (
                      <th key={h} className="text-left text-falcon-muted font-medium px-4 py-3 text-xs whitespace-nowrap">{h}</th>
                    ))}
                  </tr>
                </thead>
                <tbody>
                  {(assetsData?.assets ?? []).map((asset) => (
                    <tr key={asset.id} className="border-b border-falcon-border last:border-0 hover:bg-falcon-card">
                      <td className="px-4 py-3 text-white font-medium">{asset.name}</td>
                      <td className="px-4 py-3">
                        <span className={`px-2 py-0.5 rounded-sm text-xs font-medium capitalize ${TYPE_BADGE[asset.type]}`}>
                          {asset.type}
                        </span>
                      </td>
                      <td className="px-4 py-3 text-falcon-muted">{asset.emulated_service}</td>
                      <td className="px-4 py-3 text-falcon-muted font-mono text-xs">{asset.port || '—'}</td>
                      <td className="px-4 py-3">
                        <div className="flex items-center gap-2">
                          <span className={`w-2 h-2 rounded-full ${
                            asset.status === 'active' ? 'bg-green-500 animate-pulse' :
                            asset.status === 'triggered' ? 'bg-red-500' : 'bg-gray-500'
                          }`} />
                          <span className={`text-xs capitalize ${
                            asset.status === 'active' ? 'text-green-400' :
                            asset.status === 'triggered' ? 'text-red-400' : 'text-falcon-muted'
                          }`}>{asset.status}</span>
                        </div>
                      </td>
                      <td className="px-4 py-3 text-white text-center">{asset.trigger_count}</td>
                      <td className="px-4 py-3">
                        {asset.alert_on_access ? (
                          <span className="px-2 py-0.5 rounded-sm text-xs bg-green-500/20 text-green-400">Yes</span>
                        ) : (
                          <span className="px-2 py-0.5 rounded-sm text-xs bg-gray-500/20 text-falcon-muted">No</span>
                        )}
                      </td>
                      <td className="px-4 py-3 text-falcon-muted text-xs whitespace-nowrap">{formatDate(asset.last_triggered)}</td>
                      <td className="px-4 py-3">
                        <button
                          onClick={() =>
                            toggleMutation.mutate({
                              id: asset.id,
                              status: asset.status === 'active' ? 'inactive' : 'active',
                            })
                          }
                          className={`px-3 py-1 rounded text-xs font-medium transition-colors ${
                            asset.status === 'active'
                              ? 'bg-gray-500/20 text-falcon-muted hover:bg-gray-500/40'
                              : 'bg-green-500/20 text-green-400 hover:bg-green-500/40'
                          }`}
                        >
                          {asset.status === 'active' ? 'Deactivate' : 'Activate'}
                        </button>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </div>
      )}

      {/* Events Tab */}
      {activeTab === 'events' && (
        <div className="bg-falcon-surface border border-falcon-border rounded-xl overflow-hidden">
          {eventsLoading ? (
            <div className="p-8 text-center text-falcon-muted">Loading events…</div>
          ) : (
            <div className="overflow-x-auto">
              <table className="w-full text-sm">
                <thead>
                  <tr className="border-b border-falcon-border">
                    {['Asset Name', 'Attacker IP', 'Event Type', 'Alert Generated', 'Timestamp'].map((h) => (
                      <th key={h} className="text-left text-falcon-muted font-medium px-4 py-3 text-xs">{h}</th>
                    ))}
                  </tr>
                </thead>
                <tbody>
                  {(eventsData?.events ?? []).map((ev) => (
                    <tr key={ev.id} className="border-b border-falcon-border last:border-0 hover:bg-falcon-card">
                      <td className="px-4 py-3 text-white font-medium">{ev.asset_name}</td>
                      <td className="px-4 py-3 text-falcon-muted font-mono text-xs">{ev.attacker_ip}</td>
                      <td className="px-4 py-3">
                        <span className="px-2 py-0.5 rounded-sm text-xs bg-orange-500/20 text-orange-400">{ev.event_type}</span>
                      </td>
                      <td className="px-4 py-3">
                        {ev.alert_generated ? (
                          <span className="px-2 py-0.5 rounded-sm text-xs bg-red-500/20 text-red-400">Yes</span>
                        ) : (
                          <span className="px-2 py-0.5 rounded-sm text-xs bg-gray-500/20 text-falcon-muted">No</span>
                        )}
                      </td>
                      <td className="px-4 py-3 text-falcon-muted text-xs">{formatDate(ev.timestamp)}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </div>
      )}

      {/* Deploy Modal */}
      {showDeployModal && (
        <div className="fixed inset-0 bg-black/60 flex items-center justify-center z-50 p-4">
          <div className="bg-falcon-surface border border-falcon-border rounded-2xl w-full max-w-md">
            <div className="flex items-center justify-between px-6 py-4 border-b border-falcon-border">
              <h2 className="text-white font-semibold flex items-center gap-2">
                <Eye className="w-5 h-5 text-falcon-red" /> Deploy Deception Asset
              </h2>
              <button onClick={() => setShowDeployModal(false)} className="text-falcon-muted hover:text-white">
                <X className="w-5 h-5" />
              </button>
            </div>
            <div className="px-6 py-4 space-y-4">
              <div>
                <label className="block text-falcon-muted text-xs mb-1">Name</label>
                <input
                  value={deployForm.name}
                  onChange={(e) => setDeployForm((f) => ({ ...f, name: e.target.value }))}
                  placeholder="e.g. FakePayroll-DB"
                  className="w-full bg-[#070d19] border border-falcon-border rounded-lg px-3 py-2 text-white text-sm focus:outline-hidden focus:border-falcon-red"
                />
              </div>
              <div className="grid grid-cols-2 gap-3">
                <div>
                  <label className="block text-falcon-muted text-xs mb-1">Type</label>
                  <select
                    value={deployForm.type}
                    onChange={(e) => setDeployForm((f) => ({ ...f, type: e.target.value as AssetType }))}
                    className="w-full bg-[#070d19] border border-falcon-border rounded-lg px-3 py-2 text-white text-sm focus:outline-hidden focus:border-falcon-red"
                  >
                    {(['honeypot', 'honeytoken', 'honeyfile', 'honeycred'] as AssetType[]).map((t) => (
                      <option key={t} value={t}>{t}</option>
                    ))}
                  </select>
                </div>
                <div>
                  <label className="block text-falcon-muted text-xs mb-1">Listen Port</label>
                  <input
                    value={deployForm.listen_port}
                    onChange={(e) => setDeployForm((f) => ({ ...f, listen_port: e.target.value }))}
                    placeholder="e.g. 8080"
                    type="number"
                    className="w-full bg-[#070d19] border border-falcon-border rounded-lg px-3 py-2 text-white text-sm focus:outline-hidden focus:border-falcon-red"
                  />
                </div>
              </div>
              <div>
                <label className="block text-falcon-muted text-xs mb-1">Emulated Service</label>
                <input
                  value={deployForm.emulated_service}
                  onChange={(e) => setDeployForm((f) => ({ ...f, emulated_service: e.target.value }))}
                  placeholder="e.g. MySQL, SMB Share, LDAP"
                  className="w-full bg-[#070d19] border border-falcon-border rounded-lg px-3 py-2 text-white text-sm focus:outline-hidden focus:border-falcon-red"
                />
              </div>
              <div className="flex items-center justify-between bg-[#070d19] border border-falcon-border rounded-lg px-3 py-2">
                <span className="text-falcon-muted text-sm">Alert on Access</span>
                <button
                  onClick={() => setDeployForm((f) => ({ ...f, alert_on_access: !f.alert_on_access }))}
                  className={`relative w-10 h-5 rounded-full transition-colors ${deployForm.alert_on_access ? 'bg-falcon-red' : 'bg-falcon-border'}`}
                >
                  <span className={`absolute top-0.5 w-4 h-4 rounded-full bg-falcon-text transition-transform ${deployForm.alert_on_access ? 'translate-x-5' : 'translate-x-0.5'}`} />
                </button>
              </div>
            </div>
            <div className="px-6 py-4 border-t border-falcon-border flex gap-3 justify-end">
              <button
                onClick={() => setShowDeployModal(false)}
                className="px-4 py-2 rounded-lg border border-falcon-border text-falcon-muted hover:text-white text-sm transition-colors"
              >
                Cancel
              </button>
              <button
                onClick={() => deployMutation.mutate(deployForm)}
                disabled={!deployForm.name || !deployForm.emulated_service || deployMutation.isPending}
                className="px-4 py-2 rounded-lg bg-falcon-red hover:bg-[#c0001f] disabled:opacity-50 disabled:cursor-not-allowed text-white text-sm font-medium transition-colors"
              >
                {deployMutation.isPending ? 'Deploying…' : 'Deploy Asset'}
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  )
}

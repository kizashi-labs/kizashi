'use client'



import { useState } from 'react'

import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'

import { apiFetch } from '@/lib/api'

import {

  ShieldOff, Shield, CheckCircle, Clock, Plus, X, RefreshCw,

  Wifi, WifiOff, AlertTriangle, Lock, Unlock

} from 'lucide-react'




import { PageDataUnavailable } from '@/components/PageDataUnavailable'
import { PageSaveFailed } from '@/components/PageSaveFailed'

// ── Types ──────────────────────────────────────────────────────────────────────



interface QuarantineStats {

  total: number

  active: number

  released: number

}



interface QuarantineEntry {

  id: string

  agent_id: string

  hostname: string

  status: 'active' | 'released' | 'pending'

  reason: string

  network_isolated: boolean

  started_at: string

  released_at?: string

}



interface CreateQuarantinePayload {

  agent_id: string

  reason: string

  network_isolated: boolean

  kill_processes: boolean

}



// ── Helpers ────────────────────────────────────────────────────────────────────



function fmtDateTime(iso?: string): string {

  if (!iso) return '—'

  try {

    return new Date(iso).toLocaleString('en-US', {

      year: 'numeric', month: '2-digit', day: '2-digit',

      hour: '2-digit', minute: '2-digit',

    })

  } catch { return '—' }

}



const STATUS_STYLES: Record<string, string> = {

  active:   'bg-red-900/40 text-red-300 border border-red-700/50',

  released: 'bg-green-900/40 text-green-300 border border-green-700/50',

  pending:  'bg-yellow-900/40 text-yellow-300 border border-yellow-700/50',

}





// ── Stat Card ─────────────────────────────────────────────────────────────────



function StatCard({ label, value, icon: Icon, color = '#7d92b0' }: {

  label: string; value: string | number; icon: React.ElementType; color?: string

}) {

  return (

    <div className="bg-[#0d1220] border border-[#1e2d42] rounded-lg p-4 flex items-center gap-4">

      <div className="w-10 h-10 rounded-lg flex items-center justify-center shrink-0"

           style={{ backgroundColor: `${color}20` }}>

        <Icon className="w-5 h-5" style={{ color }} />

      </div>

      <div>

        <p className="text-[#7d92b0] text-xs">{label}</p>

        <p className="text-white text-xl font-bold">{value}</p>

      </div>

    </div>

  )

}



// ── Toggle ────────────────────────────────────────────────────────────────────



function Toggle({ value, onChange }: { value: boolean; onChange: (v: boolean) => void }) {

  return (

    <button

      type="button"

      onClick={() => onChange(!value)}

      className={`w-10 h-5 rounded-full transition-colors relative shrink-0 ${value ? 'bg-[#e8002d]' : 'bg-[#1e2d42]'}`}

    >

      <span className={`absolute top-0.5 w-4 h-4 rounded-full bg-[#e2e8f4] transition-all ${value ? 'left-5' : 'left-0.5'}`} />

    </button>

  )

}



// ── Create Modal ──────────────────────────────────────────────────────────────



function CreateModal({ onClose, onSave }: { onClose: () => void; onSave: (d: CreateQuarantinePayload) => void }) {

  const [form, setForm] = useState<CreateQuarantinePayload>({

    agent_id: '', reason: '', network_isolated: true, kill_processes: true,

  })



  return (

    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 backdrop-blur-sm p-4">

      <div className="bg-[#0d1220] border border-[#1e2d42] rounded-xl w-full max-w-md">

        <div className="flex items-center justify-between p-6 border-b border-[#1e2d42]">

          <h3 className="text-white font-bold text-lg flex items-center gap-2">

            <Lock className="w-5 h-5 text-[#e8002d]" />

            Quarantine Agent

          </h3>

          <button onClick={onClose} className="text-[#7d92b0] hover:text-white transition-colors">

            <X className="w-5 h-5" />

          </button>

        </div>



        <div className="p-6 space-y-4">

          <div>

            <label className="block text-[#7d92b0] text-xs mb-1.5">Agent ID <span className="text-[#e8002d]">*</span></label>

            <input

              type="text"

              value={form.agent_id}

              onChange={e => setForm(f => ({ ...f, agent_id: e.target.value }))}

              placeholder="e.g. agt-001"

              className="w-full bg-[#070d19] border border-[#1e2d42] rounded-lg px-3 py-2 text-white text-sm placeholder:text-[#3d5068] focus:outline-hidden focus:border-[#e8002d]/50"

            />

          </div>



          <div>

            <label className="block text-[#7d92b0] text-xs mb-1.5">Reason <span className="text-[#e8002d]">*</span></label>

            <textarea

              value={form.reason}

              onChange={e => setForm(f => ({ ...f, reason: e.target.value }))}

              rows={3}

              placeholder="Describe the reason for quarantine..."

              className="w-full bg-[#070d19] border border-[#1e2d42] rounded-lg px-3 py-2 text-white text-sm placeholder:text-[#3d5068] focus:outline-hidden focus:border-[#e8002d]/50 resize-none"

            />

          </div>



          <div className="space-y-3">

            <label className="flex items-center justify-between cursor-pointer">

              <div className="flex items-center gap-2">

                <WifiOff className="w-4 h-4 text-[#7d92b0]" />

                <span className="text-sm text-[#7d92b0]">Network Isolated</span>

              </div>

              <Toggle value={form.network_isolated} onChange={v => setForm(f => ({ ...f, network_isolated: v }))} />

            </label>



            <label className="flex items-center justify-between cursor-pointer">

              <div className="flex items-center gap-2">

                <AlertTriangle className="w-4 h-4 text-[#7d92b0]" />

                <span className="text-sm text-[#7d92b0]">Kill Processes</span>

              </div>

              <Toggle value={form.kill_processes} onChange={v => setForm(f => ({ ...f, kill_processes: v }))} />

            </label>

          </div>

        </div>



        <div className="flex gap-3 p-6 border-t border-[#1e2d42]">

          <button onClick={onClose}

            className="flex-1 px-4 py-2 border border-[#1e2d42] text-[#7d92b0] rounded-lg text-sm hover:bg-[#19253d] transition-colors">

            Cancel

          </button>

          <button

            onClick={() => onSave(form)}

            disabled={!form.agent_id.trim() || !form.reason.trim()}

            className="flex-1 px-4 py-2 bg-[#e8002d] hover:bg-[#c0001f] disabled:opacity-50 disabled:cursor-not-allowed text-white rounded-lg text-sm font-medium transition-colors">

            Quarantine

          </button>

        </div>

      </div>

    </div>

  )

}



// ── Main Page ─────────────────────────────────────────────────────────────────



export default function QuarantinePage() {

  const qc = useQueryClient()

  const [showCreate, setShowCreate] = useState(false)



  const { data: stats = { total: 0, active: 0, released: 0 } } = useQuery<QuarantineStats>({

    queryKey: ['quarantine-stats'],

    queryFn: () => apiFetch<QuarantineStats>('/api/v1/admin/quarantine/stats'),

    staleTime: 30_000,

  })



  const { data: quarantines = [], isLoading } = useQuery<QuarantineEntry[]>({

    queryKey: ['quarantine-list'],

    queryFn: () => apiFetch<{ quarantines: QuarantineEntry[] }>('/api/v1/admin/quarantine')

      .then(r => r.quarantines)

      .catch(() => []),

    staleTime: 30_000,

  })



  const createMutation = useMutation({

    mutationFn: (data: CreateQuarantinePayload) =>

      apiFetch('/api/v1/admin/quarantine', { method: 'POST', body: JSON.stringify(data) }),

    onSuccess: () => {

      qc.invalidateQueries({ queryKey: ['quarantine-list'] })

      qc.invalidateQueries({ queryKey: ['quarantine-stats'] })

      setShowCreate(false)

    },

  })



  const releaseMutation = useMutation({

    mutationFn: (id: string) =>

      apiFetch(`/api/v1/admin/quarantine/${id}/release`, { method: 'POST' }),

    onSuccess: () => {

      qc.invalidateQueries({ queryKey: ['quarantine-list'] })

      qc.invalidateQueries({ queryKey: ['quarantine-stats'] })

    },

  })



  return (

    <div className="min-h-screen bg-[#070d19] p-6">
      <PageDataUnavailable />

      <PageSaveFailed />
      {/* Header */}

      <div className="flex items-center justify-between mb-6">

        <div>

          <h1 className="text-2xl font-bold text-white flex items-center gap-3">

            <ShieldOff className="w-7 h-7 text-[#e8002d]" />

            Endpoint Quarantine

          </h1>

          <p className="text-[#7d92b0] text-sm mt-1">Isolate and manage compromised endpoints</p>

        </div>

        <button

          onClick={() => setShowCreate(true)}

          className="flex items-center gap-2 px-4 py-2 bg-[#e8002d] hover:bg-[#c0001f] text-white rounded-lg text-sm font-medium transition-colors"

        >

          <Plus className="w-4 h-4" />

          Quarantine Agent

        </button>

      </div>



      {/* Stats */}

      <div className="grid grid-cols-3 gap-4 mb-6">

        <StatCard label="Total Quarantines" value={stats.total}    icon={Shield}       color="#7d92b0" />

        <StatCard label="Active"            value={stats.active}   icon={ShieldOff}    color="#e8002d" />

        <StatCard label="Released"          value={stats.released} icon={CheckCircle}  color="#00c853" />

      </div>



      {/* Table */}

      <div className="bg-[#0d1220] border border-[#1e2d42] rounded-xl overflow-hidden">

        {isLoading ? (

          <div className="flex items-center justify-center py-16">

            <RefreshCw className="w-6 h-6 text-[#7d92b0] animate-spin" />

          </div>

        ) : (

          <table className="w-full">

            <thead>

              <tr className="border-b border-[#1e2d42]">

                {['Agent / Hostname', 'Status', 'Reason', 'Network Isolated', 'Started At', 'Actions'].map(h => (

                  <th key={h} className="px-4 py-3 text-left text-xs text-[#7d92b0] font-medium">{h}</th>

                ))}

              </tr>

            </thead>

            <tbody>

              {quarantines.length === 0 ? (

                <tr>

                  <td colSpan={6} className="px-4 py-12 text-center text-[#7d92b0] text-sm">

                    No quarantine entries found

                  </td>

                </tr>

              ) : quarantines.map(q => (

                <tr key={q.id} className="border-b border-[#1e2d42]/50 hover:bg-[#19253d]/30 transition-colors">

                  <td className="px-4 py-3">

                    <p className="text-white text-sm font-medium">{q.hostname}</p>

                    <p className="text-[#7d92b0] text-xs font-mono">{q.agent_id}</p>

                  </td>

                  <td className="px-4 py-3">

                    <span className={`text-xs px-2 py-0.5 rounded-full capitalize ${STATUS_STYLES[q.status]}`}>

                      {q.status}

                    </span>

                  </td>

                  <td className="px-4 py-3 text-[#7d92b0] text-sm max-w-[200px] truncate" title={q.reason}>

                    {q.reason}

                  </td>

                  <td className="px-4 py-3">

                    {q.network_isolated ? (

                      <span className="flex items-center gap-1.5 text-red-400 text-xs">

                        <WifiOff className="w-3.5 h-3.5" /> Yes

                      </span>

                    ) : (

                      <span className="flex items-center gap-1.5 text-[#7d92b0] text-xs">

                        <Wifi className="w-3.5 h-3.5" /> No

                      </span>

                    )}

                  </td>

                  <td className="px-4 py-3 text-[#7d92b0] text-sm">{fmtDateTime(q.started_at)}</td>

                  <td className="px-4 py-3">

                    {q.status !== 'released' && (

                      <button

                        onClick={() => releaseMutation.mutate(q.id)}

                        disabled={releaseMutation.isPending}

                        className="flex items-center gap-1.5 px-3 py-1.5 bg-green-700/20 hover:bg-green-700/40 border border-green-700/50 text-green-300 rounded-lg text-xs font-medium transition-colors disabled:opacity-50 disabled:cursor-not-allowed"

                      >

                        {releaseMutation.isPending

                          ? <RefreshCw className="w-3.5 h-3.5 animate-spin" />

                          : <Unlock className="w-3.5 h-3.5" />}

                        Release

                      </button>

                    )}

                  </td>

                </tr>

              ))}

            </tbody>

          </table>

        )}

      </div>



      {showCreate && (

        <CreateModal

          onClose={() => setShowCreate(false)}

          onSave={data => createMutation.mutate(data)}

        />

      )}

    </div>

  )

}


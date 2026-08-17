'use client'



import { useState } from 'react'

import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'

import { apiFetch } from '@/lib/api'

import {

  Timer, AlertTriangle, CheckCircle, TrendingUp, Plus, X, RefreshCw, ShieldAlert

} from 'lucide-react'




// ── Types ──────────────────────────────────────────────────────────────────────



interface SLAStats {

  total: number

  response_breached: number

  resolution_breached: number

  compliance_rate: number

}



interface SLAPolicy {

  id: string

  name: string

  severity: 'critical' | 'high' | 'medium' | 'low'

  response_minutes: number

  resolution_hours: number

  escalation_hours: number

  enabled: boolean

}



interface CreatePolicyPayload {

  name: string

  severity: SLAPolicy['severity']

  response_minutes: number

  resolution_hours: number

  escalation_hours: number

}



// ── Helpers ────────────────────────────────────────────────────────────────────



const SEVERITY_STYLES: Record<string, string> = {

  critical: 'bg-red-900/40 text-red-300 border border-red-700/50',

  high:     'bg-orange-900/40 text-orange-300 border border-orange-700/50',

  medium:   'bg-yellow-900/40 text-yellow-300 border border-yellow-700/50',

  low:      'bg-blue-900/40 text-blue-300 border border-blue-700/50',

}



const EMPTY_FORM: CreatePolicyPayload = {

  name: '', severity: 'medium', response_minutes: 60, resolution_hours: 24, escalation_hours: 8,

}



// ── Stat Card ─────────────────────────────────────────────────────────────────



function StatCard({ label, value, icon: Icon, color = '#7d92b0' }: {

  label: string; value: string | number; icon: React.ElementType; color?: string

}) {

  return (

    <div className="bg-falcon-surface border border-falcon-border rounded-lg p-4 flex items-center gap-4">

      <div className="w-10 h-10 rounded-lg flex items-center justify-center shrink-0"

           style={{ backgroundColor: `${color}20` }}>

        <Icon className="w-5 h-5" style={{ color }} />

      </div>

      <div>

        <p className="text-falcon-muted text-xs">{label}</p>

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

      className={`w-10 h-5 rounded-full transition-colors relative shrink-0 ${value ? 'bg-green-600' : 'bg-falcon-border'}`}

    >

      <span className={`absolute top-0.5 w-4 h-4 rounded-full bg-falcon-text transition-all ${value ? 'left-5' : 'left-0.5'}`} />

    </button>

  )

}



// ── Create Modal ──────────────────────────────────────────────────────────────



function CreateModal({ onClose, onSave }: { onClose: () => void; onSave: (d: CreatePolicyPayload) => void }) {

  const [form, setForm] = useState<CreatePolicyPayload>({ ...EMPTY_FORM })



  const field = (label: string, key: keyof CreatePolicyPayload, type: 'text' | 'number', placeholder?: string) => (

    <div>

      <label className="block text-falcon-muted text-xs mb-1.5">{label} <span className="text-falcon-red">*</span></label>

      <input

        type={type}

        value={form[key] as string | number}

        onChange={e => setForm(f => ({ ...f, [key]: type === 'number' ? Number(e.target.value) : e.target.value }))}

        placeholder={placeholder}

        min={type === 'number' ? 1 : undefined}

        className="w-full bg-[#070d19] border border-falcon-border rounded-lg px-3 py-2 text-white text-sm

                   placeholder:text-falcon-subtle focus:outline-hidden focus:border-falcon-red/50"

      />

    </div>

  )



  return (

    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 backdrop-blur-xs p-4">

      <div className="bg-falcon-surface border border-falcon-border rounded-xl w-full max-w-md">

        <div className="flex items-center justify-between p-6 border-b border-falcon-border">

          <h3 className="text-white font-bold text-lg flex items-center gap-2">

            <Timer className="w-5 h-5 text-falcon-red" />

            Add SLA Policy

          </h3>

          <button onClick={onClose} className="text-falcon-muted hover:text-white transition-colors">

            <X className="w-5 h-5" />

          </button>

        </div>



        <div className="p-6 space-y-4">

          {field('Policy Name', 'name', 'text', 'e.g. Critical Incident SLA')}



          <div>

            <label className="block text-falcon-muted text-xs mb-1.5">Severity <span className="text-falcon-red">*</span></label>

            <select

              value={form.severity}

              onChange={e => setForm(f => ({ ...f, severity: e.target.value as SLAPolicy['severity'] }))}

              className="w-full bg-[#070d19] border border-falcon-border rounded-lg px-3 py-2 text-white text-sm

                         focus:outline-hidden focus:border-falcon-red/50"

            >

              <option value="critical">Critical</option>

              <option value="high">High</option>

              <option value="medium">Medium</option>

              <option value="low">Low</option>

            </select>

          </div>



          <div className="grid grid-cols-3 gap-3">

            {field('Response (min)', 'response_minutes', 'number', '60')}

            {field('Resolution (hrs)', 'resolution_hours', 'number', '24')}

            {field('Escalation (hrs)', 'escalation_hours', 'number', '8')}

          </div>

        </div>



        <div className="flex gap-3 p-6 border-t border-falcon-border">

          <button onClick={onClose}

            className="flex-1 px-4 py-2 border border-falcon-border text-falcon-muted rounded-lg text-sm hover:bg-falcon-hover transition-colors">

            Cancel

          </button>

          <button

            onClick={() => onSave(form)}

            disabled={!form.name.trim()}

            className="flex-1 px-4 py-2 bg-falcon-red hover:bg-[#c0001f] disabled:opacity-50 disabled:cursor-not-allowed

                       text-white rounded-lg text-sm font-medium transition-colors">

            Create Policy

          </button>

        </div>

      </div>

    </div>

  )

}



// ── Main Page ─────────────────────────────────────────────────────────────────



export default function SecuritySLAPage() {

  const qc = useQueryClient()

  const [showCreate, setShowCreate] = useState(false)



  const { data: stats = { total: 0, response_breached: 0, resolution_breached: 0, compliance_rate: 0 } } = useQuery<SLAStats>({

    queryKey: ['sla-stats'],

    queryFn: () => apiFetch<SLAStats>('/api/v1/admin/security-sla/stats').catch(() => ({ total: 0, response_breached: 0, resolution_breached: 0, compliance_rate: 0 } as SLAStats)),

    staleTime: 60_000,

  })



  const { data: policies = [], isLoading } = useQuery<SLAPolicy[]>({

    queryKey: ['sla-policies'],

    queryFn: () => apiFetch<{ policies: SLAPolicy[] }>('/api/v1/admin/security-sla/policies')

      .then(r => r.policies)

      .catch(() => []),

    staleTime: 60_000,

  })



  const createMutation = useMutation({

    mutationFn: (data: CreatePolicyPayload) =>

      apiFetch('/api/v1/admin/security-sla/policies', { method: 'POST', body: JSON.stringify(data) })

        .catch(() => ({})),

    onSuccess: () => {

      qc.invalidateQueries({ queryKey: ['sla-policies'] })

      setShowCreate(false)

    },

  })



  const complianceColor = stats.compliance_rate >= 90 ? '#00c853'

    : stats.compliance_rate >= 75 ? '#ff9800'

    : '#e8002d'



  return (

    <div className="min-h-screen bg-[#070d19] p-6">

      {/* Header */}

      <div className="flex items-center justify-between mb-6">

        <div>

          <h1 className="text-2xl font-bold text-white flex items-center gap-3">

            <Timer className="w-7 h-7 text-falcon-red" />

            Security SLA Management

          </h1>

          <p className="text-falcon-muted text-sm mt-1">Define and monitor security response SLA policies</p>

        </div>

        <button

          onClick={() => setShowCreate(true)}

          className="flex items-center gap-2 px-4 py-2 bg-falcon-red hover:bg-[#c0001f] text-white rounded-lg text-sm font-medium transition-colors"

        >

          <Plus className="w-4 h-4" />

          Add SLA Policy

        </button>

      </div>



      {/* Stats */}

      <div className="grid grid-cols-4 gap-4 mb-6">

        <StatCard label="Total Tracked"        value={stats.total}                              icon={ShieldAlert}   color="#7d92b0" />

        <StatCard label="Response Breached"    value={stats.response_breached}                  icon={AlertTriangle} color="#e8002d" />

        <StatCard label="Resolution Breached"  value={stats.resolution_breached}                icon={AlertTriangle} color="#ff9800" />

        <StatCard label="Compliance Rate"      value={`${stats.compliance_rate.toFixed(1)}%`}   icon={TrendingUp}    color={complianceColor} />

      </div>



      {/* Compliance progress bar */}

      <div className="bg-falcon-surface border border-falcon-border rounded-lg p-4 mb-6">

        <div className="flex items-center justify-between mb-2">

          <span className="text-falcon-muted text-sm">Overall SLA Compliance</span>

          <span className="text-white text-sm font-bold">{stats.compliance_rate.toFixed(1)}%</span>

        </div>

        <div className="w-full h-2 bg-falcon-border rounded-full overflow-hidden">

          <div

            className="h-full rounded-full transition-all"

            style={{ width: `${stats.compliance_rate}%`, backgroundColor: complianceColor }}

          />

        </div>

      </div>



      {/* Policies Table */}

      <div className="bg-falcon-surface border border-falcon-border rounded-xl overflow-hidden">

        <div className="px-4 py-3 border-b border-falcon-border">

          <h2 className="text-white font-semibold text-sm">SLA Policies</h2>

        </div>



        {isLoading ? (

          <div className="flex items-center justify-center py-16">

            <RefreshCw className="w-6 h-6 text-falcon-muted animate-spin" />

          </div>

        ) : (

          <table className="w-full">

            <thead>

              <tr className="border-b border-falcon-border">

                {['Policy Name', 'Severity', 'Response', 'Resolution', 'Escalation', 'Enabled'].map(h => (

                  <th key={h} className="px-4 py-3 text-left text-xs text-falcon-muted font-medium">{h}</th>

                ))}

              </tr>

            </thead>

            <tbody>

              {policies.length === 0 ? (

                <tr>

                  <td colSpan={6} className="px-4 py-12 text-center text-falcon-muted text-sm">

                    No SLA policies configured

                  </td>

                </tr>

              ) : policies.map(p => (

                <tr key={p.id} className="border-b border-falcon-border/50 hover:bg-falcon-hover/30 transition-colors">

                  <td className="px-4 py-3 text-white text-sm font-medium">{p.name}</td>

                  <td className="px-4 py-3">

                    <span className={`text-xs px-2 py-0.5 rounded-full capitalize ${SEVERITY_STYLES[p.severity]}`}>

                      {p.severity}

                    </span>

                  </td>

                  <td className="px-4 py-3 text-falcon-muted text-sm">{p.response_minutes} min</td>

                  <td className="px-4 py-3 text-falcon-muted text-sm">{p.resolution_hours} hrs</td>

                  <td className="px-4 py-3 text-falcon-muted text-sm">{p.escalation_hours} hrs</td>

                  <td className="px-4 py-3">

                    <Toggle value={p.enabled} onChange={() => {}} />

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


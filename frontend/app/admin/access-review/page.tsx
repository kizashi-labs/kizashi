'use client'

import { useState } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { apiFetch, apiFetchList } from '@/lib/api'
import {
  Users, ClipboardCheck, Plus, X, RefreshCw, CheckCircle,
  XCircle, Clock, AlertTriangle, Calendar, Shield
} from 'lucide-react'

// ── Types ──────────────────────────────────────────────────────────────────────

interface Campaign {
  id: string
  name: string
  description?: string
  status: 'active' | 'draft' | 'completed' | 'cancelled'
  reviewer: string
  due_date: string
}

interface ReviewItem {
  id: string
  user: string
  resource: string
  permission: string
  decision: 'pending' | 'approve' | 'revoke'
}

interface CreateCampaignPayload {
  name: string
  description: string
  reviewer: string
  due_date: string
}

// ── Helpers ────────────────────────────────────────────────────────────────────

const CAMPAIGN_STATUS_STYLES: Record<string, string> = {
  active:    'bg-green-900/40 text-green-300 border border-green-700/50',
  draft:     'bg-yellow-900/40 text-yellow-300 border border-yellow-700/50',
  completed: 'bg-blue-900/40 text-blue-300 border border-blue-700/50',
  cancelled: 'bg-[#161f33] text-[#8899aa] border border-[#1e2d42]',
}

const DECISION_STYLES: Record<string, string> = {
  pending: 'bg-yellow-900/40 text-yellow-300 border border-yellow-700/50',
  approve: 'bg-green-900/40 text-green-300 border border-green-700/50',
  revoke:  'bg-red-900/40 text-red-300 border border-red-700/50',
}

const EMPTY_FORM: CreateCampaignPayload = { name: '', description: '', reviewer: '', due_date: '' }

// ── Stat Card ─────────────────────────────────────────────────────────────────

function StatCard({ label, value, icon: Icon, color = '#7d92b0' }: {
  label: string; value: string | number; icon: React.ElementType; color?: string
}) {
  return (
    <div className="bg-[#0d1220] border border-[#1e2d42] rounded-lg p-4 flex items-center gap-4">
      <div className="w-10 h-10 rounded-lg flex items-center justify-center flex-shrink-0"
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

// ── Create Campaign Modal ─────────────────────────────────────────────────────

function CreateCampaignModal({ onClose, onSave }: {
  onClose: () => void
  onSave: (d: CreateCampaignPayload) => void
}) {
  const [form, setForm] = useState<CreateCampaignPayload>({ ...EMPTY_FORM })

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 backdrop-blur-sm p-4">
      <div className="bg-[#0d1220] border border-[#1e2d42] rounded-xl w-full max-w-md">
        <div className="flex items-center justify-between p-6 border-b border-[#1e2d42]">
          <h3 className="text-white font-bold text-lg flex items-center gap-2">
            <ClipboardCheck className="w-5 h-5 text-[#e8002d]" />
            New Review Campaign
          </h3>
          <button onClick={onClose} className="text-[#7d92b0] hover:text-white transition-colors">
            <X className="w-5 h-5" />
          </button>
        </div>

        <div className="p-6 space-y-4">
          <div>
            <label className="block text-[#7d92b0] text-xs mb-1.5">Campaign Name <span className="text-[#e8002d]">*</span></label>
            <input
              type="text"
              value={form.name}
              onChange={e => setForm(f => ({ ...f, name: e.target.value }))}
              placeholder="e.g. Q2 2026 Access Review"
              className="w-full bg-[#070d19] border border-[#1e2d42] rounded-lg px-3 py-2 text-white text-sm
                         placeholder:text-[#3d5068] focus:outline-none focus:border-[#e8002d]/50"
            />
          </div>

          <div>
            <label className="block text-[#7d92b0] text-xs mb-1.5">Description</label>
            <textarea
              value={form.description}
              onChange={e => setForm(f => ({ ...f, description: e.target.value }))}
              rows={2}
              placeholder="Brief description of this review campaign"
              className="w-full bg-[#070d19] border border-[#1e2d42] rounded-lg px-3 py-2 text-white text-sm
                         placeholder:text-[#3d5068] focus:outline-none focus:border-[#e8002d]/50 resize-none"
            />
          </div>

          <div>
            <label className="block text-[#7d92b0] text-xs mb-1.5">Reviewer <span className="text-[#e8002d]">*</span></label>
            <input
              type="text"
              value={form.reviewer}
              onChange={e => setForm(f => ({ ...f, reviewer: e.target.value }))}
              placeholder="Reviewer name or team"
              className="w-full bg-[#070d19] border border-[#1e2d42] rounded-lg px-3 py-2 text-white text-sm
                         placeholder:text-[#3d5068] focus:outline-none focus:border-[#e8002d]/50"
            />
          </div>

          <div>
            <label className="block text-[#7d92b0] text-xs mb-1.5">Due Date <span className="text-[#e8002d]">*</span></label>
            <input
              type="date"
              value={form.due_date}
              onChange={e => setForm(f => ({ ...f, due_date: e.target.value }))}
              className="w-full bg-[#070d19] border border-[#1e2d42] rounded-lg px-3 py-2 text-white text-sm
                         focus:outline-none focus:border-[#e8002d]/50"
            />
          </div>
        </div>

        <div className="flex gap-3 p-6 border-t border-[#1e2d42]">
          <button onClick={onClose}
            className="flex-1 px-4 py-2 border border-[#1e2d42] text-[#7d92b0] rounded-lg text-sm hover:bg-[#19253d] transition-colors">
            Cancel
          </button>
          <button
            onClick={() => onSave(form)}
            disabled={!form.name.trim() || !form.reviewer.trim() || !form.due_date}
            className="flex-1 px-4 py-2 bg-[#e8002d] hover:bg-[#c0001f] disabled:opacity-50 disabled:cursor-not-allowed
                       text-white rounded-lg text-sm font-medium transition-colors">
            Create Campaign
          </button>
        </div>
      </div>
    </div>
  )
}

// ── Main Page ─────────────────────────────────────────────────────────────────

export default function AccessReviewPage() {
  const qc = useQueryClient()
  const [showCreate, setShowCreate] = useState(false)
  const [selectedCampaign, setSelectedCampaign] = useState<Campaign | null>(null)

  const { data: campaigns = [] } = useQuery<Campaign[]>({
    queryKey: ['access-review-campaigns'],
    queryFn: () => apiFetch<{ campaigns: Campaign[] }>('/api/v1/admin/access-review/campaigns')
      .then(r => r.campaigns)
      .catch(() => []),
    staleTime: 60_000,
  })

  const { data: items = [] } = useQuery<ReviewItem[]>({
    queryKey: ['access-review-items', selectedCampaign?.id],
    queryFn: () => apiFetchList<ReviewItem>(`/api/v1/admin/access-review/items${selectedCampaign ? `?campaign_id=${selectedCampaign.id}` : ''}`).catch(() => []),
    staleTime: 60_000,
  })

  const createMutation = useMutation({
    mutationFn: (data: CreateCampaignPayload) =>
      apiFetch('/api/v1/admin/access-review/campaigns', { method: 'POST', body: JSON.stringify(data) })
        .catch(() => ({ id: `c-${Date.now()}`, ...data, status: 'draft' })),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['access-review-campaigns'] })
      setShowCreate(false)
    },
  })

  const activeCampaigns    = campaigns.filter(c => c.status === 'active').length
  const pendingItems       = items.filter(i => i.decision === 'pending').length
  const completedCampaigns = campaigns.filter(c => c.status === 'completed').length

  return (
    <div className="min-h-screen bg-[#070d19] p-6">
      {/* Header */}
      <div className="flex items-center justify-between mb-6">
        <div>
          <h1 className="text-2xl font-bold text-white flex items-center gap-3">
            <ClipboardCheck className="w-7 h-7 text-[#e8002d]" />
            Access Review
          </h1>
          <p className="text-[#7d92b0] text-sm mt-1">Periodic user access certification and review campaigns</p>
        </div>
        <button
          onClick={() => setShowCreate(true)}
          className="flex items-center gap-2 px-4 py-2 bg-[#e8002d] hover:bg-[#c0001f] text-white rounded-lg text-sm font-medium transition-colors"
        >
          <Plus className="w-4 h-4" />
          New Campaign
        </button>
      </div>

      {/* Stats */}
      <div className="grid grid-cols-4 gap-4 mb-6">
        <StatCard label="Total Campaigns"    value={campaigns.length}   icon={ClipboardCheck} color="#7d92b0" />
        <StatCard label="Active"             value={activeCampaigns}    icon={Shield}         color="#00c853" />
        <StatCard label="Pending Items"      value={pendingItems}       icon={Clock}          color="#ff9800" />
        <StatCard label="Completed"          value={completedCampaigns} icon={CheckCircle}    color="#1a6bff" />
      </div>

      {/* Review Campaigns */}
      <div className="bg-[#0d1220] border border-[#1e2d42] rounded-xl overflow-hidden mb-6">
        <div className="px-4 py-3 border-b border-[#1e2d42] flex items-center justify-between">
          <h2 className="text-white font-semibold text-sm flex items-center gap-2">
            <Users className="w-4 h-4 text-[#7d92b0]" />
            Review Campaigns
          </h2>
        </div>
        <table className="w-full">
          <thead>
            <tr className="border-b border-[#1e2d42]">
              {['Campaign Name', 'Status', 'Reviewer', 'Due Date', 'Actions'].map(h => (
                <th key={h} className="px-4 py-3 text-left text-xs text-[#7d92b0] font-medium">{h}</th>
              ))}
            </tr>
          </thead>
          <tbody>
            {campaigns.map(c => (
              <tr key={c.id}
                className={`border-b border-[#1e2d42]/50 hover:bg-[#19253d]/30 transition-colors cursor-pointer ${selectedCampaign?.id === c.id ? 'bg-[#19253d]/20' : ''}`}
                onClick={() => setSelectedCampaign(c)}
              >
                <td className="px-4 py-3">
                  <p className="text-white text-sm font-medium">{c.name}</p>
                  {c.description && (
                    <p className="text-[#7d92b0] text-xs mt-0.5 truncate max-w-[280px]">{c.description}</p>
                  )}
                </td>
                <td className="px-4 py-3">
                  <span className={`text-xs px-2 py-0.5 rounded-full capitalize ${CAMPAIGN_STATUS_STYLES[c.status]}`}>
                    {c.status}
                  </span>
                </td>
                <td className="px-4 py-3 text-[#7d92b0] text-sm">{c.reviewer}</td>
                <td className="px-4 py-3">
                  <span className="flex items-center gap-1.5 text-[#7d92b0] text-sm">
                    <Calendar className="w-3.5 h-3.5" />
                    {c.due_date}
                  </span>
                </td>
                <td className="px-4 py-3">
                  <button
                    onClick={e => { e.stopPropagation(); setSelectedCampaign(c) }}
                    className="text-xs px-3 py-1.5 bg-[#1e2d42] hover:bg-[#2a3f5c] text-[#7d92b0] hover:text-white rounded-lg transition-colors"
                  >
                    View Items
                  </button>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>

      {/* Review Items */}
      <div className="bg-[#0d1220] border border-[#1e2d42] rounded-xl overflow-hidden">
        <div className="px-4 py-3 border-b border-[#1e2d42] flex items-center gap-2">
          <ClipboardCheck className="w-4 h-4 text-[#7d92b0]" />
          <h2 className="text-white font-semibold text-sm">
            Review Items
            {selectedCampaign && (
              <span className="text-[#7d92b0] font-normal ml-2">— {selectedCampaign.name}</span>
            )}
          </h2>
        </div>
        <table className="w-full">
          <thead>
            <tr className="border-b border-[#1e2d42]">
              {['User', 'Resource', 'Permission', 'Decision'].map(h => (
                <th key={h} className="px-4 py-3 text-left text-xs text-[#7d92b0] font-medium">{h}</th>
              ))}
            </tr>
          </thead>
          <tbody>
            {items.map(item => (
              <tr key={item.id} className="border-b border-[#1e2d42]/50 hover:bg-[#19253d]/30 transition-colors">
                <td className="px-4 py-3 text-white text-sm font-medium font-mono">{item.user}</td>
                <td className="px-4 py-3 text-[#7d92b0] text-sm">{item.resource}</td>
                <td className="px-4 py-3">
                  <span className="text-xs px-2 py-0.5 rounded bg-[#1e2d42] text-[#7d92b0]">{item.permission}</span>
                </td>
                <td className="px-4 py-3">
                  <span className={`text-xs px-2 py-0.5 rounded-full capitalize ${DECISION_STYLES[item.decision]}`}>
                    {item.decision === 'approve' && <CheckCircle className="w-3 h-3 inline mr-1" />}
                    {item.decision === 'revoke'  && <XCircle className="w-3 h-3 inline mr-1" />}
                    {item.decision === 'pending' && <Clock className="w-3 h-3 inline mr-1" />}
                    {item.decision}
                  </span>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>

      {showCreate && (
        <CreateCampaignModal
          onClose={() => setShowCreate(false)}
          onSave={data => createMutation.mutate(data)}
        />
      )}
    </div>
  )
}

'use client'

import { useState, useEffect } from 'react'
import {
  Building2, Plus, ChevronDown, ChevronUp, ChevronRight,
  Check, X, RefreshCw, Users, Cpu,
} from 'lucide-react'
import { apiFetch, apiFetchList } from '@/lib/api'


// ── Types ────────────────────────────────────────────────────────────────────

type Plan = 'enterprise' | 'pro' | 'starter' | 'free'

interface OrgSettings {
  ssoAllowed: boolean
  retentionDays: number
}

interface Organization {
  id: string
  name: string
  slug: string
  plan: Plan
  agentLimit: number
  userLimit: number
  agentCount: number
  userCount: number
  enabled: boolean
  createdAt: string
  settings: OrgSettings
}

interface CreateOrgForm {
  name: string
  slug: string
  plan: Plan
  agentLimit: number
  userLimit: number
  ssoAllowed: boolean
  retentionDays: number
}

// ── Helpers ───────────────────────────────────────────────────────────────────

function slugify(name: string): string {
  return name.toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/^-+|-+$/g, '')
}

function PlanBadge({ plan }: { plan: Plan }) {
  const map: Record<Plan, string> = {
    enterprise: 'bg-yellow-900/40 text-yellow-300 border-yellow-800',
    pro:        'bg-blue-900/40 text-blue-300 border-blue-800',
    starter:    'bg-zinc-700/60 text-zinc-300 border-zinc-600',
    free:       'bg-zinc-800 text-zinc-500 border-zinc-700',
  }
  const labels: Record<Plan, string> = {
    enterprise: 'Enterprise',
    pro:        'Pro',
    starter:    'Starter',
    free:       'Free',
  }
  return (
    <span className={`px-2 py-0.5 rounded-full text-xs font-semibold border ${map[plan]}`}>
      {labels[plan]}
    </span>
  )
}

// ── Toast ─────────────────────────────────────────────────────────────────────

function Toast({ message, visible }: { message: string; visible: boolean }) {
  return (
    <div className={`fixed top-6 right-6 z-50 flex items-center gap-2 px-4 py-3 rounded-lg
      bg-green-900/90 border border-green-700 text-green-300 text-sm font-medium shadow-xl
      transition-all duration-300 ${visible ? 'opacity-100 translate-y-0' : 'opacity-0 -translate-y-2 pointer-events-none'}`}>
      <Check className="w-4 h-4" />
      {message}
    </div>
  )
}

// ── Create Org Modal ──────────────────────────────────────────────────────────

function CreateOrgModal({ onClose, onCreated }: {
  onClose: () => void
  onCreated: (org: Organization) => void
}) {
  const [form, setForm] = useState<CreateOrgForm>({
    name: '',
    slug: '',
    plan: 'starter',
    agentLimit: 100,
    userLimit: 20,
    ssoAllowed: false,
    retentionDays: 90,
  })
  const [saving, setSaving] = useState(false)

  const handleNameChange = (name: string) => {
    setForm(p => ({ ...p, name, slug: slugify(name) }))
  }

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault()
    if (!form.name || !form.slug) return
    setSaving(true)
    try {
      const result = await apiFetch<Organization>('/api/v1/admin/organizations', {
        method: 'POST',
        body: JSON.stringify({
          name: form.name,
          slug: form.slug,
          plan: form.plan,
          agent_limit: form.agentLimit,
          user_limit: form.userLimit,
          settings: { sso_allowed: form.ssoAllowed, retention_days: form.retentionDays },
        }),
      })
      onCreated(result)
    } catch {
      // Mock: create locally
      const mockOrg: Organization = {
        id: `org-${Date.now()}`,
        name: form.name,
        slug: form.slug,
        plan: form.plan,
        agentLimit: form.agentLimit,
        userLimit: form.userLimit,
        agentCount: 0,
        userCount: 0,
        enabled: true,
        createdAt: new Date().toISOString().slice(0, 10),
        settings: { ssoAllowed: form.ssoAllowed, retentionDays: form.retentionDays },
      }
      onCreated(mockOrg)
    }
    setSaving(false)
  }

  const inputCls = 'w-full bg-zinc-800 border border-zinc-700 rounded-lg px-3 py-2 text-sm text-zinc-200 placeholder-zinc-600 focus:outline-hidden focus:border-zinc-500 transition-colors'

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/60 backdrop-blur-xs">
      <div className="bg-zinc-900 border border-zinc-800 rounded-2xl w-full max-w-md shadow-2xl">
        <div className="flex items-center justify-between p-5 border-b border-zinc-800">
          <h2 className="text-base font-semibold text-zinc-100">組織を作成</h2>
          <button onClick={onClose} className="p-1 text-zinc-500 hover:text-zinc-300 transition-colors">
            <X className="w-4 h-4" />
          </button>
        </div>

        <form onSubmit={handleSubmit} className="p-5 space-y-4">
          <div>
            <label className="block text-xs text-zinc-400 mb-1.5">組織名 *</label>
            <input
              type="text"
              required
              value={form.name}
              onChange={e => handleNameChange(e.target.value)}
              placeholder="Acme Corp Security"
              className={inputCls}
            />
          </div>
          <div>
            <label className="block text-xs text-zinc-400 mb-1.5">スラッグ（URL安全な識別子） *</label>
            <input
              type="text"
              required
              value={form.slug}
              onChange={e => setForm(p => ({ ...p, slug: e.target.value }))}
              placeholder="acme-corp-security"
              className={`${inputCls} font-mono`}
            />
          </div>
          <div>
            <label className="block text-xs text-zinc-400 mb-1.5">プラン</label>
            <select
              value={form.plan}
              onChange={e => setForm(p => ({ ...p, plan: e.target.value as Plan }))}
              className={inputCls}
            >
              <option value="enterprise">Enterprise</option>
              <option value="pro">Pro</option>
              <option value="starter">Starter</option>
              <option value="free">Free</option>
            </select>
          </div>
          <div className="grid grid-cols-2 gap-3">
            <div>
              <label className="block text-xs text-zinc-400 mb-1.5">エージェント上限</label>
              <input
                type="number"
                min={1}
                value={form.agentLimit}
                onChange={e => setForm(p => ({ ...p, agentLimit: Number(e.target.value) }))}
                className={inputCls}
              />
            </div>
            <div>
              <label className="block text-xs text-zinc-400 mb-1.5">ユーザー上限</label>
              <input
                type="number"
                min={1}
                value={form.userLimit}
                onChange={e => setForm(p => ({ ...p, userLimit: Number(e.target.value) }))}
                className={inputCls}
              />
            </div>
          </div>
          <div>
            <label className="block text-xs text-zinc-400 mb-1.5">データ保持日数</label>
            <input
              type="number"
              min={1}
              value={form.retentionDays}
              onChange={e => setForm(p => ({ ...p, retentionDays: Number(e.target.value) }))}
              className={inputCls}
            />
          </div>
          <div className="flex items-center justify-between py-2 border-t border-zinc-800">
            <div>
              <div className="text-sm text-zinc-300">SSO許可</div>
              <div className="text-xs text-zinc-500">この組織でのSSOログインを許可します</div>
            </div>
            <button
              type="button"
              onClick={() => setForm(p => ({ ...p, ssoAllowed: !p.ssoAllowed }))}
              className={`relative w-10 h-6 rounded-full transition-colors ${form.ssoAllowed ? 'bg-red-600' : 'bg-zinc-700'}`}
            >
              <span className={`absolute top-1 w-4 h-4 rounded-full bg-falcon-text shadow-sm transition-transform ${form.ssoAllowed ? 'left-5' : 'left-1'}`} />
            </button>
          </div>

          <div className="flex justify-end gap-2 pt-2">
            <button
              type="button"
              onClick={onClose}
              className="px-4 py-2 text-sm text-zinc-400 hover:text-zinc-200 transition-colors"
            >キャンセル</button>
            <button
              type="submit"
              disabled={saving || !form.name || !form.slug}
              className="flex items-center gap-2 px-4 py-2 bg-red-600 hover:bg-red-500 text-white text-sm font-medium rounded-lg transition-colors disabled:opacity-50"
            >
              {saving ? <RefreshCw className="w-4 h-4 animate-spin" /> : <Plus className="w-4 h-4" />}
              組織を作成
            </button>
          </div>
        </form>
      </div>
    </div>
  )
}

// ── Main Page ─────────────────────────────────────────────────────────────────

export default function OrganizationsPage() {
  const [orgs, setOrgs] = useState<Organization[]>([])
  const [currentOrgId, setCurrentOrgId] = useState('org-001')
  const [expandedOrgId, setExpandedOrgId] = useState<string | null>(null)
  const [showCreateModal, setShowCreateModal] = useState(false)
  const [showOrgSwitcher, setShowOrgSwitcher] = useState(false)
  const [toast, setToast] = useState('')
  const [toastVisible, setToastVisible] = useState(false)

  useEffect(() => {
    apiFetchList<Organization>('/api/v1/admin/organizations')
      .then(data => { if (Array.isArray(data) && data.length) setOrgs(data) })
      .catch(() => { /* use mock */ })
  }, [])

  const showToast = (msg: string) => {
    setToast(msg)
    setToastVisible(true)
    setTimeout(() => setToastVisible(false), 3000)
  }

  const toggleEnabled = async (orgId: string) => {
    setOrgs(prev => prev.map(o => o.id === orgId ? { ...o, enabled: !o.enabled } : o))
    showToast('組織を更新しました')
  }

  const currentOrg = orgs.find(o => o.id === currentOrgId)

  // Stats
  const totalOrgs = orgs.length
  const enterpriseCount = orgs.filter(o => o.plan === 'enterprise').length
  const proCount = orgs.filter(o => o.plan === 'pro').length
  const freeStarterCount = orgs.filter(o => o.plan === 'free' || o.plan === 'starter').length

  return (
    <div className="min-h-screen bg-zinc-950 p-6">
      <Toast message={toast} visible={toastVisible} />
      {showCreateModal && (
        <CreateOrgModal
          onClose={() => setShowCreateModal(false)}
          onCreated={org => {
            setOrgs(prev => [...prev, org])
            setShowCreateModal(false)
            showToast(`組織「${org.name}」を作成しました`)
          }}
        />
      )}

      {/* Header */}
      <div className="flex items-start justify-between mb-6 gap-4">
        <div className="flex items-center gap-3">
          <div className="w-10 h-10 rounded-lg bg-zinc-800 flex items-center justify-center">
            <Building2 className="w-5 h-5 text-zinc-300" />
          </div>
          <div>
            <h1 className="text-xl font-bold text-zinc-100">組織</h1>
            <p className="text-xs text-zinc-500 mt-0.5">マルチテナント組織管理</p>
          </div>
        </div>
        <div className="flex items-center gap-2">
          {/* Current org switcher */}
          <div className="relative">
            <button
              onClick={() => setShowOrgSwitcher(v => !v)}
              className="flex items-center gap-2 px-3 py-2 bg-zinc-800 border border-zinc-700 hover:border-zinc-600 text-zinc-300 text-sm rounded-lg transition-colors"
            >
              <Building2 className="w-4 h-4 text-zinc-500" />
              <span>現在の組織: <span className="font-medium text-zinc-100">{currentOrg?.name ?? '—'}</span></span>
              <ChevronDown className="w-3.5 h-3.5 text-zinc-500" />
            </button>
            {showOrgSwitcher && (
              <div className="absolute right-0 top-full mt-1 w-64 bg-zinc-900 border border-zinc-800 rounded-xl shadow-xl z-20 overflow-hidden">
                {orgs.map(o => (
                  <button
                    key={o.id}
                    onClick={() => { setCurrentOrgId(o.id); setShowOrgSwitcher(false) }}
                    className={`w-full flex items-center justify-between px-4 py-2.5 text-sm hover:bg-zinc-800 transition-colors ${o.id === currentOrgId ? 'text-zinc-100 bg-zinc-800/60' : 'text-zinc-400'}`}
                  >
                    <span>{o.name}</span>
                    {o.id === currentOrgId && <Check className="w-3.5 h-3.5 text-red-400" />}
                  </button>
                ))}
              </div>
            )}
          </div>
          <button
            onClick={() => setShowCreateModal(true)}
            className="flex items-center gap-2 px-4 py-2 bg-red-600 hover:bg-red-500 text-white text-sm font-medium rounded-lg transition-colors"
          >
            <Plus className="w-4 h-4" />組織を作成</button>
        </div>
      </div>

      {/* Stats */}
      <div className="grid grid-cols-2 sm:grid-cols-4 gap-3 mb-6">
        {[
          { label: '組織数',  value: totalOrgs,       color: 'text-zinc-100'   },
          { label: 'エンタープライズ',  value: enterpriseCount,  color: 'text-yellow-400' },
          { label: 'プロ',         value: proCount,         color: 'text-blue-400'   },
          { label: 'フリー/スターター',value: freeStarterCount, color: 'text-zinc-400'   },
        ].map(s => (
          <div key={s.label} className="bg-zinc-900 border border-zinc-800 rounded-xl p-4">
            <div className={`text-2xl font-bold ${s.color}`}>{s.value}</div>
            <div className="text-xs text-zinc-500 mt-0.5">{s.label}</div>
          </div>
        ))}
      </div>

      {/* Organizations table */}
      <div className="bg-zinc-900 border border-zinc-800 rounded-xl overflow-hidden">
        <div className="overflow-x-auto">
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b border-zinc-800 bg-zinc-800/50">
                <th className="px-4 py-3 text-left text-xs text-zinc-500 font-medium uppercase tracking-wider">組織</th>
                <th className="px-4 py-3 text-left text-xs text-zinc-500 font-medium uppercase tracking-wider">スラッグ</th>
                <th className="px-4 py-3 text-left text-xs text-zinc-500 font-medium uppercase tracking-wider">プラン</th>
                <th className="px-4 py-3 text-left text-xs text-zinc-500 font-medium uppercase tracking-wider">制限</th>
                <th className="px-4 py-3 text-left text-xs text-zinc-500 font-medium uppercase tracking-wider">有効</th>
                <th className="px-4 py-3 text-left text-xs text-zinc-500 font-medium uppercase tracking-wider">作成日</th>
                <th className="px-4 py-3 text-left text-xs text-zinc-500 font-medium uppercase tracking-wider">操作</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-zinc-800">
              {orgs.map(org => (
                <>
                  <tr key={org.id} className="hover:bg-zinc-800/40 transition-colors">
                    <td className="px-4 py-3">
                      <div className="font-medium text-zinc-100">{org.name}</div>
                      {org.id === currentOrgId && (
                        <div className="text-xs text-red-400 mt-0.5">現在使用中</div>
                      )}
                    </td>
                    <td className="px-4 py-3">
                      <code className="text-xs font-mono text-zinc-400 bg-zinc-800 px-1.5 py-0.5 rounded-sm">
                        {org.slug}
                      </code>
                    </td>
                    <td className="px-4 py-3"><PlanBadge plan={org.plan} /></td>
                    <td className="px-4 py-3">
                      <div className="flex items-center gap-3 text-xs text-zinc-400">
                        <span className="flex items-center gap-1">
                          <Cpu className="w-3 h-3" />
                          {org.agentCount}/{org.agentLimit}
                        </span>
                        <span className="flex items-center gap-1">
                          <Users className="w-3 h-3" />
                          {org.userCount}/{org.userLimit}
                        </span>
                      </div>
                    </td>
                    <td className="px-4 py-3">
                      <button
                        onClick={() => toggleEnabled(org.id)}
                        className={`relative w-9 h-5 rounded-full transition-colors ${org.enabled ? 'bg-green-600' : 'bg-zinc-700'}`}
                      >
                        <span className={`absolute top-0.5 w-4 h-4 rounded-full bg-falcon-text shadow-sm transition-transform ${org.enabled ? 'left-4' : 'left-0.5'}`} />
                      </button>
                    </td>
                    <td className="px-4 py-3 text-xs text-zinc-500">{org.createdAt}</td>
                    <td className="px-4 py-3">
                      <button
                        onClick={() => setExpandedOrgId(expandedOrgId === org.id ? null : org.id)}
                        className="flex items-center gap-1 text-xs text-zinc-400 hover:text-zinc-200 transition-colors"
                      >
                        {expandedOrgId === org.id ? <ChevronUp className="w-3.5 h-3.5" /> : <ChevronDown className="w-3.5 h-3.5" />}
                        詳細
                      </button>
                    </td>
                  </tr>
                  {expandedOrgId === org.id && (
                    <tr key={`${org.id}-expanded`} className="bg-zinc-800/30">
                      <td colSpan={7} className="px-4 py-4">
                        <div className="grid grid-cols-2 sm:grid-cols-4 gap-4 text-sm">
                          <div>
                            <div className="text-xs text-zinc-500 mb-0.5">エージェント数</div>
                            <div className="text-zinc-200 font-medium">{org.agentCount}</div>
                          </div>
                          <div>
                            <div className="text-xs text-zinc-500 mb-0.5">ユーザー数</div>
                            <div className="text-zinc-200 font-medium">{org.userCount}</div>
                          </div>
                          <div>
                            <div className="text-xs text-zinc-500 mb-0.5">SSO許可</div>
                            <div className={`font-medium ${org.settings.ssoAllowed ? 'text-green-400' : 'text-zinc-500'}`}>
                              {org.settings.ssoAllowed ? 'はい' : 'いいえ'}
                            </div>
                          </div>
                          <div>
                            <div className="text-xs text-zinc-500 mb-0.5">データ保持期間</div>
                            <div className="text-zinc-200 font-medium">{org.settings.retentionDays} 日</div>
                          </div>
                        </div>
                        <div className="mt-3 flex items-center gap-2">
                          <button
                            onClick={() => setCurrentOrgId(org.id)}
                            disabled={org.id === currentOrgId}
                            className="flex items-center gap-1.5 px-3 py-1.5 bg-zinc-700 hover:bg-zinc-600 text-zinc-300 text-xs rounded-lg transition-colors disabled:opacity-40"
                          >
                            <ChevronRight className="w-3.5 h-3.5" />
                            この組織に切り替え
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
    </div>
  )
}

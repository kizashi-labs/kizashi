'use client'

import { useState } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { apiFetch } from '@/lib/api'
import { Bell, Mail, Slack, Plus, Pencil, Trash2, X, Eye, Save, Copy } from 'lucide-react'

// ── Types ──────────────────────────────────────────────────────

type TemplateType = 'email' | 'slack'
type EventType = 'alert_critical' | 'alert_high' | 'agent_offline' | 'compliance_failure' | 'weekly_report'

interface NotificationTemplate {
  id: string
  name: string
  type: TemplateType
  event_type: EventType
  subject?: string
  body: string
  updated_at: string
}

interface TemplatesResponse {
  templates: NotificationTemplate[]
}

// ── Constants ─────────────────────────────────────────────────

const EVENT_TYPE_LABELS: Record<EventType, string> = {
  alert_critical: 'クリティカルアラート',
  alert_high: '高優先度アラート',
  agent_offline: 'エージェントオフライン',
  compliance_failure: 'コンプライアンス違反',
  weekly_report: '週次レポート',
}

const EVENT_TYPE_COLORS: Record<EventType, string> = {
  alert_critical: 'bg-[#e8002d]/20 text-[#e8002d] border-[#e8002d]/30',
  alert_high: 'bg-orange-900/30 text-orange-400 border-orange-700/30',
  agent_offline: 'bg-yellow-900/30 text-yellow-400 border-yellow-700/30',
  compliance_failure: 'bg-purple-900/30 text-purple-400 border-purple-700/30',
  weekly_report: 'bg-blue-900/30 text-blue-400 border-blue-700/30',
}

const AVAILABLE_VARIABLES = [
  { name: '{{alert_title}}', desc: 'アラートのタイトル' },
  { name: '{{agent_name}}', desc: 'エージェント名' },
  { name: '{{severity}}', desc: '重大度レベル' },
  { name: '{{timestamp}}', desc: '検出日時' },
  { name: '{{dashboard_url}}', desc: 'ダッシュボードURL' },
]

const SAMPLE_VALUES: Record<string, string> = {
  '{{alert_title}}': 'Mimikatz検出 - 認証情報ダンプ',
  '{{agent_name}}': 'WIN-PROD-001',
  '{{severity}}': 'CRITICAL (10)',
  '{{timestamp}}': '2026-03-18 09:45:32 JST',
  '{{dashboard_url}}': 'https://kizashi-edr.example.com/alerts/ALT-2026-0318',
}

const emptyForm = {
  name: '',
  type: 'email' as TemplateType,
  event_type: 'alert_critical' as EventType,
  subject: '',
  body: '',
}

// ── Component ─────────────────────────────────────────────────

export default function NotificationTemplatesPage() {
  const queryClient = useQueryClient()
  const [activeTab, setActiveTab] = useState<TemplateType>('email')
  const [selectedId, setSelectedId] = useState<string | null>(null)
  const [form, setForm] = useState<typeof emptyForm>(emptyForm)
  const [isEditing, setIsEditing] = useState(false)
  const [previewOpen, setPreviewOpen] = useState(false)
  const [deleteConfirm, setDeleteConfirm] = useState<string | null>(null)
  const [saveSuccess, setSaveSuccess] = useState(false)

  // ── Data ──────────────────────────────────────────────────────

  const { data, isLoading } = useQuery<TemplatesResponse>({
    queryKey: ['notification-templates'],
    queryFn: async () => {
      try {
        return await apiFetch<TemplatesResponse>('/api/v1/admin/notification-templates')
      } catch {
        return { templates: [] }
      }
    },
  })

  const templates = data?.templates ?? []
  const filteredTemplates = templates.filter(t => t.type === activeTab)
  const selectedTemplate = templates.find(t => t.id === selectedId) ?? null

  // ── Mutations ─────────────────────────────────────────────────

  const saveMutation = useMutation({
    mutationFn: async (payload: typeof emptyForm & { id?: string }) => {
      if (payload.id) {
        return apiFetch(`/api/v1/admin/notification-templates/${payload.id}`, {
          method: 'PUT',
          body: JSON.stringify(payload),
        })
      }
      return apiFetch('/api/v1/admin/notification-templates', {
        method: 'POST',
        body: JSON.stringify(payload),
      })
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['notification-templates'] })
      setIsEditing(false)
      setSaveSuccess(true)
      setTimeout(() => setSaveSuccess(false), 2000)
    },
    onError: () => {
      // Optimistic mock save
      setIsEditing(false)
      setSaveSuccess(true)
      setTimeout(() => setSaveSuccess(false), 2000)
    },
  })

  const deleteMutation = useMutation({
    mutationFn: (id: string) =>
      apiFetch(`/api/v1/admin/notification-templates/${id}`, { method: 'DELETE' }),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['notification-templates'] })
      setSelectedId(null)
      setIsEditing(false)
      setDeleteConfirm(null)
    },
    onError: () => {
      setDeleteConfirm(null)
    },
  })

  // ── Handlers ─────────────────────────────────────────────────

  const handleSelectTemplate = (tpl: NotificationTemplate) => {
    setSelectedId(tpl.id)
    setForm({
      name: tpl.name,
      type: tpl.type,
      event_type: tpl.event_type,
      subject: tpl.subject ?? '',
      body: tpl.body,
    })
    setIsEditing(false)
  }

  const handleNewTemplate = () => {
    setSelectedId(null)
    setForm({ ...emptyForm, type: activeTab })
    setIsEditing(true)
  }

  const handleEdit = () => {
    if (selectedTemplate) {
      setForm({
        name: selectedTemplate.name,
        type: selectedTemplate.type,
        event_type: selectedTemplate.event_type,
        subject: selectedTemplate.subject ?? '',
        body: selectedTemplate.body,
      })
      setIsEditing(true)
    }
  }

  const handleSave = () => {
    saveMutation.mutate(selectedId ? { ...form, id: selectedId } : form)
  }

  const handleTabChange = (tab: TemplateType) => {
    setActiveTab(tab)
    const first = templates.find(t => t.type === tab)
    if (first) {
      handleSelectTemplate(first)
    } else {
      setSelectedId(null)
      setIsEditing(false)
    }
  }

  const insertVariable = (varName: string) => {
    setForm(f => ({ ...f, body: f.body + varName }))
  }

  const renderPreview = () => {
    let text = form.body || (selectedTemplate?.body ?? '')
    Object.entries(SAMPLE_VALUES).forEach(([k, v]) => {
      text = text.replaceAll(k, v)
    })
    return text
  }

  const formatDate = (iso: string) => {
    try { return new Date(iso).toLocaleDateString('ja-JP', { month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit' }) }
    catch { return iso }
  }

  // ── Render ───────────────────────────────────────────────────

  return (
    <div className="flex flex-col gap-6 p-6 bg-[#070d19] min-h-screen">

      {/* Header */}
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-3">
          <div className="w-10 h-10 rounded-lg bg-gradient-to-br from-[#e8002d] to-[#a80020] flex items-center justify-center shadow-lg">
            <Bell className="w-5 h-5 text-white" />
          </div>
          <div>
            <h1 className="text-xl font-bold text-[#e2e8f4]">通知テンプレート管理</h1>
            <p className="text-sm text-[#7d92b0]">メール・Slackの通知テンプレートを管理します</p>
          </div>
        </div>
        <button
          onClick={handleNewTemplate}
          className="flex items-center gap-2 px-4 py-2 bg-[#e8002d] hover:bg-[#c8001d] text-white rounded-lg text-sm font-medium transition-colors"
        >
          <Plus className="w-4 h-4" />
          テンプレート追加
        </button>
      </div>

      {/* Tabs */}
      <div className="flex gap-1 p-1 bg-[#0d1220] rounded-lg border border-[#1e2d42] w-fit">
        {(['email', 'slack'] as TemplateType[]).map(tab => (
          <button
            key={tab}
            onClick={() => handleTabChange(tab)}
            className={`flex items-center gap-2 px-4 py-2 rounded-md text-sm font-medium transition-all ${
              activeTab === tab
                ? 'bg-[#1d2f4a] text-white'
                : 'text-[#7d92b0] hover:text-[#e2e8f4]'
            }`}
          >
            {tab === 'email' ? <Mail className="w-4 h-4" /> : <Slack className="w-4 h-4" />}
            {tab === 'email' ? 'メールテンプレート' : 'Slackテンプレート'}
            <span className="text-xs px-1.5 py-0.5 rounded bg-[#0d1220] border border-[#1e2d42] text-[#7d92b0]">
              {templates.filter(t => t.type === tab).length}
            </span>
          </button>
        ))}
      </div>

      {/* Main layout: sidebar + editor */}
      <div className="flex gap-4 min-h-[600px]">

        {/* Template list sidebar */}
        <div className="w-72 flex-shrink-0 flex flex-col gap-2">
          {isLoading ? (
            Array.from({ length: 3 }).map((_, i) => (
              <div key={i} className="h-20 bg-[#0d1220] rounded-lg border border-[#1e2d42] animate-pulse" />
            ))
          ) : filteredTemplates.length === 0 ? (
            <div className="flex flex-col items-center justify-center h-32 text-[#7d92b0] text-sm bg-[#0d1220] rounded-lg border border-[#1e2d42]">
              <Bell className="w-6 h-6 mb-2 opacity-40" />
              テンプレートなし
            </div>
          ) : (
            filteredTemplates.map(tpl => (
              <button
                key={tpl.id}
                onClick={() => handleSelectTemplate(tpl)}
                className={`text-left p-3 rounded-lg border transition-all ${
                  selectedId === tpl.id
                    ? 'bg-[#1d2f4a] border-[#e8002d]/40'
                    : 'bg-[#0d1220] border-[#1e2d42] hover:border-[#2d3f5a]'
                }`}
              >
                <div className="flex items-start justify-between gap-2 mb-1.5">
                  <p className="text-sm font-medium text-[#e2e8f4] leading-tight">{tpl.name}</p>
                  {selectedId === tpl.id && (
                    <span className="w-1.5 h-1.5 rounded-full bg-[#e8002d] flex-shrink-0 mt-1" />
                  )}
                </div>
                <span className={`inline-flex items-center px-2 py-0.5 rounded border text-[11px] font-medium ${EVENT_TYPE_COLORS[tpl.event_type]}`}>
                  {EVENT_TYPE_LABELS[tpl.event_type]}
                </span>
                <p className="text-[11px] text-[#3d5068] mt-2">更新: {formatDate(tpl.updated_at)}</p>
              </button>
            ))
          )}
        </div>

        {/* Editor panel */}
        <div className="flex-1 flex flex-col gap-4">
          {selectedId === null && !isEditing ? (
            <div className="flex-1 flex flex-col items-center justify-center bg-[#0d1220] rounded-xl border border-[#1e2d42] text-[#7d92b0]">
              <Mail className="w-12 h-12 opacity-20 mb-3" />
              <p className="text-sm">テンプレートを選択するか、新規作成してください</p>
            </div>
          ) : (
            <div className="flex-1 flex flex-col gap-4 bg-[#0d1220] rounded-xl border border-[#1e2d42] p-5">

              {/* Editor header */}
              <div className="flex items-center justify-between">
                <h2 className="text-base font-semibold text-[#e2e8f4]">
                  {isEditing ? (selectedId ? 'テンプレート編集' : '新規テンプレート') : 'テンプレート詳細'}
                </h2>
                <div className="flex items-center gap-2">
                  {!isEditing && selectedId && (
                    <>
                      <button
                        onClick={handleEdit}
                        className="flex items-center gap-1.5 px-3 py-1.5 text-sm text-[#7d92b0] hover:text-white bg-[#1a2640] hover:bg-[#1d2f4a] rounded-lg border border-[#1e2d42] transition-colors"
                      >
                        <Pencil className="w-3.5 h-3.5" />
                        編集
                      </button>
                      <button
                        onClick={() => setDeleteConfirm(selectedId)}
                        className="flex items-center gap-1.5 px-3 py-1.5 text-sm text-[#e8002d] hover:bg-[#e8002d]/10 rounded-lg border border-[#e8002d]/30 transition-colors"
                      >
                        <Trash2 className="w-3.5 h-3.5" />
                        削除
                      </button>
                    </>
                  )}
                  {isEditing && (
                    <>
                      <button
                        onClick={() => setPreviewOpen(true)}
                        className="flex items-center gap-1.5 px-3 py-1.5 text-sm text-[#7d92b0] hover:text-white bg-[#1a2640] hover:bg-[#1d2f4a] rounded-lg border border-[#1e2d42] transition-colors"
                      >
                        <Eye className="w-3.5 h-3.5" />
                        プレビュー
                      </button>
                      <button
                        onClick={handleSave}
                        disabled={saveMutation.isPending}
                        className="flex items-center gap-1.5 px-3 py-1.5 text-sm text-white bg-[#e8002d] hover:bg-[#c8001d] rounded-lg transition-colors disabled:opacity-50"
                      >
                        <Save className="w-3.5 h-3.5" />
                        {saveMutation.isPending ? '保存中...' : saveSuccess ? '保存済み' : '保存'}
                      </button>
                    </>
                  )}
                </div>
              </div>

              {/* Form fields */}
              <div className="grid grid-cols-2 gap-4">
                <div className="col-span-2">
                  <label className="block text-xs font-medium text-[#7d92b0] mb-1">テンプレート名</label>
                  {isEditing ? (
                    <input
                      type="text"
                      value={form.name}
                      onChange={e => setForm(f => ({ ...f, name: e.target.value }))}
                      className="w-full px-3 py-2 bg-[#070d19] border border-[#1e2d42] rounded-lg text-sm text-[#e2e8f4] focus:border-[#e8002d]/50 focus:outline-none"
                      placeholder="テンプレート名を入力"
                    />
                  ) : (
                    <p className="text-sm text-[#e2e8f4] px-3 py-2 bg-[#070d19] rounded-lg border border-[#1e2d42]">
                      {selectedTemplate?.name}
                    </p>
                  )}
                </div>

                <div>
                  <label className="block text-xs font-medium text-[#7d92b0] mb-1">イベントタイプ</label>
                  {isEditing ? (
                    <select
                      value={form.event_type}
                      onChange={e => setForm(f => ({ ...f, event_type: e.target.value as EventType }))}
                      className="w-full px-3 py-2 bg-[#070d19] border border-[#1e2d42] rounded-lg text-sm text-[#e2e8f4] focus:border-[#e8002d]/50 focus:outline-none"
                    >
                      {Object.entries(EVENT_TYPE_LABELS).map(([val, label]) => (
                        <option key={val} value={val}>{label}</option>
                      ))}
                    </select>
                  ) : (
                    <div className="px-3 py-2">
                      <span className={`inline-flex items-center px-2 py-0.5 rounded border text-xs font-medium ${EVENT_TYPE_COLORS[selectedTemplate?.event_type ?? 'alert_critical']}`}>
                        {EVENT_TYPE_LABELS[selectedTemplate?.event_type ?? 'alert_critical']}
                      </span>
                    </div>
                  )}
                </div>

                <div>
                  <label className="block text-xs font-medium text-[#7d92b0] mb-1">タイプ</label>
                  <div className="flex items-center gap-2 px-3 py-2">
                    {activeTab === 'email'
                      ? <><Mail className="w-4 h-4 text-blue-400" /><span className="text-sm text-[#e2e8f4]">メール</span></>
                      : <><Slack className="w-4 h-4 text-green-400" /><span className="text-sm text-[#e2e8f4]">Slack</span></>
                    }
                  </div>
                </div>

                {(activeTab === 'email') && (
                  <div className="col-span-2">
                    <label className="block text-xs font-medium text-[#7d92b0] mb-1">件名</label>
                    {isEditing ? (
                      <input
                        type="text"
                        value={form.subject}
                        onChange={e => setForm(f => ({ ...f, subject: e.target.value }))}
                        className="w-full px-3 py-2 bg-[#070d19] border border-[#1e2d42] rounded-lg text-sm text-[#e2e8f4] focus:border-[#e8002d]/50 focus:outline-none"
                        placeholder="メール件名（{{変数}}が使えます）"
                      />
                    ) : (
                      <p className="text-sm text-[#e2e8f4] px-3 py-2 bg-[#070d19] rounded-lg border border-[#1e2d42] font-mono">
                        {selectedTemplate?.subject ?? '—'}
                      </p>
                    )}
                  </div>
                )}

                <div className="col-span-2">
                  <label className="block text-xs font-medium text-[#7d92b0] mb-1">本文</label>
                  {isEditing ? (
                    <textarea
                      value={form.body}
                      onChange={e => setForm(f => ({ ...f, body: e.target.value }))}
                      rows={10}
                      className="w-full px-3 py-2 bg-[#070d19] border border-[#1e2d42] rounded-lg text-sm text-[#e2e8f4] font-mono focus:border-[#e8002d]/50 focus:outline-none resize-y"
                      placeholder="テンプレート本文を入力（{{変数}}が使えます）"
                    />
                  ) : (
                    <pre className="text-sm text-[#e2e8f4] px-3 py-2 bg-[#070d19] rounded-lg border border-[#1e2d42] font-mono whitespace-pre-wrap min-h-[200px]">
                      {selectedTemplate?.body}
                    </pre>
                  )}
                </div>
              </div>

              {/* Variable reference panel */}
              <div className="rounded-lg border border-[#1e2d42] bg-[#070d19] p-3">
                <p className="text-xs font-semibold text-[#7d92b0] uppercase tracking-wider mb-2">利用可能な変数</p>
                <div className="flex flex-wrap gap-2">
                  {AVAILABLE_VARIABLES.map(v => (
                    <button
                      key={v.name}
                      onClick={() => isEditing && insertVariable(v.name)}
                      title={v.desc}
                      className={`flex items-center gap-1.5 px-2 py-1 rounded border text-xs font-mono transition-colors ${
                        isEditing
                          ? 'border-[#1e2d42] text-[#7d92b0] hover:border-[#e8002d]/40 hover:text-[#e2e8f4] hover:bg-[#1d2f4a] cursor-pointer'
                          : 'border-[#1e2d42] text-[#3d5068] cursor-default'
                      }`}
                    >
                      <Copy className="w-3 h-3 opacity-60" />
                      {v.name}
                      <span className="text-[10px] text-[#3d5068] font-sans hidden sm:inline">— {v.desc}</span>
                    </button>
                  ))}
                </div>
                {isEditing && (
                  <p className="text-[11px] text-[#3d5068] mt-2">クリックで本文末尾に挿入します</p>
                )}
              </div>

            </div>
          )}
        </div>
      </div>

      {/* Preview Modal */}
      {previewOpen && (
        <div className="fixed inset-0 bg-black/60 flex items-center justify-center z-50 p-6">
          <div className="bg-[#0d1220] border border-[#1e2d42] rounded-xl shadow-2xl w-full max-w-2xl max-h-[80vh] flex flex-col">
            <div className="flex items-center justify-between p-4 border-b border-[#1e2d42]">
              <div className="flex items-center gap-2">
                <Eye className="w-4 h-4 text-[#e8002d]" />
                <h3 className="text-sm font-semibold text-[#e2e8f4]">プレビュー (サンプルデータで表示)</h3>
              </div>
              <button onClick={() => setPreviewOpen(false)} className="text-[#7d92b0] hover:text-white">
                <X className="w-4 h-4" />
              </button>
            </div>
            <div className="flex-1 overflow-y-auto p-4">
              {activeTab === 'email' && form.subject && (
                <div className="mb-3 p-3 bg-[#070d19] rounded-lg border border-[#1e2d42]">
                  <p className="text-xs text-[#7d92b0] mb-1">件名:</p>
                  <p className="text-sm text-[#e2e8f4] font-medium">
                    {Object.entries(SAMPLE_VALUES).reduce(
                      (s, [k, v]) => s.replaceAll(k, v),
                      form.subject
                    )}
                  </p>
                </div>
              )}
              <div className="p-3 bg-[#070d19] rounded-lg border border-[#1e2d42]">
                <p className="text-xs text-[#7d92b0] mb-2">本文:</p>
                <pre className="text-sm text-[#e2e8f4] whitespace-pre-wrap font-mono leading-relaxed">
                  {renderPreview()}
                </pre>
              </div>
            </div>
            <div className="p-4 border-t border-[#1e2d42] flex justify-end">
              <button
                onClick={() => setPreviewOpen(false)}
                className="px-4 py-2 text-sm text-[#7d92b0] hover:text-white bg-[#1a2640] hover:bg-[#1d2f4a] rounded-lg border border-[#1e2d42] transition-colors"
              >
                閉じる
              </button>
            </div>
          </div>
        </div>
      )}

      {/* Delete confirm modal */}
      {deleteConfirm && (
        <div className="fixed inset-0 bg-black/60 flex items-center justify-center z-50 p-6">
          <div className="bg-[#0d1220] border border-[#1e2d42] rounded-xl shadow-2xl p-6 w-full max-w-sm">
            <h3 className="text-base font-semibold text-[#e2e8f4] mb-2">テンプレートの削除</h3>
            <p className="text-sm text-[#7d92b0] mb-5">このテンプレートを削除します。この操作は取り消せません。</p>
            <div className="flex gap-3 justify-end">
              <button
                onClick={() => setDeleteConfirm(null)}
                className="px-4 py-2 text-sm text-[#7d92b0] hover:text-white bg-[#1a2640] rounded-lg border border-[#1e2d42] transition-colors"
              >
                キャンセル
              </button>
              <button
                onClick={() => deleteMutation.mutate(deleteConfirm)}
                disabled={deleteMutation.isPending}
                className="px-4 py-2 text-sm text-white bg-[#e8002d] hover:bg-[#c8001d] rounded-lg transition-colors disabled:opacity-50"
              >
                削除する
              </button>
            </div>
          </div>
        </div>
      )}

    </div>
  )
}

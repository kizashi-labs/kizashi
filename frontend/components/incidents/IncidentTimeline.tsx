'use client'

import React, { useState } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { apiFetch } from '@/lib/api'
import { AlertTriangle, MessageSquare, Activity, Shield, Send, Clock, User } from 'lucide-react'

// ── Types ────────────────────────────────────────────────────────

interface TimelineItem {
  id: string
  type: 'alert' | 'comment' | 'status_change' | 'action'
  timestamp: string
  title: string
  description?: string
  severity?: number
  user?: string
  metadata?: Record<string, unknown>
}

interface IncidentTimelineProps {
  incidentId: string
}

// Raw API shapes
interface ApiAlert {
  alert_id: string
  title: string
  severity: number
  status: string
  hostname: string
  created_at: string
  linked_at: string
}

interface ApiNote {
  id: string
  user_name: string
  body: string
  created_at: string
}

interface IncidentDetail {
  incident: {
    id: string
    title: string
    status: string
    severity: number
    created_at: string
    updated_at: string
    resolved_at?: string
    assigned_to_name: string
    created_by_name: string
  }
  alerts: ApiAlert[]
}

interface NotesResponse {
  data: ApiNote[]
}

// ── Helpers ──────────────────────────────────────────────────────

function severityLabel(s: number): string {
  if (s >= 9) return 'CRITICAL'
  if (s >= 7) return 'HIGH'
  if (s >= 5) return 'MEDIUM'
  if (s >= 3) return 'LOW'
  return 'INFO'
}

function severityBadgeClass(s: number): string {
  if (s >= 9) return 'bg-red-900/40 text-red-300 border border-red-800/60'
  if (s >= 7) return 'bg-orange-900/40 text-orange-300 border border-orange-800/60'
  if (s >= 5) return 'bg-yellow-900/40 text-yellow-300 border border-yellow-800/60'
  if (s >= 3) return 'bg-blue-900/40 text-blue-300 border border-blue-800/60'
  return 'bg-gray-800/60 text-gray-400 border border-gray-700/60'
}

// Dot color class per timeline item type
const TYPE_DOT: Record<TimelineItem['type'], string> = {
  alert:         'bg-red-500',
  action:        'bg-blue-500',
  comment:       'bg-gray-500',
  status_change: 'bg-yellow-500',
}

const TYPE_LINE: Record<TimelineItem['type'], string> = {
  alert:         'border-red-900/60',
  action:        'border-blue-900/60',
  comment:       'border-gray-700/60',
  status_change: 'border-yellow-900/60',
}

function ItemIcon({ type }: { type: TimelineItem['type'] }) {
  const cls = 'w-3.5 h-3.5'
  switch (type) {
    case 'alert':         return <AlertTriangle  className={`${cls} text-red-400`} />
    case 'comment':       return <MessageSquare  className={`${cls} text-gray-400`} />
    case 'status_change': return <Activity       className={`${cls} text-yellow-400`} />
    case 'action':        return <Shield         className={`${cls} text-blue-400`} />
  }
}

function typeLabel(type: TimelineItem['type']): string {
  switch (type) {
    case 'alert':         return 'アラート'
    case 'comment':       return 'コメント'
    case 'status_change': return 'ステータス変更'
    case 'action':        return 'アクション'
  }
}

// ── Build timeline from incident + alerts + notes ────────────────

function buildTimeline(
  detail: IncidentDetail,
  notes: ApiNote[],
): TimelineItem[] {
  const items: TimelineItem[] = []

  // Incident created event
  items.push({
    id:        `inc-created-${detail.incident.id}`,
    type:      'status_change',
    timestamp: detail.incident.created_at,
    title:     'インシデント作成',
    description: detail.incident.title,
    user:      detail.incident.created_by_name || undefined,
    metadata:  { status: detail.incident.status },
  })

  // Resolved event
  if (detail.incident.resolved_at) {
    items.push({
      id:        `inc-resolved-${detail.incident.id}`,
      type:      'status_change',
      timestamp: detail.incident.resolved_at,
      title:     'インシデント解決',
      user:      detail.incident.assigned_to_name || undefined,
      metadata:  { status: 'resolved' },
    })
  }

  // Linked alerts → use linked_at as the event time
  for (const a of detail.alerts) {
    items.push({
      id:          `alert-${a.alert_id}`,
      type:        'alert',
      timestamp:   a.linked_at || a.created_at,
      title:       a.title || '(タイトルなし)',
      description: `ホスト: ${a.hostname}  ステータス: ${a.status}`,
      severity:    a.severity,
      metadata:    { alert_id: a.alert_id },
    })
  }

  // Notes as comments
  for (const n of notes) {
    items.push({
      id:          `note-${n.id}`,
      type:        'comment',
      timestamp:   n.created_at,
      title:       'コメント追加',
      description: n.body,
      user:        n.user_name,
    })
  }

  // Sort newest-first
  items.sort((a, b) => new Date(b.timestamp).getTime() - new Date(a.timestamp).getTime())
  return items
}

// ── Main component ────────────────────────────────────────────────

export function IncidentTimeline({ incidentId }: IncidentTimelineProps) {
  const qc = useQueryClient()
  const [commentBody, setCommentBody] = useState('')

  const { data: detail, isLoading: loadingDetail } = useQuery<IncidentDetail>({
    queryKey: ['incident', incidentId],
    queryFn:  () => apiFetch(`/api/v1/incidents/${incidentId}`),
    enabled:  !!incidentId,
  })

  const { data: notesData, isLoading: loadingNotes } = useQuery<NotesResponse>({
    queryKey:       ['incident-notes', incidentId],
    queryFn:        () => apiFetch(`/api/v1/incidents/${incidentId}/notes`),
    enabled:        !!incidentId,
    refetchInterval: 30_000,
  })

  const addCommentMutation = useMutation({
    mutationFn: (body: string) =>
      apiFetch(`/api/v1/incidents/${incidentId}/notes`, {
        method: 'POST',
        body:   JSON.stringify({ body }),
      }),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['incident-notes', incidentId] })
      setCommentBody('')
    },
  })

  const isLoading = loadingDetail || loadingNotes
  const notes     = notesData?.data ?? []
  const items     = detail ? buildTimeline(detail, notes) : []

  return (
    <div className="bg-[#111827] border border-[#1e2d42] rounded-xl p-5">
      {/* Section header */}
      <div className="flex items-center gap-2 mb-5">
        <Activity size={18} className="text-yellow-400" />
        <h2 className="font-semibold text-[#e2e8f4]">タイムライン</h2>
        {!isLoading && (
          <span className="text-xs text-[#5a6a7a] ml-auto">{items.length} 件のイベント</span>
        )}
      </div>

      {/* Loading state */}
      {isLoading && (
        <div className="py-10 text-center text-[#5a6a7a] text-sm">読み込み中...</div>
      )}

      {/* Empty state */}
      {!isLoading && items.length === 0 && (
        <div className="py-10 text-center text-[#5a6a7a] text-sm">タイムラインイベントがありません</div>
      )}

      {/* Timeline list */}
      {!isLoading && items.length > 0 && (
        <ol className="relative">
          {items.map((item, idx) => {
            const isLast = idx === items.length - 1
            return (
              <li key={item.id} className="flex gap-4 group">
                {/* Left column: dot + line */}
                <div className="flex flex-col items-center flex-shrink-0 w-6">
                  {/* Dot */}
                  <div className={`w-3 h-3 rounded-full mt-1 flex-shrink-0 ring-2 ring-[#111827] ${TYPE_DOT[item.type]}`} />
                  {/* Connector line */}
                  {!isLast && (
                    <div className={`flex-1 w-px border-l-2 border-dashed mt-1 mb-0 ${TYPE_LINE[item.type]}`} style={{ minHeight: '2rem' }} />
                  )}
                </div>

                {/* Right column: content */}
                <div className={`flex-1 min-w-0 ${isLast ? 'pb-0' : 'pb-5'}`}>
                  {/* Type label + timestamp row */}
                  <div className="flex flex-wrap items-center gap-2 mb-1">
                    <span className="flex items-center gap-1 text-[10px] font-semibold uppercase tracking-wider text-[#5a6a7a]">
                      <ItemIcon type={item.type} />
                      {typeLabel(item.type)}
                    </span>
                    {item.severity !== undefined && (
                      <span className={`text-[10px] font-bold px-1.5 py-0.5 rounded ${severityBadgeClass(item.severity)}`}>
                        {severityLabel(item.severity)} Lv{item.severity}
                      </span>
                    )}
                    <span className="ml-auto text-[10px] text-[#3d5068] flex items-center gap-0.5 font-mono flex-shrink-0">
                      <Clock size={9} />
                      {new Date(item.timestamp).toLocaleString('ja-JP')}
                    </span>
                  </div>

                  {/* Title */}
                  <p className="text-sm font-medium text-[#e2e8f4] leading-snug">{item.title}</p>

                  {/* Description */}
                  {item.description && (
                    <p className="text-xs text-[#8899aa] mt-1 whitespace-pre-wrap leading-relaxed">{item.description}</p>
                  )}

                  {/* User attribution */}
                  {item.user && (
                    <div className="flex items-center gap-1 mt-1.5 text-[10px] text-[#3d5068]">
                      <User size={9} />
                      {item.user}
                    </div>
                  )}
                </div>
              </li>
            )
          })}
        </ol>
      )}

      {/* Add Comment form */}
      <div className="mt-5 pt-4 border-t border-[#1e2d42]">
        <p className="text-xs text-[#5a6a7a] mb-2 flex items-center gap-1">
          <MessageSquare size={11} />
          コメントを追加
        </p>
        <div className="flex gap-2">
          <textarea
            value={commentBody}
            onChange={e => setCommentBody(e.target.value)}
            onKeyDown={e => {
              if (e.key === 'Enter' && (e.ctrlKey || e.metaKey) && commentBody.trim()) {
                addCommentMutation.mutate(commentBody.trim())
              }
            }}
            placeholder="コメントを入力... (Ctrl+Enter で送信)"
            rows={2}
            className="flex-1 bg-[#080c14] border border-[#1e2d42] rounded-lg px-3 py-2 text-sm
                       text-[#e2e8f4] placeholder-[#3d5068] resize-none
                       focus:outline-none focus:border-yellow-600/60 transition-colors"
          />
          <button
            onClick={() => commentBody.trim() && addCommentMutation.mutate(commentBody.trim())}
            disabled={!commentBody.trim() || addCommentMutation.isPending}
            className="self-end flex items-center gap-1.5 px-4 py-2 text-sm
                       bg-yellow-700 hover:bg-yellow-600 text-white rounded-lg
                       disabled:opacity-50 transition-colors flex-shrink-0"
          >
            <Send size={13} />
            {addCommentMutation.isPending ? '送信中...' : '送信'}
          </button>
        </div>
        {addCommentMutation.isError && (
          <p className="text-red-400 text-xs mt-1">コメントの送信に失敗しました</p>
        )}
      </div>
    </div>
  )
}

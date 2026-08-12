'use client'

import React, { useState, useEffect, useMemo } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { apiFetch } from '@/lib/api'
import { useCanWrite } from '@/lib/auth'
import { useRouter } from 'next/navigation'
import {
  Siren,
  MessageSquare,
  FileText,
  Clock,
  ChevronLeft,
  User,
  Check,
  Trash2,
  Send,
  GitBranch,
  Link,
  Phone,
  Mail,
  Slack,
  AlertTriangle,
  Users,
  ArrowUpCircle,
  PlusCircle,
  X,
  Shield,
  BookOpen,
  Download,
  ListChecks,
  Filter,
  Activity,
  ExternalLink,
} from 'lucide-react'

// ─── Types ────────────────────────────────────────────────────────────────────

interface Incident {
  id: string
  title: string
  description: string
  severity: number
  status: string
  assigned_to?: string
  assigned_to_name: string
  alert_count: number
  created_at: string
  updated_at: string
  resolved_at?: string
}

interface Comment {
  id: string
  incident_id: string
  user_id: string
  user_name?: string
  body: string
  created_at: string
}

interface Note {
  id: string
  user_name?: string
  user_id?: string
  body: string
  created_at: string
}

interface UserItem {
  id: string
  email: string
  full_name: string
}

// Communications
interface CommEntry {
  id: string
  incident_id: string
  type: string
  recipient: string
  summary: string
  logged_by?: string
  logged_by_name?: string
  created_at: string
}

// Escalation
interface EscalationEntry {
  id: string
  incident_id: string
  escalated_by?: string
  escalated_by_name?: string
  escalated_to?: string
  escalated_to_name?: string
  urgency: string
  reason: string
  created_at: string
}

// Responders
interface ResponderEntry {
  id: string
  incident_id: string
  user_id: string
  user_name?: string
  user_email?: string
  role: string
  added_at: string
}

// Post-Mortem
interface PostMortem {
  id?: string
  incident_id: string
  root_cause: string
  affected_systems: string
  affected_users: string
  duration_minutes: number
  lessons_learned: string
  action_items: ActionItem[]
  created_at?: string
  updated_at?: string
}

interface ActionItem {
  id: string
  text: string
  done: boolean
}

// ─── Helpers ──────────────────────────────────────────────────────────────────

const STATUS_LABELS: Record<string, string> = {
  open: '未対応',
  investigating: '調査中',
  contained: '封じ込め済み',
  resolved: '解決済み',
  closed: 'クローズ',
}

const STATUS_COLORS: Record<string, string> = {
  open: 'bg-red-900/50 text-red-300',
  investigating: 'bg-orange-900/50 text-orange-300',
  contained: 'bg-yellow-900/50 text-yellow-300',
  resolved: 'bg-green-900/50 text-green-300',
  closed: 'bg-[#161f33] text-[#8899aa]',
}

const NEXT_STATUSES: Record<string, string[]> = {
  open: ['investigating'],
  investigating: ['contained', 'resolved'],
  contained: ['resolved'],
  resolved: ['closed'],
  closed: [],
}

const PREV_STATUSES: Record<string, string[]> = {
  open: [],
  investigating: ['open'],
  contained: ['investigating'],
  resolved: ['investigating', 'contained'],
  closed: ['resolved'],
}

function severityColor(s: number) {
  if (s >= 9) return 'text-red-400'
  if (s >= 7) return 'text-orange-400'
  if (s >= 5) return 'text-yellow-400'
  return 'text-blue-400'
}

function severityBgBorder(s: number) {
  if (s >= 9) return 'bg-red-900/30 border-red-700/60'
  if (s >= 7) return 'bg-orange-900/30 border-orange-700/60'
  if (s >= 5) return 'bg-yellow-900/30 border-yellow-700/60'
  return 'bg-blue-900/30 border-blue-700/60'
}

function formatDate(iso: string) {
  return new Date(iso).toLocaleString('ja-JP', {
    year: 'numeric',
    month: '2-digit',
    day: '2-digit',
    hour: '2-digit',
    minute: '2-digit',
  })
}

function truncateUUID(uuid: string) {
  return uuid.length > 13 ? `${uuid.slice(0, 8)}…` : uuid
}

// ─── Tabs ─────────────────────────────────────────────────────────────────────

type TabKey =
  | 'overview'
  | 'comments'
  | 'notes'
  | 'timeline'
  | 'comms'
  | 'escalation'
  | 'responders'
  | 'postmortem'
  | 'playbook'

const TABS: { key: TabKey; label: string; icon: React.ReactNode }[] = [
  { key: 'overview',    label: '概要',           icon: <Siren size={14} /> },
  { key: 'comments',   label: 'コメント',        icon: <MessageSquare size={14} /> },
  { key: 'notes',      label: 'ノート',          icon: <FileText size={14} /> },
  { key: 'timeline',   label: 'タイムライン',    icon: <Clock size={14} /> },
  { key: 'comms',      label: 'コミュニケーション', icon: <Mail size={14} /> },
  { key: 'escalation', label: 'エスカレーション', icon: <ArrowUpCircle size={14} /> },
  { key: 'responders', label: 'レスポンダー',    icon: <Users size={14} /> },
  { key: 'postmortem', label: 'ポストモーテム',  icon: <BookOpen size={14} /> },
  { key: 'playbook',   label: 'プレイブック',    icon: <ListChecks size={14} /> },
]

// ─── Main Page ────────────────────────────────────────────────────────────────

export default function IncidentDetailPage({ params }: { params: { id: string } }) {
  const { id } = params
  const router = useRouter()
  const qc = useQueryClient()
  const canWrite = useCanWrite()
  const [activeTab, setActiveTab] = useState<TabKey>('overview')
  const [confirmDelete, setConfirmDelete] = useState(false)

  const deleteMutation = useMutation({
    mutationFn: () => apiFetch(`/api/v1/incidents/${id}`, { method: 'DELETE' }),
    onSuccess: () => router.push('/incidents'),
    onError: (err: Error) => alert(`削除に失敗しました: ${err.message}`),
  })

  // ── Incident ──────────────────────────────────────────────────────────────

  const { data: incidentData, isLoading } = useQuery<{ incident?: Incident } | Incident>({
    queryKey: ['incident', id],
    queryFn: () => apiFetch(`/api/v1/incidents/${id}`),
    enabled: !!id,
  })

  const inc: Incident | undefined = (() => {
    if (!incidentData) return undefined
    if ('incident' in (incidentData as { incident?: Incident })) {
      return (incidentData as { incident: Incident }).incident
    }
    return incidentData as Incident
  })()

  // ── Users ─────────────────────────────────────────────────────────────────

  const { data: usersData } = useQuery<{ users: UserItem[] } | { data: UserItem[] }>({
    queryKey: ['users-list'],
    queryFn: () => apiFetch('/api/v1/users?limit=50'),
  })
  const users: UserItem[] = (() => {
    if (!usersData) return []
    if ('users' in usersData) return (usersData as { users: UserItem[] }).users
    if ('data' in usersData) return (usersData as { data: UserItem[] }).data
    return []
  })()

  // ── Comments ──────────────────────────────────────────────────────────────

  const { data: commentsData } = useQuery<{ comments?: Comment[]; data?: Comment[] }>({
    queryKey: ['incident-comments', id],
    queryFn: () => apiFetch(`/api/v1/incidents/${id}/comments`),
    enabled: !!id,
    refetchInterval: 30_000,
  })
  const comments = commentsData?.comments ?? commentsData?.data ?? []

  const [commentBody, setCommentBody] = useState('')

  const addCommentMutation = useMutation({
    mutationFn: (body: string) =>
      apiFetch(`/api/v1/incidents/${id}/comments`, {
        method: 'POST',
        body: JSON.stringify({ body }),
      }),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['incident-comments', id] })
      setCommentBody('')
    },
  })

  const deleteCommentMutation = useMutation({
    mutationFn: (commentId: string) =>
      apiFetch(`/api/v1/incidents/${id}/comments/${commentId}`, { method: 'DELETE' }),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['incident-comments', id] }),
  })

  // ── Notes ─────────────────────────────────────────────────────────────────

  const { data: notesData } = useQuery<{ data?: Note[]; notes?: Note[] }>({
    queryKey: ['incident-notes', id],
    queryFn: () => apiFetch(`/api/v1/incidents/${id}/notes`),
    enabled: !!id,
  })
  const notes: Note[] = notesData?.data ?? notesData?.notes ?? []

  const [noteBody, setNoteBody] = useState('')

  const addNoteMutation = useMutation({
    mutationFn: (body: string) =>
      apiFetch(`/api/v1/incidents/${id}/notes`, {
        method: 'POST',
        body: JSON.stringify({ body }),
      }),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['incident-notes', id] })
      setNoteBody('')
    },
  })

  // ── Status transition ──────────────────────────────────────────────────────

  const statusMutation = useMutation({
    mutationFn: (status: string) =>
      apiFetch(`/api/v1/incidents/${id}/status`, {
        method: 'PATCH',
        body: JSON.stringify({ status }),
      }),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['incident', id] }),
  })

  // ── Assignee ──────────────────────────────────────────────────────────────

  const [selectedAssignee, setSelectedAssignee] = useState('')

  useEffect(() => {
    if (inc?.assigned_to) setSelectedAssignee(inc.assigned_to)
  }, [inc?.assigned_to])

  const assignMutation = useMutation({
    mutationFn: (assigned_to: string) =>
      apiFetch(`/api/v1/incidents/${id}/assign`, {
        method: 'PATCH',
        body: JSON.stringify({ assigned_to }),
      }),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['incident', id] }),
  })

  // ─────────────────────────────────────────────────────────────────────────

  if (isLoading) {
    return (
      <div className="min-h-screen bg-[#070d19] text-[#e2e8f4] flex items-center justify-center">
        <div className="text-[#7d92b0]">読み込み中...</div>
      </div>
    )
  }

  if (!inc) {
    return (
      <div className="min-h-screen bg-[#070d19] text-[#e2e8f4] flex flex-col items-center justify-center gap-4">
        <Siren size={48} className="text-red-400 opacity-40" />
        <p className="text-[#7d92b0]">インシデントが見つかりません</p>
        <button
          onClick={() => router.push('/incidents')}
          className="text-blue-400 hover:underline text-sm"
        >
          一覧に戻る
        </button>
      </div>
    )
  }

  const nextStatuses = NEXT_STATUSES[inc.status] ?? []
  const prevStatuses = PREV_STATUSES[inc.status] ?? []

  return (
    <div className="min-h-screen bg-[#070d19] text-[#e2e8f4] p-6">
      <div className="max-w-5xl mx-auto space-y-5">

        {/* Back button */}
        <button
          onClick={() => router.push('/incidents')}
          className="flex items-center gap-1.5 text-[#7d92b0] hover:text-white text-sm transition-colors"
        >
          <ChevronLeft size={16} />
          インシデント一覧
        </button>

        {/* Header card */}
        <div className={`bg-[#0d1220] border rounded-xl p-5 ${severityBgBorder(inc.severity)}`}>
          <div className="flex items-start gap-3 flex-wrap">
            <Siren className="text-red-400 flex-shrink-0 mt-0.5" size={22} />
            <div className="flex-1 min-w-0">
              <h1 className="text-xl font-bold leading-tight break-words">{inc.title}</h1>
              {inc.description && (
                <p className="text-[#7d92b0] text-sm mt-1 leading-relaxed">{inc.description}</p>
              )}
            </div>
            <div className="flex items-center gap-2 flex-shrink-0">
              <span className={`text-2xl font-bold ${severityColor(inc.severity)}`}>
                {inc.severity}
              </span>
              <span
                className={`text-xs px-2.5 py-1 rounded-full font-medium ${
                  STATUS_COLORS[inc.status] ?? 'bg-[#161f33] text-[#7d92b0]'
                }`}
              >
                {STATUS_LABELS[inc.status] ?? inc.status}
              </span>
            </div>
          </div>
          <div className="mt-3 flex items-center justify-between">
            <span className="text-xs text-[#5a6a7a]">作成: {formatDate(inc.created_at)}</span>
            {canWrite && (
              !confirmDelete ? (
                <button
                  onClick={() => setConfirmDelete(true)}
                  className="flex items-center gap-1.5 px-3 py-1.5 text-xs rounded-lg border border-red-800/60 text-red-400 hover:bg-red-900/20 transition-colors"
                >
                  <Trash2 size={12} />
                  削除
                </button>
              ) : (
                <div className="flex items-center gap-2">
                  <span className="text-xs text-red-400">本当に削除しますか？</span>
                  <button
                    onClick={() => deleteMutation.mutate()}
                    disabled={deleteMutation.isPending}
                    className="px-3 py-1.5 text-xs rounded-lg bg-red-900/40 border border-red-700/60 text-red-300 hover:bg-red-800/40 disabled:opacity-40 transition-colors"
                  >
                    {deleteMutation.isPending ? '削除中...' : '削除する'}
                  </button>
                  <button
                    onClick={() => setConfirmDelete(false)}
                    className="px-3 py-1.5 text-xs rounded-lg border border-[#1e2d42] text-[#7d92b0] hover:bg-[#111827] transition-colors"
                  >
                    キャンセル
                  </button>
                </div>
              )
            )}
          </div>
        </div>

        {/* Tabs */}
        <div className="flex gap-0 border-b border-[#1e2d42] overflow-x-auto">
          {TABS.map(tab => (
            <button
              key={tab.key}
              onClick={() => setActiveTab(tab.key)}
              className={`flex items-center gap-1.5 px-3 py-2.5 text-sm font-medium transition-colors border-b-2 -mb-px whitespace-nowrap ${
                activeTab === tab.key
                  ? 'border-[#e8002d] text-white'
                  : 'border-transparent text-[#7d92b0] hover:text-white'
              }`}
            >
              {tab.icon}
              {tab.label}
            </button>
          ))}
        </div>

        {/* Tab content */}
        {activeTab === 'overview' && (
          <OverviewTab
            inc={inc}
            users={users}
            nextStatuses={nextStatuses}
            prevStatuses={prevStatuses}
            selectedAssignee={selectedAssignee}
            setSelectedAssignee={setSelectedAssignee}
            onStatusChange={(s) => statusMutation.mutate(s)}
            onAssign={() => assignMutation.mutate(selectedAssignee)}
            statusPending={statusMutation.isPending}
            assignPending={assignMutation.isPending}
            canWrite={canWrite}
          />
        )}

        {activeTab === 'comments' && (
          <CommentsTab
            comments={comments}
            commentBody={commentBody}
            setCommentBody={setCommentBody}
            onAddComment={() => {
              if (commentBody.trim()) addCommentMutation.mutate(commentBody.trim())
            }}
            onDeleteComment={(cid) => deleteCommentMutation.mutate(cid)}
            addPending={addCommentMutation.isPending}
            deletePending={deleteCommentMutation.isPending}
            canWrite={canWrite}
          />
        )}

        {activeTab === 'notes' && (
          <NotesTab
            notes={notes}
            noteBody={noteBody}
            setNoteBody={setNoteBody}
            onAddNote={() => {
              if (noteBody.trim()) addNoteMutation.mutate(noteBody.trim())
            }}
            addPending={addNoteMutation.isPending}
            canWrite={canWrite}
          />
        )}

        {activeTab === 'timeline' && (
          <TimelineTab inc={inc} />
        )}

        {activeTab === 'comms' && (
          <CommsTab incidentId={id} />
        )}

        {activeTab === 'escalation' && (
          <EscalationTab incidentId={id} users={users} />
        )}

        {activeTab === 'responders' && (
          <RespondersTab incidentId={id} users={users} />
        )}

        {activeTab === 'postmortem' && (
          <PostMortemTab inc={inc} />
        )}

        {activeTab === 'playbook' && (
          <PlaybookTab inc={inc} />
        )}
      </div>
    </div>
  )
}

// ─── Elapsed Time Badge ───────────────────────────────────────────────────────

function ElapsedTimeBadge({ createdAt, resolvedAt }: { createdAt: string; resolvedAt?: string }) {
  const [elapsed, setElapsed] = useState('')

  useEffect(() => {
    const update = () => {
      const end = resolvedAt ? new Date(resolvedAt).getTime() : Date.now()
      const ms  = end - new Date(createdAt).getTime()
      if (ms < 0) { setElapsed('—'); return }
      const mins  = Math.floor(ms / 60_000)
      const hours = Math.floor(mins / 60)
      const days  = Math.floor(hours / 24)
      if (days > 0)  setElapsed(`${days}日 ${hours % 24}時間`)
      else if (hours > 0) setElapsed(`${hours}時間 ${mins % 60}分`)
      else setElapsed(`${mins}分`)
    }
    update()
    if (!resolvedAt) {
      const id = setInterval(update, 60_000)
      return () => clearInterval(id)
    }
  }, [createdAt, resolvedAt])

  const isResolved = !!resolvedAt
  return (
    <div className={`flex items-center gap-1.5 text-xs px-3 py-1.5 rounded-full border font-medium
      ${isResolved ? 'bg-green-900/20 text-green-400 border-green-700/40' : 'bg-orange-900/20 text-orange-400 border-orange-700/40 animate-pulse'}`}>
      <Activity size={11} />
      {isResolved ? '対応時間:' : '経過時間:'} {elapsed}
    </div>
  )
}

// ─── Linked Alerts Card ───────────────────────────────────────────────────────

interface LinkedAlert {
  alert_id: string
  title: string
  severity: number
  status: string
  mitre_technique?: string
  created_at: string
}

// ─── ATT&CK Kill-Chain ────────────────────────────────────────────────────────
// Ordered ATT&CK tactics (kill-chain stages). A correlation incident bundles the
// alerts of a multi-stage attack; visualising which stages are present makes the
// "多段攻撃" nature legible at a glance.
const KILL_CHAIN_TACTICS: { key: string; label: string }[] = [
  { key: 'reconnaissance',      label: '偵察' },
  { key: 'initial-access',      label: '初期アクセス' },
  { key: 'execution',           label: '実行' },
  { key: 'persistence',         label: '永続化' },
  { key: 'privilege-escalation',label: '権限昇格' },
  { key: 'defense-evasion',     label: '防御回避' },
  { key: 'credential-access',   label: '資格情報' },
  { key: 'discovery',           label: '探索' },
  { key: 'lateral-movement',    label: '横展開' },
  { key: 'collection',          label: '収集' },
  { key: 'command-and-control', label: 'C2' },
  { key: 'exfiltration',        label: '持ち出し' },
  { key: 'impact',              label: '影響' },
]

// tacticForTechnique maps an ATT&CK technique (T####[.###]) to its primary tactic.
// Mirrors the server-side map (killchain.go) for the techniques the detectors
// emit; unknown techniques fall through to '' and are shown separately.
const TECHNIQUE_TACTIC: Record<string, string> = {
  T1595:'reconnaissance',T1592:'reconnaissance',T1590:'reconnaissance',T1589:'reconnaissance',T1598:'reconnaissance',T1597:'reconnaissance',
  T1189:'initial-access',T1190:'initial-access',T1133:'initial-access',T1200:'initial-access',T1566:'initial-access',T1078:'initial-access',T1091:'initial-access',
  T1059:'execution',T1204:'execution',T1203:'execution',T1053:'execution',T1129:'execution',T1569:'execution',T1047:'execution',T1106:'execution',T1620:'execution',
  T1547:'persistence',T1543:'persistence',T1546:'persistence',T1136:'persistence',T1098:'persistence',T1197:'persistence',T1505:'persistence',T1574:'persistence',
  T1548:'privilege-escalation',T1134:'privilege-escalation',T1484:'privilege-escalation',T1068:'privilege-escalation',T1055:'privilege-escalation',
  T1562:'defense-evasion',T1070:'defense-evasion',T1027:'defense-evasion',T1140:'defense-evasion',T1036:'defense-evasion',T1564:'defense-evasion',T1218:'defense-evasion',T1497:'defense-evasion',T1222:'defense-evasion',T1112:'defense-evasion',T1006:'defense-evasion',T1211:'defense-evasion',
  T1003:'credential-access',T1552:'credential-access',T1555:'credential-access',T1110:'credential-access',T1212:'credential-access',T1187:'credential-access',T1056:'credential-access',T1558:'credential-access',T1621:'credential-access',
  T1087:'discovery',T1082:'discovery',T1083:'discovery',T1057:'discovery',T1016:'discovery',T1018:'discovery',T1046:'discovery',T1518:'discovery',T1201:'discovery',T1033:'discovery',T1069:'discovery',T1049:'discovery',T1007:'discovery',T1614:'discovery',T1526:'discovery',T1580:'discovery',
  T1021:'lateral-movement',T1080:'lateral-movement',T1550:'lateral-movement',T1563:'lateral-movement',T1570:'lateral-movement',T1210:'lateral-movement',
  T1005:'collection',T1039:'collection',T1025:'collection',T1114:'collection',T1213:'collection',T1560:'collection',T1119:'collection',T1113:'collection',T1115:'collection',T1074:'collection',
  T1071:'command-and-control',T1090:'command-and-control',T1095:'command-and-control',T1105:'command-and-control',T1132:'command-and-control',T1219:'command-and-control',T1568:'command-and-control',T1571:'command-and-control',T1573:'command-and-control',T1102:'command-and-control',
  T1041:'exfiltration',T1048:'exfiltration',T1567:'exfiltration',T1052:'exfiltration',T1011:'exfiltration',T1029:'exfiltration',
  T1485:'impact',T1486:'impact',T1490:'impact',T1489:'impact',T1491:'impact',T1529:'impact',T1561:'impact',T1499:'impact',T1498:'impact',T1531:'impact',
}

function tacticForTechnique(t: string): string {
  const base = t.trim().toUpperCase().split('.')[0]
  return TECHNIQUE_TACTIC[base] ?? ''
}

// KillChainStrip renders the ordered ATT&CK tactics observed across an incident's
// linked alerts, highlighting the stages the attack traversed. Only shown when at
// least one linked alert carries a MITRE technique. Reuses the same query key as
// LinkedAlertsCard so it shares the cached response (no extra request).
function KillChainStrip({ incidentId }: { incidentId: string }) {
  const { data } = useQuery<{ alerts?: LinkedAlert[] }>({
    queryKey: ['incident-alerts', incidentId],
    queryFn: () => apiFetch(`/api/v1/incidents/${incidentId}`),
    staleTime: 30_000,
  })
  const alerts: LinkedAlert[] = data?.alerts ?? []

  const { tacticTechniques, stageCount } = useMemo(() => {
    const map: Record<string, Set<string>> = {}
    for (const a of alerts) {
      const tech = a.mitre_technique?.trim()
      if (!tech) continue
      const tac = tacticForTechnique(tech)
      if (!tac) continue
      ;(map[tac] ??= new Set()).add(tech.toUpperCase())
    }
    return { tacticTechniques: map, stageCount: Object.keys(map).length }
  }, [alerts])

  if (stageCount === 0) return null

  return (
    <div className="bg-[#0d1220] border border-[#1e2d42] rounded-xl p-5">
      <div className="flex items-center gap-2 mb-4">
        <GitBranch size={14} className="text-red-400" />
        <h2 className="text-sm font-semibold text-[#7d92b0] uppercase tracking-wider">
          ATT&CK キルチェーン
        </h2>
        <span className="text-xs text-[#5a6a7a]">{stageCount} 戦術を観測</span>
      </div>
      <div className="flex items-stretch gap-1 overflow-x-auto pb-1">
        {KILL_CHAIN_TACTICS.map((stage, idx) => {
          const techs = tacticTechniques[stage.key]
          const present = !!techs && techs.size > 0
          return (
            <React.Fragment key={stage.key}>
              {idx > 0 && (
                <div className="flex items-center flex-shrink-0">
                  <span className={present || tacticTechniques[KILL_CHAIN_TACTICS[idx - 1].key] ? 'text-[#3d5068]' : 'text-[#1a2337]'}>›</span>
                </div>
              )}
              <div
                className={`flex-shrink-0 min-w-[76px] rounded-lg border px-2 py-2 text-center transition-colors ${
                  present
                    ? 'bg-red-900/25 border-red-700/50'
                    : 'bg-[#070d19]/40 border-[#161f33]'
                }`}
                title={present ? `${stage.label}: ${Array.from(techs!).sort().join(', ')}` : `${stage.label}（未観測）`}
              >
                <div className={`text-[11px] font-medium ${present ? 'text-red-300' : 'text-[#3d5068]'}`}>
                  {stage.label}
                </div>
                {present ? (
                  <div className="mt-1 flex flex-wrap gap-0.5 justify-center">
                    {Array.from(techs!).sort().slice(0, 3).map(tech => (
                      <span key={tech} className="text-[9px] px-1 py-0.5 rounded bg-red-950/60 text-red-200 font-mono leading-none">
                        {tech}
                      </span>
                    ))}
                    {techs!.size > 3 && (
                      <span className="text-[9px] text-red-300/70">+{techs!.size - 3}</span>
                    )}
                  </div>
                ) : (
                  <div className="mt-1 text-[9px] text-[#26344a]">—</div>
                )}
              </div>
            </React.Fragment>
          )
        })}
      </div>
    </div>
  )
}

function LinkedAlertsCard({ incidentId }: { incidentId: string }) {
  const qc = useQueryClient()
  const [showLink, setShowLink] = useState(false)
  const [selectedAlertId, setSelectedAlertId] = useState('')

  const { data, isLoading } = useQuery<{ incident?: unknown; alerts?: LinkedAlert[] }>({
    queryKey: ['incident-alerts', incidentId],
    queryFn: () => apiFetch(`/api/v1/incidents/${incidentId}`),
    staleTime: 30_000,
  })

  const alerts: LinkedAlert[] = data?.alerts ?? []

  const { data: alertsData } = useQuery<{ data?: { id: string; title: string; severity: number }[] }>({
    queryKey: ['alerts-for-link'],
    queryFn: () => apiFetch('/api/v1/alerts?per_page=100'),
    enabled: showLink,
    staleTime: 30_000,
  })
  const availableAlerts = (alertsData?.data ?? []).filter(
    a => !alerts.some(linked => linked.alert_id === a.id)
  )

  const linkMutation = useMutation({
    mutationFn: (alertId: string) =>
      apiFetch(`/api/v1/incidents/${incidentId}/alerts`, {
        method: 'POST',
        body: JSON.stringify({ alert_id: alertId }),
      }),
    onSuccess: () => {
      setSelectedAlertId('')
      setShowLink(false)
      qc.invalidateQueries({ queryKey: ['incident-alerts', incidentId] })
    },
  })

  const unlinkMutation = useMutation({
    mutationFn: (alertId: string) =>
      apiFetch(`/api/v1/incidents/${incidentId}/alerts/${alertId}`, { method: 'DELETE' }),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['incident-alerts', incidentId] }),
  })

  const SEV_COLOR: Record<number, string> = {
    10: 'text-red-400', 9: 'text-red-400', 8: 'text-red-300',
    7: 'text-orange-400', 6: 'text-orange-300',
    5: 'text-yellow-400', 4: 'text-yellow-300',
    3: 'text-blue-400', 2: 'text-blue-300', 1: 'text-blue-200',
  }

  if (isLoading) {
    return (
      <div className="bg-[#0d1220] border border-[#1e2d42] rounded-xl p-5 animate-pulse">
        <div className="h-4 bg-[#1e2d42] rounded w-1/3 mb-3" />
        <div className="space-y-2">{[0, 1, 2].map(i => <div key={i} className="h-8 bg-[#161f33] rounded" />)}</div>
      </div>
    )
  }

  return (
    <div className="bg-[#0d1220] border border-[#1e2d42] rounded-xl p-5">
      <div className="flex items-center gap-2 mb-3">
        <Link size={14} className="text-red-400" />
        <h2 className="text-sm font-semibold text-[#7d92b0] uppercase tracking-wider">
          リンクされたアラート
        </h2>
        <span className="text-xs text-[#5a6a7a]">{alerts.length}件</span>
        <button
          onClick={() => setShowLink(v => !v)}
          className="ml-auto flex items-center gap-1 px-2 py-1 text-xs rounded-lg bg-[#111827] border border-[#1e2d42] text-[#7d92b0] hover:text-cyan-300 hover:border-cyan-700/60 transition-colors"
        >
          <PlusCircle size={12} />
          追加
        </button>
      </div>

      {showLink && (
        <div className="mb-3 space-y-2">
          <div className="flex gap-2">
            <select
              value={selectedAlertId}
              onChange={e => setSelectedAlertId(e.target.value)}
              className="flex-1 px-3 py-1.5 text-xs bg-[#070d19] border border-[#1e2d42] rounded-lg text-[#c9d6e8] focus:outline-none focus:border-cyan-700/60"
            >
              <option value="">アラートを選択…</option>
              {availableAlerts.map(a => (
                <option key={a.id} value={a.id}>
                  [{a.severity}] {a.title}
                </option>
              ))}
            </select>
            <button
              onClick={() => selectedAlertId && linkMutation.mutate(selectedAlertId)}
              disabled={!selectedAlertId || linkMutation.isPending}
              className="px-3 py-1.5 text-xs rounded-lg bg-cyan-900/40 border border-cyan-700/60 text-cyan-300 hover:bg-cyan-800/40 disabled:opacity-40 disabled:cursor-not-allowed transition-colors"
            >
              リンク
            </button>
            <button onClick={() => setShowLink(false)} className="text-[#4a6080] hover:text-[#7d92b0]">
              <X size={14} />
            </button>
          </div>
        </div>
      )}
      {linkMutation.isError && (
        <p className="text-xs text-red-400 mb-2">リンクに失敗しました。アラートIDを確認してください。</p>
      )}

      {alerts.length === 0 ? (
        <p className="text-xs text-[#4a6080]">リンクされたアラートなし</p>
      ) : (
        <div className="space-y-2">
          {alerts.slice(0, 8).map(a => (
            <div key={a.alert_id} className="flex items-center gap-3 px-3 py-2 rounded-lg hover:bg-[#161f33] transition-colors group">
              <span className={`text-sm font-bold flex-shrink-0 ${SEV_COLOR[a.severity] ?? 'text-[#5a6a7a]'}`}>
                {a.severity}
              </span>
              <a href={`/alerts/${a.alert_id}`} className="text-xs text-[#e2e8f4] flex-1 truncate group-hover:text-white transition-colors">
                {a.title}
              </a>
              {a.mitre_technique && (
                <span className="flex-shrink-0 text-[10px] font-mono px-1.5 py-0.5 rounded bg-[#161f33] text-[#8ba3c7] border border-[#22304a]">
                  {a.mitre_technique}
                </span>
              )}
              <button
                onClick={() => unlinkMutation.mutate(a.alert_id)}
                className="opacity-0 group-hover:opacity-100 transition-opacity text-[#4a6080] hover:text-red-400 p-0.5"
                title="リンク解除"
              >
                <X size={12} />
              </button>
              <a href={`/alerts/${a.alert_id}`}>
                <ExternalLink size={11} className="text-[#3d5068] opacity-0 group-hover:opacity-100 transition-opacity" />
              </a>
            </div>
          ))}
          {alerts.length > 8 && (
            <p className="text-xs text-[#5a6a7a] pl-3">他 {alerts.length - 8}件…</p>
          )}
        </div>
      )}
    </div>
  )
}

// ─── Overview Tab ─────────────────────────────────────────────────────────────

function OverviewTab({
  inc,
  users,
  nextStatuses,
  prevStatuses,
  selectedAssignee,
  setSelectedAssignee,
  onStatusChange,
  onAssign,
  statusPending,
  assignPending,
  canWrite,
}: {
  inc: Incident
  users: UserItem[]
  nextStatuses: string[]
  prevStatuses: string[]
  selectedAssignee: string
  setSelectedAssignee: (v: string) => void
  onStatusChange: (s: string) => void
  onAssign: () => void
  statusPending: boolean
  assignPending: boolean
  canWrite: boolean
}) {
  const TRANSITION_COLORS: Record<string, string> = {
    investigating: 'bg-orange-800 hover:bg-orange-700 text-orange-100',
    contained: 'bg-yellow-800 hover:bg-yellow-700 text-yellow-100',
    resolved: 'bg-green-800 hover:bg-green-700 text-green-100',
    closed: 'bg-[#1e2d42] hover:bg-[#253649] text-[#7d92b0]',
  }

  return (
    <div className="space-y-4">
      {/* Elapsed time banner */}
      <div className="flex items-center gap-3 flex-wrap">
        <ElapsedTimeBadge createdAt={inc.created_at} resolvedAt={inc.resolved_at} />
        {inc.resolved_at && (
          <span className="text-xs text-green-400">解決済み ✓</span>
        )}
      </div>

      <div className="bg-[#0d1220] border border-[#1e2d42] rounded-xl p-5">
        <h2 className="text-sm font-semibold text-[#7d92b0] uppercase tracking-wider mb-4">
          インシデント情報
        </h2>
        <div className="grid grid-cols-2 md:grid-cols-3 gap-4 text-sm">
          <InfoCell label="ステータス">
            <span
              className={`inline-block text-xs px-2.5 py-1 rounded-full font-medium ${
                STATUS_COLORS[inc.status] ?? 'bg-[#161f33] text-[#7d92b0]'
              }`}
            >
              {STATUS_LABELS[inc.status] ?? inc.status}
            </span>
          </InfoCell>

          <InfoCell label="重大度">
            <span className={`text-2xl font-bold ${severityColor(inc.severity)}`}>
              {inc.severity}
            </span>
          </InfoCell>

          <InfoCell label="担当者">
            <span className="flex items-center gap-1.5">
              <User size={13} className="text-[#5a6a7a]" />
              {inc.assigned_to_name || '未割当'}
            </span>
          </InfoCell>

          <InfoCell label="アラート数">
            <span className="text-lg font-semibold">{inc.alert_count}</span>
          </InfoCell>

          <InfoCell label="作成日時">
            <span className="text-[#7d92b0] text-xs">{formatDate(inc.created_at)}</span>
          </InfoCell>

          <InfoCell label="更新日時">
            <span className="text-[#7d92b0] text-xs">{formatDate(inc.updated_at)}</span>
          </InfoCell>

          {inc.resolved_at && (
            <InfoCell label="解決日時">
              <span className="text-green-400 text-xs">{formatDate(inc.resolved_at)}</span>
            </InfoCell>
          )}
        </div>
      </div>

      {/* ATT&CK kill-chain of the correlated alerts (only shows if techniques present) */}
      <KillChainStrip incidentId={inc.id} />

      {/* Linked alerts quick view */}
      <LinkedAlertsCard incidentId={inc.id} />

      {(nextStatuses.length > 0 || prevStatuses.length > 0) && (
        <div className="bg-[#0d1220] border border-[#1e2d42] rounded-xl p-5">
          <h2 className="text-sm font-semibold text-[#7d92b0] uppercase tracking-wider mb-3">
            ステータス遷移
          </h2>
          <div className="flex flex-wrap gap-2">
            {nextStatuses.map(s => (
              <button
                key={s}
                onClick={() => onStatusChange(s)}
                disabled={!canWrite || statusPending}
                className={`flex items-center gap-1.5 px-4 py-2 rounded-lg text-sm font-medium transition-colors disabled:opacity-50 ${
                  TRANSITION_COLORS[s] ?? 'bg-[#1e2d42] hover:bg-[#253649] text-white'
                }`}
              >
                <Check size={13} />
                {STATUS_LABELS[s] ?? s} に変更
              </button>
            ))}
            {prevStatuses.map(s => (
              <button
                key={s}
                onClick={() => onStatusChange(s)}
                disabled={!canWrite || statusPending}
                className="flex items-center gap-1.5 px-4 py-2 rounded-lg text-sm font-medium transition-colors disabled:opacity-50 bg-[#1a2035] hover:bg-[#222d45] border border-[#2d3f55] text-[#7d92b0] hover:text-[#c9d6e8]"
              >
                ↩ {STATUS_LABELS[s] ?? s} に戻す
              </button>
            ))}
          </div>
        </div>
      )}

      {canWrite && (
        <div className="bg-[#0d1220] border border-[#1e2d42] rounded-xl p-5">
          <h2 className="text-sm font-semibold text-[#7d92b0] uppercase tracking-wider mb-3">
            担当者を変更
          </h2>
          <div className="flex gap-2">
            <select
              value={selectedAssignee}
              onChange={e => setSelectedAssignee(e.target.value)}
              className="flex-1 bg-[#070d19] border border-[#1e2d42] rounded-lg px-3 py-2 text-sm
                         text-[#e2e8f4] focus:outline-none focus:border-blue-500"
            >
              <option value="">未割当</option>
              {users.map(u => (
                <option key={u.id} value={u.id}>
                  {u.full_name || u.email}
                </option>
              ))}
            </select>
            <button
              onClick={onAssign}
              disabled={assignPending}
              className="flex items-center gap-1.5 px-4 py-2 bg-blue-700 hover:bg-blue-600
                         disabled:opacity-50 rounded-lg text-sm font-medium transition-colors"
            >
              <User size={14} />
              {assignPending ? '保存中...' : '保存'}
            </button>
          </div>
        </div>
      )}
    </div>
  )
}

function InfoCell({ label, children }: { label: string; children: React.ReactNode }) {
  return (
    <div className="bg-[#070d19]/50 rounded-lg p-3">
      <div className="text-xs text-[#5a6a7a] mb-1.5">{label}</div>
      <div>{children}</div>
    </div>
  )
}

// ─── Comments Tab ─────────────────────────────────────────────────────────────

function CommentsTab({
  comments,
  commentBody,
  setCommentBody,
  onAddComment,
  onDeleteComment,
  addPending,
  deletePending,
  canWrite,
}: {
  comments: Comment[]
  commentBody: string
  setCommentBody: (v: string) => void
  onAddComment: () => void
  onDeleteComment: (id: string) => void
  addPending: boolean
  deletePending: boolean
  canWrite: boolean
}) {
  return (
    <div className="bg-[#0d1220] border border-[#1e2d42] rounded-xl p-5 space-y-4">
      <div className="flex items-center gap-2 mb-1">
        <MessageSquare size={16} className="text-blue-400" />
        <h2 className="font-semibold">コメント</h2>
        <span className="text-xs text-[#5a6a7a] ml-auto">{comments.length}件</span>
      </div>

      {comments.length === 0 ? (
        <p className="text-[#5a6a7a] text-sm text-center py-6">コメントがありません</p>
      ) : (
        <div className="space-y-3">
          {comments.map(c => (
            <div key={c.id} className="flex gap-3">
              <div className="w-7 h-7 rounded-full bg-[#1d2f4a] border border-[#1e2d42] flex items-center justify-center flex-shrink-0 mt-0.5">
                <User size={12} className="text-[#7d92b0]" />
              </div>
              <div className="flex-1 bg-[#070d19]/50 border border-[#1e2d42]/50 rounded-lg px-3 py-2.5">
                <div className="flex items-center gap-2 mb-1">
                  <span className="text-xs font-semibold text-[#e2e8f4]">
                    {c.user_name || truncateUUID(c.user_id)}
                  </span>
                  <span className="text-[10px] text-[#3d5068] flex items-center gap-0.5 ml-auto">
                    <Clock size={9} />
                    {formatDate(c.created_at)}
                  </span>
                  {canWrite && (
                    <button
                      onClick={() => {
                        if (confirm('このコメントを削除しますか？')) onDeleteComment(c.id)
                      }}
                      disabled={deletePending}
                      className="text-[#3d5068] hover:text-red-400 transition-colors disabled:opacity-50 ml-1"
                      title="削除"
                    >
                      <Trash2 size={12} />
                    </button>
                  )}
                </div>
                <p className="text-sm text-[#7d92b0] whitespace-pre-wrap leading-relaxed">
                  {c.body}
                </p>
              </div>
            </div>
          ))}
        </div>
      )}

      {canWrite && (
        <div className="flex gap-2 pt-2 border-t border-[#1e2d42]">
          <textarea
            value={commentBody}
            onChange={e => setCommentBody(e.target.value)}
            onKeyDown={e => {
              if (e.key === 'Enter' && (e.ctrlKey || e.metaKey) && commentBody.trim()) {
                onAddComment()
              }
            }}
            placeholder="コメントを入力... (Ctrl+Enter で送信)"
            rows={2}
            className="flex-1 bg-[#070d19] border border-[#1e2d42] rounded-lg px-3 py-2 text-sm
                       text-[#e2e8f4] placeholder-[#5a6a7a] resize-none
                       focus:outline-none focus:border-blue-500"
          />
          <button
            onClick={onAddComment}
            disabled={!commentBody.trim() || addPending}
            className="self-end flex items-center gap-1.5 px-4 py-2 text-sm bg-blue-700 hover:bg-blue-600
                       text-white rounded-lg disabled:opacity-50 transition-colors"
          >
            <Send size={14} />
            {addPending ? '送信中...' : 'コメントを追加'}
          </button>
        </div>
      )}
    </div>
  )
}

// ─── Notes Tab ────────────────────────────────────────────────────────────────

function NotesTab({
  notes,
  noteBody,
  setNoteBody,
  onAddNote,
  addPending,
  canWrite,
}: {
  notes: Note[]
  noteBody: string
  setNoteBody: (v: string) => void
  onAddNote: () => void
  addPending: boolean
  canWrite: boolean
}) {
  return (
    <div className="bg-[#0d1220] border border-[#1e2d42] rounded-xl p-5 space-y-4">
      <div className="flex items-center gap-2 mb-1">
        <FileText size={16} className="text-purple-400" />
        <h2 className="font-semibold">ノート</h2>
        <span className="text-xs text-[#5a6a7a] ml-auto">{notes.length}件</span>
      </div>

      {notes.length === 0 ? (
        <p className="text-[#5a6a7a] text-sm text-center py-6">ノートがありません</p>
      ) : (
        <div className="space-y-3">
          {notes.map(note => (
            <div key={note.id} className="flex gap-3">
              <div className="w-7 h-7 rounded-full bg-[#1d2f4a] border border-[#1e2d42] flex items-center justify-center flex-shrink-0 mt-0.5">
                <User size={12} className="text-[#7d92b0]" />
              </div>
              <div className="flex-1 bg-[#070d19]/50 border border-[#1e2d42]/50 rounded-lg px-3 py-2.5">
                <div className="flex items-center gap-2 mb-1">
                  <span className="text-xs font-semibold text-[#e2e8f4]">
                    {note.user_name || (note.user_id ? truncateUUID(note.user_id) : 'システム')}
                  </span>
                  <span className="text-[10px] text-[#3d5068] flex items-center gap-0.5 ml-auto">
                    <Clock size={9} />
                    {formatDate(note.created_at)}
                  </span>
                </div>
                <p className="text-sm text-[#7d92b0] whitespace-pre-wrap leading-relaxed">
                  {note.body}
                </p>
              </div>
            </div>
          ))}
        </div>
      )}

      {canWrite && (
        <div className="flex gap-2 pt-2 border-t border-[#1e2d42]">
          <textarea
            value={noteBody}
            onChange={e => setNoteBody(e.target.value)}
            onKeyDown={e => {
              if (e.key === 'Enter' && (e.ctrlKey || e.metaKey) && noteBody.trim()) {
                onAddNote()
              }
            }}
            placeholder="ノートを追加... (Ctrl+Enter で送信)"
            rows={2}
            className="flex-1 bg-[#070d19] border border-[#1e2d42] rounded-lg px-3 py-2 text-sm
                       text-[#e2e8f4] placeholder-[#5a6a7a] resize-none
                       focus:outline-none focus:border-purple-500"
          />
          <button
            onClick={onAddNote}
            disabled={!noteBody.trim() || addPending}
            className="self-end flex items-center gap-1.5 px-4 py-2 text-sm bg-purple-800 hover:bg-purple-700
                       text-white rounded-lg disabled:opacity-50 transition-colors"
          >
            <Send size={14} />
            {addPending ? '追加中...' : '追加'}
          </button>
        </div>
      )}
    </div>
  )
}

// ─── Timeline Tab ─────────────────────────────────────────────────────────────

type TimelineEventType = 'created' | 'status_change' | 'alert_linked' | 'note' | 'comment'

interface TimelineEventItem {
  ts: string
  type: TimelineEventType
  actor: string
  detail: string
}

function formatRelativeTime(iso: string): string {
  const diff = Date.now() - new Date(iso).getTime()
  const mins = Math.floor(diff / 60_000)
  if (mins < 1) return 'たった今'
  if (mins < 60) return `${mins}分前`
  const hours = Math.floor(mins / 60)
  if (hours < 24) return `${hours}時間前`
  const days = Math.floor(hours / 24)
  return `${days}日前`
}

const EVENT_CONFIG: Record<TimelineEventType, {
  dotColor: string
  textColor: string
  icon: React.ReactNode
}> = {
  created:       { dotColor: 'bg-blue-500',   textColor: 'text-blue-300',   icon: <Clock size={13} /> },
  status_change: { dotColor: 'bg-amber-500',  textColor: 'text-amber-300',  icon: <GitBranch size={13} /> },
  alert_linked:  { dotColor: 'bg-red-500',    textColor: 'text-red-300',    icon: <Link size={13} /> },
  note:          { dotColor: 'bg-green-500',  textColor: 'text-green-300',  icon: <FileText size={13} /> },
  comment:       { dotColor: 'bg-purple-500', textColor: 'text-purple-300', icon: <MessageSquare size={13} /> },
}

function TimelineTab({ inc }: { inc: Incident }) {
  const [filterType, setFilterType] = useState<TimelineEventType | 'all'>('all')

  const { data, isLoading } = useQuery<{ timeline: TimelineEventItem[] }>({
    queryKey: ['incident-timeline', inc.id],
    queryFn: () => apiFetch(`/api/v1/incidents/${inc.id}/timeline`),
    enabled: !!inc.id,
  })

  // Build local fallback events from incident data when API returns nothing.
  const localFallback = useMemo((): TimelineEventItem[] => {
    const evts: TimelineEventItem[] = []
    evts.push({ ts: inc.created_at, type: 'created', actor: 'System', detail: 'インシデントが作成されました' })
    if (inc.assigned_to_name) {
      evts.push({ ts: inc.updated_at, type: 'status_change', actor: 'System', detail: `${inc.assigned_to_name} に割り当てられました` })
    }
    if (inc.alert_count > 0) {
      evts.push({ ts: inc.created_at, type: 'alert_linked', actor: 'System', detail: `${inc.alert_count}件のアラートがリンクされています` })
    }
    if (inc.resolved_at) {
      evts.push({ ts: inc.resolved_at, type: 'status_change', actor: inc.assigned_to_name || 'System', detail: 'インシデントが解決されました' })
    }
    return evts.sort((a, b) => new Date(b.ts).getTime() - new Date(a.ts).getTime())
  }, [inc])

  const apiEvents = data?.timeline ?? []
  const allEvents = apiEvents.length > 0 ? apiEvents : localFallback

  const filteredEvents = filterType === 'all' ? allEvents : allEvents.filter(e => e.type === filterType)

  const FILTER_OPTS: { value: TimelineEventType | 'all'; label: string }[] = [
    { value: 'all',           label: 'すべて' },
    { value: 'status_change', label: 'ステータス' },
    { value: 'comment',       label: 'コメント' },
    { value: 'alert_linked',  label: 'アラート' },
    { value: 'note',          label: 'ノート' },
    { value: 'created',       label: '作成' },
  ]

  return (
    <div className="bg-[#0d1220] border border-[#1e2d42] rounded-xl p-5">
      <div className="flex items-center gap-2 mb-4 flex-wrap">
        <Clock size={16} className="text-blue-400" />
        <h2 className="font-semibold">タイムライン</h2>
        {!isLoading && (
          <span className="text-xs text-[#5a6a7a]">{filteredEvents.length}件</span>
        )}
        {/* Event type filter */}
        <div className="ml-auto flex items-center gap-1 flex-wrap">
          <Filter size={11} className="text-[#3d5068]" />
          {FILTER_OPTS.map(opt => (
            <button
              key={opt.value}
              onClick={() => setFilterType(opt.value)}
              className={`text-[10px] px-2 py-0.5 rounded-full border transition-colors
                ${filterType === opt.value
                  ? 'bg-blue-900/40 text-blue-300 border-blue-700/50'
                  : 'text-[#5a6a7a] border-[#1e2d42] hover:text-[#8899aa]'}`}
            >
              {opt.label}
            </button>
          ))}
        </div>
      </div>

      {isLoading && (
        <div className="relative pl-6 space-y-6">
          <div className="absolute left-2.5 top-2 bottom-2 w-px bg-[#1e2d42]" />
          {[0, 1, 2].map(i => (
            <div key={i} className="relative flex gap-4 animate-pulse">
              <div className="absolute -left-3.5 w-3 h-3 rounded-full bg-[#1e2d42] mt-1" />
              <div className="flex-1 space-y-2">
                <div className="h-3.5 bg-[#1e2d42] rounded w-2/5" />
                <div className="h-3 bg-[#161f33] rounded w-3/5" />
                <div className="h-3 bg-[#161f33] rounded w-1/3" />
              </div>
            </div>
          ))}
        </div>
      )}

      {!isLoading && filteredEvents.length === 0 && (
        <div className="flex flex-col items-center justify-center py-12 text-[#5a6a7a]">
          <Clock size={32} className="mb-3 opacity-30" />
          <p className="text-sm">タイムラインイベントがありません</p>
        </div>
      )}

      {!isLoading && filteredEvents.length > 0 && (
        <div className="relative pl-6">
          <div className="absolute left-2.5 top-2 bottom-2 w-px bg-[#1e2d42]" />
          <div className="space-y-6">
            {filteredEvents.map((ev, idx) => {
              const cfg = EVENT_CONFIG[ev.type] ?? EVENT_CONFIG.created
              return (
                <div key={idx} className="relative flex gap-4">
                  <div
                    className={`absolute -left-3.5 w-3 h-3 rounded-full border-2 border-[#070d19] ${cfg.dotColor} flex-shrink-0 mt-1`}
                  />
                  <div className="flex-1 min-w-0">
                    <div className={`flex items-center gap-1.5 text-sm font-medium ${cfg.textColor}`}>
                      {cfg.icon}
                      <span>{ev.detail}</span>
                    </div>
                    {ev.actor && (
                      <div className="flex items-center gap-1 mt-0.5">
                        <User size={10} className="text-[#3d5068]" />
                        <span className="text-[11px] text-[#5a6a7a]">{ev.actor}</span>
                      </div>
                    )}
                    <div className="text-[10px] text-[#3d5068] mt-0.5 flex items-center gap-1">
                      <Clock size={9} />
                      <span>{formatRelativeTime(ev.ts)}</span>
                      <span className="text-[#1e2d42]">·</span>
                      <span>{formatDate(ev.ts)}</span>
                    </div>
                  </div>
                </div>
              )
            })}
          </div>
        </div>
      )}
    </div>
  )
}

// ─── Communications Log Tab ────────────────────────────────────────────────────

const COMM_TYPES = ['Email', 'Slack', 'Call', 'Other'] as const
type CommType = (typeof COMM_TYPES)[number]

function commTypeIcon(t: string) {
  switch (t) {
    case 'Email': return <Mail size={14} className="text-blue-400" />
    case 'Slack': return <Slack size={14} className="text-purple-400" />
    case 'Call':  return <Phone size={14} className="text-green-400" />
    default:      return <MessageSquare size={14} className="text-[#7d92b0]" />
  }
}

function CommsTab({ incidentId }: { incidentId: string }) {
  const qc = useQueryClient()

  const { data, isLoading } = useQuery<{ comms?: CommEntry[]; data?: CommEntry[] }>({
    queryKey: ['incident-comms', incidentId],
    queryFn: () => apiFetch(`/api/v1/incidents/${incidentId}/comms`),
    enabled: !!incidentId,
  })
  const comms: CommEntry[] = data?.comms ?? data?.data ?? []

  const [type, setType] = useState<CommType>('Email')
  const [recipient, setRecipient] = useState('')
  const [summary, setSummary] = useState('')

  const addMutation = useMutation({
    mutationFn: () =>
      apiFetch(`/api/v1/incidents/${incidentId}/comms`, {
        method: 'POST',
        body: JSON.stringify({ type, recipient, summary }),
      }),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['incident-comms', incidentId] })
      setRecipient('')
      setSummary('')
    },
  })

  return (
    <div className="space-y-4">
      {/* Add comm form */}
      <div className="bg-[#0d1220] border border-[#1e2d42] rounded-xl p-5">
        <div className="flex items-center gap-2 mb-4">
          <Mail size={16} className="text-blue-400" />
          <h2 className="font-semibold">外部コミュニケーションを記録</h2>
        </div>
        <div className="grid grid-cols-1 md:grid-cols-3 gap-3 mb-3">
          <div>
            <label className="text-xs text-[#7d92b0] mb-1 block">種別</label>
            <select
              value={type}
              onChange={e => setType(e.target.value as CommType)}
              className="w-full bg-[#070d19] border border-[#1e2d42] rounded-lg px-3 py-2 text-sm
                         text-[#e2e8f4] focus:outline-none focus:border-blue-500"
            >
              {COMM_TYPES.map(t => (
                <option key={t} value={t}>{t}</option>
              ))}
            </select>
          </div>
          <div className="md:col-span-2">
            <label className="text-xs text-[#7d92b0] mb-1 block">宛先 / 相手</label>
            <input
              type="text"
              value={recipient}
              onChange={e => setRecipient(e.target.value)}
              placeholder="例: security-team@example.com"
              className="w-full bg-[#070d19] border border-[#1e2d42] rounded-lg px-3 py-2 text-sm
                         text-[#e2e8f4] placeholder-[#5a6a7a] focus:outline-none focus:border-blue-500"
            />
          </div>
        </div>
        <div className="mb-3">
          <label className="text-xs text-[#7d92b0] mb-1 block">概要</label>
          <textarea
            value={summary}
            onChange={e => setSummary(e.target.value)}
            placeholder="コミュニケーションの内容を簡潔に記述してください..."
            rows={3}
            className="w-full bg-[#070d19] border border-[#1e2d42] rounded-lg px-3 py-2 text-sm
                       text-[#e2e8f4] placeholder-[#5a6a7a] resize-none
                       focus:outline-none focus:border-blue-500"
          />
        </div>
        <button
          onClick={() => {
            if (recipient.trim() && summary.trim()) addMutation.mutate()
          }}
          disabled={!recipient.trim() || !summary.trim() || addMutation.isPending}
          className="flex items-center gap-1.5 px-4 py-2 bg-blue-700 hover:bg-blue-600
                     disabled:opacity-50 rounded-lg text-sm font-medium transition-colors"
        >
          <PlusCircle size={14} />
          {addMutation.isPending ? '記録中...' : '記録する'}
        </button>
      </div>

      {/* Comm list */}
      <div className="bg-[#0d1220] border border-[#1e2d42] rounded-xl p-5">
        <div className="flex items-center gap-2 mb-4">
          <h2 className="font-semibold">コミュニケーション履歴</h2>
          <span className="text-xs text-[#5a6a7a] ml-auto">{comms.length}件</span>
        </div>

        {isLoading && (
          <div className="space-y-3">
            {[0,1,2].map(i => (
              <div key={i} className="h-16 bg-[#070d19]/50 rounded-lg animate-pulse" />
            ))}
          </div>
        )}

        {!isLoading && comms.length === 0 && (
          <div className="flex flex-col items-center py-10 text-[#5a6a7a]">
            <Mail size={28} className="mb-2 opacity-30" />
            <p className="text-sm">記録がありません</p>
          </div>
        )}

        {!isLoading && comms.length > 0 && (
          <div className="space-y-3">
            {comms.map(c => (
              <div
                key={c.id}
                className="flex gap-3 bg-[#070d19]/40 border border-[#1e2d42]/60 rounded-lg px-4 py-3"
              >
                <div className="mt-0.5">{commTypeIcon(c.type)}</div>
                <div className="flex-1 min-w-0">
                  <div className="flex items-center gap-2 flex-wrap">
                    <span className="text-xs font-semibold text-white bg-[#1e2d42] px-2 py-0.5 rounded">
                      {c.type}
                    </span>
                    <span className="text-sm text-[#e2e8f4] truncate">{c.recipient}</span>
                    <span className="text-[10px] text-[#5a6a7a] ml-auto flex items-center gap-1">
                      <Clock size={9} />
                      {formatDate(c.created_at)}
                    </span>
                  </div>
                  <p className="text-sm text-[#7d92b0] mt-1.5 leading-relaxed">{c.summary}</p>
                  {c.logged_by_name && (
                    <div className="flex items-center gap-1 mt-1">
                      <User size={10} className="text-[#3d5068]" />
                      <span className="text-[10px] text-[#5a6a7a]">記録者: {c.logged_by_name}</span>
                    </div>
                  )}
                </div>
              </div>
            ))}
          </div>
        )}
      </div>
    </div>
  )
}

// ─── Escalation History Tab ────────────────────────────────────────────────────

const URGENCY_LEVELS = ['low', 'medium', 'high', 'critical'] as const
type UrgencyLevel = (typeof URGENCY_LEVELS)[number]

const URGENCY_COLORS: Record<string, string> = {
  low:      'bg-blue-900/50 text-blue-300',
  medium:   'bg-yellow-900/50 text-yellow-300',
  high:     'bg-orange-900/50 text-orange-300',
  critical: 'bg-red-900/50 text-red-300',
}

const URGENCY_LABELS: Record<string, string> = {
  low: '低',
  medium: '中',
  high: '高',
  critical: '緊急',
}

function EscalationTab({ incidentId, users }: { incidentId: string; users: UserItem[] }) {
  const qc = useQueryClient()
  const [showModal, setShowModal] = useState(false)
  const [targetUserId, setTargetUserId] = useState('')
  const [urgency, setUrgency] = useState<UrgencyLevel>('medium')
  const [reason, setReason] = useState('')

  const { data, isLoading } = useQuery<{ escalations?: EscalationEntry[]; data?: EscalationEntry[] }>({
    queryKey: ['incident-escalations', incidentId],
    queryFn: () => apiFetch(`/api/v1/incidents/${incidentId}/escalations`),
    enabled: !!incidentId,
  })
  const escalations: EscalationEntry[] = data?.escalations ?? data?.data ?? []

  const escalateMutation = useMutation({
    mutationFn: () =>
      apiFetch(`/api/v1/incidents/${incidentId}/escalations`, {
        method: 'POST',
        body: JSON.stringify({ target_user_id: targetUserId, urgency, reason }),
      }),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['incident-escalations', incidentId] })
      setShowModal(false)
      setTargetUserId('')
      setUrgency('medium')
      setReason('')
    },
  })

  return (
    <div className="space-y-4">
      {/* Escalate button */}
      <div className="flex justify-end">
        <button
          onClick={() => setShowModal(true)}
          className="flex items-center gap-2 px-4 py-2 bg-[#e8002d] hover:bg-red-700
                     rounded-lg text-sm font-medium transition-colors"
        >
          <ArrowUpCircle size={15} />
          エスカレーション
        </button>
      </div>

      {/* History */}
      <div className="bg-[#0d1220] border border-[#1e2d42] rounded-xl p-5">
        <div className="flex items-center gap-2 mb-5">
          <ArrowUpCircle size={16} className="text-red-400" />
          <h2 className="font-semibold">エスカレーション履歴</h2>
          {!isLoading && (
            <span className="text-xs text-[#5a6a7a] ml-auto">{escalations.length}件</span>
          )}
        </div>

        {isLoading && (
          <div className="relative pl-6 space-y-5">
            <div className="absolute left-2.5 top-2 bottom-2 w-px bg-[#1e2d42]" />
            {[0,1].map(i => (
              <div key={i} className="relative animate-pulse">
                <div className="absolute -left-3.5 w-3 h-3 rounded-full bg-[#1e2d42] mt-1" />
                <div className="space-y-2 pl-1">
                  <div className="h-4 bg-[#1e2d42] rounded w-1/3" />
                  <div className="h-3 bg-[#161f33] rounded w-2/3" />
                </div>
              </div>
            ))}
          </div>
        )}

        {!isLoading && escalations.length === 0 && (
          <div className="flex flex-col items-center py-10 text-[#5a6a7a]">
            <ArrowUpCircle size={28} className="mb-2 opacity-30" />
            <p className="text-sm">エスカレーション履歴がありません</p>
          </div>
        )}

        {!isLoading && escalations.length > 0 && (
          <div className="relative pl-6">
            <div className="absolute left-2.5 top-2 bottom-2 w-px bg-[#1e2d42]" />
            <div className="space-y-5">
              {escalations.map((e, idx) => (
                <div key={e.id ?? idx} className="relative">
                  <div className="absolute -left-3.5 w-3 h-3 rounded-full bg-red-500 border-2 border-[#070d19] mt-1" />
                  <div className="bg-[#070d19]/40 border border-[#1e2d42]/60 rounded-lg px-4 py-3 ml-1">
                    <div className="flex items-center gap-2 flex-wrap mb-2">
                      <span className={`text-xs px-2 py-0.5 rounded-full font-medium ${URGENCY_COLORS[e.urgency] ?? 'bg-[#1e2d42] text-[#7d92b0]'}`}>
                        {URGENCY_LABELS[e.urgency] ?? e.urgency}
                      </span>
                      {e.escalated_by_name && (
                        <span className="text-xs text-[#7d92b0]">
                          <User size={10} className="inline mr-0.5" />
                          {e.escalated_by_name}
                        </span>
                      )}
                      {e.escalated_to_name && (
                        <>
                          <ArrowUpCircle size={12} className="text-[#5a6a7a]" />
                          <span className="text-xs text-[#e2e8f4]">{e.escalated_to_name}</span>
                        </>
                      )}
                      <span className="text-[10px] text-[#5a6a7a] ml-auto flex items-center gap-1">
                        <Clock size={9} />
                        {formatDate(e.created_at)}
                      </span>
                    </div>
                    {e.reason && (
                      <p className="text-sm text-[#7d92b0] leading-relaxed">{e.reason}</p>
                    )}
                  </div>
                </div>
              ))}
            </div>
          </div>
        )}
      </div>

      {/* Escalation modal */}
      {showModal && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60">
          <div className="bg-[#0d1220] border border-[#1e2d42] rounded-xl p-6 w-full max-w-md mx-4 shadow-2xl">
            <div className="flex items-center justify-between mb-5">
              <div className="flex items-center gap-2">
                <AlertTriangle size={18} className="text-[#e8002d]" />
                <h3 className="font-semibold text-lg">エスカレーション</h3>
              </div>
              <button
                onClick={() => setShowModal(false)}
                className="text-[#5a6a7a] hover:text-white transition-colors"
              >
                <X size={18} />
              </button>
            </div>

            <div className="space-y-4">
              <div>
                <label className="text-xs text-[#7d92b0] mb-1 block">エスカレーション先</label>
                <select
                  value={targetUserId}
                  onChange={e => setTargetUserId(e.target.value)}
                  className="w-full bg-[#070d19] border border-[#1e2d42] rounded-lg px-3 py-2 text-sm
                             text-[#e2e8f4] focus:outline-none focus:border-[#e8002d]"
                >
                  <option value="">ユーザーを選択...</option>
                  {users.map(u => (
                    <option key={u.id} value={u.id}>
                      {u.full_name || u.email}
                    </option>
                  ))}
                </select>
              </div>

              <div>
                <label className="text-xs text-[#7d92b0] mb-1 block">緊急度</label>
                <div className="grid grid-cols-4 gap-2">
                  {URGENCY_LEVELS.map(u => (
                    <button
                      key={u}
                      onClick={() => setUrgency(u)}
                      className={`py-1.5 rounded-lg text-xs font-medium transition-colors border ${
                        urgency === u
                          ? 'border-[#e8002d] ' + (URGENCY_COLORS[u] ?? '')
                          : 'border-[#1e2d42] text-[#7d92b0] bg-[#070d19] hover:border-[#3d5068]'
                      }`}
                    >
                      {URGENCY_LABELS[u]}
                    </button>
                  ))}
                </div>
              </div>

              <div>
                <label className="text-xs text-[#7d92b0] mb-1 block">理由</label>
                <textarea
                  value={reason}
                  onChange={e => setReason(e.target.value)}
                  placeholder="エスカレーションの理由を記述してください..."
                  rows={4}
                  className="w-full bg-[#070d19] border border-[#1e2d42] rounded-lg px-3 py-2 text-sm
                             text-[#e2e8f4] placeholder-[#5a6a7a] resize-none
                             focus:outline-none focus:border-[#e8002d]"
                />
              </div>

              <div className="flex gap-3 pt-2">
                <button
                  onClick={() => setShowModal(false)}
                  className="flex-1 py-2 border border-[#1e2d42] text-[#7d92b0] hover:text-white
                             hover:border-[#3d5068] rounded-lg text-sm transition-colors"
                >
                  キャンセル
                </button>
                <button
                  onClick={() => {
                    if (targetUserId && reason.trim()) escalateMutation.mutate()
                  }}
                  disabled={!targetUserId || !reason.trim() || escalateMutation.isPending}
                  className="flex-1 py-2 bg-[#e8002d] hover:bg-red-700 disabled:opacity-50
                             rounded-lg text-sm font-medium transition-colors flex items-center justify-center gap-1.5"
                >
                  <ArrowUpCircle size={14} />
                  {escalateMutation.isPending ? '送信中...' : 'エスカレーション'}
                </button>
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  )
}

// ─── Responders Tab ────────────────────────────────────────────────────────────

const RESPONDER_ROLES = ['Lead', 'Analyst', 'Observer'] as const
type ResponderRole = (typeof RESPONDER_ROLES)[number]

const ROLE_COLORS: Record<string, string> = {
  Lead:     'bg-[#e8002d]/20 text-red-300 border-red-900/50',
  Analyst:  'bg-blue-900/30 text-blue-300 border-blue-900/50',
  Observer: 'bg-[#1e2d42] text-[#7d92b0] border-[#1e2d42]',
}

const ROLE_LABELS: Record<string, string> = {
  Lead:     'リード',
  Analyst:  'アナリスト',
  Observer: 'オブザーバー',
}

function RespondersTab({ incidentId, users }: { incidentId: string; users: UserItem[] }) {
  const qc = useQueryClient()
  const [selectedUser, setSelectedUser] = useState('')
  const [role, setRole] = useState<ResponderRole>('Analyst')

  const { data, isLoading } = useQuery<{ responders?: ResponderEntry[]; data?: ResponderEntry[] }>({
    queryKey: ['incident-responders', incidentId],
    queryFn: () => apiFetch(`/api/v1/incidents/${incidentId}/responders`),
    enabled: !!incidentId,
  })
  const responders: ResponderEntry[] = data?.responders ?? data?.data ?? []

  const addMutation = useMutation({
    mutationFn: () =>
      apiFetch(`/api/v1/incidents/${incidentId}/responders`, {
        method: 'POST',
        body: JSON.stringify({ user_id: selectedUser, role }),
      }),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['incident-responders', incidentId] })
      setSelectedUser('')
    },
  })

  const removeMutation = useMutation({
    mutationFn: (responderId: string) =>
      apiFetch(`/api/v1/incidents/${incidentId}/responders/${responderId}`, { method: 'DELETE' }),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['incident-responders', incidentId] }),
  })

  // Build set of already-assigned user IDs
  const assignedIds = new Set(responders.map(r => r.user_id))
  const availableUsers = users.filter(u => !assignedIds.has(u.id))

  return (
    <div className="space-y-4">
      {/* Add responder */}
      <div className="bg-[#0d1220] border border-[#1e2d42] rounded-xl p-5">
        <div className="flex items-center gap-2 mb-4">
          <Users size={16} className="text-blue-400" />
          <h2 className="font-semibold">レスポンダーを追加</h2>
        </div>
        <div className="flex gap-3 flex-wrap">
          <select
            value={selectedUser}
            onChange={e => setSelectedUser(e.target.value)}
            className="flex-1 min-w-[200px] bg-[#070d19] border border-[#1e2d42] rounded-lg px-3 py-2 text-sm
                       text-[#e2e8f4] focus:outline-none focus:border-blue-500"
          >
            <option value="">ユーザーを選択...</option>
            {availableUsers.map(u => (
              <option key={u.id} value={u.id}>
                {u.full_name || u.email}
              </option>
            ))}
          </select>
          <div className="flex gap-2">
            {RESPONDER_ROLES.map(r => (
              <button
                key={r}
                onClick={() => setRole(r)}
                className={`px-3 py-2 rounded-lg text-xs font-medium border transition-colors ${
                  role === r
                    ? ROLE_COLORS[r]
                    : 'border-[#1e2d42] text-[#7d92b0] bg-[#070d19] hover:border-[#3d5068]'
                }`}
              >
                {ROLE_LABELS[r]}
              </button>
            ))}
          </div>
          <button
            onClick={() => { if (selectedUser) addMutation.mutate() }}
            disabled={!selectedUser || addMutation.isPending}
            className="flex items-center gap-1.5 px-4 py-2 bg-blue-700 hover:bg-blue-600
                       disabled:opacity-50 rounded-lg text-sm font-medium transition-colors"
          >
            <PlusCircle size={14} />
            {addMutation.isPending ? '追加中...' : '追加'}
          </button>
        </div>
      </div>

      {/* Responders list */}
      <div className="bg-[#0d1220] border border-[#1e2d42] rounded-xl p-5">
        <div className="flex items-center gap-2 mb-4">
          <Shield size={16} className="text-green-400" />
          <h2 className="font-semibold">担当レスポンダー</h2>
          <span className="text-xs text-[#5a6a7a] ml-auto">{responders.length}名</span>
        </div>

        {isLoading && (
          <div className="space-y-3">
            {[0,1,2].map(i => (
              <div key={i} className="h-14 bg-[#070d19]/50 rounded-lg animate-pulse" />
            ))}
          </div>
        )}

        {!isLoading && responders.length === 0 && (
          <div className="flex flex-col items-center py-10 text-[#5a6a7a]">
            <Users size={28} className="mb-2 opacity-30" />
            <p className="text-sm">レスポンダーが割り当てられていません</p>
          </div>
        )}

        {!isLoading && responders.length > 0 && (
          <div className="divide-y divide-[#1e2d42]">
            {responders.map((r, idx) => (
              <div key={r.id ?? idx} className="flex items-center gap-3 py-3">
                <div className="w-9 h-9 rounded-full bg-[#1d2f4a] border border-[#1e2d42] flex items-center justify-center flex-shrink-0">
                  <User size={15} className="text-[#7d92b0]" />
                </div>
                <div className="flex-1 min-w-0">
                  <div className="text-sm font-medium text-[#e2e8f4]">
                    {r.user_name || r.user_email || truncateUUID(r.user_id)}
                  </div>
                  {r.user_email && r.user_name && (
                    <div className="text-xs text-[#5a6a7a]">{r.user_email}</div>
                  )}
                </div>
                <span className={`text-xs px-2.5 py-1 rounded-full border font-medium ${ROLE_COLORS[r.role] ?? ROLE_COLORS.Observer}`}>
                  {ROLE_LABELS[r.role] ?? r.role}
                </span>
                <div className="text-[10px] text-[#5a6a7a] hidden sm:block">
                  {formatDate(r.added_at)}
                </div>
                <button
                  onClick={() => {
                    if (confirm('このレスポンダーを削除しますか？')) removeMutation.mutate(r.id)
                  }}
                  disabled={removeMutation.isPending}
                  className="text-[#3d5068] hover:text-red-400 transition-colors disabled:opacity-50"
                  title="削除"
                >
                  <Trash2 size={14} />
                </button>
              </div>
            ))}
          </div>
        )}
      </div>
    </div>
  )
}

// ─── Playbook Tab ──────────────────────────────────────────────────────────────

interface PlaybookStep {
  id: string
  phase: string
  title: string
  description: string
  ttp?: string        // MITRE ATT&CK ID
  done: boolean
  required: boolean
}

const PLAYBOOK_PHASES = ['検出・分析', '封じ込め', '根絶', '復旧', '事後対応'] as const

function buildDefaultPlaybook(severity: number): PlaybookStep[] {
  const steps: Omit<PlaybookStep, 'id' | 'done'>[] = [
    // 検出・分析
    { phase: '検出・分析', title: 'インシデントの初期評価', description: '重大度・影響範囲・攻撃ベクトルを評価し、トリアージを実施する', required: true },
    { phase: '検出・分析', title: '関連ログの収集', description: 'EDRテレメトリ・ネットワークログ・認証ログを収集し、タイムラインを構築する', ttp: 'T1078', required: true },
    { phase: '検出・分析', title: 'IOCの特定と抽出', description: 'IP/ドメイン/ハッシュ/ユーザー名などのIoCを抽出し、脅威インテリジェンスと照合する', ttp: 'T1082', required: severity >= 7 },
    { phase: '検出・分析', title: '攻撃者の手口の特定 (TTP)', description: 'MITRE ATT&CKフレームワークを参照し、使用されたTTPをマッピングする', required: false },
    // 封じ込め
    { phase: '封じ込め', title: '影響ホストのネットワーク隔離', description: '感染・侵害が確認されたホストをネットワークから隔離する', ttp: 'T1021', required: severity >= 8 },
    { phase: '封じ込め', title: '侵害アカウントの無効化', description: '侵害が確認されたユーザーアカウント・サービスアカウントを無効化する', ttp: 'T1078', required: severity >= 7 },
    { phase: '封じ込め', title: 'C2通信のブロック', description: 'ファイアウォール・プロキシでC2サーバーへの通信をブロックする', ttp: 'T1071', required: severity >= 8 },
    // 根絶
    { phase: '根絶', title: '悪意あるファイルの削除', description: 'マルウェア・バックドア・持続化メカニズムを特定し完全に削除する', ttp: 'T1027', required: true },
    { phase: '根絶', title: '脆弱性へのパッチ適用', description: '攻撃に利用された脆弱性に対してパッチを適用する', required: false },
    { phase: '根絶', title: '認証情報の再発行', description: '侵害が確認されたすべての認証情報（パスワード・トークン・証明書）を再発行する', required: severity >= 7 },
    // 復旧
    { phase: '復旧', title: 'システムのクリーンなバックアップからの復元', description: '検証済みのバックアップからシステムを復元し、整合性を確認する', required: false },
    { phase: '復旧', title: '監視強化の実施', description: '侵害ホスト・アカウントに対して強化された監視を一定期間継続する', required: true },
    { phase: '復旧', title: '正常性確認', description: '隔離解除前にシステムの正常性を確認し、再感染がないことを検証する', required: severity >= 8 },
    // 事後対応
    { phase: '事後対応', title: 'ポストモーテムの作成', description: '根本原因・タイムライン・影響・教訓をポストモーテムにまとめる', required: true },
    { phase: '事後対応', title: '検出ルールの更新', description: '新しいIoCを基に検出ルールを更新し、同様の攻撃を検知できるようにする', required: false },
    { phase: '事後対応', title: '関係者へのクロージャー報告', description: '関係部門・経営層に対してインシデントのクロージャー報告を実施する', required: severity >= 9 },
  ]
  return steps.map(s => ({ ...s, id: Math.random().toString(36).slice(2, 10), done: false }))
}

const PHASE_COLORS: Record<string, string> = {
  '検出・分析': 'bg-blue-900/30 border-blue-700/50 text-blue-300',
  '封じ込め':   'bg-yellow-900/30 border-yellow-700/50 text-yellow-300',
  '根絶':       'bg-red-900/30 border-red-700/50 text-red-300',
  '復旧':       'bg-green-900/30 border-green-700/50 text-green-300',
  '事後対応':   'bg-purple-900/30 border-purple-700/50 text-purple-300',
}

const PHASE_DOT: Record<string, string> = {
  '検出・分析': 'bg-blue-400',
  '封じ込め':   'bg-yellow-400',
  '根絶':       'bg-red-400',
  '復旧':       'bg-green-400',
  '事後対応':   'bg-purple-400',
}

function PlaybookTab({ inc }: { inc: Incident }) {
  const [steps, setSteps] = React.useState<PlaybookStep[]>(() => buildDefaultPlaybook(inc.severity))
  const [activePhase, setActivePhase] = React.useState<string>('すべて')

  const doneCount = steps.filter(s => s.done).length
  const progress = Math.round((doneCount / steps.length) * 100)

  const phases = ['すべて', ...PLAYBOOK_PHASES]

  const filtered = activePhase === 'すべて' ? steps : steps.filter(s => s.phase === activePhase)

  const grouped = PLAYBOOK_PHASES.reduce((acc, p) => {
    acc[p] = filtered.filter(s => s.phase === p)
    return acc
  }, {} as Record<string, PlaybookStep[]>)

  function toggle(id: string) {
    setSteps(prev => prev.map(s => s.id === id ? { ...s, done: !s.done } : s))
  }

  function exportMarkdown() {
    const lines = [
      `# 対応プレイブック — ${inc.title}`,
      ``,
      `進捗: ${doneCount}/${steps.length} (${progress}%)`,
      ``,
    ]
    for (const phase of PLAYBOOK_PHASES) {
      const phaseSteps = steps.filter(s => s.phase === phase)
      if (phaseSteps.length === 0) continue
      lines.push(`## ${phase}`)
      lines.push(``)
      for (const s of phaseSteps) {
        lines.push(`- [${s.done ? 'x' : ' '}] **${s.title}**${s.ttp ? ` (${s.ttp})` : ''}`)
        lines.push(`  ${s.description}`)
      }
      lines.push(``)
    }
    const blob = new Blob([lines.join('\n')], { type: 'text/markdown' })
    const a = document.createElement('a')
    a.href = URL.createObjectURL(blob)
    a.download = `playbook-${inc.id.slice(0, 8)}.md`
    a.click()
  }

  return (
    <div className="space-y-4">
      {/* Header */}
      <div className="flex items-center justify-between flex-wrap gap-3">
        <div className="flex items-center gap-3">
          <ListChecks size={18} className="text-cyan-400" />
          <h2 className="font-semibold text-white">インシデント対応プレイブック</h2>
          <span className="text-xs text-[#5a6a7a]">{doneCount}/{steps.length} 完了</span>
        </div>
        <button
          onClick={exportMarkdown}
          className="flex items-center gap-1.5 px-3 py-1.5 border border-[#1e2d42] text-[#7d92b0]
                     hover:text-white hover:border-[#3d5068] rounded-lg text-xs transition-colors"
        >
          <Download size={13} />
          Markdown出力
        </button>
      </div>

      {/* Progress bar */}
      <div className="bg-[#0d1220] border border-[#1e2d42] rounded-xl p-4">
        <div className="flex items-center justify-between mb-2">
          <span className="text-xs text-[#7d92b0]">全体進捗</span>
          <span className="text-xs font-bold text-white">{progress}%</span>
        </div>
        <div className="h-2.5 bg-[#1e2d42] rounded-full overflow-hidden">
          <div
            className={`h-full rounded-full transition-all duration-500 ${
              progress === 100 ? 'bg-green-500' : progress >= 60 ? 'bg-yellow-500' : 'bg-cyan-500'
            }`}
            style={{ width: `${progress}%` }}
          />
        </div>
        {/* Phase progress dots */}
        <div className="flex items-center gap-3 mt-3 flex-wrap">
          {PLAYBOOK_PHASES.map(phase => {
            const phaseSteps = steps.filter(s => s.phase === phase)
            const phaseDone = phaseSteps.filter(s => s.done).length
            const phasePct = phaseSteps.length > 0 ? Math.round((phaseDone / phaseSteps.length) * 100) : 0
            return (
              <div key={phase} className="flex items-center gap-1.5">
                <span className={`w-2 h-2 rounded-full ${PHASE_DOT[phase]}`} />
                <span className="text-[10px] text-[#5a6a7a]">{phase}: {phaseDone}/{phaseSteps.length}</span>
                {phasePct === 100 && <Check size={10} className="text-green-400" />}
              </div>
            )
          })}
        </div>
      </div>

      {/* Phase filter */}
      <div className="flex gap-1 flex-wrap">
        {phases.map(p => (
          <button
            key={p}
            onClick={() => setActivePhase(p)}
            className={`px-3 py-1 rounded-full text-xs border transition-colors ${
              activePhase === p
                ? 'bg-cyan-900/40 border-cyan-600/60 text-cyan-300'
                : 'border-[#1e2d42] text-[#7d92b0] hover:text-white hover:border-[#2a3d5a]'
            }`}
          >
            {p}
          </button>
        ))}
      </div>

      {/* Steps by phase */}
      {PLAYBOOK_PHASES.map(phase => {
        const phaseSteps = grouped[phase] ?? []
        if (phaseSteps.length === 0) return null
        return (
          <div key={phase} className="bg-[#0d1220] border border-[#1e2d42] rounded-xl overflow-hidden">
            <div className={`flex items-center gap-2 px-4 py-2.5 border-b border-[#1e2d42] ${PHASE_COLORS[phase]}`}>
              <span className={`w-2 h-2 rounded-full ${PHASE_DOT[phase]}`} />
              <span className="text-xs font-semibold uppercase tracking-wide">{phase}</span>
              <span className="text-xs opacity-60 ml-auto">
                {phaseSteps.filter(s => s.done).length}/{phaseSteps.length}
              </span>
            </div>
            <div className="divide-y divide-[#1e2d42]/50">
              {phaseSteps.map(step => (
                <div
                  key={step.id}
                  className={`flex items-start gap-3 px-4 py-3 transition-colors ${
                    step.done ? 'opacity-60' : 'hover:bg-[#0a1628]'
                  }`}
                >
                  <button
                    onClick={() => toggle(step.id)}
                    className={`mt-0.5 w-4 h-4 rounded border flex-shrink-0 flex items-center justify-center transition-colors ${
                      step.done
                        ? 'bg-green-600 border-green-600'
                        : step.required
                        ? 'border-cyan-600 hover:border-green-500'
                        : 'border-[#3d5068] hover:border-[#7d92b0]'
                    }`}
                  >
                    {step.done && <Check size={10} className="text-white" />}
                  </button>
                  <div className="flex-1 min-w-0">
                    <div className="flex items-center gap-2 flex-wrap">
                      <span className={`text-sm font-medium ${step.done ? 'line-through text-[#5a6a7a]' : 'text-white'}`}>
                        {step.title}
                      </span>
                      {step.required && !step.done && (
                        <span className="text-[10px] px-1.5 py-0.5 rounded bg-red-900/30 border border-red-700/40 text-red-400">
                          必須
                        </span>
                      )}
                      {step.ttp && (
                        <span className="text-[10px] px-1.5 py-0.5 rounded bg-[#1e2d42] text-[#7d92b0] font-mono">
                          {step.ttp}
                        </span>
                      )}
                    </div>
                    <p className="text-xs text-[#5a6a7a] mt-0.5 leading-relaxed">{step.description}</p>
                  </div>
                </div>
              ))}
            </div>
          </div>
        )
      })}
    </div>
  )
}

// ─── Post-Mortem Tab ───────────────────────────────────────────────────────────

function generateActionItemId() {
  return Math.random().toString(36).slice(2, 10)
}

function PostMortemTab({ inc }: { inc: Incident }) {
  const qc = useQueryClient()

  const { data: pmData, isLoading } = useQuery<{ post_mortem?: PostMortem; data?: PostMortem }>({
    queryKey: ['incident-postmortem', inc.id],
    queryFn: () => apiFetch(`/api/v1/incidents/${inc.id}/post-mortem`),
    enabled: !!inc.id,
  })

  const existing: PostMortem | undefined = pmData?.post_mortem ?? pmData?.data

  const [rootCause, setRootCause] = useState('')
  const [affectedSystems, setAffectedSystems] = useState('')
  const [affectedUsers, setAffectedUsers] = useState('')
  const [durationMinutes, setDurationMinutes] = useState(0)
  const [lessonsLearned, setLessonsLearned] = useState('')
  const [actionItems, setActionItems] = useState<ActionItem[]>([])
  const [newActionText, setNewActionText] = useState('')
  const [saved, setSaved] = useState(false)

  useEffect(() => {
    if (existing) {
      setRootCause(existing.root_cause ?? '')
      setAffectedSystems(existing.affected_systems ?? '')
      setAffectedUsers(existing.affected_users ?? '')
      setDurationMinutes(existing.duration_minutes ?? 0)
      setLessonsLearned(existing.lessons_learned ?? '')
      setActionItems(existing.action_items ?? [])
    }
  }, [existing])

  const saveMutation = useMutation({
    mutationFn: () =>
      apiFetch(`/api/v1/incidents/${inc.id}/post-mortem`, {
        method: existing ? 'PUT' : 'POST',
        body: JSON.stringify({
          root_cause: rootCause,
          affected_systems: affectedSystems,
          affected_users: affectedUsers,
          duration_minutes: durationMinutes,
          lessons_learned: lessonsLearned,
          action_items: actionItems,
        }),
      }),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['incident-postmortem', inc.id] })
      setSaved(true)
      setTimeout(() => setSaved(false), 2500)
    },
  })

  function addActionItem() {
    if (!newActionText.trim()) return
    setActionItems(prev => [
      ...prev,
      { id: generateActionItemId(), text: newActionText.trim(), done: false },
    ])
    setNewActionText('')
  }

  function toggleActionItem(id: string) {
    setActionItems(prev =>
      prev.map(a => a.id === id ? { ...a, done: !a.done } : a)
    )
  }

  function removeActionItem(id: string) {
    setActionItems(prev => prev.filter(a => a.id !== id))
  }

  function exportMarkdown() {
    const lines: string[] = [
      `# ポストモーテム: ${inc.title}`,
      ``,
      `**インシデントID:** ${inc.id}`,
      `**重大度:** ${inc.severity}`,
      `**ステータス:** ${STATUS_LABELS[inc.status] ?? inc.status}`,
      `**作成日時:** ${formatDate(inc.created_at)}`,
      inc.resolved_at ? `**解決日時:** ${formatDate(inc.resolved_at)}` : '',
      ``,
      `## タイムライン再構成`,
      ``,
      `- 作成: ${formatDate(inc.created_at)}`,
      inc.resolved_at ? `- 解決: ${formatDate(inc.resolved_at)}` : '',
      durationMinutes > 0 ? `- 影響期間: ${durationMinutes}分` : '',
      ``,
      `## 根本原因`,
      ``,
      rootCause || '_未入力_',
      ``,
      `## 影響評価`,
      ``,
      `**影響システム:** ${affectedSystems || '_未入力_'}`,
      `**影響ユーザー:** ${affectedUsers || '_未入力_'}`,
      durationMinutes > 0 ? `**影響時間:** ${durationMinutes}分` : '',
      ``,
      `## 教訓`,
      ``,
      lessonsLearned || '_未入力_',
      ``,
      `## アクションアイテム`,
      ``,
      ...actionItems.map(a => `- [${a.done ? 'x' : ' '}] ${a.text}`),
      actionItems.length === 0 ? '_なし_' : '',
    ].filter(l => l !== undefined)

    const md = lines.join('\n')
    const blob = new Blob([md], { type: 'text/markdown' })
    const url = URL.createObjectURL(blob)
    const a = document.createElement('a')
    a.href = url
    a.download = `postmortem-${inc.id.slice(0, 8)}.md`
    a.click()
    URL.revokeObjectURL(url)
  }

  return (
    <div className="space-y-4">
      {/* Header actions */}
      <div className="flex items-center justify-between">
        <h2 className="font-semibold flex items-center gap-2">
          <BookOpen size={16} className="text-indigo-400" />
          ポストモーテム
        </h2>
        <button
          onClick={exportMarkdown}
          className="flex items-center gap-1.5 px-3 py-1.5 border border-[#1e2d42] text-[#7d92b0]
                     hover:text-white hover:border-[#3d5068] rounded-lg text-xs transition-colors"
        >
          <Download size={13} />
          Markdownでエクスポート
        </button>
      </div>

      {isLoading && (
        <div className="space-y-3">
          {[0,1,2,3].map(i => (
            <div key={i} className="h-20 bg-[#0d1220] border border-[#1e2d42] rounded-xl animate-pulse" />
          ))}
        </div>
      )}

      {!isLoading && (
        <>
          {/* Timeline reconstruction */}
          <div className="bg-[#0d1220] border border-[#1e2d42] rounded-xl p-5">
            <h3 className="text-sm font-semibold text-[#7d92b0] uppercase tracking-wider mb-3">
              タイムライン再構成
            </h3>
            <div className="grid grid-cols-1 sm:grid-cols-3 gap-3">
              <div className="bg-[#070d19]/50 rounded-lg p-3 text-sm">
                <div className="text-xs text-[#5a6a7a] mb-1">インシデント発生</div>
                <div className="text-[#e2e8f4]">{formatDate(inc.created_at)}</div>
              </div>
              {inc.resolved_at && (
                <div className="bg-[#070d19]/50 rounded-lg p-3 text-sm">
                  <div className="text-xs text-[#5a6a7a] mb-1">解決日時</div>
                  <div className="text-green-400">{formatDate(inc.resolved_at)}</div>
                </div>
              )}
              <div className="bg-[#070d19]/50 rounded-lg p-3 text-sm">
                <div className="text-xs text-[#5a6a7a] mb-1">影響期間 (分)</div>
                <input
                  type="number"
                  value={durationMinutes}
                  onChange={e => setDurationMinutes(Number(e.target.value))}
                  min={0}
                  className="w-full bg-transparent text-[#e2e8f4] focus:outline-none"
                />
              </div>
            </div>
          </div>

          {/* Root cause */}
          <div className="bg-[#0d1220] border border-[#1e2d42] rounded-xl p-5">
            <h3 className="text-sm font-semibold text-[#7d92b0] uppercase tracking-wider mb-3">
              根本原因
            </h3>
            <textarea
              value={rootCause}
              onChange={e => setRootCause(e.target.value)}
              placeholder="インシデントの根本原因を詳細に記述してください..."
              rows={5}
              className="w-full bg-[#070d19] border border-[#1e2d42] rounded-lg px-3 py-2.5 text-sm
                         text-[#e2e8f4] placeholder-[#5a6a7a] resize-y
                         focus:outline-none focus:border-indigo-500"
            />
          </div>

          {/* Impact assessment */}
          <div className="bg-[#0d1220] border border-[#1e2d42] rounded-xl p-5">
            <h3 className="text-sm font-semibold text-[#7d92b0] uppercase tracking-wider mb-3">
              影響評価
            </h3>
            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
              <div>
                <label className="text-xs text-[#7d92b0] mb-1 block">影響を受けたシステム</label>
                <textarea
                  value={affectedSystems}
                  onChange={e => setAffectedSystems(e.target.value)}
                  placeholder="例: 認証サーバー, 顧客データベース..."
                  rows={3}
                  className="w-full bg-[#070d19] border border-[#1e2d42] rounded-lg px-3 py-2 text-sm
                             text-[#e2e8f4] placeholder-[#5a6a7a] resize-none
                             focus:outline-none focus:border-indigo-500"
                />
              </div>
              <div>
                <label className="text-xs text-[#7d92b0] mb-1 block">影響を受けたユーザー</label>
                <textarea
                  value={affectedUsers}
                  onChange={e => setAffectedUsers(e.target.value)}
                  placeholder="例: 全社員 (約500名), 外部顧客..."
                  rows={3}
                  className="w-full bg-[#070d19] border border-[#1e2d42] rounded-lg px-3 py-2 text-sm
                             text-[#e2e8f4] placeholder-[#5a6a7a] resize-none
                             focus:outline-none focus:border-indigo-500"
                />
              </div>
            </div>
          </div>

          {/* Lessons learned */}
          <div className="bg-[#0d1220] border border-[#1e2d42] rounded-xl p-5">
            <h3 className="text-sm font-semibold text-[#7d92b0] uppercase tracking-wider mb-3">
              教訓
            </h3>
            <textarea
              value={lessonsLearned}
              onChange={e => setLessonsLearned(e.target.value)}
              placeholder="このインシデントから学んだことを記述してください..."
              rows={5}
              className="w-full bg-[#070d19] border border-[#1e2d42] rounded-lg px-3 py-2.5 text-sm
                         text-[#e2e8f4] placeholder-[#5a6a7a] resize-y
                         focus:outline-none focus:border-indigo-500"
            />
          </div>

          {/* Action items */}
          <div className="bg-[#0d1220] border border-[#1e2d42] rounded-xl p-5">
            <div className="flex items-center gap-2 mb-4">
              <ListChecks size={16} className="text-green-400" />
              <h3 className="text-sm font-semibold text-[#7d92b0] uppercase tracking-wider">
                アクションアイテム
              </h3>
              <span className="text-xs text-[#5a6a7a] ml-auto">
                {actionItems.filter(a => a.done).length}/{actionItems.length}件完了
              </span>
            </div>

            {/* Existing items */}
            {actionItems.length === 0 ? (
              <p className="text-[#5a6a7a] text-sm text-center py-4">アクションアイテムがありません</p>
            ) : (
              <div className="space-y-2 mb-4">
                {actionItems.map(item => (
                  <div
                    key={item.id}
                    className="flex items-center gap-3 bg-[#070d19]/40 border border-[#1e2d42]/60 rounded-lg px-3 py-2.5"
                  >
                    <button
                      onClick={() => toggleActionItem(item.id)}
                      className={`w-4 h-4 rounded border flex-shrink-0 flex items-center justify-center transition-colors ${
                        item.done
                          ? 'bg-green-600 border-green-600'
                          : 'border-[#3d5068] hover:border-green-600'
                      }`}
                    >
                      {item.done && <Check size={11} className="text-white" />}
                    </button>
                    <span className={`flex-1 text-sm ${item.done ? 'line-through text-[#5a6a7a]' : 'text-[#e2e8f4]'}`}>
                      {item.text}
                    </span>
                    <button
                      onClick={() => removeActionItem(item.id)}
                      className="text-[#3d5068] hover:text-red-400 transition-colors"
                    >
                      <Trash2 size={13} />
                    </button>
                  </div>
                ))}
              </div>
            )}

            {/* Add new item */}
            <div className="flex gap-2">
              <input
                type="text"
                value={newActionText}
                onChange={e => setNewActionText(e.target.value)}
                onKeyDown={e => { if (e.key === 'Enter') addActionItem() }}
                placeholder="新しいアクションアイテムを追加..."
                className="flex-1 bg-[#070d19] border border-[#1e2d42] rounded-lg px-3 py-2 text-sm
                           text-[#e2e8f4] placeholder-[#5a6a7a] focus:outline-none focus:border-green-500"
              />
              <button
                onClick={addActionItem}
                disabled={!newActionText.trim()}
                className="flex items-center gap-1.5 px-3 py-2 bg-green-800 hover:bg-green-700
                           disabled:opacity-50 rounded-lg text-sm font-medium transition-colors"
              >
                <PlusCircle size={14} />
                追加
              </button>
            </div>
          </div>

          {/* Save button */}
          <div className="flex justify-end gap-3">
            {saved && (
              <span className="flex items-center gap-1.5 text-green-400 text-sm">
                <Check size={14} />
                保存しました
              </span>
            )}
            <button
              onClick={() => saveMutation.mutate()}
              disabled={saveMutation.isPending}
              className="flex items-center gap-1.5 px-5 py-2 bg-indigo-700 hover:bg-indigo-600
                         disabled:opacity-50 rounded-lg text-sm font-medium transition-colors"
            >
              <FileText size={14} />
              {saveMutation.isPending ? '保存中...' : 'ポストモーテムを保存'}
            </button>
          </div>
        </>
      )}
    </div>
  )
}

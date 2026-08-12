'use client'

import { useState, useRef, useEffect } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { apiFetch } from '@/lib/api'
import {
  AlertOctagon, Clock, Shield, Users, ChevronDown,
  Plus, Send, CheckSquare, Square, X, AlertTriangle,
  FileText, Camera, Archive, Database, Wifi, StickyNote,
  Activity, Target, MessageSquare, ClipboardList, Lock,
  UserPlus, Upload, Download, Loader2, CheckCircle, XCircle,
} from 'lucide-react'
import { USE_MOCK, m } from '@/lib/mock'

// ─── Types ────────────────────────────────────────────────────────────────────

type Severity = 'critical' | 'high' | 'medium' | 'low'
type IncidentStatus = 'open' | 'investigating' | 'contained' | 'resolved'
type EventType = 'alert' | 'action' | 'note' | 'escalation' | 'containment'
type EvidenceType = 'file' | 'screenshot' | 'log' | 'memory_dump' | 'pcap' | 'note'
type ContainStatus = 'contained' | 'partial' | 'pending' | 'uncontained'
type Priority = 'critical' | 'high' | 'medium' | 'low'

interface Incident {
  id: string
  title: string
  severity: Severity
  status: IncidentStatus
  created_at: string
  assigned_team: string
  assigned_to: string[]
  alert_ids: string[]
  affected_assets: Asset[]
}

interface TimelineEvent {
  id: string
  actor: string
  action: string
  timestamp: string
  type: EventType
  description?: string
}

interface Evidence {
  id: string
  name: string
  type: EvidenceType
  added_by: string
  added_at: string
  size: string
}

interface Task {
  id: string
  description: string
  assignee: string
  due_time: string
  priority: Priority
  done: boolean
}

interface Asset {
  id: string
  name: string
  type: string
  ip: string
  containment_status: ContainStatus
}

interface ChatMessage {
  id: string
  sender: string
  message: string
  timestamp: string
  is_system: boolean
}

// ─── Mock Data ────────────────────────────────────────────────────────────────

const MOCK_INCIDENTS: Incident[] = [
  {
    id: 'INC-2024-001', title: 'ランサムウェア感染の疑い - 財務部門',
    severity: 'critical', status: 'investigating',
    created_at: '2026-03-18T04:22:00Z', assigned_team: 'CSIRT Team Alpha',
    assigned_to: ['alice', 'bob', 'charlie'],
    alert_ids: ['ALT-001', 'ALT-002', 'ALT-003'],
    affected_assets: [
      { id: 'a1', name: 'WIN-FIN-001', type: 'workstation', ip: '10.0.5.101', containment_status: 'contained' },
      { id: 'a2', name: 'WIN-FIN-002', type: 'workstation', ip: '10.0.5.102', containment_status: 'partial' },
      { id: 'a3', name: 'WIN-FIN-003', type: 'workstation', ip: '10.0.5.103', containment_status: 'uncontained' },
      { id: 'a4', name: 'WIN-FIN-SRV', type: 'server', ip: '10.0.5.10', containment_status: 'pending' },
      { id: 'a5', name: 'NAS-001', type: 'storage', ip: '10.0.5.200', containment_status: 'uncontained' },
    ],
  },
  {
    id: 'INC-2024-002', title: '内部者によるデータ持ち出しの疑い',
    severity: 'high', status: 'open',
    created_at: '2026-03-18T06:45:00Z', assigned_team: 'CSIRT Team Beta',
    assigned_to: ['david', 'eve'],
    alert_ids: ['ALT-010', 'ALT-011'],
    affected_assets: [
      { id: 'b1', name: 'WIN-HR-015', type: 'workstation', ip: '10.0.3.215', containment_status: 'contained' },
      { id: 'b2', name: 'WIN-HR-022', type: 'workstation', ip: '10.0.3.222', containment_status: 'uncontained' },
    ],
  },
  {
    id: 'INC-2024-003', title: 'C2通信の検知 - マーケティング部門',
    severity: 'high', status: 'investigating',
    created_at: '2026-03-18T08:10:00Z', assigned_team: 'CSIRT Team Alpha',
    assigned_to: ['frank', 'grace'],
    alert_ids: ['ALT-020'],
    affected_assets: [
      { id: 'c1', name: 'WIN-MKT-007', type: 'workstation', ip: '10.0.4.107', containment_status: 'contained' },
      { id: 'c2', name: 'WIN-MKT-012', type: 'workstation', ip: '10.0.4.112', containment_status: 'pending' },
    ],
  },
]

const TIMELINE_EVENTS: Record<string, TimelineEvent[]> = {
  'INC-2024-001': [
    { id: 't1', actor: 'System', action: 'アラートが自動的にインシデントに昇格されました', timestamp: '2026-03-18T04:22:00Z', type: 'alert' },
    { id: 't2', actor: 'alice', action: 'インシデント対応を開始', timestamp: '2026-03-18T04:25:00Z', type: 'action', description: 'CSIRT Alphaチームを招集' },
    { id: 't3', actor: 'System', action: 'WIN-FIN-001を自動隔離', timestamp: '2026-03-18T04:26:00Z', type: 'containment' },
    { id: 't4', actor: 'alice', action: 'CISO・IT部門長に通知', timestamp: '2026-03-18T04:28:00Z', type: 'escalation' },
    { id: 't5', actor: 'bob', action: 'メモリダンプを取得', timestamp: '2026-03-18T04:35:00Z', type: 'action', description: 'WIN-FIN-001のメモリを保全' },
    { id: 't6', actor: 'charlie', action: 'ネットワーク通信をブロック', timestamp: '2026-03-18T04:40:00Z', type: 'containment' },
    { id: 't7', actor: 'alice', action: 'フォレンジック解析を開始', timestamp: '2026-03-18T05:00:00Z', type: 'action', description: 'Velociraptor経由でアーティファクト収集' },
    { id: 't8', actor: 'bob', action: '初期調査メモ追加', timestamp: '2026-03-18T05:15:00Z', type: 'note', description: 'YARAルールで RansomX変種を確認' },
    { id: 't9', actor: 'charlie', action: 'WIN-FIN-002を部分隔離', timestamp: '2026-03-18T05:30:00Z', type: 'containment' },
    { id: 't10', actor: 'alice', action: '経営層へのステータス報告', timestamp: '2026-03-18T06:00:00Z', type: 'escalation' },
  ],
  'INC-2024-002': [
    { id: 'u1', actor: 'System', action: 'UEBA異常スコアがしきい値を超過', timestamp: '2026-03-18T06:45:00Z', type: 'alert' },
    { id: 'u2', actor: 'david', action: 'インシデントをオープン', timestamp: '2026-03-18T06:50:00Z', type: 'action' },
    { id: 'u3', actor: 'eve', action: 'DLPログの確認開始', timestamp: '2026-03-18T07:00:00Z', type: 'action' },
    { id: 'u4', actor: 'david', action: '対象ユーザーのアクセスを一時停止', timestamp: '2026-03-18T07:10:00Z', type: 'containment' },
    { id: 'u5', actor: 'eve', action: '証拠スクリーンショットを追加', timestamp: '2026-03-18T07:15:00Z', type: 'note' },
  ],
  'INC-2024-003': [
    { id: 'v1', actor: 'System', action: 'C2通信パターンを検知', timestamp: '2026-03-18T08:10:00Z', type: 'alert' },
    { id: 'v2', actor: 'frank', action: 'インシデント対応開始', timestamp: '2026-03-18T08:15:00Z', type: 'action' },
    { id: 'v3', actor: 'grace', action: 'WIN-MKT-007を隔離', timestamp: '2026-03-18T08:20:00Z', type: 'containment' },
    { id: 'v4', actor: 'frank', action: 'C2 IPアドレスをブロック', timestamp: '2026-03-18T08:22:00Z', type: 'containment' },
    { id: 'v5', actor: 'grace', action: 'PCAPキャプチャを開始', timestamp: '2026-03-18T08:25:00Z', type: 'action' },
  ],
}

const EVIDENCE_DATA: Record<string, Evidence[]> = {
  'INC-2024-001': [
    { id: 'ev1', name: 'WIN-FIN-001_memory.dmp', type: 'memory_dump', added_by: 'bob', added_at: '2026-03-18T04:35:00Z', size: '4.2 GB' },
    { id: 'ev2', name: 'ransom_note.txt', type: 'file', added_by: 'alice', added_at: '2026-03-18T04:38:00Z', size: '1.2 KB' },
    { id: 'ev3', name: 'encrypted_files_list.log', type: 'log', added_by: 'System', added_at: '2026-03-18T04:40:00Z', size: '45.8 KB' },
    { id: 'ev4', name: 'network_capture_04h22.pcap', type: 'pcap', added_by: 'charlie', added_at: '2026-03-18T04:45:00Z', size: '128 MB' },
    { id: 'ev5', name: 'initial_analysis_notes', type: 'note', added_by: 'bob', added_at: '2026-03-18T05:15:00Z', size: '2.1 KB' },
  ],
  'INC-2024-002': [
    { id: 'eu1', name: 'dlp_alert_screenshot.png', type: 'screenshot', added_by: 'eve', added_at: '2026-03-18T07:15:00Z', size: '245 KB' },
    { id: 'eu2', name: 'usb_activity.log', type: 'log', added_by: 'david', added_at: '2026-03-18T07:20:00Z', size: '12.4 KB' },
    { id: 'eu3', name: 'file_transfer_evidence', type: 'note', added_by: 'david', added_at: '2026-03-18T07:30:00Z', size: '0.8 KB' },
  ],
  'INC-2024-003': [
    { id: 'ev1c', name: 'c2_traffic.pcap', type: 'pcap', added_by: 'grace', added_at: '2026-03-18T08:25:00Z', size: '22 MB' },
    { id: 'ev2c', name: 'beacon_sample.exe', type: 'file', added_by: 'frank', added_at: '2026-03-18T08:30:00Z', size: '156 KB' },
  ],
}

const TASKS_DATA: Record<string, Task[]> = {
  'INC-2024-001': [
    { id: 'tk1', description: '全影響端末のメモリダンプを取得', assignee: 'bob', due_time: '2026-03-18T06:00:00Z', priority: 'critical', done: true },
    { id: 'tk2', description: '感染経路の特定', assignee: 'alice', due_time: '2026-03-18T08:00:00Z', priority: 'critical', done: false },
    { id: 'tk3', description: 'バックアップシステムの確認', assignee: 'charlie', due_time: '2026-03-18T09:00:00Z', priority: 'high', done: false },
    { id: 'tk4', description: 'マルウェアサンプルをサンドボックスで解析', assignee: 'bob', due_time: '2026-03-18T10:00:00Z', priority: 'high', done: true },
    { id: 'tk5', description: '経営層向け被害報告書を作成', assignee: 'alice', due_time: '2026-03-18T12:00:00Z', priority: 'medium', done: false },
  ],
  'INC-2024-002': [
    { id: 'tu1', description: 'DLPログの完全調査', assignee: 'eve', due_time: '2026-03-18T09:00:00Z', priority: 'high', done: false },
    { id: 'tu2', description: '対象ユーザーの行動ログ収集', assignee: 'david', due_time: '2026-03-18T10:00:00Z', priority: 'high', done: true },
    { id: 'tu3', description: '法務部門への報告', assignee: 'david', due_time: '2026-03-18T14:00:00Z', priority: 'medium', done: false },
  ],
  'INC-2024-003': [
    { id: 'tv1', description: 'C2通信の完全遮断確認', assignee: 'frank', due_time: '2026-03-18T09:00:00Z', priority: 'critical', done: true },
    { id: 'tv2', description: 'マルウェアの横展開確認', assignee: 'grace', due_time: '2026-03-18T10:00:00Z', priority: 'high', done: false },
    { id: 'tv3', description: 'IOCをTIフィードに登録', assignee: 'frank', due_time: '2026-03-18T11:00:00Z', priority: 'medium', done: false },
    { id: 'tv4', description: 'YARA/Sigmaルールの更新', assignee: 'grace', due_time: '2026-03-18T13:00:00Z', priority: 'medium', done: false },
  ],
}

// ─── Helpers ──────────────────────────────────────────────────────────────────

function fmtTime(iso: string): string {
  return new Date(iso).toLocaleString('ja-JP', { month: '2-digit', day: '2-digit', hour: '2-digit', minute: '2-digit' })
}

function elapsed(iso: string): string {
  const ms = Date.now() - new Date(iso).getTime()
  const h = Math.floor(ms / 3600000)
  const m = Math.floor((ms % 3600000) / 60000)
  return `${h}時間${m}分`
}

const SEV_BADGE: Record<Severity, string> = {
  critical: 'bg-red-900/50 text-red-300 border border-red-700/50',
  high: 'bg-orange-900/50 text-orange-300 border border-orange-700/50',
  medium: 'bg-yellow-900/50 text-yellow-300 border border-yellow-700/50',
  low: 'bg-blue-900/50 text-blue-300 border border-blue-700/50',
}

const CONTAIN_BADGE: Record<ContainStatus, string> = {
  contained: 'bg-green-900/40 text-green-400',
  partial: 'bg-yellow-900/40 text-yellow-400',
  pending: 'bg-blue-900/40 text-blue-300',
  uncontained: 'bg-red-900/40 text-red-400',
}

const EVT_ICON: Record<EventType, React.ReactNode> = {
  alert: <AlertTriangle className="w-4 h-4 text-[#e8002d]" />,
  action: <Activity className="w-4 h-4 text-blue-400" />,
  note: <StickyNote className="w-4 h-4 text-yellow-400" />,
  escalation: <AlertOctagon className="w-4 h-4 text-orange-400" />,
  containment: <Shield className="w-4 h-4 text-green-400" />,
}

const EV_ICON: Record<EvidenceType, React.ReactNode> = {
  file: <FileText className="w-4 h-4 text-blue-400" />,
  screenshot: <Camera className="w-4 h-4 text-purple-400" />,
  log: <Archive className="w-4 h-4 text-green-400" />,
  memory_dump: <Database className="w-4 h-4 text-orange-400" />,
  pcap: <Wifi className="w-4 h-4 text-teal-400" />,
  note: <StickyNote className="w-4 h-4 text-yellow-400" />,
}

const PRI_COLOR: Record<Priority, string> = {
  critical: 'text-red-400',
  high: 'text-orange-400',
  medium: 'text-yellow-400',
  low: 'text-blue-400',
}

function Avatar({ name, size = 'sm' }: { name: string; size?: 'sm' | 'md' }) {
  const colors = ['from-blue-600 to-blue-800', 'from-purple-600 to-purple-800', 'from-green-600 to-green-800', 'from-orange-600 to-orange-800', 'from-teal-600 to-teal-800']
  const color = colors[name.charCodeAt(0) % colors.length]
  const sz = size === 'sm' ? 'w-7 h-7 text-[10px]' : 'w-9 h-9 text-xs'
  return (
    <div className={`${sz} rounded-full bg-gradient-to-br ${color} flex items-center justify-center font-bold text-white flex-shrink-0`}>
      {name[0]?.toUpperCase()}
    </div>
  )
}

// ─── Page ─────────────────────────────────────────────────────────────────────

export default function WarRoomPage() {
  const qc = useQueryClient()
  const [selectedId, setSelectedId] = useState('INC-2024-001')
  const [innerTab, setInnerTab] = useState<'timeline' | 'evidence' | 'chat' | 'tasks' | 'containment'>('timeline')
  const [timelineFilter, setTimelineFilter] = useState<string>('all')
  const [chatInput, setChatInput] = useState('')
  const [chatMessages, setChatMessages] = useState<ChatMessage[]>([
    { id: 'cm1', sender: 'alice', message: 'メモリダンプの解析完了。RansomX v3.2が確認されました', timestamp: '2026-03-18T05:20:00Z', is_system: false },
    { id: 'cm2', sender: 'System', message: 'System: alice が WIN-FIN-001 を隔離しました', timestamp: '2026-03-18T04:26:00Z', is_system: true },
    { id: 'cm3', sender: 'bob', message: '感染元はフィッシングメールの添付ファイルと思われます。eml形式のサンプルを確保しています', timestamp: '2026-03-18T05:30:00Z', is_system: false },
    { id: 'cm4', sender: 'charlie', message: 'ネットワーク遮断を確認しました。C2通信は完全にブロック済みです', timestamp: '2026-03-18T05:35:00Z', is_system: false },
  ])
  const [addEventForm, setAddEventForm] = useState<{ type: EventType; description: string } | null>(null)
  const [addTaskForm, setAddTaskForm] = useState(false)
  const [newTask, setNewTask] = useState({ description: '', assignee: '', due_time: '', priority: 'high' as Priority })
  const [confirmBulkContain, setConfirmBulkContain] = useState(false)
  const [localTasks, setLocalTasks] = useState<Record<string, Task[]>>(TASKS_DATA)
  const [localTimeline, setLocalTimeline] = useState<Record<string, TimelineEvent[]>>(TIMELINE_EVENTS)
  const chatEndRef = useRef<HTMLDivElement>(null)

  useEffect(() => { chatEndRef.current?.scrollIntoView({ behavior: 'smooth' }) }, [chatMessages])

  const incQ = useQuery<Incident[]>({
    queryKey: ['war-room-incidents'],
    queryFn: () =>
      apiFetch<{ data: Incident[] }>('/api/v1/incidents?per_page=100')
        .then(r => (r?.data ?? []).filter(i => i.status !== 'resolved'))
        .catch(() => []),
    ...(USE_MOCK ? { initialData: MOCK_INCIDENTS } : {}),
    retry: 1,
  })

  const incidents = incQ.data ?? m(MOCK_INCIDENTS)
  const incident = incidents.find(i => i.id === selectedId) ?? incidents[0]

  const timeline = localTimeline[incident?.id] ?? []
  const evidence = EVIDENCE_DATA[incident?.id] ?? []
  const tasks = localTasks[incident?.id] ?? []
  const assets = incident?.affected_assets ?? []

  const filteredTimeline = timeline.filter(e => timelineFilter === 'all' || e.type === timelineFilter)
  const tasksDone = tasks.filter(t => t.done).length
  const tasksTotal = tasks.length
  const containedCount = assets.filter(a => a.containment_status === 'contained').length

  const sendChat = () => {
    if (!chatInput.trim()) return
    setChatMessages(prev => [...prev, {
      id: `cm${Date.now()}`, sender: 'me', message: chatInput,
      timestamp: new Date().toISOString(), is_system: false,
    }])
    setChatInput('')
  }

  const addEvent = () => {
    if (!addEventForm?.description.trim()) return
    const ev: TimelineEvent = {
      id: `te${Date.now()}`, actor: 'me', action: addEventForm.description,
      timestamp: new Date().toISOString(), type: addEventForm.type,
    }
    setLocalTimeline(p => ({ ...p, [incident.id]: [ev, ...(p[incident.id] ?? [])] }))
    setAddEventForm(null)
  }

  const addTask = () => {
    if (!newTask.description.trim()) return
    const t: Task = { id: `tk${Date.now()}`, ...newTask, done: false }
    setLocalTasks(p => ({ ...p, [incident.id]: [...(p[incident.id] ?? []), t] }))
    setNewTask({ description: '', assignee: '', due_time: '', priority: 'high' })
    setAddTaskForm(false)
  }

  const toggleTask = (id: string) => {
    setLocalTasks(p => ({
      ...p, [incident.id]: (p[incident.id] ?? []).map(t => t.id === id ? { ...t, done: !t.done } : t),
    }))
  }

  if (!incident) return (
    <div className="min-h-screen bg-[#070d19] p-4">
      <div className="flex items-center gap-3 mb-6">
        <div className="w-10 h-10 rounded-xl bg-gradient-to-br from-[#e8002d]/20 to-[#e8002d]/5 border border-[#e8002d]/30 flex items-center justify-center">
          <AlertOctagon className="w-5 h-5 text-[#e8002d]" />
        </div>
        <div>
          <h1 className="text-white font-bold text-xl">インシデント対応作戦室</h1>
          <p className="text-[#7d92b0] text-sm">アクティブインシデントの指揮統制センター</p>
        </div>
      </div>
      <div className="bg-[#0d1220] border border-[#1e2d42] rounded-xl p-16 flex flex-col items-center justify-center gap-4">
        <AlertOctagon className="w-12 h-12 text-[#3d5068]" />
        <p className="text-[#e2e8f4] font-semibold">対応中のインシデントはありません</p>
        <p className="text-[#7d92b0] text-sm text-center">新しいインシデントが検知されると、ここに表示されます。<br />インシデントは「インシデント」ページから手動で作成することもできます。</p>
        <a href="/incidents" className="mt-2 px-4 py-2 bg-[#1e2d42] hover:bg-[#2d3f58] border border-[#2d3f58] text-[#e2e8f4] text-sm rounded-lg transition-colors">
          インシデント一覧へ
        </a>
      </div>
    </div>
  )

  return (
    <div className="min-h-screen bg-[#070d19] p-4">
      {/* Header */}
      <div className="flex items-center justify-between mb-4">
        <div className="flex items-center gap-3">
          <div className="w-10 h-10 rounded-xl bg-gradient-to-br from-[#e8002d]/20 to-[#e8002d]/5 border border-[#e8002d]/30 flex items-center justify-center">
            <AlertOctagon className="w-5 h-5 text-[#e8002d]" />
          </div>
          <div>
            <h1 className="text-white font-bold text-xl">インシデント対応作戦室</h1>
            <p className="text-[#7d92b0] text-sm">アクティブインシデントの指揮統制センター</p>
          </div>
        </div>
        {/* Incident Selector */}
        <div className="flex items-center gap-2 overflow-x-auto max-w-[60%] pb-1">
          {incidents.map(i => (
            <button key={i.id} onClick={() => setSelectedId(i.id)}
              className={`flex-shrink-0 px-3 py-2 rounded-lg text-xs font-medium border transition-colors ${
                selectedId === i.id ? 'bg-[#e8002d]/20 border-[#e8002d]/50 text-white' : 'bg-[#0d1220] border-[#1e2d42] text-[#7d92b0] hover:border-[#7d92b0]/40'
              }`}>
              <span className={`inline-block w-1.5 h-1.5 rounded-full mr-1.5 ${i.severity === 'critical' ? 'bg-red-400 animate-pulse' : 'bg-orange-400'}`} />
              {i.id.slice(0, 8)}…
            </button>
          ))}
        </div>
      </div>

      <div className="flex gap-4 h-[calc(100vh-140px)]">
        {/* ── Left Panel ──────────────────────────────────────────────────────── */}
        <div className="w-[30%] flex-shrink-0 flex flex-col gap-3 overflow-y-auto">
          {/* Summary */}
          <div className="bg-[#0d1220] border border-[#1e2d42] rounded-xl p-4">
            <div className="flex items-start justify-between mb-3">
              <div>
                <p className="text-[#7d92b0] text-xs">{incident.id}</p>
                <h2 className="text-white font-semibold text-sm mt-0.5 leading-snug">{incident.title}</h2>
              </div>
              <span className={`px-2 py-0.5 rounded text-xs font-medium ${SEV_BADGE[incident.severity]}`}>{incident.severity}</span>
            </div>
            <div className="grid grid-cols-2 gap-2 text-xs">
              <div className="bg-[#070d19] rounded-lg p-2">
                <p className="text-[#7d92b0]">ステータス</p>
                <p className="text-white font-medium mt-0.5">{incident.status}</p>
              </div>
              <div className="bg-[#070d19] rounded-lg p-2">
                <p className="text-[#7d92b0]">経過時間</p>
                <p className="text-white font-medium mt-0.5">{elapsed(incident.created_at)}</p>
              </div>
              <div className="bg-[#070d19] rounded-lg p-2">
                <p className="text-[#7d92b0]">影響資産</p>
                <p className="text-white font-medium mt-0.5">{assets.length}台</p>
              </div>
              <div className="bg-[#070d19] rounded-lg p-2">
                <p className="text-[#7d92b0]">タイムライン</p>
                <p className="text-white font-medium mt-0.5">{timeline.length}件</p>
              </div>
            </div>
          </div>

          {/* Responders */}
          <div className="bg-[#0d1220] border border-[#1e2d42] rounded-xl p-4">
            <div className="flex items-center justify-between mb-3">
              <div className="flex items-center gap-2">
                <Users className="w-4 h-4 text-[#7d92b0]" />
                <span className="text-white text-sm font-medium">対応チーム</span>
              </div>
              <button className="flex items-center gap-1 px-2 py-1 bg-[#e8002d]/10 hover:bg-[#e8002d]/20 border border-[#e8002d]/30 rounded text-xs text-[#e8002d]">
                <UserPlus className="w-3 h-3" />参加
              </button>
            </div>
            <p className="text-[#7d92b0] text-xs mb-2">{incident.assigned_team}</p>
            <div className="flex flex-wrap gap-2">
              {(incident.assigned_to ?? []).map(u => (
                <div key={u} className="flex items-center gap-1.5">
                  <Avatar name={u} size="sm" />
                  <span className="text-[#7d92b0] text-xs">{u}</span>
                </div>
              ))}
            </div>
          </div>

          {/* Escalation Path */}
          <div className="bg-[#0d1220] border border-[#1e2d42] rounded-xl p-4">
            <div className="flex items-center gap-2 mb-3">
              <AlertOctagon className="w-4 h-4 text-orange-400" />
              <span className="text-white text-sm font-medium">エスカレーションパス</span>
            </div>
            <div className="space-y-2 text-xs">
              {[
                { who: 'CSIRT Alert System', when: fmtTime(incident.created_at), done: true },
                { who: 'CSIRT チームリード', when: fmtTime(incident.created_at), done: true },
                { who: 'CISO', when: `${new Date(new Date(incident.created_at).getTime() + 6 * 60000).toLocaleTimeString('ja-JP', { hour: '2-digit', minute: '2-digit' })}`, done: incident.severity === 'critical' },
                { who: 'IT部門長', when: `${new Date(new Date(incident.created_at).getTime() + 8 * 60000).toLocaleTimeString('ja-JP', { hour: '2-digit', minute: '2-digit' })}`, done: incident.severity === 'critical' },
                { who: 'CEO・役員', when: '必要時', done: false },
              ].map((step, i) => (
                <div key={i} className="flex items-center gap-2">
                  {step.done
                    ? <CheckCircle className="w-4 h-4 text-green-400 flex-shrink-0" />
                    : <div className="w-4 h-4 rounded-full border border-[#1e2d42] flex-shrink-0" />}
                  <span className={step.done ? 'text-white' : 'text-[#3d5068]'}>{step.who}</span>
                  <span className="ml-auto text-[#3d5068]">{step.when}</span>
                </div>
              ))}
            </div>
          </div>

          {/* Related Alerts */}
          <div className="bg-[#0d1220] border border-[#1e2d42] rounded-xl p-4">
            <div className="flex items-center gap-2 mb-3">
              <AlertTriangle className="w-4 h-4 text-[#e8002d]" />
              <span className="text-white text-sm font-medium">関連アラート</span>
            </div>
            <div className="space-y-1.5">
              {(incident.alert_ids ?? []).map(id => (
                <div key={id} className="flex items-center gap-2 px-2 py-1.5 bg-[#070d19] rounded-lg">
                  <span className="w-1.5 h-1.5 rounded-full bg-[#e8002d] flex-shrink-0" />
                  <span className="text-white text-xs">{id}</span>
                  <button className="ml-auto text-[#7d92b0] text-[10px] hover:text-white">詳細 →</button>
                </div>
              ))}
            </div>
          </div>
        </div>

        {/* ── Main Panel ──────────────────────────────────────────────────────── */}
        <div className="flex-1 flex flex-col min-w-0 bg-[#0d1220] border border-[#1e2d42] rounded-xl overflow-hidden">
          {/* Inner Tabs */}
          <div className="flex border-b border-[#1e2d42] px-1 pt-1 gap-1 flex-shrink-0">
            {([
              ['timeline', 'タイムライン', <Activity key="t" className="w-3.5 h-3.5" />],
              ['evidence', '証拠', <Archive key="e" className="w-3.5 h-3.5" />],
              ['chat', 'チャット', <MessageSquare key="c" className="w-3.5 h-3.5" />],
              ['tasks', 'タスク', <ClipboardList key="tk" className="w-3.5 h-3.5" />],
              ['containment', '封じ込め', <Lock key="co" className="w-3.5 h-3.5" />],
            ] as const).map(([key, label, icon]) => (
              <button key={key} onClick={() => setInnerTab(key as typeof innerTab)}
                className={`flex items-center gap-1.5 px-3 py-2.5 text-xs font-medium rounded-t-lg border-b-2 transition-colors ${
                  innerTab === key
                    ? 'border-[#e8002d] text-white bg-[#070d19]'
                    : 'border-transparent text-[#7d92b0] hover:text-white'
                }`}>
                {icon}{label}
              </button>
            ))}
          </div>

          <div className="flex-1 overflow-y-auto p-4">
            {/* ── Timeline ──── */}
            {innerTab === 'timeline' && (
              <div className="space-y-4">
                <div className="flex items-center justify-between">
                  <div className="flex gap-2 flex-wrap">
                    {(['all', 'alert', 'action', 'note', 'escalation', 'containment'] as const).map(f => (
                      <button key={f} onClick={() => setTimelineFilter(f)}
                        className={`px-3 py-1 rounded-lg text-xs border transition-colors ${
                          timelineFilter === f ? 'bg-[#e8002d]/20 border-[#e8002d]/50 text-white' : 'bg-[#070d19] border-[#1e2d42] text-[#7d92b0]'
                        }`}>{f === 'all' ? '全て' : f}</button>
                    ))}
                  </div>
                  <button onClick={() => setAddEventForm({ type: 'note', description: '' })}
                    className="flex items-center gap-1.5 px-3 py-1.5 bg-[#e8002d] hover:bg-[#c8001e] text-white rounded-lg text-xs">
                    <Plus className="w-3.5 h-3.5" />イベント追加
                  </button>
                </div>

                {addEventForm && (
                  <div className="bg-[#070d19] border border-[#e8002d]/30 rounded-xl p-4">
                    <div className="flex gap-3 mb-3">
                      <select value={addEventForm.type} onChange={e => setAddEventForm(p => p ? { ...p, type: e.target.value as EventType } : null)}
                        className="bg-[#0d1220] border border-[#1e2d42] rounded-lg px-3 py-1.5 text-sm text-white focus:outline-none">
                        {(['alert', 'action', 'note', 'escalation', 'containment'] as EventType[]).map(t => <option key={t} value={t}>{t}</option>)}
                      </select>
                    </div>
                    <textarea value={addEventForm.description} onChange={e => setAddEventForm(p => p ? { ...p, description: e.target.value } : null)}
                      rows={2} placeholder="イベント内容を入力..."
                      className="w-full bg-[#0d1220] border border-[#1e2d42] rounded-lg px-3 py-2 text-sm text-white resize-none focus:outline-none mb-3" />
                    <div className="flex gap-2 justify-end">
                      <button onClick={() => setAddEventForm(null)} className="px-3 py-1.5 text-xs text-[#7d92b0] border border-[#1e2d42] rounded-lg">キャンセル</button>
                      <button onClick={addEvent} className="px-3 py-1.5 text-xs bg-[#e8002d] text-white rounded-lg">追加</button>
                    </div>
                  </div>
                )}

                <div className="relative pl-6">
                  <div className="absolute left-2 top-0 bottom-0 w-0.5 bg-[#1e2d42]" />
                  <div className="space-y-4">
                    {filteredTimeline.map(ev => (
                      <div key={ev.id} className="relative">
                        <div className="absolute -left-[18px] top-1 w-5 h-5 rounded-full bg-[#0d1220] border border-[#1e2d42] flex items-center justify-center">
                          {EVT_ICON[ev.type]}
                        </div>
                        <div className="bg-[#070d19] border border-[#1e2d42] rounded-lg p-3">
                          <div className="flex items-center gap-2 mb-1">
                            <Avatar name={ev.actor} size="sm" />
                            <span className="text-white text-xs font-medium">{ev.actor}</span>
                            <span className="text-[#3d5068] text-xs ml-auto">{fmtTime(ev.timestamp)}</span>
                          </div>
                          <p className="text-[#7d92b0] text-xs">{ev.action}</p>
                          {ev.description && <p className="text-[#e2e8f4] text-xs mt-1 italic">{ev.description}</p>}
                        </div>
                      </div>
                    ))}
                  </div>
                </div>
              </div>
            )}

            {/* ── Evidence ──── */}
            {innerTab === 'evidence' && (
              <div className="space-y-4">
                {/* Upload Area */}
                <div className="border-2 border-dashed border-[#1e2d42] hover:border-[#e8002d]/40 rounded-xl p-6 text-center transition-colors cursor-pointer">
                  <Upload className="w-8 h-8 text-[#3d5068] mx-auto mb-2" />
                  <p className="text-[#7d92b0] text-sm">ファイルをドロップまたはクリックしてアップロード</p>
                  <p className="text-[#3d5068] text-xs mt-1">または</p>
                  <button className="mt-2 px-3 py-1.5 bg-[#1e2d42] hover:bg-[#253650] rounded-lg text-xs text-[#7d92b0]">テキストノートを追加</button>
                </div>

                <div className="space-y-2">
                  {evidence.map(ev => (
                    <div key={ev.id} className="flex items-center gap-3 bg-[#070d19] border border-[#1e2d42] rounded-xl p-3">
                      <div className="w-9 h-9 bg-[#0d1220] rounded-lg flex items-center justify-center flex-shrink-0">
                        {EV_ICON[ev.type]}
                      </div>
                      <div className="flex-1 min-w-0">
                        <p className="text-white text-sm truncate">{ev.name}</p>
                        <p className="text-[#7d92b0] text-xs">{ev.added_by} · {fmtTime(ev.added_at)} · {ev.size}</p>
                      </div>
                      <span className="px-2 py-0.5 bg-[#1e2d42] rounded text-xs text-[#7d92b0]">{ev.type}</span>
                      <button className="p-1.5 hover:bg-[#1e2d42] rounded text-[#7d92b0] hover:text-white transition-colors">
                        <Download className="w-4 h-4" />
                      </button>
                    </div>
                  ))}
                </div>
              </div>
            )}

            {/* ── Chat ──── */}
            {innerTab === 'chat' && (
              <div className="flex flex-col h-full">
                <div className="flex-1 overflow-y-auto space-y-3 mb-4">
                  {[...chatMessages].sort((a, b) => new Date(a.timestamp).getTime() - new Date(b.timestamp).getTime()).map(m => (
                    <div key={m.id} className={`${m.is_system ? 'flex justify-center' : 'flex items-start gap-2.5'}`}>
                      {m.is_system ? (
                        <span className="text-[#3d5068] text-xs bg-[#070d19] px-3 py-1 rounded-full border border-[#1e2d42]">{m.message}</span>
                      ) : (
                        <>
                          <Avatar name={m.sender} size="sm" />
                          <div>
                            <div className="flex items-center gap-2 mb-1">
                              <span className="text-white text-xs font-medium">{m.sender}</span>
                              <span className="text-[#3d5068] text-[10px]">{fmtTime(m.timestamp)}</span>
                            </div>
                            <div className="bg-[#070d19] border border-[#1e2d42] rounded-xl px-3 py-2 text-sm text-[#e2e8f4] max-w-md">
                              {m.message}
                            </div>
                          </div>
                        </>
                      )}
                    </div>
                  ))}
                  <div ref={chatEndRef} />
                </div>
                <div className="flex gap-2 flex-shrink-0">
                  <input value={chatInput} onChange={e => setChatInput(e.target.value)}
                    onKeyDown={e => e.key === 'Enter' && !e.shiftKey && (e.preventDefault(), sendChat())}
                    placeholder="メッセージを入力... (Enter送信)"
                    className="flex-1 bg-[#070d19] border border-[#1e2d42] rounded-xl px-4 py-2.5 text-sm text-white focus:outline-none focus:border-[#e8002d]/50" />
                  <button onClick={sendChat} className="p-2.5 bg-[#e8002d] hover:bg-[#c8001e] text-white rounded-xl transition-colors">
                    <Send className="w-4 h-4" />
                  </button>
                </div>
              </div>
            )}

            {/* ── Tasks ──── */}
            {innerTab === 'tasks' && (
              <div className="space-y-4">
                <div className="flex items-center justify-between">
                  <div className="flex-1 mr-4">
                    <div className="flex items-center justify-between mb-1">
                      <span className="text-[#7d92b0] text-xs">{tasksDone}/{tasksTotal} 完了</span>
                      <span className="text-white text-xs font-medium">{tasksTotal > 0 ? Math.round(tasksDone / tasksTotal * 100) : 0}%</span>
                    </div>
                    <div className="w-full bg-[#1e2d42] rounded-full h-2">
                      <div className="bg-green-500 h-2 rounded-full transition-all" style={{ width: `${tasksTotal > 0 ? tasksDone / tasksTotal * 100 : 0}%` }} />
                    </div>
                  </div>
                  <button onClick={() => setAddTaskForm(true)}
                    className="flex items-center gap-1.5 px-3 py-1.5 bg-[#e8002d] hover:bg-[#c8001e] text-white rounded-lg text-xs">
                    <Plus className="w-3.5 h-3.5" />タスク追加
                  </button>
                </div>

                {addTaskForm && (
                  <div className="bg-[#070d19] border border-[#e8002d]/30 rounded-xl p-4 space-y-3">
                    <input value={newTask.description} onChange={e => setNewTask(p => ({ ...p, description: e.target.value }))}
                      placeholder="タスク内容..."
                      className="w-full bg-[#0d1220] border border-[#1e2d42] rounded-lg px-3 py-2 text-sm text-white focus:outline-none" />
                    <div className="grid grid-cols-3 gap-2">
                      <input value={newTask.assignee} onChange={e => setNewTask(p => ({ ...p, assignee: e.target.value }))}
                        placeholder="担当者"
                        className="bg-[#0d1220] border border-[#1e2d42] rounded-lg px-3 py-2 text-sm text-white focus:outline-none" />
                      <input type="datetime-local" value={newTask.due_time} onChange={e => setNewTask(p => ({ ...p, due_time: e.target.value }))}
                        className="bg-[#0d1220] border border-[#1e2d42] rounded-lg px-3 py-2 text-sm text-white focus:outline-none" />
                      <select value={newTask.priority} onChange={e => setNewTask(p => ({ ...p, priority: e.target.value as Priority }))}
                        className="bg-[#0d1220] border border-[#1e2d42] rounded-lg px-3 py-2 text-sm text-white focus:outline-none">
                        {(['critical', 'high', 'medium', 'low'] as Priority[]).map(p => <option key={p} value={p}>{p}</option>)}
                      </select>
                    </div>
                    <div className="flex gap-2 justify-end">
                      <button onClick={() => setAddTaskForm(false)} className="px-3 py-1.5 text-xs text-[#7d92b0] border border-[#1e2d42] rounded-lg">キャンセル</button>
                      <button onClick={addTask} className="px-3 py-1.5 text-xs bg-[#e8002d] text-white rounded-lg">追加</button>
                    </div>
                  </div>
                )}

                <div className="space-y-2">
                  {tasks.map(t => (
                    <div key={t.id} className={`flex items-center gap-3 bg-[#070d19] border rounded-xl p-3 transition-colors ${t.done ? 'border-[#1e2d42] opacity-60' : 'border-[#1e2d42]'}`}>
                      <button onClick={() => toggleTask(t.id)} className="flex-shrink-0">
                        {t.done
                          ? <CheckSquare className="w-5 h-5 text-green-400" />
                          : <Square className="w-5 h-5 text-[#3d5068] hover:text-[#7d92b0]" />}
                      </button>
                      <div className="flex-1 min-w-0">
                        <p className={`text-sm ${t.done ? 'line-through text-[#3d5068]' : 'text-white'}`}>{t.description}</p>
                        <p className="text-[#7d92b0] text-xs mt-0.5">{t.assignee} · 期限: {fmtTime(t.due_time)}</p>
                      </div>
                      <span className={`text-xs font-medium ${PRI_COLOR[t.priority]}`}>{t.priority}</span>
                    </div>
                  ))}
                </div>
              </div>
            )}

            {/* ── Containment ──── */}
            {innerTab === 'containment' && (
              <div className="space-y-4">
                {/* Summary */}
                <div className="flex items-center justify-between bg-[#070d19] border border-[#1e2d42] rounded-xl p-4">
                  <div>
                    <p className="text-[#7d92b0] text-xs mb-1">封じ込め状況</p>
                    <div className="flex items-center gap-3">
                      <span className="text-white text-2xl font-bold">{containedCount}</span>
                      <span className="text-[#7d92b0] text-sm">/ {assets.length} 台 封じ込め済み</span>
                    </div>
                    <div className="w-48 bg-[#1e2d42] rounded-full h-1.5 mt-2">
                      <div className="bg-green-500 h-1.5 rounded-full" style={{ width: `${assets.length > 0 ? containedCount / assets.length * 100 : 0}%` }} />
                    </div>
                  </div>
                  <button onClick={() => setConfirmBulkContain(true)}
                    className="px-4 py-2 bg-[#e8002d] hover:bg-[#c8001e] text-white rounded-lg text-sm font-medium">
                    全資産を封じ込め
                  </button>
                </div>

                {confirmBulkContain && (
                  <div className="bg-red-900/20 border border-red-700/50 rounded-xl p-4">
                    <p className="text-white text-sm font-medium mb-2">全資産の封じ込めを実行しますか？</p>
                    <p className="text-red-300 text-xs mb-4">この操作により全{assets.length}台の端末がネットワークから隔離されます。</p>
                    <div className="flex gap-2">
                      <button onClick={() => setConfirmBulkContain(false)} className="px-3 py-1.5 text-xs border border-[#1e2d42] text-[#7d92b0] rounded-lg">キャンセル</button>
                      <button onClick={() => setConfirmBulkContain(false)} className="px-3 py-1.5 text-xs bg-[#e8002d] text-white rounded-lg">実行確認</button>
                    </div>
                  </div>
                )}

                <div className="bg-[#0d1220] border border-[#1e2d42] rounded-xl overflow-hidden">
                  <table className="w-full text-sm">
                    <thead>
                      <tr className="border-b border-[#1e2d42]">
                        {['資産名', 'タイプ', 'IPアドレス', '封じ込め状態', '操作'].map(h => (
                          <th key={h} className="text-left px-4 py-3 text-xs text-[#7d92b0]">{h}</th>
                        ))}
                      </tr>
                    </thead>
                    <tbody>
                      {assets.map(a => (
                        <tr key={a.id} className="border-b border-[#1e2d42] hover:bg-[#070d19] transition-colors">
                          <td className="px-4 py-3 text-white font-medium">{a.name}</td>
                          <td className="px-4 py-3 text-[#7d92b0]">{a.type}</td>
                          <td className="px-4 py-3 text-[#7d92b0] font-mono text-xs">{a.ip}</td>
                          <td className="px-4 py-3">
                            <span className={`px-2 py-0.5 rounded text-xs font-medium ${CONTAIN_BADGE[a.containment_status]}`}>
                              {a.containment_status}
                            </span>
                          </td>
                          <td className="px-4 py-3">
                            <div className="flex gap-1.5 flex-wrap">
                              {['隔離', 'ブロック', 'ファイル検疫', 'プロセス終了'].map(action => (
                                <button key={action}
                                  className="px-2 py-0.5 bg-[#070d19] hover:bg-[#1e2d42] border border-[#1e2d42] rounded text-[10px] text-[#7d92b0] transition-colors">
                                  {action}
                                </button>
                              ))}
                            </div>
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              </div>
            )}
          </div>
        </div>
      </div>
    </div>
  )
}

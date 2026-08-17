'use client'

import { useState, useRef, useEffect } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { apiFetch } from '@/lib/api'
import {
  MessageSquare, Plus, X, Send, Pin, CheckSquare,
  Square, AlertTriangle, Users, Bell, BellOff,
  Circle, Clock, Activity, ChevronRight, Trash2,
  Hash, Eye, Settings
} from 'lucide-react'

// ─── Types ────────────────────────────────────────────────────────────────────

type ParticipantStatus = 'online' | 'away' | 'offline'
type RoomStatus = 'active' | 'closed' | 'paused'

interface Participant {
  id: string
  name: string
  role: string
  status: ParticipantStatus
  avatar: string
}

interface ChatMessage {
  id: string
  sender_id: string
  sender_name: string
  sender_avatar: string
  content: string
  timestamp: string
  is_system?: boolean
  mentions?: string[]
}

interface PinnedNote {
  id: string
  content: string
  author: string
  created_at: string
}

interface SharedIOC {
  id: string
  value: string
  type: 'ip' | 'domain' | 'hash' | 'url'
  added_by: string
}

interface TaskItem {
  id: string
  text: string
  done: boolean
  assignee?: string
}

interface Room {
  id: string
  name: string
  investigation: string
  status: RoomStatus
  participants: Participant[]
  last_activity: string
  message_count: number
  pinned_notes: PinnedNote[]
  shared_iocs: SharedIOC[]
  tasks: TaskItem[]
}

interface ActivityFeedItem {
  id: string
  room_name: string
  action: string
  actor: string
  timestamp: string
}

// ─── Mock Data ────────────────────────────────────────────────────────────────

const MOCK_ROOMS: Room[] = [
  {
    id: 'room-001',
    name: 'APT29 侵害調査',
    investigation: 'INC-2026-0042',
    status: 'active',
    last_activity: '2026-03-18T10:45:00Z',
    message_count: 47,
    participants: [
      { id: 'u1', name: '田中 健一', role: 'SOCアナリスト', status: 'online', avatar: 'TK' },
      { id: 'u2', name: '鈴木 美咲', role: 'インシデントマネージャー', status: 'online', avatar: 'SM' },
      { id: 'u3', name: '佐藤 太郎', role: 'フォレンジクス', status: 'away', avatar: 'ST' },
      { id: 'u4', name: '山田 花子', role: 'マルウェア分析', status: 'online', avatar: 'YH' },
    ],
    pinned_notes: [
      { id: 'n1', content: '初期侵害ポイント: VPN経由の認証情報漏洩を確認', author: '田中 健一', created_at: '2026-03-18T08:30:00Z' },
      { id: 'n2', content: 'C2サーバー: 192.168.99.5 ← ブロック済み', author: '鈴木 美咲', created_at: '2026-03-18T09:15:00Z' },
    ],
    shared_iocs: [
      { id: 'i1', value: '192.168.99.5', type: 'ip', added_by: '田中' },
      { id: 'i2', value: 'malware.evil.com', type: 'domain', added_by: '山田' },
      { id: 'i3', value: 'a3f1b2c9d4e5f678901234567890abcd', type: 'hash', added_by: '佐藤' },
    ],
    tasks: [
      { id: 't1', text: 'インパクト範囲の全エンドポイント特定', done: true, assignee: '田中' },
      { id: 't2', text: 'メモリダンプ取得 (SERVER-04)', done: false, assignee: '佐藤' },
      { id: 't3', text: 'CISO へのエスカレーション', done: false, assignee: '鈴木' },
    ],
  },
  {
    id: 'room-002',
    name: 'ランサムウェア対応',
    investigation: 'INC-2026-0038',
    status: 'active',
    last_activity: '2026-03-18T10:20:00Z',
    message_count: 23,
    participants: [
      { id: 'u2', name: '鈴木 美咲', role: 'インシデントマネージャー', status: 'online', avatar: 'SM' },
      { id: 'u5', name: '伊藤 次郎', role: 'SOCアナリスト', status: 'online', avatar: 'IJ' },
      { id: 'u6', name: '渡辺 良子', role: 'レスポンスエンジニア', status: 'away', avatar: 'WR' },
    ],
    pinned_notes: [
      { id: 'n3', content: '感染経路: フィッシングメール (3/17 14:22)', author: '鈴木 美咲', created_at: '2026-03-18T06:00:00Z' },
    ],
    shared_iocs: [
      { id: 'i4', value: 'https://badsite.ru/drop', type: 'url', added_by: '伊藤' },
    ],
    tasks: [
      { id: 't4', text: 'バックアップの整合性確認', done: false, assignee: '渡辺' },
      { id: 't5', text: '感染端末の隔離完了', done: true, assignee: '伊藤' },
    ],
  },
  {
    id: 'room-003',
    name: 'データ流出調査',
    investigation: 'INC-2026-0031',
    status: 'paused',
    last_activity: '2026-03-17T16:00:00Z',
    message_count: 89,
    participants: [
      { id: 'u1', name: '田中 健一', role: 'SOCアナリスト', status: 'offline', avatar: 'TK' },
      { id: 'u7', name: '小林 誠', role: 'コンプライアンス', status: 'offline', avatar: 'KM' },
    ],
    pinned_notes: [],
    shared_iocs: [],
    tasks: [
      { id: 't6', text: 'DLPログの詳細分析', done: false, assignee: '田中' },
    ],
  },
]

const MOCK_MESSAGES: Record<string, ChatMessage[]> = {
  'room-001': [
    { id: 'm1', sender_id: 'system', sender_name: 'システム', sender_avatar: 'SY', content: '田中 健一 がルームを作成しました', timestamp: '2026-03-18T07:00:00Z', is_system: true },
    { id: 'm2', sender_id: 'u1', sender_name: '田中 健一', sender_avatar: 'TK', content: '初期トリアージ完了。APT29のTTPに一致するパターンを確認しました。', timestamp: '2026-03-18T07:05:00Z' },
    { id: 'm3', sender_id: 'u2', sender_name: '鈴木 美咲', sender_avatar: 'SM', content: 'C2通信をブロックしました。@佐藤 メモリダンプをお願いできますか？', timestamp: '2026-03-18T08:30:00Z', mentions: ['佐藤'] },
    { id: 'm4', sender_id: 'u3', sender_name: '佐藤 太郎', sender_avatar: 'ST', content: 'SERVER-04のメモリダンプを取得中です。30分ほどかかります。', timestamp: '2026-03-18T08:35:00Z' },
    { id: 'm5', sender_id: 'u4', sender_name: '山田 花子', sender_avatar: 'YH', content: 'マルウェアのサンプル解析完了。Cobalt Strike Beaconを確認。IOCリストに追加しました。', timestamp: '2026-03-18T10:00:00Z' },
    { id: 'm6', sender_id: 'u1', sender_name: '田中 健一', sender_avatar: 'TK', content: '影響端末: 7台を特定。全て隔離済みです。', timestamp: '2026-03-18T10:30:00Z' },
    { id: 'm7', sender_id: 'system', sender_name: 'システム', sender_avatar: 'SY', content: '山田 花子 がIOCを3件追加しました', timestamp: '2026-03-18T10:45:00Z', is_system: true },
  ],
  'room-002': [
    { id: 'm8', sender_id: 'u2', sender_name: '鈴木 美咲', sender_avatar: 'SM', content: 'ランサムウェア感染を確認。初動対応を開始します。', timestamp: '2026-03-18T06:00:00Z' },
    { id: 'm9', sender_id: 'u5', sender_name: '伊藤 次郎', sender_avatar: 'IJ', content: '感染端末を隔離しました。5台確認。', timestamp: '2026-03-18T06:30:00Z' },
    { id: 'm10', sender_id: 'u6', sender_name: '渡辺 良子', sender_avatar: 'WR', content: 'バックアップシステムの確認を開始します。', timestamp: '2026-03-18T08:00:00Z' },
  ],
  'room-003': [],
}

const MOCK_ACTIVITY: ActivityFeedItem[] = [
  { id: 'a1', room_name: 'APT29 侵害調査', action: 'IOCを3件追加', actor: '山田 花子', timestamp: '2026-03-18T10:45:00Z' },
  { id: 'a2', room_name: 'APT29 侵害調査', action: 'タスクを完了: インパクト範囲の全エンドポイント特定', actor: '田中 健一', timestamp: '2026-03-18T10:30:00Z' },
  { id: 'a3', room_name: 'ランサムウェア対応', action: 'タスクを完了: 感染端末の隔離完了', actor: '伊藤 次郎', timestamp: '2026-03-18T09:00:00Z' },
  { id: 'a4', room_name: 'APT29 侵害調査', action: 'ノートを固定', actor: '鈴木 美咲', timestamp: '2026-03-18T09:15:00Z' },
  { id: 'a5', room_name: 'ランサムウェア対応', action: '新しいメッセージ', actor: '渡辺 良子', timestamp: '2026-03-18T08:00:00Z' },
]

// ─── Helpers ──────────────────────────────────────────────────────────────────

const statusColor: Record<ParticipantStatus, string> = {
  online: 'bg-green-400', away: 'bg-yellow-400', offline: 'bg-falcon-subtle',
}
const statusLabel: Record<ParticipantStatus, string> = {
  online: 'オンライン', away: '離席中', offline: 'オフライン',
}
const roomStatusColor: Record<RoomStatus, string> = {
  active: 'text-green-400', closed: 'text-falcon-muted', paused: 'text-yellow-400',
}
const iocTypeColor: Record<SharedIOC['type'], string> = {
  ip: 'bg-red-500/20 text-red-300', domain: 'bg-orange-500/20 text-orange-300',
  hash: 'bg-purple-500/20 text-purple-300', url: 'bg-blue-500/20 text-blue-300',
}

function Avatar({ initials, size = 'sm' }: { initials: string; size?: 'sm' | 'md' }) {
  const sz = size === 'md' ? 'w-9 h-9 text-sm' : 'w-7 h-7 text-xs'
  const colors = ['from-blue-600 to-blue-800', 'from-purple-600 to-purple-800', 'from-green-600 to-green-800', 'from-orange-600 to-orange-800']
  const ci = initials.charCodeAt(0) % colors.length
  return (
    <div className={`${sz} rounded-full bg-linear-to-br ${colors[ci]} flex items-center justify-center shrink-0 font-bold text-white`}>
      {initials}
    </div>
  )
}

function timeAgo(ts: string) {
  const diff = Date.now() - new Date(ts).getTime()
  const m = Math.floor(diff / 60000)
  if (m < 1) return 'たった今'
  if (m < 60) return `${m}分前`
  const h = Math.floor(m / 60)
  if (h < 24) return `${h}時間前`
  return `${Math.floor(h / 24)}日前`
}

// ─── New Room Modal ───────────────────────────────────────────────────────────

function NewRoomModal({ onClose, onSave }: { onClose: () => void; onSave: (d: any) => void }) {
  const [investigation, setInvestigation] = useState('')
  const [name, setName] = useState('')
  const [inviteEmail, setInviteEmail] = useState('')

  return (
    <div className="fixed inset-0 bg-black/60 z-50 flex items-center justify-center p-4">
      <div className="bg-falcon-surface border border-falcon-border rounded-xl w-full max-w-md">
        <div className="flex items-center justify-between px-6 py-4 border-b border-falcon-border">
          <h3 className="text-white font-semibold">新規ルーム作成</h3>
          <button onClick={onClose} className="text-falcon-muted hover:text-white"><X className="w-5 h-5" /></button>
        </div>
        <div className="p-6 space-y-4">
          <div>
            <label className="text-xs text-falcon-muted mb-1 block">ルーム名</label>
            <input
              className="w-full bg-[#070d19] border border-falcon-border rounded-sm px-3 py-2 text-sm text-white focus:outline-hidden focus:border-falcon-red/50"
              placeholder="例: APT41 侵害調査"
              value={name} onChange={e => setName(e.target.value)}
            />
          </div>
          <div>
            <label className="text-xs text-falcon-muted mb-1 block">インシデント/調査 ID</label>
            <input
              className="w-full bg-[#070d19] border border-falcon-border rounded-sm px-3 py-2 text-sm text-white focus:outline-hidden focus:border-falcon-red/50"
              placeholder="例: INC-2026-0050"
              value={investigation} onChange={e => setInvestigation(e.target.value)}
            />
          </div>
          <div>
            <label className="text-xs text-falcon-muted mb-1 block">メンバー招待 (メール)</label>
            <input
              className="w-full bg-[#070d19] border border-falcon-border rounded-sm px-3 py-2 text-sm text-white focus:outline-hidden focus:border-falcon-red/50"
              placeholder="user@corp.com, ..."
              value={inviteEmail} onChange={e => setInviteEmail(e.target.value)}
            />
          </div>
        </div>
        <div className="flex justify-end gap-3 px-6 py-4 border-t border-falcon-border">
          <button onClick={onClose} className="px-4 py-2 text-sm text-falcon-muted hover:text-white">キャンセル</button>
          <button
            onClick={() => onSave({ name, investigation, invite_emails: inviteEmail.split(',').map(e => e.trim()) })}
            className="px-4 py-2 bg-falcon-red hover:bg-[#c0001f] text-white text-sm rounded-lg"
          >
            作成
          </button>
        </div>
      </div>
    </div>
  )
}

// ─── Main Page ────────────────────────────────────────────────────────────────

export default function CollaborationPage() {
  const qc = useQueryClient()
  const [selectedRoom, setSelectedRoom] = useState<Room | null>(null)
  const [showNewRoom, setShowNewRoom] = useState(false)
  const [msgInput, setMsgInput] = useState('')
  const [newNote, setNewNote] = useState('')
  const [addingNote, setAddingNote] = useState(false)
  const [newIOC, setNewIOC] = useState('')
  const [newIOCType, setNewIOCType] = useState<SharedIOC['type']>('ip')
  const [newTask, setNewTask] = useState('')
  const [alertOnMsg, setAlertOnMsg] = useState(true)
  const [alertOnMention, setAlertOnMention] = useState(true)
  const [rooms, setRooms] = useState<Room[]>([])
  const [messagesMap, setMessagesMap] = useState<Record<string, ChatMessage[]>>({})
  const chatEndRef = useRef<HTMLDivElement>(null)

  const messages = selectedRoom ? (messagesMap[selectedRoom.id] ?? []) : []

  useEffect(() => {
    chatEndRef.current?.scrollIntoView({ behavior: 'smooth' })
  }, [messages.length])

  const sendMessage = () => {
    if (!msgInput.trim() || !selectedRoom) return
    const msg: ChatMessage = {
      id: `m-${Date.now()}`, sender_id: 'me', sender_name: '現在のユーザー',
      sender_avatar: 'ME', content: msgInput, timestamp: new Date().toISOString(),
    }
    setMessagesMap(prev => ({ ...prev, [selectedRoom.id]: [...(prev[selectedRoom.id] ?? []), msg] }))
    setMsgInput('')
  }

  const addNote = () => {
    if (!newNote.trim() || !selectedRoom) return
    const note: PinnedNote = { id: `n-${Date.now()}`, content: newNote, author: '現在のユーザー', created_at: new Date().toISOString() }
    setRooms(prev => prev.map(r => r.id === selectedRoom.id ? { ...r, pinned_notes: [...r.pinned_notes, note] } : r))
    setSelectedRoom(prev => prev ? { ...prev, pinned_notes: [...prev.pinned_notes, note] } : prev)
    setNewNote(''); setAddingNote(false)
  }

  const addIOC = () => {
    if (!newIOC.trim() || !selectedRoom) return
    const ioc: SharedIOC = { id: `i-${Date.now()}`, value: newIOC, type: newIOCType, added_by: '現在のユーザー' }
    setRooms(prev => prev.map(r => r.id === selectedRoom.id ? { ...r, shared_iocs: [...r.shared_iocs, ioc] } : r))
    setSelectedRoom(prev => prev ? { ...prev, shared_iocs: [...prev.shared_iocs, ioc] } : prev)
    setNewIOC('')
  }

  const addTask = () => {
    if (!newTask.trim() || !selectedRoom) return
    const task: TaskItem = { id: `t-${Date.now()}`, text: newTask, done: false }
    setRooms(prev => prev.map(r => r.id === selectedRoom.id ? { ...r, tasks: [...r.tasks, task] } : r))
    setSelectedRoom(prev => prev ? { ...prev, tasks: [...prev.tasks, task] } : prev)
    setNewTask('')
  }

  const toggleTask = (taskId: string) => {
    if (!selectedRoom) return
    const updated = selectedRoom.tasks.map(t => t.id === taskId ? { ...t, done: !t.done } : t)
    setRooms(prev => prev.map(r => r.id === selectedRoom.id ? { ...r, tasks: updated } : r))
    setSelectedRoom(prev => prev ? { ...prev, tasks: updated } : prev)
  }

  return (
    <div className="min-h-screen bg-[#070d19] p-6 space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-3">
          <div className="w-10 h-10 rounded-lg bg-falcon-red/10 border border-falcon-red/30 flex items-center justify-center">
            <MessageSquare className="w-5 h-5 text-falcon-red" />
          </div>
          <div>
            <h1 className="text-xl font-bold text-white">チームコラボレーション</h1>
            <p className="text-xs text-falcon-muted">リアルタイム調査コラボレーション</p>
          </div>
        </div>
        <div className="flex items-center gap-3">
          {/* Notification settings */}
          <div className="flex items-center gap-2 bg-falcon-surface border border-falcon-border rounded-lg px-3 py-2">
            <button
              onClick={() => setAlertOnMsg(!alertOnMsg)}
              className={`flex items-center gap-1 text-xs transition-colors ${alertOnMsg ? 'text-blue-400' : 'text-falcon-muted'}`}
              title="新着メッセージ通知"
            >
              {alertOnMsg ? <Bell className="w-3.5 h-3.5" /> : <BellOff className="w-3.5 h-3.5" />}
              <span>メッセージ</span>
            </button>
            <div className="w-px h-4 bg-falcon-border" />
            <button
              onClick={() => setAlertOnMention(!alertOnMention)}
              className={`flex items-center gap-1 text-xs transition-colors ${alertOnMention ? 'text-blue-400' : 'text-falcon-muted'}`}
              title="メンション通知"
            >
              {alertOnMention ? <Bell className="w-3.5 h-3.5" /> : <BellOff className="w-3.5 h-3.5" />}
              <span>メンション</span>
            </button>
          </div>
          <button
            onClick={() => setShowNewRoom(true)}
            className="flex items-center gap-2 px-4 py-2 bg-falcon-red hover:bg-[#c0001f] text-white text-sm rounded-lg transition-colors"
          >
            <Plus className="w-4 h-4" /> 新規ルーム作成
          </button>
        </div>
      </div>

      <div className="grid grid-cols-12 gap-4" style={{ minHeight: '70vh' }}>
        {/* Room list (left) */}
        <div className="col-span-3 space-y-2">
          <p className="text-xs text-falcon-muted font-medium px-1">調査ルーム ({rooms.length})</p>
          {rooms.map(room => (
            <button
              key={room.id}
              onClick={() => setSelectedRoom(room)}
              className={`w-full text-left bg-falcon-surface border rounded-xl p-3 transition-all ${
                selectedRoom?.id === room.id ? 'border-falcon-red/40 bg-falcon-active/50' : 'border-falcon-border hover:border-falcon-border/80'
              }`}
            >
              <div className="flex items-start justify-between mb-1">
                <p className="text-sm text-white font-medium leading-tight">{room.name}</p>
                <span className={`text-[10px] ${roomStatusColor[room.status]}`}>
                  {room.status === 'active' ? '● アクティブ' : room.status === 'paused' ? '⏸ 一時停止' : '● クローズ'}
                </span>
              </div>
              <p className="text-[11px] text-falcon-muted mb-2">{room.investigation}</p>
              <div className="flex items-center justify-between">
                <div className="flex -space-x-1">
                  {room.participants.slice(0, 4).map(p => (
                    <div key={p.id} className="relative">
                      <Avatar initials={p.avatar} />
                      <span className={`absolute -bottom-0.5 -right-0.5 w-2 h-2 rounded-full border border-falcon-surface ${statusColor[p.status]}`} />
                    </div>
                  ))}
                  {room.participants.length > 4 && (
                    <div className="w-7 h-7 rounded-full bg-falcon-border flex items-center justify-center text-[10px] text-falcon-muted">
                      +{room.participants.length - 4}
                    </div>
                  )}
                </div>
                <span className="text-[10px] text-falcon-muted">{timeAgo(room.last_activity)}</span>
              </div>
            </button>
          ))}
        </div>

        {/* Main area */}
        {selectedRoom ? (
          <>
            {/* Participants (left inner) */}
            <div className="col-span-2 bg-falcon-surface border border-falcon-border rounded-xl p-3 space-y-2">
              <p className="text-xs text-falcon-muted font-medium mb-3">参加者 ({selectedRoom.participants.length})</p>
              {selectedRoom.participants.map(p => (
                <div key={p.id} className="flex items-center gap-2">
                  <div className="relative">
                    <Avatar initials={p.avatar} />
                    <span className={`absolute -bottom-0.5 -right-0.5 w-2.5 h-2.5 rounded-full border-2 border-falcon-surface ${statusColor[p.status]}`} />
                  </div>
                  <div className="min-w-0">
                    <p className="text-xs text-white font-medium truncate">{p.name}</p>
                    <p className="text-[10px] text-falcon-muted truncate">{p.role}</p>
                    <p className={`text-[10px] ${p.status === 'online' ? 'text-green-400' : p.status === 'away' ? 'text-yellow-400' : 'text-falcon-subtle'}`}>
                      {statusLabel[p.status]}
                    </p>
                  </div>
                </div>
              ))}
            </div>

            {/* Chat (center) */}
            <div className="col-span-4 bg-falcon-surface border border-falcon-border rounded-xl flex flex-col">
              <div className="flex items-center gap-2 px-4 py-3 border-b border-falcon-border">
                <Hash className="w-4 h-4 text-falcon-muted" />
                <p className="text-sm text-white font-medium">{selectedRoom.name}</p>
                <span className="text-[11px] text-falcon-muted ml-auto">{messages.length} メッセージ</span>
              </div>
              <div className="flex-1 overflow-y-auto p-3 space-y-3 min-h-0 max-h-[480px]">
                {messages.map(msg => (
                  <div key={msg.id}>
                    {msg.is_system ? (
                      <div className="flex items-center gap-2 text-xs text-falcon-muted justify-center">
                        <div className="h-px flex-1 bg-falcon-border" />
                        <span className="flex items-center gap-1"><Activity className="w-3 h-3" />{msg.content}</span>
                        <div className="h-px flex-1 bg-falcon-border" />
                      </div>
                    ) : (
                      <div className="flex items-start gap-2">
                        <Avatar initials={msg.sender_avatar} />
                        <div className="flex-1 min-w-0">
                          <div className="flex items-baseline gap-2 mb-0.5">
                            <span className="text-xs font-semibold text-white">{msg.sender_name}</span>
                            <span className="text-[10px] text-falcon-subtle">{timeAgo(msg.timestamp)}</span>
                          </div>
                          <p className="text-xs text-falcon-muted leading-relaxed">{msg.content}</p>
                        </div>
                      </div>
                    )}
                  </div>
                ))}
                <div ref={chatEndRef} />
              </div>
              <div className="p-3 border-t border-falcon-border">
                <div className="flex items-center gap-2">
                  <input
                    className="flex-1 bg-[#070d19] border border-falcon-border rounded-lg px-3 py-2 text-sm text-white focus:outline-hidden focus:border-falcon-red/50"
                    placeholder="メッセージを入力... (@メンション)"
                    value={msgInput}
                    onChange={e => setMsgInput(e.target.value)}
                    onKeyDown={e => e.key === 'Enter' && sendMessage()}
                  />
                  <button
                    onClick={sendMessage}
                    className="p-2 bg-falcon-red hover:bg-[#c0001f] text-white rounded-lg transition-colors"
                  >
                    <Send className="w-4 h-4" />
                  </button>
                </div>
              </div>
            </div>

            {/* Shared Workspace (right) */}
            <div className="col-span-3 space-y-3">
              {/* Pinned Notes */}
              <div className="bg-falcon-surface border border-falcon-border rounded-xl p-3">
                <div className="flex items-center justify-between mb-2">
                  <div className="flex items-center gap-2">
                    <Pin className="w-3.5 h-3.5 text-yellow-400" />
                    <p className="text-xs text-white font-medium">固定メモ</p>
                  </div>
                  <button onClick={() => setAddingNote(!addingNote)} className="text-falcon-red hover:text-white">
                    <Plus className="w-3.5 h-3.5" />
                  </button>
                </div>
                {addingNote && (
                  <div className="mb-2 space-y-1">
                    <textarea
                      className="w-full bg-[#070d19] border border-falcon-border rounded-sm px-2 py-1 text-xs text-white focus:outline-hidden resize-none"
                      rows={2} placeholder="メモを入力..." value={newNote} onChange={e => setNewNote(e.target.value)}
                    />
                    <div className="flex gap-1">
                      <button onClick={addNote} className="flex-1 py-1 text-xs bg-falcon-red text-white rounded-sm">追加</button>
                      <button onClick={() => setAddingNote(false)} className="flex-1 py-1 text-xs text-falcon-muted border border-falcon-border rounded-sm">キャンセル</button>
                    </div>
                  </div>
                )}
                <div className="space-y-2 max-h-32 overflow-y-auto">
                  {selectedRoom.pinned_notes.length === 0 && <p className="text-[11px] text-falcon-subtle">メモなし</p>}
                  {selectedRoom.pinned_notes.map(n => (
                    <div key={n.id} className="bg-yellow-500/5 border border-yellow-500/20 rounded-sm p-2">
                      <p className="text-[11px] text-falcon-text leading-relaxed">{n.content}</p>
                      <p className="text-[10px] text-falcon-subtle mt-1">{n.author} · {timeAgo(n.created_at)}</p>
                    </div>
                  ))}
                </div>
              </div>

              {/* Shared IOCs */}
              <div className="bg-falcon-surface border border-falcon-border rounded-xl p-3">
                <div className="flex items-center justify-between mb-2">
                  <div className="flex items-center gap-2">
                    <AlertTriangle className="w-3.5 h-3.5 text-red-400" />
                    <p className="text-xs text-white font-medium">共有 IOC</p>
                  </div>
                </div>
                <div className="flex gap-1 mb-2">
                  <select
                    className="bg-[#070d19] border border-falcon-border rounded-sm px-1 py-1 text-[11px] text-white focus:outline-hidden"
                    value={newIOCType} onChange={e => setNewIOCType(e.target.value as SharedIOC['type'])}
                  >
                    <option value="ip">IP</option>
                    <option value="domain">ドメイン</option>
                    <option value="hash">ハッシュ</option>
                    <option value="url">URL</option>
                  </select>
                  <input
                    className="flex-1 bg-[#070d19] border border-falcon-border rounded-sm px-2 py-1 text-[11px] text-white focus:outline-hidden"
                    placeholder="IOC値..."
                    value={newIOC} onChange={e => setNewIOC(e.target.value)}
                    onKeyDown={e => e.key === 'Enter' && addIOC()}
                  />
                  <button onClick={addIOC} className="p-1 text-falcon-red hover:text-white"><Plus className="w-3.5 h-3.5" /></button>
                </div>
                <div className="space-y-1 max-h-28 overflow-y-auto">
                  {selectedRoom.shared_iocs.map(ioc => (
                    <div key={ioc.id} className="flex items-center gap-1.5">
                      <span className={`text-[10px] px-1.5 py-0.5 rounded-sm ${iocTypeColor[ioc.type]}`}>{ioc.type.toUpperCase()}</span>
                      <span className="text-[11px] text-falcon-muted font-mono truncate flex-1">{ioc.value}</span>
                    </div>
                  ))}
                  {selectedRoom.shared_iocs.length === 0 && <p className="text-[11px] text-falcon-subtle">IOCなし</p>}
                </div>
              </div>

              {/* Task Checklist */}
              <div className="bg-falcon-surface border border-falcon-border rounded-xl p-3">
                <div className="flex items-center gap-2 mb-2">
                  <CheckSquare className="w-3.5 h-3.5 text-blue-400" />
                  <p className="text-xs text-white font-medium">タスク ({selectedRoom.tasks.filter(t => t.done).length}/{selectedRoom.tasks.length})</p>
                </div>
                <div className="space-y-1.5 max-h-36 overflow-y-auto mb-2">
                  {selectedRoom.tasks.map(task => (
                    <div key={task.id} className="flex items-start gap-2 cursor-pointer" onClick={() => toggleTask(task.id)}>
                      {task.done
                        ? <CheckSquare className="w-4 h-4 text-green-400 shrink-0 mt-0.5" />
                        : <Square className="w-4 h-4 text-falcon-subtle shrink-0 mt-0.5" />
                      }
                      <div className="flex-1 min-w-0">
                        <p className={`text-[11px] ${task.done ? 'line-through text-falcon-subtle' : 'text-falcon-text'}`}>{task.text}</p>
                        {task.assignee && <p className="text-[10px] text-falcon-subtle">{task.assignee}</p>}
                      </div>
                    </div>
                  ))}
                </div>
                <div className="flex gap-1">
                  <input
                    className="flex-1 bg-[#070d19] border border-falcon-border rounded-sm px-2 py-1 text-[11px] text-white focus:outline-hidden"
                    placeholder="新しいタスク..."
                    value={newTask} onChange={e => setNewTask(e.target.value)}
                    onKeyDown={e => e.key === 'Enter' && addTask()}
                  />
                  <button onClick={addTask} className="p-1 text-falcon-red hover:text-white"><Plus className="w-3.5 h-3.5" /></button>
                </div>
              </div>
            </div>
          </>
        ) : (
          <div className="col-span-9 bg-falcon-surface border border-falcon-border rounded-xl flex items-center justify-center">
            <p className="text-falcon-muted">ルームを選択してください</p>
          </div>
        )}
      </div>

      {/* Activity Feed */}
      <div className="bg-falcon-surface border border-falcon-border rounded-xl p-4">
        <p className="text-sm text-white font-medium mb-3">最近のアクティビティ</p>
        <div className="space-y-2">
          {([] as ActivityFeedItem[]).map(a => (
            <div key={a.id} className="flex items-center gap-3 text-xs">
              <span className="text-falcon-muted w-20 shrink-0">{timeAgo(a.timestamp)}</span>
              <span className="text-falcon-red font-medium">{a.room_name}</span>
              <span className="text-falcon-muted">{a.actor} が {a.action}</span>
            </div>
          ))}
        </div>
      </div>

      {showNewRoom && (
        <NewRoomModal
          onClose={() => setShowNewRoom(false)}
          onSave={data => {
            const newRoom: Room = {
              id: `room-${Date.now()}`, name: data.name, investigation: data.investigation,
              status: 'active', participants: [], last_activity: new Date().toISOString(),
              message_count: 0, pinned_notes: [], shared_iocs: [], tasks: [],
            }
            setRooms(prev => [newRoom, ...prev])
            setShowNewRoom(false)
          }}
        />
      )}
    </div>
  )
}

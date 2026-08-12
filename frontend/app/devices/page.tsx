'use client'

import { useState } from 'react'
import { useQuery } from '@tanstack/react-query'
import { apiFetch } from '@/lib/api'
import {
  Usb, HardDrive, Monitor, Plus, Minus, RefreshCw,
  ChevronLeft, ChevronRight, ChevronDown,
} from 'lucide-react'

// ── Types ────────────────────────────────────────────────────────────────────

interface DeviceEvent {
  id: string
  agent_id: string
  device_type: string
  action: string
  vendor_id?: string
  product_id?: string
  serial?: string
  device_name?: string
  created_at: string
}

interface DeviceEventsResponse {
  data: DeviceEvent[]
  total: number
  limit: number
  offset: number
  has_more: boolean
}

interface StatEntry {
  action: string
  device_type: string
  count: number
}

interface DeviceStatsResponse {
  data: StatEntry[]
  since: string
  hours: number
}

// ── Helpers ──────────────────────────────────────────────────────────────────

function formatDate(iso: string): string {
  const d = new Date(iso)
  return d.toLocaleString('ja-JP', {
    year: 'numeric',
    month: '2-digit',
    day: '2-digit',
    hour: '2-digit',
    minute: '2-digit',
    second: '2-digit',
  })
}

function truncate(s: string, max = 16): string {
  return s.length > max ? s.slice(0, max) + '…' : s
}

function buildQuery(params: Record<string, string | number | undefined>): string {
  const p = new URLSearchParams()
  for (const [k, v] of Object.entries(params)) {
    if (v !== undefined && v !== '') p.set(k, String(v))
  }
  const s = p.toString()
  return s ? `?${s}` : ''
}

// ── Sub-components ────────────────────────────────────────────────────────────

function StatCard({
  label,
  value,
  icon: Icon,
  color,
}: {
  label: string
  value: number
  icon: React.ElementType
  color: string
}) {
  return (
    <div className="bg-gray-800 border border-gray-700 rounded-xl p-4 flex items-center gap-4">
      <div className={`p-2.5 rounded-lg bg-gray-900 ${color}`}>
        <Icon className="w-5 h-5" />
      </div>
      <div>
        <p className="text-gray-400 text-xs mb-0.5">{label}</p>
        <p className="text-white text-2xl font-bold leading-none">{value.toLocaleString()}</p>
      </div>
    </div>
  )
}

function DeviceTypeBadge({ type }: { type: string }) {
  const map: Record<string, { icon: React.ElementType; cls: string }> = {
    usb:     { icon: Usb,       cls: 'text-blue-300  bg-blue-900/40  border-blue-700/50' },
    storage: { icon: HardDrive, cls: 'text-purple-300 bg-purple-900/40 border-purple-700/50' },
    monitor: { icon: Monitor,   cls: 'text-cyan-300   bg-cyan-900/40   border-cyan-700/50' },
  }
  const { icon: Icon, cls } = map[type.toLowerCase()] ?? {
    icon: Usb,
    cls: 'text-gray-300 bg-gray-700/50 border-gray-600/50',
  }
  return (
    <span className={`inline-flex items-center gap-1 px-2 py-0.5 rounded-md border text-xs font-medium ${cls}`}>
      <Icon className="w-3 h-3" />
      {type}
    </span>
  )
}

function ActionBadge({ action }: { action: string }) {
  const isConnected = action === 'connected'
  return (
    <span
      className={`inline-flex items-center gap-1 px-2 py-0.5 rounded-md border text-xs font-medium ${
        isConnected
          ? 'text-green-300 bg-green-900/40 border-green-700/50'
          : 'text-red-300   bg-red-900/40   border-red-700/50'
      }`}
    >
      {isConnected ? <Plus className="w-3 h-3" /> : <Minus className="w-3 h-3" />}
      {action}
    </span>
  )
}

// ── Page ──────────────────────────────────────────────────────────────────────

const PAGE_LIMIT = 20

export default function DevicesPage() {
  const [agentId, setAgentId]       = useState('')
  const [action, setAction]         = useState('')
  const [deviceType, setDeviceType] = useState('')
  const [offset, setOffset]         = useState(0)

  const { data: agentsData } = useQuery<{ data: { id: string; hostname: string }[] }>({
    queryKey: ['agents-for-devices'],
    queryFn: () => apiFetch('/api/v1/agents?per_page=500'),
    staleTime: 60_000,
  })
  const agentsList = agentsData?.data ?? []

  // Stats (last 24 h)
  const { data: statsData, refetch: refetchStats, isFetching: statsFetching } =
    useQuery<DeviceStatsResponse>({
      queryKey: ['device-events-stats'],
      queryFn: () => apiFetch('/api/v1/device-events/stats'),
    })

  // Events list
  const { data: eventsData, isFetching: eventsFetching, refetch: refetchEvents } =
    useQuery<DeviceEventsResponse>({
      queryKey: ['device-events', agentId, action, deviceType, offset],
      queryFn: () =>
        apiFetch(
          `/api/v1/device-events${buildQuery({
            agent_id: agentId    || undefined,
            action:   action     || undefined,
            type:     deviceType || undefined,
            limit:    PAGE_LIMIT,
            offset,
          })}`
        ),
      placeholderData: (prev) => prev,
    })

  // Derived stats
  const stats = statsData?.data ?? []
  const connectedCount    = stats.filter(s => s.action === 'connected').reduce((a, s) => a + s.count, 0)
  const disconnectedCount = stats.filter(s => s.action === 'disconnected').reduce((a, s) => a + s.count, 0)
  const uniqueDeviceTypes = new Set(stats.map(s => s.device_type)).size

  const events = eventsData?.data ?? []
  const total  = eventsData?.total ?? 0
  const from   = total === 0 ? 0 : offset + 1
  const to     = Math.min(offset + PAGE_LIMIT, total)

  const isFetching = statsFetching || eventsFetching

  function handleRefresh() {
    refetchStats()
    refetchEvents()
  }

  function resetOffset() {
    setOffset(0)
  }

  return (
    <div className="p-6 space-y-6 max-w-7xl">

      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-white flex items-center gap-2">
            <Usb className="w-6 h-6 text-blue-400" />
            デバイスイベント
          </h1>
          <p className="text-gray-400 mt-1 text-sm">
            USBおよびストレージデバイスの接続・切断イベント
          </p>
        </div>
        <button
          onClick={handleRefresh}
          disabled={isFetching}
          className="flex items-center gap-2 px-3 py-1.5 bg-gray-800 hover:bg-gray-700
                     border border-gray-700 text-gray-400 hover:text-white rounded-lg
                     text-sm transition-colors disabled:opacity-50"
        >
          <RefreshCw className={`w-4 h-4 ${isFetching ? 'animate-spin' : ''}`} />
          更新
        </button>
      </div>

      {/* Stats bar */}
      <div className="grid grid-cols-3 gap-4">
        <StatCard
          label="接続 (直近24h)"
          value={connectedCount}
          icon={Plus}
          color="text-green-400"
        />
        <StatCard
          label="切断 (直近24h)"
          value={disconnectedCount}
          icon={Minus}
          color="text-red-400"
        />
        <StatCard
          label="デバイス種別数"
          value={uniqueDeviceTypes}
          icon={HardDrive}
          color="text-purple-400"
        />
      </div>

      {/* Filter bar */}
      <div className="bg-gray-800 border border-gray-700 rounded-xl p-4">
        <div className="flex flex-wrap gap-3 items-end">

          {/* Agent */}
          <div className="flex flex-col gap-1 min-w-[200px]">
            <label className="text-gray-400 text-xs font-medium">エージェント</label>
            <div className="relative">
              <select
                value={agentId}
                onChange={e => { setAgentId(e.target.value); resetOffset() }}
                className="w-full appearance-none bg-gray-900 border border-gray-700 rounded-lg px-3 py-1.5 text-sm text-white focus:outline-none focus:border-blue-500 transition-colors pr-8"
              >
                <option value="">すべて</option>
                {agentsList.map(a => (
                  <option key={a.id} value={a.id}>{a.hostname}</option>
                ))}
              </select>
              <ChevronDown className="absolute right-2 top-1/2 -translate-y-1/2 w-4 h-4 text-gray-500 pointer-events-none" />
            </div>
          </div>

          {/* Action */}
          <div className="flex flex-col gap-1">
            <label className="text-gray-400 text-xs font-medium">アクション</label>
            <select
              value={action}
              onChange={e => { setAction(e.target.value); resetOffset() }}
              className="bg-gray-900 border border-gray-700 rounded-lg px-3 py-1.5
                         text-sm text-white
                         focus:outline-none focus:border-blue-500 transition-colors"
            >
              <option value="">すべて</option>
              <option value="connected">connected</option>
              <option value="disconnected">disconnected</option>
            </select>
          </div>

          {/* Device type */}
          <div className="flex flex-col gap-1">
            <label className="text-gray-400 text-xs font-medium">デバイス種別</label>
            <select
              value={deviceType}
              onChange={e => { setDeviceType(e.target.value); resetOffset() }}
              className="bg-gray-900 border border-gray-700 rounded-lg px-3 py-1.5
                         text-sm text-white
                         focus:outline-none focus:border-blue-500 transition-colors"
            >
              <option value="">すべて</option>
              <option value="usb">usb</option>
              <option value="storage">storage</option>
              <option value="monitor">monitor</option>
            </select>
          </div>
        </div>
      </div>

      {/* Table */}
      <div className="bg-gray-800 border border-gray-700 rounded-xl overflow-hidden">
        <div className="overflow-x-auto">
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b border-gray-700 bg-gray-900/60">
                <th className="text-left text-gray-400 font-medium px-4 py-3">Agent ID</th>
                <th className="text-left text-gray-400 font-medium px-4 py-3">デバイス名</th>
                <th className="text-left text-gray-400 font-medium px-4 py-3">種別</th>
                <th className="text-left text-gray-400 font-medium px-4 py-3">アクション</th>
                <th className="text-left text-gray-400 font-medium px-4 py-3">Vendor ID</th>
                <th className="text-left text-gray-400 font-medium px-4 py-3">日時</th>
              </tr>
            </thead>
            <tbody>
              {events.length === 0 ? (
                <tr>
                  <td colSpan={6} className="text-center text-gray-500 py-12">
                    {isFetching ? '読み込み中...' : 'イベントが見つかりませんでした'}
                  </td>
                </tr>
              ) : (
                events.map((ev, i) => (
                  <tr
                    key={ev.id}
                    className={`border-b border-gray-700/50 hover:bg-gray-700/30 transition-colors ${
                      i % 2 === 0 ? '' : 'bg-gray-900/20'
                    }`}
                  >
                    <td className="px-4 py-3">
                      <span
                        title={ev.agent_id}
                        className="font-mono text-blue-300 text-xs bg-blue-900/20
                                   border border-blue-800/40 rounded px-1.5 py-0.5"
                      >
                        {truncate(ev.agent_id)}
                      </span>
                    </td>
                    <td className="px-4 py-3 text-gray-200">
                      {ev.device_name ?? <span className="text-gray-500">—</span>}
                    </td>
                    <td className="px-4 py-3">
                      <DeviceTypeBadge type={ev.device_type} />
                    </td>
                    <td className="px-4 py-3">
                      <ActionBadge action={ev.action} />
                    </td>
                    <td className="px-4 py-3 font-mono text-gray-400 text-xs">
                      {ev.vendor_id ?? <span className="text-gray-600">—</span>}
                    </td>
                    <td className="px-4 py-3 text-gray-400 text-xs whitespace-nowrap">
                      {formatDate(ev.created_at)}
                    </td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>

        {/* Pagination */}
        <div className="flex items-center justify-between px-4 py-3 border-t border-gray-700 bg-gray-900/40">
          <p className="text-gray-400 text-sm">
            {total === 0
              ? '0 件'
              : `${from} – ${to} / ${total.toLocaleString()} 件`}
          </p>
          <div className="flex items-center gap-2">
            <button
              onClick={() => setOffset(Math.max(0, offset - PAGE_LIMIT))}
              disabled={offset === 0 || isFetching}
              className="flex items-center gap-1 px-3 py-1.5 bg-gray-800 hover:bg-gray-700
                         border border-gray-700 text-gray-400 hover:text-white rounded-lg
                         text-sm transition-colors disabled:opacity-40 disabled:cursor-not-allowed"
            >
              <ChevronLeft className="w-4 h-4" />
              前へ
            </button>
            <button
              onClick={() => setOffset(offset + PAGE_LIMIT)}
              disabled={!eventsData?.has_more || isFetching}
              className="flex items-center gap-1 px-3 py-1.5 bg-gray-800 hover:bg-gray-700
                         border border-gray-700 text-gray-400 hover:text-white rounded-lg
                         text-sm transition-colors disabled:opacity-40 disabled:cursor-not-allowed"
            >
              次へ
              <ChevronRight className="w-4 h-4" />
            </button>
          </div>
        </div>
      </div>

    </div>
  )
}

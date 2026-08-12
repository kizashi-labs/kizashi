'use client'

import { useState, useMemo } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { apiFetch } from '@/lib/api'
import {
  Wifi, WifiOff, AlertTriangle, Shield,
  Filter, X, CheckCircle, XCircle, Eye,
  Radio, Cpu, Printer, Camera, Activity,
  ChevronRight, AlertOctagon, Bell, Clock,
} from 'lucide-react'
// ── Types ─────────────────────────────────────────────────────────────────────

type SecurityType = 'Open' | 'WEP' | 'WPA' | 'WPA2' | 'WPA3'
type Frequency = '2.4GHz' | '5GHz' | '6GHz'
type DeviceType = 'camera' | 'sensor' | 'printer' | 'controller' | 'gateway' | 'unknown'
type AlertSeverity = 'critical' | 'high' | 'medium' | 'low'
type AlertStatus = 'open' | 'resolved'

interface WirelessNetwork {
  id: string
  ssid: string
  bssid: string
  channel: number
  frequency: Frequency
  security_type: SecurityType
  signal_strength: number // dBm (negative)
  vendor: string
  is_authorized: boolean
  is_rogue: boolean
  first_seen: string
  last_seen: string
}

interface IoTDevice {
  id: string
  ip_address: string
  mac_address: string
  device_name: string
  device_type: DeviceType
  manufacturer: string
  firmware_version: string
  open_ports: number[]
  risk_score: number
  is_managed: boolean
  last_seen: string
  vulnerabilities: { cve: string; severity: string; description: string }[]
}

interface SecurityAlert {
  id: string
  type: string
  target_name: string
  severity: AlertSeverity
  detected_at: string
  status: AlertStatus
  description: string
}

interface WirelessStats {
  authorized_networks: number
  rogue_aps: number
  iot_devices: number
  high_risk_iot: number
}

// ── Helpers ───────────────────────────────────────────────────────────────────

const SECURITY_TYPE_CONFIG: Record<SecurityType, { color: string; label: string }> = {
  'Open': { color: 'bg-red-500/20 text-red-300 border border-red-500/30', label: 'Open' },
  'WEP':  { color: 'bg-red-500/20 text-red-300 border border-red-500/30', label: 'WEP' },
  'WPA':  { color: 'bg-yellow-500/20 text-yellow-300 border border-yellow-500/30', label: 'WPA' },
  'WPA2': { color: 'bg-green-500/20 text-green-300 border border-green-500/30', label: 'WPA2' },
  'WPA3': { color: 'bg-green-500/20 text-green-300 border border-green-500/30', label: 'WPA3' },
}

const FREQ_CONFIG: Record<Frequency, { color: string }> = {
  '2.4GHz': { color: 'bg-blue-500/20 text-blue-300 border border-blue-500/30' },
  '5GHz':   { color: 'bg-purple-500/20 text-purple-300 border border-purple-500/30' },
  '6GHz':   { color: 'bg-cyan-500/20 text-cyan-300 border border-cyan-500/30' },
}

const DEVICE_TYPE_CONFIG: Record<DeviceType, { label: string; color: string; icon: React.ReactNode }> = {
  camera:     { label: 'カメラ',    color: 'bg-blue-500/20 text-blue-300 border border-blue-500/30',     icon: <Camera className="w-3.5 h-3.5" /> },
  sensor:     { label: 'センサー',  color: 'bg-green-500/20 text-green-300 border border-green-500/30',   icon: <Activity className="w-3.5 h-3.5" /> },
  printer:    { label: 'プリンター', color: 'bg-purple-500/20 text-purple-300 border border-purple-500/30', icon: <Printer className="w-3.5 h-3.5" /> },
  controller: { label: 'コントローラー', color: 'bg-orange-500/20 text-orange-300 border border-orange-500/30', icon: <Cpu className="w-3.5 h-3.5" /> },
  gateway:    { label: 'ゲートウェイ', color: 'bg-cyan-500/20 text-cyan-300 border border-cyan-500/30',   icon: <Radio className="w-3.5 h-3.5" /> },
  unknown:    { label: '不明',       color: 'bg-red-500/20 text-red-300 border border-red-500/30',         icon: <AlertOctagon className="w-3.5 h-3.5" /> },
}

const SEVERITY_CONFIG: Record<AlertSeverity, { label: string; color: string; dot: string }> = {
  critical: { label: 'クリティカル', color: 'bg-red-500/20 text-red-300 border border-red-500/30', dot: 'bg-red-400' },
  high:     { label: '高',           color: 'bg-orange-500/20 text-orange-300 border border-orange-500/30', dot: 'bg-orange-400' },
  medium:   { label: '中',           color: 'bg-yellow-500/20 text-yellow-300 border border-yellow-500/30', dot: 'bg-yellow-400' },
  low:      { label: '低',           color: 'bg-green-500/20 text-green-300 border border-green-500/30', dot: 'bg-green-400' },
}

function getSignalColor(dbm: number): string {
  if (dbm < -80) return 'bg-red-500'
  if (dbm < -60) return 'bg-yellow-500'
  return 'bg-green-500'
}

function signalPercent(dbm: number): number {
  // Map -100 dBm = 0% to -30 dBm = 100%
  return Math.max(0, Math.min(100, ((dbm + 100) / 70) * 100))
}

function hasDangerousPort(ports: number[]): boolean {
  return ports.some(p => p === 23 || p === 80)
}

function getRiskScoreColor(score: number): string {
  if (score >= 81) return 'bg-red-500'
  if (score >= 61) return 'bg-orange-500'
  if (score >= 31) return 'bg-yellow-500'
  return 'bg-green-500'
}

function getRiskScoreTextColor(score: number): string {
  if (score >= 81) return 'text-red-400'
  if (score >= 61) return 'text-orange-400'
  if (score >= 31) return 'text-yellow-400'
  return 'text-green-400'
}

function formatDate(d: string): string {
  try { return new Date(d).toLocaleString('ja-JP', { month: 'numeric', day: 'numeric', hour: '2-digit', minute: '2-digit' }) }
  catch { return d }
}

// ── Device Detail Panel ───────────────────────────────────────────────────────

function DeviceDetailPanel({ device, onClose }: { device: IoTDevice; onClose: () => void }) {
  const typeConf = DEVICE_TYPE_CONFIG[device.device_type]
  return (
    <div className="fixed inset-y-0 right-0 z-50 w-96 bg-[#0d1220] border-l border-[#1e2d42] shadow-2xl overflow-y-auto">
      <div className="px-5 py-4 border-b border-[#1e2d42] flex items-center justify-between">
        <div>
          <h2 className="text-white font-semibold">{device.device_name}</h2>
          <p className="text-[#7d92b0] text-xs mt-0.5">{device.manufacturer}</p>
        </div>
        <button onClick={onClose} className="text-[#7d92b0] hover:text-white p-1"><X className="w-5 h-5" /></button>
      </div>
      <div className="p-5 space-y-5">
        {/* Basic info */}
        <div className="space-y-2 text-sm">
          {[
            ['IPアドレス', <span key="ip" className="font-mono text-white">{device.ip_address}</span>],
            ['MACアドレス', <span key="mac" className="font-mono text-white">{device.mac_address}</span>],
            ['デバイスタイプ', <span key="type" className={`text-xs px-2 py-0.5 rounded-full flex items-center gap-1 w-fit ${typeConf.color}`}>{typeConf.icon}{typeConf.label}</span>],
            ['メーカー', <span key="mfr" className="text-white">{device.manufacturer}</span>],
            ['ファームウェア', <span key="fw" className="font-mono text-white">{device.firmware_version}</span>],
            ['リスクスコア', <span key="rs" className={`font-bold ${getRiskScoreTextColor(device.risk_score)}`}>{device.risk_score}</span>],
            ['管理状態', device.is_managed
              ? <span key="m" className="flex items-center gap-1 text-green-400"><CheckCircle className="w-3.5 h-3.5" />管理済み</span>
              : <span key="um" className="flex items-center gap-1 text-red-400"><XCircle className="w-3.5 h-3.5" />未管理</span>],
            ['最終確認', <span key="ls" className="text-[#7d92b0]">{formatDate(device.last_seen)}</span>],
          ].map(([label, val], i) => (
            <div key={i} className="flex justify-between items-center py-1.5 border-b border-[#1e2d42]/50">
              <span className="text-[#7d92b0]">{label}</span>
              {val}
            </div>
          ))}
        </div>

        {/* Open Ports */}
        <div>
          <h3 className="text-white font-medium mb-2 text-sm">オープンポート</h3>
          <div className="flex flex-wrap gap-2">
            {device.open_ports.map(port => (
              <span key={port} className={`text-xs px-2.5 py-1 rounded font-mono font-medium ${
                port === 23 ? 'bg-red-500/20 text-red-300 border border-red-500/30' :
                port === 80 ? 'bg-orange-500/20 text-orange-300 border border-orange-500/30' :
                'bg-[#1e2d42] text-[#7d92b0]'
              }`}>
                {port}
                {port === 23 && ' (Telnet)'}
                {port === 80 && ' (HTTP)'}
                {port === 22 && ' (SSH)'}
                {port === 443 && ' (HTTPS)'}
                {port === 554 && ' (RTSP)'}
                {port === 9100 && ' (Print)'}
                {port === 502 && ' (Modbus)'}
                {port === 8883 && ' (MQTT)'}
              </span>
            ))}
          </div>
        </div>

        {/* Vulnerabilities */}
        <div>
          <h3 className="text-white font-medium mb-2 text-sm">
            脆弱性 ({device.vulnerabilities.length})
          </h3>
          {device.vulnerabilities.length === 0 ? (
            <div className="flex items-center gap-2 text-green-400 text-sm">
              <CheckCircle className="w-4 h-4" /> 脆弱性なし
            </div>
          ) : (
            <div className="space-y-2">
              {device.vulnerabilities.map((vuln, i) => (
                <div key={i} className={`p-3 rounded-lg border ${
                  vuln.severity === 'critical' ? 'border-red-500/30 bg-red-500/5' :
                  vuln.severity === 'high' ? 'border-orange-500/30 bg-orange-500/5' :
                  'border-yellow-500/30 bg-yellow-500/5'
                }`}>
                  <div className="flex items-center justify-between mb-1">
                    <span className="font-mono text-xs text-blue-400">{vuln.cve}</span>
                    <span className={`text-xs px-2 py-0.5 rounded-full ${
                      vuln.severity === 'critical' ? 'bg-red-500/20 text-red-300' :
                      vuln.severity === 'high' ? 'bg-orange-500/20 text-orange-300' :
                      'bg-yellow-500/20 text-yellow-300'
                    }`}>{vuln.severity}</span>
                  </div>
                  <p className="text-[#7d92b0] text-xs">{vuln.description}</p>
                </div>
              ))}
            </div>
          )}
        </div>
      </div>
    </div>
  )
}

// ── Main Page ─────────────────────────────────────────────────────────────────

export default function WirelessSecurityPage() {
  const queryClient = useQueryClient()
  const [activeTab, setActiveTab] = useState<'wireless' | 'iot' | 'alerts'>('wireless')

  // Wireless filters
  const [authorizedFilter, setAuthorizedFilter] = useState<string>('all')
  const [rogueFilter, setRogueFilter] = useState<string>('all')
  const [freqFilter, setFreqFilter] = useState<string>('all')

  // IoT filters
  const [deviceTypeFilter, setDeviceTypeFilter] = useState<string>('all')
  const [managedFilter, setManagedFilter] = useState<string>('all')
  const [minRiskFilter, setMinRiskFilter] = useState<number>(0)

  // Detail panel
  const [selectedDevice, setSelectedDevice] = useState<IoTDevice | null>(null)

  // Authorize confirm
  const [confirmingNetworkId, setConfirmingNetworkId] = useState<string | null>(null)

  // Queries
  const { data: statsData } = useQuery<WirelessStats>({
    queryKey: ['wireless-stats'],
    queryFn: () => apiFetch('/api/v1/wireless/stats'),
    retry: false, staleTime: 30_000,
  })
  const EMPTY_STATS: WirelessStats = { authorized_networks: 0, rogue_aps: 0, iot_devices: 0, high_risk_iot: 0 }
  const stats = statsData ?? EMPTY_STATS

  const { data: networksData } = useQuery<{ items: WirelessNetwork[] }>({
    queryKey: ['wireless-networks'],
    queryFn: () => apiFetch('/api/v1/wireless/networks'),
    retry: false, staleTime: 30_000,
  })
  const networks = networksData?.items ?? []

  const { data: iotData } = useQuery<{ items: IoTDevice[] }>({
    queryKey: ['wireless-iot'],
    queryFn: () => apiFetch('/api/v1/wireless/iot'),
    retry: false, staleTime: 30_000,
  })
  const iotDevices = iotData?.items ?? []

  const { data: alertsData } = useQuery<{ items: SecurityAlert[] }>({
    queryKey: ['wireless-alerts'],
    queryFn: () => apiFetch('/api/v1/wireless/alerts'),
    retry: false, staleTime: 30_000,
  })
  const alerts = alertsData?.items ?? []

  // Authorize mutation
  const authorizeMutation = useMutation({
    mutationFn: (networkId: string) =>
      apiFetch(`/api/v1/wireless/networks/${networkId}/authorize`, { method: 'POST' }),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['wireless-networks'] })
      setConfirmingNetworkId(null)
    },
    onError: () => setConfirmingNetworkId(null),
  })

  // Resolve alert mutation
  const resolveAlertMutation = useMutation({
    mutationFn: (alertId: string) =>
      apiFetch(`/api/v1/wireless/alerts/${alertId}/resolve`, { method: 'POST' }),
    onSuccess: () => queryClient.invalidateQueries({ queryKey: ['wireless-alerts'] }),
    onError: () => {},
  })

  const filteredNetworks = useMemo(() => networks.filter(n => {
    if (authorizedFilter === 'authorized' && !n.is_authorized) return false
    if (authorizedFilter === 'unauthorized' && n.is_authorized) return false
    if (rogueFilter === 'rogue' && !n.is_rogue) return false
    if (rogueFilter === 'non_rogue' && n.is_rogue) return false
    if (freqFilter !== 'all' && n.frequency !== freqFilter) return false
    return true
  }), [networks, authorizedFilter, rogueFilter, freqFilter])

  const filteredIoT = useMemo(() => iotDevices.filter(d => {
    if (deviceTypeFilter !== 'all' && d.device_type !== deviceTypeFilter) return false
    if (managedFilter === 'managed' && !d.is_managed) return false
    if (managedFilter === 'unmanaged' && d.is_managed) return false
    if (d.risk_score < minRiskFilter) return false
    return true
  }), [iotDevices, deviceTypeFilter, managedFilter, minRiskFilter])

  return (
    <div className="min-h-screen bg-[#070d19] p-6">
      {/* Header */}
      <div className="mb-6">
        <h1 className="text-2xl font-bold text-white">ワイヤレス/IoTセキュリティ</h1>
        <p className="text-[#7d92b0] mt-1 text-sm">不正アクセスポイント・IoTデバイスの検知と管理</p>
      </div>

      {/* Stats Row */}
      <div className="grid grid-cols-4 gap-4 mb-6">
        {[
          { label: '承認済みネットワーク', value: stats.authorized_networks, icon: <Wifi className="w-5 h-5" />, color: 'text-green-400', bg: 'bg-green-500/10' },
          { label: '不正AP検知', value: stats.rogue_aps, icon: <WifiOff className="w-5 h-5" />, color: 'text-red-400', bg: 'bg-red-500/10' },
          { label: 'IoTデバイス', value: stats.iot_devices, icon: <Cpu className="w-5 h-5" />, color: 'text-blue-400', bg: 'bg-blue-500/10' },
          { label: '高リスクIoT', value: stats.high_risk_iot, icon: <AlertTriangle className="w-5 h-5" />, color: 'text-red-400', bg: 'bg-red-500/10' },
        ].map(({ label, value, icon, color, bg }) => (
          <div key={label} className="bg-[#0d1220] border border-[#1e2d42] rounded-lg p-4">
            <div className="flex items-center gap-3">
              <div className={`p-2 rounded-lg ${bg} ${color}`}>{icon}</div>
              <div>
                <p className="text-[#7d92b0] text-xs">{label}</p>
                <p className={`text-2xl font-bold ${color}`}>{value}</p>
              </div>
            </div>
          </div>
        ))}
      </div>

      {/* Tabs */}
      <div className="flex gap-1 mb-6 bg-[#0d1220] border border-[#1e2d42] rounded-lg p-1 w-fit">
        {[
          { id: 'wireless', label: 'ワイヤレスネットワーク' },
          { id: 'iot', label: 'IoTデバイス' },
          { id: 'alerts', label: 'セキュリティアラート' },
        ].map(tab => (
          <button
            key={tab.id}
            onClick={() => setActiveTab(tab.id as typeof activeTab)}
            className={`px-4 py-2 rounded text-sm font-medium transition-colors ${
              activeTab === tab.id ? 'bg-[#1d2f4a] text-white' : 'text-[#7d92b0] hover:text-white'
            }`}
          >
            {tab.label}
          </button>
        ))}
      </div>

      {/* ── Wireless Networks Tab ── */}
      {activeTab === 'wireless' && (
        <div className="space-y-4">
          {/* Filters */}
          <div className="flex items-center gap-3 flex-wrap">
            <div className="flex items-center gap-2 text-[#7d92b0] text-sm">
              <Filter className="w-4 h-4" />
              <span>フィルター:</span>
            </div>
            <select value={authorizedFilter} onChange={e => setAuthorizedFilter(e.target.value)}
              className="px-3 py-1.5 bg-[#0d1220] border border-[#1e2d42] rounded text-sm text-white focus:outline-none focus:border-[#7d92b0]/50">
              <option value="all">承認状態: すべて</option>
              <option value="authorized">承認済み</option>
              <option value="unauthorized">未承認</option>
            </select>
            <select value={rogueFilter} onChange={e => setRogueFilter(e.target.value)}
              className="px-3 py-1.5 bg-[#0d1220] border border-[#1e2d42] rounded text-sm text-white focus:outline-none focus:border-[#7d92b0]/50">
              <option value="all">不正AP: すべて</option>
              <option value="rogue">不正のみ</option>
              <option value="non_rogue">正規のみ</option>
            </select>
            <select value={freqFilter} onChange={e => setFreqFilter(e.target.value)}
              className="px-3 py-1.5 bg-[#0d1220] border border-[#1e2d42] rounded text-sm text-white focus:outline-none focus:border-[#7d92b0]/50">
              <option value="all">周波数: すべて</option>
              <option value="2.4GHz">2.4GHz</option>
              <option value="5GHz">5GHz</option>
              <option value="6GHz">6GHz</option>
            </select>
            {(authorizedFilter !== 'all' || rogueFilter !== 'all' || freqFilter !== 'all') && (
              <button onClick={() => { setAuthorizedFilter('all'); setRogueFilter('all'); setFreqFilter('all') }}
                className="flex items-center gap-1 px-2 py-1.5 text-xs text-[#7d92b0] hover:text-white">
                <X className="w-3.5 h-3.5" /> クリア
              </button>
            )}
            <span className="text-[#7d92b0] text-sm">{filteredNetworks.length} 件</span>
          </div>

          {/* Networks Table */}
          <div className="bg-[#0d1220] border border-[#1e2d42] rounded-lg overflow-hidden">
            <div className="overflow-x-auto">
              <table className="w-full text-sm">
                <thead>
                  <tr className="text-[#7d92b0] text-xs border-b border-[#1e2d42] bg-[#0a101d]">
                    <th className="text-left px-4 py-3">SSID</th>
                    <th className="text-left px-4 py-3">BSSID</th>
                    <th className="text-left px-4 py-3">CH</th>
                    <th className="text-left px-4 py-3">周波数</th>
                    <th className="text-left px-4 py-3">セキュリティ</th>
                    <th className="text-left px-4 py-3 w-36">シグナル強度</th>
                    <th className="text-left px-4 py-3">メーカー</th>
                    <th className="text-left px-4 py-3">承認</th>
                    <th className="text-left px-4 py-3">不正AP</th>
                    <th className="text-left px-4 py-3">初回検知</th>
                    <th className="text-left px-4 py-3">最終確認</th>
                    <th className="text-left px-4 py-3">アクション</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-[#1e2d42]">
                  {filteredNetworks.map(net => {
                    const secConf = SECURITY_TYPE_CONFIG[net.security_type]
                    const freqConf = FREQ_CONFIG[net.frequency]
                    const sigPct = signalPercent(net.signal_strength)
                    const sigColor = getSignalColor(net.signal_strength)
                    return (
                      <tr key={net.id} className={`hover:bg-[#0d1830]/40 transition-colors ${net.is_rogue ? 'bg-red-500/5' : ''}`}>
                        <td className="px-4 py-3">
                          <span className="text-white font-medium">{net.ssid}</span>
                        </td>
                        <td className="px-4 py-3">
                          <span className="font-mono text-xs text-[#7d92b0]">{net.bssid}</span>
                        </td>
                        <td className="px-4 py-3 text-[#7d92b0] text-xs">{net.channel}</td>
                        <td className="px-4 py-3">
                          <span className={`text-xs px-2 py-0.5 rounded-full font-medium ${freqConf.color}`}>{net.frequency}</span>
                        </td>
                        <td className="px-4 py-3">
                          <span className={`text-xs px-2 py-0.5 rounded-full font-medium ${secConf.color}`}>{secConf.label}</span>
                        </td>
                        <td className="px-4 py-3">
                          <div className="flex items-center gap-2">
                            <div className="flex-1 h-1.5 bg-[#1e2d42] rounded-full overflow-hidden">
                              <div className={`h-full rounded-full ${sigColor}`} style={{ width: `${sigPct}%` }} />
                            </div>
                            <span className="text-xs font-mono text-[#7d92b0] w-12 text-right">{net.signal_strength} dBm</span>
                          </div>
                        </td>
                        <td className="px-4 py-3 text-[#7d92b0] text-xs">{net.vendor}</td>
                        <td className="px-4 py-3">
                          {net.is_authorized
                            ? <span className="flex items-center gap-1 text-green-400 text-xs"><CheckCircle className="w-3.5 h-3.5" />承認済み</span>
                            : <span className="flex items-center gap-1 text-[#7d92b0] text-xs"><XCircle className="w-3.5 h-3.5" />未承認</span>}
                        </td>
                        <td className="px-4 py-3">
                          {net.is_rogue ? (
                            <span className="flex items-center gap-1 text-xs bg-red-500/20 text-red-300 border border-red-500/30 px-2 py-0.5 rounded-full">
                              <AlertTriangle className="w-3 h-3" /> 不正AP
                            </span>
                          ) : <span className="text-[#3d5068] text-xs">—</span>}
                        </td>
                        <td className="px-4 py-3 text-[#7d92b0] text-xs whitespace-nowrap">{formatDate(net.first_seen)}</td>
                        <td className="px-4 py-3 text-[#7d92b0] text-xs whitespace-nowrap">{formatDate(net.last_seen)}</td>
                        <td className="px-4 py-3">
                          {!net.is_authorized && (
                            <button
                              onClick={() => setConfirmingNetworkId(net.id)}
                              className="flex items-center gap-1.5 px-3 py-1.5 bg-green-600/20 hover:bg-green-600/30 text-green-300 text-xs rounded border border-green-600/30 transition-colors"
                            >
                              <CheckCircle className="w-3.5 h-3.5" />
                              承認
                            </button>
                          )}
                        </td>
                      </tr>
                    )
                  })}
                </tbody>
              </table>
            </div>
          </div>
        </div>
      )}

      {/* ── IoT Devices Tab ── */}
      {activeTab === 'iot' && (
        <div className="space-y-4">
          {/* Filters */}
          <div className="flex items-center gap-3 flex-wrap">
            <div className="flex items-center gap-2 text-[#7d92b0] text-sm">
              <Filter className="w-4 h-4" />
              <span>フィルター:</span>
            </div>
            <select value={deviceTypeFilter} onChange={e => setDeviceTypeFilter(e.target.value)}
              className="px-3 py-1.5 bg-[#0d1220] border border-[#1e2d42] rounded text-sm text-white focus:outline-none focus:border-[#7d92b0]/50">
              <option value="all">デバイスタイプ: すべて</option>
              <option value="camera">カメラ</option>
              <option value="sensor">センサー</option>
              <option value="printer">プリンター</option>
              <option value="controller">コントローラー</option>
              <option value="gateway">ゲートウェイ</option>
              <option value="unknown">不明</option>
            </select>
            <select value={managedFilter} onChange={e => setManagedFilter(e.target.value)}
              className="px-3 py-1.5 bg-[#0d1220] border border-[#1e2d42] rounded text-sm text-white focus:outline-none focus:border-[#7d92b0]/50">
              <option value="all">管理状態: すべて</option>
              <option value="managed">管理済み</option>
              <option value="unmanaged">未管理</option>
            </select>
            <div className="flex items-center gap-2">
              <span className="text-[#7d92b0] text-sm">リスクスコア最小値:</span>
              <input type="number" value={minRiskFilter} min={0} max={100}
                onChange={e => setMinRiskFilter(Number(e.target.value))}
                className="w-16 px-2 py-1.5 bg-[#0d1220] border border-[#1e2d42] rounded text-sm text-white focus:outline-none focus:border-[#7d92b0]/50" />
            </div>
            {(deviceTypeFilter !== 'all' || managedFilter !== 'all' || minRiskFilter > 0) && (
              <button onClick={() => { setDeviceTypeFilter('all'); setManagedFilter('all'); setMinRiskFilter(0) }}
                className="flex items-center gap-1 px-2 py-1.5 text-xs text-[#7d92b0] hover:text-white">
                <X className="w-3.5 h-3.5" /> クリア
              </button>
            )}
            <span className="text-[#7d92b0] text-sm">{filteredIoT.length} 件</span>
          </div>

          {/* IoT Table */}
          <div className="bg-[#0d1220] border border-[#1e2d42] rounded-lg overflow-hidden">
            <div className="overflow-x-auto">
              <table className="w-full text-sm">
                <thead>
                  <tr className="text-[#7d92b0] text-xs border-b border-[#1e2d42] bg-[#0a101d]">
                    <th className="text-left px-4 py-3">IPアドレス</th>
                    <th className="text-left px-4 py-3">MACアドレス</th>
                    <th className="text-left px-4 py-3">デバイス名</th>
                    <th className="text-left px-4 py-3">タイプ</th>
                    <th className="text-left px-4 py-3">メーカー</th>
                    <th className="text-left px-4 py-3">ファームウェア</th>
                    <th className="text-left px-4 py-3">ポート数</th>
                    <th className="text-left px-4 py-3 w-36">リスクスコア</th>
                    <th className="text-left px-4 py-3">管理</th>
                    <th className="text-left px-4 py-3">最終確認</th>
                    <th className="text-left px-4 py-3">詳細</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-[#1e2d42]">
                  {filteredIoT.map(device => {
                    const typeConf = DEVICE_TYPE_CONFIG[device.device_type]
                    const dangerousPorts = hasDangerousPort(device.open_ports)
                    return (
                      <tr key={device.id} className={`hover:bg-[#0d1830]/40 transition-colors ${device.risk_score > 70 ? 'bg-red-500/3' : ''}`}>
                        <td className="px-4 py-3">
                          <span className="font-mono text-xs text-white">{device.ip_address}</span>
                        </td>
                        <td className="px-4 py-3">
                          <span className="font-mono text-xs text-[#7d92b0]">{device.mac_address}</span>
                        </td>
                        <td className="px-4 py-3">
                          <span className="text-white font-medium">{device.device_name}</span>
                        </td>
                        <td className="px-4 py-3">
                          <span className={`text-xs px-2 py-0.5 rounded-full font-medium flex items-center gap-1 w-fit ${typeConf.color}`}>
                            {typeConf.icon} {typeConf.label}
                          </span>
                        </td>
                        <td className="px-4 py-3 text-[#7d92b0] text-xs">{device.manufacturer}</td>
                        <td className="px-4 py-3">
                          <span className="font-mono text-xs text-[#7d92b0]">{device.firmware_version}</span>
                        </td>
                        <td className="px-4 py-3">
                          <span className={`text-xs font-bold ${dangerousPorts ? 'text-red-400' : 'text-[#7d92b0]'}`}>
                            {device.open_ports.length}
                            {dangerousPorts && ' ⚠'}
                          </span>
                        </td>
                        <td className="px-4 py-3">
                          <div className="flex items-center gap-2">
                            <div className="flex-1 h-1.5 bg-[#1e2d42] rounded-full overflow-hidden">
                              <div className={`h-full rounded-full ${getRiskScoreColor(device.risk_score)}`}
                                style={{ width: `${device.risk_score}%` }} />
                            </div>
                            <span className={`text-xs font-bold tabular-nums w-8 text-right ${getRiskScoreTextColor(device.risk_score)}`}>
                              {device.risk_score}
                            </span>
                          </div>
                        </td>
                        <td className="px-4 py-3">
                          {device.is_managed
                            ? <span className="flex items-center gap-1 text-green-400 text-xs"><CheckCircle className="w-3.5 h-3.5" />管理済み</span>
                            : <span className="flex items-center gap-1 text-red-400 text-xs"><XCircle className="w-3.5 h-3.5" />未管理</span>}
                        </td>
                        <td className="px-4 py-3 text-[#7d92b0] text-xs whitespace-nowrap">{formatDate(device.last_seen)}</td>
                        <td className="px-4 py-3">
                          <button
                            onClick={() => setSelectedDevice(device)}
                            className="flex items-center gap-1.5 px-3 py-1.5 bg-[#1d2f4a] hover:bg-[#243a5e] text-white text-xs rounded transition-colors"
                          >
                            <Eye className="w-3.5 h-3.5" />
                            詳細
                          </button>
                        </td>
                      </tr>
                    )
                  })}
                </tbody>
              </table>
            </div>
          </div>
        </div>
      )}

      {/* ── Security Alerts Tab ── */}
      {activeTab === 'alerts' && (
        <div className="bg-[#0d1220] border border-[#1e2d42] rounded-lg overflow-hidden">
          <div className="px-5 py-4 border-b border-[#1e2d42] flex items-center gap-2">
            <Bell className="w-4 h-4 text-[#e8002d]" />
            <h3 className="text-white font-semibold">セキュリティアラート</h3>
            <span className="text-xs bg-[#e8002d]/20 text-red-300 border border-[#e8002d]/30 px-2 py-0.5 rounded-full ml-2">
              {alerts.filter(a => a.status === 'open').length} 未対処
            </span>
          </div>
          <div className="overflow-x-auto">
            <table className="w-full text-sm">
              <thead>
                <tr className="text-[#7d92b0] text-xs border-b border-[#1e2d42] bg-[#0a101d]">
                  <th className="text-left px-4 py-3">タイプ</th>
                  <th className="text-left px-4 py-3">対象</th>
                  <th className="text-left px-4 py-3">深刻度</th>
                  <th className="text-left px-4 py-3">説明</th>
                  <th className="text-left px-4 py-3">検知日時</th>
                  <th className="text-left px-4 py-3">ステータス</th>
                  <th className="text-left px-4 py-3">アクション</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-[#1e2d42]">
                {alerts.map(alert => {
                  const sevConf = SEVERITY_CONFIG[alert.severity]
                  return (
                    <tr key={alert.id} className={`hover:bg-[#0d1830]/40 transition-colors ${
                      alert.status === 'resolved' ? 'opacity-60' : ''
                    }`}>
                      <td className="px-4 py-3">
                        <span className="text-white font-medium text-xs">{alert.type}</span>
                      </td>
                      <td className="px-4 py-3 text-[#7d92b0] text-xs max-w-[200px]">
                        <span className="truncate block">{alert.target_name}</span>
                      </td>
                      <td className="px-4 py-3">
                        <span className={`text-xs px-2 py-0.5 rounded-full font-medium flex items-center gap-1 w-fit ${sevConf.color}`}>
                          <span className={`w-1.5 h-1.5 rounded-full ${sevConf.dot}`} />
                          {sevConf.label}
                        </span>
                      </td>
                      <td className="px-4 py-3 text-[#7d92b0] text-xs max-w-[280px]">
                        <span className="line-clamp-2">{alert.description}</span>
                      </td>
                      <td className="px-4 py-3 text-[#7d92b0] text-xs whitespace-nowrap">
                        <div className="flex items-center gap-1">
                          <Clock className="w-3 h-3" />
                          {formatDate(alert.detected_at)}
                        </div>
                      </td>
                      <td className="px-4 py-3">
                        {alert.status === 'resolved'
                          ? <span className="flex items-center gap-1 text-green-400 text-xs"><CheckCircle className="w-3.5 h-3.5" />対処済み</span>
                          : <span className="flex items-center gap-1 text-orange-400 text-xs"><AlertOctagon className="w-3.5 h-3.5" />未対処</span>}
                      </td>
                      <td className="px-4 py-3">
                        {alert.status === 'open' && (
                          <button
                            onClick={() => resolveAlertMutation.mutate(alert.id)}
                            className="flex items-center gap-1.5 px-3 py-1.5 bg-green-600/20 hover:bg-green-600/30 text-green-300 text-xs rounded border border-green-600/30 transition-colors"
                          >
                            <CheckCircle className="w-3.5 h-3.5" />
                            対処済み
                          </button>
                        )}
                      </td>
                    </tr>
                  )
                })}
              </tbody>
            </table>
          </div>
        </div>
      )}

      {/* ── Authorize Confirmation Dialog ── */}
      {confirmingNetworkId && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 backdrop-blur-sm" onClick={() => setConfirmingNetworkId(null)}>
          <div className="bg-[#0d1220] border border-[#1e2d42] rounded-xl p-6 w-full max-w-sm shadow-2xl" onClick={e => e.stopPropagation()}>
            <div className="flex items-center gap-3 mb-4">
              <div className="p-2 bg-green-500/10 rounded-lg text-green-400"><CheckCircle className="w-6 h-6" /></div>
              <h2 className="text-white font-semibold">ネットワークを承認</h2>
            </div>
            <p className="text-[#7d92b0] text-sm mb-6">
              このネットワークを承認済みとして登録します。この操作は取り消せません。続行しますか？
            </p>
            <div className="flex gap-3">
              <button onClick={() => setConfirmingNetworkId(null)}
                className="flex-1 px-4 py-2 border border-[#1e2d42] text-[#7d92b0] hover:text-white rounded text-sm transition-colors">
                キャンセル
              </button>
              <button
                onClick={() => authorizeMutation.mutate(confirmingNetworkId)}
                className="flex-1 px-4 py-2 bg-green-600 hover:bg-green-700 text-white rounded text-sm font-medium transition-colors"
              >
                承認する
              </button>
            </div>
          </div>
        </div>
      )}

      {/* ── Device Detail Side Panel ── */}
      {selectedDevice && (
        <DeviceDetailPanel device={selectedDevice} onClose={() => setSelectedDevice(null)} />
      )}
    </div>
  )
}

'use client'

import { useState, useRef } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import {
  Cpu, Upload, Play, RefreshCw, AlertTriangle, CheckCircle,
  Loader2, Search, Filter, Eye, Plus, Trash2, ChevronDown,
  ChevronRight, Download, FileText, Network, Hash,
  Shield, Terminal, Globe,
} from 'lucide-react'
import { PageDataUnavailable } from '@/components/PageDataUnavailable'

import { apiFetch } from '@/lib/api'
import { USE_MOCK, m } from '@/lib/mock'

// ─── Types ────────────────────────────────────────────────────────────────────

interface MemoryDump {
  id: string
  filename: string
  hostname: string
  size_mb: number
  acquisition_time: string
  analysis_status: 'pending' | 'analyzing' | 'complete' | 'error'
  os: string
  architecture: string
}

interface ProcessEntry {
  pid: number
  ppid: number
  process_name: string
  path: string
  user: string
  start_time: string
  memory_mb: number
  indicators: Array<'hollowing' | 'injection' | 'hidden' | 'unsigned_dll'>
  dlls?: string[]
  handles?: string[]
  connections?: string[]
  memory_regions?: MemRegion[]
}

interface MemRegion {
  base: string
  size: string
  permissions: string
  type: string
  suspicious: boolean
}

interface NetworkConnectionEntry {
  pid: number
  process: string
  local_addr: string
  local_port: number
  remote_addr: string
  remote_port: number
  state: string
  protocol: string
  suspicious: boolean
}

interface StringEntry {
  id: string
  value: string
  type: 'url' | 'ip' | 'registry' | 'command' | 'base64' | 'suspicious'
  pid: number
  process: string
  offset: string
}

interface YaraResult {
  rule_name: string
  process: string
  pid: number
  region: string
  score: number
  malware_family: string
}

interface AnalysisResults {
  processes: ProcessEntry[]
  network_connections: NetworkConnectionEntry[]
  strings: StringEntry[]
  yara_results: YaraResult[]
  rwx_regions: MemRegion[]
  suspicious_sections: Array<{ process: string; section: string; note: string }>
}

// ─── Mock Data ────────────────────────────────────────────────────────────────

const MOCK_DUMPS: MemoryDump[] = [
  {
    id: 'dump1',
    filename: 'WIN10-WORKSTATION-01_2026-03-18_0830.dmp',
    hostname: 'WIN10-WORKSTATION-01',
    size_mb: 8192,
    acquisition_time: '2026-03-18T08:30:00Z',
    analysis_status: 'complete',
    os: 'Windows 10 22H2',
    architecture: 'x86_64',
  },
  {
    id: 'dump2',
    filename: 'SRV-DC01_2026-03-17_2145.raw',
    hostname: 'SRV-DC01',
    size_mb: 16384,
    acquisition_time: '2026-03-17T21:45:00Z',
    analysis_status: 'analyzing',
    os: 'Windows Server 2022',
    architecture: 'x86_64',
  },
  {
    id: 'dump3',
    filename: 'UBUNTU-DEV-03_2026-03-16_1020.mem',
    hostname: 'UBUNTU-DEV-03',
    size_mb: 4096,
    acquisition_time: '2026-03-16T10:20:00Z',
    analysis_status: 'pending',
    os: 'Ubuntu 22.04 LTS',
    architecture: 'x86_64',
  },
]

const MOCK_ANALYSIS: AnalysisResults = {
  processes: [
    { pid: 4, ppid: 0, process_name: 'System', path: 'N/A', user: 'SYSTEM', start_time: '2026-03-18T00:00:01Z', memory_mb: 12, indicators: [] },
    { pid: 564, ppid: 4, process_name: 'smss.exe', path: 'C:\\Windows\\System32\\smss.exe', user: 'SYSTEM', start_time: '2026-03-18T00:00:02Z', memory_mb: 4, indicators: [] },
    { pid: 812, ppid: 564, process_name: 'csrss.exe', path: 'C:\\Windows\\System32\\csrss.exe', user: 'SYSTEM', start_time: '2026-03-18T00:00:04Z', memory_mb: 8, indicators: [] },
    { pid: 944, ppid: 812, process_name: 'winlogon.exe', path: 'C:\\Windows\\System32\\winlogon.exe', user: 'SYSTEM', start_time: '2026-03-18T00:00:05Z', memory_mb: 14, indicators: [] },
    { pid: 1032, ppid: 944, process_name: 'services.exe', path: 'C:\\Windows\\System32\\services.exe', user: 'SYSTEM', start_time: '2026-03-18T00:00:06Z', memory_mb: 22, indicators: [] },
    { pid: 2148, ppid: 1032, process_name: 'svchost.exe', path: 'C:\\Windows\\System32\\svchost.exe', user: 'NETWORK SERVICE', start_time: '2026-03-18T00:01:12Z', memory_mb: 45, indicators: [] },
    { pid: 3812, ppid: 2148, process_name: 'rundll32.exe', path: 'C:\\Windows\\System32\\rundll32.exe', user: 'SYSTEM', start_time: '2026-03-18T07:41:22Z', memory_mb: 128, indicators: ['injection', 'unsigned_dll'],
      dlls: ['C:\\Windows\\System32\\kernel32.dll', 'C:\\ProgramData\\tmp\\a.dll (UNSIGNED)', 'ntdll.dll'],
      connections: ['192.168.1.105:54321 -> 185.220.101.45:443 ESTABLISHED'],
      memory_regions: [
        { base: '0x00401000', size: '0x1000', permissions: 'RWX', type: 'Private', suspicious: true },
        { base: '0x7FFE0000', size: '0x1000', permissions: 'R--', type: 'Mapped', suspicious: false },
      ],
    },
    { pid: 4512, ppid: 1032, process_name: 'explorer.exe', path: 'C:\\Windows\\explorer.exe', user: 'DESKTOP-01\\user', start_time: '2026-03-18T08:01:55Z', memory_mb: 210, indicators: [] },
    { pid: 5204, ppid: 4512, process_name: 'chrome.exe', path: 'C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe', user: 'DESKTOP-01\\user', start_time: '2026-03-18T08:15:00Z', memory_mb: 512, indicators: [] },
    { pid: 6340, ppid: 3812, process_name: 'cmd.exe', path: 'C:\\Windows\\System32\\cmd.exe', user: 'SYSTEM', start_time: '2026-03-18T08:28:10Z', memory_mb: 8, indicators: ['hidden'],
      handles: ['HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run', 'C:\\Users\\user\\AppData\\Local\\Temp\\payload.exe'],
    },
    { pid: 7120, ppid: 6340, process_name: 'powershell.exe', path: 'C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe', user: 'SYSTEM', start_time: '2026-03-18T08:28:12Z', memory_mb: 94, indicators: ['hollowing', 'injection'],
      handles: ['\\Device\\KsecDD', '\\Device\\CNG'],
    },
  ],
  network_connections: [
    { pid: 3812, process: 'rundll32.exe', local_addr: '192.168.1.105', local_port: 54321, remote_addr: '185.220.101.45', remote_port: 443, state: 'ESTABLISHED', protocol: 'TCP', suspicious: true },
    { pid: 5204, process: 'chrome.exe', local_addr: '192.168.1.105', local_port: 49213, remote_addr: '142.250.80.46', remote_port: 443, state: 'ESTABLISHED', protocol: 'TCP', suspicious: false },
    { pid: 2148, process: 'svchost.exe', local_addr: '192.168.1.105', local_port: 137, remote_addr: '0.0.0.0', remote_port: 0, state: 'LISTEN', protocol: 'UDP', suspicious: false },
    { pid: 7120, process: 'powershell.exe', local_addr: '192.168.1.105', local_port: 61234, remote_addr: '10.20.30.40', remote_port: 8080, state: 'ESTABLISHED', protocol: 'TCP', suspicious: true },
    { pid: 1032, process: 'services.exe', local_addr: '0.0.0.0', local_port: 445, remote_addr: '0.0.0.0', remote_port: 0, state: 'LISTEN', protocol: 'TCP', suspicious: false },
    { pid: 5204, process: 'chrome.exe', local_addr: '192.168.1.105', local_port: 49300, remote_addr: '23.55.220.8', remote_port: 80, state: 'TIME_WAIT', protocol: 'TCP', suspicious: false },
  ],
  strings: [
    { id: 's1', value: 'http://185.220.101.45/c2/beacon', type: 'url', pid: 3812, process: 'rundll32.exe', offset: '0x004A1234' },
    { id: 's2', value: '185.220.101.45', type: 'ip', pid: 3812, process: 'rundll32.exe', offset: '0x004A1298' },
    { id: 's3', value: 'HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options', type: 'registry', pid: 7120, process: 'powershell.exe', offset: '0x007B2210' },
    { id: 's4', value: 'cmd.exe /c whoami && net user /domain', type: 'command', pid: 6340, process: 'cmd.exe', offset: '0x003C0100' },
    { id: 's5', value: 'cG93ZXJzaGVsbCAtZW5jb2RlZCBjb21tYW5kIFN0YXJ0LVByb2Nlc3M=', type: 'base64', pid: 7120, process: 'powershell.exe', offset: '0x007B3400' },
    { id: 's6', value: 'http://malware-c2.onion.to/payload.bin', type: 'url', pid: 7120, process: 'powershell.exe', offset: '0x007B3800' },
    { id: 's7', value: '10.20.30.40', type: 'ip', pid: 7120, process: 'powershell.exe', offset: '0x007B3A00' },
    { id: 's8', value: 'HKCU\\Software\\Classes\\ms-settings\\shell\\open\\command', type: 'registry', pid: 3812, process: 'rundll32.exe', offset: '0x004A1500' },
    { id: 's9', value: 'net user hacker P@ssw0rd /add && net localgroup administrators hacker /add', type: 'command', pid: 6340, process: 'cmd.exe', offset: '0x003C0400' },
    { id: 's10', value: 'SeDebugPrivilege', type: 'suspicious', pid: 3812, process: 'rundll32.exe', offset: '0x004A1600' },
    { id: 's11', value: 'VirtualAllocEx', type: 'suspicious', pid: 3812, process: 'rundll32.exe', offset: '0x004A1700' },
    { id: 's12', value: 'WriteProcessMemory', type: 'suspicious', pid: 3812, process: 'rundll32.exe', offset: '0x004A1800' },
  ],
  yara_results: [
    { rule_name: 'APT_Cobalt_Strike_Beacon', process: 'rundll32.exe', pid: 3812, region: '0x00401000', score: 98, malware_family: 'Cobalt Strike' },
    { rule_name: 'Generic_Shellcode_Injection', process: 'powershell.exe', pid: 7120, region: '0x007B0000', score: 87, malware_family: 'Shellcode Dropper' },
    { rule_name: 'MITRE_T1055_ProcessInjection', process: 'rundll32.exe', pid: 3812, region: '0x00410000', score: 92, malware_family: 'Process Injection' },
    { rule_name: 'Suspicious_PowerShell_Download', process: 'powershell.exe', pid: 7120, region: '0x007C0000', score: 76, malware_family: 'PowerShell Downloader' },
  ],
  rwx_regions: [
    { base: '0x00401000', size: '0x5000', permissions: 'RWX', type: 'Private', suspicious: true },
    { base: '0x007B0000', size: '0x3000', permissions: 'RWX', type: 'Private', suspicious: true },
    { base: '0x00C10000', size: '0x1000', permissions: 'RWX', type: 'Private', suspicious: true },
  ],
  suspicious_sections: [
    { process: 'rundll32.exe (3812)', section: '.text overlay', note: 'コードセクションに書き込み可能な領域、unpacked shellcode の可能性' },
    { process: 'powershell.exe (7120)', section: 'heap region', note: 'ヒープ上に実行可能コード、インジェクションの痕跡' },
  ],
}

// ─── Helper Components ────────────────────────────────────────────────────────

function StatusBadge({ status }: { status: MemoryDump['analysis_status'] }) {
  const cfg: Record<string, { cls: string; label: string }> = {
    pending: { cls: 'bg-[#7d92b0]/20 text-[#7d92b0]', label: '待機中' },
    analyzing: { cls: 'bg-[#1a6bff]/20 text-[#1a6bff]', label: '分析中' },
    complete: { cls: 'bg-[#00c853]/20 text-[#00c853]', label: '完了' },
    error: { cls: 'bg-[#e8002d]/20 text-[#e8002d]', label: 'エラー' },
  }
  const c = cfg[status]
  return (
    <span className={`text-[10px] font-bold px-2 py-0.5 rounded-sm flex items-center gap-1 w-fit ${c.cls}`}>
      {status === 'analyzing' && <Loader2 className="w-2.5 h-2.5 animate-spin" />}
      {c.label}
    </span>
  )
}

function IndicatorChip({ type }: { type: ProcessEntry['indicators'][number] }) {
  const cfg: Record<string, { cls: string; label: string }> = {
    hollowing: { cls: 'bg-[#e8002d]/20 text-[#e8002d] border-[#e8002d]/30', label: 'Hollowing' },
    injection: { cls: 'bg-orange-500/20 text-orange-400 border-orange-500/30', label: 'Injection' },
    hidden: { cls: 'bg-purple-500/20 text-purple-400 border-purple-500/30', label: 'Hidden' },
    unsigned_dll: { cls: 'bg-yellow-500/20 text-yellow-400 border-yellow-500/30', label: 'Unsigned DLL' },
  }
  const c = cfg[type]
  return (
    <span className={`text-[9px] font-bold px-1.5 py-0.5 rounded-sm border whitespace-nowrap ${c.cls}`}>{c.label}</span>
  )
}

function StringTypeBadge({ type }: { type: StringEntry['type'] }) {
  const cfg: Record<string, string> = {
    url: 'bg-[#1a6bff]/20 text-[#1a6bff]',
    ip: 'bg-orange-500/20 text-orange-400',
    registry: 'bg-purple-500/20 text-purple-400',
    command: 'bg-[#e8002d]/20 text-[#e8002d]',
    base64: 'bg-teal-500/20 text-teal-400',
    suspicious: 'bg-yellow-500/20 text-yellow-400',
  }
  const labels: Record<string, string> = { url: 'URL', ip: 'IP', registry: 'Registry', command: 'Command', base64: 'Base64', suspicious: 'Suspicious' }
  return (
    <span className={`text-[9px] font-bold px-2 py-0.5 rounded-sm uppercase ${cfg[type]}`}>{labels[type]}</span>
  )
}

// ─── Process Detail Panel ─────────────────────────────────────────────────────

function ProcessDetailPanel({ proc, onClose }: { proc: ProcessEntry; onClose: () => void }) {
  const [tab, setTab] = useState<'dll' | 'handles' | 'conn' | 'regions'>('dll')
  const isSuspicious = proc.indicators.length > 0

  return (
    <div className={`mt-2 mx-4 mb-2 rounded-lg border p-4 ${isSuspicious ? 'border-[#e8002d]/40 bg-[#e8002d]/5' : 'border-[#1e2d42] bg-[#070d19]'}`}>
      <div className="flex items-center justify-between mb-3">
        <div className="flex items-center gap-2">
          <span className="text-white font-mono font-bold">{proc.process_name}</span>
          <span className="text-[#3d5068] text-xs">(PID: {proc.pid})</span>
          {proc.indicators.map(ind => <IndicatorChip key={ind} type={ind} />)}
        </div>
        <button onClick={onClose} className="text-[#7d92b0] hover:text-white text-xs">閉じる</button>
      </div>
      <p className="text-[#3d5068] text-xs font-mono mb-3">{proc.path}</p>
      <div className="flex gap-2 mb-3">
        {(['dll', 'handles', 'conn', 'regions'] as const).map(t => {
          const labels = { dll: 'DLL一覧', handles: 'ハンドル', conn: 'ネットワーク', regions: 'メモリ領域' }
          return (
            <button
              key={t}
              onClick={() => setTab(t)}
              className={`text-xs px-3 py-1 rounded-sm transition-colors ${tab === t ? 'bg-[#e8002d] text-white' : 'bg-[#1e2d42] text-[#7d92b0] hover:text-white'}`}
            >
              {labels[t]}
            </button>
          )
        })}
      </div>
      <div className="text-xs font-mono space-y-1">
        {tab === 'dll' && (proc.dlls ?? ['(DLL情報なし)']).map((d, i) => (
          <div key={i} className={`py-1 border-b border-[#1e2d42] last:border-0 ${d.includes('UNSIGNED') ? 'text-[#e8002d]' : 'text-[#7d92b0]'}`}>{d}</div>
        ))}
        {tab === 'handles' && (proc.handles ?? ['(ハンドル情報なし)']).map((h, i) => (
          <div key={i} className="py-1 border-b border-[#1e2d42] last:border-0 text-[#7d92b0]">{h}</div>
        ))}
        {tab === 'conn' && (proc.connections ?? ['(接続情報なし)']).map((c, i) => (
          <div key={i} className="py-1 border-b border-[#1e2d42] last:border-0 text-[#ff9800]">{c}</div>
        ))}
        {tab === 'regions' && (proc.memory_regions ?? []).map((r, i) => (
          <div key={i} className={`py-1 border-b border-[#1e2d42] last:border-0 flex items-center gap-3 ${r.suspicious ? 'text-[#e8002d]' : 'text-[#7d92b0]'}`}>
            <span>{r.base}</span>
            <span className="text-[#3d5068]">size: {r.size}</span>
            <span className={`font-bold ${r.permissions === 'RWX' ? 'text-[#e8002d]' : ''}`}>{r.permissions}</span>
            <span>{r.type}</span>
            {r.suspicious && <AlertTriangle className="w-3 h-3" />}
          </div>
        ))}
        {tab === 'regions' && !proc.memory_regions?.length && (
          <div className="text-[#3d5068]">(メモリ領域情報なし)</div>
        )}
      </div>
    </div>
  )
}

// ─── Analysis Tabs ────────────────────────────────────────────────────────────

function ProcessTab({ processes }: { processes: ProcessEntry[] }) {
  const [expanded, setExpanded] = useState<number | null>(null)
  const [search, setSearch] = useState('')

  const filtered = processes.filter(p =>
    p.process_name.toLowerCase().includes(search.toLowerCase()) ||
    p.path.toLowerCase().includes(search.toLowerCase())
  )

  return (
    <div className="space-y-3">
      <div className="flex items-center gap-3">
        <div className="relative flex-1">
          <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-[#3d5068]" />
          <input
            className="w-full bg-[#0d1220] border border-[#1e2d42] rounded-lg pl-9 pr-3 py-2 text-white text-sm focus:outline-hidden focus:border-[#1a6bff]"
            placeholder="プロセス名、パスで検索..."
            value={search}
            onChange={e => setSearch(e.target.value)}
          />
        </div>
        <span className="text-xs text-[#3d5068]">{filtered.length} プロセス</span>
      </div>
      <div className="bg-[#0d1220] border border-[#1e2d42] rounded-xl overflow-hidden">
        <table className="w-full text-xs">
          <thead>
            <tr className="border-b border-[#1e2d42] text-[#3d5068]">
              <th className="text-left px-4 py-3">PID</th>
              <th className="text-left px-4 py-3">PPID</th>
              <th className="text-left px-4 py-3">プロセス名</th>
              <th className="text-left px-4 py-3">パス</th>
              <th className="text-left px-4 py-3">ユーザー</th>
              <th className="text-right px-4 py-3">メモリ</th>
              <th className="text-left px-4 py-3">インジケーター</th>
              <th className="px-4 py-3"></th>
            </tr>
          </thead>
          <tbody>
            {filtered.map(proc => (
              <>
                <tr
                  key={proc.pid}
                  className={`border-b border-[#1e2d42] last:border-0 transition-colors cursor-pointer
                    ${proc.indicators.length > 0 ? 'bg-[#e8002d]/5 hover:bg-[#e8002d]/10' : 'hover:bg-[#19253d]'}`}
                  onClick={() => setExpanded(expanded === proc.pid ? null : proc.pid)}
                >
                  <td className="px-4 py-2.5 font-mono text-white">{proc.pid}</td>
                  <td className="px-4 py-2.5 font-mono text-[#3d5068]">{proc.ppid}</td>
                  <td className="px-4 py-2.5">
                    <span className={`font-medium font-mono ${proc.indicators.length > 0 ? 'text-[#e8002d]' : 'text-white'}`}>
                      {proc.process_name}
                    </span>
                  </td>
                  <td className="px-4 py-2.5 font-mono text-[#7d92b0] max-w-[200px] truncate">{proc.path}</td>
                  <td className="px-4 py-2.5 text-[#7d92b0]">{proc.user}</td>
                  <td className="px-4 py-2.5 text-right text-[#7d92b0]">{proc.memory_mb} MB</td>
                  <td className="px-4 py-2.5">
                    <div className="flex flex-wrap gap-1">
                      {proc.indicators.map(ind => <IndicatorChip key={ind} type={ind} />)}
                    </div>
                  </td>
                  <td className="px-4 py-2.5">
                    <ChevronRight className={`w-3 h-3 text-[#3d5068] transition-transform ${expanded === proc.pid ? 'rotate-90' : ''}`} />
                  </td>
                </tr>
                {expanded === proc.pid && (
                  <tr key={`${proc.pid}-detail`} className="border-b border-[#1e2d42]">
                    <td colSpan={8} className="p-0">
                      <ProcessDetailPanel proc={proc} onClose={() => setExpanded(null)} />
                    </td>
                  </tr>
                )}
              </>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  )
}

function NetworkTab({ connections }: { connections: NetworkConnectionEntry[] }) {
  return (
    <div className="space-y-3">
      <div className="flex items-center gap-2 text-xs">
        <AlertTriangle className="w-4 h-4 text-[#e8002d]" />
        <span className="text-[#e8002d] font-medium">
          {connections.filter(c => c.suspicious).length} 件の疑わしい接続
        </span>
        <span className="text-[#3d5068]">— 既知のC2レンジへの接続をハイライト</span>
      </div>
      <div className="bg-[#0d1220] border border-[#1e2d42] rounded-xl overflow-hidden">
        <table className="w-full text-xs">
          <thead>
            <tr className="border-b border-[#1e2d42] text-[#3d5068]">
              <th className="text-left px-4 py-3">PID</th>
              <th className="text-left px-4 py-3">プロセス</th>
              <th className="text-left px-4 py-3">ローカルアドレス</th>
              <th className="text-left px-4 py-3">リモートアドレス</th>
              <th className="text-left px-4 py-3">状態</th>
              <th className="text-left px-4 py-3">プロトコル</th>
            </tr>
          </thead>
          <tbody>
            {connections.map((c, i) => (
              <tr
                key={i}
                className={`border-b border-[#1e2d42] last:border-0 transition-colors
                  ${c.suspicious ? 'bg-[#e8002d]/5 hover:bg-[#e8002d]/10' : 'hover:bg-[#19253d]'}`}
              >
                <td className="px-4 py-2.5 font-mono text-white">{c.pid}</td>
                <td className="px-4 py-2.5">
                  <span className={`font-mono font-medium ${c.suspicious ? 'text-[#e8002d]' : 'text-white'}`}>
                    {c.process}
                  </span>
                </td>
                <td className="px-4 py-2.5 font-mono text-[#7d92b0]">{c.local_addr}:{c.local_port}</td>
                <td className="px-4 py-2.5">
                  <span className={`font-mono ${c.suspicious ? 'text-[#e8002d] font-bold' : 'text-[#7d92b0]'}`}>
                    {c.remote_addr}:{c.remote_port}
                  </span>
                  {c.suspicious && <AlertTriangle className="w-3 h-3 text-[#e8002d] inline ml-1" />}
                </td>
                <td className="px-4 py-2.5">
                  <span className={`text-[9px] font-bold px-1.5 py-0.5 rounded-sm ${
                    c.state === 'ESTABLISHED' ? 'bg-[#00c853]/20 text-[#00c853]' :
                    c.state === 'LISTEN' ? 'bg-[#1a6bff]/20 text-[#1a6bff]' :
                    'bg-[#1e2d42] text-[#7d92b0]'
                  }`}>{c.state}</span>
                </td>
                <td className="px-4 py-2.5 text-[#7d92b0]">{c.protocol}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  )
}

function StringsTab({ strings }: { strings: StringEntry[] }) {
  const [filter, setFilter] = useState<StringEntry['type'] | 'all'>('all')
  const [selected, setSelected] = useState<Set<string>>(new Set())
  const [addedToIOC, setAddedToIOC] = useState(false)

  const types: Array<StringEntry['type'] | 'all'> = ['all', 'url', 'ip', 'registry', 'command', 'base64', 'suspicious']
  const filtered = filter === 'all' ? strings : strings.filter(s => s.type === filter)

  const toggleSelect = (id: string) => {
    setSelected(prev => {
      const next = new Set(prev)
      if (next.has(id)) next.delete(id)
      else next.add(id)
      return next
    })
  }

  const handleAddIOC = () => {
    setAddedToIOC(true)
    setTimeout(() => { setAddedToIOC(false); setSelected(new Set()) }, 2000)
  }

  return (
    <div className="space-y-3">
      <div className="flex items-center gap-3 flex-wrap">
        <div className="flex gap-1 flex-wrap">
          {types.map(t => (
            <button
              key={t}
              onClick={() => setFilter(t)}
              className={`text-xs px-3 py-1 rounded-sm transition-colors ${filter === t ? 'bg-[#e8002d] text-white' : 'bg-[#1e2d42] text-[#7d92b0] hover:text-white'}`}
            >
              {t === 'all' ? '全て' : t}
            </button>
          ))}
        </div>
        {selected.size > 0 && (
          <button
            onClick={handleAddIOC}
            className="ml-auto text-xs px-3 py-1.5 rounded-sm bg-[#1a6bff] text-white hover:bg-blue-600 transition-colors flex items-center gap-1"
          >
            {addedToIOC ? <><CheckCircle className="w-3 h-3" /> IOC追加完了</> : <><Plus className="w-3 h-3" /> IOCに追加 ({selected.size})</>}
          </button>
        )}
      </div>
      <div className="bg-[#0d1220] border border-[#1e2d42] rounded-xl overflow-hidden">
        <table className="w-full text-xs">
          <thead>
            <tr className="border-b border-[#1e2d42] text-[#3d5068]">
              <th className="px-4 py-3 w-8">
                <input type="checkbox" className="accent-[#e8002d]" onChange={e => {
                  if (e.target.checked) setSelected(new Set(filtered.map(s => s.id)))
                  else setSelected(new Set())
                }} />
              </th>
              <th className="text-left px-4 py-3">タイプ</th>
              <th className="text-left px-4 py-3">値</th>
              <th className="text-left px-4 py-3">プロセス (PID)</th>
              <th className="text-left px-4 py-3">オフセット</th>
            </tr>
          </thead>
          <tbody>
            {filtered.map(s => (
              <tr key={s.id} className={`border-b border-[#1e2d42] last:border-0 transition-colors ${selected.has(s.id) ? 'bg-[#1a6bff]/10' : 'hover:bg-[#19253d]'}`}>
                <td className="px-4 py-2.5">
                  <input type="checkbox" checked={selected.has(s.id)} onChange={() => toggleSelect(s.id)} className="accent-[#e8002d]" />
                </td>
                <td className="px-4 py-2.5"><StringTypeBadge type={s.type} /></td>
                <td className="px-4 py-2.5 font-mono text-[#7d92b0] max-w-[300px] truncate">
                  {(s.type === 'url' || s.type === 'ip') ? (
                    <span className="text-[#1a6bff] hover:underline cursor-pointer">{s.value}</span>
                  ) : (
                    <span className={s.type === 'command' ? 'text-[#e8002d]' : s.type === 'base64' ? 'text-teal-400' : ''}>{s.value}</span>
                  )}
                </td>
                <td className="px-4 py-2.5 text-white">{s.process} ({s.pid})</td>
                <td className="px-4 py-2.5 font-mono text-[#3d5068]">{s.offset}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  )
}

function MalwareTab({ results, rwxRegions, suspSections }: {
  results: YaraResult[]
  rwxRegions: MemRegion[]
  suspSections: AnalysisResults['suspicious_sections']
}) {
  return (
    <div className="space-y-6">

      {/* YARA Results */}
      <div>
        <h4 className="text-white font-medium mb-3 flex items-center gap-2">
          <Shield className="w-4 h-4 text-[#e8002d]" /> YARAスキャン結果
        </h4>
        <div className="bg-[#0d1220] border border-[#1e2d42] rounded-xl overflow-hidden">
          <table className="w-full text-xs">
            <thead>
              <tr className="border-b border-[#1e2d42] text-[#3d5068]">
                <th className="text-left px-4 py-3">ルール名</th>
                <th className="text-left px-4 py-3">プロセス (PID)</th>
                <th className="text-left px-4 py-3">リージョン</th>
                <th className="text-right px-4 py-3">スコア</th>
                <th className="text-left px-4 py-3">マルウェアファミリー</th>
              </tr>
            </thead>
            <tbody>
              {results.map((r, i) => (
                <tr key={i} className="border-b border-[#1e2d42] last:border-0 hover:bg-[#19253d] transition-colors">
                  <td className="px-4 py-2.5 font-mono text-[#e8002d] font-medium">{r.rule_name}</td>
                  <td className="px-4 py-2.5 text-white">{r.process} ({r.pid})</td>
                  <td className="px-4 py-2.5 font-mono text-[#7d92b0]">{r.region}</td>
                  <td className="px-4 py-2.5 text-right">
                    <span className={`font-bold ${r.score >= 90 ? 'text-[#e8002d]' : r.score >= 75 ? 'text-[#ff9800]' : 'text-yellow-400'}`}>
                      {r.score}
                    </span>
                  </td>
                  <td className="px-4 py-2.5">
                    <span className="text-xs bg-[#e8002d]/20 text-[#e8002d] px-2 py-0.5 rounded-sm">{r.malware_family}</span>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>

      {/* RWX Regions */}
      <div>
        <h4 className="text-white font-medium mb-3 flex items-center gap-2">
          <AlertTriangle className="w-4 h-4 text-[#ff9800]" /> RWX メモリ領域 (コードインジェクション指標)
        </h4>
        <div className="bg-[#0d1220] border border-[#1e2d42] rounded-xl overflow-hidden">
          <table className="w-full text-xs">
            <thead>
              <tr className="border-b border-[#1e2d42] text-[#3d5068]">
                <th className="text-left px-4 py-3">ベースアドレス</th>
                <th className="text-left px-4 py-3">サイズ</th>
                <th className="text-left px-4 py-3">権限</th>
                <th className="text-left px-4 py-3">タイプ</th>
              </tr>
            </thead>
            <tbody>
              {rwxRegions.map((r, i) => (
                <tr key={i} className="border-b border-[#1e2d42] last:border-0 bg-[#ff9800]/5">
                  <td className="px-4 py-2.5 font-mono text-white">{r.base}</td>
                  <td className="px-4 py-2.5 font-mono text-[#7d92b0]">{r.size}</td>
                  <td className="px-4 py-2.5">
                    <span className="font-mono font-bold text-[#ff9800] bg-[#ff9800]/20 px-2 py-0.5 rounded-sm">{r.permissions}</span>
                  </td>
                  <td className="px-4 py-2.5 text-[#7d92b0]">{r.type}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>

      {/* Suspicious Sections */}
      <div>
        <h4 className="text-white font-medium mb-3 flex items-center gap-2">
          <Terminal className="w-4 h-4 text-purple-400" /> アンパックコードセクション
        </h4>
        <div className="space-y-2">
          {suspSections.map((s, i) => (
            <div key={i} className="bg-[#0d1220] border border-purple-500/30 rounded-lg p-4 flex items-start gap-3">
              <AlertTriangle className="w-4 h-4 text-purple-400 shrink-0 mt-0.5" />
              <div>
                <p className="text-white text-sm font-medium">{s.process} — <span className="font-mono">{s.section}</span></p>
                <p className="text-[#7d92b0] text-xs mt-1">{s.note}</p>
              </div>
            </div>
          ))}
        </div>
      </div>
    </div>
  )
}

// ─── Main Page ────────────────────────────────────────────────────────────────

export default function MemoryForensicsPage() {
  const [selectedDump, setSelectedDump] = useState<string | null>('dump1')
  const [analysisTab, setAnalysisTab] = useState<'process' | 'network' | 'strings' | 'malware'>('process')
  const [dumps, setDumps] = useState<MemoryDump[]>(m(MOCK_DUMPS))
  const [dragging, setDragging] = useState(false)
  const [analyzingId, setAnalyzingId] = useState<string | null>(null)
  const fileInputRef = useRef<HTMLInputElement>(null)

  const handleFileSelect = (files: FileList | null) => {
    if (!files || files.length === 0) return
    const file = files[0]
    const newDump: MemoryDump = {
      id: `dump-${Date.now()}`,
      filename: file.name,
      hostname: '—',
      size_mb: Math.round(file.size / (1024 * 1024)) || 1,
      acquisition_time: new Date().toISOString(),
      analysis_status: 'pending',
      os: '—',
      architecture: '—',
    }
    setDumps(prev => [newDump, ...prev])
    setSelectedDump(newDump.id)
  }

  const { data: dumpsData, isLoading: dumpsLoading } = useQuery<{ dumps: MemoryDump[] }>({
    queryKey: ['memory-dumps'],
    queryFn: () => apiFetch('/api/v1/forensics/memory/dumps'),
    staleTime: 30_000,
  })

  const actualDumps = dumpsData?.dumps ?? dumps
  const selected = actualDumps.find(d => d.id === selectedDump) ?? null
  const results = m(MOCK_ANALYSIS)

  const startAnalysis = (id: string) => {
    setAnalyzingId(id)
    setDumps(prev => prev.map(d => d.id === id ? { ...d, analysis_status: 'analyzing' } : d))
    setTimeout(() => {
      setDumps(prev => prev.map(d => d.id === id ? { ...d, analysis_status: 'complete' } : d))
      setAnalyzingId(null)
    }, 4000)
  }

  const analysisTabs = [
    { id: 'process' as const, label: 'プロセス一覧' },
    { id: 'network' as const, label: 'ネットワーク接続' },
    { id: 'strings' as const, label: '文字列抽出' },
    { id: 'malware' as const, label: 'マルウェア検出' },
  ]

  return (
    <div className="min-h-screen bg-[#070d19] text-[#7d92b0]">
      <PageDataUnavailable />
      {/* Header */}
      <div className="border-b border-[#1e2d42] bg-[#0d1220] px-6 py-4">
        <div className="flex items-center gap-3">
          <div className="w-9 h-9 rounded-lg bg-linear-to-br from-[#7c3aed] to-[#4c1d95] flex items-center justify-center">
            <Cpu className="w-5 h-5 text-white" />
          </div>
          <div>
            <h1 className="text-xl font-bold text-white">メモリフォレンジクス分析</h1>
            <p className="text-xs text-[#3d5068] mt-0.5">Advanced Memory Forensics — プロセス・ネットワーク・文字列・YARAスキャン</p>
          </div>
        </div>
      </div>

      <div className="p-6 space-y-6">

        {/* Memory Dump Management */}
        <div>
          <div className="flex items-center justify-between mb-3">
            <h2 className="text-white font-semibold">メモリダンプ管理</h2>
          </div>

          {/* Upload Area */}
          <div
            className={`border-2 border-dashed rounded-xl p-6 mb-4 text-center transition-colors ${
              dragging ? 'border-[#e8002d] bg-[#e8002d]/5' : 'border-[#1e2d42] hover:border-[#7d92b0]/40'
            }`}
            onDragOver={e => { e.preventDefault(); setDragging(true) }}
            onDragLeave={() => setDragging(false)}
            onDrop={e => { e.preventDefault(); setDragging(false); handleFileSelect(e.dataTransfer.files) }}
          >
            <input
              ref={fileInputRef}
              type="file"
              accept=".dmp,.raw,.mem"
              className="hidden"
              onChange={e => handleFileSelect(e.target.files)}
            />
            <Upload className="w-8 h-8 text-[#3d5068] mx-auto mb-2" />
            <p className="text-white font-medium mb-1">ダンプファイルをドロップ</p>
            <p className="text-xs text-[#3d5068]">.dmp / .raw / .mem ファイルに対応</p>
            <button
              onClick={() => fileInputRef.current?.click()}
              className="mt-3 px-4 py-2 rounded-lg bg-[#e8002d] text-white text-sm hover:bg-[#c0001f] transition-colors"
            >
              ファイルを選択
            </button>
          </div>

          {/* Dumps Table */}
          <div className="bg-[#0d1220] border border-[#1e2d42] rounded-xl overflow-hidden">
            <table className="w-full text-sm">
              <thead>
                <tr className="border-b border-[#1e2d42] text-[#3d5068] text-xs">
                  <th className="text-left px-4 py-3">ファイル名</th>
                  <th className="text-left px-4 py-3">ホスト名</th>
                  <th className="text-right px-4 py-3">サイズ</th>
                  <th className="text-left px-4 py-3">取得日時</th>
                  <th className="text-left px-4 py-3">OS / アーキテクチャ</th>
                  <th className="text-left px-4 py-3">ステータス</th>
                  <th className="px-4 py-3"></th>
                </tr>
              </thead>
              <tbody>
                {actualDumps.map(d => (
                  <tr
                    key={d.id}
                    className={`border-b border-[#1e2d42] last:border-0 transition-colors cursor-pointer ${
                      selectedDump === d.id ? 'bg-[#1d2f4a]' : 'hover:bg-[#19253d]'
                    }`}
                    onClick={() => setSelectedDump(d.id)}
                  >
                    <td className="px-4 py-3">
                      <span className="text-white font-mono text-xs">{d.filename}</span>
                    </td>
                    <td className="px-4 py-3 text-white font-medium">{d.hostname}</td>
                    <td className="px-4 py-3 text-right text-[#7d92b0] font-mono">
                      {d.size_mb >= 1024 ? `${(d.size_mb / 1024).toFixed(0)} GB` : `${d.size_mb} MB`}
                    </td>
                    <td className="px-4 py-3 text-xs text-[#7d92b0]">
                      {new Date(d.acquisition_time).toLocaleString('ja-JP')}
                    </td>
                    <td className="px-4 py-3 text-xs text-[#7d92b0]">{d.os} / {d.architecture}</td>
                    <td className="px-4 py-3"><StatusBadge status={d.analysis_status} /></td>
                    <td className="px-4 py-3">
                      {d.analysis_status === 'pending' && (
                        <button
                          onClick={e => { e.stopPropagation(); startAnalysis(d.id) }}
                          disabled={analyzingId !== null}
                          className="flex items-center gap-1.5 text-xs px-3 py-1.5 rounded-sm bg-[#e8002d] text-white hover:bg-[#c0001f] disabled:opacity-50 transition-colors"
                        >
                          <Play className="w-3 h-3" /> 分析開始
                        </button>
                      )}
                      {d.analysis_status === 'analyzing' && (
                        <span className="flex items-center gap-1 text-xs text-[#1a6bff]">
                          <Loader2 className="w-3 h-3 animate-spin" /> 処理中...
                        </span>
                      )}
                      {d.analysis_status === 'complete' && (
                        <button
                          onClick={e => { e.stopPropagation(); setSelectedDump(d.id) }}
                          className="flex items-center gap-1 text-xs px-3 py-1.5 rounded-sm bg-[#00c853]/20 text-[#00c853] hover:bg-[#00c853]/30 transition-colors"
                        >
                          <Eye className="w-3 h-3" /> 結果表示
                        </button>
                      )}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>

        {/* Analysis Results */}
        {selected && selected.analysis_status === 'complete' && (
          <div>
            <div className="flex items-center gap-3 mb-4">
              <div className="flex-1">
                <h2 className="text-white font-semibold">分析結果: {selected.hostname}</h2>
                <p className="text-xs text-[#3d5068] mt-0.5 font-mono">{selected.filename}</p>
              </div>
              <div className="flex items-center gap-2">
                <span className="text-xs text-[#e8002d] bg-[#e8002d]/10 border border-[#e8002d]/30 px-3 py-1 rounded-lg font-medium">
                  疑わしいプロセス: {results.processes.filter(p => p.indicators.length > 0).length}
                </span>
                <span className="text-xs text-[#ff9800] bg-[#ff9800]/10 border border-[#ff9800]/30 px-3 py-1 rounded-lg font-medium">
                  C2接続: {results.network_connections.filter(c => c.suspicious).length}
                </span>
                <span className="text-xs text-purple-400 bg-purple-500/10 border border-purple-500/30 px-3 py-1 rounded-lg font-medium">
                  YARAマッチ: {results.yara_results.length}
                </span>
              </div>
            </div>

            {/* Analysis Sub-Tabs */}
            <div className="flex gap-0 border-b border-[#1e2d42] mb-4">
              {analysisTabs.map(t => (
                <button
                  key={t.id}
                  onClick={() => setAnalysisTab(t.id)}
                  className={`px-5 py-3 text-sm font-medium border-b-2 transition-all ${
                    analysisTab === t.id
                      ? 'border-[#e8002d] text-white'
                      : 'border-transparent text-[#7d92b0] hover:text-[#e2e8f4]'
                  }`}
                >
                  {t.label}
                  {t.id === 'malware' && results.yara_results.length > 0 && (
                    <span className="ml-1.5 text-[9px] bg-[#e8002d] text-white px-1.5 py-0.5 rounded-sm font-bold">
                      {results.yara_results.length}
                    </span>
                  )}
                  {t.id === 'process' && results.processes.filter(p => p.indicators.length > 0).length > 0 && (
                    <span className="ml-1.5 text-[9px] bg-[#ff9800] text-white px-1.5 py-0.5 rounded-sm font-bold">
                      {results.processes.filter(p => p.indicators.length > 0).length}
                    </span>
                  )}
                </button>
              ))}
            </div>

            {analysisTab === 'process' && <ProcessTab processes={results.processes} />}
            {analysisTab === 'network' && <NetworkTab connections={results.network_connections} />}
            {analysisTab === 'strings' && <StringsTab strings={results.strings} />}
            {analysisTab === 'malware' && (
              <MalwareTab
                results={results.yara_results}
                rwxRegions={results.rwx_regions}
                suspSections={results.suspicious_sections}
              />
            )}
          </div>
        )}

        {selected && selected.analysis_status !== 'complete' && (
          <div className="bg-[#0d1220] border border-[#1e2d42] rounded-xl p-12 text-center">
            <Cpu className="w-12 h-12 text-[#3d5068] mx-auto mb-3" />
            <p className="text-white font-medium">
              {selected.analysis_status === 'pending' ? '分析待機中' : '分析中...'}
            </p>
            <p className="text-xs text-[#3d5068] mt-1">
              {selected.analysis_status === 'pending'
                ? '「分析開始」ボタンをクリックして分析を開始してください'
                : 'メモリダンプを解析しています。しばらくお待ちください'}
            </p>
          </div>
        )}

        {!selected && (
          <div className="bg-[#0d1220] border border-[#1e2d42] rounded-xl p-12 text-center">
            <Cpu className="w-12 h-12 text-[#3d5068] mx-auto mb-3" />
            <p className="text-white font-medium">ダンプファイルを選択してください</p>
            <p className="text-xs text-[#3d5068] mt-1">上のテーブルからメモリダンプを選択すると分析結果が表示されます</p>
          </div>
        )}
      </div>
    </div>
  )
}

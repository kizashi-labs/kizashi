'use client'

import { useState, useEffect, useCallback, useRef } from 'react'
import { useQuery } from '@tanstack/react-query'
import { apiFetch } from '@/lib/api'
import {
  Globe, RefreshCw, AlertTriangle, Zap, Shield,
  Filter, ChevronDown, X, Activity, ArrowRight,
} from 'lucide-react'
import { PageDataUnavailable } from '@/components/PageDataUnavailable'

import { WorldMap } from '@/components/WorldMap'
import { USE_MOCK, m } from '@/lib/mock'

// ── Types ──────────────────────────────────────────────────────────────────

type Severity = 'critical' | 'high' | 'medium' | 'low'
type ThreatType = 'ransomware' | 'ddos' | 'phishing' | 'apt' | 'exploit' | 'botnet' | 'malware'
type TimeRange = '1h' | '6h' | '24h' | '7d'

interface ThreatSource {
  id: string
  country: string
  flag: string
  countryCode: string
  lat: number
  lon: number
  threat_count: number
  top_threat_type: ThreatType
  severity: Severity
  targeted_sectors: string[]
  top_targets: { country: string; flag: string }[]
}

interface LiveEvent {
  id: string
  time: string
  src_country: string
  src_flag: string
  dst_country: string
  dst_flag: string
  threat_type: ThreatType
  severity: Severity
}

interface AttackLine {
  id: string
  srcX: number
  srcY: number
  dstX: number
  dstY: number
  severity: Severity
  progress: number
}

interface GeoThreatData {
  sources: ThreatSource[]
  live_events: LiveEvent[]
  stats: {
    total_today: number
    top_source: string
    top_type: string
    critical_count: number
  }
}

// ── Constants ──────────────────────────────────────────────────────────────

const THREAT_SOURCES: ThreatSource[] = [
  { id: 'cn', country: '中国', flag: '🇨🇳', countryCode: 'CN', lat: 35, lon: 105, threat_count: 14872, top_threat_type: 'apt', severity: 'critical', targeted_sectors: ['金融', '防衛', '製造'], top_targets: [{ country: '米国', flag: '🇺🇸' }, { country: '日本', flag: '🇯🇵' }] },
  { id: 'ru', country: 'ロシア', flag: '🇷🇺', countryCode: 'RU', lat: 60, lon: 90, threat_count: 11234, top_threat_type: 'ransomware', severity: 'critical', targeted_sectors: ['政府', 'エネルギー', '医療'], top_targets: [{ country: 'ウクライナ', flag: '🇺🇦' }, { country: '独国', flag: '🇩🇪' }] },
  { id: 'kp', country: '北朝鮮', flag: '🇰🇵', countryCode: 'KP', lat: 40, lon: 127, threat_count: 6543, top_threat_type: 'apt', severity: 'critical', targeted_sectors: ['仮想通貨', '防衛', '航空'], top_targets: [{ country: '韓国', flag: '🇰🇷' }, { country: '米国', flag: '🇺🇸' }] },
  { id: 'ir', country: 'イラン', flag: '🇮🇷', countryCode: 'IR', lat: 33, lon: 53, threat_count: 4321, top_threat_type: 'exploit', severity: 'high', targeted_sectors: ['石油', 'インフラ', '政府'], top_targets: [{ country: 'イスラエル', flag: '🇮🇱' }, { country: '米国', flag: '🇺🇸' }] },
  { id: 'br', country: 'ブラジル', flag: '🇧🇷', countryCode: 'BR', lat: -14, lon: -51, threat_count: 3210, top_threat_type: 'botnet', severity: 'high', targeted_sectors: ['金融', 'EC', '小売'], top_targets: [{ country: '米国', flag: '🇺🇸' }, { country: '欧州', flag: '🇪🇺' }] },
  { id: 'ng', country: 'ナイジェリア', flag: '🇳🇬', countryCode: 'NG', lat: 9, lon: 8, threat_count: 2876, top_threat_type: 'phishing', severity: 'medium', targeted_sectors: ['金融', 'EC'], top_targets: [{ country: '米国', flag: '🇺🇸' }, { country: '英国', flag: '🇬🇧' }] },
  { id: 'us', country: '米国 (内部)', flag: '🇺🇸', countryCode: 'US', lat: 38, lon: -97, threat_count: 2145, top_threat_type: 'malware', severity: 'medium', targeted_sectors: ['医療', '教育', '政府'], top_targets: [{ country: '日本', flag: '🇯🇵' }, { country: '独国', flag: '🇩🇪' }] },
  { id: 'vn', country: 'ベトナム', flag: '🇻🇳', countryCode: 'VN', lat: 16, lon: 108, threat_count: 1987, top_threat_type: 'apt', severity: 'high', targeted_sectors: ['製造', '政府'], top_targets: [{ country: '日本', flag: '🇯🇵' }, { country: '台湾', flag: '🇹🇼' }] },
  { id: 'in', country: 'インド', flag: '🇮🇳', countryCode: 'IN', lat: 20, lon: 77, threat_count: 1654, top_threat_type: 'phishing', severity: 'medium', targeted_sectors: ['IT', '通信'], top_targets: [{ country: '米国', flag: '🇺🇸' }] },
  { id: 'ro', country: 'ルーマニア', flag: '🇷🇴', countryCode: 'RO', lat: 46, lon: 25, threat_count: 1432, top_threat_type: 'exploit', severity: 'medium', targeted_sectors: ['金融', 'EC'], top_targets: [{ country: '欧州', flag: '🇪🇺' }] },
  { id: 'pk', country: 'パキスタン', flag: '🇵🇰', countryCode: 'PK', lat: 30, lon: 70, threat_count: 1123, top_threat_type: 'ddos', severity: 'medium', targeted_sectors: ['政府', 'メディア'], top_targets: [{ country: 'インド', flag: '🇮🇳' }] },
  { id: 'ua', country: 'ウクライナ', flag: '🇺🇦', countryCode: 'UA', lat: 49, lon: 32, threat_count: 987, top_threat_type: 'ransomware', severity: 'high', targeted_sectors: ['エネルギー', '政府'], top_targets: [{ country: 'ロシア', flag: '🇷🇺' }] },
  { id: 'by', country: 'ベラルーシ', flag: '🇧🇾', countryCode: 'BY', lat: 53, lon: 28, threat_count: 876, top_threat_type: 'apt', severity: 'high', targeted_sectors: ['政府', '通信'], top_targets: [{ country: 'ポーランド', flag: '🇵🇱' }] },
  { id: 'mx', country: 'メキシコ', flag: '🇲🇽', countryCode: 'MX', lat: 23, lon: -102, threat_count: 765, top_threat_type: 'botnet', severity: 'low', targeted_sectors: ['金融', '小売'], top_targets: [{ country: '米国', flag: '🇺🇸' }] },
  { id: 'id', country: 'インドネシア', flag: '🇮🇩', countryCode: 'ID', lat: -5, lon: 120, threat_count: 654, top_threat_type: 'phishing', severity: 'low', targeted_sectors: ['銀行', 'EC'], top_targets: [{ country: '豪州', flag: '🇦🇺' }] },
  { id: 'tr', country: 'トルコ', flag: '🇹🇷', countryCode: 'TR', lat: 39, lon: 35, threat_count: 543, top_threat_type: 'ddos', severity: 'medium', targeted_sectors: ['メディア', '政府'], top_targets: [{ country: '欧州', flag: '🇪🇺' }] },
  { id: 'za', country: '南アフリカ', flag: '🇿🇦', countryCode: 'ZA', lat: -29, lon: 25, threat_count: 432, top_threat_type: 'malware', severity: 'low', targeted_sectors: ['鉱業', '金融'], top_targets: [{ country: '欧州', flag: '🇪🇺' }] },
  { id: 'eg', country: 'エジプト', flag: '🇪🇬', countryCode: 'EG', lat: 27, lon: 30, threat_count: 376, top_threat_type: 'phishing', severity: 'low', targeted_sectors: ['政府', '教育'], top_targets: [{ country: '中東', flag: '🌍' }] },
  { id: 'th', country: 'タイ', flag: '🇹🇭', countryCode: 'TH', lat: 15, lon: 101, threat_count: 298, top_threat_type: 'botnet', severity: 'low', targeted_sectors: ['観光', '金融'], top_targets: [{ country: '日本', flag: '🇯🇵' }] },
  { id: 'ar', country: 'アルゼンチン', flag: '🇦🇷', countryCode: 'AR', lat: -34, lon: -64, threat_count: 212, top_threat_type: 'malware', severity: 'low', targeted_sectors: ['農業', '金融'], top_targets: [{ country: '欧州', flag: '🇪🇺' }] },
]

const MOCK_LIVE_EVENTS: LiveEvent[] = [
  { id: 'e1', time: '14:32:01', src_country: '中国', src_flag: '🇨🇳', dst_country: '日本', dst_flag: '🇯🇵', threat_type: 'apt', severity: 'critical' },
  { id: 'e2', time: '14:31:55', src_country: 'ロシア', src_flag: '🇷🇺', dst_country: 'ウクライナ', dst_flag: '🇺🇦', threat_type: 'ransomware', severity: 'critical' },
  { id: 'e3', time: '14:31:48', src_country: '北朝鮮', src_flag: '🇰🇵', dst_country: '韓国', dst_flag: '🇰🇷', threat_type: 'apt', severity: 'critical' },
  { id: 'e4', time: '14:31:42', src_country: 'ナイジェリア', src_flag: '🇳🇬', dst_country: '米国', dst_flag: '🇺🇸', threat_type: 'phishing', severity: 'high' },
  { id: 'e5', time: '14:31:35', src_country: 'イラン', src_flag: '🇮🇷', dst_country: 'イスラエル', dst_flag: '🇮🇱', threat_type: 'exploit', severity: 'critical' },
  { id: 'e6', time: '14:31:28', src_country: 'ブラジル', src_flag: '🇧🇷', dst_country: 'ドイツ', dst_flag: '🇩🇪', threat_type: 'botnet', severity: 'medium' },
  { id: 'e7', time: '14:31:20', src_country: '米国', src_flag: '🇺🇸', dst_country: '英国', dst_flag: '🇬🇧', threat_type: 'malware', severity: 'medium' },
  { id: 'e8', time: '14:31:14', src_country: 'ルーマニア', src_flag: '🇷🇴', dst_country: 'フランス', dst_flag: '🇫🇷', threat_type: 'exploit', severity: 'high' },
  { id: 'e9', time: '14:31:07', src_country: 'ベトナム', src_flag: '🇻🇳', dst_country: '台湾', dst_flag: '🇹🇼', threat_type: 'apt', severity: 'high' },
  { id: 'e10', time: '14:31:00', src_country: '中国', src_flag: '🇨🇳', dst_country: '米国', dst_flag: '🇺🇸', threat_type: 'ddos', severity: 'high' },
  { id: 'e11', time: '14:30:54', src_country: 'パキスタン', src_flag: '🇵🇰', dst_country: 'インド', dst_flag: '🇮🇳', threat_type: 'ddos', severity: 'medium' },
  { id: 'e12', time: '14:30:47', src_country: 'トルコ', src_flag: '🇹🇷', dst_country: 'ギリシャ', dst_flag: '🇬🇷', threat_type: 'ddos', severity: 'medium' },
  { id: 'e13', time: '14:30:40', src_country: 'インド', src_flag: '🇮🇳', dst_country: '米国', dst_flag: '🇺🇸', threat_type: 'phishing', severity: 'low' },
  { id: 'e14', time: '14:30:33', src_country: 'ロシア', src_flag: '🇷🇺', dst_country: 'バルト諸国', dst_flag: '🇱🇻', threat_type: 'apt', severity: 'critical' },
  { id: 'e15', time: '14:30:26', src_country: '北朝鮮', src_flag: '🇰🇵', dst_country: '日本', dst_flag: '🇯🇵', threat_type: 'ransomware', severity: 'critical' },
  { id: 'e16', time: '14:30:19', src_country: 'インドネシア', src_flag: '🇮🇩', dst_country: '豪州', dst_flag: '🇦🇺', threat_type: 'phishing', severity: 'low' },
  { id: 'e17', time: '14:30:12', src_country: '中国', src_flag: '🇨🇳', dst_country: '台湾', dst_flag: '🇹🇼', threat_type: 'apt', severity: 'critical' },
  { id: 'e18', time: '14:30:05', src_country: 'ナイジェリア', src_flag: '🇳🇬', dst_country: '英国', dst_flag: '🇬🇧', threat_type: 'phishing', severity: 'medium' },
  { id: 'e19', time: '14:29:58', src_country: 'ブラジル', src_flag: '🇧🇷', dst_country: '米国', dst_flag: '🇺🇸', threat_type: 'botnet', severity: 'high' },
  { id: 'e20', time: '14:29:51', src_country: 'ベラルーシ', src_flag: '🇧🇾', dst_country: 'ポーランド', dst_flag: '🇵🇱', threat_type: 'apt', severity: 'high' },
]

const MOCK_STATS = {
  total_today: 54_921,
  top_source: '中国',
  top_type: 'APT',
  critical_count: 347,
}

const THREAT_TYPES: ThreatType[] = ['ransomware', 'ddos', 'phishing', 'apt', 'exploit', 'botnet', 'malware']
const TIME_RANGES: { value: TimeRange; label: string }[] = [
  { value: '1h', label: '1時間' },
  { value: '6h', label: '6時間' },
  { value: '24h', label: '24時間' },
  { value: '7d', label: '7日間' },
]

// ── Helpers ────────────────────────────────────────────────────────────────

function latLonToPercent(lat: number, lon: number): { x: number; y: number } {
  // Simple equirectangular projection
  const x = ((lon + 180) / 360) * 100
  const y = ((90 - lat) / 180) * 100
  return { x, y }
}

function severityColor(s: Severity): string {
  switch (s) {
    case 'critical': return '#e8002d'
    case 'high': return '#f97316'
    case 'medium': return '#eab308'
    case 'low': return '#22c55e'
  }
}

function severityBg(s: Severity): string {
  switch (s) {
    case 'critical': return 'bg-red-900/30 text-red-400 border-red-800/50'
    case 'high': return 'bg-orange-900/30 text-orange-400 border-orange-800/50'
    case 'medium': return 'bg-yellow-900/30 text-yellow-400 border-yellow-800/50'
    case 'low': return 'bg-green-900/30 text-green-400 border-green-800/50'
  }
}

function threatTypeBadge(t: ThreatType): string {
  const map: Record<ThreatType, string> = {
    ransomware: 'bg-red-900/30 text-red-300',
    apt: 'bg-purple-900/30 text-purple-300',
    ddos: 'bg-blue-900/30 text-blue-300',
    phishing: 'bg-yellow-900/30 text-yellow-300',
    exploit: 'bg-orange-900/30 text-orange-300',
    botnet: 'bg-cyan-900/30 text-cyan-300',
    malware: 'bg-pink-900/30 text-pink-300',
  }
  return map[t]
}

function threatTypeLabel(t: ThreatType): string {
  const map: Record<ThreatType, string> = {
    ransomware: 'Ransomware', apt: 'APT', ddos: 'DDoS',
    phishing: 'Phishing', exploit: 'Exploit', botnet: 'Botnet', malware: 'Malware',
  }
  return map[t]
}

function generateEventId(): string {
  return 'ev_' + Math.random().toString(36).slice(2, 9)
}

function randomFrom<T>(arr: T[]): T {
  return arr[Math.floor(Math.random() * arr.length)]
}

function generateNewEvent(): LiveEvent {
  const src = randomFrom(THREAT_SOURCES)
  const dst = randomFrom(THREAT_SOURCES.filter(s => s.id !== src.id))
  const severities: Severity[] = ['critical', 'critical', 'high', 'high', 'medium', 'low']
  const now = new Date()
  const timeStr = `${String(now.getHours()).padStart(2, '0')}:${String(now.getMinutes()).padStart(2, '0')}:${String(now.getSeconds()).padStart(2, '0')}`
  return {
    id: generateEventId(),
    time: timeStr,
    src_country: src.country,
    src_flag: src.flag,
    dst_country: dst.country,
    dst_flag: dst.flag,
    threat_type: src.top_threat_type,
    severity: randomFrom(severities),
  }
}

// ── Sub-components ─────────────────────────────────────────────────────────

function PulseDot({ source, heatmapMode, onClick }: {
  source: ThreatSource
  heatmapMode: boolean
  onClick: (s: ThreatSource) => void
}) {
  const { x, y } = latLonToPercent(source.lat, source.lon)
  const color = severityColor(source.severity)
  const size = heatmapMode
    ? Math.max(20, Math.min(60, source.threat_count / 300))
    : Math.max(8, Math.min(20, source.threat_count / 800))

  return (
    <div
      className="absolute cursor-pointer group"
      style={{ left: `${x}%`, top: `${y}%`, transform: 'translate(-50%, -50%)' }}
      onClick={() => onClick(source)}
    >
      {heatmapMode ? (
        <div
          className="rounded-full opacity-30 blur-md"
          style={{ width: size, height: size, backgroundColor: color }}
        />
      ) : (
        <>
          <div
            className="rounded-full animate-ping absolute"
            style={{ width: size, height: size, backgroundColor: color, opacity: 0.4 }}
          />
          <div
            className="rounded-full relative z-10 border border-white/20"
            style={{ width: size * 0.6, height: size * 0.6, backgroundColor: color, margin: `${size * 0.2}px` }}
          />
        </>
      )}
      {/* Tooltip */}
      <div className="absolute z-50 hidden group-hover:block bottom-full mb-2 left-1/2 -translate-x-1/2 bg-[#0d1220] border border-[#1e2d42] rounded-sm px-2 py-1.5 text-xs whitespace-nowrap pointer-events-none">
        <p className="text-white font-semibold">{source.flag} {source.country}</p>
        <p className="text-[#7d92b0]">{(source.threat_count ?? 0).toLocaleString()} 件</p>
        <p className="text-[#7d92b0]">{threatTypeLabel(source.top_threat_type)}</p>
      </div>
    </div>
  )
}

function AttackSvgLines({ sources, heatmapMode }: { sources: ThreatSource[]; heatmapMode: boolean }) {
  const [lines, setLines] = useState<AttackLine[]>([])

  useEffect(() => {
    if (heatmapMode) { setLines([]); return }
    // Generate attack lines between critical sources and targets
    const newLines: AttackLine[] = []
    const criticalSources = sources.filter(s => s.severity === 'critical' || s.severity === 'high').slice(0, 6)
    const targets = [
      { lat: 35.7, lon: 139.7 }, // Japan
      { lat: 38.9, lon: -77.0 }, // USA DC
      { lat: 51.5, lon: -0.1 },  // UK London
      { lat: 48.9, lon: 2.4 },   // France Paris
      { lat: 52.5, lon: 13.4 },  // Germany Berlin
    ]
    criticalSources.forEach((src, i) => {
      const target = targets[i % targets.length]
      const sp = latLonToPercent(src.lat, src.lon)
      const dp = latLonToPercent(target.lat, target.lon)
      newLines.push({
        id: src.id,
        srcX: sp.x, srcY: sp.y,
        dstX: dp.x, dstY: dp.y,
        severity: src.severity,
        progress: Math.random(),
      })
    })
    setLines(newLines)
    const interval = setInterval(() => {
      setLines(prev => prev.map(l => ({ ...l, progress: (l.progress + 0.012) % 1 })))
    }, 50)
    return () => clearInterval(interval)
  }, [sources, heatmapMode])

  return (
    <svg className="absolute inset-0 w-full h-full pointer-events-none" style={{ zIndex: 5 }}>
      <defs>
        {lines.map(line => (
          <marker key={`arrow-${line.id}`} id={`arrow-${line.id}`} markerWidth="6" markerHeight="6" refX="3" refY="3" orient="auto">
            <path d="M0,0 L0,6 L6,3 z" fill={severityColor(line.severity)} opacity="0.7" />
          </marker>
        ))}
      </defs>
      {lines.map(line => {
        const mx = (line.srcX + line.dstX) / 2
        const my = Math.min(line.srcY, line.dstY) - 15
        const px = line.srcX + (line.dstX - line.srcX) * line.progress
        const py = line.srcY + (line.dstY - line.srcY) * line.progress
        return (
          <g key={line.id}>
            <path
              d={`M ${line.srcX}% ${line.srcY}% Q ${mx}% ${my}% ${line.dstX}% ${line.dstY}%`}
              fill="none"
              stroke={severityColor(line.severity)}
              strokeWidth="0.5"
              strokeDasharray="4,4"
              opacity="0.3"
            />
            <circle
              cx={`${px}%`}
              cy={`${py}%`}
              r="2"
              fill={severityColor(line.severity)}
              opacity="0.9"
            />
          </g>
        )
      })}
    </svg>
  )
}

function SourcePopup({ source, onClose }: { source: ThreatSource; onClose: () => void }) {
  return (
    <div className="absolute z-50 top-4 right-4 w-72 bg-[#0d1220] border border-[#1e2d42] rounded-lg p-4 shadow-2xl">
      <div className="flex items-start justify-between mb-3">
        <div>
          <p className="text-white font-bold text-lg">{source.flag} {source.country}</p>
          <span className={`inline-block px-2 py-0.5 rounded-sm text-xs border font-medium mt-1 ${severityBg(source.severity)}`}>
            {source.severity.toUpperCase()}
          </span>
        </div>
        <button onClick={onClose} className="text-[#7d92b0] hover:text-white p-1">
          <X className="w-4 h-4" />
        </button>
      </div>
      <div className="space-y-2 text-sm">
        <div className="flex justify-between">
          <span className="text-[#7d92b0]">攻撃件数</span>
          <span className="text-white font-bold">{(source.threat_count ?? 0).toLocaleString()}</span>
        </div>
        <div className="flex justify-between">
          <span className="text-[#7d92b0]">主要脅威</span>
          <span className={`px-1.5 py-0.5 rounded-sm text-xs font-medium ${threatTypeBadge(source.top_threat_type)}`}>
            {threatTypeLabel(source.top_threat_type)}
          </span>
        </div>
        <div>
          <p className="text-[#7d92b0] mb-1">ターゲットセクター</p>
          <div className="flex flex-wrap gap-1">
            {source.targeted_sectors.map(s => (
              <span key={s} className="px-2 py-0.5 rounded-sm bg-[#1e2d42] text-[#7d92b0] text-xs">{s}</span>
            ))}
          </div>
        </div>
        <div>
          <p className="text-[#7d92b0] mb-1">主要ターゲット</p>
          <div className="flex gap-2">
            {source.top_targets.map(t => (
              <span key={t.country} className="text-sm">{t.flag} {t.country}</span>
            ))}
          </div>
        </div>
      </div>
    </div>
  )
}

// ── World Map Grid Background ──────────────────────────────────────────────


// ── Main Page ──────────────────────────────────────────────────────────────

export default function ThreatMapPage() {
  const [selectedSource, setSelectedSource] = useState<ThreatSource | null>(null)
  const [heatmapMode, setHeatmapMode] = useState(false)
  const [timeRange, setTimeRange] = useState<TimeRange>('24h')
  const [typeFilter, setTypeFilter] = useState<ThreatType | 'all'>('all')
  const [severityFilter, setSeverityFilter] = useState<Severity | 'all'>('all')
  const [liveEvents, setLiveEvents] = useState<LiveEvent[]>(m(MOCK_LIVE_EVENTS))
  const [lastRefresh, setLastRefresh] = useState<Date>(new Date())
  const [isRefreshing, setIsRefreshing] = useState(false)

  const { data } = useQuery<GeoThreatData>({
    queryKey: ['geo-threats', timeRange],
    queryFn: () => apiFetch(`/api/v1/threat-intel/geo-threats?range=${timeRange}`),
    retry: 0,
  })

  const stats = data?.stats ?? m(MOCK_STATS)

  // Auto-refresh live feed every 30s
  useEffect(() => {
    const interval = setInterval(() => {
      setIsRefreshing(true)
      setLiveEvents(prev => {
        const newEvent = generateNewEvent()
        return [newEvent, ...prev.slice(0, 19)]
      })
      setLastRefresh(new Date())
      setTimeout(() => setIsRefreshing(false), 500)
    }, 30_000)
    return () => clearInterval(interval)
  }, [])

  const filteredSources = THREAT_SOURCES.filter(s => {
    if (typeFilter !== 'all' && s.top_threat_type !== typeFilter) return false
    if (severityFilter !== 'all' && s.severity !== severityFilter) return false
    return true
  })

  const handleRefresh = () => {
    setIsRefreshing(true)
    setLiveEvents(prev => {
      const newEvent = generateNewEvent()
      return [newEvent, ...prev.slice(0, 19)]
    })
    setLastRefresh(new Date())
    setTimeout(() => setIsRefreshing(false), 600)
  }

  return (
    <div className="min-h-screen bg-[#070d19] p-6 space-y-6">
      <PageDataUnavailable />

      {/* ── Header ── */}
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-3">
          <div className="w-10 h-10 rounded-lg bg-[#0d1220] border border-[#1e2d42] flex items-center justify-center">
            <Globe className="w-5 h-5 text-[#e8002d]" />
          </div>
          <div>
            <h1 className="text-white font-bold text-xl">脅威地図</h1>
            <p className="text-[#7d92b0] text-sm">リアルタイム脅威マップ</p>
          </div>
        </div>
        <div className="flex items-center gap-3">
          {/* Last refresh */}
          <span className="text-[#7d92b0] text-xs">
            最終更新: {lastRefresh.toLocaleTimeString('ja-JP')}
          </span>
          <button
            onClick={handleRefresh}
            className="flex items-center gap-2 px-3 py-1.5 bg-[#0d1220] border border-[#1e2d42] rounded-sm text-sm text-[#7d92b0] hover:text-white hover:border-[#7d92b0]/40 transition-colors"
          >
            <RefreshCw className={`w-3.5 h-3.5 ${isRefreshing ? 'animate-spin' : ''}`} />
            更新
          </button>
          {/* Heatmap toggle */}
          <button
            onClick={() => setHeatmapMode(prev => !prev)}
            className={`flex items-center gap-2 px-3 py-1.5 rounded-sm text-sm border transition-colors ${
              heatmapMode
                ? 'bg-[#e8002d]/20 border-[#e8002d]/50 text-[#e8002d]'
                : 'bg-[#0d1220] border-[#1e2d42] text-[#7d92b0] hover:text-white'
            }`}
          >
            <Activity className="w-3.5 h-3.5" />
            ヒートマップ
          </button>
        </div>
      </div>

      {/* ── Filters ── */}
      <div className="flex items-center gap-3 flex-wrap">
        <div className="flex items-center gap-2">
          <Filter className="w-4 h-4 text-[#7d92b0]" />
          <span className="text-[#7d92b0] text-sm">フィルター:</span>
        </div>
        {/* Time range */}
        <div className="flex items-center gap-1 bg-[#0d1220] border border-[#1e2d42] rounded-sm p-0.5">
          {TIME_RANGES.map(tr => (
            <button
              key={tr.value}
              onClick={() => setTimeRange(tr.value)}
              className={`px-3 py-1 rounded-sm text-xs font-medium transition-colors ${
                timeRange === tr.value
                  ? 'bg-[#e8002d] text-white'
                  : 'text-[#7d92b0] hover:text-white'
              }`}
            >
              {tr.label}
            </button>
          ))}
        </div>
        {/* Type filter */}
        <select
          value={typeFilter}
          onChange={e => setTypeFilter(e.target.value as ThreatType | 'all')}
          className="bg-[#0d1220] border border-[#1e2d42] text-[#7d92b0] text-sm rounded-sm px-3 py-1.5 focus:outline-hidden focus:border-[#7d92b0]/40"
        >
          <option value="all">すべての脅威タイプ</option>
          {THREAT_TYPES.map(t => <option key={t} value={t}>{threatTypeLabel(t)}</option>)}
        </select>
        {/* Severity filter */}
        <select
          value={severityFilter}
          onChange={e => setSeverityFilter(e.target.value as Severity | 'all')}
          className="bg-[#0d1220] border border-[#1e2d42] text-[#7d92b0] text-sm rounded-sm px-3 py-1.5 focus:outline-hidden focus:border-[#7d92b0]/40"
        >
          <option value="all">すべての深刻度</option>
          <option value="critical">クリティカル</option>
          <option value="high">高</option>
          <option value="medium">中</option>
          <option value="low">低</option>
        </select>
        <span className="text-[#7d92b0] text-xs ml-auto">
          表示中: {filteredSources.length} / {THREAT_SOURCES.length} ソース
        </span>
      </div>

      {/* ── Main content: Map + Live Feed ── */}
      <div className="flex gap-4" style={{ height: 480 }}>

        {/* World Map */}
        <div className="flex-1 relative bg-[#0a1020] border border-[#1e2d42] rounded-lg overflow-hidden">
          <WorldMap landFill="#0f1e30" borderStroke="#1e3550" borderWidth={0.4} />
          <AttackSvgLines sources={filteredSources} heatmapMode={heatmapMode} />

          {/* Threat source dots */}
          {filteredSources.map(source => (
            <PulseDot
              key={source.id}
              source={source}
              heatmapMode={heatmapMode}
              onClick={setSelectedSource}
            />
          ))}

          {/* Selected source popup */}
          {selectedSource && (
            <SourcePopup source={selectedSource} onClose={() => setSelectedSource(null)} />
          )}

          {/* Legend */}
          <div className="absolute bottom-3 left-3 bg-[#0d1220]/90 border border-[#1e2d42] rounded-sm p-2 text-xs space-y-1" style={{ zIndex: 10 }}>
            <p className="text-[#7d92b0] font-medium mb-1.5">深刻度</p>
            {(['critical', 'high', 'medium', 'low'] as Severity[]).map(s => (
              <div key={s} className="flex items-center gap-2">
                <div className="w-2.5 h-2.5 rounded-full" style={{ backgroundColor: severityColor(s) }} />
                <span className="text-[#7d92b0] capitalize">{s === 'critical' ? 'クリティカル' : s === 'high' ? '高' : s === 'medium' ? '中' : '低'}</span>
              </div>
            ))}
          </div>

          {/* Map label */}
          <div className="absolute top-3 left-3 text-[#3d5068] text-[10px] font-mono" style={{ zIndex: 10 }}>
            {heatmapMode ? 'ヒートマップモード' : 'リアルタイムモード'} · {filteredSources.length} 脅威ソース
          </div>
        </div>

        {/* Live Feed */}
        <div className="w-72 bg-[#0d1220] border border-[#1e2d42] rounded-lg flex flex-col overflow-hidden">
          <div className="px-3 py-2.5 border-b border-[#1e2d42] flex items-center justify-between shrink-0">
            <div className="flex items-center gap-2">
              <div className="w-2 h-2 rounded-full bg-[#00c853] animate-pulse" />
              <span className="text-white font-medium text-sm">ライブ脅威フィード</span>
            </div>
            <span className="text-[#7d92b0] text-xs">{liveEvents.length}件</span>
          </div>
          <div className="flex-1 overflow-y-auto divide-y divide-[#1e2d42]">
            {liveEvents.map((event, idx) => (
              <div
                key={event.id}
                className={`px-3 py-2 text-xs transition-colors ${idx === 0 ? 'bg-[#e8002d]/5' : 'hover:bg-[#1e2d42]/30'}`}
              >
                <div className="flex items-center justify-between mb-1">
                  <span className="text-[#7d92b0] font-mono">{event.time}</span>
                  <span className={`px-1.5 py-0.5 rounded-sm text-[10px] border ${severityBg(event.severity)}`}>
                    {event.severity === 'critical' ? 'CRIT' : event.severity.toUpperCase()}
                  </span>
                </div>
                <div className="flex items-center gap-1 text-white">
                  <span>{event.src_flag}</span>
                  <span className="text-[#7d92b0] truncate max-w-[60px]">{event.src_country}</span>
                  <ArrowRight className="w-3 h-3 text-[#e8002d] shrink-0" />
                  <span>{event.dst_flag}</span>
                  <span className="text-[#7d92b0] truncate max-w-[60px]">{event.dst_country}</span>
                </div>
                <span className={`inline-block px-1.5 py-0.5 rounded-sm text-[10px] mt-1 ${threatTypeBadge(event.threat_type)}`}>
                  {threatTypeLabel(event.threat_type)}
                </span>
              </div>
            ))}
          </div>
        </div>
      </div>

      {/* ── Stats Row ── */}
      <div className="grid grid-cols-4 gap-4">
        <div className="bg-[#0d1220] border border-[#1e2d42] rounded-lg p-4">
          <div className="flex items-center gap-2 mb-2">
            <Zap className="w-4 h-4 text-[#e8002d]" />
            <span className="text-[#7d92b0] text-sm">本日の総攻撃数</span>
          </div>
          <p className="text-white font-bold text-2xl">{(stats.total_today ?? 0).toLocaleString()}</p>
          <p className="text-green-400 text-xs mt-1">↑ 昨日比 +12.4%</p>
        </div>
        <div className="bg-[#0d1220] border border-[#1e2d42] rounded-lg p-4">
          <div className="flex items-center gap-2 mb-2">
            <Globe className="w-4 h-4 text-orange-400" />
            <span className="text-[#7d92b0] text-sm">主要攻撃元</span>
          </div>
          <p className="text-white font-bold text-2xl">🇨🇳 {stats.top_source}</p>
          <p className="text-[#7d92b0] text-xs mt-1">14,872 件</p>
        </div>
        <div className="bg-[#0d1220] border border-[#1e2d42] rounded-lg p-4">
          <div className="flex items-center gap-2 mb-2">
            <AlertTriangle className="w-4 h-4 text-yellow-400" />
            <span className="text-[#7d92b0] text-sm">主要脅威タイプ</span>
          </div>
          <p className="text-white font-bold text-2xl">{stats.top_type}</p>
          <p className="text-[#7d92b0] text-xs mt-1">27.1% of total</p>
        </div>
        <div className="bg-[#0d1220] border border-[#1e2d42] rounded-lg p-4">
          <div className="flex items-center gap-2 mb-2">
            <Shield className="w-4 h-4 text-[#e8002d]" />
            <span className="text-[#7d92b0] text-sm">クリティカルアラート</span>
          </div>
          <p className="text-white font-bold text-2xl">{stats.critical_count}</p>
          <p className="text-[#e8002d] text-xs mt-1 animate-pulse">● 対応必要</p>
        </div>
      </div>

      {/* ── Source Table ── */}
      <div className="bg-[#0d1220] border border-[#1e2d42] rounded-lg">
        <div className="px-4 py-3 border-b border-[#1e2d42] flex items-center justify-between">
          <h2 className="text-white font-semibold">脅威ソース詳細</h2>
          <span className="text-[#7d92b0] text-sm">{filteredSources.length} 件</span>
        </div>
        <div className="overflow-x-auto">
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b border-[#1e2d42]">
                <th className="text-left text-[#7d92b0] font-medium px-4 py-2.5">国</th>
                <th className="text-right text-[#7d92b0] font-medium px-4 py-2.5">攻撃件数</th>
                <th className="text-left text-[#7d92b0] font-medium px-4 py-2.5">主要脅威</th>
                <th className="text-left text-[#7d92b0] font-medium px-4 py-2.5">深刻度</th>
                <th className="text-left text-[#7d92b0] font-medium px-4 py-2.5">ターゲットセクター</th>
                <th className="text-left text-[#7d92b0] font-medium px-4 py-2.5">主要ターゲット</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-[#1e2d42]">
              {filteredSources.sort((a, b) => b.threat_count - a.threat_count).map(src => (
                <tr
                  key={src.id}
                  className="hover:bg-[#1e2d42]/30 cursor-pointer transition-colors"
                  onClick={() => setSelectedSource(src)}
                >
                  <td className="px-4 py-2.5 text-white font-medium">
                    {src.flag} {src.country}
                  </td>
                  <td className="px-4 py-2.5 text-right text-white font-mono">
                    {(src.threat_count ?? 0).toLocaleString()}
                  </td>
                  <td className="px-4 py-2.5">
                    <span className={`px-2 py-0.5 rounded-sm text-xs font-medium ${threatTypeBadge(src.top_threat_type)}`}>
                      {threatTypeLabel(src.top_threat_type)}
                    </span>
                  </td>
                  <td className="px-4 py-2.5">
                    <span className={`px-2 py-0.5 rounded-sm text-xs border font-medium ${severityBg(src.severity)}`}>
                      {src.severity === 'critical' ? 'クリティカル' : src.severity === 'high' ? '高' : src.severity === 'medium' ? '中' : '低'}
                    </span>
                  </td>
                  <td className="px-4 py-2.5">
                    <div className="flex gap-1 flex-wrap">
                      {src.targeted_sectors.slice(0, 2).map(s => (
                        <span key={s} className="px-1.5 py-0.5 rounded-sm bg-[#1e2d42] text-[#7d92b0] text-xs">{s}</span>
                      ))}
                      {src.targeted_sectors.length > 2 && (
                        <span className="text-[#7d92b0] text-xs">+{src.targeted_sectors.length - 2}</span>
                      )}
                    </div>
                  </td>
                  <td className="px-4 py-2.5 text-[#7d92b0] text-xs">
                    {src.top_targets.map(t => t.flag).join(' ')}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  )
}

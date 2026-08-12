import type { AlertSeverity, AlertStatus, Platform } from '@/types/api'

// ── Severity Badge ──────────────────────────────────────────────
// CrowdStrike-style: sharp, compact, uppercase with colored left accent

interface SeverityBadgeProps {
  severity: AlertSeverity | number
  showLabel?: boolean
}

export function SeverityBadge({ severity, showLabel = true }: SeverityBadgeProps) {
  const { border, bg, text, label } = getSeverityStyle(severity)
  return (
    <span
      className={`inline-flex items-center gap-1.5 text-[10px] font-bold tracking-widest
                  uppercase px-2 py-0.5 rounded ${bg} ${text} border-l-2 ${border}`}
    >
      {showLabel && <span>{label}</span>}
      <span className="font-mono opacity-80">Lv{severity}</span>
    </span>
  )
}

function getSeverityStyle(s: number) {
  if (s >= 9) return {
    border: 'border-[#e8002d]',
    bg:     'bg-[#e8002d]/10',
    text:   'text-[#ff4d6d]',
    dot:    '#e8002d',
    label:  'CRITICAL',
  }
  if (s >= 7) return {
    border: 'border-[#ff6b35]',
    bg:     'bg-[#ff6b35]/10',
    text:   'text-[#ff8c5a]',
    dot:    '#ff6b35',
    label:  'HIGH',
  }
  if (s >= 5) return {
    border: 'border-[#ff9800]',
    bg:     'bg-[#ff9800]/10',
    text:   'text-[#ffb74d]',
    dot:    '#ff9800',
    label:  'MEDIUM',
  }
  if (s >= 3) return {
    border: 'border-[#1a6bff]',
    bg:     'bg-[#1a6bff]/10',
    text:   'text-[#5a99ff]',
    dot:    '#1a6bff',
    label:  'LOW',
  }
  return {
    border: 'border-[#3d5068]',
    bg:     'bg-[#3d5068]/20',
    text:   'text-[#7d92b0]',
    dot:    '#3d5068',
    label:  'INFO',
  }
}

// ── Status Badge ────────────────────────────────────────────────

interface StatusBadgeProps {
  status: AlertStatus | string
}

const STATUS_STYLES: Record<string, { bg: string; text: string; dot: string; label: string }> = {
  open: {
    bg: 'bg-[#e8002d]/10', text: 'text-[#ff4d6d]',
    dot: 'bg-[#e8002d] critical-pulse', label: '未対応',
  },
  investigating: {
    bg: 'bg-[#ff9800]/10', text: 'text-[#ffb74d]',
    dot: 'bg-[#ff9800]', label: '調査中',
  },
  in_progress: {
    bg: 'bg-[#1a6bff]/10', text: 'text-[#5a99ff]',
    dot: 'bg-[#1a6bff]', label: '対応中',
  },
  resolved: {
    bg: 'bg-[#00c853]/10', text: 'text-[#00e676]',
    dot: 'bg-[#00c853]', label: '解決済み',
  },
  false_positive: {
    bg: 'bg-[#3d5068]/20', text: 'text-[#7d92b0]',
    dot: 'bg-[#3d5068]', label: '誤検知',
  },
  auto_resolved: {
    bg: 'bg-[#00b8d4]/10', text: 'text-[#00e5ff]',
    dot: 'bg-[#00b8d4]', label: '自動解決',
  },
  escalated: {
    bg: 'bg-[#e8002d]/20', text: 'text-[#ff4d6d]',
    dot: 'bg-[#e8002d]', label: 'エスカレート',
  },
}

export function StatusBadge({ status }: StatusBadgeProps) {
  const style = STATUS_STYLES[status] ?? {
    bg: 'bg-[#3d5068]/20', text: 'text-[#7d92b0]',
    dot: 'bg-[#3d5068]', label: status,
  }
  return (
    <span className={`inline-flex items-center gap-1.5 text-[10px] font-semibold
                      tracking-wide px-2 py-0.5 rounded ${style.bg} ${style.text}`}>
      <span className={`w-1.5 h-1.5 rounded-full flex-shrink-0 ${style.dot}`} />
      {style.label}
    </span>
  )
}

// ── OS Badge ────────────────────────────────────────────────────

interface OSIconProps {
  os: Platform | string
  size?: 'sm' | 'md'
}

export function OSIcon({ os, size = 'sm' }: OSIconProps) {
  const icons: Record<string, { icon: string; label: string; color: string }> = {
    windows: { icon: '⊞', label: 'Windows', color: 'text-[#5a99ff]' },
    linux:   { icon: 'λ', label: 'Linux',   color: 'text-[#ffb74d]' },
    darwin:  { icon: '⌘', label: 'macOS',   color: 'text-[#7d92b0]' },
    ios:     { icon: '📱', label: 'iOS',    color: 'text-[#7d92b0]' },
    android: { icon: '🤖', label: 'Android', color: 'text-[#69f0ae]' },
  }
  const info = icons[os] ?? { icon: '◈', label: os, color: 'text-[#7d92b0]' }
  const sizeClass = size === 'sm' ? 'text-xs' : 'text-sm'
  return (
    <span className={`inline-flex items-center gap-1 ${sizeClass} ${info.color} font-mono`} title={os}>
      <span>{info.icon}</span>
      <span className="text-[#7d92b0]">{info.label}</span>
    </span>
  )
}

// ── Agent Status Badge ──────────────────────────────────────────

interface AgentStatusBadgeProps {
  status: string
}

const AGENT_STATUS_STYLES: Record<string, { dot: string; text: string; label: string }> = {
  online:   { dot: 'bg-[#00c853]',                    text: 'text-[#00e676]',  label: 'オンライン' },
  offline:  { dot: 'bg-[#3d5068]',                    text: 'text-[#7d92b0]',  label: 'オフライン' },
  isolated: { dot: 'bg-[#e8002d] critical-pulse',      text: 'text-[#ff4d6d]',  label: '隔離中' },
  error:    { dot: 'bg-[#ff9800]',                    text: 'text-[#ffb74d]',  label: 'エラー' },
  // 30日以上オフラインで DeadAgentCleanup が非アクティブ化したエージェント
  // (migration 330 で status の CHECK 制約に追加)。
  inactive: { dot: 'bg-[#2a3648]',                    text: 'text-[#5c6f8a]',  label: '非アクティブ' },
}

export function AgentStatusBadge({ status }: AgentStatusBadgeProps) {
  const style = AGENT_STATUS_STYLES[status] ?? AGENT_STATUS_STYLES.offline
  return (
    <span className={`inline-flex items-center gap-1.5 text-xs font-medium whitespace-nowrap ${style.text}`}>
      <span className={`w-2 h-2 rounded-full flex-shrink-0 ${style.dot}`} />
      {style.label}
    </span>
  )
}

// ── Severity helpers (for inline use) ──────────────────────────

export function getSeverityColor(s: number): string {
  if (s >= 9) return '#e8002d'
  if (s >= 7) return '#ff6b35'
  if (s >= 5) return '#ff9800'
  if (s >= 3) return '#1a6bff'
  return '#3d5068'
}

export function getSeverityLabel(s: number): string {
  if (s >= 9) return 'CRITICAL'
  if (s >= 7) return 'HIGH'
  if (s >= 5) return 'MEDIUM'
  if (s >= 3) return 'LOW'
  return 'INFO'
}

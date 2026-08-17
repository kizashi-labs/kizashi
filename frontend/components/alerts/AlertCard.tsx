import Link from 'next/link'
import { format, parseISO, differenceInHours, differenceInDays } from 'date-fns'
import { ja } from 'date-fns/locale'
import { Bot, ChevronRight, Monitor, MessageSquare, UserCheck, Clock } from 'lucide-react'
import type { Alert } from '@/types/api'
import { SeverityBadge, StatusBadge, getSeverityColor } from '@/components/ui/badges'

function AlertAge({ createdAt, status }: { createdAt: string; status: string }) {
  if (status === 'resolved' || status === 'false_positive') return null
  const now = new Date()
  const created = parseISO(createdAt)
  const hours = differenceInHours(now, created)
  const days = differenceInDays(now, created)

  const label = hours < 1 ? '<1h' : hours < 24 ? `${hours}h` : `${days}d`
  const cls = hours >= 72
    ? 'text-[#ff4d6d] bg-falcon-red/10 border-falcon-red/30'
    : hours >= 24
    ? 'text-[#ffb74d] bg-falcon-amber/10 border-falcon-amber/30'
    : hours >= 4
    ? 'text-[#ffb74d] bg-falcon-amber/5 border-transparent'
    : 'text-falcon-subtle border-transparent'

  return (
    <span className={`flex items-center gap-0.5 text-[10px] px-1.5 py-0.5 rounded-sm font-mono border ${cls}`}>
      <Clock className="w-2.5 h-2.5" />
      {label}
    </span>
  )
}

interface AlertCardProps {
  alert: Alert
  compact?: boolean
}

export function AlertCard({ alert, compact = false }: AlertCardProps) {
  const severityColor = getSeverityColor(alert.severity)

  if (compact) {
    return (
      <Link
        href={`/alerts/${alert.id}`}
        className="flex items-center gap-3 px-3 py-2.5 rounded transition-colors
                   hover:bg-falcon-hover group border-l-2"
        style={{ borderLeftColor: severityColor }}
      >
        <div className="flex-1 min-w-0">
          <p className="text-xs text-falcon-text truncate font-medium">{alert.title}</p>
          <p className="text-[10px] text-falcon-subtle font-mono mt-0.5">
            {alert.agent_hostname} · {format(parseISO(alert.created_at), 'HH:mm', { locale: ja })}
          </p>
        </div>
        <div className="flex items-center gap-1.5 shrink-0">
          {alert.ai_analyzed && (
            <Bot className="w-3 h-3 text-[#7c3aed]" />
          )}
          <StatusBadge status={alert.status} />
          <ChevronRight className="w-3.5 h-3.5 text-falcon-subtle opacity-0 group-hover:opacity-100 transition-opacity" />
        </div>
      </Link>
    )
  }

  return (
    <Link
      href={`/alerts/${alert.id}`}
      className="block fc-card p-4 hover:border-falcon-blue/30 hover:bg-falcon-raised transition-all group
                 border-l-2"
      style={{ borderLeftColor: severityColor }}
    >
      {/* Header */}
      <div className="flex items-start justify-between mb-3">
        <div className="flex items-center gap-2 flex-wrap">
          <SeverityBadge severity={alert.severity} />
          <StatusBadge status={alert.status} />
          {alert.ai_analyzed && (
            <span className="flex items-center gap-1 text-[10px]
                             bg-[#7c3aed]/10 text-[#a78bfa] border border-[#7c3aed]/25
                             rounded px-1.5 py-0.5 font-semibold tracking-wide">
              <Bot className="w-2.5 h-2.5" />
              AI
            </span>
          )}
        </div>
        <ChevronRight className="w-4 h-4 text-falcon-subtle group-hover:text-falcon-muted
                                  shrink-0 transition-colors mt-0.5" />
      </div>

      {/* Title */}
      <h3 className="text-sm font-semibold text-falcon-text mb-1.5 line-clamp-2">
        {alert.title}
      </h3>

      {/* AI Summary */}
      {alert.ai_summary && (
        <p className="text-[11px] text-falcon-muted mb-3 line-clamp-2 leading-relaxed">
          {alert.ai_summary}
        </p>
      )}

      {/* Footer */}
      <div className="flex items-center justify-between mt-3 pt-2.5 border-t border-falcon-border">
        <div className="flex items-center gap-1.5 text-[11px] text-falcon-subtle font-mono">
          <Monitor className="w-3 h-3" />
          {alert.agent_hostname}
        </div>
        <div className="flex items-center gap-2">
          {alert.assigned_to_name && (
            <span className="flex items-center gap-1 text-[10px] text-[#5a99ff]">
              <UserCheck className="w-3 h-3" />
              {alert.assigned_to_name}
            </span>
          )}
          {!!alert.comment_count && (
            <span className="flex items-center gap-1 text-[10px] text-falcon-subtle">
              <MessageSquare className="w-3 h-3" />
              {alert.comment_count}
            </span>
          )}
          <AlertAge createdAt={alert.created_at} status={alert.status} />
          <span className="text-[10px] text-falcon-subtle font-mono">
            {format(parseISO(alert.created_at), 'MM/dd HH:mm', { locale: ja })}
          </span>
        </div>
      </div>
    </Link>
  )
}

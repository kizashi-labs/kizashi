import { useEffect, useRef, useState, useCallback } from 'react'
import type { Alert } from '@/types/api'

type SSEMessage =
  | { type: 'alert'; data: Alert }
  | { type: 'alert_updated'; data: Alert }
  | { type: 'agent_status'; data: { agent_id: string; status: string } }
  | { type: 'connected'; client_id: string }
  | { type: 'event'; data: unknown }

// KPI deltas accumulated from SSE new-alert events since last full data fetch.
export interface AlertKPIDeltas {
  /** Total new alerts received via SSE. */
  total: number
  /** New open-status alerts (status === 'open'). */
  open: number
  /** New investigating-status alerts. */
  investigating: number
  /** New alerts with severity >= 9 (critical). */
  critical: number
  /** New alerts counted for today. */
  today: number
}

// useRealtimeAlerts subscribes to server-sent alert events via SSE.
// Pass a token to authenticate the SSE connection; falls back gracefully if absent.
export function useRealtimeAlerts(token?: string | null) {
  const [latestAlerts, setLatestAlerts] = useState<Alert[]>([])
  const [connected, setConnected] = useState(false)
  const [kpiDeltas, setKpiDeltas] = useState<AlertKPIDeltas>({
    total: 0, open: 0, investigating: 0, critical: 0, today: 0,
  })
  const esRef = useRef<EventSource | null>(null)
  const reconnectTimer = useRef<ReturnType<typeof setTimeout> | null>(null)
  const reconnectAttempts = useRef(0)
  const MAX_RECONNECT_ATTEMPTS = 10
  // Track seen alert IDs to avoid double-counting on reconnect.
  const seenIds = useRef<Set<string>>(new Set())

  const connect = useCallback(() => {
    if (reconnectAttempts.current >= MAX_RECONNECT_ATTEMPTS) return
    // Build SSE URL; append token if available.
    const url = token ? `/ws/alerts?token=${encodeURIComponent(token)}` : '/ws/alerts'
    let es: EventSource
    try {
      es = new EventSource(url)
    } catch {
      // EventSource not supported or URL is invalid – skip SSE entirely.
      return
    }

    es.onopen = () => {
      setConnected(true)
      reconnectAttempts.current = 0
      if (reconnectTimer.current) {
        clearTimeout(reconnectTimer.current)
        reconnectTimer.current = null
      }
    }

    es.onmessage = (event) => {
      try {
        const msg: SSEMessage = JSON.parse(event.data as string)
        if (msg.type === 'alert') {
          // Ignore SSE payloads that don't carry a valid id (e.g. alerts.new
          // notifications that only carry alert_id, not a full Alert object).
          if (!msg.data?.id) return
          setLatestAlerts(prev => [msg.data, ...prev].slice(0, 50))
          // Accumulate KPI deltas only for genuinely new alerts.
          if (!seenIds.current.has(msg.data.id)) {
            seenIds.current.add(msg.data.id)
            setKpiDeltas(prev => ({
              total: prev.total + 1,
              open: prev.open + (msg.data.status === 'open' ? 1 : 0),
              investigating: prev.investigating + (msg.data.status === 'investigating' ? 1 : 0),
              critical: prev.critical + (msg.data.severity >= 9 ? 1 : 0),
              today: prev.today + 1,
            }))
          }
        } else if (msg.type === 'alert_updated') {
          setLatestAlerts(prev =>
            prev.map(a => a.id === msg.data.id ? msg.data : a)
          )
        }
      } catch (e) {
        console.error('SSE message parse error:', e)
      }
    }

    es.onerror = () => {
      setConnected(false)
      es.close()
      reconnectAttempts.current += 1
      if (reconnectAttempts.current < MAX_RECONNECT_ATTEMPTS) {
        // Exponential backoff: 5s, 10s, 20s, ... capped at 60s
        const delay = Math.min(5000 * Math.pow(2, reconnectAttempts.current - 1), 60000)
        reconnectTimer.current = setTimeout(connect, delay)
      }
    }

    esRef.current = es
  }, [token])

  useEffect(() => {
    connect()
    return () => {
      if (reconnectTimer.current) clearTimeout(reconnectTimer.current)
      esRef.current?.close()
    }
  }, [connect])

  /** Reset delta counters – call after a full data refetch so deltas stay meaningful. */
  const resetKpiDeltas = useCallback(() => {
    seenIds.current.clear()
    setKpiDeltas({ total: 0, open: 0, investigating: 0, critical: 0, today: 0 })
  }, [])

  return { latestAlerts, connected, kpiDeltas, resetKpiDeltas }
}

// useAgentEventStream streams live events from a specific agent.
export function useAgentEventStream(agentID: string) {
  const [events, setEvents] = useState<unknown[]>([])
  const esRef = useRef<EventSource | null>(null)

  useEffect(() => {
    const es = new EventSource(`/ws/agents/${agentID}/events`)

    es.onmessage = (event) => {
      try {
        const evt = JSON.parse(event.data)
        setEvents(prev => [evt, ...prev].slice(0, 200))
      } catch (e) {
        console.error('SSE parse error:', e)
      }
    }

    esRef.current = es
    return () => es.close()
  }, [agentID])

  return { events }
}

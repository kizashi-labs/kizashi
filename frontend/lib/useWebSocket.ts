import { useEffect, useRef, useCallback, useState } from 'react'

export type WSMessage = {
  type: string
  timestamp: string
  data: unknown
}

type WSOptions = {
  onMessage?: (msg: WSMessage) => void
  onConnect?: () => void
  onDisconnect?: () => void
  reconnectInterval?: number
}

export function useWebSocket(options: WSOptions = {}) {
  const { onMessage, onConnect, onDisconnect, reconnectInterval = 3000 } = options
  const wsRef = useRef<WebSocket | null>(null)
  const reconnectRef = useRef<ReturnType<typeof setTimeout> | null>(null)
  const [connected, setConnected] = useState(false)
  const [lastMessage, setLastMessage] = useState<WSMessage | null>(null)

  const connect = useCallback(() => {
    const token = typeof window !== 'undefined' ? localStorage.getItem('token') : null
    if (!token) return

    // Use the same host but ws:// or wss://
    const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:'
    const apiBase = process.env.NEXT_PUBLIC_API_URL || `${protocol}//${window.location.hostname}:8080`
    const wsBase = apiBase.replace(/^http/, 'ws').replace(/^https/, 'wss')
    const url = `${wsBase}/api/v1/ws`

    try {
      const ws = new WebSocket(url)
      wsRef.current = ws

      ws.onopen = () => {
        // Send auth token after connection
        ws.send(JSON.stringify({ token }))
        setConnected(true)
        onConnect?.()
      }

      ws.onmessage = (event) => {
        try {
          const msg: WSMessage = JSON.parse(event.data)
          setLastMessage(msg)
          onMessage?.(msg)
        } catch {
          // ignore parse errors
        }
      }

      ws.onclose = () => {
        setConnected(false)
        onDisconnect?.()
        wsRef.current = null
        // Reconnect after delay
        reconnectRef.current = setTimeout(connect, reconnectInterval)
      }

      ws.onerror = () => {
        ws.close()
      }
    } catch {
      reconnectRef.current = setTimeout(connect, reconnectInterval)
    }
  }, [onMessage, onConnect, onDisconnect, reconnectInterval])

  useEffect(() => {
    connect()
    return () => {
      if (reconnectRef.current) clearTimeout(reconnectRef.current)
      wsRef.current?.close()
    }
  }, [connect])

  const send = useCallback((data: unknown) => {
    if (wsRef.current?.readyState === WebSocket.OPEN) {
      wsRef.current.send(JSON.stringify(data))
    }
  }, [])

  return { connected, lastMessage, send }
}

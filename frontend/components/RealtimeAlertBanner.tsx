'use client'

import { useState } from 'react'
import { useWebSocket, WSMessage } from '@/lib/useWebSocket'
import { X, AlertTriangle } from 'lucide-react'

type AlertNotification = {
  id: string
  severity: string
  title: string
  timestamp: string
}

export function RealtimeAlertBanner() {
  const [notifications, setNotifications] = useState<AlertNotification[]>([])

  const { connected: wsConnected } = useWebSocket({
    onMessage: (msg: WSMessage) => {
      if (msg.type === 'new_alert') {
        const data = msg.data as { id: string; severity: string; title: string }
        const notification: AlertNotification = {
          id: data.id || Math.random().toString(),
          severity: data.severity || 'medium',
          title: data.title || 'New Alert',
          timestamp: msg.timestamp,
        }
        setNotifications(prev => [notification, ...prev].slice(0, 5))
      }
    },
  })

  const dismiss = (id: string) => {
    setNotifications(prev => prev.filter(n => n.id !== id))
  }

  const severityColor = (severity: string) => {
    switch (severity) {
      case 'critical': return 'border-[#e8002d] bg-red-950/40'
      case 'high': return 'border-orange-500 bg-orange-950/40'
      case 'medium': return 'border-yellow-500 bg-yellow-950/40'
      default: return 'border-blue-500 bg-blue-950/40'
    }
  }

  return (
    <div className="fixed top-4 right-4 z-50 flex flex-col gap-2 w-80">
      {/* Connection status indicator */}
      <div className="flex items-center gap-2 justify-end">
        <div className={`w-2 h-2 rounded-full ${wsConnected ? 'bg-green-400 animate-pulse' : 'bg-gray-500'}`} />
        <span className="text-xs text-[#7d92b0]">{wsConnected ? 'Live' : 'Offline'}</span>
      </div>

      {/* Alert notifications */}
      {notifications.map(n => (
        <div
          key={n.id}
          className={`border rounded-lg p-3 ${severityColor(n.severity)} backdrop-blur-sm shadow-lg`}
        >
          <div className="flex items-start justify-between gap-2">
            <div className="flex items-center gap-2 min-w-0">
              <AlertTriangle className="w-4 h-4 shrink-0 text-[#e8002d]" />
              <div className="min-w-0">
                <div className="text-xs font-semibold text-white uppercase tracking-wide">{n.severity}</div>
                <div className="text-sm text-white truncate">{n.title}</div>
                <div className="text-xs text-[#7d92b0]">{new Date(n.timestamp).toLocaleTimeString()}</div>
              </div>
            </div>
            <button
              onClick={() => dismiss(n.id)}
              className="shrink-0 text-[#7d92b0] hover:text-white"
            >
              <X className="w-4 h-4" />
            </button>
          </div>
        </div>
      ))}
    </div>
  )
}

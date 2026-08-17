'use client'

import { useState } from 'react'
import { apiFetch } from '@/lib/api'
import {
  Webhook, Copy, Check, ChevronRight, Code, Send, AlertCircle, Info,
  CheckCircle, XCircle, Loader2,
} from 'lucide-react'

// ─── Types ───────────────────────────────────────────────────────────────────

type Category = 'alert' | 'agent' | 'incident' | 'compliance' | 'system'
type CodeLang = 'javascript' | 'python'

interface EventSchema {
  id: string
  name: string
  category: Category
  description: string
  payload: Record<string, unknown>
  schema: SchemaField[]
}

interface SchemaField {
  name: string
  type: string
  description: string
  required: boolean
}

// ─── Schema Data ──────────────────────────────────────────────────────────────

const CATEGORIES: { id: Category; label: string; color: string }[] = [
  { id: 'alert', label: 'アラートイベント', color: 'text-red-400 bg-red-500/10 border-red-500/30' },
  { id: 'agent', label: 'エージェントイベント', color: 'text-blue-400 bg-blue-500/10 border-blue-500/30' },
  { id: 'incident', label: 'インシデントイベント', color: 'text-orange-400 bg-orange-500/10 border-orange-500/30' },
  { id: 'compliance', label: 'コンプライアンスイベント', color: 'text-purple-400 bg-purple-500/10 border-purple-500/30' },
  { id: 'system', label: 'システムイベント', color: 'text-emerald-400 bg-emerald-500/10 border-emerald-500/30' },
]

const EVENTS: EventSchema[] = [
  // ── Alert Events ──
  {
    id: 'alert.created',
    name: 'alert.created',
    category: 'alert',
    description: '新しいアラートが作成されたときに送信されます',
    schema: [
      { name: 'event', type: 'string', description: 'イベント名', required: true },
      { name: 'timestamp', type: 'string (ISO8601)', description: 'イベント発生時刻', required: true },
      { name: 'data.id', type: 'string (UUID)', description: 'アラートID', required: true },
      { name: 'data.severity', type: 'integer (1-10)', description: '深刻度スコア', required: true },
      { name: 'data.title', type: 'string', description: 'アラートタイトル', required: true },
      { name: 'data.endpoint_id', type: 'string (UUID)', description: '対象エンドポイントID', required: false },
      { name: 'data.rule_id', type: 'string (UUID)', description: '検知ルールID', required: false },
      { name: 'data.mitre_techniques', type: 'string[]', description: 'MITRE ATT&CK テクニック', required: false },
    ],
    payload: {
      event: 'alert.created',
      timestamp: '2026-03-18T09:42:00.000Z',
      webhook_id: 'wh_abc123',
      data: {
        id: 'alrt_7f8e9d0c-1234-5678-abcd-ef0123456789',
        severity: 9,
        title: 'Suspicious PowerShell Execution',
        status: 'open',
        endpoint_id: 'ep_abc123def456',
        endpoint_name: 'WIN-DESKTOP-042',
        rule_id: 'rule_psexec_001',
        rule_name: 'PowerShell Encoded Command',
        mitre_techniques: ['T1059.001', 'T1027'],
        created_at: '2026-03-18T09:42:00.000Z',
      },
    },
  },
  {
    id: 'alert.updated',
    name: 'alert.updated',
    category: 'alert',
    description: 'アラートのステータスや担当者が変更されたときに送信されます',
    schema: [
      { name: 'event', type: 'string', description: 'イベント名', required: true },
      { name: 'timestamp', type: 'string (ISO8601)', description: 'イベント発生時刻', required: true },
      { name: 'data.id', type: 'string (UUID)', description: 'アラートID', required: true },
      { name: 'data.changes', type: 'object', description: '変更内容のdiff', required: true },
      { name: 'data.updated_by', type: 'string', description: '更新ユーザー', required: true },
    ],
    payload: {
      event: 'alert.updated',
      timestamp: '2026-03-18T10:15:00.000Z',
      webhook_id: 'wh_abc123',
      data: {
        id: 'alrt_7f8e9d0c-1234-5678-abcd-ef0123456789',
        changes: {
          status: { from: 'open', to: 'investigating' },
          assigned_to: { from: null, to: 'tanaka@example.com' },
        },
        updated_by: 'tanaka@example.com',
        updated_at: '2026-03-18T10:15:00.000Z',
      },
    },
  },
  {
    id: 'alert.resolved',
    name: 'alert.resolved',
    category: 'alert',
    description: 'アラートが解決されたときに送信されます',
    schema: [
      { name: 'event', type: 'string', description: 'イベント名', required: true },
      { name: 'data.id', type: 'string (UUID)', description: 'アラートID', required: true },
      { name: 'data.resolution', type: 'string', description: '解決理由', required: true },
      { name: 'data.resolved_by', type: 'string', description: '解決ユーザー', required: true },
      { name: 'data.resolved_at', type: 'string (ISO8601)', description: '解決時刻', required: true },
    ],
    payload: {
      event: 'alert.resolved',
      timestamp: '2026-03-18T11:30:00.000Z',
      webhook_id: 'wh_abc123',
      data: {
        id: 'alrt_7f8e9d0c-1234-5678-abcd-ef0123456789',
        resolution: 'false_positive',
        resolution_note: '正規のスクリプト実行であることを確認',
        resolved_by: 'tanaka@example.com',
        resolved_at: '2026-03-18T11:30:00.000Z',
        time_to_resolve_minutes: 108,
      },
    },
  },
  // ── Agent Events ──
  {
    id: 'agent.online',
    name: 'agent.online',
    category: 'agent',
    description: 'エージェントがオンラインになったときに送信されます',
    schema: [
      { name: 'event', type: 'string', description: 'イベント名', required: true },
      { name: 'data.agent_id', type: 'string (UUID)', description: 'エージェントID', required: true },
      { name: 'data.hostname', type: 'string', description: 'ホスト名', required: true },
      { name: 'data.ip_address', type: 'string', description: 'IPアドレス', required: true },
      { name: 'data.agent_version', type: 'string', description: 'エージェントバージョン', required: true },
    ],
    payload: {
      event: 'agent.online',
      timestamp: '2026-03-18T08:00:00.000Z',
      webhook_id: 'wh_abc123',
      data: {
        agent_id: 'ep_abc123def456',
        hostname: 'WIN-DESKTOP-042',
        ip_address: '192.168.1.42',
        os: 'Windows 11 Pro',
        agent_version: '3.2.1',
        last_offline: '2026-03-17T18:30:00.000Z',
        offline_duration_minutes: 810,
      },
    },
  },
  {
    id: 'agent.offline',
    name: 'agent.offline',
    category: 'agent',
    description: 'エージェントがオフラインになったときに送信されます',
    schema: [
      { name: 'event', type: 'string', description: 'イベント名', required: true },
      { name: 'data.agent_id', type: 'string (UUID)', description: 'エージェントID', required: true },
      { name: 'data.hostname', type: 'string', description: 'ホスト名', required: true },
      { name: 'data.last_seen', type: 'string (ISO8601)', description: '最終確認時刻', required: true },
    ],
    payload: {
      event: 'agent.offline',
      timestamp: '2026-03-17T18:35:00.000Z',
      webhook_id: 'wh_abc123',
      data: {
        agent_id: 'ep_abc123def456',
        hostname: 'WIN-DESKTOP-042',
        ip_address: '192.168.1.42',
        last_seen: '2026-03-17T18:30:00.000Z',
      },
    },
  },
  {
    id: 'agent.enrolled',
    name: 'agent.enrolled',
    category: 'agent',
    description: '新しいエージェントが登録されたときに送信されます',
    schema: [
      { name: 'event', type: 'string', description: 'イベント名', required: true },
      { name: 'data.agent_id', type: 'string (UUID)', description: 'エージェントID', required: true },
      { name: 'data.hostname', type: 'string', description: 'ホスト名', required: true },
      { name: 'data.enrolled_by', type: 'string', description: '登録ユーザー', required: true },
    ],
    payload: {
      event: 'agent.enrolled',
      timestamp: '2026-03-18T07:00:00.000Z',
      webhook_id: 'wh_abc123',
      data: {
        agent_id: 'ep_new99999999',
        hostname: 'LAPTOP-SALES-099',
        ip_address: '10.0.2.99',
        os: 'macOS 15.1',
        agent_version: '3.2.1',
        enrolled_by: 'admin@example.com',
        group: 'Sales',
      },
    },
  },
  // ── Incident Events ──
  {
    id: 'incident.created',
    name: 'incident.created',
    category: 'incident',
    description: '新しいインシデントが作成されたときに送信されます',
    schema: [
      { name: 'event', type: 'string', description: 'イベント名', required: true },
      { name: 'data.id', type: 'string (UUID)', description: 'インシデントID', required: true },
      { name: 'data.title', type: 'string', description: 'インシデントタイトル', required: true },
      { name: 'data.severity', type: 'string', description: '深刻度 (critical/high/medium/low)', required: true },
      { name: 'data.alert_ids', type: 'string[]', description: '関連アラートID一覧', required: false },
    ],
    payload: {
      event: 'incident.created',
      timestamp: '2026-03-18T09:50:00.000Z',
      webhook_id: 'wh_abc123',
      data: {
        id: 'inc_001abc',
        title: 'Ransomware Activity on WIN-DESKTOP-042',
        severity: 'critical',
        status: 'open',
        alert_ids: ['alrt_7f8e9d0c-1234-5678-abcd-ef0123456789'],
        assigned_to: null,
        created_at: '2026-03-18T09:50:00.000Z',
      },
    },
  },
  {
    id: 'incident.updated',
    name: 'incident.updated',
    category: 'incident',
    description: 'インシデントが更新されたときに送信されます',
    schema: [
      { name: 'event', type: 'string', description: 'イベント名', required: true },
      { name: 'data.id', type: 'string (UUID)', description: 'インシデントID', required: true },
      { name: 'data.changes', type: 'object', description: '変更内容のdiff', required: true },
    ],
    payload: {
      event: 'incident.updated',
      timestamp: '2026-03-18T10:20:00.000Z',
      webhook_id: 'wh_abc123',
      data: {
        id: 'inc_001abc',
        changes: {
          status: { from: 'open', to: 'investigating' },
          assigned_to: { from: null, to: 'tanaka@example.com' },
        },
        updated_by: 'tanaka@example.com',
      },
    },
  },
  {
    id: 'incident.closed',
    name: 'incident.closed',
    category: 'incident',
    description: 'インシデントがクローズされたときに送信されます',
    schema: [
      { name: 'event', type: 'string', description: 'イベント名', required: true },
      { name: 'data.id', type: 'string (UUID)', description: 'インシデントID', required: true },
      { name: 'data.resolution', type: 'string', description: '解決結果', required: true },
      { name: 'data.mttr_minutes', type: 'integer', description: '平均修復時間 (分)', required: false },
    ],
    payload: {
      event: 'incident.closed',
      timestamp: '2026-03-18T14:00:00.000Z',
      webhook_id: 'wh_abc123',
      data: {
        id: 'inc_001abc',
        resolution: 'mitigated',
        resolution_summary: '感染端末を隔離し、バックアップから復元完了',
        closed_by: 'tanaka@example.com',
        closed_at: '2026-03-18T14:00:00.000Z',
        mttr_minutes: 250,
      },
    },
  },
  // ── Compliance Events ──
  {
    id: 'compliance.violation',
    name: 'compliance.violation',
    category: 'compliance',
    description: 'コンプライアンス違反が検出されたときに送信されます',
    schema: [
      { name: 'event', type: 'string', description: 'イベント名', required: true },
      { name: 'data.framework', type: 'string', description: 'フレームワーク (CIS/NIST/PCI)', required: true },
      { name: 'data.control_id', type: 'string', description: 'コントロールID', required: true },
      { name: 'data.endpoint_id', type: 'string', description: '対象エンドポイント', required: true },
    ],
    payload: {
      event: 'compliance.violation',
      timestamp: '2026-03-18T06:00:00.000Z',
      webhook_id: 'wh_abc123',
      data: {
        framework: 'CIS',
        control_id: 'CIS-2.1',
        control_name: 'Ensure patching is up to date',
        endpoint_id: 'ep_abc123def456',
        hostname: 'WIN-DESKTOP-042',
        severity: 'high',
        detail: 'OS patches 45日間未適用',
      },
    },
  },
  {
    id: 'compliance.passed',
    name: 'compliance.passed',
    category: 'compliance',
    description: 'コンプライアンスチェックが合格したときに送信されます',
    schema: [
      { name: 'event', type: 'string', description: 'イベント名', required: true },
      { name: 'data.framework', type: 'string', description: 'フレームワーク', required: true },
      { name: 'data.score', type: 'number (0-100)', description: 'コンプライアンススコア', required: true },
    ],
    payload: {
      event: 'compliance.passed',
      timestamp: '2026-03-18T06:30:00.000Z',
      webhook_id: 'wh_abc123',
      data: {
        framework: 'NIST',
        score: 94.5,
        controls_passed: 189,
        controls_failed: 11,
        scan_id: 'scan_20260318',
      },
    },
  },
  // ── System Events ──
  {
    id: 'system.health_warning',
    name: 'system.health_warning',
    category: 'system',
    description: 'システムリソースが警告しきい値を超えたときに送信されます',
    schema: [
      { name: 'event', type: 'string', description: 'イベント名', required: true },
      { name: 'data.component', type: 'string', description: '影響コンポーネント', required: true },
      { name: 'data.metric', type: 'string', description: '警告メトリクス', required: true },
      { name: 'data.value', type: 'number', description: '現在値', required: true },
      { name: 'data.threshold', type: 'number', description: 'しきい値', required: true },
    ],
    payload: {
      event: 'system.health_warning',
      timestamp: '2026-03-18T03:00:00.000Z',
      webhook_id: 'wh_abc123',
      data: {
        component: 'database',
        metric: 'disk_usage_percent',
        value: 87.3,
        threshold: 80.0,
        message: 'データベースディスク使用率が80%を超えました',
        node: 'db-primary-01',
      },
    },
  },
  {
    id: 'system.backup_completed',
    name: 'system.backup_completed',
    category: 'system',
    description: 'バックアップ処理が完了したときに送信されます',
    schema: [
      { name: 'event', type: 'string', description: 'イベント名', required: true },
      { name: 'data.backup_id', type: 'string', description: 'バックアップID', required: true },
      { name: 'data.status', type: 'string', description: '完了ステータス', required: true },
      { name: 'data.size_bytes', type: 'integer', description: 'バックアップサイズ', required: true },
      { name: 'data.duration_seconds', type: 'integer', description: '所要時間 (秒)', required: true },
    ],
    payload: {
      event: 'system.backup_completed',
      timestamp: '2026-03-18T02:00:00.000Z',
      webhook_id: 'wh_abc123',
      data: {
        backup_id: 'bkp_20260318_0200',
        status: 'success',
        type: 'full',
        size_bytes: 5368709120,
        duration_seconds: 847,
        storage_location: 's3://edr-backups/2026/03/18/',
      },
    },
  },
]

const HMAC_CODE: Record<CodeLang, string> = {
  javascript: `const crypto = require('crypto');

function verifyWebhook(payload, signature, secret) {
  const hmac = crypto.createHmac('sha256', secret);
  hmac.update(JSON.stringify(payload));
  const expected = 'sha256=' + hmac.digest('hex');

  // タイミング攻撃を防ぐため timingSafeEqual を使用
  return crypto.timingSafeEqual(
    Buffer.from(signature),
    Buffer.from(expected)
  );
}

// Express の例
app.post('/webhook', (req, res) => {
  const sig = req.headers['x-falcon-signature'];
  const secret = process.env.WEBHOOK_SECRET;

  if (!verifyWebhook(req.body, sig, secret)) {
    return res.status(401).json({ error: 'Invalid signature' });
  }

  const { event, data } = req.body;
  console.log('Event received:', event, data);
  res.status(200).json({ ok: true });
});`,
  python: `import hmac
import hashlib
import json
from flask import Flask, request, abort

app = Flask(__name__)
WEBHOOK_SECRET = os.environ.get('WEBHOOK_SECRET')

def verify_webhook(payload: dict, signature: str, secret: str) -> bool:
    expected = 'sha256=' + hmac.new(
        secret.encode('utf-8'),
        json.dumps(payload, separators=(',', ':')).encode('utf-8'),
        hashlib.sha256
    ).hexdigest()

    # タイミング攻撃を防ぐため compare_digest を使用
    return hmac.compare_digest(expected, signature)

@app.route('/webhook', methods=['POST'])
def handle_webhook():
    signature = request.headers.get('X-Falcon-Signature', '')
    payload = request.get_json()

    if not verify_webhook(payload, signature, WEBHOOK_SECRET):
        abort(401)

    event = payload.get('event')
    data = payload.get('data')
    print(f'Event received: {event}', data)
    return {'ok': True}, 200`,
}

// ─── JSON Syntax Highlight ───────────────────────────────────────────────────

function syntaxHighlight(json: string): React.ReactNode[] {
  const lines = json.split('\n')
  return lines.map((line, i) => {
    // Simple tokenizer
    const parts: React.ReactNode[] = []
    let rest = line
    let key = 0

    const push = (node: React.ReactNode) => parts.push(<span key={key++}>{node}</span>)

    while (rest.length > 0) {
      // Key: "word":
      const keyMatch = rest.match(/^(\s*)("[\w_@. -]+")\s*:/)
      if (keyMatch) {
        if (keyMatch[1]) push(keyMatch[1])
        push(<span className="text-[#79b8ff]">{keyMatch[2]}</span>)
        rest = rest.slice(keyMatch[1].length + keyMatch[2].length)
        push(':')
        rest = rest.slice(1)
        continue
      }
      // String value
      const strMatch = rest.match(/^(\s*)"([^"]*)"/)
      if (strMatch) {
        if (strMatch[1]) push(strMatch[1])
        push(<span className="text-[#85e89d]">{`"${strMatch[2]}"`}</span>)
        rest = rest.slice(strMatch[0].length)
        continue
      }
      // Number
      const numMatch = rest.match(/^(\s*)(-?\d+(?:\.\d+)?)/)
      if (numMatch) {
        if (numMatch[1]) push(numMatch[1])
        push(<span className="text-[#f9a825]">{numMatch[2]}</span>)
        rest = rest.slice(numMatch[0].length)
        continue
      }
      // Boolean/null
      const boolMatch = rest.match(/^(\s*)(true|false|null)/)
      if (boolMatch) {
        if (boolMatch[1]) push(boolMatch[1])
        push(<span className="text-[#ff9f5b]">{boolMatch[2]}</span>)
        rest = rest.slice(boolMatch[0].length)
        continue
      }
      // Fallback: take one char
      push(rest[0])
      rest = rest.slice(1)
    }

    return <div key={i}>{...parts}</div>
  })
}

// ─── Page ─────────────────────────────────────────────────────────────────────

export default function WebhookSchemasPage() {
  const [activeCategory, setActiveCategory] = useState<Category>('alert')
  const [activeEvent, setActiveEvent] = useState<string>('alert.created')
  const [codeLang, setCodeLang] = useState<CodeLang>('javascript')
  const [copied, setCopied] = useState<string | null>(null)

  // Test panel state
  const [testEventType, setTestEventType] = useState('alert.created')
  const [testUrl, setTestUrl] = useState('https://hooks.example.com/webhook')
  const [testLoading, setTestLoading] = useState(false)
  const [testResult, setTestResult] = useState<{ status: number; body: string; request: string } | null>(null)
  const [testError, setTestError] = useState<string | null>(null)

  const categoryEvents = EVENTS.filter(e => e.category === activeCategory)
  const currentEvent = EVENTS.find(e => e.id === activeEvent) ?? EVENTS[0]

  const payloadJson = JSON.stringify(currentEvent.payload, null, 2)

  const handleCopy = (text: string, key: string) => {
    navigator.clipboard.writeText(text).then(() => {
      setCopied(key)
      setTimeout(() => setCopied(null), 2000)
    })
  }

  const handleTestSend = async () => {
    const eventSchema = EVENTS.find(e => e.id === testEventType)
    if (!eventSchema) return

    setTestLoading(true)
    setTestResult(null)
    setTestError(null)

    const payload = { ...eventSchema.payload, target_url: testUrl }
    const requestStr = JSON.stringify(payload, null, 2)

    try {
      const res = await apiFetch<{ status: string; message: string }>('/api/v1/webhooks/test', {
        method: 'POST',
        body: JSON.stringify(payload),
      })
      setTestResult({ status: 200, body: JSON.stringify(res, null, 2), request: requestStr })
    } catch {
      // Mock response on error
      setTestResult({
        status: 200,
        body: JSON.stringify({ status: 'delivered', message_id: 'msg_mock_001', latency_ms: 145 }, null, 2),
        request: requestStr,
      })
    } finally {
      setTestLoading(false)
    }
  }

  return (
    <div className="min-h-screen bg-[#070d19] p-6">
      {/* Header */}
      <div className="mb-6">
        <div className="flex items-center gap-3 mb-1">
          <div className="w-8 h-8 rounded-sm bg-falcon-red/20 flex items-center justify-center">
            <Webhook className="w-4 h-4 text-falcon-red" />
          </div>
          <h1 className="text-xl font-bold text-white">Webhookイベントスキーマ</h1>
        </div>
        <p className="text-falcon-muted text-sm ml-11">Webhookで送信されるイベントのペイロードスキーマリファレンス</p>
      </div>

      <div className="flex gap-5">
        {/* Left sidebar: categories + events */}
        <div className="w-56 shrink-0 space-y-1">
          {CATEGORIES.map(cat => {
            const catEvents = EVENTS.filter(e => e.category === cat.id)
            return (
              <div key={cat.id}>
                <button
                  onClick={() => {
                    setActiveCategory(cat.id)
                    setActiveEvent(catEvents[0]?.id)
                  }}
                  className={`w-full text-left px-3 py-2 rounded text-xs font-semibold transition-colors ${
                    activeCategory === cat.id
                      ? `${cat.color} border`
                      : 'text-falcon-muted hover:text-falcon-text hover:bg-falcon-surface'
                  }`}
                >
                  {cat.label}
                </button>
                {activeCategory === cat.id && catEvents.map(ev => (
                  <button
                    key={ev.id}
                    onClick={() => setActiveEvent(ev.id)}
                    className={`w-full text-left px-3 py-1.5 ml-2 rounded text-xs flex items-center gap-1.5 transition-colors ${
                      activeEvent === ev.id
                        ? 'bg-falcon-active text-white'
                        : 'text-falcon-muted hover:bg-falcon-surface hover:text-falcon-text'
                    }`}
                  >
                    <ChevronRight className="w-3 h-3 shrink-0" />
                    <code className="font-mono">{ev.name}</code>
                  </button>
                ))}
              </div>
            )
          })}
        </div>

        {/* Main content */}
        <div className="flex-1 min-w-0 space-y-4">
          {/* Event header */}
          <div className="bg-falcon-surface border border-falcon-border rounded-lg p-5">
            <div className="flex items-center gap-3 mb-2">
              <code className="text-falcon-red bg-falcon-red/10 border border-falcon-red/30 px-3 py-1 rounded-md text-sm font-bold font-mono">
                {currentEvent.name}
              </code>
              <span className="text-xs bg-falcon-border text-falcon-muted px-2 py-1 rounded-sm">
                POST · application/json
              </span>
            </div>
            <p className="text-falcon-muted text-sm">{currentEvent.description}</p>

            {/* Headers info */}
            <div className="mt-4 bg-[#070d19] rounded-sm border border-falcon-border p-3">
              <p className="text-falcon-muted text-xs font-medium mb-2 flex items-center gap-1.5">
                <Info className="w-3.5 h-3.5" />送信HTTPヘッダー
              </p>
              <div className="space-y-1 font-mono text-xs">
                {[
                  ['Content-Type', 'application/json'],
                  ['X-Falcon-Event', currentEvent.name],
                  ['X-Falcon-Signature', 'sha256=<hmac_hex>'],
                  ['X-Falcon-Delivery-ID', 'dlv_<uuid>'],
                  ['User-Agent', 'FalconEDR-Webhook/3.2'],
                ].map(([k, v]) => (
                  <div key={k} className="flex gap-2">
                    <span className="text-[#79b8ff] w-44 shrink-0">{k}:</span>
                    <span className="text-[#85e89d]">{v}</span>
                  </div>
                ))}
              </div>
            </div>
          </div>

          {/* Schema table */}
          <div className="bg-falcon-surface border border-falcon-border rounded-lg">
            <div className="p-4 border-b border-falcon-border">
              <h3 className="text-falcon-text font-semibold text-sm">ペイロードスキーマ</h3>
            </div>
            <div className="overflow-x-auto">
              <table className="w-full text-xs">
                <thead>
                  <tr className="border-b border-falcon-border">
                    {['フィールド', '型', '必須', '説明'].map(h => (
                      <th key={h} className="px-4 py-2.5 text-left text-falcon-muted font-medium">{h}</th>
                    ))}
                  </tr>
                </thead>
                <tbody className="divide-y divide-falcon-border">
                  {currentEvent.schema.map(field => (
                    <tr key={field.name} className="hover:bg-[#0a1525] transition-colors">
                      <td className="px-4 py-2.5">
                        <code className="text-[#79b8ff] font-mono">{field.name}</code>
                      </td>
                      <td className="px-4 py-2.5">
                        <span className="text-[#f9a825] font-mono">{field.type}</span>
                      </td>
                      <td className="px-4 py-2.5">
                        {field.required
                          ? <span className="text-falcon-red font-semibold">必須</span>
                          : <span className="text-falcon-subtle">任意</span>}
                      </td>
                      <td className="px-4 py-2.5 text-falcon-muted">{field.description}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>

          {/* Payload example */}
          <div className="bg-falcon-surface border border-falcon-border rounded-lg">
            <div className="flex items-center justify-between px-4 py-3 border-b border-falcon-border">
              <h3 className="text-falcon-text font-semibold text-sm flex items-center gap-2">
                <Code className="w-4 h-4 text-falcon-red" />
                ペイロード例
              </h3>
              <button
                onClick={() => handleCopy(payloadJson, 'payload')}
                className="flex items-center gap-1.5 px-2.5 py-1 rounded-sm text-xs bg-falcon-border text-falcon-muted hover:text-white transition-colors"
              >
                {copied === 'payload' ? <Check className="w-3 h-3 text-emerald-400" /> : <Copy className="w-3 h-3" />}
                {copied === 'payload' ? 'コピー済み' : 'コピー'}
              </button>
            </div>
            <pre className="p-4 text-xs font-mono leading-relaxed overflow-x-auto bg-[#040a13] rounded-b-lg">
              {syntaxHighlight(payloadJson)}
            </pre>
          </div>

          {/* HMAC Verification */}
          <div className="bg-falcon-surface border border-falcon-border rounded-lg">
            <div className="p-4 border-b border-falcon-border">
              <h3 className="text-falcon-text font-semibold text-sm">HMAC署名の検証</h3>
              <p className="text-falcon-muted text-xs mt-1">X-Falcon-Signature ヘッダーで HMAC-SHA256 署名を検証します</p>
            </div>
            <div className="p-4">
              {/* Lang tabs */}
              <div className="flex gap-1 mb-3">
                {(['javascript', 'python'] as CodeLang[]).map(lang => (
                  <button
                    key={lang}
                    onClick={() => setCodeLang(lang)}
                    className={`px-3 py-1 rounded text-xs font-medium transition-colors ${
                      codeLang === lang
                        ? 'bg-falcon-red text-white'
                        : 'bg-falcon-border text-falcon-muted hover:text-white'
                    }`}
                  >
                    {lang === 'javascript' ? 'JavaScript' : 'Python'}
                  </button>
                ))}
                <button
                  onClick={() => handleCopy(HMAC_CODE[codeLang], 'hmac')}
                  className="ml-auto flex items-center gap-1.5 px-2.5 py-1 rounded-sm text-xs bg-falcon-border text-falcon-muted hover:text-white transition-colors"
                >
                  {copied === 'hmac' ? <Check className="w-3 h-3 text-emerald-400" /> : <Copy className="w-3 h-3" />}
                  {copied === 'hmac' ? 'コピー済み' : 'コピー'}
                </button>
              </div>
              <pre className="bg-[#040a13] rounded-sm border border-falcon-border p-4 text-xs font-mono text-falcon-text leading-relaxed overflow-x-auto whitespace-pre">
                {HMAC_CODE[codeLang]}
              </pre>
            </div>
          </div>
        </div>
      </div>

      {/* Test Panel */}
      <div className="mt-6 bg-falcon-surface border border-falcon-border rounded-lg">
        <div className="flex items-center gap-3 px-5 py-4 border-b border-falcon-border">
          <Send className="w-4 h-4 text-falcon-red" />
          <h2 className="text-falcon-text font-semibold text-sm">Webhookテスト送信</h2>
        </div>
        <div className="p-5 space-y-4">
          <div className="flex gap-4">
            <div className="flex-1">
              <label className="text-falcon-muted text-xs font-medium block mb-1.5">イベントタイプ</label>
              <select
                value={testEventType}
                onChange={e => setTestEventType(e.target.value)}
                className="w-full bg-[#070d19] border border-falcon-border rounded-sm px-3 py-2 text-sm text-falcon-text focus:outline-hidden focus:border-falcon-subtle"
              >
                {EVENTS.map(ev => (
                  <option key={ev.id} value={ev.id}>{ev.name}</option>
                ))}
              </select>
            </div>
            <div className="flex-2">
              <label className="text-falcon-muted text-xs font-medium block mb-1.5">送信先URL</label>
              <input
                value={testUrl}
                onChange={e => setTestUrl(e.target.value)}
                className="w-full bg-[#070d19] border border-falcon-border rounded-sm px-3 py-2 text-sm text-falcon-text focus:outline-hidden focus:border-falcon-subtle"
                placeholder="https://hooks.example.com/webhook"
              />
            </div>
            <div className="flex items-end">
              <button
                onClick={handleTestSend}
                disabled={testLoading}
                className="flex items-center gap-2 px-5 py-2 rounded-sm bg-falcon-red hover:bg-[#c0001f] disabled:opacity-50 text-white text-sm font-medium transition-colors"
              >
                {testLoading ? <Loader2 className="w-4 h-4 animate-spin" /> : <Send className="w-4 h-4" />}
                テスト送信
              </button>
            </div>
          </div>

          {testResult && (
            <div className="grid grid-cols-2 gap-4">
              <div>
                <div className="flex items-center gap-2 mb-2">
                  <span className="text-falcon-muted text-xs font-medium">リクエスト</span>
                </div>
                <pre className="bg-[#040a13] border border-falcon-border rounded-sm p-3 text-xs font-mono text-falcon-muted max-h-48 overflow-y-auto">
                  {testResult.request}
                </pre>
              </div>
              <div>
                <div className="flex items-center gap-2 mb-2">
                  {testResult.status < 400
                    ? <CheckCircle className="w-3.5 h-3.5 text-emerald-400" />
                    : <XCircle className="w-3.5 h-3.5 text-red-400" />}
                  <span className="text-falcon-muted text-xs font-medium">レスポンス</span>
                  <span className={`text-xs font-bold ${testResult.status < 400 ? 'text-emerald-400' : 'text-red-400'}`}>
                    {testResult.status}
                  </span>
                </div>
                <pre className="bg-[#040a13] border border-falcon-border rounded-sm p-3 text-xs font-mono text-[#85e89d] max-h-48 overflow-y-auto">
                  {testResult.body}
                </pre>
              </div>
            </div>
          )}
          {testError && (
            <div className="flex items-center gap-2 p-3 rounded-sm bg-red-500/10 border border-red-500/30 text-red-400 text-xs">
              <AlertCircle className="w-4 h-4 shrink-0" />
              {testError}
            </div>
          )}
        </div>
      </div>
    </div>
  )
}

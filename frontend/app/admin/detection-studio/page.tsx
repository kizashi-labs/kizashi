'use client'

import { useState, useMemo, useRef, useEffect } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { apiFetch } from '@/lib/api'
import {
  Code, Save, Play, AlignLeft, Trash2, Upload, Download,
  X, ChevronRight, ChevronDown, FileCode, Folder, FolderOpen,
  Plus, Share2, Users, Globe, Copy, CheckCircle2,
  AlertTriangle, Info, Clock, Zap, RotateCcw, Diff,
  RefreshCw, Book, Cpu, Terminal, Search, Hash, Tag,
  Eye, GitBranch, Star, MessageSquare, Bot,
} from 'lucide-react'

// ─── Types ────────────────────────────────────────────────────────────────────

type RuleType = 'sigma' | 'yara' | 'kql' | 'json'
type RuleStatus = 'experimental' | 'test' | 'stable' | 'deprecated'
type RuleLevel = 'informational' | 'low' | 'medium' | 'high' | 'critical'
type PanelView = 'docs' | 'test' | 'history' | 'ai'

interface RuleVersion {
  version: number
  author: string
  date: string
  comment: string
  content: string
}

interface DetectionRule {
  id: string
  name: string
  type: RuleType
  category: string
  status: RuleStatus
  level: RuleLevel
  content: string
  created_at: string
  updated_at: string
  author: string
  tags: string[]
  versions: RuleVersion[]
  match_count?: number
}

interface TestResult {
  matched: boolean
  matched_fields: Record<string, string>
  eval_time_ms: number
  error?: string
}

// ─── Templates ────────────────────────────────────────────────────────────────

const TEMPLATES: Record<RuleType, string> = {
  sigma: `title: Suspicious Process Creation
description: Detects suspicious process
status: experimental
author: Security Team
date: ${new Date().toISOString().slice(0, 10)}
tags:
  - attack.execution
  - attack.t1059.001
logsource:
  product: windows
  category: process_creation
detection:
  selection:
    Image|endswith: '\\\\powershell.exe'
    CommandLine|contains: '-enc'
  condition: selection
level: high
falsepositives:
  - Legitimate administrative activity`,
  yara: `rule SuspiciousPattern {
  meta:
    description = "Detects suspicious pattern"
    author = "Security Team"
    date = "${new Date().toISOString().slice(0, 10)}"
    severity = "high"
  strings:
    $s1 = "suspicious_string" nocase
    $s2 = { DE AD BE EF }
  condition:
    any of them
}`,
  kql: `// KQL Detection Query
// Detects suspicious activity
DeviceProcessEvents
| where TimeGenerated > ago(1h)
| where FileName =~ "powershell.exe"
| where ProcessCommandLine has_any ("-enc", "-encodedcommand")
| project
    TimeGenerated,
    DeviceName,
    AccountName,
    FileName,
    ProcessCommandLine
| order by TimeGenerated desc`,
  json: `{
  "name": "Custom Detection Rule",
  "description": "Detects suspicious activity",
  "version": "1.0",
  "conditions": {
    "operator": "AND",
    "rules": [
      {
        "field": "event.type",
        "operator": "equals",
        "value": "process_create"
      }
    ]
  },
  "actions": [
    { "type": "alert", "severity": "high" }
  ]
}`,
}

const SAMPLE_EVENT = `{
  "timestamp": "2026-03-18T10:30:00Z",
  "event_type": "process_create",
  "host": "DESKTOP-ABC123",
  "process": {
    "image": "C:\\\\Windows\\\\System32\\\\WindowsPowerShell\\\\v1.0\\\\powershell.exe",
    "command_line": "powershell.exe -enc SQBFAFgA...",
    "pid": 4821,
    "parent_image": "cmd.exe",
    "parent_pid": 3200,
    "user": "CONTOSO\\\\jdoe"
  }
}`

const SAMPLE_EVENTS: { label: string; category: string; json: string }[] = [
  {
    label: 'PowerShell エンコード実行',
    category: '実行',
    json: SAMPLE_EVENT,
  },
  {
    label: 'LSASS メモリダンプ',
    category: '認証情報',
    json: `{
  "timestamp": "2026-03-18T14:22:00Z",
  "event_type": "process_access",
  "host": "WIN-SRV-01",
  "process": {
    "image": "C:\\\\Windows\\\\System32\\\\rundll32.exe",
    "command_line": "rundll32.exe C:\\\\temp\\\\dump.dll",
    "pid": 9912,
    "target_image": "C:\\\\Windows\\\\System32\\\\lsass.exe",
    "granted_access": "0x1FFFFF",
    "user": "CONTOSO\\\\attacker"
  }
}`,
  },
  {
    label: 'ネットワーク偵察 (ポートスキャン)',
    category: '偵察',
    json: `{
  "timestamp": "2026-03-18T15:45:00Z",
  "event_type": "network_connection",
  "host": "DESKTOP-XYZ789",
  "network": {
    "initiated": true,
    "protocol": "tcp",
    "destination_ip": "192.168.1.100",
    "destination_port": 445,
    "source_ip": "10.0.1.5",
    "source_port": 54321
  },
  "process": {
    "image": "C:\\\\Windows\\\\System32\\\\cmd.exe",
    "command_line": "cmd.exe /c net use \\\\\\\\192.168.1.100\\\\IPC$"
  }
}`,
  },
  {
    label: 'スケジュールタスク 永続化',
    category: '永続化',
    json: `{
  "timestamp": "2026-03-18T16:10:00Z",
  "event_type": "process_create",
  "host": "LAPTOP-FINANCE",
  "process": {
    "image": "C:\\\\Windows\\\\System32\\\\schtasks.exe",
    "command_line": "schtasks /create /sc onlogon /tn Updater /tr C:\\\\Users\\\\Public\\\\update.exe /ru SYSTEM",
    "pid": 7832,
    "parent_image": "cmd.exe",
    "user": "CONTOSO\\\\jdoe"
  }
}`,
  },
  {
    label: 'ランサムウェア ファイル暗号化',
    category: '影響',
    json: `{
  "timestamp": "2026-03-18T03:15:00Z",
  "event_type": "file_create",
  "host": "SRV-FILE-01",
  "file": {
    "path": "D:\\\\shares\\\\finance\\\\Q1_report.xlsx.locked",
    "extension": ".locked",
    "entropy": 7.98,
    "size_bytes": 45312
  },
  "process": {
    "image": "C:\\\\Users\\\\TEMP\\\\svchost32.exe",
    "pid": 11204,
    "parent_image": "explorer.exe"
  }
}`,
  },
  {
    label: 'Webシェル アップロード',
    category: 'C2',
    json: `{
  "timestamp": "2026-03-18T09:05:00Z",
  "event_type": "file_create",
  "host": "WEB-PROD-01",
  "file": {
    "path": "/var/www/html/uploads/shell.php",
    "extension": ".php",
    "user": "www-data"
  },
  "process": {
    "image": "/usr/sbin/apache2",
    "command_line": "apache2 -k start",
    "pid": 1234
  }
}`,
  },
]

// ─── Sigma/YARA Docs ──────────────────────────────────────────────────────────

const DOCS: Record<RuleType, { title: string; items: { label: string; desc: string }[] }> = {
  sigma: {
    title: 'Sigma フィールドモディファイヤー',
    items: [
      { label: 'contains', desc: '部分文字列マッチ' },
      { label: 'startswith', desc: '前方一致' },
      { label: 'endswith', desc: '後方一致' },
      { label: 'contains|all', desc: '全文字列を含む' },
      { label: 'regex', desc: '正規表現マッチ' },
      { label: 'cidr', desc: 'CIDR IPマッチ' },
      { label: 'base64offset', desc: 'Base64エンコード検索' },
      { label: 'windash', desc: 'スラッシュ/ダッシュ変換' },
    ],
  },
  yara: {
    title: 'YARA モディファイヤー',
    items: [
      { label: 'nocase', desc: '大文字小文字を無視' },
      { label: 'wide', desc: 'ワイド文字列 (UTF-16)' },
      { label: 'ascii', desc: 'ASCII文字列' },
      { label: 'fullword', desc: '単語境界マッチ' },
      { label: 'xor', desc: 'XOR変換文字列' },
      { label: 'base64', desc: 'Base64エンコード文字列' },
      { label: '{ hex }', desc: '16進バイト列' },
      { label: 'any of ($*)', desc: 'パターン内いずれか' },
    ],
  },
  kql: {
    title: 'KQL 演算子',
    items: [
      { label: 'where', desc: 'フィルター条件' },
      { label: 'summarize', desc: '集計' },
      { label: 'project', desc: '列選択' },
      { label: 'extend', desc: '列追加' },
      { label: 'join', desc: 'テーブル結合' },
      { label: 'has_any()', desc: '複数値いずれか含む' },
      { label: 'contains', desc: '大文字小文字無視含む' },
      { label: 'ago()', desc: '相対時間' },
    ],
  },
  json: {
    title: 'Custom JSON 演算子',
    items: [
      { label: 'equals', desc: '完全一致' },
      { label: 'contains', desc: '部分一致' },
      { label: 'greater_than', desc: '大なり比較' },
      { label: 'less_than', desc: '小なり比較' },
      { label: 'in', desc: 'リスト内含む' },
      { label: 'regex', desc: '正規表現' },
      { label: 'AND / OR', desc: '論理演算子' },
      { label: 'NOT', desc: '否定' },
    ],
  },
}

const COMMON_PATTERNS = [
  { label: 'エンコードコマンド検出', rule_type: 'sigma', desc: 'Base64エンコードPowerShellの検出' },
  { label: 'プロセスインジェクション', rule_type: 'sigma', desc: 'CreateRemoteThread/WriteProcessMemory' },
  { label: 'ファイル名なりすまし', rule_type: 'yara', desc: '正規ファイル名を偽装するマルウェア' },
  { label: 'DNS トンネリング', rule_type: 'kql', desc: '異常に長いDNSクエリ検出' },
]

// ─── Helper Functions ─────────────────────────────────────────────────────────

const CATEGORIES = ['Process', 'Network', 'File', 'Registry', 'Custom']

function getLevelBadge(level: RuleLevel) {
  const map: Record<RuleLevel, string> = {
    critical: 'bg-red-900/40 text-red-400 border-red-700/40',
    high: 'bg-orange-900/40 text-orange-400 border-orange-700/40',
    medium: 'bg-yellow-900/40 text-yellow-400 border-yellow-700/40',
    low: 'bg-blue-900/40 text-blue-400 border-blue-700/40',
    informational: 'bg-slate-700/40 text-slate-400 border-slate-600/40',
  }
  return map[level]
}

function getStatusBadge(status: RuleStatus) {
  const map: Record<RuleStatus, string> = {
    stable: 'bg-green-900/40 text-green-400',
    test: 'bg-yellow-900/40 text-yellow-400',
    experimental: 'bg-blue-900/40 text-blue-400',
    deprecated: 'bg-slate-700/40 text-slate-400',
  }
  return map[status]
}

function getTypeColor(type: RuleType) {
  const map: Record<RuleType, string> = {
    sigma: 'text-blue-400',
    yara: 'text-orange-400',
    kql: 'text-purple-400',
    json: 'text-green-400',
  }
  return map[type]
}

function validateRule(content: string, type: RuleType): string[] {
  const errors: string[] = []
  if (!content.trim()) {
    errors.push('ルール内容が空です')
    return errors
  }

  if (type === 'sigma') {
    if (!content.includes('title:')) errors.push('Sigma: "title:" フィールドが必要です')
    if (!content.includes('detection:')) errors.push('Sigma: "detection:" セクションが必要です')
    if (!content.includes('logsource:')) errors.push('Sigma: "logsource:" セクションが必要です')
    if (!content.includes('condition:')) errors.push('Sigma: "condition:" が必要です')
  } else if (type === 'yara') {
    if (!content.includes('rule ')) errors.push('YARA: "rule" キーワードが必要です')
    if (!content.includes('strings:') && !content.includes('condition:')) errors.push('YARA: "strings:" または "condition:" が必要です')
    if (!content.includes('condition:')) errors.push('YARA: "condition:" セクションが必要です')
  } else if (type === 'json') {
    try {
      JSON.parse(content)
    } catch {
      errors.push('JSON: 構文エラー — 有効なJSONではありません')
    }
  }

  return errors
}

// ─── File Tree ────────────────────────────────────────────────────────────────

function FileTree({
  rules,
  selectedId,
  onSelect,
}: {
  rules: DetectionRule[]
  selectedId: string | null
  onSelect: (rule: DetectionRule) => void
}) {
  const [openCategories, setOpenCategories] = useState<Record<string, boolean>>(
    Object.fromEntries(CATEGORIES.map(c => [c, true]))
  )

  const byCategory = useMemo(() => {
    const map: Record<string, DetectionRule[]> = {}
    CATEGORIES.forEach(c => { map[c] = [] })
    rules.forEach(r => {
      if (map[r.category]) map[r.category].push(r)
      else {
        map['Custom'] = map['Custom'] ?? []
        map['Custom'].push(r)
      }
    })
    return map
  }, [rules])

  const toggle = (cat: string) => setOpenCategories(p => ({ ...p, [cat]: !p[cat] }))

  return (
    <div className="text-sm space-y-0.5">
      {CATEGORIES.filter(c => byCategory[c]?.length > 0).map(cat => (
        <div key={cat}>
          <button
            onClick={() => toggle(cat)}
            className="w-full flex items-center gap-1.5 px-2 py-1.5 rounded-sm text-falcon-muted hover:text-white hover:bg-falcon-border/40 transition-colors"
          >
            {openCategories[cat]
              ? <FolderOpen className="w-3.5 h-3.5 text-falcon-red/60 shrink-0" />
              : <Folder className="w-3.5 h-3.5 text-falcon-subtle shrink-0" />
            }
            <span className="flex-1 text-left text-xs font-semibold uppercase tracking-wide">{cat}</span>
            <span className="text-[10px] text-falcon-subtle">{byCategory[cat].length}</span>
            {openCategories[cat] ? <ChevronDown className="w-3 h-3" /> : <ChevronRight className="w-3 h-3" />}
          </button>
          {openCategories[cat] && byCategory[cat].map(rule => (
            <button
              key={rule.id}
              onClick={() => onSelect(rule)}
              className={`w-full flex items-center gap-1.5 px-2 py-1.5 pl-6 rounded text-xs transition-colors ${
                selectedId === rule.id
                  ? 'bg-falcon-active text-white'
                  : 'text-falcon-muted hover:bg-falcon-border/40 hover:text-white'
              }`}
            >
              <FileCode className={`w-3 h-3 shrink-0 ${getTypeColor(rule.type)}`} />
              <span className="flex-1 text-left truncate">{rule.name}</span>
              {rule.match_count && rule.match_count > 0 && (
                <span className="text-[10px] text-falcon-muted">{rule.match_count}</span>
              )}
            </button>
          ))}
        </div>
      ))}
    </div>
  )
}

// ─── History Diff View ────────────────────────────────────────────────────────

function HistoryPanel({ rule, onRestore }: { rule: DetectionRule; onRestore: (content: string) => void }) {
  const [selectedVersion, setSelectedVersion] = useState<RuleVersion | null>(null)

  return (
    <div className="space-y-3">
      <h3 className="text-sm font-semibold text-white">バージョン履歴</h3>
      <div className="space-y-2">
        {rule.versions.map(v => (
          <button
            key={v.version}
            onClick={() => setSelectedVersion(selectedVersion?.version === v.version ? null : v)}
            className={`w-full text-left p-3 rounded-lg border transition-colors ${
              selectedVersion?.version === v.version
                ? 'bg-falcon-active border-falcon-red/30'
                : 'bg-[#070d19] border-falcon-border hover:border-falcon-muted/30'
            }`}
          >
            <div className="flex items-center justify-between">
              <span className="text-xs font-bold text-white">v{v.version}</span>
              <span className="text-xs text-falcon-muted">{v.date}</span>
            </div>
            <p className="text-xs text-falcon-muted mt-0.5">{v.author} · {v.comment}</p>
          </button>
        ))}
      </div>
      {selectedVersion && (
        <div className="bg-[#070d19] border border-falcon-border rounded-lg p-3">
          <div className="flex items-center justify-between mb-2">
            <span className="text-xs font-semibold text-white">v{selectedVersion.version} 内容</span>
            <button
              onClick={() => onRestore(rule.content)}
              className="text-xs px-2 py-1 bg-falcon-red/20 text-falcon-red border border-falcon-red/30 rounded-sm hover:bg-falcon-red/30"
            >
              <RotateCcw className="w-3 h-3 inline mr-1" />
              復元
            </button>
          </div>
          <p className="text-xs text-falcon-muted italic">
            {selectedVersion.version < rule.versions.length
              ? '(この版の内容はアーカイブされています)'
              : '(現在の版)'}
          </p>
        </div>
      )}
    </div>
  )
}

// ─── Main Page ─────────────────────────────────────────────────────────────────

export default function DetectionStudioPage() {
  const queryClient = useQueryClient()

  const [ruleName, setRuleName] = useState('New Detection Rule')
  const [ruleType, setRuleType] = useState<RuleType>('sigma')
  const [content, setContent] = useState(TEMPLATES.sigma)
  const [selectedRule, setSelectedRule] = useState<DetectionRule | null>(null)
  const [panelView, setPanelView] = useState<PanelView>('docs')
  const [testEvent, setTestEvent] = useState(SAMPLE_EVENT)
  const [testResult, setTestResult] = useState<TestResult | null>(null)
  const [isTesting, setIsTesting] = useState(false)
  const [isSaving, setIsSaving] = useState(false)
  const [savedNotice, setSavedNotice] = useState(false)
  const [extraRules, setExtraRules] = useState<DetectionRule[]>([])
  const [aiDescription, setAiDescription] = useState('')
  const [aiGenerating, setAiGenerating] = useState(false)
  const [aiResult, setAiResult] = useState('')
  const [copyNotice, setCopyNotice] = useState(false)
  const textareaRef = useRef<HTMLTextAreaElement>(null)
  const [lineCount, setLineCount] = useState(1)

  const { data: apiRules } = useQuery<DetectionRule[]>({
    queryKey: ['detection-rules'],
    queryFn: () => apiFetch('/api/v1/admin/detection-rules'),
    staleTime: 60_000,
    retry: false,
  })

  const allRules = useMemo(() => {
    return [...(apiRules ?? []), ...extraRules]
  }, [apiRules, extraRules])

  // Update line count whenever content changes
  useEffect(() => {
    setLineCount(content.split('\n').length)
  }, [content])

  // Load rule into editor
  const loadRule = (rule: DetectionRule) => {
    setSelectedRule(rule)
    setRuleName(rule.name)
    setRuleType(rule.type)
    setContent(rule.content)
    setTestResult(null)
    setPanelView('docs')
  }

  const handleTypeChange = (newType: RuleType) => {
    setRuleType(newType)
    setContent(TEMPLATES[newType])
    setTestResult(null)
  }

  const validationErrors = useMemo(() => validateRule(content, ruleType), [content, ruleType])

  const handleSave = async () => {
    if (validationErrors.length > 0) return
    setIsSaving(true)
    try {
      if (selectedRule) {
        await apiFetch(`/api/v1/admin/detection-rules/${selectedRule.id}`, {
          method: 'PUT',
          body: JSON.stringify({ name: ruleName, content, type: ruleType }),
        })
      } else {
        await apiFetch('/api/v1/admin/detection-rules', {
          method: 'POST',
          body: JSON.stringify({ name: ruleName, content, type: ruleType }),
        })
      }
    } catch {
      // Mock: save locally
      const newRule: DetectionRule = {
        id: `rule-${Date.now()}`,
        name: ruleName,
        type: ruleType,
        category: 'Custom',
        status: 'experimental',
        level: 'medium',
        content,
        created_at: new Date().toISOString(),
        updated_at: new Date().toISOString(),
        author: 'admin',
        tags: [],
        versions: [{ version: 1, author: 'admin', date: new Date().toISOString().slice(0, 10), comment: '新規作成', content }],
        match_count: 0,
      }
      if (!selectedRule) setExtraRules(prev => [...prev, newRule])
    }
    setIsSaving(false)
    setSavedNotice(true)
    setTimeout(() => setSavedNotice(false), 2000)
  }

  const handleTest = async () => {
    setIsTesting(true)
    setPanelView('test')
    try {
      const result = await apiFetch(`/api/v1/admin/detection-rules/${selectedRule?.id ?? 'new'}/test`, {
        method: 'POST',
        body: JSON.stringify({ content, event: testEvent }),
      })
      setTestResult(result as TestResult)
    } catch {
      // Mock test result
      await new Promise(r => setTimeout(r, 800))
      const matched = Math.random() > 0.3
      setTestResult({
        matched,
        matched_fields: matched ? { 'Image': 'C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe', 'CommandLine': 'powershell.exe -enc SQBFAFgA...' } : {},
        eval_time_ms: Math.round(Math.random() * 5 + 0.5),
      })
    }
    setIsTesting(false)
  }

  const handleFormat = () => {
    if (ruleType === 'json') {
      try {
        setContent(JSON.stringify(JSON.parse(content), null, 2))
      } catch {}
    }
    // For sigma/yara/kql, we'd call a formatter endpoint — mock: just trim
    else {
      setContent(content.split('\n').map(l => l.trimEnd()).join('\n'))
    }
  }

  const handleAIGenerate = async () => {
    if (!aiDescription.trim()) return
    setAiGenerating(true)
    await new Promise(r => setTimeout(r, 1200))
    // Mock AI response based on description
    const mockSigma = `title: ${aiDescription.slice(0, 50)}
description: AI-generated rule based on: ${aiDescription}
status: experimental
author: AI Assistant
date: ${new Date().toISOString().slice(0, 10)}
logsource:
  product: windows
  category: process_creation
detection:
  selection:
    CommandLine|contains:
      - 'suspicious_pattern'
  condition: selection
level: medium
falsepositives:
  - Review before production use`
    setAiResult(mockSigma)
    setAiGenerating(false)
  }

  const handleExport = () => {
    const blob = new Blob([content], { type: 'text/plain' })
    const url = URL.createObjectURL(blob)
    const a = document.createElement('a')
    a.href = url
    a.download = `${ruleName.replace(/\s+/g, '_')}.${ruleType === 'sigma' ? 'yml' : ruleType === 'yara' ? 'yar' : ruleType === 'kql' ? 'kql' : 'json'}`
    a.click()
    URL.revokeObjectURL(url)
  }

  const handleCopy = async () => {
    await navigator.clipboard.writeText(content).catch(() => {})
    setCopyNotice(true)
    setTimeout(() => setCopyNotice(false), 1500)
  }

  const docs = DOCS[ruleType]

  return (
    <div className="min-h-screen bg-[#070d19] flex flex-col">
      {/* Header */}
      <div className="flex items-center justify-between px-6 py-4 border-b border-falcon-border bg-falcon-surface">
        <div className="flex items-center gap-3">
          <div className="w-9 h-9 rounded-lg bg-falcon-red/10 border border-falcon-red/20 flex items-center justify-center">
            <Code className="w-4.5 h-4.5 text-falcon-red" />
          </div>
          <div>
            <h1 className="text-xl font-bold text-white">検出ルールスタジオ</h1>
            <p className="text-xs text-falcon-muted">ルール開発・テスト環境</p>
          </div>
        </div>
        <div className="flex items-center gap-2">
          <button
            onClick={() => {
              setSelectedRule(null)
              setRuleName('New Detection Rule')
              setContent(TEMPLATES[ruleType])
              setTestResult(null)
            }}
            className="flex items-center gap-1.5 px-3 py-1.5 text-xs border border-falcon-border rounded-sm text-falcon-muted hover:text-white hover:border-falcon-muted/40 transition-colors"
          >
            <Plus className="w-3.5 h-3.5" />
            新規
          </button>
          <button
            className="flex items-center gap-1.5 px-3 py-1.5 text-xs border border-falcon-border rounded-sm text-falcon-muted hover:text-white transition-colors"
            title="コミュニティに公開"
          >
            <Globe className="w-3.5 h-3.5" />
            公開
          </button>
          <button
            className="flex items-center gap-1.5 px-3 py-1.5 text-xs border border-falcon-border rounded-sm text-falcon-muted hover:text-white transition-colors"
            title="チームに共有"
          >
            <Users className="w-3.5 h-3.5" />
            共有
          </button>
        </div>
      </div>

      {/* Main IDE layout */}
      <div className="flex flex-1 overflow-hidden" style={{ minHeight: 'calc(100vh - 73px)' }}>

        {/* Left Panel — File Tree (25%) */}
        <div className="w-[220px] shrink-0 bg-falcon-surface border-r border-falcon-border flex flex-col overflow-hidden">
          <div className="px-3 py-2 border-b border-falcon-border">
            <p className="text-[10px] font-bold text-falcon-subtle uppercase tracking-wider">ルールライブラリ ({allRules.length})</p>
          </div>
          <div className="flex-1 overflow-y-auto p-2 scrollbar-thin">
            <FileTree
              rules={allRules}
              selectedId={selectedRule?.id ?? null}
              onSelect={loadRule}
            />
          </div>
        </div>

        {/* Center Panel — Editor (50%) */}
        <div className="flex-1 flex flex-col min-w-0 bg-[#070d19]">
          {/* Editor toolbar */}
          <div className="flex items-center gap-2 px-4 py-2 border-b border-falcon-border bg-falcon-surface flex-wrap gap-y-1.5">
            {/* Rule name */}
            <input
              className="bg-transparent text-sm font-medium text-white border-b border-falcon-border focus:outline-hidden focus:border-falcon-red/50 px-1 py-0.5 w-48 min-w-[120px]"
              value={ruleName}
              onChange={e => setRuleName(e.target.value)}
            />
            {/* Type selector */}
            <div className="flex gap-0.5 ml-2 bg-[#070d19] rounded-sm border border-falcon-border p-0.5">
              {(['sigma', 'yara', 'kql', 'json'] as RuleType[]).map(t => (
                <button
                  key={t}
                  onClick={() => handleTypeChange(t)}
                  className={`px-2.5 py-1 text-xs rounded font-medium transition-colors ${
                    ruleType === t
                      ? 'bg-falcon-border text-white'
                      : 'text-falcon-muted hover:text-white'
                  }`}
                >
                  {t.toUpperCase()}
                </button>
              ))}
            </div>

            <div className="flex-1" />

            {/* Action buttons */}
            <div className="flex items-center gap-1">
              <button
                onClick={handleSave}
                disabled={isSaving || validationErrors.length > 0}
                className="flex items-center gap-1 px-2.5 py-1.5 text-xs bg-falcon-red text-white rounded-sm hover:bg-[#c0001f] disabled:opacity-50 transition-colors"
              >
                {savedNotice ? <CheckCircle2 className="w-3.5 h-3.5" /> : <Save className="w-3.5 h-3.5" />}
                {savedNotice ? '保存済' : '保存'}
              </button>
              <button
                onClick={handleTest}
                disabled={isTesting}
                className="flex items-center gap-1 px-2.5 py-1.5 text-xs bg-green-800/60 border border-green-700/40 text-green-400 rounded-sm hover:bg-green-800/80 disabled:opacity-50 transition-colors"
              >
                <Play className="w-3.5 h-3.5" />
                テスト
              </button>
              <button onClick={handleFormat} className="flex items-center gap-1 px-2.5 py-1.5 text-xs border border-falcon-border text-falcon-muted rounded-sm hover:text-white transition-colors">
                <AlignLeft className="w-3.5 h-3.5" />
                整形
              </button>
              <button onClick={handleCopy} className="flex items-center gap-1 px-2.5 py-1.5 text-xs border border-falcon-border text-falcon-muted rounded-sm hover:text-white transition-colors">
                {copyNotice ? <CheckCircle2 className="w-3.5 h-3.5 text-green-400" /> : <Copy className="w-3.5 h-3.5" />}
              </button>
              <button onClick={handleExport} className="flex items-center gap-1 px-2.5 py-1.5 text-xs border border-falcon-border text-falcon-muted rounded-sm hover:text-white transition-colors">
                <Download className="w-3.5 h-3.5" />
              </button>
            </div>
          </div>

          {/* Validation errors */}
          {validationErrors.length > 0 && (
            <div className="flex items-start gap-2 px-4 py-2 bg-red-900/20 border-b border-red-700/30">
              <AlertTriangle className="w-3.5 h-3.5 text-red-400 mt-0.5 shrink-0" />
              <div className="flex-1">
                {validationErrors.map((e, i) => (
                  <p key={i} className="text-xs text-red-400">{e}</p>
                ))}
              </div>
            </div>
          )}

          {/* Code editor area */}
          <div className="flex-1 flex overflow-hidden font-mono text-sm">
            {/* Line numbers */}
            <div
              className="select-none bg-[#070d19] border-r border-falcon-border text-falcon-subtle text-xs text-right pr-3 pt-3 leading-6 min-w-[44px]"
              style={{ userSelect: 'none' }}
            >
              {Array.from({ length: lineCount }, (_, i) => (
                <div key={i + 1}>{i + 1}</div>
              ))}
            </div>
            {/* Textarea */}
            <textarea
              ref={textareaRef}
              className="flex-1 bg-[#070d19] text-falcon-text text-sm font-mono resize-none focus:outline-hidden px-4 pt-3 leading-6 scrollbar-thin"
              spellCheck={false}
              value={content}
              onChange={e => setContent(e.target.value)}
              placeholder={TEMPLATES[ruleType]}
              style={{ tabSize: 2 }}
            />
          </div>

          {/* Status bar */}
          <div className="flex items-center justify-between px-4 py-1.5 border-t border-falcon-border bg-falcon-surface text-[10px] text-falcon-subtle">
            <div className="flex items-center gap-3">
              <span className={getTypeColor(ruleType)}>{ruleType.toUpperCase()}</span>
              <span>{lineCount} 行</span>
              <span>{content.length} 文字</span>
              {validationErrors.length === 0
                ? <span className="text-green-400">✓ 構文OK</span>
                : <span className="text-red-400">✗ エラー {validationErrors.length}件</span>
              }
            </div>
            <div className="flex items-center gap-3">
              {selectedRule && (
                <>
                  <span>作成: {selectedRule.author}</span>
                  <span>{new Date(selectedRule.updated_at).toLocaleDateString('ja-JP')}</span>
                  <span className={getStatusBadge(selectedRule.status) + ' px-1.5 py-0.5 rounded-sm text-[9px]'}>{selectedRule.status}</span>
                </>
              )}
            </div>
          </div>
        </div>

        {/* Right Panel — Docs/Test/History/AI (25%) */}
        <div className="w-[280px] shrink-0 bg-falcon-surface border-l border-falcon-border flex flex-col overflow-hidden">
          {/* Panel tabs */}
          <div className="flex border-b border-falcon-border">
            {[
              { id: 'docs', icon: Book, label: 'Docs' },
              { id: 'test', icon: Play, label: 'Test' },
              { id: 'history', icon: GitBranch, label: '履歴' },
              { id: 'ai', icon: Bot, label: 'AI' },
            ].map(tab => (
              <button
                key={tab.id}
                onClick={() => setPanelView(tab.id as PanelView)}
                className={`flex-1 flex items-center justify-center gap-1 py-2.5 text-xs border-b-2 transition-colors ${
                  panelView === tab.id
                    ? 'border-falcon-red text-white'
                    : 'border-transparent text-falcon-muted hover:text-white'
                }`}
              >
                <tab.icon className="w-3.5 h-3.5" />
                {tab.label}
              </button>
            ))}
          </div>

          <div className="flex-1 overflow-y-auto p-4 scrollbar-thin">

            {/* Docs Panel */}
            {panelView === 'docs' && (
              <div className="space-y-4">
                <div>
                  <h3 className="text-xs font-bold text-white mb-2">{docs.title}</h3>
                  <div className="space-y-1.5">
                    {docs.items.map(item => (
                      <div key={item.label} className="flex items-center gap-2">
                        <code className="text-xs font-mono text-falcon-red bg-[#070d19] px-1.5 py-0.5 rounded-sm min-w-[80px] shrink-0">{item.label}</code>
                        <span className="text-xs text-falcon-muted">{item.desc}</span>
                      </div>
                    ))}
                  </div>
                </div>

                <div>
                  <h3 className="text-xs font-bold text-white mb-2">共通検出パターン</h3>
                  <div className="space-y-1.5">
                    {COMMON_PATTERNS.map(p => (
                      <div key={p.label} className="bg-[#070d19] border border-falcon-border rounded-sm p-2">
                        <div className="flex items-center gap-1.5 mb-0.5">
                          <span className={`text-[10px] font-bold ${getTypeColor(p.rule_type as RuleType)}`}>{p.rule_type.toUpperCase()}</span>
                          <span className="text-xs font-medium text-white">{p.label}</span>
                        </div>
                        <p className="text-[10px] text-falcon-muted">{p.desc}</p>
                      </div>
                    ))}
                  </div>
                </div>
              </div>
            )}

            {/* Test Panel */}
            {panelView === 'test' && (
              <div className="space-y-3">
                {/* Sample events quick-fill */}
                <div>
                  <label className="text-xs font-semibold text-falcon-muted block mb-1.5">
                    シナリオ選択
                  </label>
                  <div className="flex flex-wrap gap-1.5">
                    {SAMPLE_EVENTS.map(s => (
                      <button
                        key={s.label}
                        onClick={() => setTestEvent(s.json)}
                        className="flex items-center gap-1 px-2 py-1 text-[10px] rounded border border-falcon-border
                                   bg-falcon-surface text-falcon-muted hover:text-white hover:border-falcon-subtle transition-colors"
                        title={s.label}
                      >
                        <span className="opacity-50">{s.category}</span>
                        <span className="text-falcon-text">{s.label}</span>
                      </button>
                    ))}
                  </div>
                </div>
                <div>
                  <label className="text-xs font-semibold text-falcon-muted block mb-1.5">サンプルイベント (JSON)</label>
                  <textarea
                    className="w-full h-40 bg-[#070d19] border border-falcon-border rounded-sm p-2 text-xs font-mono text-falcon-muted focus:outline-hidden focus:border-falcon-red/50 resize-none"
                    value={testEvent}
                    onChange={e => setTestEvent(e.target.value)}
                    spellCheck={false}
                  />
                </div>

                <button
                  onClick={handleTest}
                  disabled={isTesting}
                  className="w-full flex items-center justify-center gap-2 py-2 bg-green-800/40 border border-green-700/40 text-green-400 text-sm rounded-sm hover:bg-green-800/60 disabled:opacity-50 transition-colors"
                >
                  {isTesting ? (
                    <><RefreshCw className="w-4 h-4 animate-spin" />テスト中...</>
                  ) : (
                    <><Play className="w-4 h-4" />テスト実行</>
                  )}
                </button>

                {testResult && (
                  <div className="space-y-2">
                    <div className={`flex items-center gap-2 p-3 rounded-lg border ${
                      testResult.matched
                        ? 'bg-red-900/20 border-red-700/30'
                        : 'bg-green-900/20 border-green-700/30'
                    }`}>
                      {testResult.matched
                        ? <AlertTriangle className="w-5 h-5 text-red-400 shrink-0" />
                        : <CheckCircle2 className="w-5 h-5 text-green-400 shrink-0" />
                      }
                      <div>
                        <p className={`text-sm font-bold ${testResult.matched ? 'text-red-400' : 'text-green-400'}`}>
                          {testResult.matched ? 'マッチ!' : 'マッチなし'}
                        </p>
                        <p className="text-xs text-falcon-muted">評価時間: {testResult.eval_time_ms}ms</p>
                      </div>
                    </div>

                    {testResult.matched && Object.keys(testResult.matched_fields).length > 0 && (
                      <div className="bg-[#070d19] border border-falcon-border rounded-lg p-3">
                        <p className="text-xs font-semibold text-white mb-2">マッチしたフィールド</p>
                        {Object.entries(testResult.matched_fields).map(([k, v]) => (
                          <div key={k} className="mb-1">
                            <span className="text-xs text-falcon-red">{k}:</span>
                            <span className="text-xs text-falcon-muted ml-1 break-all">{v}</span>
                          </div>
                        ))}
                      </div>
                    )}

                    <button className="w-full py-1.5 text-xs border border-falcon-border text-falcon-muted rounded-sm hover:text-white hover:border-falcon-muted/40 transition-colors">
                      <Cpu className="w-3.5 h-3.5 inline mr-1" />
                      過去7日間で 142件マッチ (シミュレーション)
                    </button>
                  </div>
                )}
              </div>
            )}

            {/* History Panel */}
            {panelView === 'history' && (
              selectedRule
                ? <HistoryPanel rule={selectedRule} onRestore={setContent} />
                : <p className="text-xs text-falcon-muted text-center py-8">ルールを選択してください</p>
            )}

            {/* AI Assist Panel */}
            {panelView === 'ai' && (
              <div className="space-y-3">
                <div className="flex items-center gap-2">
                  <Bot className="w-5 h-5 text-falcon-red" />
                  <h3 className="text-sm font-bold text-white">AIアシスト</h3>
                </div>
                <p className="text-xs text-falcon-muted">検出したい脅威シナリオを説明すると、ルールテンプレートを生成します。</p>

                <div>
                  <label className="text-xs text-falcon-muted mb-1 block">脅威シナリオの説明</label>
                  <textarea
                    className="w-full h-24 bg-[#070d19] border border-falcon-border rounded-sm p-2 text-xs text-white placeholder-falcon-subtle focus:outline-hidden focus:border-falcon-red/50 resize-none"
                    placeholder="例: PowerShellがBase64エンコードされたコマンドを実行し、外部サーバーにデータを送信している"
                    value={aiDescription}
                    onChange={e => setAiDescription(e.target.value)}
                  />
                </div>

                <button
                  onClick={handleAIGenerate}
                  disabled={aiGenerating || !aiDescription.trim()}
                  className="w-full flex items-center justify-center gap-2 py-2 bg-falcon-red/20 border border-falcon-red/30 text-falcon-red text-sm rounded-sm hover:bg-falcon-red/30 disabled:opacity-50 transition-colors"
                >
                  {aiGenerating
                    ? <><RefreshCw className="w-4 h-4 animate-spin" />生成中...</>
                    : <><Zap className="w-4 h-4" />ルール生成</>
                  }
                </button>

                {aiResult && (
                  <div className="space-y-2">
                    <div className="bg-[#070d19] border border-falcon-border rounded-lg p-3">
                      <div className="flex items-center justify-between mb-2">
                        <span className="text-xs font-semibold text-white">生成されたルール (Sigma)</span>
                        <button
                          onClick={() => { setContent(aiResult); setPanelView('docs') }}
                          className="text-xs px-2 py-0.5 bg-falcon-red/20 text-falcon-red border border-falcon-red/30 rounded-sm hover:bg-falcon-red/30 transition-colors"
                        >
                          エディタに適用
                        </button>
                      </div>
                      <pre className="text-xs font-mono text-falcon-muted overflow-x-auto whitespace-pre-wrap">{aiResult}</pre>
                    </div>
                    <p className="text-[10px] text-falcon-subtle italic">* AIが生成したルールは必ずレビューしてください</p>
                  </div>
                )}
              </div>
            )}
          </div>
        </div>
      </div>
    </div>
  )
}

'use client'

import { useState, useEffect, Suspense } from 'react'
import { useParams, useSearchParams, useRouter } from 'next/navigation'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import {
  ArrowLeft, Save, TestTube, Shield, AlertTriangle,
  CheckCircle, XCircle, Play, FileCode, Brain
} from 'lucide-react'
import Link from 'next/link'
import { apiFetch } from '@/lib/api'

interface Rule {
  id: string
  name: string
  type: 'sigma' | 'yara' | 'behavioral'
  platform: string[]
  severity: number
  enabled: boolean
  source: string
  mitre_tags: string[]
  auto_isolate: boolean
  auto_kill: boolean
  auto_quarantine: boolean
  description?: string
  false_positive_rate: number
  content: string
  created_at: string
  updated_at: string
}

async function fetchRule(id: string): Promise<Rule> {
  if (id === 'new') return {
    id: '', name: '', type: 'sigma', platform: ['windows'], severity: 5,
    enabled: true, source: 'custom', mitre_tags: [], auto_isolate: false,
    auto_kill: false, auto_quarantine: false, description: '', content: '',
    false_positive_rate: 0, created_at: '', updated_at: ''
  }
  return apiFetch<Rule>(`/api/v1/rules/${id}`)
}

async function saveRule(rule: Partial<Rule> & { id: string }) {
  const isNew = !rule.id
  return apiFetch<Rule>(
    isNew ? '/api/v1/rules' : `/api/v1/rules/${rule.id}`,
    {
      method: isNew ? 'POST' : 'PUT',
      body: JSON.stringify(rule),
    }
  )
}

async function testRule(id: string, sampleEvent: string) {
  return apiFetch<{ matched: boolean; details: string; elapsed_ms: number }>(
    `/api/v1/rules/${id}/test`,
    {
      method: 'POST',
      body: JSON.stringify({ event: sampleEvent }),
    }
  )
}

const PLATFORMS = ['windows', 'linux', 'darwin']
const MITRE_TECHNIQUES = [
  'T1059.001', 'T1059.004', 'T1003.001', 'T1486', 'T1490',
  'T1505.003', 'T1543.004', 'T1550.002', 'T1078', 'T1021'
]

function RuleDetailInner() {
  const params = useParams()
  const searchParams = useSearchParams()
  const router = useRouter()
  const qc = useQueryClient()
  const id = params.id as string
  const isNew = id === 'new'
  const initialTab = searchParams.get('tab') || 'edit'

  const [activeTab, setActiveTab] = useState(initialTab)
  const [form, setForm] = useState<Partial<Rule>>({})
  const [sampleEvent, setSampleEvent] = useState('')
  const [testResult, setTestResult] = useState<{ matched: boolean; details: string; elapsed_ms: number } | null>(null)
  const [mitreInput, setMitreInput] = useState('')
  const [saveSuccess, setSaveSuccess] = useState(false)

  const { data: rule, isLoading } = useQuery({
    queryKey: ['rule', id],
    queryFn: () => fetchRule(id)
  })

  useEffect(() => {
    if (rule) setForm(rule)
  }, [rule])

  const saveMutation = useMutation({
    mutationFn: saveRule,
    onSuccess: (saved) => {
      qc.invalidateQueries({ queryKey: ['rules'] })
      if (isNew) {
        router.push(`/rules/${saved.id}`)
      } else {
        setSaveSuccess(true)
        setTimeout(() => setSaveSuccess(false), 3000)
      }
    },
    onError: (err: Error) => alert(`保存に失敗しました: ${err.message}`),
  })

  const testMutation = useMutation({
    mutationFn: ({ id, event }: { id: string; event: string }) => testRule(id, event),
    onSuccess: (data) => setTestResult(data)
  })

  if (isLoading && !isNew) {
    return (
      <div className="p-6 flex items-center justify-center h-64">
        <div className="w-8 h-8 border-2 border-blue-500 border-t-transparent rounded-full animate-spin" />
      </div>
    )
  }

  const tabs = [
    { id: 'edit', label: '編集' },
    { id: 'test', label: 'テスト' },
    { id: 'info', label: '詳細情報' },
  ]

  return (
    <div className="p-6 space-y-6">
      {/* Header */}
      <div className="flex items-center gap-4">
        <Link href="/rules" className="text-[#8899aa] hover:text-white transition-colors">
          <ArrowLeft className="w-5 h-5" />
        </Link>
        <div className="flex-1">
          <h1 className="text-2xl font-bold text-white">
            {isNew ? '新規ルール作成' : form.name || 'ルール編集'}
          </h1>
          {!isNew && rule && (
            <p className="text-[#8899aa] text-sm mt-1">
              最終更新: {new Date(rule.updated_at).toLocaleString('ja-JP')}
            </p>
          )}
        </div>
        <button
          onClick={() => saveMutation.mutate({ ...form, id: form.id || '' } as Rule)}
          disabled={saveMutation.isPending}
          className={`flex items-center gap-2 px-4 py-2 rounded-lg transition-colors disabled:opacity-50 text-white ${
            saveSuccess ? 'bg-green-600 hover:bg-green-700' : 'bg-[#1a6bff] hover:bg-[#1557d4]'
          }`}
        >
          {saveMutation.isPending ? (
            <div className="w-4 h-4 border-2 border-white/30 border-t-white rounded-full animate-spin" />
          ) : saveSuccess ? (
            <CheckCircle className="w-4 h-4" />
          ) : (
            <Save className="w-4 h-4" />
          )}
          {saveSuccess ? '保存しました' : '保存'}
        </button>
      </div>

      {/* Tabs */}
      <div className="border-b border-[#1e2d42]">
        <div className="flex gap-1">
          {tabs.map(tab => (
            <button
              key={tab.id}
              onClick={() => setActiveTab(tab.id)}
              className={`px-4 py-2 text-sm font-medium transition-colors border-b-2 -mb-px ${
                activeTab === tab.id
                  ? 'border-blue-500 text-blue-400'
                  : 'border-transparent text-[#8899aa] hover:text-[#8899aa]'
              }`}
            >
              {tab.label}
            </button>
          ))}
        </div>
      </div>

      {activeTab === 'edit' && (
        <div className="grid grid-cols-3 gap-6">
          {/* Left: Basic Info */}
          <div className="col-span-1 space-y-4">
            <div className="bg-[#111827] rounded-xl p-4 space-y-4">
              <h3 className="text-white font-medium">基本情報</h3>

              <div>
                <label className="text-[#8899aa] text-sm block mb-1">ルール名 *</label>
                <input
                  type="text"
                  value={form.name || ''}
                  onChange={e => setForm(f => ({ ...f, name: e.target.value }))}
                  className="w-full bg-[#080c14] text-white px-3 py-2 rounded-lg border border-[#1e2d42] focus:outline-none focus:border-[#1a6bff] text-sm"
                />
              </div>

              <div>
                <label className="text-[#8899aa] text-sm block mb-1">タイプ</label>
                <select
                  value={form.type || 'sigma'}
                  onChange={e => setForm(f => ({ ...f, type: e.target.value as Rule['type'] }))}
                  className="w-full bg-[#080c14] text-white px-3 py-2 rounded-lg border border-[#1e2d42] text-sm focus:outline-none focus:border-[#1a6bff]"
                >
                  <option value="sigma">Sigma</option>
                  <option value="yara">YARA</option>
                  <option value="behavioral">Behavioral</option>
                </select>
              </div>

              <div>
                <label className="text-[#8899aa] text-sm block mb-1">深刻度 (1-10)</label>
                <div className="flex items-center gap-3">
                  <input
                    type="range" min={1} max={10}
                    value={form.severity || 5}
                    onChange={e => setForm(f => ({ ...f, severity: Number(e.target.value) }))}
                    className="flex-1"
                  />
                  <span className={`text-sm font-bold px-2 py-1 rounded ${
                    (form.severity || 5) >= 9 ? 'text-red-400 bg-red-900/30' :
                    (form.severity || 5) >= 7 ? 'text-orange-400 bg-orange-900/30' :
                    (form.severity || 5) >= 5 ? 'text-yellow-400 bg-yellow-900/30' :
                    'text-green-400 bg-green-900/30'
                  }`}>
                    {form.severity || 5}
                  </span>
                </div>
              </div>

              <div>
                <label className="text-[#8899aa] text-sm block mb-2">プラットフォーム</label>
                <div className="space-y-1">
                  {PLATFORMS.map(p => (
                    <label key={p} className="flex items-center gap-2 cursor-pointer">
                      <input
                        type="checkbox"
                        checked={(form.platform || []).includes(p)}
                        onChange={e => setForm(f => ({
                          ...f,
                          platform: e.target.checked
                            ? [...(f.platform || []), p]
                            : (f.platform || []).filter(x => x !== p)
                        }))}
                        className="rounded"
                      />
                      <span className="text-[#8899aa] text-sm capitalize">{p}</span>
                    </label>
                  ))}
                </div>
              </div>

              <div>
                <label className="text-[#8899aa] text-sm block mb-1">説明</label>
                <textarea
                  value={form.description || ''}
                  onChange={e => setForm(f => ({ ...f, description: e.target.value }))}
                  rows={3}
                  className="w-full bg-[#080c14] text-white px-3 py-2 rounded-lg border border-[#1e2d42] focus:outline-none focus:border-[#1a6bff] text-sm resize-none"
                />
              </div>
            </div>

            <div className="bg-[#111827] rounded-xl p-4 space-y-3">
              <h3 className="text-white font-medium">自動対応</h3>
              {[
                { key: 'auto_isolate', label: 'エンドポイント隔離', color: 'text-red-400', desc: '深刻度9以上推奨' },
                { key: 'auto_kill', label: 'プロセス停止', color: 'text-orange-400', desc: '深刻度7以上推奨' },
                { key: 'auto_quarantine', label: 'ファイル検疫', color: 'text-yellow-400', desc: '深刻度6以上推奨' },
              ].map(opt => (
                <label key={opt.key} className="flex items-start gap-3 cursor-pointer">
                  <input
                    type="checkbox"
                    checked={!!form[opt.key as keyof Rule]}
                    onChange={e => setForm(f => ({ ...f, [opt.key]: e.target.checked }))}
                    className="mt-0.5 rounded"
                  />
                  <div>
                    <span className={`text-sm font-medium ${opt.color}`}>{opt.label}</span>
                    <p className="text-[#5a6a7a] text-xs">{opt.desc}</p>
                  </div>
                </label>
              ))}
              {(form.auto_isolate || form.auto_kill || form.auto_quarantine) && (
                <div className="flex items-center gap-2 text-yellow-400 text-xs bg-yellow-900/20 px-3 py-2 rounded-lg">
                  <AlertTriangle className="w-3 h-3 flex-shrink-0" />
                  自動対応は誤検知率が低いルールにのみ設定してください
                </div>
              )}
            </div>

            <div className="bg-[#111827] rounded-xl p-4 space-y-3">
              <h3 className="text-white font-medium">MITRE ATT&CK</h3>
              <div className="flex flex-wrap gap-1.5">
                {(form.mitre_tags || []).map(tag => (
                  <span
                    key={tag}
                    className="text-xs bg-[#161f33] text-[#8899aa] px-2 py-1 rounded font-mono flex items-center gap-1 cursor-pointer hover:bg-red-900/30 hover:text-red-300"
                    onClick={() => setForm(f => ({ ...f, mitre_tags: (f.mitre_tags || []).filter(t => t !== tag) }))}
                  >
                    {tag} ×
                  </span>
                ))}
              </div>
              <div className="flex gap-2">
                <input
                  type="text"
                  value={mitreInput}
                  onChange={e => setMitreInput(e.target.value)}
                  placeholder="T1059.001"
                  className="flex-1 bg-[#080c14] text-white px-2 py-1 rounded border border-[#1e2d42] text-xs focus:outline-none focus:border-[#1a6bff] font-mono"
                  onKeyDown={e => {
                    if (e.key === 'Enter' && mitreInput) {
                      setForm(f => ({ ...f, mitre_tags: [...new Set([...(f.mitre_tags || []), mitreInput])] }))
                      setMitreInput('')
                    }
                  }}
                />
              </div>
              <div className="flex flex-wrap gap-1">
                {MITRE_TECHNIQUES.filter(t => !(form.mitre_tags || []).includes(t)).slice(0, 6).map(t => (
                  <button
                    key={t}
                    onClick={() => setForm(f => ({ ...f, mitre_tags: [...(f.mitre_tags || []), t] }))}
                    className="text-xs text-[#5a6a7a] hover:text-[#8899aa] font-mono"
                  >
                    +{t}
                  </button>
                ))}
              </div>
            </div>
          </div>

          {/* Right: Rule Content */}
          <div className="col-span-2">
            <div className="bg-[#111827] rounded-xl h-full flex flex-col">
              <div className="flex items-center justify-between px-4 py-3 border-b border-[#1e2d42]">
                <h3 className="text-white font-medium flex items-center gap-2">
                  <FileCode className="w-4 h-4 text-blue-400" />
                  ルール内容
                </h3>
                <span className="text-[#5a6a7a] text-xs font-mono">
                  {form.type === 'sigma' ? 'YAML' : form.type === 'yara' ? 'YARA' : 'JSON'}
                </span>
              </div>
              <textarea
                value={form.content || ''}
                onChange={e => setForm(f => ({ ...f, content: e.target.value }))}
                placeholder={
                  form.type === 'sigma'
                    ? 'title: Rule Name\ndetection:\n  selection:\n    Image|endswith: \'\\\\example.exe\'\n  condition: selection'
                    : form.type === 'yara'
                    ? 'rule RuleName {\n  strings:\n    $s1 = "malicious_string"\n  condition:\n    $s1\n}'
                    : '{\n  "sequence": [],\n  "timeWindow": "5m"\n}'
                }
                className="flex-1 bg-[#080c14] text-[#e2e8f4] p-4 font-mono text-sm focus:outline-none resize-none rounded-b-xl"
                style={{ minHeight: '500px' }}
              />
            </div>
          </div>
        </div>
      )}

      {activeTab === 'test' && (
        <div className="grid grid-cols-2 gap-6">
          <div className="space-y-4">
            {!form.id && (
              <div className="flex items-center gap-2 text-yellow-400 text-sm bg-yellow-900/20
                              border border-yellow-700/50 rounded-lg px-4 py-3">
                <AlertTriangle className="w-4 h-4 flex-shrink-0" />
                ルールを先に保存してからテストを実行してください。
              </div>
            )}
            <div className="bg-[#111827] rounded-xl p-4">
              <h3 className="text-white font-medium mb-3 flex items-center gap-2">
                <TestTube className="w-4 h-4 text-yellow-400" />
                テストイベント
              </h3>
              <textarea
                value={sampleEvent}
                onChange={e => setSampleEvent(e.target.value)}
                placeholder='{"EventID": 4624, "Image": "C:\\Windows\\System32\\powershell.exe", "CommandLine": "powershell.exe -enc base64..."}'
                rows={15}
                className="w-full bg-[#080c14] text-[#e2e8f4] px-3 py-2 rounded-lg border border-[#1e2d42] focus:outline-none focus:border-yellow-500 text-sm font-mono resize-none"
              />
              <button
                onClick={() => testMutation.mutate({ id: form.id || '', event: sampleEvent })}
                disabled={!sampleEvent || !form.id || testMutation.isPending}
                className="mt-3 w-full py-2 bg-yellow-600 text-white rounded-lg hover:bg-yellow-700 transition-colors disabled:opacity-50 flex items-center justify-center gap-2"
              >
                {testMutation.isPending ? (
                  <div className="w-4 h-4 border-2 border-white/30 border-t-white rounded-full animate-spin" />
                ) : (
                  <Play className="w-4 h-4" />
                )}
                テスト実行
              </button>
            </div>
          </div>

          <div>
            {testResult ? (
              <div className="bg-[#111827] rounded-xl p-4 space-y-4">
                <h3 className="text-white font-medium">テスト結果</h3>
                <div className={`flex items-center gap-3 p-4 rounded-lg ${
                  testResult.matched ? 'bg-red-900/30 border border-red-700' : 'bg-green-900/30 border border-green-700'
                }`}>
                  {testResult.matched
                    ? <XCircle className="w-8 h-8 text-red-400" />
                    : <CheckCircle className="w-8 h-8 text-green-400" />
                  }
                  <div>
                    <div className={`font-bold text-lg ${testResult.matched ? 'text-red-300' : 'text-green-300'}`}>
                      {testResult.matched ? 'マッチ（脅威を検知）' : 'マッチなし'}
                    </div>
                    <div className="text-[#8899aa] text-sm">{testResult.elapsed_ms}ms</div>
                  </div>
                </div>
                {testResult.details && (
                  <div>
                    <div className="text-[#8899aa] text-sm mb-2">詳細</div>
                    <pre className="bg-[#080c14] text-[#8899aa] p-3 rounded-lg text-xs overflow-auto font-mono">
                      {testResult.details}
                    </pre>
                  </div>
                )}
              </div>
            ) : (
              <div className="bg-[#111827] rounded-xl p-4 flex items-center justify-center h-64">
                <div className="text-center text-[#5a6a7a]">
                  <TestTube className="w-12 h-12 mx-auto mb-3 opacity-30" />
                  <p>左のフォームにイベントを入力して<br />テストを実行してください</p>
                </div>
              </div>
            )}
          </div>
        </div>
      )}

      {activeTab === 'info' && rule && (
        <div className="grid grid-cols-2 gap-6">
          <div className="bg-[#111827] rounded-xl p-4 space-y-3">
            <h3 className="text-white font-medium">メタデータ</h3>
            {[
              { label: 'ルールID', value: rule.id },
              { label: 'ソース', value: rule.source },
              { label: '誤検知率', value: `${(rule.false_positive_rate * 100).toFixed(1)}%` },
              { label: '作成日時', value: new Date(rule.created_at).toLocaleString('ja-JP') },
              { label: '更新日時', value: new Date(rule.updated_at).toLocaleString('ja-JP') },
            ].map(item => (
              <div key={item.label} className="flex justify-between">
                <span className="text-[#8899aa] text-sm">{item.label}</span>
                <span className="text-[#e2e8f4] text-sm font-mono">{item.value}</span>
              </div>
            ))}
          </div>
          <div className="bg-[#111827] rounded-xl p-4 space-y-3">
            <h3 className="text-white font-medium">MITRE ATT&CK マッピング</h3>
            {rule.mitre_tags.map(tag => (
              <div key={tag} className="flex items-center gap-3 p-2 bg-[#080c14] rounded-lg">
                <span className="text-xs font-mono bg-blue-900/40 text-blue-300 px-2 py-1 rounded">{tag}</span>
                <span className="text-[#8899aa] text-sm">Technique {tag}</span>
              </div>
            ))}
            {rule.mitre_tags.length === 0 && (
              <p className="text-[#5a6a7a] text-sm">MITREタグが設定されていません</p>
            )}
          </div>
        </div>
      )}
    </div>
  )
}

export default function RuleDetailPage() {
  return (
    <Suspense fallback={
      <div className="p-6 space-y-4">
        <div className="h-8 w-48 bg-[#111827] rounded-lg animate-pulse" />
        <div className="h-96 bg-[#111827] rounded-xl border border-[#1e2d42] animate-pulse" />
      </div>
    }>
      <RuleDetailInner />
    </Suspense>
  )
}

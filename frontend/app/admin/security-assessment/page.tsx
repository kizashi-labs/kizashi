'use client'

import { useState } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { apiFetch } from '@/lib/api'
import { mockOr } from '@/lib/mock'
import { Plus, FileText, Download, Pencil, Upload, ChevronRight, AlertTriangle, CheckCircle, Clock } from 'lucide-react'

import { PageDataUnavailable } from '@/components/PageDataUnavailable'
import { PageSaveFailed } from '@/components/PageSaveFailed'

interface AssessmentFinding {
  id: string
  category: string
  severity: 'critical' | 'high' | 'medium' | 'low'
  description: string
  recommendation: string
}

interface Assessment {
  id: string
  name: string
  type: 'gap_analysis' | 'maturity' | 'compliance' | 'risk'
  framework: string
  status: 'draft' | 'in_progress' | 'review' | 'completed'
  score: number | null
  assessor: string
  created_at: string
  updated_at: string
  findings: AssessmentFinding[]
  recommendations: string[]
}

interface AssessmentData {
  assessments: Assessment[]
}

const MOCK_ASSESSMENTS: Assessment[] = [
  {
    id: 'a1', name: 'NIST CSF ギャップ分析 2026 Q1', type: 'gap_analysis', framework: 'NIST CSF 2.0', status: 'completed', score: 78, assessor: '田中 太郎',
    created_at: '2026-03-01T00:00:00Z', updated_at: '2026-03-15T00:00:00Z',
    findings: [
      { id: 'f1', category: 'ID.AM', severity: 'high', description: '資産インベントリの自動更新が未実装', recommendation: 'CMDB ツールを導入し24時間以内に自動同期を実現する' },
      { id: 'f2', category: 'PR.AC', severity: 'critical', description: '特権アカウントのMFA適用率が62%にとどまる', recommendation: '90日以内に全特権アカウントへMFAを強制適用する' },
      { id: 'f3', category: 'DE.CM', severity: 'medium', description: 'クラウド環境のログ収集が一部未設定', recommendation: 'AWS CloudTrailおよびAzure Monitorを全リージョンへ展開する' },
    ],
    recommendations: [
      '特権アカウントMFA強制適用を最優先タスクとして設定する',
      'CMDB導入プロジェクトを次四半期に開始する',
      'クラウドログ収集設定を今月中に完了させる',
      'セキュリティ意識向上トレーニングを年2回以上実施する',
    ],
  },
  {
    id: 'a2', name: 'ISO 27001 成熟度評価', type: 'maturity', framework: 'ISO/IEC 27001:2022', status: 'in_progress', score: null, assessor: '鈴木 花子',
    created_at: '2026-03-10T00:00:00Z', updated_at: '2026-03-18T00:00:00Z',
    findings: [], recommendations: [],
  },
  {
    id: 'a3', name: 'PCI DSS v4.0 コンプライアンス確認', type: 'compliance', framework: 'PCI DSS v4.0', status: 'review', score: null, assessor: '山田 次郎',
    created_at: '2026-02-20T00:00:00Z', updated_at: '2026-03-17T00:00:00Z',
    findings: [
      { id: 'f4', category: 'Req 8', severity: 'high', description: 'パスワードポリシーが最新要件を未充足', recommendation: 'ポリシーを更新し最小長16文字・複雑性要件を満たす' },
    ],
    recommendations: ['パスワードポリシーを今週中に更新する'],
  },
]

// 取得できなかったときに出すもの。MOCK は USE_MOCK のときだけです。
const EMPTY: AssessmentData = { assessments: [] }

// API が落ちている/未実装のときのフォールバック。NEXT_PUBLIC_USE_MOCK=true の
// ローカル開発でだけモックを返し、それ以外では空を返す。**ガードは MOCK_* の
// 隣に置く。** 素の定数を先に作って使用箇所でだけ包む形にすると、後から別の
// 参照が増えたときにガードの無い経路ができる（本番で API が失敗したときに
// 架空の評価結果が表示される）。
const FALLBACK: AssessmentData = mockOr({ assessments: MOCK_ASSESSMENTS }, EMPTY)

const TYPE_STYLES: Record<string, { bg: string; text: string; label: string }> = {
  gap_analysis: { bg: 'bg-blue-900/40',   text: 'text-blue-300',   label: 'ギャップ分析' },
  maturity:     { bg: 'bg-green-900/40',  text: 'text-green-300',  label: '成熟度評価' },
  compliance:   { bg: 'bg-purple-900/40', text: 'text-purple-300', label: 'コンプライアンス' },
  risk:         { bg: 'bg-orange-900/40', text: 'text-orange-300', label: 'リスク評価' },
}

const STATUS_META: Record<string, { badge: string; label: string; icon: typeof Clock }> = {
  draft:       { badge: 'bg-gray-700/60 text-gray-300',   label: 'ドラフト',   icon: FileText },
  in_progress: { badge: 'bg-blue-900/40 text-blue-300',   label: '進行中',     icon: Clock },
  review:      { badge: 'bg-yellow-900/40 text-yellow-300', label: 'レビュー中', icon: AlertTriangle },
  completed:   { badge: 'bg-green-900/40 text-green-300', label: '完了',       icon: CheckCircle },
}

const SEV_STYLES: Record<string, { badge: string; label: string }> = {
  critical: { badge: 'bg-red-900/60 text-red-300',       label: 'クリティカル' },
  high:     { badge: 'bg-orange-900/60 text-orange-300', label: '高' },
  medium:   { badge: 'bg-yellow-900/60 text-yellow-300', label: '中' },
  low:      { badge: 'bg-blue-900/60 text-blue-300',     label: '低' },
}

const STATS = [
  { label: '総アセスメント', value: '8' },
  { label: '完了', value: '5' },
  { label: '進行中', value: '2' },
  { label: '平均スコア', value: '82.3%' },
]

function ScoreCircle({ score }: { score: number }) {
  const r = 36
  const circ = 2 * Math.PI * r
  const dash = (score / 100) * circ
  const color = score >= 80 ? '#22c55e' : score >= 60 ? '#eab308' : '#e8002d'
  return (
    <svg width="96" height="96" viewBox="0 0 96 96">
      <circle cx="48" cy="48" r={r} fill="none" stroke="#1e2d42" strokeWidth="8" />
      <circle cx="48" cy="48" r={r} fill="none" stroke={color} strokeWidth="8"
        strokeDasharray={`${dash} ${circ}`} strokeLinecap="round" transform="rotate(-90 48 48)" />
      <text x="48" y="52" textAnchor="middle" fill="white" fontSize="18" fontWeight="bold">{score}</text>
    </svg>
  )
}

export default function SecurityAssessmentPage() {
  const [selected, setSelected] = useState<string | null>(null)
  const [showForm, setShowForm] = useState(false)

  const { data } = useQuery<AssessmentData>({
    queryKey: ['security-assessment'],
    queryFn: () => apiFetch<AssessmentData>('/api/v1/admin/security-assessment'),
  })

  const qc = useQueryClient()
  const exportPDF = useMutation({
    mutationFn: (id: string) => apiFetch(`/api/v1/admin/security-assessment/${id}/export`),
  })

  const d = data ?? FALLBACK
  const detail = d.assessments.find(a => a.id === selected) ?? null

  return (
    <div className="min-h-screen bg-[#070d19] text-white p-6 space-y-6">
      <PageDataUnavailable />
      <PageSaveFailed className="mb-4" />
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold">セキュリティアセスメント</h1>
          <p className="text-[#7d92b0] text-sm mt-1">セキュリティ体制の評価・ギャップ分析・コンプライアンス確認を管理します</p>
        </div>
        <button onClick={() => setShowForm(true)} className="flex items-center gap-2 bg-[#e8002d] hover:bg-[#c8001d] text-white px-4 py-2 rounded-lg text-sm font-medium transition-colors">
          <Plus size={16} /> 新規アセスメント
        </button>
      </div>

      {/* Stats */}
      <div className="grid grid-cols-4 gap-4">
        {STATS.map(s => (
          <div key={s.label} className="bg-[#0d1220] border border-[#1e2d42] rounded-xl p-4">
            <div className="text-2xl font-bold text-white">{s.value}</div>
            <div className="text-[#7d92b0] text-sm mt-1">{s.label}</div>
          </div>
        ))}
      </div>

      {/* Main Layout */}
      <div className="flex gap-5">
        {/* Left: Assessment list (40%) */}
        <div className="w-[40%] shrink-0 space-y-3">
          <h2 className="font-semibold text-white text-sm">アセスメント一覧</h2>
          {d.assessments.map(a => {
            const ts = TYPE_STYLES[a.type] ?? TYPE_STYLES.gap_analysis
            const ss = STATUS_META[a.status] ?? STATUS_META.draft
            const isSelected = selected === a.id
            return (
              <div key={a.id} onClick={() => setSelected(isSelected ? null : a.id)}
                className={`bg-[#0d1220] border rounded-xl p-4 cursor-pointer transition-colors ${isSelected ? 'border-[#e8002d]' : 'border-[#1e2d42] hover:border-[#7d92b0]'}`}>
                <div className="flex items-start justify-between gap-3">
                  <div className="flex-1 min-w-0">
                    <div className="font-medium text-white text-sm leading-snug">{a.name}</div>
                    <div className="flex flex-wrap gap-1.5 mt-2">
                      <span className={`text-xs px-2 py-0.5 rounded-full ${ts.bg} ${ts.text}`}>{ts.label}</span>
                      <span className="text-xs px-2 py-0.5 rounded-full bg-[#1e2d42] text-[#7d92b0]">{a.framework}</span>
                      <span className={`text-xs px-2 py-0.5 rounded-full flex items-center gap-1 ${ss.badge} ${a.status === 'in_progress' ? 'animate-pulse' : ''}`}>
                        {ss.label}
                      </span>
                    </div>
                    <div className="text-[#7d92b0] text-xs mt-2">担当: {a.assessor}</div>
                  </div>
                  <div className="flex items-center gap-2 shrink-0">
                    {a.score !== null && <ScoreCircle score={a.score} />}
                    <ChevronRight size={14} className={`text-[#7d92b0] transition-transform ${isSelected ? 'rotate-90' : ''}`} />
                  </div>
                </div>
              </div>
            )
          })}
        </div>

        {/* Right: Detail (60%) */}
        <div className="flex-1">
          {!detail ? (
            <div className="bg-[#0d1220] border border-[#1e2d42] rounded-xl p-12 flex flex-col items-center justify-center text-center h-full min-h-[400px]">
              <FileText size={48} className="text-[#1e2d42] mb-4" />
              <div className="text-white font-medium">アセスメントを選択してください</div>
              <div className="text-[#7d92b0] text-sm mt-2">左のリストからアセスメントを選択すると詳細が表示されます</div>
            </div>
          ) : (
            <div className="bg-[#0d1220] border border-[#1e2d42] rounded-xl overflow-hidden">
              {/* Detail Header */}
              <div className="p-5 border-b border-[#1e2d42]">
                <div className="flex items-start justify-between gap-4">
                  <div className="flex-1 min-w-0">
                    <h2 className="font-semibold text-white text-lg leading-snug">{detail.name}</h2>
                    <div className="flex flex-wrap gap-2 mt-2">
                      <span className={`text-xs px-2 py-0.5 rounded-full ${(TYPE_STYLES[detail.type] ?? TYPE_STYLES.gap_analysis).bg} ${(TYPE_STYLES[detail.type] ?? TYPE_STYLES.gap_analysis).text}`}>
                        {(TYPE_STYLES[detail.type] ?? TYPE_STYLES.gap_analysis).label}
                      </span>
                      <span className="text-xs px-2 py-0.5 rounded-full bg-[#1e2d42] text-[#7d92b0]">{detail.framework}</span>
                      <span className={`text-xs px-2 py-0.5 rounded-full ${(STATUS_META[detail.status] ?? STATUS_META.draft).badge}`}>
                        {(STATUS_META[detail.status] ?? STATUS_META.draft).label}
                      </span>
                    </div>
                  </div>
                  {detail.score !== null && (
                    <div className="flex flex-col items-center shrink-0">
                      <ScoreCircle score={detail.score} />
                      <div className="text-[#7d92b0] text-xs mt-1">/ 100</div>
                    </div>
                  )}
                </div>
                {detail.score !== null && (
                  <div className="mt-3">
                    <div className="h-2 bg-[#1e2d42] rounded-full overflow-hidden">
                      <div className="h-full bg-green-500 rounded-full transition-all" style={{ width: `${detail.score}%` }} />
                    </div>
                    <div className="text-[#7d92b0] text-xs mt-1">スコア: {detail.score} / 100</div>
                  </div>
                )}
                <div className="flex gap-2 mt-3">
                  <button className="flex items-center gap-1.5 px-3 py-1.5 border border-[#1e2d42] hover:border-[#7d92b0] text-[#7d92b0] hover:text-white rounded-lg text-xs transition-colors">
                    <Pencil size={12} /> 編集
                  </button>
                  <button onClick={() => exportPDF.mutate(detail.id)} className="flex items-center gap-1.5 px-3 py-1.5 border border-[#1e2d42] hover:border-[#e8002d] text-[#7d92b0] hover:text-[#e8002d] rounded-lg text-xs transition-colors">
                    <Download size={12} /> PDFエクスポート
                  </button>
                </div>
              </div>

              <div className="p-5 space-y-6 overflow-y-auto max-h-[520px]">
                {/* Findings */}
                {detail.findings.length > 0 && (
                  <div>
                    <h3 className="font-semibold text-white text-sm mb-3">調査結果 ({detail.findings.length}件)</h3>
                    <div className="space-y-3">
                      {detail.findings.map(f => {
                        const sev = SEV_STYLES[f.severity] ?? SEV_STYLES.low
                        return (
                          <div key={f.id} className="bg-[#070d19] border border-[#1e2d42] rounded-lg p-3 space-y-2">
                            <div className="flex items-center gap-2 flex-wrap">
                              <span className="text-xs px-2 py-0.5 rounded-sm bg-[#1e2d42] text-[#7d92b0] font-mono">{f.category}</span>
                              <span className={`text-xs px-2 py-0.5 rounded-full ${sev.badge}`}>{sev.label}</span>
                            </div>
                            <p className="text-white text-xs leading-relaxed">{f.description}</p>
                            <div className="border-t border-[#1e2d42] pt-2">
                              <span className="text-[#7d92b0] text-xs">推奨: </span>
                              <span className="text-[#7d92b0] text-xs">{f.recommendation}</span>
                            </div>
                          </div>
                        )
                      })}
                    </div>
                  </div>
                )}

                {/* Recommendations */}
                {detail.recommendations.length > 0 && (
                  <div>
                    <h3 className="font-semibold text-white text-sm mb-3">推奨事項</h3>
                    <ol className="space-y-2">
                      {detail.recommendations.map((rec, i) => (
                        <li key={i} className="flex gap-3 text-sm">
                          <span className="w-6 h-6 rounded-full bg-[#e8002d]/20 text-[#e8002d] text-xs flex items-center justify-center font-bold shrink-0 mt-0.5">{i + 1}</span>
                          <span className="text-[#7d92b0] leading-relaxed">{rec}</span>
                        </li>
                      ))}
                    </ol>
                  </div>
                )}

                {/* Evidence */}
                <div>
                  <h3 className="font-semibold text-white text-sm mb-3">証拠一覧</h3>
                  <div className="border-2 border-dashed border-[#1e2d42] rounded-xl p-8 flex flex-col items-center justify-center text-center hover:border-[#7d92b0] transition-colors cursor-pointer">
                    <Upload size={24} className="text-[#7d92b0] mb-2" />
                    <div className="text-[#7d92b0] text-sm">ファイルをドロップするか</div>
                    <button className="text-[#e8002d] text-sm hover:underline mt-0.5">クリックしてアップロード</button>
                    <div className="text-[#7d92b0] text-xs mt-2">PDF, PNG, DOCX — 最大50MB</div>
                  </div>
                </div>
              </div>
            </div>
          )}
        </div>
      </div>

      {showForm && (
        <div className="fixed inset-0 bg-black/60 flex items-center justify-center z-50 p-4">
          <div className="bg-[#0d1220] border border-[#1e2d42] rounded-xl p-6 w-full max-w-md space-y-4">
            <h3 className="font-semibold text-white">新規セキュリティアセスメント</h3>
            <input placeholder="アセスメント名" className="w-full bg-[#070d19] border border-[#1e2d42] rounded-lg px-3 py-2 text-sm text-white placeholder-[#7d92b0] focus:outline-hidden focus:border-[#e8002d]" />
            <select className="w-full bg-[#070d19] border border-[#1e2d42] rounded-lg px-3 py-2 text-sm text-white focus:outline-hidden focus:border-[#e8002d]">
              {Object.entries(TYPE_STYLES).map(([k, v]) => <option key={k} value={k}>{v.label}</option>)}
            </select>
            <input placeholder="フレームワーク (例: NIST CSF 2.0)" className="w-full bg-[#070d19] border border-[#1e2d42] rounded-lg px-3 py-2 text-sm text-white placeholder-[#7d92b0] focus:outline-hidden focus:border-[#e8002d]" />
            <input placeholder="担当者" className="w-full bg-[#070d19] border border-[#1e2d42] rounded-lg px-3 py-2 text-sm text-white placeholder-[#7d92b0] focus:outline-hidden focus:border-[#e8002d]" />
            <div className="flex gap-3 pt-2">
              <button className="flex-1 bg-[#e8002d] hover:bg-[#c8001d] text-white rounded-lg py-2 text-sm font-medium transition-colors">作成</button>
              <button onClick={() => setShowForm(false)} className="flex-1 border border-[#1e2d42] text-[#7d92b0] hover:text-white rounded-lg py-2 text-sm font-medium transition-colors">キャンセル</button>
            </div>
          </div>
        </div>
      )}
    </div>
  )
}

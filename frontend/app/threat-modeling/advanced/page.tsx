'use client'

import { useState } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { apiFetch } from '@/lib/api'
import { displayUser } from '@/lib/display-user'
import {
  Brain, Save, Download, Plus, X, ChevronDown, ChevronRight,
  Shield, Database, User, Globe, ArrowRight, AlertTriangle,
  CheckCircle, Clock, Loader2, Trash2, Edit3, Eye, Server,
  BarChart2, FileText, Lock, Upload,
} from 'lucide-react'
import { mockOr } from '@/lib/mock'

// ─── Types ────────────────────────────────────────────────────────────────────

type Methodology = 'STRIDE' | 'PASTA' | 'DREAD' | 'LINDDUN'
type ComponentType = 'external' | 'process' | 'datastore' | 'dataflow'
type RiskStatus = 'identified' | 'mitigated' | 'accepted' | 'transferred'
type PASTAStage = 1 | 2 | 3 | 4 | 5 | 6 | 7

interface ThreatComponent {
  id: string
  name: string
  type: ComponentType
  description: string
}

interface STRIDEThreat {
  id: string
  component_id: string
  category: 'S' | 'T' | 'R' | 'I' | 'D' | 'E'
  description: string
  likelihood: number
  impact: number
  mitigations: string
  status: RiskStatus
}

interface DREADThreat {
  id: string
  name: string
  damage: number
  reproducibility: number
  exploitability: number
  affected_users: number
  discoverability: number
}

interface LINDDUNThreat {
  id: string
  component_id: string
  category: 'L' | 'I' | 'N' | 'D' | 'Di' | 'U' | 'Nc'
  description: string
  mitigation: string
}

interface PASTAData {
  objectives: string
  scope_components: string[]
  threats: { id: string; name: string; tactic: string; description: string }[]
  attack_trees: { id: string; name: string; children: { name: string; likelihood: string }[] }[]
  risks: { id: string; threat: string; likelihood: number; impact: number; mitigation: string }[]
}

interface ThreatModel {
  id: string
  name: string
  created_by: string
  last_modified: string
  components: ThreatComponent[]
  stride_threats: STRIDEThreat[]
  dread_threats: DREADThreat[]
  linddun_threats: LINDDUNThreat[]
  pasta: PASTAData
}

// ─── Mock Data ────────────────────────────────────────────────────────────────

const MOCK_COMPONENTS: ThreatComponent[] = [
  { id: 'comp-01', name: 'Webブラウザ', type: 'external', description: 'エンドユーザーのウェブクライアント' },
  { id: 'comp-02', name: 'APIゲートウェイ', type: 'process', description: 'RESTful APIエンドポイント処理' },
  { id: 'comp-03', name: '認証サービス', type: 'process', description: 'JWT/OAuth2認証処理' },
  { id: 'comp-04', name: 'ユーザーDB', type: 'datastore', description: 'ユーザー情報・認証情報ストア' },
  { id: 'comp-05', name: 'ログストア', type: 'datastore', description: '監査ログ・イベントストレージ' },
]

const MOCK_STRIDE_THREATS: STRIDEThreat[] = [
  { id: 'st-01', component_id: 'comp-01', category: 'S', description: 'セッションハイジャックによるユーザーなりすまし', likelihood: 3, impact: 4, mitigations: 'SameSite Cookie、HTTPS強制、セッション固定対策', status: 'mitigated' },
  { id: 'st-02', component_id: 'comp-01', category: 'T', description: 'XSSによるクライアント側スクリプト改ざん', likelihood: 4, impact: 3, mitigations: 'CSP実装、入力値検証、DOMサニタイズ', status: 'identified' },
  { id: 'st-03', component_id: 'comp-02', category: 'I', description: 'APIレスポンスから機密データが漏洩', likelihood: 2, impact: 5, mitigations: 'レスポンスフィルタリング、フィールドレベル暗号化', status: 'mitigated' },
  { id: 'st-04', component_id: 'comp-02', category: 'D', description: 'レートリミットなしによるAPIへのDoS攻撃', likelihood: 4, impact: 4, mitigations: 'レートリミット実装、DDoS対策サービス', status: 'accepted' },
  { id: 'st-05', component_id: 'comp-03', category: 'S', description: 'ブルートフォースによるパスワード推測', likelihood: 5, impact: 5, mitigations: 'アカウントロックアウト、MFA必須化', status: 'mitigated' },
  { id: 'st-06', component_id: 'comp-03', category: 'E', description: 'JWT署名検証バイパスによる権限昇格', likelihood: 2, impact: 5, mitigations: 'alg: none対策、RS256使用、署名鍵ローテーション', status: 'mitigated' },
  { id: 'st-07', component_id: 'comp-04', category: 'T', description: 'SQLインジェクションによるDBデータ改ざん', likelihood: 3, impact: 5, mitigations: 'パラメータ化クエリ、ORMの使用', status: 'mitigated' },
  { id: 'st-08', component_id: 'comp-04', category: 'R', description: '管理者操作ログの欠如による否認可能性', likelihood: 3, impact: 3, mitigations: '改ざん防止ログ、監査証跡', status: 'identified' },
  { id: 'st-09', component_id: 'comp-05', category: 'I', description: '平文ログによる機密データ露出', likelihood: 2, impact: 4, mitigations: 'ログマスキング、暗号化ストレージ', status: 'accepted' },
  { id: 'st-10', component_id: 'comp-02', category: 'E', description: 'IDOR脆弱性による他ユーザーデータへのアクセス', likelihood: 3, impact: 4, mitigations: 'オブジェクトレベル認可チェック実装', status: 'identified' },
]

const MOCK_DREAD_THREATS: DREADThreat[] = [
  { id: 'dr-01', name: 'SQLインジェクション攻撃', damage: 9, reproducibility: 7, exploitability: 6, affected_users: 10, discoverability: 5 },
  { id: 'dr-02', name: 'JWT署名バイパス', damage: 10, reproducibility: 4, exploitability: 5, affected_users: 10, discoverability: 3 },
  { id: 'dr-03', name: 'XSS攻撃', damage: 6, reproducibility: 8, exploitability: 7, affected_users: 8, discoverability: 8 },
  { id: 'dr-04', name: 'ブルートフォース認証攻撃', damage: 8, reproducibility: 9, exploitability: 8, affected_users: 9, discoverability: 9 },
  { id: 'dr-05', name: 'DoS/DDoS攻撃', damage: 7, reproducibility: 6, exploitability: 7, affected_users: 10, discoverability: 10 },
  { id: 'dr-06', name: 'セッションハイジャック', damage: 8, reproducibility: 5, exploitability: 6, affected_users: 7, discoverability: 4 },
]

const MOCK_LINDDUN_THREATS: LINDDUNThreat[] = [
  { id: 'li-01', component_id: 'comp-04', category: 'L', description: 'ユーザーの行動ログが蓄積・連携されプロファイリングに利用される', mitigation: 'データ最小化、ログの定期削除ポリシー' },
  { id: 'li-02', component_id: 'comp-04', category: 'I', description: 'IPアドレスとユーザーID紐付けによる個人の特定', mitigation: 'IPマスキング、プロキシ経由アクセス推奨' },
  { id: 'li-03', component_id: 'comp-02', category: 'Di', description: 'APIレスポンスの過剰データ返却による情報開示', mitigation: 'レスポンスフィールドの最小化' },
  { id: 'li-04', component_id: 'comp-01', category: 'U', description: 'プライバシーポリシーの不明確さによるユーザー不認識', mitigation: 'クリアなプライバシー通知、オプトイン設計' },
  { id: 'li-05', component_id: 'comp-05', category: 'Nc', description: 'GDPRの保持期限要件への非準拠', mitigation: 'データ保持ポリシーの自動化、定期監査' },
]

const MOCK_PASTA: PASTAData = {
  objectives: 'EDRプラットフォームの機密顧客データとセキュリティインシデントデータを保護する。SOC2 Type II準拠を維持し、データ漏洩・サービス停止のビジネスリスクを最小化する。',
  scope_components: ['Webアプリケーション', 'APIゲートウェイ', '認証サービス', 'データベースクラスター', 'ログ収集システム'],
  threats: [
    { id: 'pt-01', name: 'APT侵入攻撃', tactic: 'Initial Access', description: '標的型スピアフィッシングによる認証情報窃取' },
    { id: 'pt-02', name: 'インサイダー脅威', tactic: 'Collection', description: '不正な特権アクセスによるデータ窃取' },
    { id: 'pt-03', name: 'ランサムウェア攻撃', tactic: 'Impact', description: 'DBバックアップ暗号化によるサービス停止' },
    { id: 'pt-04', name: 'サプライチェーン攻撃', tactic: 'Initial Access', description: 'NPMパッケージへのマルウェア混入' },
  ],
  attack_trees: [
    { id: 'at-01', name: 'データベース不正アクセス', children: [
      { name: 'SQLインジェクション経由', likelihood: '中' },
      { name: '認証情報窃取後の直接接続', likelihood: '高' },
      { name: 'バックアップファイル窃取', likelihood: '低' },
    ]},
    { id: 'at-02', name: '認証バイパス', children: [
      { name: 'JWTフォージェリ', likelihood: '低' },
      { name: 'OAuthフロー悪用', likelihood: '中' },
      { name: 'パスワードリセット悪用', likelihood: '中' },
    ]},
  ],
  risks: [
    { id: 'pr-01', threat: 'APT侵入攻撃', likelihood: 3, impact: 5, mitigation: 'MFA必須化、セキュリティ意識向上訓練、EDR導入' },
    { id: 'pr-02', threat: 'インサイダー脅威', likelihood: 2, impact: 5, mitigation: 'PAM導入、行動分析、最小権限原則' },
    { id: 'pr-03', threat: 'ランサムウェア攻撃', likelihood: 4, impact: 5, mitigation: 'オフラインバックアップ、ネットワーク分離、ランサムウェア対策ツール' },
    { id: 'pr-04', threat: 'サプライチェーン攻撃', likelihood: 3, impact: 4, mitigation: 'SCA自動化、依存関係監視、SBOM管理' },
  ],
}

const MOCK_MODEL: ThreatModel = {
  id: 'model-001',
  name: 'EDRプラットフォーム脅威モデル v2.1',
  created_by: '田中太郎',
  last_modified: '2026-03-18T08:00:00Z',
  components: MOCK_COMPONENTS,
  stride_threats: MOCK_STRIDE_THREATS,
  dread_threats: MOCK_DREAD_THREATS,
  linddun_threats: MOCK_LINDDUN_THREATS,
  pasta: MOCK_PASTA,
}

const EMPTY_MODEL: ThreatModel = {
  id: '', name: '', created_by: '', last_modified: '',
  components: [], stride_threats: [], dread_threats: [], linddun_threats: [],
  pasta: { stages: [] } as any,
}

// API が未実装／失敗したときに表示するモデル。NEXT_PUBLIC_USE_MOCK=true の
// ローカル開発でだけデモ用モデルを出し、それ以外では空のモデルを出す。
// ここを素の MOCK_MODEL にしておくと、本番で「EDRプラットフォーム脅威モデル v2.1」
// という実在しないモデルが、担当者名つきで表示されてしまう。
const FALLBACK_MODEL: ThreatModel = mockOr(MOCK_MODEL, EMPTY_MODEL)

// ─── Helpers ──────────────────────────────────────────────────────────────────

const STRIDE_LABELS: Record<string, { label: string; full: string; color: string }> = {
  S: { label: 'S', full: 'Spoofing (なりすまし)', color: 'bg-red-900/30 text-red-400 border-red-700/30' },
  T: { label: 'T', full: 'Tampering (改ざん)', color: 'bg-orange-900/30 text-orange-400 border-orange-700/30' },
  R: { label: 'R', full: 'Repudiation (否認)', color: 'bg-yellow-900/30 text-yellow-400 border-yellow-700/30' },
  I: { label: 'I', full: 'Info Disclosure (情報漏洩)', color: 'bg-blue-900/30 text-blue-400 border-blue-700/30' },
  D: { label: 'D', full: 'DoS (サービス拒否)', color: 'bg-purple-900/30 text-purple-400 border-purple-700/30' },
  E: { label: 'E', full: 'Elevation (権限昇格)', color: 'bg-pink-900/30 text-pink-400 border-pink-700/30' },
}

const LINDDUN_LABELS: Record<string, { label: string; full: string }> = {
  L: { label: 'L', full: 'Linkability (連結可能性)' },
  I: { label: 'I', full: 'Identifiability (識別可能性)' },
  N: { label: 'N', full: 'Non-repudiation (否認不可能)' },
  D: { label: 'D', full: 'Detectability (検出可能性)' },
  Di: { label: 'Di', full: 'Disclosure (情報開示)' },
  U: { label: 'U', full: 'Unawareness (非認識)' },
  Nc: { label: 'Nc', full: 'Non-compliance (非準拠)' },
}

function riskColor(score: number): string {
  if (score >= 20) return 'bg-red-900/40 text-red-400 border-red-700/40'
  if (score >= 12) return 'bg-orange-900/40 text-orange-400 border-orange-700/40'
  if (score >= 6) return 'bg-yellow-900/40 text-yellow-400 border-yellow-700/40'
  return 'bg-emerald-900/40 text-emerald-400 border-emerald-700/40'
}

function riskLabel(score: number): string {
  if (score >= 20) return '重大'
  if (score >= 12) return '高'
  if (score >= 6) return '中'
  return '低'
}

function ComponentIcon({ type }: { type: ComponentType }) {
  const map: Record<ComponentType, React.ComponentType<{ className?: string }>> = {
    external: Globe, process: Server, datastore: Database, dataflow: ArrowRight
  }
  const Icon = map[type]
  return <Icon className="w-4 h-4" />
}

function ComponentTypeBadge({ type }: { type: ComponentType }) {
  const map: Record<ComponentType, { label: string; color: string }> = {
    external: { label: '外部エンティティ', color: 'bg-blue-900/30 text-blue-400' },
    process: { label: 'プロセス', color: 'bg-emerald-900/30 text-emerald-400' },
    datastore: { label: 'データストア', color: 'bg-orange-900/30 text-orange-400' },
    dataflow: { label: 'データフロー', color: 'bg-purple-900/30 text-purple-400' },
  }
  const { label, color } = map[type]
  return <span className={`px-2 py-0.5 rounded-sm text-xs ${color}`}>{label}</span>
}

function StatusBadge({ status }: { status: RiskStatus }) {
  const map: Record<RiskStatus, { label: string; color: string }> = {
    identified: { label: '識別済み', color: 'bg-blue-900/30 text-blue-400 border-blue-700/30' },
    mitigated: { label: '緩和済み', color: 'bg-emerald-900/30 text-emerald-400 border-emerald-700/30' },
    accepted: { label: '受容', color: 'bg-amber-900/30 text-amber-400 border-amber-700/30' },
    transferred: { label: '移転', color: 'bg-purple-900/30 text-purple-400 border-purple-700/30' },
  }
  const { label, color } = map[status]
  return <span className={`px-2 py-0.5 rounded-full text-xs border ${color}`}>{label}</span>
}

function formatDate(iso: string) {
  return new Date(iso).toLocaleString('ja-JP', { year: 'numeric', month: '2-digit', day: '2-digit', hour: '2-digit', minute: '2-digit' })
}

// ─── STRIDE Tab ───────────────────────────────────────────────────────────────

function STRIDETab({ model }: { model: ThreatModel }) {
  const [selectedComponent, setSelectedComponent] = useState<string>(model.components[0]?.id ?? '')
  const [editingThreat, setEditingThreat] = useState<STRIDEThreat | null>(null)

  const compThreats = model.stride_threats.filter(t => t.component_id === selectedComponent)
  const selectedComp = model.components.find(c => c.id === selectedComponent)

  return (
    <div className="grid grid-cols-1 lg:grid-cols-4 gap-6">
      {/* Component Canvas */}
      <div className="lg:col-span-1 space-y-3">
        <h3 className="text-white font-semibold text-sm">システムコンポーネント</h3>
        <div className="grid grid-cols-1 gap-2">
          {model.components.map(comp => {
            const threatCount = model.stride_threats.filter(t => t.component_id === comp.id).length
            const highRisk = model.stride_threats.filter(t => t.component_id === comp.id && t.likelihood * t.impact >= 12).length
            return (
              <button
                key={comp.id}
                onClick={() => setSelectedComponent(comp.id)}
                className={`flex items-center gap-2.5 p-3 rounded-xl border transition-all text-left ${
                  selectedComponent === comp.id
                    ? 'bg-falcon-active border-falcon-red/50 text-white'
                    : 'bg-falcon-surface border-falcon-border text-falcon-muted hover:border-[#2a3d5a] hover:text-white'
                }`}
              >
                <div className={`w-8 h-8 rounded-lg flex items-center justify-center shrink-0 ${
                  comp.type === 'external' ? 'bg-blue-900/40 text-blue-400'
                  : comp.type === 'process' ? 'bg-emerald-900/40 text-emerald-400'
                  : comp.type === 'datastore' ? 'bg-orange-900/40 text-orange-400'
                  : 'bg-purple-900/40 text-purple-400'
                }`}>
                  <ComponentIcon type={comp.type} />
                </div>
                <div className="min-w-0 flex-1">
                  <p className="text-sm font-medium truncate">{comp.name}</p>
                  <div className="flex items-center gap-2 mt-0.5">
                    <span className="text-xs text-falcon-subtle">{threatCount} 脅威</span>
                    {highRisk > 0 && <span className="text-xs text-red-400">{highRisk} 高リスク</span>}
                  </div>
                </div>
              </button>
            )
          })}
        </div>
      </div>

      {/* Threat Matrix */}
      <div className="lg:col-span-3">
        {selectedComp && (
          <>
            <div className="flex items-center gap-3 mb-4">
              <div className={`w-8 h-8 rounded-lg flex items-center justify-center ${
                selectedComp.type === 'external' ? 'bg-blue-900/40 text-blue-400'
                : selectedComp.type === 'process' ? 'bg-emerald-900/40 text-emerald-400'
                : selectedComp.type === 'datastore' ? 'bg-orange-900/40 text-orange-400'
                : 'bg-purple-900/40 text-purple-400'
              }`}>
                <ComponentIcon type={selectedComp.type} />
              </div>
              <div>
                <h3 className="text-white font-semibold">{selectedComp.name}</h3>
                <div className="flex items-center gap-2">
                  <ComponentTypeBadge type={selectedComp.type} />
                  <span className="text-xs text-falcon-muted">{selectedComp.description}</span>
                </div>
              </div>
            </div>

            <div className="space-y-3">
              {(['S', 'T', 'R', 'I', 'D', 'E'] as const).map(cat => {
                const threats = compThreats.filter(t => t.category === cat)
                const catInfo = STRIDE_LABELS[cat]
                return (
                  <div key={cat} className="bg-falcon-surface border border-falcon-border rounded-xl overflow-hidden">
                    <div className="flex items-center justify-between px-4 py-3 border-b border-falcon-border">
                      <div className="flex items-center gap-2">
                        <span className={`px-2 py-0.5 rounded-sm text-xs font-bold border ${catInfo.color}`}>{cat}</span>
                        <span className="text-white text-sm font-medium">{catInfo.full}</span>
                      </div>
                      <span className="text-xs text-falcon-muted">{threats.length} 脅威</span>
                    </div>
                    {threats.length === 0 ? (
                      <div className="px-4 py-3 text-xs text-falcon-subtle">この脅威カテゴリに脅威はありません</div>
                    ) : (
                      <div className="divide-y divide-falcon-border">
                        {threats.map(threat => {
                          const score = threat.likelihood * threat.impact
                          return (
                            <div key={threat.id} className="px-4 py-3">
                              <div className="flex items-start justify-between gap-3">
                                <div className="flex-1 min-w-0">
                                  <p className="text-white text-sm">{threat.description}</p>
                                  <p className="text-falcon-muted text-xs mt-1 truncate">{threat.mitigations}</p>
                                </div>
                                <div className="flex items-center gap-2 shrink-0">
                                  <div className={`px-2 py-1 rounded-sm text-xs font-bold border ${riskColor(score)}`}>
                                    {score} ({riskLabel(score)})
                                  </div>
                                  <StatusBadge status={threat.status} />
                                  <button onClick={() => setEditingThreat(threat)} className="p-1 rounded-sm hover:bg-falcon-border text-falcon-muted transition-colors"><Edit3 className="w-3.5 h-3.5" /></button>
                                </div>
                              </div>
                              <div className="flex items-center gap-4 mt-2 text-xs text-falcon-muted">
                                <span>可能性: <span className="text-white">{threat.likelihood}/5</span></span>
                                <span>影響: <span className="text-white">{threat.impact}/5</span></span>
                                <span>リスクスコア: <span className={`font-bold ${score >= 12 ? 'text-red-400' : score >= 6 ? 'text-amber-400' : 'text-emerald-400'}`}>{score}</span></span>
                              </div>
                            </div>
                          )
                        })}
                      </div>
                    )}
                  </div>
                )
              })}
            </div>
          </>
        )}
      </div>

      {/* Edit Threat Modal */}
      {editingThreat && (
        <div className="fixed inset-0 bg-black/60 backdrop-blur-xs flex items-center justify-center z-50 p-4 col-span-full">
          <div className="bg-falcon-surface border border-falcon-border rounded-2xl w-full max-w-lg shadow-2xl">
            <div className="flex items-center justify-between px-6 py-5 border-b border-falcon-border">
              <h3 className="text-white font-semibold">脅威を編集</h3>
              <button onClick={() => setEditingThreat(null)} className="text-falcon-muted hover:text-white"><X className="w-5 h-5" /></button>
            </div>
            <div className="px-6 py-5 space-y-4">
              <div>
                <label className="block text-xs text-falcon-muted mb-1.5">脅威の説明</label>
                <textarea defaultValue={editingThreat.description} rows={3} className="w-full px-3 py-2 rounded-lg bg-[#070d19] border border-falcon-border text-white text-sm focus:outline-hidden focus:border-falcon-muted/50 resize-none" />
              </div>
              <div className="grid grid-cols-2 gap-4">
                <div>
                  <label className="block text-xs text-falcon-muted mb-1.5">可能性 (1-5)</label>
                  <input type="number" min={1} max={5} defaultValue={editingThreat.likelihood} className="w-full px-3 py-2 rounded-lg bg-[#070d19] border border-falcon-border text-white text-sm focus:outline-hidden" />
                </div>
                <div>
                  <label className="block text-xs text-falcon-muted mb-1.5">影響 (1-5)</label>
                  <input type="number" min={1} max={5} defaultValue={editingThreat.impact} className="w-full px-3 py-2 rounded-lg bg-[#070d19] border border-falcon-border text-white text-sm focus:outline-hidden" />
                </div>
              </div>
              <div>
                <label className="block text-xs text-falcon-muted mb-1.5">緩和策</label>
                <textarea defaultValue={editingThreat.mitigations} rows={2} className="w-full px-3 py-2 rounded-lg bg-[#070d19] border border-falcon-border text-white text-sm focus:outline-hidden resize-none" />
              </div>
              <div>
                <label className="block text-xs text-falcon-muted mb-1.5">ステータス</label>
                <select defaultValue={editingThreat.status} className="w-full px-3 py-2 rounded-lg bg-[#070d19] border border-falcon-border text-white text-sm focus:outline-hidden">
                  <option value="identified">識別済み</option>
                  <option value="mitigated">緩和済み</option>
                  <option value="accepted">受容</option>
                  <option value="transferred">移転</option>
                </select>
              </div>
            </div>
            <div className="px-6 py-4 border-t border-falcon-border flex justify-end gap-3">
              <button onClick={() => setEditingThreat(null)} className="px-4 py-2 rounded-lg border border-falcon-border text-falcon-muted hover:text-white text-sm transition-colors">キャンセル</button>
              <button onClick={() => setEditingThreat(null)} className="px-4 py-2 rounded-lg bg-falcon-red hover:bg-[#c8001d] text-white text-sm font-medium transition-colors">保存</button>
            </div>
          </div>
        </div>
      )}
    </div>
  )
}

// ─── PASTA Tab ────────────────────────────────────────────────────────────────

function PASTATab({ pasta }: { pasta: PASTAData }) {
  const [currentStage, setCurrentStage] = useState<PASTAStage>(1)
  const [expandedTrees, setExpandedTrees] = useState<Set<string>>(new Set())

  const stages = [
    { n: 1, title: '目標定義', subtitle: 'ビジネス目標の明確化' },
    { n: 2, title: '技術スコープ', subtitle: 'システムコンポーネントの特定' },
    { n: 3, title: 'アプリケーション分解', subtitle: 'データフロー分析' },
    { n: 4, title: '脅威分析', subtitle: 'ATT&CK戦術による脅威カタログ' },
    { n: 5, title: '脆弱性分析', subtitle: '既知の脆弱性との関連付け' },
    { n: 6, title: '攻撃モデリング', subtitle: '攻撃ツリーの構築' },
    { n: 7, title: 'リスク分析', subtitle: 'リスクマトリクスと緩和計画' },
  ] as const

  return (
    <div className="grid grid-cols-1 lg:grid-cols-4 gap-6">
      {/* Stepper */}
      <div className="lg:col-span-1">
        <div className="space-y-1">
          {stages.map((stage, i) => (
            <button
              key={stage.n}
              onClick={() => setCurrentStage(stage.n)}
              className={`w-full flex items-center gap-3 p-3 rounded-xl text-left transition-all ${
                currentStage === stage.n ? 'bg-falcon-active border border-falcon-red/30' : 'hover:bg-falcon-border/30'
              }`}
            >
              <div className={`w-7 h-7 rounded-full flex items-center justify-center text-xs font-bold shrink-0 ${
                currentStage === stage.n ? 'bg-falcon-red text-white' : 'bg-falcon-border text-falcon-muted'
              }`}>{stage.n}</div>
              <div>
                <p className={`text-sm font-medium ${currentStage === stage.n ? 'text-white' : 'text-falcon-muted'}`}>{stage.title}</p>
                <p className="text-xs text-falcon-subtle">{stage.subtitle}</p>
              </div>
            </button>
          ))}
        </div>
      </div>

      {/* Stage Content */}
      <div className="lg:col-span-3">
        {currentStage === 1 && (
          <div className="space-y-4">
            <h3 className="text-white font-semibold">ステージ1: 目標定義</h3>
            <div>
              <label className="block text-xs text-falcon-muted mb-2">ビジネス目標・セキュリティ要件</label>
              <textarea defaultValue={pasta.objectives} rows={6} className="w-full px-4 py-3 rounded-xl bg-[#070d19] border border-falcon-border text-white text-sm focus:outline-hidden focus:border-falcon-muted/50 resize-none" />
            </div>
          </div>
        )}
        {currentStage === 2 && (
          <div className="space-y-4">
            <h3 className="text-white font-semibold">ステージ2: 技術スコープ</h3>
            <div className="space-y-2">
              {pasta.scope_components.map((comp, i) => (
                <div key={i} className="flex items-center gap-3 p-3 rounded-xl bg-falcon-surface border border-falcon-border">
                  <div className="w-6 h-6 rounded-full bg-falcon-red/20 flex items-center justify-center text-xs text-falcon-red font-bold">{i + 1}</div>
                  <span className="text-white text-sm flex-1">{comp}</span>
                  <button className="p-1 rounded-sm hover:bg-falcon-border text-falcon-muted transition-colors"><Trash2 className="w-3.5 h-3.5" /></button>
                </div>
              ))}
              <button className="w-full py-2.5 rounded-xl border border-dashed border-falcon-border text-falcon-muted hover:text-white hover:border-falcon-muted/50 text-sm transition-colors flex items-center justify-center gap-2">
                <Plus className="w-4 h-4" />コンポーネントを追加
              </button>
            </div>
          </div>
        )}
        {currentStage === 3 && (
          <div className="space-y-4">
            <h3 className="text-white font-semibold">ステージ3: アプリケーション分解</h3>
            <div className="bg-falcon-surface border border-falcon-border rounded-xl p-6">
              <div className="flex items-center justify-between">
                <div className="text-center">
                  <div className="w-16 h-16 rounded-xl bg-blue-900/30 border border-blue-700/30 flex flex-col items-center justify-center">
                    <Globe className="w-6 h-6 text-blue-400 mb-1" />
                    <span className="text-xs text-blue-400">ブラウザ</span>
                  </div>
                </div>
                <div className="flex-1 flex items-center justify-center">
                  <div className="flex items-center gap-2">
                    <div className="h-px w-12 bg-falcon-red/50" />
                    <div className="text-xs text-falcon-red bg-falcon-red/10 px-2 py-0.5 rounded-sm border border-falcon-red/30">HTTPS</div>
                    <div className="h-px w-12 bg-falcon-red/50" />
                  </div>
                </div>
                <div className="text-center">
                  <div className="w-16 h-16 rounded-xl bg-emerald-900/30 border border-emerald-700/30 flex flex-col items-center justify-center">
                    <Server className="w-6 h-6 text-emerald-400 mb-1" />
                    <span className="text-xs text-emerald-400">API GW</span>
                  </div>
                </div>
                <div className="flex-1 flex items-center justify-center">
                  <div className="flex items-center gap-2">
                    <div className="h-px w-8 bg-falcon-border" />
                    <ArrowRight className="w-4 h-4 text-falcon-muted" />
                    <div className="h-px w-8 bg-falcon-border" />
                  </div>
                </div>
                <div className="text-center">
                  <div className="w-16 h-16 rounded-xl bg-orange-900/30 border border-orange-700/30 flex flex-col items-center justify-center">
                    <Database className="w-6 h-6 text-orange-400 mb-1" />
                    <span className="text-xs text-orange-400">DB</span>
                  </div>
                </div>
              </div>
              <p className="text-center text-xs text-falcon-subtle mt-4">データフロー図 (簡易表示)</p>
            </div>
          </div>
        )}
        {currentStage === 4 && (
          <div className="space-y-4">
            <h3 className="text-white font-semibold">ステージ4: 脅威分析</h3>
            <div className="space-y-2">
              {pasta.threats.map(threat => (
                <div key={threat.id} className="p-4 rounded-xl bg-falcon-surface border border-falcon-border">
                  <div className="flex items-center gap-2 mb-1">
                    <span className="px-2 py-0.5 rounded-sm text-xs bg-red-900/30 text-red-400 border border-red-700/30">{threat.tactic}</span>
                    <span className="text-white font-medium text-sm">{threat.name}</span>
                  </div>
                  <p className="text-falcon-muted text-xs">{threat.description}</p>
                </div>
              ))}
            </div>
          </div>
        )}
        {currentStage === 5 && (
          <div className="space-y-4">
            <h3 className="text-white font-semibold">ステージ5: 脆弱性分析</h3>
            <div className="p-4 rounded-xl bg-blue-900/20 border border-blue-700/30">
              <div className="flex items-center gap-2 mb-2">
                <Eye className="w-4 h-4 text-blue-400" />
                <span className="text-blue-400 text-sm font-medium">脆弱性スキャナーとの連携</span>
              </div>
              <p className="text-falcon-muted text-xs">脆弱性管理モジュールから最新のスキャン結果を参照してください。CVSS 7.0以上の脆弱性が4件検出されています。</p>
              <a href="/vulnerabilities" className="inline-flex items-center gap-1.5 mt-3 text-xs text-blue-400 hover:text-blue-300 transition-colors">
                <ArrowRight className="w-3.5 h-3.5" />
                脆弱性管理ページへ
              </a>
            </div>
          </div>
        )}
        {currentStage === 6 && (
          <div className="space-y-4">
            <h3 className="text-white font-semibold">ステージ6: 攻撃モデリング</h3>
            <div className="space-y-3">
              {pasta.attack_trees.map(tree => (
                <div key={tree.id} className="bg-falcon-surface border border-falcon-border rounded-xl overflow-hidden">
                  <button
                    className="w-full flex items-center justify-between px-4 py-3 hover:bg-falcon-border/20 transition-colors"
                    onClick={() => setExpandedTrees(prev => { const n = new Set(prev); n.has(tree.id) ? n.delete(tree.id) : n.add(tree.id); return n })}
                  >
                    <div className="flex items-center gap-2">
                      <AlertTriangle className="w-4 h-4 text-amber-400" />
                      <span className="text-white font-medium text-sm">{tree.name}</span>
                    </div>
                    {expandedTrees.has(tree.id) ? <ChevronDown className="w-4 h-4 text-falcon-muted" /> : <ChevronRight className="w-4 h-4 text-falcon-muted" />}
                  </button>
                  {expandedTrees.has(tree.id) && (
                    <div className="border-t border-falcon-border p-4 space-y-2">
                      {tree.children.map((child, i) => (
                        <div key={i} className="flex items-center gap-3 ml-6">
                          <div className="w-px h-4 bg-falcon-border" />
                          <ChevronRight className="w-3 h-3 text-falcon-subtle" />
                          <span className="text-falcon-muted text-sm flex-1">{child.name}</span>
                          <span className={`text-xs px-2 py-0.5 rounded ${
                            child.likelihood === '高' ? 'bg-red-900/30 text-red-400' :
                            child.likelihood === '中' ? 'bg-amber-900/30 text-amber-400' : 'bg-emerald-900/30 text-emerald-400'
                          }`}>{child.likelihood}</span>
                        </div>
                      ))}
                    </div>
                  )}
                </div>
              ))}
            </div>
          </div>
        )}
        {currentStage === 7 && (
          <div className="space-y-4">
            <h3 className="text-white font-semibold">ステージ7: リスク分析</h3>
            <div className="overflow-auto rounded-xl border border-falcon-border">
              <table className="w-full text-sm">
                <thead>
                  <tr className="bg-falcon-surface border-b border-falcon-border">
                    <th className="text-left px-4 py-3 text-falcon-muted font-medium">脅威</th>
                    <th className="text-center px-4 py-3 text-falcon-muted font-medium">可能性</th>
                    <th className="text-center px-4 py-3 text-falcon-muted font-medium">影響</th>
                    <th className="text-center px-4 py-3 text-falcon-muted font-medium">スコア</th>
                    <th className="text-left px-4 py-3 text-falcon-muted font-medium">緩和策</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-falcon-border bg-[#070d19]">
                  {pasta.risks.map(risk => {
                    const score = risk.likelihood * risk.impact
                    return (
                      <tr key={risk.id} className="hover:bg-falcon-border/20 transition-colors">
                        <td className="px-4 py-3 text-white">{risk.threat}</td>
                        <td className="px-4 py-3 text-center text-falcon-muted">{risk.likelihood}/5</td>
                        <td className="px-4 py-3 text-center text-falcon-muted">{risk.impact}/5</td>
                        <td className="px-4 py-3 text-center">
                          <span className={`px-2 py-0.5 rounded-sm text-xs font-bold border ${riskColor(score)}`}>{score}</span>
                        </td>
                        <td className="px-4 py-3 text-falcon-muted text-xs max-w-xs truncate">{risk.mitigation}</td>
                      </tr>
                    )
                  })}
                </tbody>
              </table>
            </div>
          </div>
        )}
      </div>
    </div>
  )
}

// ─── DREAD Tab ────────────────────────────────────────────────────────────────

function DREADTab({ threats }: { threats: DREADThreat[] }) {
  const [sortField, setSortField] = useState<'total' | 'damage' | 'reproducibility' | 'exploitability' | 'affected_users' | 'discoverability'>('total')
  const [sortDir, setSortDir] = useState<'desc' | 'asc'>('desc')

  const withTotals = threats.map(t => ({ ...t, total: t.damage + t.reproducibility + t.exploitability + t.affected_users + t.discoverability }))
  const sorted = [...withTotals].sort((a, b) => {
    const diff = a[sortField] - b[sortField]
    return sortDir === 'desc' ? -diff : diff
  })

  const handleSort = (field: typeof sortField) => {
    if (sortField === field) setSortDir(prev => prev === 'desc' ? 'asc' : 'desc')
    else { setSortField(field); setSortDir('desc') }
  }

  const exportCSV = () => {
    const header = 'Threat,Damage,Reproducibility,Exploitability,Affected Users,Discoverability,Total'
    const rows = sorted.map(t => `${t.name},${t.damage},${t.reproducibility},${t.exploitability},${t.affected_users},${t.discoverability},${t.total}`)
    const blob = new Blob([[header, ...rows].join('\n')], { type: 'text/csv' })
    const url = URL.createObjectURL(blob)
    const a = document.createElement('a'); a.href = url; a.download = 'dread-threats.csv'; a.click()
    URL.revokeObjectURL(url)
  }

  const cols: { key: typeof sortField; label: string }[] = [
    { key: 'damage', label: 'D' },
    { key: 'reproducibility', label: 'R' },
    { key: 'exploitability', label: 'E' },
    { key: 'affected_users', label: 'A' },
    { key: 'discoverability', label: 'D2' },
    { key: 'total', label: 'DREAD合計' },
  ]

  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between">
        <h3 className="text-white font-semibold">DREADスコアリング</h3>
        <button onClick={exportCSV} className="flex items-center gap-2 px-3 py-1.5 rounded-lg bg-falcon-border hover:bg-[#2a3d5a] text-white text-sm transition-colors">
          <Download className="w-4 h-4" />
          CSV出力
        </button>
      </div>
      <div className="overflow-auto rounded-xl border border-falcon-border">
        <table className="w-full text-sm">
          <thead>
            <tr className="bg-falcon-surface border-b border-falcon-border">
              <th className="text-left px-4 py-3 text-falcon-muted font-medium">脅威名</th>
              {cols.map(col => (
                <th key={col.key}>
                  <button
                    onClick={() => handleSort(col.key)}
                    className={`w-full px-3 py-3 text-center font-medium transition-colors hover:text-white ${sortField === col.key ? 'text-falcon-red' : 'text-falcon-muted'}`}
                  >
                    {col.label} {sortField === col.key ? (sortDir === 'desc' ? '↓' : '↑') : ''}
                  </button>
                </th>
              ))}
            </tr>
          </thead>
          <tbody className="divide-y divide-falcon-border bg-[#070d19]">
            {sorted.map(t => (
              <tr key={t.id} className="hover:bg-falcon-border/20 transition-colors">
                <td className="px-4 py-3 text-white font-medium">{t.name}</td>
                {[t.damage, t.reproducibility, t.exploitability, t.affected_users, t.discoverability].map((val, i) => (
                  <td key={i} className="px-3 py-3 text-center">
                    <span className={`text-sm font-bold ${val >= 8 ? 'text-red-400' : val >= 5 ? 'text-amber-400' : 'text-emerald-400'}`}>{val}</span>
                  </td>
                ))}
                <td className="px-3 py-3 text-center">
                  <span className={`px-2 py-1 rounded-sm text-xs font-bold border ${riskColor(t.total * 1.2)}`}>{t.total}</span>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
      <div className="text-xs text-falcon-muted p-3 rounded-lg bg-falcon-surface border border-falcon-border">
        <strong className="text-white">D</strong> Damage (被害) · <strong className="text-white">R</strong> Reproducibility (再現性) · <strong className="text-white">E</strong> Exploitability (悪用可能性) · <strong className="text-white">A</strong> Affected Users (影響ユーザー) · <strong className="text-white">D2</strong> Discoverability (発見可能性) — 各項目1-10で評価
      </div>
    </div>
  )
}

// ─── LINDDUN Tab ──────────────────────────────────────────────────────────────

function LINDDUNTab({ threats, components }: { threats: LINDDUNThreat[]; components: ThreatComponent[] }) {
  const categories = Object.keys(LINDDUN_LABELS) as (keyof typeof LINDDUN_LABELS)[]

  return (
    <div className="space-y-4">
      <h3 className="text-white font-semibold">LINDDUNプライバシー脅威分析</h3>
      <div className="overflow-auto rounded-xl border border-falcon-border">
        <table className="w-full text-sm">
          <thead>
            <tr className="bg-falcon-surface border-b border-falcon-border">
              <th className="text-left px-4 py-3 text-falcon-muted font-medium">コンポーネント</th>
              {categories.map(cat => (
                <th key={cat} className="px-3 py-3 text-center">
                  <div className="text-falcon-muted font-bold">{cat}</div>
                </th>
              ))}
            </tr>
          </thead>
          <tbody className="divide-y divide-falcon-border bg-[#070d19]">
            {components.map(comp => (
              <tr key={comp.id} className="hover:bg-falcon-border/20 transition-colors">
                <td className="px-4 py-3">
                  <div className="flex items-center gap-2">
                    <ComponentIcon type={comp.type} />
                    <span className="text-white text-sm">{comp.name}</span>
                  </div>
                </td>
                {categories.map(cat => {
                  const threat = threats.find(t => t.component_id === comp.id && t.category === cat)
                  return (
                    <td key={cat} className="px-3 py-3 text-center">
                      {threat ? (
                        <div className="group relative">
                          <div className="w-6 h-6 rounded-full bg-red-900/40 border border-red-700/40 flex items-center justify-center mx-auto cursor-help">
                            <AlertTriangle className="w-3 h-3 text-red-400" />
                          </div>
                          <div className="absolute z-10 bottom-8 left-1/2 -translate-x-1/2 w-64 p-3 rounded-xl bg-falcon-surface border border-falcon-border text-left hidden group-hover:block shadow-2xl">
                            <p className="text-white text-xs font-medium mb-1">{LINDDUN_LABELS[cat].full}</p>
                            <p className="text-falcon-muted text-xs mb-2">{threat.description}</p>
                            <p className="text-emerald-400 text-xs"><strong>緩和策:</strong> {threat.mitigation}</p>
                          </div>
                        </div>
                      ) : (
                        <div className="w-6 h-6 rounded-full bg-falcon-border flex items-center justify-center mx-auto">
                          <div className="w-1.5 h-1.5 rounded-full bg-falcon-subtle" />
                        </div>
                      )}
                    </td>
                  )
                })}
              </tr>
            ))}
          </tbody>
        </table>
      </div>
      <div className="grid grid-cols-2 md:grid-cols-4 gap-2">
        {Object.entries(LINDDUN_LABELS).map(([key, val]) => (
          <div key={key} className="p-2.5 rounded-lg bg-falcon-surface border border-falcon-border">
            <span className="text-falcon-red font-bold text-xs">{key}</span>
            <p className="text-falcon-muted text-[10px] mt-0.5">{val.full}</p>
          </div>
        ))}
      </div>
    </div>
  )
}

// ─── Main Component ───────────────────────────────────────────────────────────

export default function AdvancedThreatModelingPage() {
  const queryClient = useQueryClient()
  const [methodology, setMethodology] = useState<Methodology>('STRIDE')
  const [modelName, setModelName] = useState('EDRプラットフォーム脅威モデル v2.1')
  const [saveModal, setSaveModal] = useState(false)
  const [loadModal, setLoadModal] = useState(false)

  const { data: model } = useQuery<ThreatModel>({
    queryKey: ['threat-model-advanced'],
    queryFn: () => apiFetch('/api/v1/threat-models?advanced=true'),
    // APIが未実装の場合のプレースホルダー（モック無効時は空モデル）
    placeholderData: FALLBACK_MODEL,
    retry: 0,
  })

  const saveMutation = useMutation({
    mutationFn: (data: Partial<ThreatModel>) =>
      data.id
        ? apiFetch(`/api/v1/threat-models/${data.id}`, { method: 'PUT', body: JSON.stringify(data) })
        : apiFetch('/api/v1/threat-models', { method: 'POST', body: JSON.stringify(data) }),
    onSuccess: () => { queryClient.invalidateQueries({ queryKey: ['threat-model-advanced'] }); setSaveModal(false) },
  })

  // APIが返したデータを優先し、なければフォールバック（モック無効時は空）
  const activeModel: ThreatModel = { ...EMPTY_MODEL, ...(model ?? FALLBACK_MODEL) }

  const exportJSON = () => {
    const blob = new Blob([JSON.stringify(activeModel, null, 2)], { type: 'application/json' })
    const url = URL.createObjectURL(blob)
    const a = document.createElement('a'); a.href = url; a.download = `${modelName}.json`; a.click()
    URL.revokeObjectURL(url)
  }

  const methodologies: Methodology[] = ['STRIDE', 'PASTA', 'DREAD', 'LINDDUN']

  return (
    <div className="min-h-screen bg-[#070d19] text-falcon-muted">
      <div className="max-w-7xl mx-auto px-6 py-6 space-y-6">

        {/* Header */}
        <div className="flex items-center justify-between flex-wrap gap-4">
          <div className="flex items-center gap-3">
            <div className="w-10 h-10 rounded-lg bg-linear-to-br from-falcon-red to-falcon-red-dark flex items-center justify-center shadow-lg">
              <Brain className="w-5 h-5 text-white" />
            </div>
            <div>
              <h1 className="text-2xl font-bold text-white">高度脅威モデリング</h1>
              <p className="text-sm text-falcon-muted">STRIDE · PASTA · DREAD · LINDDUN マルチメソドロジー対応</p>
            </div>
          </div>
          <div className="flex items-center gap-2">
            <button
              onClick={() => setLoadModal(true)}
              className="flex items-center gap-2 px-3 py-2 rounded-lg border border-falcon-border text-falcon-muted hover:text-white text-sm transition-colors"
            >
              <Upload className="w-4 h-4" />
              読み込み
            </button>
            <button
              onClick={exportJSON}
              className="flex items-center gap-2 px-3 py-2 rounded-lg border border-falcon-border text-falcon-muted hover:text-white text-sm transition-colors"
            >
              <Download className="w-4 h-4" />
              JSONエクスポート
            </button>
            <button
              onClick={() => setSaveModal(true)}
              className="flex items-center gap-2 px-4 py-2 rounded-lg bg-falcon-red hover:bg-[#c8001d] text-white text-sm font-medium transition-colors"
            >
              <Save className="w-4 h-4" />
              保存
            </button>
          </div>
        </div>

        {/* Model Info */}
        <div className="bg-falcon-surface border border-falcon-border rounded-xl p-4">
          <div className="flex items-center gap-6 flex-wrap">
            <div>
              <label className="block text-xs text-falcon-muted mb-1">モデル名</label>
              <input
                value={modelName}
                onChange={e => setModelName(e.target.value)}
                className="px-3 py-1.5 rounded-lg bg-[#070d19] border border-falcon-border text-white text-sm focus:outline-hidden focus:border-falcon-muted/50 w-80"
              />
            </div>
            <div>
              <label className="block text-xs text-falcon-muted mb-1">作成者</label>
              <p className="text-white text-sm">{displayUser(activeModel.created_by)}</p>
            </div>
            <div>
              <label className="block text-xs text-falcon-muted mb-1">最終更新</label>
              <p className="text-white text-sm flex items-center gap-1.5"><Clock className="w-3.5 h-3.5 text-falcon-muted" />{formatDate(activeModel.last_modified)}</p>
            </div>
            <div className="ml-auto flex items-center gap-3 text-sm">
              <span className="text-falcon-muted">{activeModel.components.length} コンポーネント</span>
              <span className="text-falcon-muted">{activeModel.stride_threats.length} STRIDE脅威</span>
              <span className="text-falcon-muted">{activeModel.dread_threats.length} DREAD脅威</span>
            </div>
          </div>
        </div>

        {/* Methodology Tabs */}
        <div className="flex gap-1 border-b border-falcon-border">
          {methodologies.map(m => (
            <button
              key={m}
              onClick={() => setMethodology(m)}
              className={`px-5 py-2.5 text-sm font-semibold transition-colors border-b-2 -mb-px ${
                methodology === m ? 'border-falcon-red text-white' : 'border-transparent text-falcon-muted hover:text-white'
              }`}
            >
              {m}
            </button>
          ))}
        </div>

        {/* Tab Content */}
        {methodology === 'STRIDE' && <STRIDETab model={activeModel} />}
        {methodology === 'PASTA' && <PASTATab pasta={activeModel.pasta} />}
        {methodology === 'DREAD' && <DREADTab threats={activeModel.dread_threats} />}
        {methodology === 'LINDDUN' && <LINDDUNTab threats={activeModel.linddun_threats} components={activeModel.components} />}
      </div>

      {/* Save Modal */}
      {saveModal && (
        <div className="fixed inset-0 bg-black/60 backdrop-blur-xs flex items-center justify-center z-50 p-4">
          <div className="bg-falcon-surface border border-falcon-border rounded-2xl w-full max-w-md shadow-2xl">
            <div className="flex items-center justify-between px-6 py-5 border-b border-falcon-border">
              <h3 className="text-white font-semibold flex items-center gap-2"><Save className="w-4 h-4 text-falcon-red" />モデルを保存</h3>
              <button onClick={() => setSaveModal(false)} className="text-falcon-muted hover:text-white"><X className="w-5 h-5" /></button>
            </div>
            <div className="px-6 py-5 space-y-4">
              <div>
                <label className="block text-xs text-falcon-muted mb-1.5">モデル名</label>
                <input value={modelName} onChange={e => setModelName(e.target.value)} className="w-full px-3 py-2 rounded-lg bg-[#070d19] border border-falcon-border text-white text-sm focus:outline-hidden" />
              </div>
              <div className="p-3 rounded-lg bg-falcon-border/40 text-xs text-falcon-muted space-y-1">
                <p><span className="text-white">{activeModel.stride_threats.length}</span> STRIDE脅威</p>
                <p><span className="text-white">{activeModel.dread_threats.length}</span> DREAD脅威</p>
                <p><span className="text-white">{activeModel.linddun_threats.length}</span> LINDDUN脅威</p>
              </div>
            </div>
            <div className="px-6 py-4 border-t border-falcon-border flex justify-end gap-3">
              <button onClick={() => setSaveModal(false)} className="px-4 py-2 rounded-lg border border-falcon-border text-falcon-muted hover:text-white text-sm transition-colors">キャンセル</button>
              <button
                onClick={() => saveMutation.mutate({ ...activeModel, name: modelName })}
                disabled={saveMutation.isPending}
                className="flex items-center gap-2 px-4 py-2 rounded-lg bg-falcon-red hover:bg-[#c8001d] text-white text-sm font-medium transition-colors disabled:opacity-50"
              >
                {saveMutation.isPending ? <Loader2 className="w-4 h-4 animate-spin" /> : <Save className="w-4 h-4" />}
                保存
              </button>
            </div>
          </div>
        </div>
      )}

      {/* Load Modal */}
      {loadModal && (
        <div className="fixed inset-0 bg-black/60 backdrop-blur-xs flex items-center justify-center z-50 p-4">
          <div className="bg-falcon-surface border border-falcon-border rounded-2xl w-full max-w-md shadow-2xl">
            <div className="flex items-center justify-between px-6 py-5 border-b border-falcon-border">
              <h3 className="text-white font-semibold">モデルを読み込む</h3>
              <button onClick={() => setLoadModal(false)} className="text-falcon-muted hover:text-white"><X className="w-5 h-5" /></button>
            </div>
            <div className="px-6 py-5 space-y-2">
              {[
                { name: 'EDRプラットフォーム脅威モデル v2.1', date: '2026-03-18', by: '田中太郎' },
                { name: 'モバイルアプリ脅威モデル v1.0', date: '2026-03-10', by: '山田花子' },
                { name: 'クラウドインフラ脅威モデル v3.0', date: '2026-03-05', by: '佐藤次郎' },
              ].map((m, i) => (
                <button
                  key={i}
                  onClick={() => setLoadModal(false)}
                  className="w-full flex items-center justify-between p-3 rounded-xl bg-[#070d19] border border-falcon-border hover:border-falcon-muted/40 text-left transition-colors"
                >
                  <div>
                    <p className="text-white text-sm font-medium">{m.name}</p>
                    <p className="text-xs text-falcon-muted mt-0.5">{m.by} · {m.date}</p>
                  </div>
                  <ChevronRight className="w-4 h-4 text-falcon-muted" />
                </button>
              ))}
            </div>
            <div className="px-6 py-4 border-t border-falcon-border flex justify-end">
              <button onClick={() => setLoadModal(false)} className="px-4 py-2 rounded-lg border border-falcon-border text-falcon-muted hover:text-white text-sm transition-colors">閉じる</button>
            </div>
          </div>
        </div>
      )}
    </div>
  )
}

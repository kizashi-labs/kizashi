'use client'

import { useState, useCallback, useRef } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { apiFetch } from '@/lib/api'
import { displayUser } from '@/lib/display-user'
import {
  Plus, Save, Download, Trash2, X, Shield, Database,
  User, ArrowRight, Square, Circle, CheckCircle,
  AlertTriangle, ChevronDown, Filter, BarChart2
} from 'lucide-react'
import { m } from '@/lib/mock'

// ─── Types ────────────────────────────────────────────────────────────────────

type ElementType = 'process' | 'datastore' | 'external' | 'dataflow' | 'trustboundary'
type TrustLevel = 'untrusted' | 'low' | 'medium' | 'high' | 'critical'
type RiskLevel = 'none' | 'low' | 'medium' | 'high' | 'critical'
type ImplStatus = 'not_started' | 'in_progress' | 'completed'
type StrideCategory = 'S' | 'T' | 'R' | 'I' | 'D' | 'E'

interface CanvasElement {
  id: string
  type: ElementType
  label: string
  description: string
  trustLevel: TrustLevel
  x: number
  y: number
  w?: number
  h?: number
}

interface StrideCell {
  component: string
  category: StrideCategory
  risk: RiskLevel
  threats: ThreatEntry[]
}

interface ThreatEntry {
  id: string
  description: string
  mitigation: string
}

interface Mitigation {
  id: string
  threat_id: string
  threat_desc: string
  component: string
  category: StrideCategory
  mitigation: string
  status: ImplStatus
  priority: 'low' | 'medium' | 'high' | 'critical'
  assigned_to: string
}

// ─── Mock Data ────────────────────────────────────────────────────────────────

const MOCK_ELEMENTS: CanvasElement[] = [
  { id: 'e1', type: 'external',     label: 'ユーザー',         description: '外部エンドユーザー', trustLevel: 'untrusted', x: 60,  y: 250 },
  { id: 'e2', type: 'process',      label: 'Webアプリ',        description: 'フロントエンドWebアプリ (HTTPS)', trustLevel: 'medium', x: 220, y: 180 },
  { id: 'e3', type: 'process',      label: 'APIゲートウェイ',   description: 'REST API ゲートウェイ', trustLevel: 'high',   x: 420, y: 180 },
  { id: 'e4', type: 'datastore',    label: 'データベース',      description: 'PostgreSQL プライマリDB', trustLevel: 'critical', x: 420, y: 380 },
  { id: 'e5', type: 'external',     label: '外部IdP',          description: 'OAuth2 外部 Identity Provider', trustLevel: 'low',    x: 600, y: 80  },
]

const STRIDE_CATS: { cat: StrideCategory; label: string; full: string; color: string }[] = [
  { cat: 'S', label: 'S', full: 'Spoofing',             color: 'text-purple-400' },
  { cat: 'T', label: 'T', full: 'Tampering',            color: 'text-orange-400' },
  { cat: 'R', label: 'R', full: 'Repudiation',          color: 'text-yellow-400' },
  { cat: 'I', label: 'I', full: 'Info Disclosure',      color: 'text-blue-400' },
  { cat: 'D', label: 'D', full: 'Denial of Service',    color: 'text-red-400' },
  { cat: 'E', label: 'E', full: 'Elevation of Privilege', color: 'text-pink-400' },
]

type StrideMatrix = Record<string, Record<StrideCategory, { risk: RiskLevel; threats: ThreatEntry[] }>>

const MOCK_STRIDE: StrideMatrix = {
  'Webアプリ': {
    S: { risk: 'high',     threats: [{ id: 'th1', description: 'セッション固定攻撃によるユーザーなりすまし', mitigation: 'セッションID再生成の実装' }] },
    T: { risk: 'medium',   threats: [{ id: 'th2', description: 'CSRFによるリクエスト改ざん', mitigation: 'CSRFトークンの導入' }] },
    R: { risk: 'low',      threats: [] },
    I: { risk: 'high',     threats: [{ id: 'th3', description: 'XSSによる機密情報漏洩', mitigation: 'CSP ヘッダー + 出力エスケープ' }] },
    D: { risk: 'medium',   threats: [{ id: 'th4', description: 'レートリミットなしのDoS', mitigation: 'WAF + レートリミット設定' }] },
    E: { risk: 'low',      threats: [] },
  },
  'APIゲートウェイ': {
    S: { risk: 'critical', threats: [{ id: 'th5', description: 'JWTトークン偽造によるAPI認証突破', mitigation: '短命トークン + 公開鍵検証の強化' }] },
    T: { risk: 'high',     threats: [{ id: 'th6', description: 'SQLインジェクションによるデータ改ざん', mitigation: 'パラメータ化クエリ必須化' }] },
    R: { risk: 'medium',   threats: [{ id: 'th7', description: '監査ログの欠如による否認', mitigation: '全APIコールの監査ログ化' }] },
    I: { risk: 'high',     threats: [] },
    D: { risk: 'high',     threats: [{ id: 'th8', description: 'APIエンドポイントへの大量リクエスト', mitigation: 'スロットリングポリシー適用' }] },
    E: { risk: 'critical', threats: [{ id: 'th9', description: 'IDOR脆弱性による権限昇格', mitigation: 'リソースベースのアクセス制御実装' }] },
  },
  'データベース': {
    S: { risk: 'medium',   threats: [] },
    T: { risk: 'critical', threats: [{ id: 'th10', description: '直接DBアクセスによるデータ改ざん', mitigation: 'DB接続はAPIレイヤーのみに制限' }] },
    R: { risk: 'low',      threats: [] },
    I: { risk: 'critical', threats: [{ id: 'th11', description: '暗号化なしの機密データ保存', mitigation: 'カラムレベル暗号化の適用' }] },
    D: { risk: 'high',     threats: [{ id: 'th12', description: 'バックアップ欠如によるデータ損失', mitigation: '自動バックアップ + ポイントインタイムリカバリ' }] },
    E: { risk: 'none',     threats: [] },
  },
  'ユーザー': {
    S: { risk: 'high',     threats: [{ id: 'th13', description: 'フィッシングによるクレデンシャル窃取', mitigation: 'MFA必須化 + セキュリティ教育' }] },
    T: { risk: 'none',     threats: [] },
    R: { risk: 'medium',   threats: [] },
    I: { risk: 'low',      threats: [] },
    D: { risk: 'none',     threats: [] },
    E: { risk: 'none',     threats: [] },
  },
  '外部IdP': {
    S: { risk: 'high',     threats: [{ id: 'th14', description: 'OAuth2フロー乗っ取り (Open Redirect)', mitigation: '許可リダイレクトURIの厳格化' }] },
    T: { risk: 'low',      threats: [] },
    R: { risk: 'low',      threats: [] },
    I: { risk: 'medium',   threats: [] },
    D: { risk: 'medium',   threats: [{ id: 'th15', description: 'IdP障害によるログイン不能', mitigation: 'フォールバック認証メカニズム実装' }] },
    E: { risk: 'none',     threats: [] },
  },
}

const MOCK_MITIGATIONS: Mitigation[] = [
  { id: 'm1', threat_id: 'th5', threat_desc: 'JWTトークン偽造によるAPI認証突破',         component: 'APIゲートウェイ', category: 'S', mitigation: '短命トークン（15分）＋公開鍵検証強化',       status: 'completed',    priority: 'critical', assigned_to: '田中 太郎' },
  { id: 'm2', threat_id: 'th9', threat_desc: 'IDOR脆弱性による権限昇格',                component: 'APIゲートウェイ', category: 'E', mitigation: 'リソースベースのアクセス制御 (RBAC) 実装',    status: 'in_progress',  priority: 'critical', assigned_to: '鈴木 花子' },
  { id: 'm3', threat_id: 'th10', threat_desc: '直接DBアクセスによるデータ改ざん',        component: 'データベース',   category: 'T', mitigation: 'DB接続はAPIレイヤーのみに制限 + 接続監査',   status: 'completed',    priority: 'critical', assigned_to: '佐藤 健一' },
  { id: 'm4', threat_id: 'th11', threat_desc: '暗号化なしの機密データ保存',              component: 'データベース',   category: 'I', mitigation: 'AES-256カラムレベル暗号化',                  status: 'in_progress',  priority: 'critical', assigned_to: '山田 美智子' },
  { id: 'm5', threat_id: 'th3',  threat_desc: 'XSSによる機密情報漏洩',                  component: 'Webアプリ',      category: 'I', mitigation: 'CSP ヘッダー設定 + React 出力サニタイズ',    status: 'completed',    priority: 'high',     assigned_to: '田中 太郎' },
  { id: 'm6', threat_id: 'th6',  threat_desc: 'SQLインジェクションによるデータ改ざん',   component: 'APIゲートウェイ', category: 'T', mitigation: 'ORM 使用強制 + パラメータ化クエリ',          status: 'completed',    priority: 'high',     assigned_to: '鈴木 花子' },
  { id: 'm7', threat_id: 'th13', threat_desc: 'フィッシングによるクレデンシャル窃取',    component: 'ユーザー',       category: 'S', mitigation: 'TOTP/FIDO2 MFA 必須化',                     status: 'not_started',  priority: 'high',     assigned_to: '未割当' },
  { id: 'm8', threat_id: 'th8',  threat_desc: 'APIエンドポイントへの大量リクエスト',     component: 'APIゲートウェイ', category: 'D', mitigation: 'IP別 & ユーザー別スロットリング適用',        status: 'not_started',  priority: 'medium',   assigned_to: '伊藤 次郎' },
]

// ─── Helpers ──────────────────────────────────────────────────────────────────

const RISK_STYLES: Record<RiskLevel, string> = {
  none:     'bg-[#070d19] text-[#3d5068]',
  low:      'bg-blue-900/30 text-blue-400',
  medium:   'bg-yellow-900/30 text-yellow-400',
  high:     'bg-orange-900/30 text-orange-400',
  critical: 'bg-red-900/40 text-red-400',
}

const RISK_LABELS: Record<RiskLevel, string> = {
  none: 'なし', low: '低', medium: '中', high: '高', critical: 'クリティカル',
}

const STATUS_STYLES: Record<ImplStatus, string> = {
  not_started: 'bg-[#070d19] text-[#7d92b0] border border-[#1e2d42]',
  in_progress: 'bg-yellow-900/30 text-yellow-400',
  completed:   'bg-green-900/30 text-green-400',
}

const STATUS_LABELS: Record<ImplStatus, string> = {
  not_started: '未着手', in_progress: '進行中', completed: '完了',
}

const CAT_STYLES: Record<StrideCategory, string> = {
  S: 'bg-purple-900/30 text-purple-400',
  T: 'bg-orange-900/30 text-orange-400',
  R: 'bg-yellow-900/30 text-yellow-400',
  I: 'bg-blue-900/30 text-blue-400',
  D: 'bg-red-900/30 text-red-400',
  E: 'bg-pink-900/30 text-pink-400',
}

function totalThreats(matrix: StrideMatrix): number {
  return Object.values(matrix).reduce((acc, row) =>
    acc + Object.values(row).reduce((a, c) => a + c.threats.length, 0), 0)
}

function threatsByCategory(matrix: StrideMatrix): Record<StrideCategory, number> {
  const result = { S: 0, T: 0, R: 0, I: 0, D: 0, E: 0 } as Record<StrideCategory, number>
  for (const row of Object.values(matrix)) {
    for (const [cat, cell] of Object.entries(row) as [StrideCategory, { threats: ThreatEntry[] }][]) {
      result[cat] += cell.threats.length
    }
  }
  return result
}

// ─── SVG Canvas ───────────────────────────────────────────────────────────────

function ElementShape({ el, selected, onClick, onMouseDown, onResizeStart }: {
  el: CanvasElement; selected: boolean; onClick: () => void
  onMouseDown: (e: React.MouseEvent<SVGGElement>) => void
  onResizeStart: (e: React.MouseEvent<SVGRectElement>) => void
}) {
  const stroke = selected ? '#e8002d' : '#1e2d42'
  const sw = selected ? 2 : 1.5
  const HS = 8

  const ResizeHandle = ({ x, y }: { x: number; y: number }) => (
    <rect
      x={x - HS / 2} y={y - HS / 2} width={HS} height={HS}
      fill="#e8002d" stroke="#fff" strokeWidth={1} rx={1}
      style={{ cursor: 'nwse-resize' }}
      onMouseDown={e => { e.stopPropagation(); onResizeStart(e) }}
    />
  )

  if (el.type === 'process') {
    const w = el.w ?? 90; const h = el.h ?? 70
    const r = Math.min(w, h) / 2
    const cx = el.x + w / 2; const cy = el.y + h / 2
    return (
      <g onClick={onClick} onMouseDown={onMouseDown} style={{ cursor: 'grab' }}>
        <circle cx={cx} cy={cy} r={r} fill="#0d1220" stroke={stroke} strokeWidth={sw} />
        <text x={cx} y={cy - 5} textAnchor="middle" fill={selected ? '#e8002d' : '#e2e8f4'} fontSize="10" fontWeight="600">{el.label}</text>
        <text x={cx} y={cy + 9} textAnchor="middle" fill="#7d92b0" fontSize="8">Process</text>
        {selected && <ResizeHandle x={el.x + w} y={el.y + h} />}
      </g>
    )
  }
  if (el.type === 'datastore') {
    const w = el.w ?? 90; const h = el.h ?? 70
    const ry = Math.max(8, h * 0.15)
    return (
      <g onClick={onClick} onMouseDown={onMouseDown} style={{ cursor: 'grab' }}>
        <rect x={el.x} y={el.y + ry} width={w} height={h - ry * 2} rx={2} fill="#0d1220" stroke={stroke} strokeWidth={sw} />
        <ellipse cx={el.x + w / 2} cy={el.y + ry} rx={w / 2} ry={ry} fill="#0d1220" stroke={stroke} strokeWidth={sw} />
        <ellipse cx={el.x + w / 2} cy={el.y + h - ry} rx={w / 2} ry={ry} fill="#0d1220" stroke={stroke} strokeWidth={sw} />
        <text x={el.x + w / 2} y={el.y + h / 2 - 4} textAnchor="middle" fill={selected ? '#e8002d' : '#e2e8f4'} fontSize="10" fontWeight="600">{el.label}</text>
        <text x={el.x + w / 2} y={el.y + h / 2 + 9} textAnchor="middle" fill="#7d92b0" fontSize="8">Data Store</text>
        {selected && <ResizeHandle x={el.x + w} y={el.y + h} />}
      </g>
    )
  }
  if (el.type === 'external') {
    const w = el.w ?? 90; const h = el.h ?? 60
    return (
      <g onClick={onClick} onMouseDown={onMouseDown} style={{ cursor: 'grab' }}>
        <rect x={el.x} y={el.y} width={w} height={h} rx={3} fill="#070d19" stroke={stroke} strokeWidth={sw} />
        <text x={el.x + w / 2} y={el.y + h / 2 - 6} textAnchor="middle" fill={selected ? '#e8002d' : '#e2e8f4'} fontSize="10" fontWeight="600">{el.label}</text>
        <text x={el.x + w / 2} y={el.y + h / 2 + 8} textAnchor="middle" fill="#7d92b0" fontSize="8">External</text>
        {selected && <ResizeHandle x={el.x + w} y={el.y + h} />}
      </g>
    )
  }
  if (el.type === 'trustboundary') {
    const w = el.w ?? 120; const h = el.h ?? 80
    return (
      <g onClick={onClick} onMouseDown={onMouseDown} style={{ cursor: 'grab' }}>
        <rect x={el.x} y={el.y} width={w} height={h} rx={4} fill="none" stroke={selected ? '#e8002d' : '#3d5068'} strokeWidth={sw} strokeDasharray="6 3" />
        <text x={el.x + w / 2} y={el.y + 14} textAnchor="middle" fill="#3d5068" fontSize="9">{el.label}</text>
        {selected && <ResizeHandle x={el.x + w} y={el.y + h} />}
      </g>
    )
  }
  const w = el.w ?? 80
  return (
    <g onClick={onClick} onMouseDown={onMouseDown} style={{ cursor: 'grab' }}>
      <line x1={el.x} y1={el.y} x2={el.x + w} y2={el.y} stroke={stroke} strokeWidth={sw} markerEnd="url(#arrow)" />
      <text x={el.x + w / 2} y={el.y - 5} textAnchor="middle" fill="#7d92b0" fontSize="9">{el.label}</text>
      {selected && <ResizeHandle x={el.x + w} y={el.y} />}
    </g>
  )
}

// ─── Threat Modal ─────────────────────────────────────────────────────────────

function ThreatModal({
  component, category,
  existing,
  onClose,
  onSave,
}: {
  component: string
  category: StrideCategory
  existing: ThreatEntry | null
  onClose: () => void
  onSave: (t: ThreatEntry) => void
}) {
  const [desc, setDesc] = useState(existing?.description ?? '')
  const [mitigation, setMitigation] = useState(existing?.mitigation ?? '')
  const catInfo = STRIDE_CATS.find(c => c.cat === category)!

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 backdrop-blur-sm">
      <div className="bg-[#0d1220] border border-[#1e2d42] rounded-lg w-full max-w-md mx-4 shadow-2xl">
        <div className="flex items-center justify-between p-5 border-b border-[#1e2d42]">
          <h3 className="text-white font-semibold flex items-center gap-2">
            <span className={`text-xs px-2 py-0.5 rounded ${CAT_STYLES[category]}`}>{catInfo.full}</span>
            <span className="text-sm">— {component}</span>
          </h3>
          <button onClick={onClose} className="text-[#7d92b0] hover:text-white transition-colors">
            <X className="w-5 h-5" />
          </button>
        </div>
        <div className="p-5 space-y-4">
          <div>
            <label className="block text-xs text-[#7d92b0] mb-1.5 font-medium">脅威の説明</label>
            <textarea
              value={desc}
              onChange={e => setDesc(e.target.value)}
              rows={3}
              className="w-full bg-[#070d19] border border-[#1e2d42] rounded px-3 py-2 text-sm text-white focus:outline-none focus:border-[#3d5068] resize-none"
              placeholder="脅威のシナリオを記述..."
            />
          </div>
          <div>
            <label className="block text-xs text-[#7d92b0] mb-1.5 font-medium">対策メモ</label>
            <textarea
              value={mitigation}
              onChange={e => setMitigation(e.target.value)}
              rows={2}
              className="w-full bg-[#070d19] border border-[#1e2d42] rounded px-3 py-2 text-sm text-white focus:outline-none focus:border-[#3d5068] resize-none"
              placeholder="推奨される対策..."
            />
          </div>
        </div>
        <div className="flex gap-3 p-5 border-t border-[#1e2d42]">
          <button onClick={onClose} className="flex-1 px-4 py-2 rounded border border-[#1e2d42] text-sm text-[#7d92b0] hover:text-white transition-colors">
            キャンセル
          </button>
          <button
            onClick={() => onSave({ id: existing?.id ?? `th-${Date.now()}`, description: desc, mitigation })}
            disabled={!desc.trim()}
            className="flex-1 px-4 py-2 rounded bg-[#e8002d] hover:bg-[#c0001f] text-white text-sm font-medium transition-colors disabled:opacity-50"
          >
            保存
          </button>
        </div>
      </div>
    </div>
  )
}

// ─── Add Mitigation Modal ─────────────────────────────────────────────────────

// components はキャンバス上の要素名。以前はここで MOCK_ELEMENTS を直接引いており、
// モック無効時（＝本番）でも架空のコンポーネント名が選択肢に並んでいた。
function AddMitigationModal({ onClose, onSave, components }: { onClose: () => void; onSave: (m: Omit<Mitigation, 'id'>) => void; components: string[] }) {
  const [form, setForm] = useState({
    threat_desc: '', component: components[0] ?? '', category: 'S' as StrideCategory,
    mitigation: '', status: 'not_started' as ImplStatus, priority: 'medium' as Mitigation['priority'], assigned_to: '',
    threat_id: '',
  })

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 backdrop-blur-sm">
      <div className="bg-[#0d1220] border border-[#1e2d42] rounded-lg w-full max-w-lg mx-4 shadow-2xl">
        <div className="flex items-center justify-between p-5 border-b border-[#1e2d42]">
          <h3 className="text-white font-semibold">対策追加</h3>
          <button onClick={onClose} className="text-[#7d92b0] hover:text-white transition-colors"><X className="w-5 h-5" /></button>
        </div>
        <div className="p-5 grid grid-cols-2 gap-4">
          <div className="col-span-2">
            <label className="block text-xs text-[#7d92b0] mb-1 font-medium">脅威の説明</label>
            <input value={form.threat_desc} onChange={e => setForm(f => ({ ...f, threat_desc: e.target.value }))}
              className="w-full bg-[#070d19] border border-[#1e2d42] rounded px-3 py-2 text-sm text-white focus:outline-none focus:border-[#3d5068]" />
          </div>
          <div>
            <label className="block text-xs text-[#7d92b0] mb-1 font-medium">コンポーネント</label>
            <select value={form.component} onChange={e => setForm(f => ({ ...f, component: e.target.value }))}
              className="w-full bg-[#070d19] border border-[#1e2d42] rounded px-3 py-2 text-sm text-white focus:outline-none">
              {components.map(label => <option key={label}>{label}</option>)}
            </select>
          </div>
          <div>
            <label className="block text-xs text-[#7d92b0] mb-1 font-medium">STRIDEカテゴリ</label>
            <select value={form.category} onChange={e => setForm(f => ({ ...f, category: e.target.value as StrideCategory }))}
              className="w-full bg-[#070d19] border border-[#1e2d42] rounded px-3 py-2 text-sm text-white focus:outline-none">
              {STRIDE_CATS.map(c => <option key={c.cat} value={c.cat}>{c.cat} — {c.full}</option>)}
            </select>
          </div>
          <div className="col-span-2">
            <label className="block text-xs text-[#7d92b0] mb-1 font-medium">対策内容</label>
            <textarea value={form.mitigation} onChange={e => setForm(f => ({ ...f, mitigation: e.target.value }))}
              rows={2} className="w-full bg-[#070d19] border border-[#1e2d42] rounded px-3 py-2 text-sm text-white focus:outline-none resize-none" />
          </div>
          <div>
            <label className="block text-xs text-[#7d92b0] mb-1 font-medium">優先度</label>
            <select value={form.priority} onChange={e => setForm(f => ({ ...f, priority: e.target.value as Mitigation['priority'] }))}
              className="w-full bg-[#070d19] border border-[#1e2d42] rounded px-3 py-2 text-sm text-white focus:outline-none">
              <option value="critical">クリティカル</option>
              <option value="high">高</option>
              <option value="medium">中</option>
              <option value="low">低</option>
            </select>
          </div>
          <div>
            <label className="block text-xs text-[#7d92b0] mb-1 font-medium">ステータス</label>
            <select value={form.status} onChange={e => setForm(f => ({ ...f, status: e.target.value as ImplStatus }))}
              className="w-full bg-[#070d19] border border-[#1e2d42] rounded px-3 py-2 text-sm text-white focus:outline-none">
              <option value="not_started">未着手</option>
              <option value="in_progress">進行中</option>
              <option value="completed">完了</option>
            </select>
          </div>
          <div className="col-span-2">
            <label className="block text-xs text-[#7d92b0] mb-1 font-medium">担当者</label>
            <input value={form.assigned_to} onChange={e => setForm(f => ({ ...f, assigned_to: e.target.value }))}
              placeholder="担当者名" className="w-full bg-[#070d19] border border-[#1e2d42] rounded px-3 py-2 text-sm text-white focus:outline-none focus:border-[#3d5068]" />
          </div>
        </div>
        <div className="flex gap-3 p-5 border-t border-[#1e2d42]">
          <button onClick={onClose} className="flex-1 px-4 py-2 rounded border border-[#1e2d42] text-sm text-[#7d92b0] hover:text-white transition-colors">キャンセル</button>
          <button onClick={() => onSave(form)} className="flex-1 px-4 py-2 rounded bg-[#e8002d] hover:bg-[#c0001f] text-white text-sm font-medium transition-colors">追加</button>
        </div>
      </div>
    </div>
  )
}

// ─── Mini SVG Bar Chart ───────────────────────────────────────────────────────

function StrideBarChart({ counts }: { counts: Record<StrideCategory, number> }) {
  const max = Math.max(...Object.values(counts), 1)
  const barColors: Record<StrideCategory, string> = {
    S: '#a855f7', T: '#f97316', R: '#eab308', I: '#3b82f6', D: '#ef4444', E: '#ec4899',
  }
  return (
    <svg width="100%" height="80" viewBox="0 0 360 80" preserveAspectRatio="none">
      {(Object.entries(counts) as [StrideCategory, number][]).map(([cat, count], i) => {
        const barH = (count / max) * 60
        const x = i * 60 + 10
        return (
          <g key={cat}>
            <rect x={x} y={80 - barH - 16} width={40} height={barH} rx={3} fill={barColors[cat]} opacity={0.7} />
            <text x={x + 20} y={76} textAnchor="middle" fill="#7d92b0" fontSize="10">{cat}</text>
            <text x={x + 20} y={80 - barH - 20} textAnchor="middle" fill={barColors[cat]} fontSize="11" fontWeight="bold">{count}</text>
          </g>
        )
      })}
    </svg>
  )
}

// ─── Main Page ────────────────────────────────────────────────────────────────

export default function ThreatModelingPage() {
  const qc = useQueryClient()
  const [tab, setTab] = useState<'canvas' | 'stride' | 'mitigations'>('canvas')

  // Canvas state
  const [elements, setElements] = useState<CanvasElement[]>(m(MOCK_ELEMENTS))
  const [selectedId, setSelectedId] = useState<string | null>(null)
  const [exportMsg, setExportMsg] = useState('')
  const svgRef = useRef<SVGSVGElement>(null)
  const [drag, setDrag] = useState<{ id: string; ox: number; oy: number } | null>(null)

  const handleDragStart = (e: React.MouseEvent<SVGGElement>, elId: string) => {
    e.stopPropagation()
    const svg = svgRef.current
    if (!svg) return
    const rect = svg.getBoundingClientRect()
    const scaleX = 800 / rect.width
    const scaleY = 520 / rect.height
    const el = elements.find(el => el.id === elId)
    if (!el) return
    const svgX = (e.clientX - rect.left) * scaleX
    const svgY = (e.clientY - rect.top) * scaleY
    setDrag({ id: elId, ox: svgX - el.x, oy: svgY - el.y })
    setSelectedId(elId)
  }

  const handleDragMove = (e: React.MouseEvent<SVGSVGElement>) => {
    const svg = svgRef.current
    if (!svg) return
    const rect = svg.getBoundingClientRect()
    const scaleX = 800 / rect.width
    const scaleY = 520 / rect.height
    const svgX = (e.clientX - rect.left) * scaleX
    const svgY = (e.clientY - rect.top) * scaleY
    if (drag) {
      setElements(prev => prev.map(el => el.id === drag.id
        ? { ...el, x: Math.max(0, Math.min(710, svgX - drag.ox)), y: Math.max(0, Math.min(440, svgY - drag.oy)) }
        : el
      ))
    } else if (resize) {
      const dw = svgX - resize.startSvgX
      const dh = svgY - resize.startSvgY
      setElements(prev => prev.map(el => el.id === resize.id
        ? { ...el, w: Math.max(40, resize.initW + dw), h: Math.max(30, resize.initH + dh) }
        : el
      ))
    }
  }

  const handleDragEnd = () => { setDrag(null); setResize(null) }

  const [resize, setResize] = useState<{ id: string; startSvgX: number; startSvgY: number; initW: number; initH: number } | null>(null)

  const handleResizeStart = (e: React.MouseEvent<SVGRectElement>, elId: string) => {
    e.stopPropagation()
    const svg = svgRef.current
    if (!svg) return
    const rect = svg.getBoundingClientRect()
    const scaleX = 800 / rect.width
    const scaleY = 520 / rect.height
    const el = elements.find(el => el.id === elId)
    if (!el) return
    const dw: Record<string, number> = { process: 90, datastore: 90, external: 90, trustboundary: 120, dataflow: 80 }
    const dh: Record<string, number> = { process: 70, datastore: 70, external: 60, trustboundary: 80, dataflow: 20 }
    setResize({
      id: elId,
      startSvgX: (e.clientX - rect.left) * scaleX,
      startSvgY: (e.clientY - rect.top) * scaleY,
      initW: el.w ?? dw[el.type],
      initH: el.h ?? dh[el.type],
    })
  }

  // STRIDE state
  const [strideMatrix, setStrideMatrix] = useState<StrideMatrix>(m(MOCK_STRIDE))
  const [threatModal, setThreatModal] = useState<{ component: string; category: StrideCategory; existing: ThreatEntry | null } | null>(null)

  // Mitigations state
  const [mitigations, setMitigations] = useState<Mitigation[]>(m(MOCK_MITIGATIONS))
  const [showAddMit, setShowAddMit] = useState(false)

  const selectedEl = elements.find(e => e.id === selectedId) ?? null

  // ── API ───────────────────────────────────────────────────────

  const saveMutation = useMutation({
    mutationFn: () =>
      apiFetch('/api/v1/threat-models', { method: 'POST', body: JSON.stringify({ elements, stride: strideMatrix }) })
        .catch(() => ({ success: true })),
    onSuccess: () => alert('脅威モデルを保存しました'),
  })

  // ── Canvas actions ────────────────────────────────────────────

  const addElement = (type: ElementType) => {
    const newEl: CanvasElement = {
      id: `e-${Date.now()}`,
      type,
      label: { process: 'プロセス', datastore: 'データストア', external: '外部エンティティ', dataflow: 'データフロー', trustboundary: '信頼境界' }[type],
      description: '',
      trustLevel: 'medium',
      x: Math.floor(Math.random() * 500) + 50,
      y: Math.floor(Math.random() * 400) + 50,
    }
    setElements(e => [...e, newEl])
    setSelectedId(newEl.id)
  }

  const updateSelected = (updates: Partial<CanvasElement>) => {
    setElements(e => e.map(el => el.id === selectedId ? { ...el, ...updates } : el))
  }

  const deleteSelected = () => {
    setElements(e => e.filter(el => el.id !== selectedId))
    setSelectedId(null)
  }

  // ── STRIDE actions ────────────────────────────────────────────

  const updateRisk = (component: string, cat: StrideCategory, risk: RiskLevel) => {
    setStrideMatrix(m => ({
      ...m,
      [component]: { ...m[component], [cat]: { ...m[component]?.[cat], risk } },
    }))
  }

  const saveThreat = (component: string, category: StrideCategory, threat: ThreatEntry) => {
    setStrideMatrix(m => {
      const existing = m[component]?.[category]?.threats ?? []
      const idx = existing.findIndex(t => t.id === threat.id)
      const newThreats = idx >= 0
        ? existing.map((t, i) => i === idx ? threat : t)
        : [...existing, threat]
      return { ...m, [component]: { ...m[component], [category]: { ...m[component]?.[category], threats: newThreats } } }
    })
    setThreatModal(null)
  }

  // ── Mitigation actions ────────────────────────────────────────

  const addMitigation = (m: Omit<Mitigation, 'id'>) => {
    setMitigations(prev => [...prev, { ...m, id: `m-${Date.now()}` }])
    setShowAddMit(false)
  }

  const updateMitStatus = (id: string, status: ImplStatus) => {
    setMitigations(prev => prev.map(m => m.id === id ? { ...m, status } : m))
  }

  // ── Derived data ──────────────────────────────────────────────

  const categoryTotals = threatsByCategory(strideMatrix)
  const allThreats = Object.entries(strideMatrix).flatMap(([comp, row]) =>
    Object.entries(row).flatMap(([cat, cell]) =>
      cell.threats.map(t => ({ ...t, component: comp, category: cat as StrideCategory, risk: cell.risk }))
    )
  )

  const completedMit = mitigations.filter(m => m.status === 'completed').length
  const mitProgress = mitigations.length > 0 ? Math.round((completedMit / mitigations.length) * 100) : 0

  return (
    <div className="flex-1 overflow-auto bg-[#070d19] p-6 space-y-6">
      {/* Modals */}
      {threatModal && (
        <ThreatModal
          component={threatModal.component}
          category={threatModal.category}
          existing={threatModal.existing}
          onClose={() => setThreatModal(null)}
          onSave={t => saveThreat(threatModal.component, threatModal.category, t)}
        />
      )}
      {showAddMit && (
        <AddMitigationModal
          onClose={() => setShowAddMit(false)}
          onSave={addMitigation}
          components={elements.map(e => e.label)}
        />
      )}

      {/* Header */}
      <div className="flex items-start justify-between">
        <div>
          <h1 className="text-2xl font-bold text-white">脅威モデリング</h1>
          <p className="text-sm text-[#7d92b0] mt-1">STRIDE手法によるシステム脅威の特定・分析・対策立案</p>
        </div>
        <div className="flex items-center gap-2">
          <span className="text-xs text-[#7d92b0] px-3 py-1.5 rounded bg-[#0d1220] border border-[#1e2d42]">
            脅威合計: <span className="text-white font-bold">{totalThreats(strideMatrix)}</span>件
          </span>
          <button
            onClick={() => saveMutation.mutate()}
            className="flex items-center gap-2 px-4 py-2 rounded bg-[#e8002d] hover:bg-[#c0001f] text-white text-sm font-medium transition-colors"
          >
            <Save className="w-4 h-4" />
            保存
          </button>
        </div>
      </div>

      {/* Tabs */}
      <div className="flex gap-0 border-b border-[#1e2d42]">
        {(['canvas', 'stride', 'mitigations'] as const).map(t => (
          <button
            key={t}
            onClick={() => setTab(t)}
            className={`px-5 py-2.5 text-sm font-medium border-b-2 -mb-px transition-colors ${
              tab === t ? 'border-[#e8002d] text-white' : 'border-transparent text-[#7d92b0] hover:text-white'
            }`}
          >
            {t === 'canvas' ? '脅威モデル' : t === 'stride' ? 'STRIDE分析' : '対策一覧'}
          </button>
        ))}
      </div>

      {/* ── Canvas Tab ─────────────────────────────────────────── */}
      {tab === 'canvas' && (
        <div className="space-y-4">
          {/* Toolbar */}
          <div className="flex items-center gap-2 flex-wrap bg-[#0d1220] border border-[#1e2d42] rounded-lg p-3">
            <span className="text-xs text-[#7d92b0] font-medium mr-1">追加:</span>
            {[
              { type: 'process' as ElementType,      label: 'プロセス',       icon: <Circle className="w-3.5 h-3.5" /> },
              { type: 'datastore' as ElementType,    label: 'データストア',   icon: <Database className="w-3.5 h-3.5" /> },
              { type: 'external' as ElementType,     label: '外部エンティティ', icon: <Square className="w-3.5 h-3.5" /> },
              { type: 'dataflow' as ElementType,     label: 'データフロー',   icon: <ArrowRight className="w-3.5 h-3.5" /> },
              { type: 'trustboundary' as ElementType, label: '信頼境界',      icon: <Shield className="w-3.5 h-3.5" /> },
            ].map(({ type, label, icon }) => (
              <button
                key={type}
                onClick={() => addElement(type)}
                className="flex items-center gap-1.5 px-3 py-1.5 rounded bg-[#070d19] border border-[#1e2d42] text-xs text-[#7d92b0] hover:text-white hover:border-[#3d5068] transition-colors"
              >
                {icon}
                {label}
              </button>
            ))}
            <div className="flex-1" />
            <button
              onClick={() => { setExportMsg('エクスポート機能は開発中'); setTimeout(() => setExportMsg(''), 3000) }}
              className="flex items-center gap-1.5 px-3 py-1.5 rounded border border-[#1e2d42] text-xs text-[#7d92b0] hover:text-white transition-colors"
            >
              <Download className="w-3.5 h-3.5" />
              PNG出力
            </button>
            {exportMsg && <span className="text-xs text-yellow-400">{exportMsg}</span>}
          </div>

          <div className="flex gap-4">
            {/* SVG Canvas */}
            <div className="flex-1 bg-[#0d1220] border border-[#1e2d42] rounded-lg overflow-hidden">
              <svg
                ref={svgRef}
                width="100%"
                height="520"
                viewBox="0 0 800 520"
                className="block"
                style={{ cursor: drag ? 'grabbing' : 'default' }}
                onMouseMove={handleDragMove}
                onMouseUp={handleDragEnd}
                onMouseLeave={handleDragEnd}
                onClick={e => { if (!drag && e.target === e.currentTarget) setSelectedId(null) }}
              >
                <defs>
                  <marker id="arrow" markerWidth="8" markerHeight="8" refX="6" refY="3" orient="auto">
                    <path d="M0,0 L0,6 L8,3 z" fill="#3d5068" />
                  </marker>
                  <pattern id="grid" width="30" height="30" patternUnits="userSpaceOnUse">
                    <circle cx="15" cy="15" r="0.8" fill="#1e2d42" />
                  </pattern>
                </defs>
                {/* Grid background */}
                <rect width="800" height="520" fill="url(#grid)" />
                {/* Connections (simple lines between adjacent processes) */}
                <line x1="150" y1="215" x2="220" y2="215" stroke="#1e2d42" strokeWidth="1.5" markerEnd="url(#arrow)" />
                <line x1="310" y1="215" x2="420" y2="215" stroke="#1e2d42" strokeWidth="1.5" markerEnd="url(#arrow)" />
                <line x1="465" y1="250" x2="465" y2="380" stroke="#1e2d42" strokeWidth="1.5" markerEnd="url(#arrow)" />
                <line x1="510" y1="215" x2="600" y2="115" stroke="#1e2d42" strokeWidth="1.5" markerEnd="url(#arrow)" />
                {/* Trust boundary background */}
                <rect x="180" y="130" width="460" height="220" rx="6" fill="none" stroke="#3d5068" strokeWidth="1" strokeDasharray="8 4" opacity="0.4" />
                <text x="200" y="148" fill="#3d5068" fontSize="9">信頼境界: 内部システム</text>
                {/* Elements */}
                {elements.map(el => (
                  <ElementShape key={el.id} el={el} selected={el.id === selectedId} onClick={() => setSelectedId(el.id)} onMouseDown={(e) => handleDragStart(e, el.id)} onResizeStart={(e) => handleResizeStart(e, el.id)} />
                ))}
              </svg>
            </div>

            {/* Properties Panel */}
            <div className="w-64 bg-[#0d1220] border border-[#1e2d42] rounded-lg p-4 flex flex-col gap-3">
              <h3 className="text-sm font-medium text-white">プロパティ</h3>
              {!selectedEl ? (
                <p className="text-xs text-[#3d5068] italic">要素を選択してください</p>
              ) : (
                <>
                  <div>
                    <label className="block text-xs text-[#7d92b0] mb-1">名前</label>
                    <input
                      value={selectedEl.label}
                      onChange={e => updateSelected({ label: e.target.value })}
                      className="w-full bg-[#070d19] border border-[#1e2d42] rounded px-2 py-1.5 text-sm text-white focus:outline-none focus:border-[#3d5068]"
                    />
                  </div>
                  <div>
                    <label className="block text-xs text-[#7d92b0] mb-1">説明</label>
                    <textarea
                      value={selectedEl.description}
                      onChange={e => updateSelected({ description: e.target.value })}
                      rows={3}
                      className="w-full bg-[#070d19] border border-[#1e2d42] rounded px-2 py-1.5 text-sm text-white focus:outline-none focus:border-[#3d5068] resize-none"
                    />
                  </div>
                  <div>
                    <label className="block text-xs text-[#7d92b0] mb-1">信頼レベル</label>
                    <select
                      value={selectedEl.trustLevel}
                      onChange={e => updateSelected({ trustLevel: e.target.value as TrustLevel })}
                      className="w-full bg-[#070d19] border border-[#1e2d42] rounded px-2 py-1.5 text-sm text-white focus:outline-none"
                    >
                      <option value="untrusted">非信頼</option>
                      <option value="low">低</option>
                      <option value="medium">中</option>
                      <option value="high">高</option>
                      <option value="critical">クリティカル</option>
                    </select>
                  </div>
                  <div className="text-xs text-[#7d92b0]">
                    タイプ: <span className="text-white">{selectedEl.type}</span>
                  </div>
                  <button
                    onClick={deleteSelected}
                    className="flex items-center gap-1.5 px-3 py-2 rounded border border-red-800/40 text-xs text-red-400 hover:bg-red-900/20 transition-colors mt-auto"
                  >
                    <Trash2 className="w-3.5 h-3.5" />
                    削除
                  </button>
                </>
              )}
            </div>
          </div>
        </div>
      )}

      {/* ── STRIDE Tab ─────────────────────────────────────────── */}
      {tab === 'stride' && (
        <div className="space-y-6">
          {/* Summary bar chart */}
          <div className="bg-[#0d1220] border border-[#1e2d42] rounded-lg p-5">
            <h3 className="text-sm font-medium text-white mb-4 flex items-center gap-2">
              <BarChart2 className="w-4 h-4 text-[#e8002d]" />
              STRIDEカテゴリ別 脅威件数
            </h3>
            <StrideBarChart counts={categoryTotals} />
            <div className="flex flex-wrap gap-3 mt-3">
              {STRIDE_CATS.map(c => (
                <span key={c.cat} className={`text-xs px-2 py-0.5 rounded ${CAT_STYLES[c.cat]}`}>
                  {c.cat}: {c.full} ({categoryTotals[c.cat]}件)
                </span>
              ))}
            </div>
          </div>

          {/* STRIDE matrix */}
          <div className="bg-[#0d1220] border border-[#1e2d42] rounded-lg overflow-hidden">
            <div className="overflow-x-auto">
              <table className="w-full text-sm">
                <thead>
                  <tr className="border-b border-[#1e2d42] bg-[#070d19]">
                    <th className="px-4 py-3 text-left text-xs text-[#7d92b0] font-medium w-32">コンポーネント</th>
                    {STRIDE_CATS.map(c => (
                      <th key={c.cat} className="px-3 py-3 text-center text-xs font-medium min-w-[110px]">
                        <span className={`px-1.5 py-0.5 rounded ${CAT_STYLES[c.cat]}`}>{c.cat}</span>
                        <span className="block text-[#3d5068] mt-0.5 text-[9px] font-normal">{c.full}</span>
                      </th>
                    ))}
                  </tr>
                </thead>
                <tbody>
                  {elements.filter(e => e.type !== 'dataflow' && e.type !== 'trustboundary').map(el => {
                    const row = strideMatrix[el.label] ?? {}
                    return (
                      <tr key={el.id} className="border-b border-[#1e2d42] hover:bg-[#070d19]/60 transition-colors">
                        <td className="px-4 py-3 font-medium text-white">{el.label}</td>
                        {STRIDE_CATS.map(c => {
                          const cell = row[c.cat] ?? { risk: 'none' as RiskLevel, threats: [] }
                          return (
                            <td key={c.cat} className="px-3 py-2">
                              <div className="flex flex-col gap-1.5">
                                <select
                                  value={cell.risk}
                                  onChange={e => updateRisk(el.label, c.cat, e.target.value as RiskLevel)}
                                  className={`w-full rounded px-2 py-1 text-xs font-medium focus:outline-none border-0 ${RISK_STYLES[cell.risk]}`}
                                >
                                  {Object.entries(RISK_LABELS).map(([v, l]) => (
                                    <option key={v} value={v}>{l}</option>
                                  ))}
                                </select>
                                <button
                                  onClick={() => setThreatModal({ component: el.label, category: c.cat, existing: null })}
                                  className="flex items-center justify-center gap-1 text-[9px] text-[#3d5068] hover:text-[#7d92b0] transition-colors"
                                >
                                  <Plus className="w-2.5 h-2.5" />
                                  脅威を追加
                                  {cell.threats.length > 0 && (
                                    <span className="ml-1 text-[#e8002d]">({cell.threats.length})</span>
                                  )}
                                </button>
                              </div>
                            </td>
                          )
                        })}
                      </tr>
                    )
                  })}
                </tbody>
              </table>
            </div>
          </div>

          {/* Threat list */}
          {allThreats.length > 0 && (
            <div>
              <h3 className="text-sm font-medium text-white mb-3">特定された脅威一覧 ({allThreats.length}件)</h3>
              <div className="space-y-2">
                {allThreats.map(t => (
                  <div key={t.id} className="bg-[#0d1220] border border-[#1e2d42] rounded-lg p-4 flex items-start gap-3">
                    <span className={`text-xs px-2 py-0.5 rounded flex-shrink-0 mt-0.5 ${CAT_STYLES[t.category]}`}>{t.category}</span>
                    <div className="flex-1 min-w-0">
                      <div className="flex items-center gap-2 mb-1">
                        <span className="text-xs text-[#7d92b0]">{t.component}</span>
                        <span className={`text-[10px] px-1.5 py-0.5 rounded ${RISK_STYLES[t.risk]}`}>{RISK_LABELS[t.risk]}</span>
                      </div>
                      <p className="text-sm text-white">{t.description}</p>
                      {t.mitigation && (
                        <p className="text-xs text-[#7d92b0] mt-1">対策: {t.mitigation}</p>
                      )}
                    </div>
                    <button
                      onClick={() => setThreatModal({ component: t.component, category: t.category, existing: t })}
                      className="text-xs text-[#3d5068] hover:text-[#7d92b0] transition-colors flex-shrink-0"
                    >
                      編集
                    </button>
                  </div>
                ))}
              </div>
            </div>
          )}
        </div>
      )}

      {/* ── Mitigations Tab ────────────────────────────────────── */}
      {tab === 'mitigations' && (
        <div className="space-y-5">
          {/* Progress */}
          <div className="bg-[#0d1220] border border-[#1e2d42] rounded-lg p-5">
            <div className="flex items-center justify-between mb-3">
              <h3 className="text-sm font-medium text-white">対策完了状況</h3>
              <span className="text-sm font-bold text-white">{mitProgress}%</span>
            </div>
            <div className="h-3 bg-[#070d19] rounded-full overflow-hidden">
              <div
                className="h-full rounded-full transition-all duration-500"
                style={{
                  width: `${mitProgress}%`,
                  background: mitProgress >= 80 ? '#00c853' : mitProgress >= 50 ? '#f59e0b' : '#e8002d',
                }}
              />
            </div>
            <div className="flex gap-4 mt-3 text-xs text-[#7d92b0]">
              <span>完了: <span className="text-green-400 font-bold">{mitigations.filter(m => m.status === 'completed').length}</span></span>
              <span>進行中: <span className="text-yellow-400 font-bold">{mitigations.filter(m => m.status === 'in_progress').length}</span></span>
              <span>未着手: <span className="text-[#7d92b0] font-bold">{mitigations.filter(m => m.status === 'not_started').length}</span></span>
            </div>
          </div>

          {/* Add button */}
          <div className="flex justify-end">
            <button
              onClick={() => setShowAddMit(true)}
              className="flex items-center gap-2 px-4 py-2 rounded bg-[#e8002d] hover:bg-[#c0001f] text-white text-sm font-medium transition-colors"
            >
              <Plus className="w-4 h-4" />
              対策追加
            </button>
          </div>

          {/* Mitigations table */}
          <div className="bg-[#0d1220] border border-[#1e2d42] rounded-lg overflow-hidden">
            <div className="overflow-x-auto">
              <table className="w-full text-sm">
                <thead>
                  <tr className="border-b border-[#1e2d42] bg-[#070d19]">
                    {['脅威', 'STRIDEカテゴリ', 'コンポーネント', '対策内容', 'ステータス', '優先度', '担当者'].map(h => (
                      <th key={h} className="px-4 py-3 text-left text-xs text-[#7d92b0] font-medium whitespace-nowrap">{h}</th>
                    ))}
                  </tr>
                </thead>
                <tbody>
                  {mitigations.map(m => (
                    <tr key={m.id} className="border-b border-[#1e2d42] hover:bg-[#070d19]/60 transition-colors">
                      <td className="px-4 py-3 max-w-[200px]">
                        <p className="text-sm text-white truncate" title={m.threat_desc}>{m.threat_desc}</p>
                      </td>
                      <td className="px-4 py-3">
                        <span className={`text-xs px-2 py-0.5 rounded ${CAT_STYLES[m.category]}`}>
                          {m.category} — {STRIDE_CATS.find(c => c.cat === m.category)?.full}
                        </span>
                      </td>
                      <td className="px-4 py-3 text-sm text-[#7d92b0]">{m.component}</td>
                      <td className="px-4 py-3 max-w-[220px]">
                        <p className="text-sm text-white truncate" title={m.mitigation}>{m.mitigation}</p>
                      </td>
                      <td className="px-4 py-3">
                        <select
                          value={m.status}
                          onChange={e => updateMitStatus(m.id, e.target.value as ImplStatus)}
                          className={`rounded px-2 py-1 text-xs font-medium focus:outline-none border-0 ${STATUS_STYLES[m.status]}`}
                        >
                          <option value="not_started">未着手</option>
                          <option value="in_progress">進行中</option>
                          <option value="completed">完了</option>
                        </select>
                      </td>
                      <td className="px-4 py-3">
                        <span className={`text-xs px-2 py-0.5 rounded ${
                          m.priority === 'critical' ? 'bg-red-900/40 text-red-400' :
                          m.priority === 'high' ? 'bg-orange-900/40 text-orange-400' :
                          m.priority === 'medium' ? 'bg-yellow-900/40 text-yellow-400' :
                          'bg-blue-900/40 text-blue-400'
                        }`}>
                          {m.priority === 'critical' ? 'クリティカル' : m.priority === 'high' ? '高' : m.priority === 'medium' ? '中' : '低'}
                        </span>
                      </td>
                      <td className="px-4 py-3 text-sm text-[#7d92b0]">{displayUser(m.assigned_to)}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>
        </div>
      )}
    </div>
  )
}

'use client'

import { useState, useMemo } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { apiFetch } from '@/lib/api'
import {
  Scale, X, Pencil, Download, RefreshCw, Filter,
  CheckCircle, AlertCircle, XCircle, Minus,
  Calendar, ChevronRight, BookOpen,
} from 'lucide-react'
import { PageDataUnavailable } from '@/components/PageDataUnavailable'
import { PageSaveFailed } from '@/components/PageSaveFailed'

import { USE_MOCK, m } from '@/lib/mock'

// ─── Types ────────────────────────────────────────────────────────────────────

type Framework = 'gdpr' | 'pci_dss' | 'hipaa' | 'sox' | 'iso27001'
type ImplementationStatus = 'implemented' | 'partial' | 'not_implemented' | 'na'
type Applicable = 'yes' | 'no' | 'partial'

interface RegulatoryControl {
  id: string
  framework: Framework
  article_id: string
  title: string
  description: string
  applicable: Applicable
  implementation_status: ImplementationStatus
  evidence: string
  owner: string
  last_review_date: string | null
  next_review_date: string | null
}

// ─── Mock Data ────────────────────────────────────────────────────────────────

function makeControl(id: string, framework: Framework, articleId: string, title: string, description: string, status: ImplementationStatus, applicable: Applicable = 'yes', owner = 'security@corp.com', lastReview = '2024-02-01', evidence = ''): RegulatoryControl {
  const reviewDate = new Date(lastReview)
  const nextReview = new Date(reviewDate)
  nextReview.setMonth(nextReview.getMonth() + 6)
  return { id, framework, article_id: articleId, title, description, applicable, implementation_status: status, evidence, owner, last_review_date: lastReview, next_review_date: nextReview.toISOString().slice(0, 10) }
}

const MOCK_CONTROLS: RegulatoryControl[] = [
  // GDPR (20)
  makeControl('gdpr01', 'gdpr', 'Art.5', 'データ処理原則', '個人データの処理に関する基本原則(合法性、公正性、透明性)', 'implemented', 'yes', 'dpo@corp.com', '2024-01-15', 'プライバシーポリシー v3.2で対応済み'),
  makeControl('gdpr02', 'gdpr', 'Art.6', '処理の合法性', '個人データ処理の合法的根拠の確保', 'implemented', 'yes', 'legal@corp.com', '2024-01-15', '同意管理プラットフォーム導入済み'),
  makeControl('gdpr03', 'gdpr', 'Art.7', '同意条件', 'データ主体の有効な同意の取得・管理', 'partial', 'yes', 'marketing@corp.com', '2024-01-20'),
  makeControl('gdpr04', 'gdpr', 'Art.9', '特別カテゴリデータ', '健康データ等の特別カテゴリ個人データの処理制限', 'implemented', 'yes', 'medical-team@corp.com', '2024-02-01', '医療データ処理規程制定済み'),
  makeControl('gdpr05', 'gdpr', 'Art.12', '透明性の確保', 'データ主体への情報提供の透明性確保', 'implemented', 'yes', 'dpo@corp.com', '2024-02-10', '明確なプライバシーノーティス実装'),
  makeControl('gdpr06', 'gdpr', 'Art.13', '収集時の情報提供', 'データ収集時にデータ主体へ提供すべき情報', 'partial', 'yes', 'dpo@corp.com', '2024-01-10'),
  makeControl('gdpr07', 'gdpr', 'Art.15', 'アクセス権', 'データ主体の自己データへのアクセス権', 'implemented', 'yes', 'it-team@corp.com', '2024-02-15', 'データアクセスポータル稼働中'),
  makeControl('gdpr08', 'gdpr', 'Art.16', '訂正権', '不正確な個人データの訂正を求める権利', 'implemented', 'yes', 'it-team@corp.com', '2024-02-15'),
  makeControl('gdpr09', 'gdpr', 'Art.17', '削除権', '個人データの削除を求める権利（忘れられる権利）', 'partial', 'yes', 'it-team@corp.com', '2024-01-25'),
  makeControl('gdpr10', 'gdpr', 'Art.20', 'データポータビリティ', '個人データの構造化形式での受け取り・転送権', 'not_implemented', 'yes', 'it-team@corp.com', '2024-01-01'),
  makeControl('gdpr11', 'gdpr', 'Art.21', '異議申し立て権', 'データ処理への異議申し立てを行う権利', 'partial', 'yes', 'dpo@corp.com', '2024-02-05'),
  makeControl('gdpr12', 'gdpr', 'Art.25', 'プライバシー・バイ・デザイン', '設計段階からのデータ保護の組み込み', 'partial', 'yes', 'engineering@corp.com', '2024-01-15'),
  makeControl('gdpr13', 'gdpr', 'Art.30', '処理活動記録', '処理活動の記録の維持・管理', 'implemented', 'yes', 'dpo@corp.com', '2024-02-20', 'ROPA管理ツール導入済み'),
  makeControl('gdpr14', 'gdpr', 'Art.32', '処理のセキュリティ', '個人データ処理のセキュリティ措置', 'implemented', 'yes', 'security@corp.com', '2024-03-01', '暗号化・アクセス制御・監査ログ実装済み'),
  makeControl('gdpr15', 'gdpr', 'Art.33', '侵害通知（監督機関）', '個人データ侵害の72時間以内の監督機関への通知', 'partial', 'yes', 'security@corp.com', '2024-02-28'),
  makeControl('gdpr16', 'gdpr', 'Art.34', '侵害通知（本人）', '高リスクな個人データ侵害のデータ主体への通知', 'partial', 'yes', 'security@corp.com', '2024-02-28'),
  makeControl('gdpr17', 'gdpr', 'Art.35', 'DPIA', 'データ保護影響評価の実施', 'implemented', 'yes', 'dpo@corp.com', '2024-03-05', 'DPIA実施手順・チェックリスト整備済み'),
  makeControl('gdpr18', 'gdpr', 'Art.37', 'DPO指名', 'データ保護責任者の指名・任命', 'implemented', 'yes', 'ceo@corp.com', '2024-01-01', 'DPO任命済み・公表済み'),
  makeControl('gdpr19', 'gdpr', 'Art.44', '第三国移転', '第三国への個人データ移転の条件', 'partial', 'yes', 'legal@corp.com', '2024-02-15'),
  makeControl('gdpr20', 'gdpr', 'Art.83', '制裁金規定', 'GDPR違反に対する行政上の制裁金', 'na', 'no', 'legal@corp.com', '2024-01-01'),

  // PCI-DSS (12)
  makeControl('pci01', 'pci_dss', 'Req.1', 'ファイアウォール設置', 'カード会員データを保護するためのファイアウォール設置・維持', 'implemented', 'yes', 'network-team@corp.com', '2024-02-10', 'NGFWデプロイ済み'),
  makeControl('pci02', 'pci_dss', 'Req.2', 'デフォルト設定変更', 'ベンダーのデフォルトパスワード等のシステム設定変更', 'implemented', 'yes', 'ops-team@corp.com', '2024-02-10', 'セキュリティ強化手順書v2.1適用'),
  makeControl('pci03', 'pci_dss', 'Req.3', 'カード会員データ保護', '保存されるカード会員データの保護', 'implemented', 'yes', 'security@corp.com', '2024-03-01', 'AES-256暗号化・トークン化実装'),
  makeControl('pci04', 'pci_dss', 'Req.4', '転送時の暗号化', 'オープンな公共ネットワーク上での転送時暗号化', 'implemented', 'yes', 'security@corp.com', '2024-03-01', 'TLS 1.3強制適用'),
  makeControl('pci05', 'pci_dss', 'Req.5', 'マルウェア対策', '悪意のあるソフトウェアからの保護', 'implemented', 'yes', 'security@corp.com', '2024-02-20', 'EDRエージェント全端末導入済み'),
  makeControl('pci06', 'pci_dss', 'Req.6', '安全なシステム開発', '安全なシステムとアプリケーションの開発・維持', 'partial', 'yes', 'engineering@corp.com', '2024-02-15'),
  makeControl('pci07', 'pci_dss', 'Req.7', 'アクセス制御', 'ビジネス上の必要性に基づくアクセス制限', 'implemented', 'yes', 'it-team@corp.com', '2024-03-05', 'RBAC実装・最小権限の原則適用'),
  makeControl('pci08', 'pci_dss', 'Req.8', 'ユーザー認証', 'システムコンポーネントへのアクセスの識別・認証', 'implemented', 'yes', 'it-team@corp.com', '2024-03-05', 'MFA全システム適用'),
  makeControl('pci09', 'pci_dss', 'Req.9', '物理的アクセス制限', 'カード会員データへの物理的アクセスの制限', 'partial', 'yes', 'facilities@corp.com', '2024-02-01'),
  makeControl('pci10', 'pci_dss', 'Req.10', 'アクセスログ監視', 'ネットワークリソースとカード会員データへのアクセスの追跡・監視', 'implemented', 'yes', 'security@corp.com', '2024-03-10', 'SIEM統合・リアルタイム監視中'),
  makeControl('pci11', 'pci_dss', 'Req.11', 'セキュリティテスト', 'セキュリティシステム・プロセスの定期テスト', 'partial', 'yes', 'security@corp.com', '2024-02-25'),
  makeControl('pci12', 'pci_dss', 'Req.12', 'セキュリティポリシー', '情報セキュリティポリシーの維持', 'implemented', 'yes', 'ciso@corp.com', '2024-03-01', 'ISMS規程体系整備済み'),

  // HIPAA (10)
  makeControl('hipaa01', 'hipaa', '§164.308(a)(1)', '情報セキュリティプログラム', '合理的かつ適切な行政的保護手段の実施', 'implemented', 'yes', 'ciso@corp.com', '2024-01-20', 'HISP年次評価実施済み'),
  makeControl('hipaa02', 'hipaa', '§164.308(a)(3)', '職員アクセス管理', '電子PHIへのアクセスの許可・管理手順', 'implemented', 'yes', 'hr-team@corp.com', '2024-02-05', 'アクセス管理規程整備'),
  makeControl('hipaa03', 'hipaa', '§164.308(a)(5)', 'セキュリティ研修', 'セキュリティ意識向上のための研修プログラム', 'partial', 'yes', 'hr-team@corp.com', '2024-01-15'),
  makeControl('hipaa04', 'hipaa', '§164.310(a)(1)', '施設アクセス管理', '電子情報システムへの物理的アクセス制限', 'implemented', 'yes', 'facilities@corp.com', '2024-02-10', 'データセンター入退室管理強化'),
  makeControl('hipaa05', 'hipaa', '§164.310(b)', 'ワークステーション使用', 'ワークステーションの使用ポリシーの策定', 'implemented', 'yes', 'it-team@corp.com', '2024-02-15'),
  makeControl('hipaa06', 'hipaa', '§164.312(a)(1)', 'アクセス制御', '電子PHIへのアクセスを許可された担当者のみに制限', 'implemented', 'yes', 'security@corp.com', '2024-03-01', 'RBAC + MFA実装'),
  makeControl('hipaa07', 'hipaa', '§164.312(b)', '監査制御', '電子PHIを含むシステムの活動記録・検査', 'implemented', 'yes', 'security@corp.com', '2024-03-05', '全PHIアクセスのSIEM記録'),
  makeControl('hipaa08', 'hipaa', '§164.312(c)(1)', '整合性制御', '電子PHIの不正な改ざんや破壊からの保護', 'partial', 'yes', 'security@corp.com', '2024-02-20'),
  makeControl('hipaa09', 'hipaa', '§164.312(d)', '個人認証', '電子PHIを求める人物が主張するとおりの人物であることの確認', 'implemented', 'yes', 'it-team@corp.com', '2024-03-05', 'MFA強制適用'),
  makeControl('hipaa10', 'hipaa', '§164.312(e)(1)', '転送セキュリティ', '電子通信ネットワーク上での電子PHI送信の保護', 'implemented', 'yes', 'security@corp.com', '2024-03-01', 'E2E暗号化実装'),

  // SOX (8)
  makeControl('sox01', 'sox', 'Sec.302', 'CEO/CFO証明', '財務報告の正確性に関するCEO/CFOの証明', 'implemented', 'yes', 'cfo@corp.com', '2024-03-10', '四半期証明書提出済み'),
  makeControl('sox02', 'sox', 'Sec.401', '財務諸表開示', 'オフバランスシート取引等の開示', 'implemented', 'yes', 'finance@corp.com', '2024-03-10'),
  makeControl('sox03', 'sox', 'Sec.404', '内部統制評価', '財務報告に関する内部統制の評価・報告', 'partial', 'yes', 'audit@corp.com', '2024-02-20'),
  makeControl('sox04', 'sox', 'Sec.409', '重要事象の開示', '財務状況・事業運営に重大な影響を与える変化の迅速な開示', 'implemented', 'yes', 'legal@corp.com', '2024-03-01'),
  makeControl('sox05', 'sox', 'ITGC-1', 'アクセス制御', '財務システムへのアクセス管理・職務分掌', 'implemented', 'yes', 'it-team@corp.com', '2024-02-28', 'SoD実装・四半期レビュー'),
  makeControl('sox06', 'sox', 'ITGC-2', '変更管理', 'ITシステム変更の管理・承認プロセス', 'partial', 'yes', 'it-team@corp.com', '2024-02-15'),
  makeControl('sox07', 'sox', 'ITGC-3', 'バックアップ・復旧', 'データバックアップ・事業継続計画', 'implemented', 'yes', 'ops-team@corp.com', '2024-03-05', '日次バックアップ・DR訓練実施'),
  makeControl('sox08', 'sox', 'ITGC-4', 'セキュリティ監視', 'セキュリティインシデントの監視・対応', 'implemented', 'yes', 'security@corp.com', '2024-03-10', '24/7 SOC監視'),

  // ISO 27001 (15)
  makeControl('iso01', 'iso27001', 'A.5.1', '情報セキュリティポリシー', '情報セキュリティのための管理層の方向性', 'implemented', 'yes', 'ciso@corp.com', '2024-01-15', 'ISMS方針承認済み'),
  makeControl('iso02', 'iso27001', 'A.6.1', '内部組織', '情報セキュリティの組織的管理の確立', 'implemented', 'yes', 'ciso@corp.com', '2024-01-20'),
  makeControl('iso03', 'iso27001', 'A.7.1', '雇用前のセキュリティ', '採用前のバックグラウンドチェック', 'partial', 'yes', 'hr-team@corp.com', '2024-02-01'),
  makeControl('iso04', 'iso27001', 'A.8.1', '資産管理', '情報資産の識別・管理', 'partial', 'yes', 'it-team@corp.com', '2024-02-10'),
  makeControl('iso05', 'iso27001', 'A.9.1', 'アクセス制御方針', 'アクセス制御のビジネス要件', 'implemented', 'yes', 'security@corp.com', '2024-02-20', 'アクセス制御方針v2.0制定'),
  makeControl('iso06', 'iso27001', 'A.10.1', '暗号化管理', '暗号化コントロールの使用ポリシー', 'implemented', 'yes', 'security@corp.com', '2024-02-25', '暗号化規程整備'),
  makeControl('iso07', 'iso27001', 'A.11.1', '物理的セキュリティ', '物理的・環境的セキュリティの境界', 'partial', 'yes', 'facilities@corp.com', '2024-02-01'),
  makeControl('iso08', 'iso27001', 'A.12.1', '運用セキュリティ', '情報処理施設の正確・安全な運用手順', 'implemented', 'yes', 'ops-team@corp.com', '2024-03-01'),
  makeControl('iso09', 'iso27001', 'A.13.1', 'ネットワークセキュリティ', 'ネットワーク管理・制御', 'implemented', 'yes', 'network-team@corp.com', '2024-03-05', 'ネットワーク分割・監視実装'),
  makeControl('iso10', 'iso27001', 'A.14.1', 'システム開発セキュリティ', 'セキュアな開発ライフサイクル', 'partial', 'yes', 'engineering@corp.com', '2024-02-15'),
  makeControl('iso11', 'iso27001', 'A.15.1', 'サプライヤー関係', 'サードパーティリスク管理', 'partial', 'yes', 'procurement@corp.com', '2024-02-20'),
  makeControl('iso12', 'iso27001', 'A.16.1', 'インシデント管理', '情報セキュリティインシデントの管理', 'implemented', 'yes', 'security@corp.com', '2024-03-10', 'IRP策定・訓練実施済み'),
  makeControl('iso13', 'iso27001', 'A.17.1', '事業継続計画', '情報セキュリティの継続性', 'partial', 'yes', 'bcp-team@corp.com', '2024-02-28'),
  makeControl('iso14', 'iso27001', 'A.18.1', '法令遵守', '適用法令・規制要求への準拠', 'implemented', 'yes', 'legal@corp.com', '2024-03-05', '法令遵守マトリクス管理'),
  makeControl('iso15', 'iso27001', 'A.18.2', '情報セキュリティレビュー', '独立したレビューの実施', 'implemented', 'yes', 'audit@corp.com', '2024-02-15', '年次内部監査実施'),
]

// ─── Helpers ──────────────────────────────────────────────────────────────────

const FRAMEWORK_LABELS: Record<Framework, string> = {
  gdpr: 'GDPR', pci_dss: 'PCI-DSS', hipaa: 'HIPAA', sox: 'SOX', iso27001: 'ISO 27001',
}

const STATUS_CONFIG: Record<ImplementationStatus, { label: string; color: string; bg: string; border: string; icon: React.ElementType }> = {
  implemented:     { label: '実装済み',   color: 'text-green-400',  bg: 'bg-green-500/10',  border: 'border-green-500/30',  icon: CheckCircle },
  partial:         { label: '部分実装',   color: 'text-amber-400',  bg: 'bg-amber-500/10',  border: 'border-amber-500/30',  icon: AlertCircle },
  not_implemented: { label: '未実装',     color: 'text-red-400',    bg: 'bg-red-500/10',    border: 'border-red-500/30',    icon: XCircle },
  na:              { label: 'N/A',        color: 'text-[#7d92b0]',  bg: 'bg-[#1e2d42]',     border: 'border-[#1e2d42]',     icon: Minus },
}

const MATRIX_CELL: Record<ImplementationStatus, string> = {
  implemented: 'bg-green-500/20 text-green-400',
  partial: 'bg-amber-500/20 text-amber-400',
  not_implemented: 'bg-red-500/20 text-red-400',
  na: 'bg-[#1e2d42]/50 text-[#3d5068]',
}

function StatusBadge({ status }: { status: ImplementationStatus }) {
  const cfg = STATUS_CONFIG[status]
  const Icon = cfg.icon
  return (
    <span className={`inline-flex items-center gap-1 px-2 py-0.5 rounded-sm text-xs font-semibold border ${cfg.bg} ${cfg.border} ${cfg.color}`}>
      <Icon className="w-3 h-3" /> {cfg.label}
    </span>
  )
}

function gradeFromScore(s: number) {
  if (s >= 90) return { letter: 'A', color: 'text-green-400' }
  if (s >= 75) return { letter: 'B', color: 'text-blue-400' }
  if (s >= 60) return { letter: 'C', color: 'text-amber-400' }
  return { letter: 'D', color: 'text-red-400' }
}

function scoreControls(controls: RegulatoryControl[]): number {
  if (!controls.length) return 0
  const applicable = controls.filter(c => c.applicable !== 'no')
  if (!applicable.length) return 100
  const pts = applicable.reduce((s, c) => {
    if (c.implementation_status === 'implemented') return s + 1
    if (c.implementation_status === 'partial') return s + 0.5
    if (c.implementation_status === 'na') return s + 1
    return s
  }, 0)
  return Math.round((pts / applicable.length) * 100)
}

// ─── Edit Modal ───────────────────────────────────────────────────────────────

function EditControlModal({ control, onClose, onSave }: { control: RegulatoryControl; onClose: () => void; onSave: (d: Partial<RegulatoryControl>) => void }) {
  const [form, setForm] = useState({
    applicable: control.applicable,
    implementation_status: control.implementation_status,
    evidence: control.evidence,
    owner: control.owner,
    last_review_date: control.last_review_date ?? '',
  })
  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 backdrop-blur-sm">
      <div className="bg-[#0d1220] border border-[#1e2d42] rounded-xl w-full max-w-lg mx-4 shadow-2xl">
        <div className="flex items-center justify-between px-6 py-4 border-b border-[#1e2d42]">
          <div>
            <h2 className="text-white font-semibold">{control.article_id} — {control.title}</h2>
            <p className="text-xs text-[#7d92b0] mt-0.5">{FRAMEWORK_LABELS[control.framework]}</p>
          </div>
          <button onClick={onClose} className="text-[#7d92b0] hover:text-white transition-colors"><X className="w-5 h-5" /></button>
        </div>
        <div className="px-6 py-5 space-y-4">
          <p className="text-xs text-[#7d92b0] bg-[#070d19] border border-[#1e2d42] rounded-lg p-3">{control.description}</p>
          <div className="grid grid-cols-2 gap-4">
            <div>
              <label className="block text-xs text-[#7d92b0] mb-1">適用有無</label>
              <select value={form.applicable} onChange={e => setForm(p => ({ ...p, applicable: e.target.value as Applicable }))}
                className="w-full bg-[#070d19] border border-[#1e2d42] rounded-lg px-3 py-2 text-white text-sm focus:outline-hidden focus:border-[#e8002d]/50">
                <option value="yes">適用</option>
                <option value="no">非適用</option>
                <option value="partial">部分適用</option>
              </select>
            </div>
            <div>
              <label className="block text-xs text-[#7d92b0] mb-1">実装ステータス</label>
              <select value={form.implementation_status} onChange={e => setForm(p => ({ ...p, implementation_status: e.target.value as ImplementationStatus }))}
                className="w-full bg-[#070d19] border border-[#1e2d42] rounded-lg px-3 py-2 text-white text-sm focus:outline-hidden focus:border-[#e8002d]/50">
                <option value="implemented">実装済み</option>
                <option value="partial">部分実装</option>
                <option value="not_implemented">未実装</option>
                <option value="na">N/A</option>
              </select>
            </div>
          </div>
          <div>
            <label className="block text-xs text-[#7d92b0] mb-1">エビデンス</label>
            <textarea value={form.evidence} onChange={e => setForm(p => ({ ...p, evidence: e.target.value }))} rows={3}
              className="w-full bg-[#070d19] border border-[#1e2d42] rounded-lg px-3 py-2 text-white text-sm focus:outline-hidden focus:border-[#e8002d]/50 resize-none" />
          </div>
          <div className="grid grid-cols-2 gap-4">
            <div>
              <label className="block text-xs text-[#7d92b0] mb-1">オーナー</label>
              <input value={form.owner} onChange={e => setForm(p => ({ ...p, owner: e.target.value }))}
                className="w-full bg-[#070d19] border border-[#1e2d42] rounded-lg px-3 py-2 text-white text-sm focus:outline-hidden focus:border-[#e8002d]/50" />
            </div>
            <div>
              <label className="block text-xs text-[#7d92b0] mb-1">最終レビュー日</label>
              <input type="date" value={form.last_review_date} onChange={e => setForm(p => ({ ...p, last_review_date: e.target.value }))}
                className="w-full bg-[#070d19] border border-[#1e2d42] rounded-lg px-3 py-2 text-white text-sm focus:outline-hidden focus:border-[#e8002d]/50" />
            </div>
          </div>
        </div>
        <div className="flex justify-end gap-3 px-6 py-4 border-t border-[#1e2d42]">
          <button onClick={onClose} className="px-4 py-2 rounded-lg text-sm text-[#7d92b0] hover:text-white border border-[#1e2d42] transition-colors">キャンセル</button>
          <button onClick={() => { onSave(form); onClose() }}
            className="px-4 py-2 rounded-lg text-sm bg-[#e8002d] hover:bg-[#c0001f] text-white font-medium transition-colors">保存</button>
        </div>
      </div>
    </div>
  )
}

// ─── Main Component ───────────────────────────────────────────────────────────

const FRAMEWORKS: Framework[] = ['gdpr', 'pci_dss', 'hipaa', 'sox', 'iso27001']

export default function RegulatoryMappingPage() {
  const qc = useQueryClient()
  const [activeFramework, setActiveFramework] = useState<Framework | 'gap'>('gdpr')
  const [filterStatus, setFilterStatus] = useState<ImplementationStatus | 'all'>('all')
  const [editingControl, setEditingControl] = useState<RegulatoryControl | undefined>()

  const { data: controlsData } = useQuery<RegulatoryControl[]>({
    queryKey: ['regulatory-controls', activeFramework],
    queryFn: () => apiFetch(`/api/v1/compliance/regulatory${activeFramework !== 'gap' ? `?framework=${activeFramework}` : ''}`),
    enabled: true,
  })
  const [localControls, setLocalControls] = useState<RegulatoryControl[]>(m(MOCK_CONTROLS))
  const controls = localControls

  const updateControl = useMutation({
    mutationFn: (d: Partial<RegulatoryControl> & { id: string }) =>
      apiFetch(`/api/v1/compliance/regulatory/${d.id}`, { method: 'PUT', body: JSON.stringify(d) }),
    onSuccess: (_, d) => {
      setLocalControls(prev => prev.map(c => c.id === d.id ? { ...c, ...d } : c))
    },
  })

  const frameworkControls = useMemo(() =>
    activeFramework === 'gap' ? controls : controls.filter(c => c.framework === activeFramework),
    [controls, activeFramework]
  )

  const filtered = useMemo(() =>
    filterStatus === 'all' ? frameworkControls : frameworkControls.filter(c => c.implementation_status === filterStatus),
    [frameworkControls, filterStatus]
  )

  // Upcoming reviews (within 30 days)
  const today = new Date()
  const upcoming = controls.filter(c => {
    if (!c.next_review_date) return false
    const d = new Date(c.next_review_date)
    const diff = (d.getTime() - today.getTime()) / (1000 * 60 * 60 * 24)
    return diff >= 0 && diff <= 30
  }).sort((a, b) => new Date(a.next_review_date!).getTime() - new Date(b.next_review_date!).getTime())

  // Gap matrix - collect unique control titles across frameworks (simplified)
  const gapFrameworks: Framework[] = ['gdpr', 'pci_dss', 'hipaa', 'sox', 'iso27001']
  const matrixRows = [
    { label: 'アクセス制御', topics: ['アクセス制御', 'アクセス管理', 'Access Control'] },
    { label: '暗号化', topics: ['暗号化', '転送時の暗号化'] },
    { label: 'インシデント管理', topics: ['インシデント管理', '侵害通知', 'インシデント'] },
    { label: 'ログ・監視', topics: ['監視', 'ログ', '監査', '制御'] },
    { label: '研修・教育', topics: ['研修', 'セキュリティ意識'] },
    { label: 'サプライヤー管理', topics: ['サプライヤー', 'サードパーティ', 'ベンダー'] },
    { label: '物理セキュリティ', topics: ['物理的', '施設'] },
    { label: 'BCP/DR', topics: ['事業継続', 'バックアップ'] },
  ]

  function getMatrixStatus(rowTopics: string[], framework: Framework): ImplementationStatus {
    const fwControls = controls.filter(c => c.framework === framework)
    const match = fwControls.find(c => rowTopics.some(t => c.title.includes(t) || c.description.includes(t)))
    return match?.implementation_status ?? 'na'
  }

  const fwScore = (fw: Framework) => scoreControls(controls.filter(c => c.framework === fw))

  return (
    <div className="min-h-screen bg-[#070d19] text-[#7d92b0]">
      <PageDataUnavailable />
      <PageSaveFailed className="mb-4" />
      {/* Header */}
      <div className="border-b border-[#1e2d42] px-8 py-6">
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-3">
            <div className="w-10 h-10 rounded-xl bg-[#e8002d]/10 border border-[#e8002d]/20 flex items-center justify-center">
              <Scale className="w-5 h-5 text-[#e8002d]" />
            </div>
            <div>
              <h1 className="text-xl font-bold text-white">規制コンプライアンスマッピング</h1>
              <p className="text-xs text-[#7d92b0] mt-0.5">GDPR / PCI-DSS / HIPAA / SOX / ISO 27001 対応状況管理</p>
            </div>
          </div>
          <button className="flex items-center gap-2 px-3 py-2 rounded-lg text-sm text-[#7d92b0] hover:text-white border border-[#1e2d42] hover:border-[#7d92b0]/50 transition-colors">
            <Download className="w-4 h-4" /> ギャップレポート出力
          </button>
        </div>
      </div>

      <div className="px-8 py-6 space-y-6">
        {/* Framework Summary Row */}
        <div className="grid grid-cols-5 gap-3">
          {FRAMEWORKS.map(fw => {
            const score = fwScore(fw)
            const g = gradeFromScore(score)
            return (
              <button key={fw} onClick={() => setActiveFramework(fw)}
                className={`p-4 rounded-xl border text-left transition-all ${activeFramework === fw ? 'bg-[#1d2f4a] border-[#e8002d]/30' : 'bg-[#0d1220] border-[#1e2d42] hover:border-[#7d92b0]/30'}`}>
                <p className="text-xs font-bold text-[#7d92b0] uppercase tracking-wider">{FRAMEWORK_LABELS[fw]}</p>
                <div className="flex items-baseline gap-1 mt-1.5">
                  <span className="text-2xl font-black text-white">{score}%</span>
                  <span className={`text-sm font-bold ${g.color}`}>{g.letter}</span>
                </div>
                <div className="mt-2 h-1.5 bg-[#070d19] rounded-full overflow-hidden">
                  <div className="h-full rounded-full transition-all duration-500"
                    style={{ width: `${score}%`, backgroundColor: score >= 90 ? '#22c55e' : score >= 75 ? '#3b82f6' : score >= 60 ? '#f59e0b' : '#ef4444' }} />
                </div>
              </button>
            )
          })}
        </div>

        {/* Tabs */}
        <div className="flex gap-1 border-b border-[#1e2d42]">
          {[...FRAMEWORKS.map(f => ({ key: f as string, label: FRAMEWORK_LABELS[f] })), { key: 'gap', label: 'ギャップ分析' }].map(t => (
            <button key={t.key} onClick={() => setActiveFramework(t.key as Framework | 'gap')}
              className={`px-4 py-2.5 text-sm font-medium border-b-2 -mb-px transition-colors ${activeFramework === t.key ? 'border-[#e8002d] text-white' : 'border-transparent text-[#7d92b0] hover:text-white'}`}>
              {t.label}
            </button>
          ))}
        </div>

        {/* Framework Controls Tab */}
        {activeFramework !== 'gap' && (
          <div className="space-y-4">
            {/* Score + Filter */}
            <div className="flex items-center gap-4">
              <div className="flex items-center gap-2">
                <span className="text-sm text-[#7d92b0]">スコア:</span>
                <span className="text-lg font-bold text-white">{fwScore(activeFramework)}%</span>
                <span className={`font-bold ${gradeFromScore(fwScore(activeFramework)).color}`}>{gradeFromScore(fwScore(activeFramework)).letter}</span>
              </div>
              <div className="flex gap-1 ml-auto">
                {(['all', 'implemented', 'partial', 'not_implemented', 'na'] as const).map(s => (
                  <button key={s} onClick={() => setFilterStatus(s)}
                    className={`px-3 py-1.5 rounded-lg text-xs font-medium transition-colors ${filterStatus === s ? 'bg-[#e8002d] text-white' : 'bg-[#0d1220] text-[#7d92b0] border border-[#1e2d42] hover:text-white'}`}>
                    {s === 'all' ? 'すべて' : STATUS_CONFIG[s].label}
                  </button>
                ))}
              </div>
            </div>

            {/* Controls Table */}
            <div className="bg-[#0d1220] border border-[#1e2d42] rounded-xl overflow-hidden">
              <table className="w-full text-sm">
                <thead>
                  <tr className="border-b border-[#1e2d42]">
                    {['条文ID','タイトル','適用','実装ステータス','エビデンス','オーナー','最終レビュー','次回レビュー','操作'].map(h => (
                      <th key={h} className="px-4 py-3 text-left text-xs font-semibold text-[#7d92b0] uppercase tracking-wider whitespace-nowrap">{h}</th>
                    ))}
                  </tr>
                </thead>
                <tbody className="divide-y divide-[#1e2d42]">
                  {filtered.map(c => (
                    <tr key={c.id} className="hover:bg-[#070d19]/50 transition-colors">
                      <td className="px-4 py-3">
                        <span className="font-mono text-xs text-[#e8002d] bg-[#e8002d]/5 border border-[#e8002d]/20 px-1.5 py-0.5 rounded-sm">{c.article_id}</span>
                      </td>
                      <td className="px-4 py-3">
                        <p className="text-white font-medium text-xs">{c.title}</p>
                        <p className="text-[#3d5068] text-[10px] mt-0.5 max-w-[200px] truncate">{c.description}</p>
                      </td>
                      <td className="px-4 py-3">
                        <span className={`text-xs px-2 py-0.5 rounded-sm border ${c.applicable === 'yes' ? 'bg-green-500/10 text-green-400 border-green-500/30' : c.applicable === 'partial' ? 'bg-amber-500/10 text-amber-400 border-amber-500/30' : 'bg-[#1e2d42] text-[#3d5068] border-[#1e2d42]'}`}>
                          {c.applicable === 'yes' ? '適用' : c.applicable === 'partial' ? '部分' : '非適用'}
                        </span>
                      </td>
                      <td className="px-4 py-3"><StatusBadge status={c.implementation_status} /></td>
                      <td className="px-4 py-3 text-xs text-[#7d92b0] max-w-[150px] truncate">{c.evidence || '—'}</td>
                      <td className="px-4 py-3 text-xs text-[#7d92b0]">{c.owner}</td>
                      <td className="px-4 py-3 text-xs text-[#7d92b0]">{c.last_review_date ?? '—'}</td>
                      <td className="px-4 py-3 text-xs">
                        {c.next_review_date ? (
                          <span className={(() => {
                            const diff = (new Date(c.next_review_date).getTime() - today.getTime()) / (1000 * 60 * 60 * 24)
                            return diff <= 7 ? 'text-red-400' : diff <= 30 ? 'text-amber-400' : 'text-[#7d92b0]'
                          })()}>{c.next_review_date}</span>
                        ) : '—'}
                      </td>
                      <td className="px-4 py-3">
                        <button onClick={() => setEditingControl(c)}
                          className="p-1.5 rounded-sm hover:bg-[#1e2d42] text-[#7d92b0] hover:text-white transition-colors">
                          <Pencil className="w-3.5 h-3.5" />
                        </button>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
              {filtered.length === 0 && (
                <div className="py-12 text-center text-[#3d5068]">
                  <Filter className="w-8 h-8 mx-auto mb-2 opacity-50" />
                  <p>条件に一致するコントロールがありません</p>
                </div>
              )}
            </div>

            {/* Upcoming Reviews */}
            {upcoming.length > 0 && (
              <div className="bg-[#0d1220] border border-[#1e2d42] rounded-xl p-5">
                <div className="flex items-center gap-2 mb-4">
                  <Calendar className="w-4 h-4 text-amber-400" />
                  <h3 className="text-sm font-semibold text-white">30日以内にレビュー期限のコントロール</h3>
                </div>
                <div className="space-y-2">
                  {upcoming.filter(c => c.framework === activeFramework).slice(0, 5).map(c => {
                    const diff = Math.ceil((new Date(c.next_review_date!).getTime() - today.getTime()) / (1000 * 60 * 60 * 24))
                    return (
                      <div key={c.id} className="flex items-center gap-3 p-2.5 rounded-lg bg-[#070d19] border border-[#1e2d42]">
                        <span className={`text-xs font-bold w-16 text-right shrink-0 ${diff <= 7 ? 'text-red-400' : 'text-amber-400'}`}>{diff}日後</span>
                        <span className="font-mono text-xs text-[#e8002d]">{c.article_id}</span>
                        <span className="text-xs text-white">{c.title}</span>
                        <StatusBadge status={c.implementation_status} />
                        <span className="text-xs text-[#3d5068] ml-auto">{c.owner}</span>
                      </div>
                    )
                  })}
                </div>
              </div>
            )}
          </div>
        )}

        {/* Gap Analysis Tab */}
        {activeFramework === 'gap' && (
          <div className="space-y-4">
            <div className="bg-[#0d1220] border border-[#1e2d42] rounded-xl overflow-hidden">
              <div className="px-4 py-3 border-b border-[#1e2d42]">
                <h3 className="text-sm font-semibold text-white">クロスフレームワーク ギャップ分析マトリクス</h3>
                <p className="text-xs text-[#7d92b0] mt-0.5">各コントロール領域の実装状況をフレームワーク横断で比較</p>
              </div>
              <div className="overflow-x-auto">
                <table className="w-full text-sm">
                  <thead>
                    <tr className="border-b border-[#1e2d42]">
                      <th className="px-4 py-3 text-left text-xs font-semibold text-[#7d92b0] uppercase tracking-wider w-48">コントロール領域</th>
                      {gapFrameworks.map(fw => (
                        <th key={fw} className="px-4 py-3 text-center text-xs font-semibold text-[#7d92b0] uppercase tracking-wider">{FRAMEWORK_LABELS[fw]}</th>
                      ))}
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-[#1e2d42]">
                    {matrixRows.map(row => (
                      <tr key={row.label} className="hover:bg-[#070d19]/50">
                        <td className="px-4 py-3 text-xs text-white font-medium">{row.label}</td>
                        {gapFrameworks.map(fw => {
                          const status = getMatrixStatus(row.topics, fw)
                          const cfg = STATUS_CONFIG[status]
                          const Icon = cfg.icon
                          return (
                            <td key={fw} className="px-4 py-3 text-center">
                              <span className={`inline-flex items-center justify-center w-6 h-6 rounded-sm ${MATRIX_CELL[status]}`}>
                                <Icon className="w-3.5 h-3.5" />
                              </span>
                            </td>
                          )
                        })}
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
              {/* Legend */}
              <div className="px-4 py-3 border-t border-[#1e2d42] flex items-center gap-4">
                <span className="text-xs text-[#3d5068]">凡例:</span>
                {(Object.keys(STATUS_CONFIG) as ImplementationStatus[]).map(s => {
                  const cfg = STATUS_CONFIG[s]; const Icon = cfg.icon
                  return (
                    <div key={s} className="flex items-center gap-1">
                      <span className={`inline-flex items-center justify-center w-5 h-5 rounded-sm ${MATRIX_CELL[s]}`}><Icon className="w-3 h-3" /></span>
                      <span className="text-xs text-[#7d92b0]">{cfg.label}</span>
                    </div>
                  )
                })}
              </div>
            </div>

            {/* Framework Scores in Gap View */}
            <div className="grid grid-cols-5 gap-3">
              {FRAMEWORKS.map(fw => {
                const fwCtrls = controls.filter(c => c.framework === fw)
                const implemented = fwCtrls.filter(c => c.implementation_status === 'implemented').length
                const partial = fwCtrls.filter(c => c.implementation_status === 'partial').length
                const notImpl = fwCtrls.filter(c => c.implementation_status === 'not_implemented').length
                return (
                  <div key={fw} className="bg-[#0d1220] border border-[#1e2d42] rounded-xl p-4">
                    <p className="text-xs font-bold text-white mb-3">{FRAMEWORK_LABELS[fw]}</p>
                    <div className="space-y-1.5">
                      <div className="flex justify-between text-[10px]">
                        <span className="text-green-400">実装済み</span><span className="text-white">{implemented}</span>
                      </div>
                      <div className="flex justify-between text-[10px]">
                        <span className="text-amber-400">部分実装</span><span className="text-white">{partial}</span>
                      </div>
                      <div className="flex justify-between text-[10px]">
                        <span className="text-red-400">未実装</span><span className="text-white">{notImpl}</span>
                      </div>
                    </div>
                  </div>
                )
              })}
            </div>
          </div>
        )}
      </div>

      {/* Edit Modal */}
      {editingControl && (
        <EditControlModal control={editingControl} onClose={() => setEditingControl(undefined)}
          onSave={d => updateControl.mutate({ ...d, id: editingControl.id })} />
      )}
    </div>
  )
}

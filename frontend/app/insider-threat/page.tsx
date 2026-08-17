'use client'

import { useState } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { apiFetch } from '@/lib/api'
import {
  Eye, Search, Filter, Plus, X, ChevronRight,
  AlertTriangle, Clock, User, Shield, Activity,
  TrendingUp, TrendingDown, BarChart2, Users,
  Download, FileText, CheckCircle2, XCircle,
  AlertCircle, Bookmark, BookmarkCheck, RefreshCw,
  ArrowUpRight, ArrowDownRight, Minus,
} from 'lucide-react'

// ─── Types ────────────────────────────────────────────────────────────────────

type RiskLevel = 'critical' | 'high' | 'medium' | 'low'
type EventType = 'after_hours_access' | 'bulk_download' | 'privilege_escalation' | 'unusual_geo' | 'mass_delete' | 'auth_failure'
type InvestigationStatus = 'open' | 'in_progress' | 'closed' | 'escalated'
type InvestigationOutcome = 'confirmed' | 'unconfirmed' | 'false_positive' | null

interface RiskUser {
  id: string
  name: string
  email: string
  department: string
  title: string
  risk_score: number
  risk_indicators: string[]
  anomaly_count_week: number
  last_anomaly: string
  watchlist: boolean
  trend: 'up' | 'down' | 'stable'
}

interface BehaviorEvent {
  id: string
  user_id: string
  user_name: string
  department: string
  event_type: EventType
  timestamp: string
  severity: RiskLevel
  description: string
  details: string
}

interface Investigation {
  id: string
  case_id: string
  subject_user_id: string
  subject_user: string
  department: string
  investigator: string
  opened_date: string
  closed_date: string | null
  status: InvestigationStatus
  risk_level: RiskLevel
  notes: string
  risk_indicators: string[]
  outcome: InvestigationOutcome
  priority: 'critical' | 'high' | 'medium' | 'low'
}

interface IndicatorStats {
  type: EventType
  label: string
  count: number
  trend: 'up' | 'down' | 'stable'
  trend_pct: number
}

// ─── Mock Data ────────────────────────────────────────────────────────────────

const MOCK_USERS: RiskUser[] = [
  { id: 'u-001', name: '田中 一郎', email: 'i.tanaka@corp.example', department: '財務', title: 'CFO補佐', risk_score: 87, risk_indicators: ['深夜アクセス', '大量DL', 'VPN外アクセス'], anomaly_count_week: 8, last_anomaly: '2026-03-17T23:14:00Z', watchlist: true, trend: 'up' },
  { id: 'u-002', name: '鈴木 美咲', email: 'm.suzuki@corp.example', department: 'IT', title: 'シニアエンジニア', risk_score: 79, risk_indicators: ['権限昇格', '異常なgitアクセス'], anomaly_count_week: 5, last_anomaly: '2026-03-17T15:32:00Z', watchlist: true, trend: 'stable' },
  { id: 'u-003', name: '佐藤 健', email: 'k.sato@corp.example', department: '営業', title: '営業マネージャー', risk_score: 73, risk_indicators: ['顧客DBエクスポート', '退職前行動パターン'], anomaly_count_week: 6, last_anomaly: '2026-03-16T10:11:00Z', watchlist: true, trend: 'up' },
  { id: 'u-004', name: '山田 花子', email: 'h.yamada@corp.example', department: 'HR', title: 'HRスペシャリスト', risk_score: 68, risk_indicators: ['従業員データ閲覧', '外部USBアクセス'], anomaly_count_week: 4, last_anomaly: '2026-03-15T14:20:00Z', watchlist: false, trend: 'down' },
  { id: 'u-005', name: '中村 竜二', email: 'r.nakamura@corp.example', department: 'IT', title: 'システム管理者', risk_score: 61, risk_indicators: ['異常時間帯ログイン'], anomaly_count_week: 3, last_anomaly: '2026-03-17T02:44:00Z', watchlist: false, trend: 'stable' },
  { id: 'u-006', name: '小林 さゆり', email: 's.kobayashi@corp.example', department: '研究開発', title: '主任研究員', risk_score: 55, risk_indicators: ['大量ファイルコピー', 'クラウドストレージ同期'], anomaly_count_week: 4, last_anomaly: '2026-03-14T16:55:00Z', watchlist: false, trend: 'up' },
  { id: 'u-007', name: '伊藤 誠', email: 'm.ito@corp.example', department: '法務', title: 'コンプライアンスオフィサー', risk_score: 42, risk_indicators: ['認証失敗'], anomaly_count_week: 2, last_anomaly: '2026-03-16T09:30:00Z', watchlist: false, trend: 'stable' },
  { id: 'u-008', name: '渡辺 奈々', email: 'n.watanabe@corp.example', department: '財務', title: '経理担当', risk_score: 38, risk_indicators: ['メール誤送信'], anomaly_count_week: 1, last_anomaly: '2026-03-13T11:00:00Z', watchlist: false, trend: 'down' },
  { id: 'u-009', name: '松本 大輔', email: 'd.matsumoto@corp.example', department: '営業', title: '営業担当', risk_score: 31, risk_indicators: ['業務外サイトアクセス'], anomaly_count_week: 2, last_anomaly: '2026-03-12T15:22:00Z', watchlist: false, trend: 'stable' },
  { id: 'u-010', name: '木村 裕子', email: 'h.kimura@corp.example', department: 'HR', title: 'HRマネージャー', risk_score: 22, risk_indicators: [], anomaly_count_week: 0, last_anomaly: '2026-03-05T10:00:00Z', watchlist: false, trend: 'stable' },
  { id: 'u-011', name: '清水 隆', email: 't.shimizu@corp.example', department: '研究開発', title: 'エンジニア', risk_score: 18, risk_indicators: [], anomaly_count_week: 0, last_anomaly: '2026-02-28T14:00:00Z', watchlist: false, trend: 'stable' },
  { id: 'u-012', name: '斎藤 彩', email: 'a.saito@corp.example', department: 'IT', title: 'ネットワーク担当', risk_score: 15, risk_indicators: [], anomaly_count_week: 0, last_anomaly: '2026-02-20T11:00:00Z', watchlist: false, trend: 'stable' },
  // Extra users for heatmap fill
  { id: 'u-013', name: '橋本 浩', email: 'h.hashimoto@corp.example', department: '法務', title: '法務担当', risk_score: 45, risk_indicators: ['認証失敗'], anomaly_count_week: 2, last_anomaly: '2026-03-10T09:00:00Z', watchlist: false, trend: 'stable' },
  { id: 'u-014', name: '加藤 真', email: 'm.kato@corp.example', department: '財務', title: 'アナリスト', risk_score: 64, risk_indicators: ['深夜アクセス'], anomaly_count_week: 3, last_anomaly: '2026-03-16T22:00:00Z', watchlist: false, trend: 'up' },
  { id: 'u-015', name: '伊藤 舞', email: 'ma.ito@corp.example', department: '営業', title: '営業担当', risk_score: 28, risk_indicators: [], anomaly_count_week: 1, last_anomaly: '2026-03-08T13:00:00Z', watchlist: false, trend: 'stable' },
  { id: 'u-016', name: '坂本 龍', email: 'r.sakamoto@corp.example', department: '研究開発', risk_score: 77, title: '研究員', risk_indicators: ['知財アクセス', '大量DL'], anomaly_count_week: 5, last_anomaly: '2026-03-17T11:00:00Z', watchlist: true, trend: 'up' },
  { id: 'u-017', name: '中島 香', email: 'k.nakashima@corp.example', department: 'IT', title: 'セキュリティエンジニア', risk_score: 33, risk_indicators: [], anomaly_count_week: 1, last_anomaly: '2026-03-11T14:00:00Z', watchlist: false, trend: 'stable' },
  { id: 'u-018', name: '前田 誠', email: 'm.maeda@corp.example', department: 'HR', title: '採用担当', risk_score: 19, risk_indicators: [], anomaly_count_week: 0, last_anomaly: '2026-02-25T10:00:00Z', watchlist: false, trend: 'stable' },
  { id: 'u-019', name: '後藤 晴美', email: 'h.goto@corp.example', department: '法務', title: '弁護士', risk_score: 12, risk_indicators: [], anomaly_count_week: 0, last_anomaly: '2026-02-15T09:00:00Z', watchlist: false, trend: 'stable' },
  { id: 'u-020', name: '高橋 翔', email: 's.takahashi@corp.example', department: '財務', title: 'CFO', risk_score: 8, risk_indicators: [], anomaly_count_week: 0, last_anomaly: '2026-02-10T09:00:00Z', watchlist: false, trend: 'stable' },
]

const MOCK_EVENTS: BehaviorEvent[] = [
  { id: 'e-001', user_id: 'u-001', user_name: '田中 一郎', department: '財務', event_type: 'bulk_download', timestamp: '2026-03-17T23:14:00Z', severity: 'critical', description: '大量データダウンロード', details: '財務システムから1.2GBのデータを深夜に一括ダウンロード' },
  { id: 'e-002', user_id: 'u-002', user_name: '鈴木 美咲', department: 'IT', event_type: 'privilege_escalation', timestamp: '2026-03-17T15:32:00Z', severity: 'high', description: '権限昇格の試み', details: 'rootアクセスを未承認で取得しようとした形跡' },
  { id: 'e-003', user_id: 'u-003', user_name: '佐藤 健', department: '営業', event_type: 'bulk_download', timestamp: '2026-03-16T10:11:00Z', severity: 'high', description: '顧客DBの大量エクスポート', details: '顧客マスタデータ全件をCSVエクスポート（退職予定確認済み）' },
  { id: 'e-004', user_id: 'u-001', user_name: '田中 一郎', department: '財務', event_type: 'after_hours_access', timestamp: '2026-03-17T01:22:00Z', severity: 'high', description: '深夜1時のシステムアクセス', details: '財務ERPに深夜1時アクセス。VPNなし、社外IP' },
  { id: 'e-005', user_id: 'u-016', user_name: '坂本 龍', department: '研究開発', event_type: 'bulk_download', timestamp: '2026-03-17T11:00:00Z', severity: 'high', description: '特許関連ファイルの一括コピー', details: '知財サーバーから特許文書500件以上をコピー' },
  { id: 'e-006', user_id: 'u-004', user_name: '山田 花子', department: 'HR', event_type: 'unusual_geo', timestamp: '2026-03-15T14:20:00Z', severity: 'medium', description: '海外IPからのログイン', details: '通常は東京からログインするが、今回はバンコクIPから接続' },
  { id: 'e-007', user_id: 'u-005', user_name: '中村 竜二', department: 'IT', event_type: 'after_hours_access', timestamp: '2026-03-17T02:44:00Z', severity: 'medium', description: '深夜2時44分のサーバーアクセス', details: '承認なしで本番サーバーに深夜アクセス' },
  { id: 'e-008', user_id: 'u-006', user_name: '小林 さゆり', department: '研究開発', event_type: 'bulk_download', timestamp: '2026-03-14T16:55:00Z', severity: 'medium', description: 'クラウドへの大量同期', details: 'OneDriveへ研究データ3GB分を同期。通常の5倍の量' },
  { id: 'e-009', user_id: 'u-007', user_name: '伊藤 誠', department: '法務', event_type: 'auth_failure', timestamp: '2026-03-16T09:30:00Z', severity: 'low', description: '認証失敗が5回連続', details: 'アクセス管理システムで5回連続で認証失敗' },
  { id: 'e-010', user_id: 'u-002', user_name: '鈴木 美咲', department: 'IT', event_type: 'mass_delete', timestamp: '2026-03-16T18:00:00Z', severity: 'critical', description: 'ログファイルの大量削除', details: '過去30日分のアクセスログ200件を削除。証拠隠滅の可能性' },
  { id: 'e-011', user_id: 'u-013', user_name: '橋本 浩', department: '法務', event_type: 'auth_failure', timestamp: '2026-03-10T09:00:00Z', severity: 'low', description: '認証失敗3回', details: 'メールサーバーへの認証失敗' },
  { id: 'e-012', user_id: 'u-014', user_name: '加藤 真', department: '財務', event_type: 'after_hours_access', timestamp: '2026-03-16T22:00:00Z', severity: 'medium', description: '深夜の財務システムアクセス', details: '月次締め作業とは無関係な深夜アクセス' },
  { id: 'e-013', user_id: 'u-001', user_name: '田中 一郎', department: '財務', event_type: 'unusual_geo', timestamp: '2026-03-15T20:00:00Z', severity: 'high', description: 'シンガポールIPからのアクセス', details: '同時に東京オフィスでもカード使用記録あり' },
  { id: 'e-014', user_id: 'u-016', user_name: '坂本 龍', department: '研究開発', event_type: 'privilege_escalation', timestamp: '2026-03-16T14:00:00Z', severity: 'high', description: '管理者権限への昇格', details: '研究システム管理者権限を不正取得' },
  { id: 'e-015', user_id: 'u-003', user_name: '佐藤 健', department: '営業', event_type: 'bulk_download', timestamp: '2026-03-17T09:00:00Z', severity: 'high', description: '取引先連絡先リストのDL', details: '全取引先リスト（5,000件）をエクスポート' },
  // Additional events
  { id: 'e-016', user_id: 'u-005', user_name: '中村 竜二', department: 'IT', event_type: 'mass_delete', timestamp: '2026-03-15T03:00:00Z', severity: 'high', description: 'バックアップファイルの削除', details: '先月のバックアップファイル50件を削除' },
  { id: 'e-017', user_id: 'u-008', user_name: '渡辺 奈々', department: '財務', event_type: 'auth_failure', timestamp: '2026-03-13T11:00:00Z', severity: 'low', description: '認証失敗', details: 'MFAコードの入力ミス2回' },
  { id: 'e-018', user_id: 'u-004', user_name: '山田 花子', department: 'HR', event_type: 'bulk_download', timestamp: '2026-03-14T10:00:00Z', severity: 'medium', description: '従業員個人情報のエクスポート', details: '全従業員の個人情報CSVをダウンロード' },
  { id: 'e-019', user_id: 'u-001', user_name: '田中 一郎', department: '財務', event_type: 'privilege_escalation', timestamp: '2026-03-16T00:30:00Z', severity: 'critical', description: 'DB管理者権限の取得', details: '財務DBの管理者権限を不正取得し、監査テーブルにアクセス' },
  { id: 'e-020', user_id: 'u-002', user_name: '鈴木 美咲', department: 'IT', event_type: 'unusual_geo', timestamp: '2026-03-17T08:00:00Z', severity: 'medium', description: '海外VPNからのアクセス', details: 'Torノード経由のアクセスを検知' },
  { id: 'e-021', user_id: 'u-009', user_name: '松本 大輔', department: '営業', event_type: 'after_hours_access', timestamp: '2026-03-12T22:30:00Z', severity: 'low', description: '業務時間外アクセス', details: '軽微な業務外サイトへのアクセス' },
  { id: 'e-022', user_id: 'u-006', user_name: '小林 さゆり', department: '研究開発', event_type: 'unusual_geo', timestamp: '2026-03-13T15:00:00Z', severity: 'medium', description: '異常なIPからのアクセス', details: 'データセンターとは異なる地域から研究サーバーに接続' },
  { id: 'e-023', user_id: 'u-014', user_name: '加藤 真', department: '財務', event_type: 'bulk_download', timestamp: '2026-03-15T21:00:00Z', severity: 'high', description: '財務レポートの一括ダウンロード', details: '四半期レポート全件をダウンロード（業務不明）' },
  { id: 'e-024', user_id: 'u-016', user_name: '坂本 龍', department: '研究開発', event_type: 'mass_delete', timestamp: '2026-03-17T10:30:00Z', severity: 'high', description: '実験データの削除', details: '過去12ヶ月の実験ログ300件を削除' },
  { id: 'e-025', user_id: 'u-003', user_name: '佐藤 健', department: '営業', event_type: 'after_hours_access', timestamp: '2026-03-15T23:00:00Z', severity: 'medium', description: '深夜のCRMアクセス', details: '深夜にCRMシステムに接続、取引先データを閲覧' },
  { id: 'e-026', user_id: 'u-005', user_name: '中村 竜二', department: 'IT', event_type: 'auth_failure', timestamp: '2026-03-16T12:00:00Z', severity: 'low', description: '認証失敗', details: '管理コンソールへのログイン失敗' },
  { id: 'e-027', user_id: 'u-002', user_name: '鈴木 美咲', department: 'IT', event_type: 'bulk_download', timestamp: '2026-03-14T20:00:00Z', severity: 'high', description: 'ソースコードの一括DL', details: '機密リポジトリから2,000ファイルをクローン' },
  { id: 'e-028', user_id: 'u-013', user_name: '橋本 浩', department: '法務', event_type: 'unusual_geo', timestamp: '2026-03-09T10:00:00Z', severity: 'low', description: 'VPN接続なし', details: '社外から直接社内システムにアクセス（ポリシー違反）' },
  { id: 'e-029', user_id: 'u-001', user_name: '田中 一郎', department: '財務', event_type: 'mass_delete', timestamp: '2026-03-18T00:10:00Z', severity: 'critical', description: '監査ログ削除の試み', details: '自身に関連する監査ログの削除を試みたが失敗（権限エラー）' },
  { id: 'e-030', user_id: 'u-016', user_name: '坂本 龍', department: '研究開発', event_type: 'unusual_geo', timestamp: '2026-03-16T22:00:00Z', severity: 'high', description: '競合他社IPからのアクセス', details: 'IPアドレスが競合他社データセンターと一致' },
]

const MOCK_INVESTIGATIONS: Investigation[] = [
  {
    id: 'inv-001', case_id: 'INV-2026-001',
    subject_user_id: 'u-001', subject_user: '田中 一郎', department: '財務',
    investigator: '佐藤 セキュリティ', opened_date: '2026-03-15', closed_date: null,
    status: 'in_progress', risk_level: 'critical',
    notes: '財務データの大量持ち出しおよびデータ隠蔽の疑い。法務部と連携中。',
    risk_indicators: ['深夜アクセス', '大量DL', '監査ログ削除試行', '海外IP'],
    outcome: null, priority: 'critical',
  },
  {
    id: 'inv-002', case_id: 'INV-2026-002',
    subject_user_id: 'u-002', subject_user: '鈴木 美咲', department: 'IT',
    investigator: '田中 セキュリティリード', opened_date: '2026-03-16', closed_date: null,
    status: 'open', risk_level: 'high',
    notes: '権限昇格とログ削除の複合的な行動パターンを確認。IT管理者へのヒアリング予定。',
    risk_indicators: ['権限昇格', 'ログ削除', 'Tor経由アクセス', 'ソースコード一括DL'],
    outcome: null, priority: 'high',
  },
  {
    id: 'inv-003', case_id: 'INV-2026-003',
    subject_user_id: 'u-003', subject_user: '佐藤 健', department: '営業',
    investigator: '山田 SOCアナリスト', opened_date: '2026-03-10', closed_date: null,
    status: 'in_progress', risk_level: 'high',
    notes: '退職交渉中の社員。顧客データ・取引先リストの持ち出し疑い。退職日まで監視継続。',
    risk_indicators: ['退職前行動', '顧客DBエクスポート', '深夜CRMアクセス'],
    outcome: null, priority: 'high',
  },
  {
    id: 'inv-004', case_id: 'INV-2025-089',
    subject_user_id: 'u-010', subject_user: '木村 裕子', department: 'HR',
    investigator: '鈴木 SOCアナリスト', opened_date: '2025-12-01', closed_date: '2025-12-20',
    status: 'closed', risk_level: 'medium',
    notes: '人事データへの不正アクセス調査。結果、システム設定ミスによる誤検知と判明。',
    risk_indicators: ['人事データ閲覧異常'],
    outcome: 'false_positive', priority: 'medium',
  },
  {
    id: 'inv-005', case_id: 'INV-2025-076',
    subject_user_id: 'u-017', subject_user: '中島 香', department: 'IT',
    investigator: '田中 セキュリティリード', opened_date: '2025-10-15', closed_date: '2025-11-01',
    status: 'closed', risk_level: 'high',
    notes: '内部情報を競合他社に売却したことが確認。法的措置済み。',
    risk_indicators: ['外部メール送信', 'ファイル持ち出し', '競合IPアクセス'],
    outcome: 'confirmed', priority: 'critical',
  },
]

// ─── Helpers ─────────────────────────────────────────────────────────────────

const RISK_COLORS: Record<RiskLevel, string> = {
  critical: 'bg-falcon-red/20 text-falcon-red border border-falcon-red/30',
  high: 'bg-orange-900/40 text-orange-400 border border-orange-700/40',
  medium: 'bg-yellow-900/40 text-yellow-400 border border-yellow-700/40',
  low: 'bg-green-900/40 text-green-400 border border-green-700/40',
}

const RISK_LABELS: Record<RiskLevel, string> = { critical: '重大', high: '高', medium: '中', low: '低' }

const EVENT_TYPE_LABELS: Record<EventType, string> = {
  after_hours_access: '時間外アクセス',
  bulk_download: '大量ダウンロード',
  privilege_escalation: '権限昇格',
  unusual_geo: '異常ジオ',
  mass_delete: '大量削除',
  auth_failure: '認証失敗',
}

const EVENT_TYPE_COLORS: Record<EventType, string> = {
  after_hours_access: 'bg-blue-900/40 text-blue-300',
  bulk_download: 'bg-orange-900/40 text-orange-300',
  privilege_escalation: 'bg-falcon-red/20 text-falcon-red',
  unusual_geo: 'bg-purple-900/40 text-purple-300',
  mass_delete: 'bg-red-900/40 text-red-300',
  auth_failure: 'bg-gray-800 text-gray-400',
}

const STATUS_STYLES: Record<InvestigationStatus, string> = {
  open: 'bg-blue-900/40 text-blue-300 border border-blue-700/40',
  in_progress: 'bg-yellow-900/40 text-yellow-400 border border-yellow-700/40',
  closed: 'bg-gray-800 text-gray-400 border border-gray-700/40',
  escalated: 'bg-falcon-red/20 text-falcon-red border border-falcon-red/30',
}

const STATUS_LABELS: Record<InvestigationStatus, string> = {
  open: 'オープン', in_progress: '調査中', closed: 'クローズ', escalated: 'エスカレーション'
}

const OUTCOME_LABELS: Record<string, string> = {
  confirmed: '脅威確認', unconfirmed: '未確認', false_positive: '誤検知', 'null': '—'
}

const DEPARTMENTS = ['財務', 'IT', '営業', 'HR', '研究開発', '法務']
const RISK_BUCKETS = ['0-25', '26-50', '51-75', '76-100'] as const
type RiskBucket = typeof RISK_BUCKETS[number]

function getRiskBucket(score: number): RiskBucket {
  if (score <= 25) return '0-25'
  if (score <= 50) return '26-50'
  if (score <= 75) return '51-75'
  return '76-100'
}

const BUCKET_BG: Record<RiskBucket, (count: number) => string> = {
  '0-25': (n) => n === 0 ? 'bg-falcon-surface' : 'bg-green-900/30 hover:bg-green-900/50',
  '26-50': (n) => n === 0 ? 'bg-falcon-surface' : 'bg-yellow-900/30 hover:bg-yellow-900/50',
  '51-75': (n) => n === 0 ? 'bg-falcon-surface' : 'bg-orange-900/30 hover:bg-orange-900/50',
  '76-100': (n) => n === 0 ? 'bg-falcon-surface' : 'bg-falcon-red/20 hover:bg-falcon-red/30',
}

const BUCKET_TEXT: Record<RiskBucket, string> = {
  '0-25': 'text-green-400',
  '26-50': 'text-yellow-400',
  '51-75': 'text-orange-400',
  '76-100': 'text-falcon-red',
}

// ─── Heatmap ──────────────────────────────────────────────────────────────────

function UserRiskHeatmap({ users, onCellClick, activeDept, activeBucket }: {
  users: RiskUser[]
  onCellClick: (dept: string, bucket: RiskBucket) => void
  activeDept: string
  activeBucket: RiskBucket | ''
}) {
  return (
    <div className="bg-falcon-surface border border-falcon-border rounded-lg p-5 mb-4">
      <h3 className="text-white font-semibold mb-4 text-sm">リスクユーザーマトリクス（クリックでフィルタ）</h3>
      <div className="overflow-x-auto">
        <table className="w-full">
          <thead>
            <tr>
              <th className="text-left text-falcon-muted text-xs pb-2 pr-4 font-medium w-28">部門</th>
              {RISK_BUCKETS.map(b => (
                <th key={b} className={`text-center text-xs pb-2 font-medium px-2 ${BUCKET_TEXT[b]}`}>
                  {b}
                </th>
              ))}
            </tr>
          </thead>
          <tbody className="divide-y divide-falcon-border">
            {DEPARTMENTS.map(dept => (
              <tr key={dept}>
                <td className="text-falcon-muted text-xs py-2 pr-4 font-medium">{dept}</td>
                {RISK_BUCKETS.map(bucket => {
                  const count = users.filter(u => u.department === dept && getRiskBucket(u.risk_score) === bucket).length
                  const isActive = activeDept === dept && activeBucket === bucket
                  return (
                    <td key={bucket} className="px-2 py-1.5 text-center">
                      <button
                        onClick={() => onCellClick(dept, bucket)}
                        className={`w-full h-10 rounded flex items-center justify-center text-sm font-bold transition-all
                                    ${count === 0 ? 'bg-falcon-surface text-falcon-subtle cursor-default' : BUCKET_BG[bucket](count)}
                                    ${isActive ? 'ring-2 ring-white' : ''}
                                    `}
                        disabled={count === 0}
                      >
                        {count > 0 ? count : '—'}
                      </button>
                    </td>
                  )
                })}
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  )
}

// ─── Indicator Stats ──────────────────────────────────────────────────────────

function IndicatorCards({ events }: { events: BehaviorEvent[] }) {
  const indicators: IndicatorStats[] = [
    { type: 'after_hours_access', label: '時間外アクセス', count: events.filter(e => e.event_type === 'after_hours_access').length, trend: 'up', trend_pct: 23 },
    { type: 'bulk_download', label: '大量ダウンロード', count: events.filter(e => e.event_type === 'bulk_download').length, trend: 'up', trend_pct: 45 },
    { type: 'privilege_escalation', label: '権限昇格試行', count: events.filter(e => e.event_type === 'privilege_escalation').length, trend: 'stable', trend_pct: 0 },
    { type: 'unusual_geo', label: '異常ジオログイン', count: events.filter(e => e.event_type === 'unusual_geo').length, trend: 'up', trend_pct: 15 },
    { type: 'mass_delete', label: '大量ファイル削除', count: events.filter(e => e.event_type === 'mass_delete').length, trend: 'up', trend_pct: 67 },
    { type: 'auth_failure', label: '認証失敗', count: events.filter(e => e.event_type === 'auth_failure').length, trend: 'down', trend_pct: -10 },
  ]

  return (
    <div className="grid grid-cols-2 md:grid-cols-3 gap-3 mb-5">
      {indicators.map(ind => (
        <div key={ind.type} className="bg-falcon-surface border border-falcon-border rounded-lg p-4">
          <div className="flex items-start justify-between mb-2">
            <span className={`text-xs px-2 py-0.5 rounded-sm ${EVENT_TYPE_COLORS[ind.type]}`}>{ind.label}</span>
            <div className={`flex items-center gap-1 text-xs ${ind.trend === 'up' ? 'text-falcon-red' : ind.trend === 'down' ? 'text-green-400' : 'text-falcon-muted'}`}>
              {ind.trend === 'up' ? <ArrowUpRight className="w-3.5 h-3.5" /> : ind.trend === 'down' ? <ArrowDownRight className="w-3.5 h-3.5" /> : <Minus className="w-3.5 h-3.5" />}
              {ind.trend !== 'stable' && `${Math.abs(ind.trend_pct)}%`}
            </div>
          </div>
          <p className="text-white text-2xl font-bold">{ind.count}</p>
          <p className="text-falcon-muted text-xs mt-0.5">今週のイベント数</p>
        </div>
      ))}
    </div>
  )
}

// ─── Peer Comparison ─────────────────────────────────────────────────────────

function PeerComparison({ users, events }: { users: RiskUser[]; events: BehaviorEvent[] }) {
  const [selectedUserId, setSelectedUserId] = useState(users[0]?.id ?? '')
  const selectedUser = users.find(u => u.id === selectedUserId)

  const userEventTypes: EventType[] = ['after_hours_access', 'bulk_download', 'privilege_escalation', 'unusual_geo', 'mass_delete', 'auth_failure']

  const getUserCount = (userId: string, type: EventType) =>
    events.filter(e => e.user_id === userId && e.event_type === type).length

  const getDeptAvg = (dept: string, type: EventType) => {
    const deptUsers = users.filter(u => u.department === dept)
    if (deptUsers.length === 0) return 0
    const total = deptUsers.reduce((sum, u) => sum + getUserCount(u.id, type), 0)
    return Math.round((total / deptUsers.length) * 10) / 10
  }

  const maxCount = selectedUser
    ? Math.max(...userEventTypes.map(t => Math.max(getUserCount(selectedUser.id, t), getDeptAvg(selectedUser.department, t))), 1)
    : 1

  return (
    <div className="bg-falcon-surface border border-falcon-border rounded-lg p-5">
      <div className="flex items-center justify-between mb-4">
        <h3 className="text-white font-semibold text-sm">ピア比較</h3>
        <select
          value={selectedUserId}
          onChange={e => setSelectedUserId(e.target.value)}
          className="bg-[#070d19] border border-falcon-border rounded-sm px-2 py-1 text-white text-xs focus:outline-hidden focus:border-falcon-red/50"
        >
          {users.map(u => <option key={u.id} value={u.id}>{u.name}</option>)}
        </select>
      </div>
      {selectedUser && (
        <>
          <div className="flex items-center gap-4 text-xs mb-4">
            <span className="flex items-center gap-1.5"><span className="w-3 h-3 rounded-sm bg-falcon-red/60 inline-block" />選択ユーザー: {selectedUser.name}</span>
            <span className="flex items-center gap-1.5"><span className="w-3 h-3 rounded-sm bg-blue-500/60 inline-block" />部門平均 ({selectedUser.department})</span>
          </div>
          <div className="space-y-3">
            {userEventTypes.map(type => {
              const userCnt = getUserCount(selectedUser.id, type)
              const deptAvg = getDeptAvg(selectedUser.department, type)
              const userPct = (userCnt / maxCount) * 100
              const avgPct = (deptAvg / maxCount) * 100
              return (
                <div key={type}>
                  <div className="flex items-center justify-between mb-1">
                    <span className="text-falcon-muted text-xs">{EVENT_TYPE_LABELS[type]}</span>
                    <div className="flex gap-3 text-xs">
                      <span className="text-falcon-red">{userCnt}</span>
                      <span className="text-blue-400">{deptAvg}</span>
                    </div>
                  </div>
                  <div className="relative h-4 bg-falcon-border rounded-sm overflow-hidden">
                    <div className="absolute left-0 top-0.5 h-1.5 rounded-sm bg-falcon-red/60 transition-all" style={{ width: `${userPct}%` }} />
                    <div className="absolute left-0 bottom-0.5 h-1.5 rounded-sm bg-blue-500/60 transition-all" style={{ width: `${avgPct}%` }} />
                  </div>
                </div>
              )
            })}
          </div>
        </>
      )}
    </div>
  )
}

// ─── New Investigation Modal ──────────────────────────────────────────────────

function NewInvestigationModal({ users, onClose, onSubmit }: {
  users: RiskUser[]
  onClose: () => void
  onSubmit: (data: Partial<Investigation>) => void
}) {
  const [form, setForm] = useState({
    subject_user_id: '',
    reason: '',
    risk_indicators: [] as string[],
    investigator: '',
    priority: 'medium' as Investigation['priority'],
    notes: '',
  })
  const [indicatorInput, setIndicatorInput] = useState('')

  const addIndicator = () => {
    if (indicatorInput.trim()) {
      setForm(p => ({ ...p, risk_indicators: [...p.risk_indicators, indicatorInput.trim()] }))
      setIndicatorInput('')
    }
  }

  const handleSubmit = () => {
    if (!form.subject_user_id || !form.investigator) return
    const user = users.find(u => u.id === form.subject_user_id)
    onSubmit({
      case_id: `INV-${new Date().getFullYear()}-${String(Math.floor(Math.random() * 900) + 100)}`,
      subject_user_id: form.subject_user_id,
      subject_user: user?.name ?? '',
      department: user?.department ?? '',
      investigator: form.investigator,
      opened_date: new Date().toISOString().slice(0, 10),
      closed_date: null,
      status: 'open',
      risk_level: form.priority === 'critical' ? 'critical' : form.priority === 'high' ? 'high' : form.priority === 'medium' ? 'medium' : 'low',
      notes: form.notes,
      risk_indicators: form.risk_indicators,
      outcome: null,
      priority: form.priority,
    })
    onClose()
  }

  const ALL_INDICATORS = ['深夜アクセス', '大量DL', '権限昇格', '退職前行動', '海外IPアクセス', 'ログ削除', 'データ持ち出し', 'ソーシャルエンジニアリング']

  return (
    <div className="fixed inset-0 z-50 bg-black/70 flex items-center justify-center p-4">
      <div className="bg-falcon-surface border border-falcon-border rounded-xl w-full max-w-lg max-h-[85vh] overflow-y-auto">
        <div className="flex items-center justify-between p-5 border-b border-falcon-border sticky top-0 bg-falcon-surface">
          <h3 className="text-white font-bold">新規調査開始</h3>
          <button onClick={onClose} className="text-falcon-muted hover:text-white"><X className="w-5 h-5" /></button>
        </div>
        <div className="p-5 space-y-4">
          <div>
            <label className="text-falcon-muted text-xs mb-1 block">対象ユーザー *</label>
            <select
              value={form.subject_user_id}
              onChange={e => setForm(p => ({ ...p, subject_user_id: e.target.value }))}
              className="w-full bg-[#070d19] border border-falcon-border rounded-sm px-3 py-2 text-white text-sm focus:outline-hidden focus:border-falcon-red/50"
            >
              <option value="">選択してください</option>
              {users.map(u => <option key={u.id} value={u.id}>{u.name} ({u.department})</option>)}
            </select>
          </div>
          <div>
            <label className="text-falcon-muted text-xs mb-1 block">調査担当者 *</label>
            <input
              value={form.investigator}
              onChange={e => setForm(p => ({ ...p, investigator: e.target.value }))}
              className="w-full bg-[#070d19] border border-falcon-border rounded-sm px-3 py-2 text-white text-sm focus:outline-hidden focus:border-falcon-red/50"
              placeholder="担当者名..."
            />
          </div>
          <div>
            <label className="text-falcon-muted text-xs mb-1 block">優先度</label>
            <select
              value={form.priority}
              onChange={e => setForm(p => ({ ...p, priority: e.target.value as Investigation['priority'] }))}
              className="w-full bg-[#070d19] border border-falcon-border rounded-sm px-3 py-2 text-white text-sm focus:outline-hidden focus:border-falcon-red/50"
            >
              <option value="critical">重大</option>
              <option value="high">高</option>
              <option value="medium">中</option>
              <option value="low">低</option>
            </select>
          </div>
          <div>
            <label className="text-falcon-muted text-xs mb-2 block">リスク指標（チェック）</label>
            <div className="flex flex-wrap gap-2 mb-2">
              {ALL_INDICATORS.map(ind => (
                <label key={ind} className="flex items-center gap-1.5 text-xs cursor-pointer">
                  <input
                    type="checkbox"
                    checked={form.risk_indicators.includes(ind)}
                    onChange={() => setForm(p => ({
                      ...p,
                      risk_indicators: p.risk_indicators.includes(ind)
                        ? p.risk_indicators.filter(x => x !== ind)
                        : [...p.risk_indicators, ind],
                    }))}
                    className="accent-falcon-red"
                  />
                  <span className="text-falcon-muted">{ind}</span>
                </label>
              ))}
            </div>
            <div className="flex gap-2">
              <input
                value={indicatorInput}
                onChange={e => setIndicatorInput(e.target.value)}
                onKeyDown={e => e.key === 'Enter' && addIndicator()}
                placeholder="カスタム指標を追加..."
                className="flex-1 bg-[#070d19] border border-falcon-border rounded-sm px-3 py-2 text-white text-xs focus:outline-hidden focus:border-falcon-red/50"
              />
              <button onClick={addIndicator} className="px-3 py-2 bg-falcon-border text-falcon-muted rounded-sm text-xs hover:text-white transition-colors">追加</button>
            </div>
          </div>
          <div>
            <label className="text-falcon-muted text-xs mb-1 block">備考</label>
            <textarea
              value={form.notes}
              onChange={e => setForm(p => ({ ...p, notes: e.target.value }))}
              rows={3}
              className="w-full bg-[#070d19] border border-falcon-border rounded-sm px-3 py-2 text-white text-sm focus:outline-hidden focus:border-falcon-red/50 resize-none"
              placeholder="調査の背景・理由..."
            />
          </div>
        </div>
        <div className="flex justify-end gap-3 p-5 border-t border-falcon-border">
          <button onClick={onClose} className="px-4 py-2 text-sm text-falcon-muted hover:text-white transition-colors">キャンセル</button>
          <button
            onClick={handleSubmit}
            disabled={!form.subject_user_id || !form.investigator}
            className="px-4 py-2 text-sm bg-falcon-red text-white rounded-sm font-medium hover:bg-[#c5001f] disabled:opacity-50 disabled:cursor-not-allowed transition-colors"
          >
            調査開始
          </button>
        </div>
      </div>
    </div>
  )
}

// ─── Main Page ────────────────────────────────────────────────────────────────

type Tab = 'risk_users' | 'behavior' | 'investigations'

export default function InsiderThreatPage() {
  const queryClient = useQueryClient()
  const [tab, setTab] = useState<Tab>('risk_users')
  const [selectedDept, setSelectedDept] = useState('')
  const [selectedBucket, setSelectedBucket] = useState<RiskBucket | ''>('')
  const [userSearch, setUserSearch] = useState('')
  const [eventSearch, setEventSearch] = useState('')
  const [showNewInvModal, setShowNewInvModal] = useState(false)
  const [watchlist, setWatchlist] = useState<Set<string>>(new Set<string>())
  const [selectedEventDetail, setSelectedEventDetail] = useState<BehaviorEvent | null>(null)

  const { data: usersData } = useQuery<RiskUser[]>({
    queryKey: ['insider-threat-users'],
    queryFn: () => apiFetch('/api/v1/insider-threat/users'),
    staleTime: 30_000,
  })

  const { data: eventsData } = useQuery<BehaviorEvent[]>({
    queryKey: ['insider-threat-events'],
    queryFn: () => apiFetch('/api/v1/insider-threat/events'),
    staleTime: 30_000,
  })

  const { data: investigationsData } = useQuery<Investigation[]>({
    queryKey: ['insider-threat-investigations'],
    queryFn: () => apiFetch('/api/v1/insider-threat/investigations'),
    staleTime: 30_000,
  })

  const users = usersData ?? []
  const events = eventsData ?? []
  const investigations = investigationsData ?? []

  const addInvMutation = useMutation({
    mutationFn: (data: Partial<Investigation>) =>
      apiFetch('/api/v1/insider-threat/investigations', { method: 'POST', body: JSON.stringify(data) }),
    onSuccess: () => queryClient.invalidateQueries({ queryKey: ['insider-threat-investigations'] }),
  })

  const highRiskUsers = users.filter(u => u.risk_score > 70)
  const activeInvestigations = investigations.filter(i => i.status !== 'closed')
  const incidentsThisMonth = investigations.filter(i => i.opened_date >= '2026-03-01').length

  // Filtered users
  const filteredUsers = users.filter(u => {
    if (userSearch && !u.name.toLowerCase().includes(userSearch.toLowerCase()) && !u.department.toLowerCase().includes(userSearch.toLowerCase())) return false
    if (selectedDept && u.department !== selectedDept) return false
    if (selectedBucket) {
      const bucket = getRiskBucket(u.risk_score)
      if (bucket !== selectedBucket) return false
    }
    return true
  }).sort((a, b) => b.risk_score - a.risk_score)

  const filteredEvents = events.filter(e => {
    if (eventSearch && !e.user_name.toLowerCase().includes(eventSearch.toLowerCase()) && !e.description.toLowerCase().includes(eventSearch.toLowerCase())) return false
    return true
  }).sort((a, b) => new Date(b.timestamp).getTime() - new Date(a.timestamp).getTime())

  const closedInvs = investigations.filter(i => i.status === 'closed')
  const confirmedCount = closedInvs.filter(i => i.outcome === 'confirmed').length
  const unconfirmedCount = closedInvs.filter(i => i.outcome === 'unconfirmed').length
  const fpCount = closedInvs.filter(i => i.outcome === 'false_positive').length

  const handleHeatmapClick = (dept: string, bucket: RiskBucket) => {
    if (selectedDept === dept && selectedBucket === bucket) {
      setSelectedDept('')
      setSelectedBucket('')
    } else {
      setSelectedDept(dept)
      setSelectedBucket(bucket)
    }
  }

  const toggleWatchlist = (userId: string) => {
    setWatchlist(prev => {
      const next = new Set(prev)
      next.has(userId) ? next.delete(userId) : next.add(userId)
      return next
    })
  }

  const tabs: { id: Tab; label: string }[] = [
    { id: 'risk_users', label: 'リスクユーザー' },
    { id: 'behavior', label: '行動分析' },
    { id: 'investigations', label: '調査' },
  ]

  return (
    <div className="min-h-screen bg-[#070d19] p-6">
      {/* Header */}
      <div className="flex items-center justify-between mb-6">
        <div className="flex items-center gap-3">
          <div className="w-9 h-9 rounded-lg bg-falcon-red/10 border border-falcon-red/30 flex items-center justify-center">
            <Eye className="w-5 h-5 text-falcon-red" />
          </div>
          <div>
            <h1 className="text-white font-bold text-xl">内部脅威ダッシュボード</h1>
            <p className="text-falcon-muted text-sm">内部リスクの検知・分析・調査</p>
          </div>
        </div>
        <button
          onClick={() => queryClient.invalidateQueries({ queryKey: ['insider-threat-users', 'insider-threat-events', 'insider-threat-investigations'] })}
          className="p-2 rounded-lg border border-falcon-border text-falcon-muted hover:text-white hover:border-falcon-muted/40 transition-colors"
        >
          <RefreshCw className="w-4 h-4" />
        </button>
      </div>

      {/* Summary row */}
      <div className="grid grid-cols-4 gap-4 mb-6">
        {[
          { label: '監視対象ユーザー', value: users.length, icon: Users, color: 'text-white' },
          { label: '高リスク (>70)', value: highRiskUsers.length, icon: AlertTriangle, color: 'text-falcon-red' },
          { label: '進行中の調査', value: activeInvestigations.length, icon: Activity, color: 'text-orange-400' },
          { label: '今月のインシデント', value: incidentsThisMonth, icon: Shield, color: 'text-yellow-400' },
        ].map(({ label, value, icon: Icon, color }) => (
          <div key={label} className="bg-falcon-surface border border-falcon-border rounded-lg p-4">
            <div className="flex items-center gap-3">
              <Icon className={`w-5 h-5 ${color}`} />
              <div>
                <p className={`text-2xl font-bold ${color}`}>{value}</p>
                <p className="text-falcon-muted text-xs">{label}</p>
              </div>
            </div>
          </div>
        ))}
      </div>

      {/* Tabs */}
      <div className="flex gap-1 mb-6 bg-falcon-surface border border-falcon-border rounded-lg p-1 w-fit">
        {tabs.map(t => (
          <button
            key={t.id}
            onClick={() => setTab(t.id)}
            className={`px-5 py-2 rounded text-sm font-medium transition-colors ${
              tab === t.id
                ? 'bg-falcon-active text-white'
                : 'text-falcon-muted hover:text-white'
            }`}
          >
            {t.label}
          </button>
        ))}
      </div>

      {/* ── リスクユーザー tab ────────────────────────────────────────── */}
      {tab === 'risk_users' && (
        <div>
          <UserRiskHeatmap
            users={users}
            onCellClick={handleHeatmapClick}
            activeDept={selectedDept}
            activeBucket={selectedBucket}
          />

          {/* User search */}
          <div className="flex items-center gap-3 mb-4">
            <div className="relative flex-1 max-w-sm">
              <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-falcon-muted" />
              <input
                value={userSearch}
                onChange={e => setUserSearch(e.target.value)}
                placeholder="ユーザー名または部門で検索..."
                className="w-full bg-falcon-surface border border-falcon-border rounded px-3 py-2 pl-9 text-white text-sm
                           focus:outline-hidden focus:border-falcon-red/50 placeholder:text-falcon-subtle"
              />
            </div>
            {(selectedDept || selectedBucket || userSearch) && (
              <button
                onClick={() => { setSelectedDept(''); setSelectedBucket(''); setUserSearch('') }}
                className="flex items-center gap-1 text-sm text-falcon-red hover:text-[#ff3355] transition-colors"
              >
                <X className="w-4 h-4" />
                フィルタクリア
              </button>
            )}
            <span className="text-falcon-muted text-xs">{filteredUsers.length} / {users.length} ユーザー</span>
          </div>

          {/* Risk users table */}
          <div className="bg-falcon-surface border border-falcon-border rounded-lg overflow-hidden">
            <div className="overflow-x-auto">
              <table className="w-full text-sm">
                <thead className="border-b border-falcon-border">
                  <tr>
                    {['ユーザー', '部門', 'リスクスコア', 'リスク指標', '今週の異常数', '最終異常', 'ウォッチリスト', 'アクション'].map(h => (
                      <th key={h} className="text-left text-falcon-muted text-xs px-4 py-3 font-medium whitespace-nowrap">{h}</th>
                    ))}
                  </tr>
                </thead>
                <tbody className="divide-y divide-falcon-border">
                  {filteredUsers.map(user => (
                    <tr key={user.id} className="hover:bg-falcon-card transition-colors">
                      <td className="px-4 py-3">
                        <div>
                          <div className="flex items-center gap-2">
                            <p className="text-white font-medium text-sm">{user.name}</p>
                            {user.trend === 'up' && <TrendingUp className="w-3.5 h-3.5 text-falcon-red" />}
                            {user.trend === 'down' && <TrendingDown className="w-3.5 h-3.5 text-green-400" />}
                          </div>
                          <p className="text-falcon-muted text-xs">{user.title}</p>
                        </div>
                      </td>
                      <td className="px-4 py-3 text-falcon-muted text-xs">{user.department}</td>
                      <td className="px-4 py-3">
                        <div className="flex items-center gap-2">
                          <div className="w-20 h-2 bg-falcon-border rounded-full">
                            <div
                              className={`h-full rounded-full ${
                                user.risk_score > 75 ? 'bg-falcon-red' :
                                user.risk_score > 50 ? 'bg-orange-500' :
                                user.risk_score > 25 ? 'bg-yellow-500' : 'bg-green-500'
                              }`}
                              style={{ width: `${user.risk_score}%` }}
                            />
                          </div>
                          <span className={`font-bold text-sm ${
                            user.risk_score > 75 ? 'text-falcon-red' :
                            user.risk_score > 50 ? 'text-orange-400' :
                            user.risk_score > 25 ? 'text-yellow-400' : 'text-green-400'
                          }`}>{user.risk_score}</span>
                        </div>
                      </td>
                      <td className="px-4 py-3">
                        <div className="flex flex-wrap gap-1">
                          {user.risk_indicators.slice(0, 2).map(ind => (
                            <span key={ind} className="text-[10px] px-1.5 py-0.5 rounded-sm bg-falcon-red/10 text-falcon-red/80 border border-falcon-red/20">
                              {ind}
                            </span>
                          ))}
                          {user.risk_indicators.length > 2 && (
                            <span className="text-[10px] px-1.5 py-0.5 rounded-sm bg-falcon-border text-falcon-muted">
                              +{user.risk_indicators.length - 2}
                            </span>
                          )}
                        </div>
                      </td>
                      <td className="px-4 py-3">
                        <span className={`font-bold text-sm ${user.anomaly_count_week > 5 ? 'text-falcon-red' : user.anomaly_count_week > 2 ? 'text-orange-400' : 'text-falcon-muted'}`}>
                          {user.anomaly_count_week}
                        </span>
                      </td>
                      <td className="px-4 py-3 text-falcon-muted text-xs whitespace-nowrap">
                        {new Date(user.last_anomaly).toLocaleString('ja-JP', { month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit' })}
                      </td>
                      <td className="px-4 py-3">
                        <button
                          onClick={() => toggleWatchlist(user.id)}
                          className={`transition-colors ${watchlist.has(user.id) ? 'text-yellow-400' : 'text-falcon-subtle hover:text-falcon-muted'}`}
                        >
                          {watchlist.has(user.id) ? <BookmarkCheck className="w-4 h-4" /> : <Bookmark className="w-4 h-4" />}
                        </button>
                      </td>
                      <td className="px-4 py-3">
                        <button
                          onClick={() => { setShowNewInvModal(true) }}
                          className="text-xs px-3 py-1.5 rounded bg-falcon-red/10 text-falcon-red border border-falcon-red/30
                                     hover:bg-falcon-red/20 transition-colors whitespace-nowrap"
                        >
                          調査開始
                        </button>
                      </td>
                    </tr>
                  ))}
                  {filteredUsers.length === 0 && (
                    <tr>
                      <td colSpan={8} className="px-4 py-12 text-center text-falcon-muted">
                        <Users className="w-10 h-10 mx-auto mb-2 text-falcon-subtle" />
                        条件に一致するユーザーが見つかりません
                      </td>
                    </tr>
                  )}
                </tbody>
              </table>
            </div>
          </div>
        </div>
      )}

      {/* ── 行動分析 tab ─────────────────────────────────────────────── */}
      {tab === 'behavior' && (
        <div>
          <IndicatorCards events={events} />

          {/* Anomaly timeline */}
          <div className="grid grid-cols-1 lg:grid-cols-3 gap-5">
            <div className="lg:col-span-2">
              <div className="bg-falcon-surface border border-falcon-border rounded-lg overflow-hidden">
                <div className="flex items-center justify-between px-5 py-3 border-b border-falcon-border">
                  <h3 className="text-white font-semibold text-sm">異常タイムライン</h3>
                  <div className="relative">
                    <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-3.5 h-3.5 text-falcon-muted" />
                    <input
                      value={eventSearch}
                      onChange={e => setEventSearch(e.target.value)}
                      placeholder="検索..."
                      className="bg-[#070d19] border border-falcon-border rounded-sm px-3 py-1.5 pl-8 text-white text-xs focus:outline-hidden focus:border-falcon-red/50 w-48"
                    />
                  </div>
                </div>
                <div className="overflow-y-auto max-h-96">
                  {filteredEvents.map((event, i) => (
                    <div key={event.id} className={`flex items-start gap-3 px-5 py-3 border-b border-falcon-border/50 hover:bg-falcon-card transition-colors ${i === 0 ? '' : ''}`}>
                      <div className="shrink-0 mt-1">
                        <div className={`w-2 h-2 rounded-full mt-1 ${
                          event.severity === 'critical' ? 'bg-falcon-red' :
                          event.severity === 'high' ? 'bg-orange-500' :
                          event.severity === 'medium' ? 'bg-yellow-500' : 'bg-green-500'
                        }`} />
                      </div>
                      <div className="flex-1 min-w-0">
                        <div className="flex items-start justify-between gap-2">
                          <div>
                            <p className="text-white text-sm font-medium">{event.description}</p>
                            <div className="flex items-center gap-2 mt-0.5">
                              <span className="text-falcon-muted text-xs">{event.user_name}</span>
                              <span className="text-falcon-subtle text-xs">·</span>
                              <span className="text-falcon-muted text-xs">{event.department}</span>
                              <span className={`text-[10px] px-1.5 py-0.5 rounded-sm ${EVENT_TYPE_COLORS[event.event_type]}`}>
                                {EVENT_TYPE_LABELS[event.event_type]}
                              </span>
                            </div>
                          </div>
                          <div className="shrink-0 flex items-center gap-2">
                            <span className="text-falcon-muted text-xs whitespace-nowrap">
                              {new Date(event.timestamp).toLocaleString('ja-JP', { month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit' })}
                            </span>
                            <button
                              onClick={() => setSelectedEventDetail(event)}
                              className="text-xs px-2 py-1 rounded-sm bg-falcon-border text-falcon-muted hover:text-white transition-colors whitespace-nowrap"
                            >
                              詳細
                            </button>
                          </div>
                        </div>
                      </div>
                    </div>
                  ))}
                </div>
              </div>
            </div>

            {/* Peer comparison */}
            <div>
              <PeerComparison users={users} events={events} />
            </div>
          </div>

          {/* Event detail mini-modal */}
          {selectedEventDetail && (
            <div className="fixed inset-0 z-50 bg-black/60 flex items-center justify-center p-4">
              <div className="bg-falcon-surface border border-falcon-border rounded-xl w-full max-w-md p-5">
                <div className="flex items-center justify-between mb-4">
                  <h3 className="text-white font-bold">イベント詳細</h3>
                  <button onClick={() => setSelectedEventDetail(null)} className="text-falcon-muted hover:text-white"><X className="w-5 h-5" /></button>
                </div>
                <div className="space-y-3">
                  <div>
                    <p className="text-falcon-muted text-xs">説明</p>
                    <p className="text-white text-sm font-medium">{selectedEventDetail.description}</p>
                  </div>
                  <div>
                    <p className="text-falcon-muted text-xs">詳細</p>
                    <p className="text-falcon-text text-sm">{selectedEventDetail.details}</p>
                  </div>
                  <div className="grid grid-cols-2 gap-3">
                    <div>
                      <p className="text-falcon-muted text-xs">ユーザー</p>
                      <p className="text-white text-sm">{selectedEventDetail.user_name}</p>
                    </div>
                    <div>
                      <p className="text-falcon-muted text-xs">部門</p>
                      <p className="text-white text-sm">{selectedEventDetail.department}</p>
                    </div>
                    <div>
                      <p className="text-falcon-muted text-xs">発生時刻</p>
                      <p className="text-white text-sm">{new Date(selectedEventDetail.timestamp).toLocaleString('ja-JP')}</p>
                    </div>
                    <div>
                      <p className="text-falcon-muted text-xs">重要度</p>
                      <span className={`text-xs px-2 py-0.5 rounded-full font-medium ${RISK_COLORS[selectedEventDetail.severity]}`}>
                        {RISK_LABELS[selectedEventDetail.severity]}
                      </span>
                    </div>
                  </div>
                </div>
              </div>
            </div>
          )}
        </div>
      )}

      {/* ── 調査 tab ─────────────────────────────────────────────────── */}
      {tab === 'investigations' && (
        <div>
          <div className="flex items-center justify-between mb-4">
            <h3 className="text-white font-semibold">進行中の調査</h3>
            <button
              onClick={() => setShowNewInvModal(true)}
              className="flex items-center gap-2 px-4 py-2 rounded-lg bg-falcon-red text-white text-sm font-medium hover:bg-[#c5001f] transition-colors"
            >
              <Plus className="w-4 h-4" />
              新規調査
            </button>
          </div>

          {/* Active investigations */}
          <div className="bg-falcon-surface border border-falcon-border rounded-lg overflow-hidden mb-6">
            <div className="overflow-x-auto">
              <table className="w-full text-sm">
                <thead className="border-b border-falcon-border">
                  <tr>
                    {['ケースID', '対象ユーザー', '調査担当者', '開始日', 'ステータス', 'リスクレベル', '備考', 'アクション'].map(h => (
                      <th key={h} className="text-left text-falcon-muted text-xs px-4 py-3 font-medium whitespace-nowrap">{h}</th>
                    ))}
                  </tr>
                </thead>
                <tbody className="divide-y divide-falcon-border">
                  {investigations.filter(i => i.status !== 'closed').map(inv => (
                    <tr key={inv.id} className="hover:bg-falcon-card transition-colors">
                      <td className="px-4 py-3">
                        <span className="text-falcon-muted font-mono text-xs">{inv.case_id}</span>
                      </td>
                      <td className="px-4 py-3">
                        <p className="text-white font-medium text-sm">{inv.subject_user}</p>
                        <p className="text-falcon-muted text-xs">{inv.department}</p>
                      </td>
                      <td className="px-4 py-3 text-falcon-muted text-xs">{inv.investigator}</td>
                      <td className="px-4 py-3 text-falcon-muted text-xs">{inv.opened_date}</td>
                      <td className="px-4 py-3">
                        <span className={`text-xs px-2 py-0.5 rounded-full font-medium ${STATUS_STYLES[inv.status]}`}>
                          {STATUS_LABELS[inv.status]}
                        </span>
                      </td>
                      <td className="px-4 py-3">
                        <span className={`text-xs px-2 py-0.5 rounded-full font-medium ${RISK_COLORS[inv.risk_level]}`}>
                          {RISK_LABELS[inv.risk_level]}
                        </span>
                      </td>
                      <td className="px-4 py-3 text-falcon-muted text-xs max-w-[200px] truncate">{inv.notes}</td>
                      <td className="px-4 py-3">
                        <button className="text-xs px-3 py-1.5 rounded-sm bg-falcon-border text-falcon-muted hover:text-white transition-colors">
                          続行
                        </button>
                      </td>
                    </tr>
                  ))}
                  {investigations.filter(i => i.status !== 'closed').length === 0 && (
                    <tr>
                      <td colSpan={8} className="px-4 py-8 text-center text-falcon-muted">進行中の調査はありません</td>
                    </tr>
                  )}
                </tbody>
              </table>
            </div>
          </div>

          {/* Closed investigations summary */}
          <div className="bg-falcon-surface border border-falcon-border rounded-lg p-5">
            <h3 className="text-white font-semibold text-sm mb-4">クローズ済み調査サマリー</h3>
            <div className="grid grid-cols-3 gap-4">
              {[
                { label: '脅威確認', value: confirmedCount, color: 'text-falcon-red', bg: 'bg-falcon-red/10 border-falcon-red/20' },
                { label: '未確認', value: unconfirmedCount, color: 'text-yellow-400', bg: 'bg-yellow-900/20 border-yellow-700/20' },
                { label: '誤検知', value: fpCount, color: 'text-green-400', bg: 'bg-green-900/20 border-green-700/20' },
              ].map(({ label, value, color, bg }) => (
                <div key={label} className={`rounded-lg p-4 border ${bg}`}>
                  <p className={`text-2xl font-bold ${color}`}>{value}</p>
                  <p className="text-falcon-muted text-xs mt-1">{label}</p>
                </div>
              ))}
            </div>
            {closedInvs.length > 0 && (
              <div className="mt-4 overflow-x-auto">
                <table className="w-full text-sm">
                  <thead>
                    <tr className="border-b border-falcon-border">
                      {['ケースID', '対象ユーザー', '担当者', 'クローズ日', '結果'].map(h => (
                        <th key={h} className="text-left text-falcon-muted text-xs pb-2 pr-4 font-medium">{h}</th>
                      ))}
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-falcon-border">
                    {closedInvs.map(inv => (
                      <tr key={inv.id}>
                        <td className="py-2 pr-4 text-falcon-muted font-mono text-xs">{inv.case_id}</td>
                        <td className="py-2 pr-4 text-white text-xs">{inv.subject_user}</td>
                        <td className="py-2 pr-4 text-falcon-muted text-xs">{inv.investigator}</td>
                        <td className="py-2 pr-4 text-falcon-muted text-xs">{inv.closed_date}</td>
                        <td className="py-2 text-xs">
                          <span className={`px-2 py-0.5 rounded-full font-medium ${
                            inv.outcome === 'confirmed' ? 'bg-falcon-red/20 text-falcon-red' :
                            inv.outcome === 'false_positive' ? 'bg-green-900/40 text-green-400' :
                            'bg-yellow-900/40 text-yellow-400'
                          }`}>
                            {OUTCOME_LABELS[inv.outcome ?? 'null']}
                          </span>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
          </div>
        </div>
      )}

      {/* New investigation modal */}
      {showNewInvModal && (
        <NewInvestigationModal
          users={users}
          onClose={() => setShowNewInvModal(false)}
          onSubmit={data => addInvMutation.mutate(data)}
        />
      )}
    </div>
  )
}

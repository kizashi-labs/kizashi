'use client'

import { useState, useMemo } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { apiFetch } from '@/lib/api'
import {
  RefreshCw, Plus, Upload, Download, AlertTriangle, CheckCircle2,
  Clock, Trash2, Edit2, ChevronRight, X, Filter, Search,
  Server, Laptop, Router, Smartphone, Cpu, Cloud,
  DollarSign, Calendar, User, MapPin, Hash, ArrowRight,
  ChevronDown, Loader2,
} from 'lucide-react'
import { USE_MOCK, m } from '@/lib/mock'

// ── Types ─────────────────────────────────────────────────────────────────────

type AssetType = 'server' | 'laptop' | 'network' | 'mobile' | 'iot' | 'virtual'
type LifecycleStage = 'procurement' | 'deployment' | 'active' | 'maintenance' | 'retirement' | 'disposal'

interface LifecycleHistoryEntry {
  from_stage: LifecycleStage | null
  to_stage: LifecycleStage
  changed_at: string
  actor: string
  notes?: string
}

interface Asset {
  id: string
  asset_name: string
  type: AssetType
  serial_number: string
  purchase_date: string
  warranty_expiry: string
  lifecycle_stage: LifecycleStage
  assigned_user: string
  location: string
  cost: number
  total_cost_of_ownership: number
  lifecycle_history: LifecycleHistoryEntry[]
}

// ── Mock Data ──────────────────────────────────────────────────────────────────

const NOW = new Date('2026-03-18')

function daysFromNow(d: string) {
  return Math.ceil((new Date(d).getTime() - NOW.getTime()) / 86400000)
}

const STAGE_ORDER: LifecycleStage[] = ['procurement', 'deployment', 'active', 'maintenance', 'retirement', 'disposal']

const MOCK_ASSETS: Asset[] = [
  { id: 'ast-001', asset_name: 'srv-prod-01', type: 'server', serial_number: 'SRV-2021-001-XY', purchase_date: '2021-04-15', warranty_expiry: '2026-04-15', lifecycle_stage: 'active', assigned_user: '田中 健二', location: '東京DC-A', cost: 850000, total_cost_of_ownership: 1250000, lifecycle_history: [{ from_stage: null, to_stage: 'procurement', changed_at: '2021-03-01T10:00:00Z', actor: '佐藤 管理者' }, { from_stage: 'procurement', to_stage: 'deployment', changed_at: '2021-04-15T09:00:00Z', actor: '田中 健二' }, { from_stage: 'deployment', to_stage: 'active', changed_at: '2021-05-01T14:00:00Z', actor: '田中 健二' }] },
  { id: 'ast-002', asset_name: 'WIN-DC01', type: 'server', serial_number: 'WIN-2020-DC-001', purchase_date: '2020-08-10', warranty_expiry: '2025-08-10', lifecycle_stage: 'maintenance', assigned_user: '鈴木 一郎', location: '東京DC-B', cost: 720000, total_cost_of_ownership: 1100000, lifecycle_history: [{ from_stage: null, to_stage: 'procurement', changed_at: '2020-07-01T10:00:00Z', actor: '山田 管理者' }, { from_stage: 'procurement', to_stage: 'deployment', changed_at: '2020-08-10T09:00:00Z', actor: '鈴木 一郎' }, { from_stage: 'deployment', to_stage: 'active', changed_at: '2020-09-01T14:00:00Z', actor: '鈴木 一郎' }, { from_stage: 'active', to_stage: 'maintenance', changed_at: '2025-10-15T10:00:00Z', actor: '田中 健二' }] },
  { id: 'ast-003', asset_name: 'LAPTOP-HR-03', type: 'laptop', serial_number: 'LP-2023-HR-003', purchase_date: '2023-06-20', warranty_expiry: '2026-06-20', lifecycle_stage: 'active', assigned_user: '高橋 花子', location: '本社3F', cost: 180000, total_cost_of_ownership: 220000, lifecycle_history: [{ from_stage: null, to_stage: 'procurement', changed_at: '2023-06-01T10:00:00Z', actor: '佐藤 管理者' }, { from_stage: 'procurement', to_stage: 'deployment', changed_at: '2023-06-20T09:00:00Z', actor: '高橋 花子' }, { from_stage: 'deployment', to_stage: 'active', changed_at: '2023-07-01T14:00:00Z', actor: '高橋 花子' }] },
  { id: 'ast-004', asset_name: 'LAPTOP-DEV-07', type: 'laptop', serial_number: 'LP-2022-DEV-007', purchase_date: '2022-01-15', warranty_expiry: '2026-01-15', lifecycle_stage: 'active', assigned_user: '渡辺 太郎', location: 'リモート', cost: 220000, total_cost_of_ownership: 270000, lifecycle_history: [{ from_stage: null, to_stage: 'procurement', changed_at: '2022-01-01T10:00:00Z', actor: '佐藤 管理者' }, { from_stage: 'procurement', to_stage: 'deployment', changed_at: '2022-01-15T09:00:00Z', actor: '渡辺 太郎' }, { from_stage: 'deployment', to_stage: 'active', changed_at: '2022-02-01T14:00:00Z', actor: '渡辺 太郎' }] },
  { id: 'ast-005', asset_name: 'CISCO-SW-CORE-01', type: 'network', serial_number: 'CSC-2019-CORE-01', purchase_date: '2019-11-20', warranty_expiry: '2024-11-20', lifecycle_stage: 'retirement', assigned_user: 'インフラチーム', location: '東京DC-A', cost: 1200000, total_cost_of_ownership: 2100000, lifecycle_history: [{ from_stage: null, to_stage: 'procurement', changed_at: '2019-10-01T10:00:00Z', actor: '山田 管理者' }, { from_stage: 'procurement', to_stage: 'deployment', changed_at: '2019-11-20T09:00:00Z', actor: 'インフラチーム' }, { from_stage: 'deployment', to_stage: 'active', changed_at: '2019-12-01T14:00:00Z', actor: 'インフラチーム' }, { from_stage: 'active', to_stage: 'maintenance', changed_at: '2024-09-01T10:00:00Z', actor: '田中 健二' }, { from_stage: 'maintenance', to_stage: 'retirement', changed_at: '2025-12-15T10:00:00Z', actor: '佐藤 管理者' }] },
  { id: 'ast-006', asset_name: 'IPHONE-EXEC-01', type: 'mobile', serial_number: 'APL-2024-M-001', purchase_date: '2024-09-15', warranty_expiry: '2026-09-15', lifecycle_stage: 'active', assigned_user: '山田 社長', location: '本社', cost: 180000, total_cost_of_ownership: 200000, lifecycle_history: [{ from_stage: null, to_stage: 'procurement', changed_at: '2024-09-01T10:00:00Z', actor: '佐藤 管理者' }, { from_stage: 'procurement', to_stage: 'deployment', changed_at: '2024-09-15T09:00:00Z', actor: '山田 社長' }, { from_stage: 'deployment', to_stage: 'active', changed_at: '2024-09-20T14:00:00Z', actor: '山田 社長' }] },
  { id: 'ast-007', asset_name: 'IOT-SENSOR-B01', type: 'iot', serial_number: 'IOT-2022-B-001', purchase_date: '2022-03-10', warranty_expiry: '2026-03-10', lifecycle_stage: 'active', assigned_user: '施設管理', location: '工場B棟', cost: 45000, total_cost_of_ownership: 60000, lifecycle_history: [{ from_stage: null, to_stage: 'procurement', changed_at: '2022-02-15T10:00:00Z', actor: '佐藤 管理者' }, { from_stage: 'procurement', to_stage: 'deployment', changed_at: '2022-03-10T09:00:00Z', actor: '施設管理' }, { from_stage: 'deployment', to_stage: 'active', changed_at: '2022-03-15T14:00:00Z', actor: '施設管理' }] },
  { id: 'ast-008', asset_name: 'VM-K8S-NODE-01', type: 'virtual', serial_number: 'VMID-2023-K8S-001', purchase_date: '2023-08-01', warranty_expiry: '2028-08-01', lifecycle_stage: 'active', assigned_user: 'DevOpsチーム', location: 'AWS ap-northeast-1', cost: 0, total_cost_of_ownership: 480000, lifecycle_history: [{ from_stage: null, to_stage: 'procurement', changed_at: '2023-07-20T10:00:00Z', actor: 'DevOpsチーム' }, { from_stage: 'procurement', to_stage: 'deployment', changed_at: '2023-08-01T09:00:00Z', actor: 'DevOpsチーム' }, { from_stage: 'deployment', to_stage: 'active', changed_at: '2023-08-05T14:00:00Z', actor: 'DevOpsチーム' }] },
  { id: 'ast-009', asset_name: 'srv-db-mysql-01', type: 'server', serial_number: 'SRV-2021-DB-009', purchase_date: '2021-07-22', warranty_expiry: '2026-07-22', lifecycle_stage: 'active', assigned_user: '伊藤 DB管理者', location: '東京DC-A', cost: 950000, total_cost_of_ownership: 1400000, lifecycle_history: [{ from_stage: null, to_stage: 'procurement', changed_at: '2021-06-01T10:00:00Z', actor: '佐藤 管理者' }, { from_stage: 'procurement', to_stage: 'deployment', changed_at: '2021-07-22T09:00:00Z', actor: '伊藤 DB管理者' }, { from_stage: 'deployment', to_stage: 'active', changed_at: '2021-08-01T14:00:00Z', actor: '伊藤 DB管理者' }] },
  { id: 'ast-010', asset_name: 'LAPTOP-NEW-01', type: 'laptop', serial_number: 'LP-2026-NEW-001', purchase_date: '2026-03-01', warranty_expiry: '2029-03-01', lifecycle_stage: 'procurement', assigned_user: '未割り当て', location: '倉庫', cost: 195000, total_cost_of_ownership: 195000, lifecycle_history: [{ from_stage: null, to_stage: 'procurement', changed_at: '2026-03-01T10:00:00Z', actor: '佐藤 管理者' }] },
  { id: 'ast-011', asset_name: 'LAPTOP-NEW-02', type: 'laptop', serial_number: 'LP-2026-NEW-002', purchase_date: '2026-03-01', warranty_expiry: '2029-03-01', lifecycle_stage: 'deployment', assigned_user: '木村 次郎', location: '本社2F', cost: 195000, total_cost_of_ownership: 195000, lifecycle_history: [{ from_stage: null, to_stage: 'procurement', changed_at: '2026-03-01T10:00:00Z', actor: '佐藤 管理者' }, { from_stage: 'procurement', to_stage: 'deployment', changed_at: '2026-03-10T09:00:00Z', actor: '木村 次郎' }] },
  { id: 'ast-012', asset_name: 'CISCO-FW-01', type: 'network', serial_number: 'CSC-2021-FW-001', purchase_date: '2021-05-15', warranty_expiry: '2026-05-15', lifecycle_stage: 'active', assigned_user: 'セキュリティチーム', location: '東京DC-A', cost: 680000, total_cost_of_ownership: 950000, lifecycle_history: [{ from_stage: null, to_stage: 'procurement', changed_at: '2021-04-01T10:00:00Z', actor: '山田 管理者' }, { from_stage: 'procurement', to_stage: 'deployment', changed_at: '2021-05-15T09:00:00Z', actor: 'セキュリティチーム' }, { from_stage: 'deployment', to_stage: 'active', changed_at: '2021-06-01T14:00:00Z', actor: 'セキュリティチーム' }] },
  { id: 'ast-013', asset_name: 'IOT-CAM-C01', type: 'iot', serial_number: 'IOT-2020-CAM-001', purchase_date: '2020-12-01', warranty_expiry: '2025-12-01', lifecycle_stage: 'retirement', assigned_user: '施設管理', location: '本社エントランス', cost: 38000, total_cost_of_ownership: 65000, lifecycle_history: [{ from_stage: null, to_stage: 'procurement', changed_at: '2020-11-01T10:00:00Z', actor: '佐藤 管理者' }, { from_stage: 'procurement', to_stage: 'deployment', changed_at: '2020-12-01T09:00:00Z', actor: '施設管理' }, { from_stage: 'deployment', to_stage: 'active', changed_at: '2020-12-10T14:00:00Z', actor: '施設管理' }, { from_stage: 'active', to_stage: 'maintenance', changed_at: '2025-06-01T10:00:00Z', actor: '田中 健二' }, { from_stage: 'maintenance', to_stage: 'retirement', changed_at: '2026-01-15T10:00:00Z', actor: '佐藤 管理者' }] },
  { id: 'ast-014', asset_name: 'PRINTER-OF-01', type: 'iot', serial_number: 'PRT-2018-OF-001', purchase_date: '2018-09-10', warranty_expiry: '2023-09-10', lifecycle_stage: 'disposal', assigned_user: '総務部', location: '廃棄予定', cost: 120000, total_cost_of_ownership: 280000, lifecycle_history: [{ from_stage: null, to_stage: 'procurement', changed_at: '2018-08-01T10:00:00Z', actor: '山田 管理者' }, { from_stage: 'procurement', to_stage: 'deployment', changed_at: '2018-09-10T09:00:00Z', actor: '総務部' }, { from_stage: 'deployment', to_stage: 'active', changed_at: '2018-10-01T14:00:00Z', actor: '総務部' }, { from_stage: 'active', to_stage: 'maintenance', changed_at: '2022-09-01T10:00:00Z', actor: '田中 健二' }, { from_stage: 'maintenance', to_stage: 'retirement', changed_at: '2023-10-15T10:00:00Z', actor: '佐藤 管理者' }, { from_stage: 'retirement', to_stage: 'disposal', changed_at: '2026-02-01T10:00:00Z', actor: '佐藤 管理者' }] },
  { id: 'ast-015', asset_name: 'VM-JENKINS-01', type: 'virtual', serial_number: 'VMID-2022-JKS-001', purchase_date: '2022-05-10', warranty_expiry: '2027-05-10', lifecycle_stage: 'maintenance', assigned_user: 'DevOpsチーム', location: 'オンプレ VMware', cost: 0, total_cost_of_ownership: 240000, lifecycle_history: [{ from_stage: null, to_stage: 'procurement', changed_at: '2022-04-20T10:00:00Z', actor: 'DevOpsチーム' }, { from_stage: 'procurement', to_stage: 'deployment', changed_at: '2022-05-10T09:00:00Z', actor: 'DevOpsチーム' }, { from_stage: 'deployment', to_stage: 'active', changed_at: '2022-05-15T14:00:00Z', actor: 'DevOpsチーム' }, { from_stage: 'active', to_stage: 'maintenance', changed_at: '2026-01-10T10:00:00Z', actor: '田中 健二' }] },
  { id: 'ast-016', asset_name: 'LAPTOP-SALES-09', type: 'laptop', serial_number: 'LP-2023-SL-009', purchase_date: '2023-04-01', warranty_expiry: '2026-04-01', lifecycle_stage: 'active', assigned_user: '中村 営業', location: 'リモート大阪', cost: 175000, total_cost_of_ownership: 210000, lifecycle_history: [{ from_stage: null, to_stage: 'procurement', changed_at: '2023-03-15T10:00:00Z', actor: '佐藤 管理者' }, { from_stage: 'procurement', to_stage: 'deployment', changed_at: '2023-04-01T09:00:00Z', actor: '中村 営業' }, { from_stage: 'deployment', to_stage: 'active', changed_at: '2023-04-10T14:00:00Z', actor: '中村 営業' }] },
  { id: 'ast-017', asset_name: 'srv-backup-nas', type: 'server', serial_number: 'NAS-2020-BKP-001', purchase_date: '2020-03-15', warranty_expiry: '2026-03-15', lifecycle_stage: 'active', assigned_user: 'インフラチーム', location: '大阪DR-A', cost: 580000, total_cost_of_ownership: 890000, lifecycle_history: [{ from_stage: null, to_stage: 'procurement', changed_at: '2020-02-01T10:00:00Z', actor: '山田 管理者' }, { from_stage: 'procurement', to_stage: 'deployment', changed_at: '2020-03-15T09:00:00Z', actor: 'インフラチーム' }, { from_stage: 'deployment', to_stage: 'active', changed_at: '2020-04-01T14:00:00Z', actor: 'インフラチーム' }] },
  { id: 'ast-018', asset_name: 'CISCO-AP-FLOOR3', type: 'network', serial_number: 'CSC-2022-AP-003', purchase_date: '2022-09-20', warranty_expiry: '2026-09-20', lifecycle_stage: 'active', assigned_user: 'ネットワークチーム', location: '本社3F', cost: 85000, total_cost_of_ownership: 110000, lifecycle_history: [{ from_stage: null, to_stage: 'procurement', changed_at: '2022-08-15T10:00:00Z', actor: '山田 管理者' }, { from_stage: 'procurement', to_stage: 'deployment', changed_at: '2022-09-20T09:00:00Z', actor: 'ネットワークチーム' }, { from_stage: 'deployment', to_stage: 'active', changed_at: '2022-10-01T14:00:00Z', actor: 'ネットワークチーム' }] },
  { id: 'ast-019', asset_name: 'ANDROID-TAB-W01', type: 'mobile', serial_number: 'SAM-2024-T-001', purchase_date: '2024-02-10', warranty_expiry: '2026-02-10', lifecycle_stage: 'maintenance', assigned_user: '倉庫管理部', location: '本社倉庫', cost: 95000, total_cost_of_ownership: 115000, lifecycle_history: [{ from_stage: null, to_stage: 'procurement', changed_at: '2024-01-20T10:00:00Z', actor: '佐藤 管理者' }, { from_stage: 'procurement', to_stage: 'deployment', changed_at: '2024-02-10T09:00:00Z', actor: '倉庫管理部' }, { from_stage: 'deployment', to_stage: 'active', changed_at: '2024-02-15T14:00:00Z', actor: '倉庫管理部' }, { from_stage: 'active', to_stage: 'maintenance', changed_at: '2026-02-10T10:00:00Z', actor: '田中 健二', notes: 'バッテリー劣化のため修理中' }] },
  { id: 'ast-020', asset_name: 'VM-GRAFANA-01', type: 'virtual', serial_number: 'VMID-2023-GRF-001', purchase_date: '2023-11-05', warranty_expiry: '2028-11-05', lifecycle_stage: 'active', assigned_user: 'DevOpsチーム', location: 'AWS ap-northeast-1', cost: 0, total_cost_of_ownership: 180000, lifecycle_history: [{ from_stage: null, to_stage: 'procurement', changed_at: '2023-10-20T10:00:00Z', actor: 'DevOpsチーム' }, { from_stage: 'procurement', to_stage: 'deployment', changed_at: '2023-11-05T09:00:00Z', actor: 'DevOpsチーム' }, { from_stage: 'deployment', to_stage: 'active', changed_at: '2023-11-10T14:00:00Z', actor: 'DevOpsチーム' }] },
  { id: 'ast-021', asset_name: 'LAPTOP-ACCT-05', type: 'laptop', serial_number: 'LP-2021-AC-005', purchase_date: '2021-10-20', warranty_expiry: '2024-10-20', lifecycle_stage: 'retirement', assigned_user: '松本 経理', location: '本社5F', cost: 165000, total_cost_of_ownership: 210000, lifecycle_history: [{ from_stage: null, to_stage: 'procurement', changed_at: '2021-10-01T10:00:00Z', actor: '佐藤 管理者' }, { from_stage: 'procurement', to_stage: 'deployment', changed_at: '2021-10-20T09:00:00Z', actor: '松本 経理' }, { from_stage: 'deployment', to_stage: 'active', changed_at: '2021-11-01T14:00:00Z', actor: '松本 経理' }, { from_stage: 'active', to_stage: 'maintenance', changed_at: '2024-08-01T10:00:00Z', actor: '田中 健二' }, { from_stage: 'maintenance', to_stage: 'retirement', changed_at: '2025-01-10T10:00:00Z', actor: '佐藤 管理者' }] },
  { id: 'ast-022', asset_name: 'IOT-BADGE-READER', type: 'iot', serial_number: 'IOT-2021-BD-001', purchase_date: '2021-06-01', warranty_expiry: '2026-06-01', lifecycle_stage: 'active', assigned_user: '施設管理', location: '本社入口', cost: 55000, total_cost_of_ownership: 75000, lifecycle_history: [{ from_stage: null, to_stage: 'procurement', changed_at: '2021-05-10T10:00:00Z', actor: '佐藤 管理者' }, { from_stage: 'procurement', to_stage: 'deployment', changed_at: '2021-06-01T09:00:00Z', actor: '施設管理' }, { from_stage: 'deployment', to_stage: 'active', changed_at: '2021-06-10T14:00:00Z', actor: '施設管理' }] },
  { id: 'ast-023', asset_name: 'srv-mail-01', type: 'server', serial_number: 'SRV-2020-MAIL-001', purchase_date: '2020-06-15', warranty_expiry: '2026-06-15', lifecycle_stage: 'active', assigned_user: 'インフラチーム', location: '東京DC-B', cost: 640000, total_cost_of_ownership: 980000, lifecycle_history: [{ from_stage: null, to_stage: 'procurement', changed_at: '2020-05-01T10:00:00Z', actor: '山田 管理者' }, { from_stage: 'procurement', to_stage: 'deployment', changed_at: '2020-06-15T09:00:00Z', actor: 'インフラチーム' }, { from_stage: 'deployment', to_stage: 'active', changed_at: '2020-07-01T14:00:00Z', actor: 'インフラチーム' }] },
  { id: 'ast-024', asset_name: 'CISCO-VPN-GW-01', type: 'network', serial_number: 'CSC-2021-VPN-001', purchase_date: '2021-02-28', warranty_expiry: '2026-04-30', lifecycle_stage: 'active', assigned_user: 'セキュリティチーム', location: '東京DC-A', cost: 920000, total_cost_of_ownership: 1350000, lifecycle_history: [{ from_stage: null, to_stage: 'procurement', changed_at: '2021-01-15T10:00:00Z', actor: '山田 管理者' }, { from_stage: 'procurement', to_stage: 'deployment', changed_at: '2021-02-28T09:00:00Z', actor: 'セキュリティチーム' }, { from_stage: 'deployment', to_stage: 'active', changed_at: '2021-03-15T14:00:00Z', actor: 'セキュリティチーム' }] },
  { id: 'ast-025', asset_name: 'MACBOOK-DEV-12', type: 'laptop', serial_number: 'APL-2024-MB-012', purchase_date: '2024-11-20', warranty_expiry: '2027-11-20', lifecycle_stage: 'deployment', assigned_user: '小林 エンジニア', location: 'リモート', cost: 298000, total_cost_of_ownership: 298000, lifecycle_history: [{ from_stage: null, to_stage: 'procurement', changed_at: '2024-11-01T10:00:00Z', actor: '佐藤 管理者' }, { from_stage: 'procurement', to_stage: 'deployment', changed_at: '2024-11-20T09:00:00Z', actor: '小林 エンジニア' }] },
]

const STAGE_LABELS: Record<LifecycleStage, string> = {
  procurement: '調達',
  deployment: '展開',
  active: '稼働中',
  maintenance: 'メンテナンス',
  retirement: '退役',
  disposal: '廃棄',
}

const STAGE_COLORS: Record<LifecycleStage, string> = {
  procurement: 'bg-blue-500/10 border-blue-500/30 text-blue-400',
  deployment: 'bg-cyan-500/10 border-cyan-500/30 text-cyan-400',
  active: 'bg-green-500/10 border-green-500/30 text-green-400',
  maintenance: 'bg-yellow-500/10 border-yellow-500/30 text-yellow-400',
  retirement: 'bg-orange-500/10 border-orange-500/30 text-orange-400',
  disposal: 'bg-red-500/10 border-red-500/30 text-red-400',
}

const STAGE_PIPELINE_COLORS: Record<LifecycleStage, string> = {
  procurement: 'bg-blue-500/20 border-blue-500/40',
  deployment: 'bg-cyan-500/20 border-cyan-500/40',
  active: 'bg-green-500/20 border-green-500/40',
  maintenance: 'bg-yellow-500/20 border-yellow-500/40',
  retirement: 'bg-orange-500/20 border-orange-500/40',
  disposal: 'bg-red-500/20 border-red-500/40',
}

const TYPE_LABELS: Record<AssetType, string> = {
  server: 'サーバー',
  laptop: 'ラップトップ',
  network: 'ネットワーク',
  mobile: 'モバイル',
  iot: 'IoT',
  virtual: '仮想',
}

const TYPE_COLORS: Record<AssetType, string> = {
  server: 'bg-purple-500/10 border-purple-500/30 text-purple-400',
  laptop: 'bg-blue-500/10 border-blue-500/30 text-blue-400',
  network: 'bg-cyan-500/10 border-cyan-500/30 text-cyan-400',
  mobile: 'bg-green-500/10 border-green-500/30 text-green-400',
  iot: 'bg-orange-500/10 border-orange-500/30 text-orange-400',
  virtual: 'bg-pink-500/10 border-pink-500/30 text-pink-400',
}

function TypeIcon({ type }: { type: AssetType }) {
  const props = { className: 'w-3.5 h-3.5' }
  if (type === 'server') return <Server {...props} />
  if (type === 'laptop') return <Laptop {...props} />
  if (type === 'network') return <Router {...props} />
  if (type === 'mobile') return <Smartphone {...props} />
  if (type === 'iot') return <Cpu {...props} />
  return <Cloud {...props} />
}

function warrantyColor(expiry: string) {
  const days = daysFromNow(expiry)
  if (days < 0) return 'text-red-400'
  if (days < 90) return 'text-orange-400'
  return 'text-[#7d92b0]'
}

function fmtYen(n: number) {
  return `¥${n.toLocaleString('ja-JP')}`
}

// ── Blank Asset Template ───────────────────────────────────────────────────────

const BLANK_ASSET: Omit<Asset, 'id' | 'lifecycle_history'> = {
  asset_name: '',
  type: 'laptop',
  serial_number: '',
  purchase_date: '',
  warranty_expiry: '',
  lifecycle_stage: 'procurement',
  assigned_user: '',
  location: '',
  cost: 0,
  total_cost_of_ownership: 0,
}

// ── Main Component ─────────────────────────────────────────────────────────────

export default function AssetLifecyclePage() {
  const queryClient = useQueryClient()
  const [typeFilter, setTypeFilter] = useState<AssetType | ''>('')
  const [stageFilter, setStageFilter] = useState<LifecycleStage | ''>('')
  const [warrantyFilter, setWarrantyFilter] = useState<'all' | 'expired' | 'expiring' | 'ok'>('all')
  const [search, setSearch] = useState('')
  const [sortBy, setSortBy] = useState<'warranty_expiry' | 'purchase_date' | 'cost'>('warranty_expiry')
  const [sortDir, setSortDir] = useState<'asc' | 'desc'>('asc')
  const [selectedAsset, setSelectedAsset] = useState<Asset | null>(null)
  const [showAddModal, setShowAddModal] = useState(false)
  const [showAdvanceConfirm, setShowAdvanceConfirm] = useState<Asset | null>(null)
  const [bulkSelected, setBulkSelected] = useState<string[]>([])
  const [newAsset, setNewAsset] = useState<typeof BLANK_ASSET>({ ...BLANK_ASSET })
  const [addLoading, setAddLoading] = useState(false)

  // API
  const { data: apiData } = useQuery({
    queryKey: ['assets-lifecycle'],
    queryFn: () => apiFetch('/api/v1/assets/lifecycle'),
    retry: false,
  })

  const advanceMutation = useMutation({
    mutationFn: (id: string) => apiFetch(`/api/v1/assets/lifecycle/${id}/advance-stage`, { method: 'POST' }),
    onSuccess: () => { queryClient.invalidateQueries({ queryKey: ['assets-lifecycle'] }); setShowAdvanceConfirm(null) },
  })

  const deleteMutation = useMutation({
    mutationFn: (id: string) => apiFetch(`/api/v1/assets/lifecycle/${id}`, { method: 'DELETE' }),
    onSuccess: () => { queryClient.invalidateQueries({ queryKey: ['assets-lifecycle'] }); setSelectedAsset(null) },
  })

  const assets: Asset[] = (apiData as { assets?: Asset[] } | null)?.assets ?? m(MOCK_ASSETS)

  // Pipeline counts
  const stageCounts = useMemo(() => {
    const counts: Record<LifecycleStage, number> = { procurement: 0, deployment: 0, active: 0, maintenance: 0, retirement: 0, disposal: 0 }
    assets.forEach(a => { counts[a.lifecycle_stage]++ })
    return counts
  }, [assets])

  // Filtered & sorted assets
  const filteredAssets = useMemo(() => {
    let list = assets.filter(a => {
      if (typeFilter && a.type !== typeFilter) return false
      if (stageFilter && a.lifecycle_stage !== stageFilter) return false
      if (search && !a.asset_name.toLowerCase().includes(search.toLowerCase()) && !a.assigned_user.toLowerCase().includes(search.toLowerCase()) && !a.serial_number.toLowerCase().includes(search.toLowerCase())) return false
      if (warrantyFilter !== 'all') {
        const days = daysFromNow(a.warranty_expiry)
        if (warrantyFilter === 'expired' && days >= 0) return false
        if (warrantyFilter === 'expiring' && (days < 0 || days >= 90)) return false
        if (warrantyFilter === 'ok' && days < 90) return false
      }
      return true
    })
    list = [...list].sort((a, b) => {
      let cmp = 0
      if (sortBy === 'warranty_expiry') cmp = new Date(a.warranty_expiry).getTime() - new Date(b.warranty_expiry).getTime()
      else if (sortBy === 'purchase_date') cmp = new Date(a.purchase_date).getTime() - new Date(b.purchase_date).getTime()
      else cmp = a.cost - b.cost
      return sortDir === 'asc' ? cmp : -cmp
    })
    return list
  }, [assets, typeFilter, stageFilter, warrantyFilter, search, sortBy, sortDir])

  // Warranty expiry alerts (within 90 days or expired)
  const warrantyAlerts = useMemo(() => assets.filter(a => {
    const days = daysFromNow(a.warranty_expiry)
    return days < 90
  }).sort((a, b) => daysFromNow(a.warranty_expiry) - daysFromNow(b.warranty_expiry)), [assets])

  // Retirement/disposal candidates
  const retirementCandidates = useMemo(() => assets.filter(a => a.lifecycle_stage === 'retirement' || a.lifecycle_stage === 'maintenance'), [assets])

  // TCO by type
  const tcoByType = useMemo(() => {
    const map: Record<AssetType, { total: number; count: number }> = {} as any
    assets.forEach(a => {
      if (!map[a.type]) map[a.type] = { total: 0, count: 0 }
      map[a.type].total += a.total_cost_of_ownership
      map[a.type].count++
    })
    return Object.entries(map).sort((a, b) => b[1].total - a[1].total) as [AssetType, { total: number; count: number }][]
  }, [assets])

  const maxTco = tcoByType[0]?.[1].total ?? 1

  function toggleSort(col: typeof sortBy) {
    if (sortBy === col) setSortDir(d => d === 'asc' ? 'desc' : 'asc')
    else { setSortBy(col); setSortDir('asc') }
  }

  function handleAdvance(asset: Asset) {
    const idx = STAGE_ORDER.indexOf(asset.lifecycle_stage)
    if (idx >= STAGE_ORDER.length - 1) return
    setShowAdvanceConfirm(asset)
  }

  function nextStage(stage: LifecycleStage): LifecycleStage | null {
    const idx = STAGE_ORDER.indexOf(stage)
    return idx < STAGE_ORDER.length - 1 ? STAGE_ORDER[idx + 1] : null
  }

  function handleAddAsset() {
    setAddLoading(true)
    setTimeout(() => { setAddLoading(false); setShowAddModal(false); setNewAsset({ ...BLANK_ASSET }) }, 800)
  }

  return (
    <div className="min-h-screen bg-[#070d19] text-[#7d92b0]">
      {/* ── Header ─────────────────────────────────────────── */}
      <div className="border-b border-[#1e2d42] px-6 py-4">
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-3">
            <div className="w-9 h-9 rounded-lg bg-[#e8002d]/10 border border-[#e8002d]/20 flex items-center justify-center">
              <RefreshCw className="w-5 h-5 text-[#e8002d]" />
            </div>
            <div>
              <h1 className="text-white text-xl font-bold tracking-tight">資産ライフサイクル管理</h1>
              <p className="text-xs text-[#7d92b0] mt-0.5">調達から廃棄まで全資産のライフサイクルを管理</p>
            </div>
          </div>
          <div className="flex items-center gap-3">
            <button className="flex items-center gap-2 px-3 py-2 rounded-lg bg-[#0d1220] border border-[#1e2d42] text-xs text-[#7d92b0] hover:text-white transition-colors">
              <Upload className="w-3.5 h-3.5" />
              CSV インポート
            </button>
            <button className="flex items-center gap-2 px-3 py-2 rounded-lg bg-[#0d1220] border border-[#1e2d42] text-xs text-[#7d92b0] hover:text-white transition-colors">
              <Download className="w-3.5 h-3.5" />
              エクスポート
            </button>
            <button
              onClick={() => setShowAddModal(true)}
              className="flex items-center gap-2 px-3 py-2 rounded-lg bg-[#e8002d] text-white text-xs hover:bg-[#c0001f] transition-colors"
            >
              <Plus className="w-3.5 h-3.5" />
              資産追加
            </button>
          </div>
        </div>
      </div>

      <div className="p-6 space-y-6">
        {/* ── Lifecycle Pipeline ───────────────────────────── */}
        <div className="bg-[#0d1220] border border-[#1e2d42] rounded-xl p-4">
          <h2 className="text-white font-semibold text-sm mb-4">ライフサイクルパイプライン</h2>
          <div className="flex items-center gap-2">
            {STAGE_ORDER.map((stage, idx) => (
              <div key={stage} className="flex items-center gap-2 flex-1">
                <button
                  onClick={() => setStageFilter(stageFilter === stage ? '' : stage)}
                  className={`flex-1 flex flex-col items-center gap-1.5 px-3 py-3 rounded-xl border-2 transition-all cursor-pointer
                    ${stageFilter === stage ? 'border-white/30 scale-105' : 'border-transparent hover:scale-102'}
                    ${STAGE_PIPELINE_COLORS[stage]}`}
                >
                  <span className="text-xs font-medium text-white">{STAGE_LABELS[stage]}</span>
                  <span className="text-2xl font-bold text-white">{stageCounts[stage]}</span>
                  <span className="text-[10px] text-[#7d92b0]">資産</span>
                </button>
                {idx < STAGE_ORDER.length - 1 && (
                  <ArrowRight className="w-4 h-4 text-[#3d5068] flex-shrink-0" />
                )}
              </div>
            ))}
          </div>
        </div>

        {/* ── Filters ─────────────────────────────────────── */}
        <div className="flex items-center gap-3 flex-wrap">
          <div className="relative">
            <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-3.5 h-3.5 text-[#3d5068]" />
            <input
              type="text"
              placeholder="資産名・担当者・シリアル番号..."
              value={search}
              onChange={e => setSearch(e.target.value)}
              className="pl-8 pr-3 py-2 text-xs bg-[#0d1220] border border-[#1e2d42] rounded-lg text-white placeholder-[#3d5068] focus:outline-none focus:border-[#7d92b0] w-56"
            />
          </div>
          {/* Type filter */}
          <div className="relative">
            <select
              value={typeFilter}
              onChange={e => setTypeFilter(e.target.value as AssetType | '')}
              className="pl-3 pr-8 py-2 text-xs bg-[#0d1220] border border-[#1e2d42] rounded-lg text-[#7d92b0] focus:outline-none appearance-none cursor-pointer"
            >
              <option value="">全タイプ</option>
              {(Object.keys(TYPE_LABELS) as AssetType[]).map(t => <option key={t} value={t}>{TYPE_LABELS[t]}</option>)}
            </select>
            <ChevronDown className="absolute right-2 top-1/2 -translate-y-1/2 w-3 h-3 text-[#3d5068] pointer-events-none" />
          </div>
          {/* Stage filter */}
          <div className="relative">
            <select
              value={stageFilter}
              onChange={e => setStageFilter(e.target.value as LifecycleStage | '')}
              className="pl-3 pr-8 py-2 text-xs bg-[#0d1220] border border-[#1e2d42] rounded-lg text-[#7d92b0] focus:outline-none appearance-none cursor-pointer"
            >
              <option value="">全ステージ</option>
              {STAGE_ORDER.map(s => <option key={s} value={s}>{STAGE_LABELS[s]}</option>)}
            </select>
            <ChevronDown className="absolute right-2 top-1/2 -translate-y-1/2 w-3 h-3 text-[#3d5068] pointer-events-none" />
          </div>
          {/* Warranty filter */}
          <div className="flex items-center gap-1 bg-[#0d1220] border border-[#1e2d42] rounded-lg p-0.5">
            {(['all', 'expired', 'expiring', 'ok'] as const).map(w => (
              <button
                key={w}
                onClick={() => setWarrantyFilter(w)}
                className={`px-2.5 py-1 rounded text-xs transition-colors ${warrantyFilter === w ? 'bg-[#1e2d42] text-white' : 'text-[#7d92b0] hover:text-white'}`}
              >
                {w === 'all' ? '全て' : w === 'expired' ? '期限切れ' : w === 'expiring' ? '90日以内' : '正常'}
              </button>
            ))}
          </div>
          {(typeFilter || stageFilter || warrantyFilter !== 'all' || search) && (
            <button
              onClick={() => { setTypeFilter(''); setStageFilter(''); setWarrantyFilter('all'); setSearch('') }}
              className="flex items-center gap-1 text-xs text-[#7d92b0] hover:text-white"
            >
              <X className="w-3 h-3" /> クリア
            </button>
          )}
        </div>

        {/* ── Assets Table ─────────────────────────────────── */}
        <div className="bg-[#0d1220] border border-[#1e2d42] rounded-xl overflow-hidden">
          <div className="px-4 py-3 border-b border-[#1e2d42] flex items-center justify-between">
            <h2 className="text-white font-semibold text-sm">資産一覧 ({filteredAssets.length}件)</h2>
            {bulkSelected.length > 0 && (
              <button className="flex items-center gap-1.5 text-xs text-orange-400 border border-orange-400/30 bg-orange-400/5 px-3 py-1.5 rounded hover:bg-orange-400/10 transition-colors">
                <Trash2 className="w-3.5 h-3.5" />
                選択 {bulkSelected.length}件 廃棄申請
              </button>
            )}
          </div>
          <div className="overflow-x-auto">
            <table className="w-full text-xs">
              <thead>
                <tr className="border-b border-[#1e2d42]">
                  <th className="px-3 py-2.5 w-8">
                    <input
                      type="checkbox"
                      className="accent-[#e8002d]"
                      checked={bulkSelected.length === filteredAssets.length && filteredAssets.length > 0}
                      onChange={e => setBulkSelected(e.target.checked ? filteredAssets.map(a => a.id) : [])}
                    />
                  </th>
                  {['資産名', 'タイプ', 'シリアル番号', '購入日', '保証期限', 'ステージ', '担当者', '場所', '取得価格', 'TCO', '操作'].map((h, i) => {
                    const sortable = h === '保証期限' || h === '購入日' || h === '取得価格'
                    const sortKey = h === '保証期限' ? 'warranty_expiry' : h === '購入日' ? 'purchase_date' : 'cost'
                    return (
                      <th
                        key={h}
                        onClick={sortable ? () => toggleSort(sortKey as typeof sortBy) : undefined}
                        className={`px-3 py-2.5 text-left text-[#3d5068] font-medium whitespace-nowrap ${sortable ? 'cursor-pointer hover:text-white' : ''}`}
                      >
                        {h}
                        {sortable && sortBy === sortKey && (
                          <span className="ml-1">{sortDir === 'asc' ? '↑' : '↓'}</span>
                        )}
                      </th>
                    )
                  })}
                </tr>
              </thead>
              <tbody className="divide-y divide-[#1e2d42]/50">
                {filteredAssets.map(asset => {
                  const wDays = daysFromNow(asset.warranty_expiry)
                  return (
                    <tr key={asset.id} className="hover:bg-[#0a1628] transition-colors">
                      <td className="px-3 py-2.5">
                        <input
                          type="checkbox"
                          className="accent-[#e8002d]"
                          checked={bulkSelected.includes(asset.id)}
                          onChange={e => setBulkSelected(prev => e.target.checked ? [...prev, asset.id] : prev.filter(id => id !== asset.id))}
                        />
                      </td>
                      <td className="px-3 py-2.5 font-mono text-white font-medium">{asset.asset_name}</td>
                      <td className="px-3 py-2.5">
                        <span className={`flex items-center gap-1 px-2 py-0.5 rounded border w-fit text-[10px] font-medium ${TYPE_COLORS[asset.type]}`}>
                          <TypeIcon type={asset.type} />
                          {TYPE_LABELS[asset.type]}
                        </span>
                      </td>
                      <td className="px-3 py-2.5 font-mono text-[#7d92b0] text-[11px]">{asset.serial_number}</td>
                      <td className="px-3 py-2.5 font-mono text-[#7d92b0] whitespace-nowrap">{asset.purchase_date}</td>
                      <td className={`px-3 py-2.5 font-mono whitespace-nowrap font-medium ${warrantyColor(asset.warranty_expiry)}`}>
                        {asset.warranty_expiry}
                        {wDays < 0 && <span className="ml-1 text-[9px]">(期限切れ)</span>}
                        {wDays >= 0 && wDays < 90 && <span className="ml-1 text-[9px]">({wDays}日)</span>}
                      </td>
                      <td className="px-3 py-2.5">
                        <span className={`px-2 py-0.5 rounded border text-[10px] font-medium ${STAGE_COLORS[asset.lifecycle_stage]}`}>
                          {STAGE_LABELS[asset.lifecycle_stage]}
                        </span>
                      </td>
                      <td className="px-3 py-2.5 text-[#7d92b0] whitespace-nowrap">{asset.assigned_user}</td>
                      <td className="px-3 py-2.5 text-[#7d92b0] whitespace-nowrap">{asset.location}</td>
                      <td className="px-3 py-2.5 font-mono text-white whitespace-nowrap">{fmtYen(asset.cost)}</td>
                      <td className="px-3 py-2.5 font-mono text-[#7d92b0] whitespace-nowrap">{fmtYen(asset.total_cost_of_ownership)}</td>
                      <td className="px-3 py-2.5">
                        <div className="flex items-center gap-1.5">
                          <button
                            onClick={() => setSelectedAsset(asset)}
                            className="text-[#7d92b0] hover:text-white transition-colors p-1 rounded hover:bg-[#1e2d42]"
                            title="詳細"
                          >
                            <Edit2 className="w-3.5 h-3.5" />
                          </button>
                          {nextStage(asset.lifecycle_stage) && (
                            <button
                              onClick={() => handleAdvance(asset)}
                              className="text-[#7d92b0] hover:text-cyan-400 transition-colors p-1 rounded hover:bg-[#1e2d42]"
                              title="次のステージへ"
                            >
                              <ChevronRight className="w-3.5 h-3.5" />
                            </button>
                          )}
                        </div>
                      </td>
                    </tr>
                  )
                })}
              </tbody>
            </table>
          </div>
        </div>

        {/* ── Warranty Alerts ──────────────────────────────── */}
        {warrantyAlerts.length > 0 && (
          <div className="bg-[#0d1220] border border-orange-500/30 rounded-xl overflow-hidden">
            <div className="px-4 py-3 border-b border-orange-500/20 flex items-center gap-2">
              <AlertTriangle className="w-4 h-4 text-orange-400" />
              <h2 className="text-white font-semibold text-sm">保証期限アラート ({warrantyAlerts.length}件)</h2>
            </div>
            <div className="overflow-x-auto">
              <table className="w-full text-xs">
                <thead>
                  <tr className="border-b border-orange-500/10">
                    {['資産名', 'タイプ', '担当者', '保証期限', '残日数', '対応'].map(h => (
                      <th key={h} className="px-3 py-2.5 text-left text-orange-400/60 font-medium">{h}</th>
                    ))}
                  </tr>
                </thead>
                <tbody className="divide-y divide-orange-500/10">
                  {warrantyAlerts.map(asset => {
                    const days = daysFromNow(asset.warranty_expiry)
                    return (
                      <tr key={asset.id} className="hover:bg-orange-500/5 transition-colors">
                        <td className="px-3 py-2.5 font-mono text-white">{asset.asset_name}</td>
                        <td className="px-3 py-2.5">
                          <span className={`px-2 py-0.5 rounded border text-[10px] ${TYPE_COLORS[asset.type]}`}>{TYPE_LABELS[asset.type]}</span>
                        </td>
                        <td className="px-3 py-2.5 text-[#7d92b0]">{asset.assigned_user}</td>
                        <td className={`px-3 py-2.5 font-mono ${warrantyColor(asset.warranty_expiry)}`}>{asset.warranty_expiry}</td>
                        <td className={`px-3 py-2.5 font-bold ${days < 0 ? 'text-red-400' : 'text-orange-400'}`}>
                          {days < 0 ? `${Math.abs(days)}日超過` : `${days}日`}
                        </td>
                        <td className="px-3 py-2.5">
                          <button className="text-xs text-blue-400 hover:text-blue-300 border border-blue-400/30 px-2 py-1 rounded transition-colors">
                            更新手続き
                          </button>
                        </td>
                      </tr>
                    )
                  })}
                </tbody>
              </table>
            </div>
          </div>
        )}

        {/* ── Retirement Planning & TCO ─────────────────────── */}
        <div className="grid grid-cols-2 gap-4">
          {/* Retirement candidates */}
          <div className="bg-[#0d1220] border border-[#1e2d42] rounded-xl overflow-hidden">
            <div className="px-4 py-3 border-b border-[#1e2d42] flex items-center justify-between">
              <h2 className="text-white font-semibold text-sm">退役・廃棄計画 ({retirementCandidates.length}件)</h2>
              {bulkSelected.length > 0 && (
                <button className="flex items-center gap-1 text-xs text-[#e8002d] border border-[#e8002d]/30 px-2.5 py-1 rounded hover:bg-[#e8002d]/10 transition-colors">
                  <Trash2 className="w-3 h-3" />
                  廃棄申請
                </button>
              )}
            </div>
            <div className="divide-y divide-[#1e2d42]/50">
              {retirementCandidates.slice(0, 8).map(asset => (
                <div key={asset.id} className="flex items-center gap-3 px-4 py-2.5 hover:bg-[#0a1628] transition-colors">
                  <input
                    type="checkbox"
                    className="accent-[#e8002d]"
                    checked={bulkSelected.includes(asset.id)}
                    onChange={e => setBulkSelected(prev => e.target.checked ? [...prev, asset.id] : prev.filter(id => id !== asset.id))}
                  />
                  <span className="font-mono text-xs text-white flex-1 truncate">{asset.asset_name}</span>
                  <span className={`px-2 py-0.5 rounded border text-[10px] ${STAGE_COLORS[asset.lifecycle_stage]}`}>{STAGE_LABELS[asset.lifecycle_stage]}</span>
                  <button
                    onClick={() => handleAdvance(asset)}
                    className="text-xs text-[#e8002d] border border-[#e8002d]/30 px-2 py-1 rounded hover:bg-[#e8002d]/10 transition-colors whitespace-nowrap"
                  >
                    次へ進める
                  </button>
                </div>
              ))}
            </div>
          </div>

          {/* TCO by type */}
          <div className="bg-[#0d1220] border border-[#1e2d42] rounded-xl p-5">
            <h2 className="text-white font-semibold text-sm mb-4 flex items-center gap-2">
              <DollarSign className="w-4 h-4 text-[#e8002d]" />
              タイプ別 TCO分析
            </h2>
            <div className="space-y-3">
              {tcoByType.map(([type, stats]) => {
                const pct = Math.round((stats.total / maxTco) * 100)
                return (
                  <div key={type} className="flex items-center gap-3">
                    <div className={`flex items-center gap-1 px-2 py-0.5 rounded border text-[10px] w-28 ${TYPE_COLORS[type]}`}>
                      <TypeIcon type={type} />
                      <span>{TYPE_LABELS[type]} ({stats.count})</span>
                    </div>
                    <div className="flex-1 h-5 bg-[#070d19] rounded overflow-hidden relative">
                      <div className="h-full bg-gradient-to-r from-[#1a6bff]/60 to-[#0044cc]/60 rounded" style={{ width: `${pct}%` }} />
                    </div>
                    <span className="text-xs font-mono text-[#7d92b0] w-24 text-right">{fmtYen(stats.total)}</span>
                  </div>
                )
              })}
            </div>
            <div className="mt-4 pt-3 border-t border-[#1e2d42] flex items-center justify-between">
              <span className="text-xs text-[#7d92b0]">総資産TCO</span>
              <span className="font-mono font-bold text-white">{fmtYen(assets.reduce((s, a) => s + a.total_cost_of_ownership, 0))}</span>
            </div>
          </div>
        </div>
      </div>

      {/* ── Asset Detail/Edit Modal ────────────────────────── */}
      {selectedAsset && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60" onClick={() => setSelectedAsset(null)}>
          <div
            className="relative w-full max-w-2xl max-h-[90vh] overflow-y-auto bg-[#0d1220] border border-[#1e2d42] rounded-xl shadow-2xl"
            onClick={e => e.stopPropagation()}
          >
            <div className="flex items-center justify-between px-6 py-4 border-b border-[#1e2d42]">
              <h3 className="text-white font-semibold">資産詳細 — {selectedAsset.asset_name}</h3>
              <button onClick={() => setSelectedAsset(null)} className="text-[#7d92b0] hover:text-white"><X className="w-5 h-5" /></button>
            </div>
            <div className="p-6 space-y-5">
              {/* Fields grid */}
              <div className="grid grid-cols-2 gap-4">
                {[
                  { label: '資産名', value: selectedAsset.asset_name, icon: Hash },
                  { label: 'シリアル番号', value: selectedAsset.serial_number, icon: Hash },
                  { label: '担当者', value: selectedAsset.assigned_user, icon: User },
                  { label: '場所', value: selectedAsset.location, icon: MapPin },
                  { label: '購入日', value: selectedAsset.purchase_date, icon: Calendar },
                  { label: '保証期限', value: selectedAsset.warranty_expiry, icon: Calendar },
                  { label: '取得価格', value: fmtYen(selectedAsset.cost), icon: DollarSign },
                  { label: 'TCO', value: fmtYen(selectedAsset.total_cost_of_ownership), icon: DollarSign },
                ].map(({ label, value, icon: Icon }) => (
                  <div key={label} className="bg-[#070d19] rounded-lg p-3 border border-[#1e2d42]">
                    <div className="flex items-center gap-1.5 mb-1">
                      <Icon className="w-3 h-3 text-[#3d5068]" />
                      <span className="text-[10px] text-[#3d5068] uppercase tracking-wider">{label}</span>
                    </div>
                    <p className="text-white text-sm font-mono">{value}</p>
                  </div>
                ))}
              </div>
              {/* Stage badges */}
              <div>
                <p className="text-xs text-[#7d92b0] mb-2">ライフサイクルステージ</p>
                <div className="flex items-center gap-2 flex-wrap">
                  {STAGE_ORDER.map((s, i) => (
                    <div key={s} className="flex items-center gap-1">
                      <span className={`px-2.5 py-1 rounded-full border text-[10px] font-medium ${selectedAsset.lifecycle_stage === s ? STAGE_COLORS[s] + ' ring-1 ring-white/20' : 'bg-[#070d19] border-[#1e2d42] text-[#3d5068]'}`}>
                        {STAGE_LABELS[s]}
                      </span>
                      {i < STAGE_ORDER.length - 1 && <ArrowRight className="w-3 h-3 text-[#1e2d42]" />}
                    </div>
                  ))}
                </div>
              </div>
              {/* History */}
              <div>
                <h4 className="text-xs text-[#7d92b0] uppercase tracking-wider mb-3">ライフサイクル履歴</h4>
                <div className="space-y-2">
                  {selectedAsset.lifecycle_history.map((h, i) => (
                    <div key={i} className="flex items-start gap-3 px-3 py-2.5 rounded bg-[#070d19] border border-[#1e2d42]">
                      <CheckCircle2 className="w-3.5 h-3.5 text-green-400 mt-0.5 flex-shrink-0" />
                      <div className="flex-1 min-w-0">
                        <p className="text-xs text-white">
                          {h.from_stage ? `${STAGE_LABELS[h.from_stage]} → ${STAGE_LABELS[h.to_stage]}` : STAGE_LABELS[h.to_stage] + ' (初期登録)'}
                        </p>
                        {h.notes && <p className="text-[10px] text-[#7d92b0] mt-0.5">{h.notes}</p>}
                      </div>
                      <div className="text-right flex-shrink-0">
                        <p className="text-[10px] text-[#3d5068] font-mono">{new Date(h.changed_at).toLocaleDateString('ja-JP')}</p>
                        <p className="text-[10px] text-[#7d92b0]">{h.actor}</p>
                      </div>
                    </div>
                  ))}
                </div>
              </div>
              {/* Actions */}
              <div className="flex gap-3 pt-2 border-t border-[#1e2d42]">
                {nextStage(selectedAsset.lifecycle_stage) && (
                  <button
                    onClick={() => { setShowAdvanceConfirm(selectedAsset); setSelectedAsset(null) }}
                    className="flex items-center gap-2 px-4 py-2 rounded bg-cyan-500/10 border border-cyan-500/30 text-cyan-400 text-sm hover:bg-cyan-500/20 transition-colors"
                  >
                    <ArrowRight className="w-4 h-4" />
                    {STAGE_LABELS[nextStage(selectedAsset.lifecycle_stage)!]}へ進める
                  </button>
                )}
                <button
                  onClick={() => deleteMutation.mutate(selectedAsset.id)}
                  className="flex items-center gap-2 px-4 py-2 rounded bg-[#e8002d]/10 border border-[#e8002d]/30 text-[#e8002d] text-sm hover:bg-[#e8002d]/20 transition-colors"
                >
                  <Trash2 className="w-4 h-4" />
                  削除
                </button>
                <button onClick={() => setSelectedAsset(null)} className="ml-auto flex items-center gap-2 px-4 py-2 rounded bg-[#1e2d42] text-[#7d92b0] text-sm hover:text-white transition-colors">
                  閉じる
                </button>
              </div>
            </div>
          </div>
        </div>
      )}

      {/* ── Advance Stage Confirm ─────────────────────────── */}
      {showAdvanceConfirm && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60" onClick={() => setShowAdvanceConfirm(null)}>
          <div className="bg-[#0d1220] border border-[#1e2d42] rounded-xl p-6 w-96 shadow-2xl" onClick={e => e.stopPropagation()}>
            <h3 className="text-white font-semibold mb-3">ステージ変更の確認</h3>
            <p className="text-sm text-[#7d92b0] mb-4">
              <span className="text-white font-mono">{showAdvanceConfirm.asset_name}</span> を<br />
              <span className={`font-medium ${STAGE_COLORS[showAdvanceConfirm.lifecycle_stage]}`}> {STAGE_LABELS[showAdvanceConfirm.lifecycle_stage]}</span>
              {' → '}
              <span className={`font-medium ${STAGE_COLORS[nextStage(showAdvanceConfirm.lifecycle_stage)!]}`}>{STAGE_LABELS[nextStage(showAdvanceConfirm.lifecycle_stage)!]}</span>
              {' '}に変更しますか？
            </p>
            <div className="flex gap-3">
              <button
                onClick={() => advanceMutation.mutate(showAdvanceConfirm.id)}
                disabled={advanceMutation.isPending}
                className="flex items-center gap-2 px-4 py-2 rounded bg-cyan-500/10 border border-cyan-500/30 text-cyan-400 text-sm hover:bg-cyan-500/20 transition-colors disabled:opacity-50"
              >
                {advanceMutation.isPending ? <Loader2 className="w-4 h-4 animate-spin" /> : <CheckCircle2 className="w-4 h-4" />}
                確定
              </button>
              <button onClick={() => setShowAdvanceConfirm(null)} className="px-4 py-2 rounded bg-[#1e2d42] text-[#7d92b0] text-sm hover:text-white transition-colors">
                キャンセル
              </button>
            </div>
          </div>
        </div>
      )}

      {/* ── Add Asset Modal ───────────────────────────────── */}
      {showAddModal && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60" onClick={() => setShowAddModal(false)}>
          <div
            className="relative w-full max-w-2xl max-h-[90vh] overflow-y-auto bg-[#0d1220] border border-[#1e2d42] rounded-xl shadow-2xl"
            onClick={e => e.stopPropagation()}
          >
            <div className="flex items-center justify-between px-6 py-4 border-b border-[#1e2d42]">
              <h3 className="text-white font-semibold">新規資産登録</h3>
              <button onClick={() => setShowAddModal(false)} className="text-[#7d92b0] hover:text-white"><X className="w-5 h-5" /></button>
            </div>
            <div className="p-6">
              <div className="grid grid-cols-2 gap-4">
                {/* Asset Name */}
                <div className="col-span-2">
                  <label className="block text-xs text-[#7d92b0] mb-1.5">資産名 <span className="text-[#e8002d]">*</span></label>
                  <input
                    type="text"
                    value={newAsset.asset_name}
                    onChange={e => setNewAsset(p => ({ ...p, asset_name: e.target.value }))}
                    className="w-full px-3 py-2 text-sm bg-[#070d19] border border-[#1e2d42] rounded-lg text-white placeholder-[#3d5068] focus:outline-none focus:border-[#7d92b0]"
                    placeholder="例: LAPTOP-HR-10"
                  />
                </div>
                {/* Type */}
                <div>
                  <label className="block text-xs text-[#7d92b0] mb-1.5">タイプ</label>
                  <div className="relative">
                    <select
                      value={newAsset.type}
                      onChange={e => setNewAsset(p => ({ ...p, type: e.target.value as AssetType }))}
                      className="w-full pl-3 pr-8 py-2 text-sm bg-[#070d19] border border-[#1e2d42] rounded-lg text-white focus:outline-none appearance-none"
                    >
                      {(Object.keys(TYPE_LABELS) as AssetType[]).map(t => <option key={t} value={t}>{TYPE_LABELS[t]}</option>)}
                    </select>
                    <ChevronDown className="absolute right-2 top-1/2 -translate-y-1/2 w-4 h-4 text-[#3d5068] pointer-events-none" />
                  </div>
                </div>
                {/* Serial Number */}
                <div>
                  <label className="block text-xs text-[#7d92b0] mb-1.5">シリアル番号</label>
                  <input
                    type="text"
                    value={newAsset.serial_number}
                    onChange={e => setNewAsset(p => ({ ...p, serial_number: e.target.value }))}
                    className="w-full px-3 py-2 text-sm bg-[#070d19] border border-[#1e2d42] rounded-lg text-white placeholder-[#3d5068] focus:outline-none focus:border-[#7d92b0] font-mono"
                    placeholder="SN-XXXX-0001"
                  />
                </div>
                {/* Purchase Date */}
                <div>
                  <label className="block text-xs text-[#7d92b0] mb-1.5">購入日</label>
                  <input
                    type="date"
                    value={newAsset.purchase_date}
                    onChange={e => setNewAsset(p => ({ ...p, purchase_date: e.target.value }))}
                    className="w-full px-3 py-2 text-sm bg-[#070d19] border border-[#1e2d42] rounded-lg text-white focus:outline-none focus:border-[#7d92b0]"
                  />
                </div>
                {/* Warranty Expiry */}
                <div>
                  <label className="block text-xs text-[#7d92b0] mb-1.5">保証期限</label>
                  <input
                    type="date"
                    value={newAsset.warranty_expiry}
                    onChange={e => setNewAsset(p => ({ ...p, warranty_expiry: e.target.value }))}
                    className="w-full px-3 py-2 text-sm bg-[#070d19] border border-[#1e2d42] rounded-lg text-white focus:outline-none focus:border-[#7d92b0]"
                  />
                </div>
                {/* Assigned User */}
                <div>
                  <label className="block text-xs text-[#7d92b0] mb-1.5">担当者</label>
                  <input
                    type="text"
                    value={newAsset.assigned_user}
                    onChange={e => setNewAsset(p => ({ ...p, assigned_user: e.target.value }))}
                    className="w-full px-3 py-2 text-sm bg-[#070d19] border border-[#1e2d42] rounded-lg text-white placeholder-[#3d5068] focus:outline-none focus:border-[#7d92b0]"
                    placeholder="山田 太郎"
                  />
                </div>
                {/* Location */}
                <div>
                  <label className="block text-xs text-[#7d92b0] mb-1.5">場所</label>
                  <input
                    type="text"
                    value={newAsset.location}
                    onChange={e => setNewAsset(p => ({ ...p, location: e.target.value }))}
                    className="w-full px-3 py-2 text-sm bg-[#070d19] border border-[#1e2d42] rounded-lg text-white placeholder-[#3d5068] focus:outline-none focus:border-[#7d92b0]"
                    placeholder="東京DC-A"
                  />
                </div>
                {/* Cost */}
                <div>
                  <label className="block text-xs text-[#7d92b0] mb-1.5">取得価格 (¥)</label>
                  <input
                    type="number"
                    value={newAsset.cost || ''}
                    onChange={e => setNewAsset(p => ({ ...p, cost: Number(e.target.value) }))}
                    className="w-full px-3 py-2 text-sm bg-[#070d19] border border-[#1e2d42] rounded-lg text-white placeholder-[#3d5068] focus:outline-none focus:border-[#7d92b0]"
                    placeholder="250000"
                  />
                </div>
                {/* TCO */}
                <div>
                  <label className="block text-xs text-[#7d92b0] mb-1.5">TCO見込み (¥)</label>
                  <input
                    type="number"
                    value={newAsset.total_cost_of_ownership || ''}
                    onChange={e => setNewAsset(p => ({ ...p, total_cost_of_ownership: Number(e.target.value) }))}
                    className="w-full px-3 py-2 text-sm bg-[#070d19] border border-[#1e2d42] rounded-lg text-white placeholder-[#3d5068] focus:outline-none focus:border-[#7d92b0]"
                    placeholder="350000"
                  />
                </div>
                {/* Initial Stage */}
                <div className="col-span-2">
                  <label className="block text-xs text-[#7d92b0] mb-1.5">初期ステージ</label>
                  <div className="flex gap-2 flex-wrap">
                    {STAGE_ORDER.map(s => (
                      <button
                        key={s}
                        onClick={() => setNewAsset(p => ({ ...p, lifecycle_stage: s }))}
                        className={`px-3 py-1.5 rounded-lg border text-xs transition-colors ${newAsset.lifecycle_stage === s ? STAGE_COLORS[s] : 'bg-[#070d19] border-[#1e2d42] text-[#3d5068] hover:text-white'}`}
                      >
                        {STAGE_LABELS[s]}
                      </button>
                    ))}
                  </div>
                </div>
              </div>
              <div className="flex gap-3 mt-6 pt-4 border-t border-[#1e2d42]">
                <button
                  onClick={handleAddAsset}
                  disabled={addLoading || !newAsset.asset_name}
                  className="flex items-center gap-2 px-4 py-2 rounded bg-[#e8002d] text-white text-sm hover:bg-[#c0001f] transition-colors disabled:opacity-50"
                >
                  {addLoading ? <Loader2 className="w-4 h-4 animate-spin" /> : <Plus className="w-4 h-4" />}
                  登録
                </button>
                <button onClick={() => setShowAddModal(false)} className="px-4 py-2 rounded bg-[#1e2d42] text-[#7d92b0] text-sm hover:text-white transition-colors">
                  キャンセル
                </button>
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  )
}

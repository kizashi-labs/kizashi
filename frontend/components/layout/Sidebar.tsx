'use client'

import React from 'react'
import NextLink from 'next/link'

import { isBackendPending } from '@/lib/backend-pending'
import { usePathname } from 'next/navigation'
import {
  LayoutDashboard, ShieldAlert, Monitor,
  BookOpen, BarChart3, Settings, Shield,
  Bell, Globe, User, Activity,
  Users, ClipboardList, Archive, Layers,
  Crosshair, AlertOctagon, Siren, ShieldOff, Workflow, CalendarClock,
  Target, Bug, Rss, Network, FolderOpen, Search, KeyRound,
  ShieldCheck, TrendingUp, TrendingDown, GitBranch, Download, Package, Tag, GitMerge, Crown, ShoppingBag, MessageSquare,
  ScanSearch, Radio, Terminal, Brain, Wifi,
  HardDrive, Cloud, Building2, Database, Usb, RefreshCw, Box, Code2,
  Map, HeartPulse, FileInput, Sliders, BellRing, Wrench, Server,
  FileCode, Webhook, HelpCircle, CheckCircle,
  Gauge, PackageCheck, MonitorSmartphone, Settings2, CheckSquare,
  SlidersHorizontal,
  FileSearch, Lock, Boxes, Ticket,
  LayoutTemplate, Timer,
  FlaskConical, Waves, Mail, Key,
  Eye, EyeOff, ClipboardCheck, UserX, ScanLine,
  GraduationCap, CalendarRange, PenTool, CalendarDays,
  Star, BarChart2, Send, AppWindow,
  BellDot, ServerCog, Flag, Tags,
  RadioTower, MailOpen,
  UserCheck, BookmarkCheck, FileBarChart,
  DollarSign, ArrowUpCircle, Scale,
  Award, Bot,
  Share2, Cpu, Zap,
  Flame, Video, Calculator,
  GitFork, Fish,
  NotebookPen, BookMarked,
  Radar, CloudLightning, Code,
  Printer, PlayCircle, Briefcase,
  Fingerprint,
  PieChart,
  Megaphone,
  Link as LinkIcon,
  FileCog,
  ChevronLeft,
  CreditCard,
  Inbox,
  X,
} from 'lucide-react'
import { useAuth } from '@/lib/auth'
import { useQuery } from '@tanstack/react-query'
import { apiFetch } from '@/lib/api'
import { TenantSwitcher } from './TenantSwitcher'
import { useState, useCallback, useEffect, useMemo } from 'react'
import { usePlan } from '@/lib/usePlan'
import { useFavorites } from '@/lib/useFavorites'

type NavItem = { href: string; label: string; icon: React.ElementType; feature?: string }
type NavGroup = { label: string; icon?: React.ElementType; items: NavItem[] }

// ── Navigation Groups ──────────────────────────────────────────

const navGroups: NavGroup[] = [
  {
    label: 'エグゼクティブ',
    icon: Star,
    items: [
      { href: '/executive', label: 'エグゼクティブ', icon: Star },
    ],
  },
  {
    label: '概要',
    icon: LayoutDashboard,
    items: [
      { href: '/dashboard',  label: 'ダッシュボード', icon: LayoutDashboard },
      { href: '/search',        label: 'グローバル検索', icon: Search },
      { href: '/search/saved',  label: '保存済み検索',   icon: BookmarkCheck },
      { href: '/timeline',      label: 'タイムライン',   icon: Activity },
    ],
  },
  {
    label: '検知',
    icon: ShieldAlert,
    items: [
      { href: '/alerts',         label: 'アラート',       icon: ShieldAlert },
      { href: '/alerts/triage', label: 'トリアージ',     icon: Layers },
      { href: '/rules',        label: '検知ルール',       icon: BookOpen },
      { href: '/alerts/rules', label: 'アラートルール',   icon: SlidersHorizontal },
      { href: '/suppressions', label: 'アラート抑制',     icon: ShieldOff },
      { href: '/alerts/correlation-v2', label: '高度イベント相関 v2', icon: GitMerge },
    ],
  },
  {
    label: 'エンドポイント',
    icon: Monitor,
    items: [
      { href: '/endpoints',      label: 'エンドポイント',   icon: Monitor },
      { href: '/groups',         label: 'グループ管理',     icon: Layers },
      { href: '/events',         label: 'イベントログ',     icon: Activity },
      { href: '/quarantine',     label: '検疫ファイル',     icon: Archive },
      { href: '/software',       label: 'ソフトウェア管理', icon: Package },
      { href: '/software/diff',  label: 'ソフトウェア変更履歴', icon: GitBranch },
      { href: '/agents/deploy',    label: 'エージェント配布', icon: Download },
      { href: '/endpoints/telemetry', label: 'テレメトリ',       icon: Activity },
      { href: '/endpoints/geo-map', label: '地理分布',       icon: Map },
      { href: '/endpoints/compare', label: 'エンドポイント比較', icon: GitBranch },
      { href: '/endpoints/batch',   label: 'バッチ実行',     icon: Terminal },
      { href: '/endpoints/bulk',    label: '一括操作',         icon: Users },
      { href: '/endpoints/tags',    label: 'エンドポイントタグ', icon: Tags },
      { href: '/live-response',  label: 'ライブレスポンス', icon: Terminal },
      { href: '/forensics',         label: 'フォレンジクス',           icon: HardDrive, feature: 'forensics' },
      { href: '/forensics/network', label: 'ネットワークフォレンジクス', icon: Wifi,      feature: 'forensics' },
      { href: '/forensics/memory',  label: 'メモリ分析',               icon: Cpu,       feature: 'forensics' },
      { href: '/endpoints/behavioral-baseline', label: '行動ベースライン', icon: Brain },
    ],
  },
  {
    label: 'インテリジェンス',
    icon: Brain,
    items: [
      { href: '/intel',                          label: 'インテリジェンスハブ',  icon: Brain },
      { href: '/threat-intel',               label: '脅威インテリジェンス', icon: Rss },
      { href: '/threat-intel/darkweb',       label: 'ダークウェブ監視',      icon: Globe },
      { href: '/threat-intelligence/actors', label: '脅威アクター',         icon: Users },
      { href: '/threat-intelligence/sharing', label: 'TI共有',              icon: Share2 },
      { href: '/threat-intelligence/fusion',       label: 'TIフュージョン',        icon: GitMerge },
      { href: '/threat-intelligence/apt-tracker', label: 'APTトラッカー',          icon: Radar },
      { href: '/admin/feed-analytics',            label: 'フィード品質',           icon: BarChart2, feature: 'threat_intel' },
      { href: '/ioc',                             label: 'IOC管理',              icon: AlertOctagon },
      { href: '/campaigns',       label: '脅威キャンペーン',     icon: GitBranch },
      { href: '/mitre',           label: 'MITRE ATT&CK',         icon: Target },
      { href: '/threat-hunting',           label: 'スレットハンティング', icon: Crosshair,  feature: 'threat_hunting' },
      { href: '/threat-hunting/automated', label: '自動ハンティング',     icon: Search,     feature: 'threat_hunting' },
      { href: '/threat-hunting/notebook',  label: 'ハンティングノート',   icon: NotebookPen, feature: 'threat_hunting' },
      { href: '/intel/vt',                 label: 'VirusTotal検索',       icon: ScanSearch },
      { href: '/sandbox',         label: 'マルウェアサンドボックス', icon: FlaskConical },
      { href: '/malware-analysis/families', label: 'マルウェア分析',        icon: Bug },
      { href: '/threat-modeling/advanced', label: '高度脅威モデリング',     icon: Brain },
      { href: '/admin/tip-integration',    label: 'TIP統合',               icon: LinkIcon, feature: 'threat_intel' },
    ],
  },
  {
    label: '監視',
    icon: Radar,
    items: [
      { href: '/threat-map',          label: '脅威マップ',          icon: Globe },
      { href: '/network',             label: 'ネットワーク分析',   icon: Network },
      { href: '/dns',                 label: 'DNS監視',            icon: Globe },
      { href: '/fim',                 label: 'ファイル変更監視',   icon: FolderOpen },
      { href: '/devices',             label: 'デバイスイベント',   icon: Usb },
      { href: '/network-connections', label: 'ネットワーク接続',   icon: Network },
      { href: '/network-topology',    label: 'ネットワークトポロジー', icon: Map },
      { href: '/auth-events',         label: '認証イベント',       icon: KeyRound },
      { href: '/ueba',                label: '行動分析 (UEBA)',    icon: Activity },
      { href: '/settings/cloud',      label: 'クラウド監視',       icon: Cloud },
      { href: '/cloud-assets',         label: 'クラウドアセット',       icon: Cloud },
      { href: '/cloud-workload',       label: 'クラウドワークロード',   icon: CloudLightning },
      { href: '/container-monitoring', label: 'コンテナ監視',           icon: Boxes },
      { href: '/network-anomalies',     label: 'ネットワーク異常検知', icon: Waves },
      { href: '/network-traffic',        label: 'トラフィック分析',     icon: BarChart2 },
      { href: '/dns-security',            label: 'DNSセキュリティ',       icon: Globe },
      { href: '/email-security',         label: 'メールセキュリティ',   icon: Mail },
      { href: '/cloud-security',         label: 'クラウドCSPM',          icon: Shield },
      { href: '/insider-threats',        label: '内部脅威検知',          icon: UserX },
      { href: '/insider-threat',         label: '内部脅威',              icon: Eye },
      { href: '/asset-discovery',        label: 'アセットディスカバリー', icon: ScanLine },
      { href: '/wireless-security',      label: 'ワイヤレス/IoT',         icon: Wifi },
      { href: '/iot-ot-security',         label: 'IoT/OTセキュリティ',      icon: Cpu },
    ],
  },
  {
    label: '対応',
    icon: Siren,
    items: [
      { href: '/incidents',          label: 'インシデント',   icon: Siren },
      { href: '/incidents/war-room', label: '作戦室',         icon: AlertOctagon },
      { href: '/playbooks',                     label: 'プレイブック',       icon: Workflow },
      { href: '/vulnerabilities',               label: '脆弱性管理',         icon: Bug },
      { href: '/vulnerabilities/intelligence',  label: '脆弱性インテリジェンス', icon: Bug },
      { href: '/vulnerabilities/remediation',   label: '修正追跡',           icon: ClipboardCheck },
      { href: '/vulnerabilities/trends',        label: '脆弱性トレンド',     icon: TrendingUp },
      { href: '/compliance',                    label: 'コンプライアンス',   icon: ShieldCheck },
      { href: '/compliance/calendar',           label: 'コンプライアンスカレンダー', icon: CalendarDays },
      { href: '/compliance/regulatory-mapping', label: '規制マッピング',             icon: Scale },
      { href: '/soc-queue',                      label: 'ワークキュー',        icon: Inbox },
      { href: '/soc/tickets',                   label: 'SOCチケット',         icon: Ticket },
      { href: '/soc/sla',                       label: 'SLA管理',             icon: Timer },
      { href: '/soc/shifts',                    label: 'シフト引継ぎ',         icon: CalendarRange },
      { href: '/soc/metrics',                   label: 'SOC指標',             icon: BarChart3 },
      { href: '/dark-web',                      label: 'ダークウェブ監視',   icon: EyeOff },
      { href: '/vendor-risk',                   label: 'サードパーティリスク', icon: Building2 },
      { href: '/soc/analytics',                 label: 'SOC分析',             icon: BarChart3 },
      { href: '/soc/collaboration',             label: 'チームコラボレーション', icon: MessageSquare },
    ],
  },
  {
    label: 'アセット',
    icon: Package,
    items: [
      { href: '/assets/lifecycle',     label: '資産ライフサイクル', icon: RefreshCw },
      { href: '/assets/dependencies',  label: '依存関係マップ',     icon: GitFork },
    ],
  },
  {
    label: '計画',
    icon: PenTool,
    items: [
      { href: '/threat-modeling',               label: '脅威モデリング',       icon: PenTool },
    ],
  },
  {
    label: 'ナレッジ',
    icon: BookOpen,
    items: [
      { href: '/knowledge-base',               label: 'ナレッジベース',         icon: BookOpen },
    ],
  },
  {
    label: '分析',
    icon: BarChart3,
    items: [
      { href: '/reports',                       label: 'レポート',                         icon: BarChart3 },
      { href: '/reports/schedules',             label: 'スケジュールレポート',             icon: CalendarClock },
      { href: '/reports/builder',               label: 'レポートビルダー',                 icon: LayoutTemplate },
      { href: '/reports/ops-report',            label: 'セキュリティOpsレポート',          icon: FileBarChart },
      { href: '/reports/security-scorecard',    label: 'セキュリティスコア',               icon: BarChart2 },
      { href: '/reports/incident-cost',         label: 'インシデントコスト',               icon: TrendingUp },
      { href: '/reports/risk-heatmap',            label: 'リスクヒートマップ',               icon: Map },
      { href: '/reports/benchmark',              label: 'ベンチマーク',                     icon: Award },
      { href: '/reports/executive-briefing',    label: '経営ブリーフィング',               icon: Briefcase },
      { href: '/soc-metrics',                   label: 'SOCメトリクス',        icon: TrendingUp },
      { href: '/risk-score',                    label: 'リスクスコア',         icon: TrendingDown },
      { href: '/security-score',                label: 'セキュリティスコア',   icon: ShieldCheck },
      { href: '/security-posture',              label: 'セキュリティ態勢', icon: Shield },
      { href: '/agent-health',                  label: 'エージェント健全性',   icon: HeartPulse },
      { href: '/settings/rules-import-export',  label: 'ルールI/E',            icon: FileInput },
    ],
  },
]

// ── Admin nav grouped into accordion sections ──────────────────

const adminNavGroups: NavGroup[] = [
  {
    label: 'コア',
    icon: LayoutDashboard,
    items: [
      { href: '/admin/dashboard',   label: 'ダッシュボード',    icon: LayoutDashboard },
      { href: '/admin/alerts',      label: 'アラート',          icon: ShieldAlert },
      { href: '/admin/agents',      label: 'エージェント',      icon: Monitor },
      { href: '/admin/events',      label: 'イベント',          icon: Activity },
    ],
  },
  {
    label: '検知',
    icon: ShieldAlert,
    items: [
      { href: '/admin/sigma-rules',      label: 'Sigmaルール',          icon: FileSearch },
      { href: '/admin/yara-rules',       label: 'YARAルール',           icon: FileCode,   feature: 'yara' },
      { href: '/admin/ml-analytics',     label: 'ML分析',               icon: Brain,      feature: 'ml_detection' },
      { href: '/admin/detection-studio', label: '検出ルールStudio',     icon: Code },
      { href: '/admin/control-testing',  label: 'コントロールテスト',   icon: FlaskConical },
      { href: '/admin/correlation-rules', label: 'コリレーション',      icon: GitBranch },
      { href: '/admin/custom-alert-rules', label: 'カスタムアラートルール', icon: Bell },
    ],
  },
  {
    label: 'ハンティング & 調査',
    icon: Crosshair,
    items: [
      { href: '/admin/threat-hunting/query-builder', label: 'スレットハンティング',    icon: Crosshair, feature: 'threat_hunting' },
      { href: '/admin/network-analysis',             label: 'ネットワーク分析',        icon: Network },
      { href: '/admin/digital-forensics',            label: 'デジタルフォレンジクス',  icon: HardDrive, feature: 'forensics' },
      { href: '/admin/watchlist',                    label: 'アラートウォッチリスト',  icon: BookmarkCheck },
      { href: '/admin/live-response',                label: 'ライブレスポンス',        icon: Terminal },
      { href: '/admin/threat-graph',                 label: '脅威グラフ',              icon: GitBranch },
    ],
  },
  {
    label: '対応',
    icon: Siren,
    items: [
      { href: '/admin/incidents',        label: 'インシデント',              icon: Siren },
      { href: '/admin/auto-remediation', label: '自動修復',                  icon: Zap },
      { href: '/admin/quarantine',       label: '検疫',                      icon: Archive },
      { href: '/admin/incident-playbooks', label: 'インシデントプレイブック', icon: Workflow, feature: 'playbooks' },
      { href: '/admin/playbooks',        label: 'プレイブック',              icon: BookOpen, feature: 'playbooks' },
      { href: '/admin/soar',             label: 'SOARワークフロー',          icon: Workflow, feature: 'soar' },
      { href: '/admin/autonomous-response', label: '自律対応エンジン',       icon: Bot,      feature: 'soar' },
    ],
  },
  {
    label: '脅威インテリジェンス',
    icon: Brain,
    items: [
      { href: '/admin/threat-intelligence', label: '脅威インテリジェンス',  icon: Rss,      feature: 'threat_intel' },
      { href: '/admin/threat-map',          label: '脅威マップ',            icon: Globe,    feature: 'threat_intel' },
      { href: '/ioc',                       label: 'IOC管理',               icon: AlertOctagon },
      { href: '/admin/dark-web',            label: 'ダークウェブ監視',      icon: EyeOff,   feature: 'threat_intel' },
      { href: '/admin/taxii',              label: 'TAXII 2.1サーバー',      icon: Server,   feature: 'threat_intel' },
      { href: '/admin/tip-integration',    label: 'TIP統合',                icon: LinkIcon, feature: 'threat_intel' },
      { href: '/admin/feed-analytics',     label: 'フィード品質',           icon: BarChart2, feature: 'threat_intel' },
    ],
  },
  {
    label: 'セキュリティ運用',
    icon: Shield,
    items: [
      { href: '/admin/endpoint-hardening',    label: 'エンドポイント強化',       icon: HardDrive },
      { href: '/admin/vulnerability-management', label: '脆弱性管理',            icon: Bug },
      { href: '/admin/user-behavior-analytics', label: 'ユーザー行動分析',       icon: Users },
      { href: '/admin/insider-threat',          label: '内部脅威',               icon: Eye },
      { href: '/admin/ueba',                    label: 'UEBA',                   icon: Activity },
      { href: '/admin/xdr',                      label: 'XDR クロスドメイン検知', icon: Globe, feature: 'xdr' },
      { href: '/admin/zero-trust',              label: 'ゼロトラストポリシー',   icon: ShieldCheck },
      { href: '/admin/dlp',                     label: 'DLP (データ損失防止)',   icon: Lock },
      { href: '/admin/ransomware-protection',   label: 'ランサムウェア対策',     icon: ShieldAlert },
      { href: '/admin/group-policies',          label: 'グループポリシー',       icon: Shield },
      { href: '/admin/edr-policies',            label: 'EDRポリシー管理',        icon: Shield },
    ],
  },
  {
    label: '統合',
    icon: Radio,
    items: [
      { href: '/admin/siem-integration',      label: 'SIEM統合',               icon: Radio,    feature: 'siem_integration' },
      { href: '/admin/webhooks',              label: 'Webhook',                 icon: Webhook },
      { href: '/admin/api-keys',              label: 'APIキー',                 icon: Key,      feature: 'api_access' },
      { href: '/settings/siem',              label: 'SIEM連携',                icon: Radio,    feature: 'siem_integration' },
      { href: '/admin/integrations/ldap',    label: 'LDAP/AD連携',             icon: Server },
      { href: '/admin/integrations/wazuh',   label: 'Wazuh連携',               icon: Shield },
      { href: '/admin/integrations/soar',    label: 'SOAR連携',                icon: Workflow, feature: 'soar' },
      { href: '/admin/webhook-tester',       label: 'Webhookテスター',         icon: Webhook },
      { href: '/admin/webhook-schemas',      label: 'Webhookスキーマ',         icon: FileCode },
      { href: '/admin/log-sources',          label: 'ログソース管理',          icon: FileInput },
      { href: '/admin/log-forwarding',       label: 'ログ転送設定',            icon: Send },
      { href: '/admin/marketplace',          label: '統合マーケットプレース',  icon: ShoppingBag },
    ],
  },
  {
    label: '管理 & 設定',
    icon: Settings,
    items: [
      { href: '/admin/users',           label: 'ユーザー管理',             icon: Users },
      { href: '/admin/agent-profiles',  label: 'エージェントプロファイル', icon: FileCog },
      { href: '/admin/organizations',   label: '組織管理',                 icon: Building2, feature: 'multi_tenant' },
      { href: '/admin/tenants',         label: 'テナント管理',             icon: Building2, feature: 'multi_tenant' },
      { href: '/admin/rbac',            label: 'RBAC権限管理',             icon: Shield },
      { href: '/admin/mfa-management',  label: 'MFA登録管理',              icon: KeyRound },
      { href: '/admin/sessions',        label: 'セッション管理',           icon: MonitorSmartphone },
      { href: '/admin/pam',             label: '特権アクセス管理 (PAM)',   icon: Key },
      { href: '/admin/service-accounts', label: 'サービスアカウント',      icon: ServerCog, feature: 'api_access' },
      { href: '/admin/oauth2-clients',  label: 'OAuth2クライアント管理',   icon: AppWindow, feature: 'api_access' },
      { href: '/admin/password-policy', label: 'パスワードポリシー',       icon: Lock },
      { href: '/admin/notifications',   label: '通知チャンネル',           icon: BellRing },
      { href: '/admin/notification-templates', label: '通知テンプレート',  icon: Bell },
      { href: '/admin/feature-flags',   label: 'フィーチャーフラグ',       icon: Flag },
    ],
  },
  {
    label: 'レポート & コンプライアンス',
    icon: BarChart3,
    items: [
      { href: '/admin/security-scorecard',  label: 'セキュリティスコアカード',     icon: BarChart2 },
      { href: '/admin/executive-dashboard', label: 'エグゼクティブダッシュボード', icon: Star },
      { href: '/admin/audit-logs',          label: 'コンプライアンス/監査ログ',    icon: ClipboardList },
      { href: '/admin/security-metrics',    label: 'セキュリティメトリクス',       icon: TrendingUp },
      { href: '/admin/kpi-dashboard',       label: 'セキュリティKPI',              icon: Target },
      { href: '/admin/compliance',           label: '準拠状況管理 (NIST/ISO)',      icon: ShieldCheck },
      { href: '/admin/compliance-auto',     label: 'コンプライアンス自動評価',     icon: ShieldCheck,    feature: 'compliance' },
      { href: '/admin/compliance-evidence', label: '証拠収集',                     icon: ClipboardCheck, feature: 'compliance' },
      { href: '/admin/compliance-workflows', label: 'コンプライアンスワークフロー', icon: GitBranch,      feature: 'compliance' },
      { href: '/admin/audit',              label: '監査ログ',                      icon: ClipboardList },
      { href: '/admin/audit-export',       label: '監査エクスポート',              icon: FileInput,      feature: 'compliance' },
      { href: '/admin/reports-engine',     label: 'レポートエンジン',              icon: Printer,        feature: 'reports' },
      { href: '/admin/security-budget',    label: 'セキュリティ予算',              icon: DollarSign },
      { href: '/admin/maturity-model',     label: '成熟度評価',                    icon: TrendingUp,     feature: 'compliance' },
    ],
  },
  {
    label: 'システム',
    icon: Server,
    items: [
      { href: '/admin/system-status',      label: 'システムステータス',      icon: HeartPulse },
      { href: '/admin/adoption-metrics',   label: '利用状況ダッシュボード',   icon: TrendingUp },
      { href: '/admin/support',            label: 'サポート管理',             icon: Ticket },
      { href: '/admin/guide',              label: '管理者ガイド',             icon: BookOpen },
      { href: '/admin/backup',             label: 'バックアップ & 復元',    icon: Database },
      { href: '/admin/dashboard-settings', label: 'ダッシュボード設定',     icon: Sliders },
      { href: '/admin/server-health',      label: 'サーバーリソース監視',   icon: Server },
      { href: '/admin/settings',           label: 'システム設定',            icon: Sliders },
      { href: '/admin/system-settings',    label: 'システム設定 (詳細)',    icon: Settings2 },
      { href: '/admin/platform-upgrade',   label: 'プラットフォーム更新',   icon: ArrowUpCircle },
      { href: '/admin/backups',            label: 'バックアップ管理',       icon: Database },
      { href: '/admin/migrations',         label: 'マイグレーション',       icon: Database },
      { href: '/admin/observability',      label: 'オブザーバビリティ設定', icon: RadioTower },
      { href: '/admin/rate-limits',        label: 'レートリミット',          icon: Gauge },
      { href: '/admin/version',            label: 'バージョン管理',          icon: PackageCheck },
      { href: '/admin/maintenance-windows', label: 'メンテナンス',           icon: CalendarClock },
      { href: '/admin/onboarding',         label: 'セットアップウィザード', icon: CheckSquare },
      { href: '/admin/api-docs',           label: 'APIドキュメント',         icon: BookOpen },
    ],
  },
  {
    label: 'セキュリティツール',
    icon: Target,
    items: [
      { href: '/admin/geo-blocking',        label: 'ジオブロッキング',     icon: Globe },
      { href: '/admin/ip-blocklist',       label: 'IPブロックリスト',     icon: Globe },
      { href: '/admin/file-hashes',        label: 'ファイルハッシュ',     icon: FileCode },
      { href: '/admin/process-allowlist',  label: 'プロセス許可リスト',   icon: CheckCircle },
      { href: '/admin/agent-tags',         label: 'タグ管理',             icon: Tag },
      { href: '/admin/assign-rules',       label: '自動割り当て',         icon: GitMerge },
      { href: '/admin/escalation-rules',   label: 'エスカレーション',     icon: TrendingUp },
      { href: '/admin/custom-fields',      label: 'カスタムフィールド',   icon: Layers },
      { href: '/admin/honeypots',          label: 'ハニーポット',          icon: Bug,       feature: 'deception' },
      { href: '/admin/deception',          label: 'デセプション技術',     icon: Crosshair, feature: 'deception' },
      { href: '/admin/honeynet',           label: 'ハニーネット',          icon: Bug,       feature: 'deception' },
      { href: '/admin/attack-surface',     label: '攻撃面管理',           icon: ScanSearch },
      { href: '/admin/red-team',           label: 'レッドチーム',          icon: Target },
      { href: '/admin/bas',               label: 'BASシミュレーション',    icon: Target },
      { href: '/admin/pentest',           label: 'ペンテスト管理',         icon: Shield },
      { href: '/admin/chaos-engineering', label: 'カオスエンジニアリング', icon: Zap },
      { href: '/admin/phishing-simulator', label: 'フィッシングSim',       icon: Fish },
      { href: '/admin/adversary-emulation', label: '敵対的エミュレーション', icon: Target },
      { href: '/admin/incident-drills',   label: '訓練シミュレーション',   icon: PlayCircle },
    ],
  },
  {
    label: 'クラウド & インフラ',
    icon: Cloud,
    items: [
      { href: '/admin/cloud-siem',       label: 'クラウドSIEM',       icon: Cloud },
      { href: '/admin/cloud-identity',   label: 'クラウドID',          icon: Users },
      { href: '/admin/container-security', label: 'コンテナセキュリティ', icon: Box },
      { href: '/admin/api-security',     label: 'APIセキュリティ',     icon: Code2 },
      { href: '/admin/data-lake',        label: 'データレイク',         icon: Database },
      { href: '/admin/network-segmentation', label: 'ネットワーク分割', icon: GitBranch },
      { href: '/admin/siem-query-builder', label: 'SIEMクエリ',         icon: Database, feature: 'siem_integration' },
      { href: '/admin/log-analysis',     label: 'ログ分析',             icon: FileSearch },
      { href: '/admin/orchestration',    label: 'オーケストレーション', icon: Network },
      { href: '/admin/patch-management', label: 'パッチ管理',           icon: Package },
    ],
  },
  {
    label: '人材 & トレーニング',
    icon: GraduationCap,
    items: [
      { href: '/admin/training',            label: 'セキュリティトレーニング', icon: GraduationCap },
      { href: '/admin/training-analytics',  label: 'トレーニング分析',         icon: GraduationCap },
      { href: '/admin/security-champions',  label: 'セキュリティチャンピオン', icon: Star },
      { href: '/admin/awareness-campaigns', label: '意識向上キャンペーン',     icon: Megaphone },
      { href: '/admin/oncall',              label: 'オンコール統合',            icon: BellDot },
    ],
  },
  {
    label: 'ID & アクセス',
    icon: KeyRound,
    items: [
      { href: '/admin/privileged-sessions', label: '特権セッション',           icon: Video },
      { href: '/admin/pag',                label: '特権アクセスガバナンス',    icon: Crown },
      { href: '/admin/identity-risk',      label: 'IDリスク',                  icon: UserX },
      { href: '/admin/enrollment',         label: 'エージェント登録承認',       icon: UserCheck },
      { href: '/admin/certificates',       label: '証明書管理',                 icon: Lock },
    ],
  },
  {
    label: '分析 & インサイト',
    icon: BarChart2,
    items: [
      { href: '/admin/metrics-explorer',      label: 'メトリクスエクスプローラー', icon: Gauge },
      { href: '/admin/data-viz',              label: 'データビジュアライゼーション', icon: PieChart },
      { href: '/admin/predictive-analytics',  label: '予測的セキュリティ分析',      icon: TrendingUp, feature: 'ai_investigation' },
      { href: '/admin/agent-performance',     label: 'エージェント性能',            icon: Activity },
      { href: '/admin/performance',           label: 'Web Vitals',                  icon: Zap },
      { href: '/admin/incident-cost-calculator', label: 'コスト計算機',             icon: Calculator },
      { href: '/admin/incident-patterns',     label: 'パターン認識',               icon: Fingerprint },
      { href: '/admin/capacity-planning',     label: 'リソース計画',               icon: TrendingUp },
    ],
  },
  {
    label: 'ガバナンス & リスク',
    icon: Scale,
    items: [
      { href: '/admin/risk-register',      label: 'リスク台帳',           icon: BookMarked },
      { href: '/admin/vendor-risk',        label: 'サードパーティリスク', icon: Building2 },
      { href: '/admin/vendor-assessment',  label: 'ベンダー評価',          icon: ClipboardList },
      { href: '/admin/cyber-insurance',    label: 'サイバー保険',          icon: Shield },
      { href: '/admin/privacy',            label: 'プライバシー/GDPR管理', icon: ShieldCheck },
      { href: '/admin/privacy-assessment', label: 'PIA/DPIA',              icon: Shield },
      { href: '/admin/arch-review',        label: 'アーキテクチャレビュー', icon: Building2 },
      { href: '/admin/supply-chain',       label: 'サプライチェーン',       icon: Package },
      { href: '/admin/tooling-inventory',  label: 'ツール台帳',             icon: Wrench },
      { href: '/admin/controls-monitoring', label: 'コントロール監視',      icon: ShieldCheck },
      { href: '/admin/runbook',            label: '運用手順書',              icon: BookOpen },
    ],
  },
  {
    label: '自動化',
    icon: Zap,
    items: [
      { href: '/admin/automation',           label: '自動化ワークフロー',    icon: Zap },
      { href: '/admin/playbook-builder',     label: 'プレイブック作成',      icon: GitBranch },
      { href: '/admin/enrichment',           label: 'エンリッチメント',      icon: Layers },
      { href: '/admin/alert-digest',         label: 'アラートダイジェスト',  icon: MailOpen },
      { href: '/admin/zero-day',             label: 'ゼロデイ対応',           icon: Flame },
    ],
  },
  {
    label: 'インストーラー & 展開',
    icon: Download,
    items: [
      { href: '/admin/installer',           label: 'インストーラー',         icon: Wrench },
      { href: '/admin/agent-deployment',    label: 'エージェント展開',       icon: Download },
      { href: '/admin/agent-tags',          label: 'エージェントタグ',        icon: Tag },
    ],
  },
]

const bottomNav = [
  { href: '/faq',                     label: 'よくある質問',       icon: HelpCircle },
  { href: '/notifications',           label: '通知設定',           icon: Bell },
  { href: '/profile/notifications',   label: '通知プリファレンス', icon: BellRing },
  { href: '/settings',                label: '設定',               icon: Settings },
  { href: '/settings/api-keys',       label: 'APIキー管理',        icon: KeyRound },
  { href: '/profile',                 label: 'プロフィール',       icon: User },
  { href: '/help',                    label: 'ヘルプ',             icon: HelpCircle },
  { href: '/support',                 label: 'サポートチケット',   icon: Ticket },
]

// ── Component ─────────────────────────────────────────────────

export function Sidebar({ onSearchOpen }: { onSearchOpen?: () => void }) {
  const pathname = usePathname()
  const { user } = useAuth()
  const isAdmin = user?.role === 'admin'
  const { hasFeature } = usePlan()

  const { data: alertStats } = useQuery<{ open: number }>({
    queryKey: ['alert-stats-sidebar'],
    queryFn: () => apiFetch('/api/v1/alerts/stats'),
    refetchInterval: 30_000,
    staleTime: 20_000,
  })

  const { data: incidentStats } = useQuery<{ total: number }>({
    queryKey: ['incident-stats-sidebar'],
    queryFn: () => apiFetch('/api/v1/incidents?status=active&per_page=1'),
    refetchInterval: 60_000,
    staleTime: 30_000,
  })

  const { data: notifUnread } = useQuery<{ count: number; urgent_alerts: number; new_incidents: number }>({
    queryKey: ['notif-unread-sidebar'],
    queryFn: () => apiFetch('/api/v1/notifications/unread'),
    refetchInterval: 60_000,
    staleTime: 30_000,
    retry: false,
  })

  const openAlertCount = alertStats?.open ?? 0
  const openIncidentCount = incidentStats?.total ?? 0
  const unreadCount = notifUnread?.count ?? 0

  // hrefs that carry a red (critical) badge when their count > 0
  const ALERT_RED_HREFS   = ['/alerts', '/admin/alerts']
  const ALERT_ORANGE_HREFS = ['/alerts/triage']
  const INCIDENT_RED_HREFS    = ['/incidents/war-room']
  const INCIDENT_ORANGE_HREFS = ['/incidents', '/admin/incidents']

  // Returns badge color class for a sub-pane item, or null if none needed.
  const itemBadgeColor = useCallback((href: string): string | null => {
    if (openAlertCount > 0) {
      if (ALERT_RED_HREFS.includes(href))    return 'bg-[#e8002d] critical-pulse'
      if (ALERT_ORANGE_HREFS.includes(href)) return 'bg-orange-500'
    }
    if (openIncidentCount > 0) {
      if (INCIDENT_RED_HREFS.includes(href))    return 'bg-[#e8002d] critical-pulse'
      if (INCIDENT_ORANGE_HREFS.includes(href)) return 'bg-orange-500'
    }
    return null
  }, [openAlertCount, openIncidentCount]) // eslint-disable-line react-hooks/exhaustive-deps

  // Returns the count number to display on a sub-pane item badge.
  const itemBadgeCount = useCallback((href: string): number => {
    if (openAlertCount > 0) {
      if (ALERT_RED_HREFS.includes(href) || ALERT_ORANGE_HREFS.includes(href)) return openAlertCount
    }
    if (openIncidentCount > 0) {
      if (INCIDENT_RED_HREFS.includes(href) || INCIDENT_ORANGE_HREFS.includes(href)) return openIncidentCount
    }
    return 0
  }, [openAlertCount, openIncidentCount]) // eslint-disable-line react-hooks/exhaustive-deps

  // Returns true when the group should show an alert (red) badge.
  const groupAlertBadge = useCallback((group: NavGroup): boolean =>
    openAlertCount > 0 && group.items.some(i => [...ALERT_RED_HREFS, ...ALERT_ORANGE_HREFS].includes(i.href))
  , [openAlertCount]) // eslint-disable-line react-hooks/exhaustive-deps

  // Returns true when the group should show an incident (orange) badge.
  const groupIncidentBadge = useCallback((group: NavGroup): boolean =>
    openIncidentCount > 0 && group.items.some(i => [...INCIDENT_RED_HREFS, ...INCIDENT_ORANGE_HREFS].includes(i.href))
  , [openIncidentCount]) // eslint-disable-line react-hooks/exhaustive-deps

  const allGroups = useMemo(
    () => [...navGroups, ...(isAdmin ? adminNavGroups : [])],
    [isAdmin],
  )

  const allNavHrefs = useMemo(
    () => allGroups.flatMap(g => g.items.map(i => i.href)),
    [allGroups],
  )

  const isActive = useCallback((href: string) => {
    if (pathname === href) return true
    if (href === '/dashboard') return false
    if (!pathname.startsWith(href + '/')) return false
    return !allNavHrefs.some(
      other => other !== href && other.startsWith(href + '/') && pathname.startsWith(other)
    )
  }, [pathname, allNavHrefs])

  // Several adminNavGroups entries share a label with a navGroups entry (e.g.
  // both have '検知'). openGroup/subPaneGroup used to be keyed on the bare
  // label, so opening an admin group whose label collides with a regular one
  // resolved to the regular group's items instead (allGroups.find() returns
  // the first match, and navGroups is spread before adminNavGroups) — the
  // admin subpane silently showed the wrong content. Admin groups now get a
  // distinct 'admin:' -prefixed key for open/lookup purposes while the
  // displayed label is untouched.
  const groupKey = (label: string, admin: boolean) => (admin ? `admin:${label}` : label)

  const findActiveGroupLabel = useCallback(() => {
    const navMatch = navGroups.find(g => g.items.some(i => isActive(i.href)))
    if (navMatch) return navMatch.label
    if (isAdmin) {
      const adminMatch = adminNavGroups.find(g => g.items.some(i => isActive(i.href)))
      if (adminMatch) return groupKey(adminMatch.label, true)
    }
    return null
  }, [isAdmin, isActive])

  const [openGroup, setOpenGroup] = useState<string | null>(() => findActiveGroupLabel())

  useEffect(() => {
    const g = findActiveGroupLabel()
    if (g) setOpenGroup(g)
  }, [pathname]) // eslint-disable-line react-hooks/exhaustive-deps

  const subPaneGroup = openGroup?.startsWith('admin:')
    ? adminNavGroups.find(g => g.label === openGroup!.slice('admin:'.length)) ?? null
    : navGroups.find(g => g.label === openGroup) ?? null

  const { favorites, isFavorite, toggleFavorite, removeFavorite } = useFavorites()

  const toggleGroup = (label: string) =>
    setOpenGroup(prev => (prev === label ? null : label))

  // Whether the *currently open* subpane is the admin instance of a group.
  // Must be derived from the openGroup key (not from a label lookup against
  // adminNavGroups) for the same reason subPaneGroup is: regular and admin
  // groups frequently share a label (e.g. both have '検知'), so a label-only
  // check would also match when the regular, non-admin subpane is open.
  const openGroupIsAdmin = openGroup?.startsWith('admin:') ?? false

  return (
    <aside
      className={`h-full shrink-0 flex bg-falcon-gradient border-r border-[#1e2d42] overflow-hidden transition-all duration-200 ${
        openGroup ? 'w-[260px]' : 'w-[52px]'
      }`}
    >
      {/* ── Icon Rail ───────────────────────────────────────────── */}
      <div className="w-[52px] shrink-0 grid grid-rows-[auto_auto_1fr_auto] h-screen border-r border-[#1e2d42]">

        {/* Logo */}
        <div className="flex items-center justify-center h-[54px] border-b border-[#1e2d42] shrink-0">
          <div className="relative" title="Kizashi">
            <div className="w-8 h-8 rounded-sm flex items-center justify-center bg-linear-to-br from-[#e8002d] to-[#a80020] shadow-falcon-glow-red">
              <Shield className="w-4 h-4 text-white" strokeWidth={2.5} />
            </div>
            <span className="absolute -bottom-0.5 -right-0.5 w-2 h-2 bg-[#00c853] rounded-full border border-[#0d1220]" />
          </div>
        </div>

        {/* Search */}
        <div className="px-2 py-2 border-b border-[#1e2d42] shrink-0">
          <button
            onClick={onSearchOpen}
            title="検索 (Ctrl+K)"
            className="w-full flex items-center justify-center p-2 rounded-sm bg-[#0d1220] border border-[#1e2d42] text-[#7d92b0] hover:text-[#e2e8f4] hover:border-[#7d92b0]/40 transition-all"
          >
            <Search className="w-3.5 h-3.5" />
          </button>
        </div>

        {/* Nav group icons */}
        <nav className="overflow-y-auto min-h-0 px-2 py-2 space-y-0.5 scrollbar-thin">
          {navGroups.map(group => {
            const GroupIcon = group.icon!
            const hasActive = group.items.some(i => isActive(i.href))
            const isOpen = openGroup === group.label
            const alertBadge    = groupAlertBadge(group)
            const incidentBadge = groupIncidentBadge(group)
            return (
              <button
                key={group.label}
                onClick={() => toggleGroup(group.label)}
                title={
                  alertBadge    ? `${group.label}（未対応アラート ${openAlertCount} 件）` :
                  incidentBadge ? `${group.label}（未処理インシデント ${openIncidentCount} 件）` :
                  group.label
                }
                className={`relative w-full p-2.5 rounded-sm flex items-center justify-center transition-colors ${
                  isOpen
                    ? 'bg-[#1d2f4a]'
                    : hasActive
                      ? 'bg-[#19253d]'
                      : 'text-[#3d5068] hover:bg-[#19253d] hover:text-[#7d92b0]'
                }`}
              >
                {(hasActive || isOpen) && (
                  <span className="absolute left-0 top-1 bottom-1 w-0.5 rounded-r bg-[#e8002d]" />
                )}
                <GroupIcon className={`w-4 h-4 ${hasActive || isOpen ? 'text-[#e8002d]' : ''}`} />
                {(alertBadge || incidentBadge) && (
                  <span className={`absolute top-0.5 right-0.5 w-2 h-2 rounded-full ${alertBadge ? 'bg-[#e8002d] critical-pulse' : 'bg-orange-500'}`} />
                )}
              </button>
            )
          })}

          {/* Admin group icons */}
          {isAdmin && (
            <>
              <div className="border-t border-[#1e2d42] my-1.5" />
              {adminNavGroups.map(group => {
                const GroupIcon = group.icon!
                const hasActive = group.items.some(i => isActive(i.href))
                const isOpen = openGroup === groupKey(group.label, true)
                const alertBadge    = groupAlertBadge(group)
                const incidentBadge = groupIncidentBadge(group)
                return (
                  <button
                    key={`admin:${group.label}`}
                    onClick={() => toggleGroup(groupKey(group.label, true))}
                    title={
                      alertBadge    ? `[管理] ${group.label}（未対応アラート ${openAlertCount} 件）` :
                      incidentBadge ? `[管理] ${group.label}（未対応インシデント ${openIncidentCount} 件）` :
                      `[管理] ${group.label}`
                    }
                    className={`relative w-full p-2.5 rounded-sm flex items-center justify-center transition-colors ${
                      isOpen
                        ? 'bg-[#1d2f4a]'
                        : hasActive
                          ? 'bg-[#19253d]'
                          : 'text-[#3d5068] hover:bg-[#19253d] hover:text-[#7d92b0]'
                    }`}
                  >
                    {(hasActive || isOpen) && (
                      <span className="absolute left-0 top-1 bottom-1 w-0.5 rounded-r bg-[#e8002d]" />
                    )}
                    <GroupIcon className={`w-4 h-4 ${hasActive || isOpen ? 'text-[#e8002d]' : ''}`} />
                    {(alertBadge || incidentBadge) && (
                      <span className={`absolute top-0.5 right-0.5 w-2 h-2 rounded-full ${alertBadge ? 'bg-[#e8002d] critical-pulse' : 'bg-orange-500'}`} />
                    )}
                  </button>
                )
              })}
            </>
          )}
        </nav>

        {/* Bottom: settings + language switcher */}
        <div className="border-t border-[#1e2d42] px-2 py-2 space-y-0.5 shrink-0">
          {bottomNav.map(({ href, label, icon: Icon }) => {
            const active = isActive(href)
            const showBadge = href === '/notifications' && unreadCount > 0
            return (
              <NextLink
                key={href}
                href={href}
                title={showBadge ? `${label}（未読 ${unreadCount}件）` : label}
                className={`relative flex items-center justify-center p-2 rounded-sm transition-all ${
                  active
                    ? 'bg-[#1d2f4a] text-[#e8002d]'
                    : 'text-[#3d5068] hover:bg-[#19253d] hover:text-[#7d92b0]'
                }`}
              >
                <Icon className="w-4 h-4" />
                {showBadge && (
                  <span className="absolute top-0.5 right-0.5 min-w-[14px] h-[14px] px-0.5 bg-[#e8002d] rounded-full text-white text-[9px] font-bold flex items-center justify-center leading-none">
                    {unreadCount > 99 ? '99+' : unreadCount}
                  </span>
                )}
              </NextLink>
            )
          })}
        </div>
      </div>

      {/* ── Sub-pane ────────────────────────────────────────────── */}
      {subPaneGroup && (() => {
        const SubIcon = subPaneGroup.icon!
        return (
        <div className="flex-1 flex flex-col overflow-hidden min-w-0">

          {/* Sub-pane header */}
          <div className="flex flex-col justify-center px-3 h-[54px] border-b border-[#1e2d42] shrink-0 gap-0.5">
            <span className="text-[9px] font-bold tracking-widest text-[#3d5068]">
              Kizashi<span className="text-[#e8002d]">EDR</span>
            </span>
            <div className="flex items-center gap-2">
              <SubIcon className="w-3.5 h-3.5 text-[#e8002d] shrink-0" />
              <span className={`text-[11px] font-bold uppercase tracking-wider flex-1 truncate ${
                openGroupIsAdmin ? 'text-[#e8002d]/70' : 'text-[#7d92b0]'
              }`}>
                {subPaneGroup.label}
              </span>
              <button
                onClick={() => setOpenGroup(null)}
                title="閉じる"
                className="p-1 rounded-sm text-[#3d5068] hover:text-[#7d92b0] hover:bg-[#19253d] transition-colors shrink-0"
              >
                <ChevronLeft className="w-3.5 h-3.5" />
              </button>
            </div>
          </div>

          {/* Tenant switcher — only for admin groups */}
          {isAdmin && openGroupIsAdmin && <TenantSwitcher />}

          {/* Items */}
          <div className="flex-1 overflow-y-auto px-2 py-2 space-y-0.5 scrollbar-thin">
            {/* お気に入りセクション */}
            {favorites.length > 0 && (
              <div className="mb-2">
                <div className="flex items-center gap-1.5 px-2 py-1">
                  <Star className="w-3 h-3 text-yellow-400 fill-yellow-400 shrink-0" />
                  <span className="text-[9px] font-bold tracking-widest text-[#3d5068] uppercase">お気に入り</span>
                </div>
                {favorites.map(fav => {
                  const active = isActive(fav.href)
                  return (
                    <div key={fav.href} className="group/favitem relative flex items-center">
                      <NextLink
                        href={fav.href}
                        className={`flex-1 flex items-center gap-2 px-2.5 py-[6px] rounded-sm text-[12px] transition-all duration-100 pr-7
                                    ${active ? 'bg-[#1d2f4a] text-white' : 'text-[#7d92b0] hover:bg-[#19253d] hover:text-[#e2e8f4]'}`}
                      >
                        {active && <span className="absolute left-0 top-1 bottom-1 w-0.5 rounded-r bg-[#e8002d]" />}
                        <Star className="w-3.5 h-3.5 text-yellow-400 fill-yellow-400 shrink-0" />
                        <span className="flex-1 font-medium truncate">{fav.label}</span>
                      </NextLink>
                      <button
                        onClick={(e) => { e.preventDefault(); e.stopPropagation(); removeFavorite(fav.href) }}
                        title="お気に入りから削除"
                        className="absolute right-1 z-10 p-1 rounded-sm opacity-0 group-hover/favitem:opacity-100 text-[#3d5068] hover:text-[#7d92b0] transition-opacity"
                      >
                        <X className="w-3 h-3" />
                      </button>
                    </div>
                  )
                })}
                <div className="my-1.5 border-t border-[#1e2d42]/60" />
              </div>
            )}

            {subPaneGroup.items.map(({ href, label: itemLabel, icon: Icon, feature }) => {
              const active = isActive(href)
              const locked = !!feature && !(hasFeature as (f: string) => boolean)(feature)
              // **サイドバーに 60 の「準備中」が、動く 232 と同じ顔で
              // 並んでいました**（実測 2026-08-12）。開いて初めて分かる
              // ので、担当者は開いて、戻って、また別のを開きます。
              // 一覧は `lib/backend-pending` にあり、バナーと同じものを
              // 読みます —— 写しを持つと片方だけ増えます。
              const pending = isBackendPending(href)
              const badgeColor = itemBadgeColor(href)
              const badgeCount = badgeColor ? itemBadgeCount(href) : 0
              const starred = isFavorite(href)
              return (
                <div key={href} className="group/navitem relative flex items-center">
                  <NextLink
                    href={href}
                    title={
                      locked
                        ? `${itemLabel}（上位プランが必要です）`
                        : pending
                          ? `${itemLabel}（バックエンド準備中です）`
                          : itemLabel
                    }
                    className={`relative flex-1 flex items-center gap-2 px-2.5 py-[6px] rounded-sm text-[12px]
                                transition-all duration-100 pr-7
                                ${active
                                  ? 'bg-[#1d2f4a] text-white'
                                  : locked
                                    ? 'text-[#3d5068] hover:bg-[#19253d]/50 hover:text-[#5a7090]'
                                    : 'text-[#7d92b0] hover:bg-[#19253d] hover:text-[#e2e8f4]'
                                }`}
                  >
                    {/* アクティブページの左ボーダー（赤） */}
                    {active && (
                      <span className="absolute left-0 top-1 bottom-1 w-0.5 rounded-r bg-[#e8002d]" />
                    )}
                    {/* 未対応件数があるページの左ボーダー（色付き・太め） */}
                    {!active && badgeColor && badgeCount > 0 && (
                      <span className={`absolute left-0 top-0.5 bottom-0.5 w-1 rounded-r ${badgeColor.includes('orange') ? 'bg-orange-500' : 'bg-[#e8002d]'}`} />
                    )}
                    <span className="shrink-0">
                      <Icon className={`w-3.5 h-3.5 ${
                        active ? 'text-[#e8002d]' : badgeColor && badgeCount > 0 ? (badgeColor.includes('orange') ? 'text-orange-400' : 'text-[#e8002d]') : 'text-[#3d5068] group-hover/navitem:text-[#7d92b0]'
                      }`} />
                    </span>
                    <span className="flex-1 font-medium truncate">{itemLabel}</span>
                    {/* 未対応件数バッジ（ラベル右側に表示） */}
                    {!active && badgeColor && badgeCount > 0 && (
                      <span className={`shrink-0 text-[9px] font-bold px-1.5 py-0.5 rounded-sm mr-6
                                        text-white ${badgeColor.includes('orange') ? 'bg-orange-500' : 'bg-[#e8002d]'}`}>
                        {badgeCount > 99 ? '99+' : badgeCount}件
                      </span>
                    )}
                    {locked && <Lock className="w-3 h-3 text-[#3d5068] shrink-0" />}
                    {!locked && pending && (
                      <span
                        className="shrink-0 text-[9px] font-medium px-1 py-0.5 rounded-sm mr-6 border border-amber-500/40 text-amber-400/90"
                      >
                        準備中
                      </span>
                    )}
                  </NextLink>
                  {!locked && (
                    <button
                      onClick={(e) => { e.preventDefault(); e.stopPropagation(); toggleFavorite(href, itemLabel) }}
                      title={starred ? 'お気に入りから削除' : 'お気に入りに追加'}
                      className={`absolute right-1 z-10 p-1 rounded-sm transition-all ${
                        starred
                          ? 'opacity-100 text-yellow-400'
                          : 'opacity-0 group-hover/navitem:opacity-100 text-[#3d5068] hover:text-yellow-400'
                      }`}
                    >
                      <Star className={`w-3 h-3 ${starred ? 'fill-yellow-400' : ''}`} />
                    </button>
                  )}
                </div>
              )
            })}
          </div>

          {/* User info strip at bottom of sub-pane */}
          {user && (
            <div className="border-t border-[#1e2d42] px-3 py-2 flex items-center gap-2 shrink-0">
              <div className="w-6 h-6 rounded-full bg-linear-to-br from-[#1a6bff] to-[#0044cc] flex items-center justify-center shrink-0">
                <span className="text-[9px] font-bold text-white uppercase">
                  {(user.full_name || user.email || user.id)?.[0]?.toUpperCase() ?? 'U'}
                </span>
              </div>
              <div className="min-w-0 flex-1">
                <p className="text-[11px] text-[#e2e8f4] font-medium truncate">{user.full_name || user.email || user.id}</p>
                <p className="text-[9px] text-[#3d5068] uppercase tracking-wide">
                  {user.role}
                  {user.role === 'viewer' && (
                    <span className="ml-1 text-[8px] px-1 py-px rounded-sm bg-[#1a1a2e] text-[#7c7cff] border border-[#2d2d5e] normal-case tracking-normal">閲覧専用</span>
                  )}
                </p>
              </div>
            </div>
          )}
        </div>
        )
      })()}
    </aside>
  )
}

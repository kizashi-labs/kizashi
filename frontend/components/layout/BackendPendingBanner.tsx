'use client'

import { usePathname } from 'next/navigation'
import { Construction } from 'lucide-react'

// Routes whose primary data APIs are not implemented on the server yet
// (verified by probing every static endpoint the frontend references).
// Listed pages show an honest "backend pending" notice instead of silently
// rendering empty or mock data. Remove a route here once its backend ships.
const BACKEND_PENDING_ROUTES = new Set<string>([
  '/admin/arch-review',
  '/admin/asset-criticality',
  '/admin/auto-response',
  '/admin/awareness-campaigns',
  '/admin/behavioral-baseline',
  '/admin/control-testing',
  '/admin/controls-monitoring',
  '/admin/custom-alert-rules',
  '/admin/compliance-remediation',
  '/admin/cyber-insurance',
  '/admin/data-lake',
  '/admin/data-viz',
  '/admin/deception-technology',
  '/admin/detection-studio',
  '/admin/encryption-mgmt',
  '/admin/file-hashes',
  '/admin/geo-blocking',
  '/admin/group-policies',
  '/admin/identity-risk',
  '/admin/log-forwarding',
  '/admin/marketplace',
  '/admin/migrations',
  '/admin/observability',
  '/admin/onboarding',
  '/admin/oncall',
  '/admin/orchestration',
  '/admin/pag',
  '/admin/playbook-builder',
  '/admin/privacy-assessment',
  '/admin/privileged-sessions',
  '/admin/quarantine',
  '/admin/rate-limits',
  '/admin/red-team',
  '/admin/runbook',
  '/admin/saved-searches',
  '/admin/security-champions',
  '/admin/security-dw',
  '/admin/security-governance',
  '/admin/security-roi',
  '/admin/siem-query-builder',
  '/admin/supply-chain',
  '/admin/supply-chain-risk',
  '/admin/tooling-inventory',
  '/admin/training-analytics',
  '/admin/training-mgmt',
  '/admin/user-behavior-analytics',
  '/admin/vendor-assessment',
  '/admin/webhooks',
  '/admin/zero-day',
  '/admin/ztna',
  '/alerts/correlation-v2',
  '/alerts/rules',
  '/assets/dependencies',
  '/assets/lifecycle',
  '/compliance/calendar',
  '/container-monitoring',
  '/malware-analysis/families',
  '/soc/shifts',
  '/threat-hunting/campaigns',
  '/wireless-security',
  '/yara',
])

// Pages that work overall but contain sections whose APIs are pending.
const PARTIAL_PENDING_ROUTES = new Set<string>([
  '/profile/notifications',
  // '/admin/incidents' は一覧・詳細・ステータス遷移・相関ルールをすべて実 API に
  // 結線したため除外した（相関ルール表が空なのは API 不在ではなく DB にルールが
  // 0 件なだけ）。
  '/admin/cloud-siem',        // クエリ実行タブは実ログ検索エンジン準備中
  '/admin/incident-patterns', // 分析実行(相関エンジン)は準備中
])

export default function BackendPendingBanner() {
  const pathname = usePathname()
  if (!pathname) return null

  const full = BACKEND_PENDING_ROUTES.has(pathname)
  const partial = !full && PARTIAL_PENDING_ROUTES.has(pathname)
  if (!full && !partial) return null

  return (
    <div className="bg-amber-500/10 border-b border-amber-500/30 px-4 py-2 flex items-center gap-2">
      <Construction className="w-4 h-4 text-amber-400 flex-shrink-0" />
      <p className="text-xs text-amber-300">
        {full
          ? 'この画面のバックエンドは準備中です。データの表示・保存はまだ行われません（実装後に自動的に有効になります）。'
          : 'この画面の一部機能はバックエンド準備中のため、表示・保存されない項目があります。'}
      </p>
    </div>
  )
}

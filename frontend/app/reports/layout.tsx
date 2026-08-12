'use client'

import { usePathname } from 'next/navigation'
import { PlanGate } from '@/components/PlanGate'
import { Feature } from '@/lib/usePlan'

// Gate every /reports/* page behind PlanGate(Reports) — Free plan
// excludes reports per planFeatures in server/internal/license/manager.go,
// and the server router enforces FeatureReports on /reports/* since v1.3.5.
// A Free tenant hitting any report page should see the same "Liteプランが
// 必要です" upgrade prompt the admin MDM pages use for Lite tenants.
//
// Exception: /reports/ops-report backs the home dashboard summary tile
// (alert counts, fleet health) that Free tenants need to render. It's a
// "dashboard view" not a "downloadable report", and the server router
// intentionally leaves it ungated.
export default function ReportsLayout({ children }: { children: React.ReactNode }) {
  const pathname = usePathname()

  if (pathname === '/reports/ops-report') {
    return <>{children}</>
  }

  return <PlanGate feature={Feature.Reports}>{children}</PlanGate>
}

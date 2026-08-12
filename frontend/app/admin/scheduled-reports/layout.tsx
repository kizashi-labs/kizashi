'use client'

import { PlanGate } from '@/components/PlanGate'
import { Feature } from '@/lib/usePlan'

// Admin scheduled-reports backs /admin/reports/schedules/* on the server,
// which is gated by FeatureReports since v1.3.5. Mirror that gate in the
// UI so a Free tenant sees the "Liteプランが必要です" prompt instead of
// an empty scheduler that can't actually create schedules.
export default function ScheduledReportsLayout({ children }: { children: React.ReactNode }) {
  return <PlanGate feature={Feature.Reports}>{children}</PlanGate>
}

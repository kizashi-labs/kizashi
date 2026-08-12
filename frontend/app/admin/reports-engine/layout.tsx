'use client'

import { PlanGate } from '@/components/PlanGate'
import { Feature } from '@/lib/usePlan'

// The admin report generator backs /admin/reports/* on the server, which
// is gated by FeatureReports since v1.3.5. Mirror that gate in the UI so
// a Free tenant who somehow navigates here sees the "Liteプランが必要
// です" prompt instead of an empty page that silently fails on every API
// call.
export default function ReportsEngineLayout({ children }: { children: React.ReactNode }) {
  return <PlanGate feature={Feature.Reports}>{children}</PlanGate>
}

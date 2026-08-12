'use client'

import { ReactNode } from 'react'
import { useRouter } from 'next/navigation'
import { Lock } from 'lucide-react'
import { usePlan, FeatureKey } from '@/lib/usePlan'

interface PlanGateProps {
  /** The feature that must be licensed to render children */
  feature: FeatureKey
  /** Content shown when feature is available */
  children: ReactNode
  /**
   * What to render when the feature is not available.
   * Defaults to an upgrade prompt card.
   */
  fallback?: ReactNode
}

/**
 * PlanGate hides premium features behind a plan check.
 *
 * Usage:
 * ```tsx
 * <PlanGate feature={Feature.AIInvestigation}>
 *   <AIPanel />
 * </PlanGate>
 * ```
 */
export function PlanGate({ feature, children, fallback }: PlanGateProps) {
  const { hasFeature, isLoading } = usePlan()

  if (isLoading) return null

  if (hasFeature(feature)) return <>{children}</>

  if (fallback !== undefined) return <>{fallback}</>

  return <UpgradePrompt feature={feature} />
}

// Plan labels for upgrade message. Keep in sync with requiredPlanFor in
// server/internal/middleware/plan_gate.go — if a feature here claims Starter
// but the server returns a different required_plan in the 402 body, the
// upgrade prompt will tell the user to buy a plan that won't unlock the
// feature.
const featurePlanLabel: Record<string, string> = {
  reports:          'Lite',          // Free excluded; Lite+ has reports
  mdm:              'Starter',       // Lite excluded; Starter+ has MDM
  ai_investigation: 'Professional',
  siem_integration: 'Professional',
  playbooks:        'Professional',
  threat_intel:     'Professional',
  yara:             'Professional',
  ml_detection:     'Professional',
  threat_hunting:   'Professional',
  multi_tenant:     'Enterprise',
  compliance:       'Enterprise',
  api_access:       'Enterprise',
  xdr:              'Enterprise',
  deception:        'Enterprise',
  forensics:        'Enterprise',
  soar:             'Enterprise',
}

function UpgradePrompt({ feature }: { feature: FeatureKey }) {
  const plan = featurePlanLabel[feature] ?? 'Enterprise'
  const router = useRouter()
  return (
    <div className="flex flex-col items-center justify-center rounded-lg border border-dashed border-slate-700 bg-slate-900/50 p-10 text-center">
      <Lock className="mb-3 h-8 w-8 text-slate-500" />
      <p className="mb-1 text-sm font-semibold text-slate-300">
        {plan}プランが必要です
      </p>
      <p className="mb-4 text-xs text-slate-500">
        この機能は{plan}プラン以上でご利用いただけます
      </p>
      <button
        onClick={() => router.push('/admin/license')}
        className="rounded-md bg-blue-600 px-4 py-2 text-xs font-medium text-white hover:bg-blue-500"
      >
        プランをアップグレード
      </button>
    </div>
  )
}

'use client'

import { useEffect } from 'react'
import { useRouter, usePathname } from 'next/navigation'
import { useAuth } from '@/lib/auth'
import { ClientOnly } from '@/components/ClientOnly'
import { usePlan, FeatureKey } from '@/lib/usePlan'
import { Lock } from 'lucide-react'

// ── Route → Feature mapping ────────────────────────────────────
// Routes listed here require the specified feature to be included
// in the current license plan. Pages already using <PlanGate> inline
// are included here too (double-gate is harmless — the layout gate
// fires first and prevents the page from rendering at all).

const routeFeatureMap: Record<string, FeatureKey> = {
  // AI / ML
  '/admin/ai-assistant':          'ai_investigation',
  '/admin/ai-triage':             'ai_investigation',
  '/admin/ai-investigation':      'ai_investigation',
  '/admin/ai-usage':              'ai_investigation',
  '/admin/predictive-analytics':  'ai_investigation',
  '/admin/ml-analytics':          'ml_detection',

  // Threat Intelligence
  '/admin/threat-intelligence':   'threat_intel',
  '/admin/threat-map':            'threat_intel',
  '/admin/dark-web':              'threat_intel',
  '/admin/taxii':                 'threat_intel',
  '/admin/tip-integration':       'threat_intel',
  '/admin/feed-analytics':        'threat_intel',

  // SIEM
  '/admin/siem-integration':      'siem_integration',
  '/admin/siem-query-builder':    'siem_integration',

  // Playbooks / SOAR
  '/admin/incident-playbooks':    'playbooks',
  '/admin/playbooks':             'playbooks',
  '/admin/soar':                  'soar',
  '/admin/autonomous-response':   'soar',
  '/admin/integrations/soar':     'soar',

  // Compliance
  '/admin/compliance-auto':       'compliance',
  '/admin/compliance-evidence':   'compliance',
  '/admin/compliance-workflows':  'compliance',
  '/admin/audit-export':          'compliance',
  '/admin/reports-engine':        'compliance',
  '/admin/maturity-model':        'compliance',

  // XDR / Deception / Forensics
  '/admin/xdr':                   'xdr',
  '/admin/digital-forensics':     'forensics',
  '/admin/deception':             'deception',
  '/admin/honeypots':             'deception',
  '/admin/honeynet':              'deception',

  // Multi-tenant / API
  '/admin/organizations':         'multi_tenant',
  '/admin/tenants':               'multi_tenant',
  '/admin/api-keys':              'api_access',
  '/admin/service-accounts':      'api_access',
  '/admin/oauth2-clients':        'api_access',

  // Threat Hunting / YARA
  '/admin/threat-hunting/query-builder': 'threat_hunting',
  '/admin/yara-rules':            'yara',
}

// Feature → required plan label (for upgrade prompt)
const featurePlanLabel: Record<string, string> = {
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

function FeatureGate({ children }: { children: React.ReactNode }) {
  const pathname = usePathname()
  const router = useRouter()
  const { hasFeature, isLoading } = usePlan()

  const requiredFeature = routeFeatureMap[pathname]

  // No feature requirement for this route
  if (!requiredFeature) return <>{children}</>

  // While loading, show children optimistically to avoid blank/spinner.
  // hasFeature returns true while loading (optimistic).
  if (hasFeature(requiredFeature)) return <>{children}</>

  // Feature locked — show upgrade prompt
  const plan = featurePlanLabel[requiredFeature] ?? 'Enterprise'
  return (
    <div className="min-h-screen bg-zinc-950 flex items-center justify-center p-6">
      <div className="flex flex-col items-center justify-center rounded-xl border border-dashed border-zinc-700 bg-zinc-900/50 p-14 text-center max-w-md">
        <Lock className="mb-4 h-10 w-10 text-zinc-500" />
        <p className="mb-2 text-lg font-semibold text-zinc-200">
          {plan}プランが必要です
        </p>
        <p className="mb-6 text-sm text-zinc-500">
          この機能は{plan}プラン以上でご利用いただけます。
          プランをアップグレードしてすべての機能をご活用ください。
        </p>
        <button
          onClick={() => router.push('/admin/license')}
          className="rounded-lg bg-blue-600 px-6 py-2.5 text-sm font-medium text-white hover:bg-blue-500 transition-colors"
        >
          プランをアップグレード
        </button>
      </div>
    </div>
  )
}

function AdminGuard({ children }: { children: React.ReactNode }) {
  const { user, isLoading } = useAuth()
  const router = useRouter()
  const pathname = usePathname()

  const isUnauthorizedPage = pathname === '/admin/unauthorized'

  useEffect(() => {
    if (isLoading) return
    if (isUnauthorizedPage) return
    if (!user) {
      router.replace('/login')
      return
    }
    if (user.role !== 'admin') {
      router.replace('/admin/unauthorized')
    }
  }, [user, isLoading, router, isUnauthorizedPage])

  if (isUnauthorizedPage) return <>{children}</>
  if (isLoading) return null
  if (!user || user.role !== 'admin') return null

  return <FeatureGate>{children}</FeatureGate>
}

export default function AdminLayout({ children }: { children: React.ReactNode }) {
  return (
    <ClientOnly>
      <AdminGuard>{children}</AdminGuard>
    </ClientOnly>
  )
}

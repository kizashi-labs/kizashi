'use client'

import React from 'react'
import { useRouter } from 'next/navigation'
import { Lock } from 'lucide-react'
import { usePlan, Feature } from '@/lib/usePlan'

// Forensics (/forensics, /forensics/network, /forensics/memory, /forensics/timeline,
// /forensics/artifacts) is an Enterprise feature. These pages live outside
// /admin, so the admin FeatureGate did not cover them — the sidebar showed a 🔒
// but the pages still rendered. This layout gates the whole /forensics subtree
// so a locked plan sees an upgrade prompt instead of the page content.
export default function ForensicsLayout({ children }: { children: React.ReactNode }) {
  const router = useRouter()
  const { hasFeature } = usePlan()

  // hasFeature returns true while the plan is still loading (optimistic), so we
  // don't flash the upgrade screen before the real plan is known.
  if (hasFeature(Feature.Forensics)) return <>{children}</>

  return (
    <div className="min-h-screen bg-zinc-950 flex items-center justify-center p-6">
      <div className="flex flex-col items-center justify-center rounded-xl border border-dashed border-zinc-700 bg-zinc-900/50 p-14 text-center max-w-md">
        <Lock className="mb-4 h-10 w-10 text-zinc-500" />
        <p className="mb-2 text-lg font-semibold text-zinc-200">Enterpriseプランが必要です</p>
        <p className="mb-6 text-sm text-zinc-500">
          デジタルフォレンジクスはEnterpriseプラン以上でご利用いただけます。
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

'use client'

import React from 'react'
import { useRouter } from 'next/navigation'
import { Lock } from 'lucide-react'
import { usePlan, Feature } from '@/lib/usePlan'

// /settings/siem is gated behind the siem_integration feature (Professional+).
// Like /forensics it lives outside /admin, so the admin FeatureGate didn't cover
// it — the sidebar showed a 🔒 but the page still rendered. Gate it here.
export default function SiemSettingsLayout({ children }: { children: React.ReactNode }) {
  const router = useRouter()
  const { hasFeature } = usePlan()

  if (hasFeature(Feature.SIEM)) return <>{children}</>

  return (
    <div className="min-h-screen bg-zinc-950 flex items-center justify-center p-6">
      <div className="flex flex-col items-center justify-center rounded-xl border border-dashed border-zinc-700 bg-zinc-900/50 p-14 text-center max-w-md">
        <Lock className="mb-4 h-10 w-10 text-zinc-500" />
        <p className="mb-2 text-lg font-semibold text-zinc-200">Professionalプランが必要です</p>
        <p className="mb-6 text-sm text-zinc-500">
          SIEM連携はProfessionalプラン以上でご利用いただけます。
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

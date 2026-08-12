'use client'

import React from 'react'
import { PlanGate } from '@/components/PlanGate'
import { Feature } from '@/lib/usePlan'

// YARA rules (/yara) is a Professional feature gated server-side
// (RequireFeature(FeatureYARA), HTTP 402). It lives outside /admin so the admin
// routeFeatureMap did not cover it and the page swallowed the 402 into an empty
// list. Gate the subtree so a locked plan sees the upgrade prompt.
export default function YaraLayout({ children }: { children: React.ReactNode }) {
  return <PlanGate feature={Feature.YARA}>{children}</PlanGate>
}

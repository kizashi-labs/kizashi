'use client'

import React from 'react'
import { PlanGate } from '@/components/PlanGate'
import { Feature } from '@/lib/usePlan'

// Threat Hunting (/threat-hunting and its sub-pages) is a Professional feature
// gated server-side (RequireFeature(FeatureThreatHunting), HTTP 402). These pages
// live outside /admin, so the admin routeFeatureMap did not cover them and the
// page silently swallowed the 402 into an empty table. Gate the whole subtree so
// a locked plan sees the upgrade prompt instead of a misleading empty view.
export default function ThreatHuntingLayout({ children }: { children: React.ReactNode }) {
  return <PlanGate feature={Feature.ThreatHunting}>{children}</PlanGate>
}

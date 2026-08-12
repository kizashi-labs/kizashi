'use client'

import { useEffect } from 'react'
import { usePWA } from '@/lib/usePWA'
import { initVitals } from '@/lib/vitals'

export function PWAInit() {
  // Registers the service worker and initialises Web Vitals collection.
  usePWA()
  useEffect(() => { initVitals() }, [])
  return null
}

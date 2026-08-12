'use client'

// ── Web Vitals collector ────────────────────────────────────────
// Measures Core Web Vitals (LCP, FID/INP, CLS, TTFB, FCP) and
// stores them in sessionStorage for the performance dashboard.

export interface VitalEntry {
  name: string
  value: number
  rating: 'good' | 'needs-improvement' | 'poor'
  delta: number
  id: string
  navigationType: string
  timestamp: number
}

const STORAGE_KEY = 'edr_web_vitals'
const MAX_ENTRIES = 100

// Thresholds based on Google's Core Web Vitals
const THRESHOLDS: Record<string, [number, number]> = {
  LCP:  [2500, 4000],   // ms
  FID:  [100,  300],    // ms
  INP:  [200,  500],    // ms
  CLS:  [0.1,  0.25],   // score
  TTFB: [800,  1800],   // ms
  FCP:  [1800, 3000],   // ms
}

function getRating(name: string, value: number): VitalEntry['rating'] {
  const t = THRESHOLDS[name]
  if (!t) return 'good'
  if (value <= t[0]) return 'good'
  if (value <= t[1]) return 'needs-improvement'
  return 'poor'
}

function saveVital(entry: VitalEntry) {
  if (typeof window === 'undefined') return
  try {
    const raw = sessionStorage.getItem(STORAGE_KEY)
    const entries: VitalEntry[] = raw ? JSON.parse(raw) : []
    entries.push(entry)
    // Keep only last MAX_ENTRIES
    if (entries.length > MAX_ENTRIES) entries.splice(0, entries.length - MAX_ENTRIES)
    sessionStorage.setItem(STORAGE_KEY, JSON.stringify(entries))
    // Dispatch event for live dashboard updates
    window.dispatchEvent(new CustomEvent('edr:vital', { detail: entry }))
  } catch {
    // sessionStorage might be unavailable
  }
}

export function getStoredVitals(): VitalEntry[] {
  if (typeof window === 'undefined') return []
  try {
    const raw = sessionStorage.getItem(STORAGE_KEY)
    return raw ? JSON.parse(raw) : []
  } catch {
    return []
  }
}

export function clearStoredVitals() {
  if (typeof window === 'undefined') return
  sessionStorage.removeItem(STORAGE_KEY)
}

// ── Navigation timing ───────────────────────────────────────────
function collectNavigationTiming() {
  if (typeof window === 'undefined' || !window.performance) return
  const nav = performance.getEntriesByType('navigation')[0] as PerformanceNavigationTiming | undefined
  if (!nav) return

  const ttfb = nav.responseStart - nav.requestStart
  saveVital({
    name: 'TTFB',
    value: ttfb,
    rating: getRating('TTFB', ttfb),
    delta: ttfb,
    id: 'nav-ttfb',
    navigationType: nav.type,
    timestamp: Date.now(),
  })
}

// ── PerformanceObserver-based metrics ──────────────────────────
function observeLCP() {
  if (typeof window === 'undefined' || !('PerformanceObserver' in window)) return
  try {
    const obs = new PerformanceObserver((list) => {
      const entries = list.getEntries()
      const last = entries[entries.length - 1] as PerformanceEntry & { startTime: number }
      const value = last.startTime
      saveVital({
        name: 'LCP',
        value,
        rating: getRating('LCP', value),
        delta: value,
        id: 'lcp-' + Date.now(),
        navigationType: 'navigate',
        timestamp: Date.now(),
      })
    })
    obs.observe({ type: 'largest-contentful-paint', buffered: true })
  } catch { /* not supported */ }
}

function observeCLS() {
  if (typeof window === 'undefined' || !('PerformanceObserver' in window)) return
  let clsValue = 0
  try {
    const obs = new PerformanceObserver((list) => {
      for (const entry of list.getEntries()) {
        const e = entry as PerformanceEntry & { hadRecentInput: boolean; value: number }
        if (!e.hadRecentInput) clsValue += e.value
      }
      saveVital({
        name: 'CLS',
        value: clsValue,
        rating: getRating('CLS', clsValue),
        delta: clsValue,
        id: 'cls-' + Date.now(),
        navigationType: 'navigate',
        timestamp: Date.now(),
      })
    })
    obs.observe({ type: 'layout-shift', buffered: true })
  } catch { /* not supported */ }
}

function observeFCP() {
  if (typeof window === 'undefined' || !('PerformanceObserver' in window)) return
  try {
    const obs = new PerformanceObserver((list) => {
      for (const entry of list.getEntries()) {
        if (entry.name === 'first-contentful-paint') {
          const value = entry.startTime
          saveVital({
            name: 'FCP',
            value,
            rating: getRating('FCP', value),
            delta: value,
            id: 'fcp-' + Date.now(),
            navigationType: 'navigate',
            timestamp: Date.now(),
          })
          obs.disconnect()
        }
      }
    })
    obs.observe({ type: 'paint', buffered: true })
  } catch { /* not supported */ }
}

function observeINP() {
  if (typeof window === 'undefined' || !('PerformanceObserver' in window)) return
  try {
    const obs = new PerformanceObserver((list) => {
      for (const entry of list.getEntries()) {
        const e = entry as PerformanceEntry & { processingStart: number; startTime: number; duration: number }
        const value = e.processingStart - e.startTime
        saveVital({
          name: 'INP',
          value,
          rating: getRating('INP', value),
          delta: value,
          id: 'inp-' + Date.now(),
          navigationType: 'navigate',
          timestamp: Date.now(),
        })
      }
    })
    obs.observe({ type: 'event', buffered: true } as PerformanceObserverInit)
  } catch { /* not supported */ }
}

// ── Initialize all observers ─────────────────────────────────────
export function initVitals() {
  if (typeof window === 'undefined') return
  // Collect after page load
  if (document.readyState === 'complete') {
    collectNavigationTiming()
  } else {
    window.addEventListener('load', collectNavigationTiming, { once: true })
  }
  observeLCP()
  observeCLS()
  observeFCP()
  observeINP()
}

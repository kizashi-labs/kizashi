'use client'

import { useEffect, useState } from 'react'

interface BeforeInstallPromptEvent extends Event {
  prompt(): Promise<void>
  userChoice: Promise<{ outcome: 'accepted' | 'dismissed' }>
}

export function usePWA() {
  const [installPrompt, setInstallPrompt] = useState<BeforeInstallPromptEvent | null>(null)
  const [isInstalled, setIsInstalled] = useState(false)
  const [swRegistered, setSwRegistered] = useState(false)
  const [isIOS, setIsIOS] = useState(false)

  useEffect(() => {
    // Register service worker
    if ('serviceWorker' in navigator) {
      navigator.serviceWorker
        .register('/sw.js', { scope: '/' })
        .then((reg) => {
          setSwRegistered(true)
          console.info('[PWA] Service worker registered', reg.scope)
        })
        .catch((err) => console.warn('[PWA] SW registration failed', err))
    }

    // Detect if already installed (standalone display mode, or iOS Safari flag)
    const iosStandalone = (window.navigator as unknown as { standalone?: boolean }).standalone === true
    if (window.matchMedia('(display-mode: standalone)').matches || iosStandalone) {
      setIsInstalled(true)
    }

    // iOS detection — Safari does not support beforeinstallprompt, needs manual install
    const ua = window.navigator.userAgent
    const iosLike = /iPad|iPhone|iPod/.test(ua) || (ua.includes('Mac') && 'ontouchend' in document)
    setIsIOS(iosLike)

    // Capture install prompt
    const handler = (e: Event) => {
      e.preventDefault()
      setInstallPrompt(e as BeforeInstallPromptEvent)
    }
    window.addEventListener('beforeinstallprompt', handler)

    // Detect successful install
    window.addEventListener('appinstalled', () => {
      setIsInstalled(true)
      setInstallPrompt(null)
    })

    return () => window.removeEventListener('beforeinstallprompt', handler)
  }, [])

  const install = async () => {
    if (!installPrompt) {
      console.warn('[PWA] install() called but no prompt available')
      return false
    }
    const withTimeout = <T,>(p: Promise<T>, ms: number, label: string): Promise<T> =>
      Promise.race([
        p,
        new Promise<T>((_, reject) =>
          setTimeout(() => reject(new Error(`[PWA] ${label} timed out after ${ms}ms`)), ms)
        ),
      ])
    try {
      console.info('[PWA] calling installPrompt.prompt()')
      await withTimeout(installPrompt.prompt(), 8000, 'prompt()')
      console.info('[PWA] waiting for userChoice')
      const { outcome } = await withTimeout(installPrompt.userChoice, 60000, 'userChoice')
      console.info('[PWA] userChoice outcome:', outcome)
      if (outcome === 'accepted') {
        setIsInstalled(true)
      }
      setInstallPrompt(null)
      return outcome === 'accepted'
    } catch (err) {
      console.warn('[PWA] install() failed', err)
      setInstallPrompt(null)
      return false
    }
  }

  return { installPrompt: !!installPrompt, isInstalled, swRegistered, install, isIOS }
}

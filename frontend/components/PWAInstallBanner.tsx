'use client'

import { useState, useEffect } from 'react'
import { usePWA } from '@/lib/usePWA'
import { Download, X, Shield, Share } from 'lucide-react'

const DISMISSED_KEY = 'edr_pwa_banner_dismissed'
const IOS_DISMISSED_KEY = 'edr_pwa_ios_banner_dismissed'

export function PWAInstallBanner() {
  const { installPrompt, isInstalled, install, isIOS } = usePWA()
  const [visible, setVisible] = useState(false)
  const [iosVisible, setIosVisible] = useState(false)
  const [installing, setInstalling] = useState(false)

  // Android / desktop Chrome — native install prompt flow
  useEffect(() => {
    if (!installPrompt || isInstalled) return
    const dismissed = sessionStorage.getItem(DISMISSED_KEY)
    if (!dismissed) {
      const t = setTimeout(() => setVisible(true), 3000)
      return () => clearTimeout(t)
    }
  }, [installPrompt, isInstalled])

  // iOS Safari — no install API, show manual instructions (persist dismiss via localStorage)
  useEffect(() => {
    if (!isIOS || isInstalled) return
    if (localStorage.getItem(IOS_DISMISSED_KEY)) return
    const t = setTimeout(() => setIosVisible(true), 3000)
    return () => clearTimeout(t)
  }, [isIOS, isInstalled])

  const handleInstall = async () => {
    setInstalling(true)
    try {
      const accepted = await install()
      if (accepted) setVisible(false)
      else setVisible(false) // prompt unavailable/dismissed — don't keep retrying
    } finally {
      setInstalling(false)
    }
  }

  const handleDismiss = () => {
    setVisible(false)
    sessionStorage.setItem(DISMISSED_KEY, '1')
  }

  const handleIosDismiss = () => {
    setIosVisible(false)
    localStorage.setItem(IOS_DISMISSED_KEY, '1')
  }

  // iOS manual install guide (Safari share menu → "Add to Home Screen")
  if (iosVisible) {
    return (
      <div className="fixed bottom-20 left-4 right-4 md:bottom-4 md:left-4 md:right-auto md:max-w-sm z-[150] safe-bottom">
        <div className="bg-[#0a1628] border border-[#1e2d42] rounded-xl shadow-2xl p-4">
          <div className="flex items-start gap-3">
            <div className="w-10 h-10 bg-[#1a6bff]/10 rounded-lg flex items-center justify-center flex-shrink-0">
              <Share className="w-5 h-5 text-[#1a6bff]" />
            </div>
            <div className="flex-1 min-w-0">
              <p className="text-sm font-semibold text-white mb-1">ホーム画面に追加</p>
              <p className="text-xs text-[#7d92b0] leading-relaxed">
                Safari下部の <Share className="inline w-3 h-3 align-[-2px]" /> 共有ボタン
                →「ホーム画面に追加」でフルスクリーンアプリとしてご利用いただけます
              </p>
              <button
                onClick={handleIosDismiss}
                className="mt-3 text-xs text-[#3d5068] hover:text-[#7d92b0] transition-colors"
              >
                了解しました
              </button>
            </div>
            <button
              onClick={handleIosDismiss}
              className="w-6 h-6 flex items-center justify-center text-[#3d5068] hover:text-white transition-colors flex-shrink-0"
              aria-label="閉じる"
            >
              <X className="w-3.5 h-3.5" />
            </button>
          </div>
        </div>
      </div>
    )
  }

  if (!visible) return null

  return (
    <div className="fixed bottom-20 left-4 right-4 md:bottom-4 md:left-4 md:right-auto md:max-w-xs z-[150] safe-bottom">
      <div className="bg-[#0a1628] border border-[#1e2d42] rounded-xl shadow-2xl p-4">
        <div className="flex items-start gap-3">
          <div className="w-10 h-10 bg-[#e8002d]/10 rounded-lg flex items-center justify-center flex-shrink-0">
            <Shield className="w-5 h-5 text-[#e8002d]" />
          </div>
          <div className="flex-1 min-w-0">
            <p className="text-sm font-semibold text-white mb-0.5">アプリをインストール</p>
            <p className="text-xs text-[#7d92b0] leading-relaxed">
              Kizashiをホーム画面に追加してすぐにアクセス
            </p>
            <div className="flex gap-2 mt-3">
              <button
                onClick={handleInstall}
                disabled={installing}
                className="flex items-center gap-1.5 bg-[#e8002d] hover:bg-[#c4001f] disabled:opacity-60 text-white text-xs font-semibold px-3 py-1.5 rounded-lg transition-colors"
              >
                <Download className="w-3.5 h-3.5" />
                {installing ? 'インストール中...' : 'インストール'}
              </button>
              <button
                onClick={handleDismiss}
                className="text-xs text-[#3d5068] hover:text-[#7d92b0] px-2 py-1.5 transition-colors"
              >
                後で
              </button>
            </div>
          </div>
          <button
            onClick={handleDismiss}
            className="w-6 h-6 flex items-center justify-center text-[#3d5068] hover:text-white transition-colors flex-shrink-0"
            aria-label="閉じる"
          >
            <X className="w-3.5 h-3.5" />
          </button>
        </div>
      </div>
    </div>
  )
}

import React from 'react'
import type { Metadata, Viewport } from 'next'
import './globals.css'
import { Providers } from './providers'
import { AppShell } from '@/components/layout/AppShell'
import { PWAInit } from '@/components/PWAInit'
import { APIErrorToast } from '@/components/notifications/APIErrorToast'
import { PWAInstallBanner } from '@/components/PWAInstallBanner'
import BackendPendingBanner from '@/components/layout/BackendPendingBanner'

export const metadata: Metadata = {
  title: 'Kizashi — エンドポイント保護プラットフォーム',
  description: 'エンドポイント検知・対応プラットフォーム',
  manifest: '/manifest.json',
  appleWebApp: {
    capable: true,
    statusBarStyle: 'black-translucent',
    title: 'Kizashi',
  },
}

export const viewport: Viewport = {
  themeColor: '#060d1a',
  width: 'device-width',
  initialScale: 1,
  viewportFit: 'cover',
}

export default function RootLayout({
  children,
}: {
  children: React.ReactNode
}) {
  return (
    <html lang="ja">
      <head>
        <link rel="apple-touch-icon" href="/icons/icon.svg" />
        <link rel="icon" type="image/svg+xml" href="/icons/icon.svg" />
      </head>
      <body className="bg-falcon-bg text-falcon-text antialiased">
        <Providers>
          <AppShell>
            <BackendPendingBanner />
            {children}
          </AppShell>
        </Providers>
        <PWAInit />
        <APIErrorToast />
        <PWAInstallBanner />
      </body>
    </html>
  )
}

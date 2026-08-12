'use client'

import { useEffect, useState, Suspense } from 'react'
import { useRouter, useSearchParams } from 'next/navigation'
import { Shield } from 'lucide-react'

/**
 * SSO Intermediate Page — shown after the IdP redirects the browser back.
 *
 * Flow (stub):
 *  1. Browser lands here after IdP redirect (GET /auth/sso?provider=<id>)
 *     OR after the IdP POST to the ACS endpoint which then redirects here.
 *  2. This page calls POST /api/v1/auth/sso/callback to exchange the
 *     SAMLResponse (or OIDC code) for a local JWT.
 *  3. On success, store the JWT and redirect to /dashboard.
 *
 * Production:
 *  - For SAML: the IdP POSTs a SAMLResponse to the ACS URL. The server
 *    verifies the XML signature (crewjam/saml) and issues a JWT, then
 *    redirects here with the token in a short-lived cookie or query param.
 *  - For OIDC: redirect to the IdP authorization endpoint with a `state`
 *    param; handle the code callback on the server; issue a JWT here.
 */
function SSOPageInner() {
  const router = useRouter()
  const searchParams = useSearchParams()
  const [status, setStatus] = useState<'loading' | 'success' | 'error'>('loading')
  const [errorMessage, setErrorMessage] = useState('')

  useEffect(() => {
    const provider = searchParams.get('provider')
    const token = searchParams.get('token') // server may pass JWT directly via redirect

    // If the server already embedded the token in the redirect query string,
    // store it immediately without another round-trip.
    if (token) {
      localStorage.setItem('auth_token', token)
      setStatus('success')
      setTimeout(() => router.push('/dashboard'), 800)
      return
    }

    // Otherwise call the stub callback endpoint.
    // In production this would send the SAMLResponse/code from the IdP.
    const body = provider ? JSON.stringify({ provider_id: provider }) : '{}'

    fetch('/api/v1/auth/sso/callback', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body,
    })
      .then(async res => {
        const data = await res.json()
        if (!res.ok) throw new Error(data.error ?? 'SSO認証に失敗しました')
        if (!data.token) throw new Error('トークンが返されませんでした')
        localStorage.setItem('auth_token', data.token)
        setStatus('success')
        setTimeout(() => router.push('/dashboard'), 800)
      })
      .catch(err => {
        setErrorMessage(err instanceof Error ? err.message : 'SSO認証に失敗しました')
        setStatus('error')
      })
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [])

  return (
    <div className="min-h-screen flex items-center justify-center bg-[#080c14]">
      <div className="flex flex-col items-center gap-6 text-center max-w-sm px-4">
        {/* Logo */}
        <div className="w-16 h-16 rounded-xl bg-gradient-to-br from-[#e8002d] to-[#a80020]
                        flex items-center justify-center shadow-falcon-glow-red">
          <Shield className="w-8 h-8 text-white" strokeWidth={1.5} />
        </div>

        {status === 'loading' && (
          <>
            {/* Spinner */}
            <div className="w-10 h-10 border-2 border-[#1e2d42] border-t-[#4a9eff] rounded-full animate-spin" />
            <div>
              <p className="text-white font-semibold text-lg">SSO認証中...</p>
              <p className="text-[#7d92b0] text-sm mt-1">IDプロバイダーで認証を処理しています</p>
            </div>
          </>
        )}

        {status === 'success' && (
          <>
            <div className="w-10 h-10 rounded-full bg-green-500/20 flex items-center justify-center">
              <svg className="w-5 h-5 text-green-400" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M5 13l4 4L19 7" />
              </svg>
            </div>
            <div>
              <p className="text-white font-semibold text-lg">認証成功</p>
              <p className="text-[#7d92b0] text-sm mt-1">ダッシュボードにリダイレクトしています...</p>
            </div>
          </>
        )}

        {status === 'error' && (
          <>
            <div className="w-10 h-10 rounded-full bg-red-500/20 flex items-center justify-center">
              <svg className="w-5 h-5 text-red-400" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M6 18L18 6M6 6l12 12" />
              </svg>
            </div>
            <div>
              <p className="text-white font-semibold text-lg">認証に失敗しました</p>
              <p className="text-red-400 text-sm mt-1">{errorMessage}</p>
            </div>
            <button
              onClick={() => router.push('/login')}
              className="mt-2 text-[#4a9eff] hover:text-white text-sm underline transition-colors"
            >
              ← ログイン画面に戻る
            </button>
          </>
        )}

        {/* Footer note */}
        <p className="text-[#3d5068] text-[10px] font-mono tracking-wider mt-4">
          KIZASHI EDR · SSO · SECURED
        </p>
      </div>
    </div>
  )
}

export default function SSOPage() {
  return (
    <Suspense fallback={
      <div className="min-h-screen flex items-center justify-center bg-[#080c14]">
        <div className="w-10 h-10 border-2 border-[#1e2d42] border-t-[#4a9eff] rounded-full animate-spin" />
      </div>
    }>
      <SSOPageInner />
    </Suspense>
  )
}

'use client'

import { useEffect, useState } from 'react'
import Link from 'next/link'
import { Lock, ArrowLeft, Users, Mail } from 'lucide-react'

export default function UnauthorizedPage() {
  const [currentRole, setCurrentRole] = useState<string | null>(null)

  useEffect(() => {
    if (typeof window !== 'undefined') {
      try {
        const raw = localStorage.getItem('edr_user')
        if (raw) {
          const user = JSON.parse(raw) as { role?: string }
          setCurrentRole(user.role ?? null)
        }
      } catch {
        // ignore
      }
    }
  }, [])

  return (
    <div className="min-h-screen bg-zinc-950 flex items-center justify-center p-6">
      <div className="text-center max-w-md w-full">
        {/* Icon */}
        <div className="w-20 h-20 rounded-2xl bg-gradient-to-br from-yellow-600 to-yellow-800 flex items-center justify-center mx-auto mb-6 shadow-lg shadow-yellow-900/30">
          <Lock className="w-10 h-10 text-white" />
        </div>

        {/* Status code */}
        <p className="text-7xl font-black font-mono text-zinc-800 mb-4 tracking-tighter select-none">
          403
        </p>

        {/* Title & message */}
        <h1 className="text-2xl font-bold text-zinc-100 mb-3">Access Denied</h1>
        <p className="text-sm text-zinc-400 mb-5 leading-relaxed">
          You don&apos;t have permission to access this resource.
        </p>

        {/* Current role badge */}
        {currentRole && (
          <div className="inline-flex items-center gap-2 px-3 py-1.5 rounded-full bg-zinc-800 border border-zinc-700 text-xs text-zinc-400 mb-6">
            <span className="w-1.5 h-1.5 rounded-full bg-zinc-500" />
            Current role: <span className="font-mono text-zinc-300">{currentRole}</span>
          </div>
        )}
        {!currentRole && (
          <div className="inline-flex items-center gap-2 px-3 py-1.5 rounded-full bg-zinc-800 border border-zinc-700 text-xs text-zinc-400 mb-6">
            <span className="w-1.5 h-1.5 rounded-full bg-zinc-500" />
            Role: <span className="font-mono text-zinc-300">unknown</span>
          </div>
        )}

        {/* Actions */}
        <div className="flex flex-col sm:flex-row items-center justify-center gap-3 mb-8">
          <Link
            href="/admin/users"
            className="flex items-center gap-2 px-4 py-2.5 bg-red-600 hover:bg-red-500 text-white text-sm font-medium rounded-lg transition-colors w-full sm:w-auto justify-center"
          >
            <Users className="w-4 h-4" />
            Request Access
          </Link>
          <a
            href="mailto:admin@example.com?subject=Access%20Request"
            className="flex items-center gap-2 px-4 py-2.5 bg-zinc-800 hover:bg-zinc-700 border border-zinc-700 hover:border-zinc-600 text-zinc-300 hover:text-zinc-100 text-sm font-medium rounded-lg transition-colors w-full sm:w-auto justify-center"
          >
            <Mail className="w-4 h-4" />
            Email Admin
          </a>
        </div>

        {/* Go back */}
        <button
          onClick={() => window.history.back()}
          className="inline-flex items-center gap-2 text-sm text-zinc-500 hover:text-zinc-300 transition-colors"
        >
          <ArrowLeft className="w-4 h-4" />
          Go Back
        </button>
      </div>
    </div>
  )
}

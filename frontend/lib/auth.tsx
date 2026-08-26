'use client'

import { createContext, useContext, useEffect, useState, ReactNode } from 'react'
import { useRouter } from 'next/navigation'

interface AuthUser {
  id: string
  email: string
  full_name: string
  role: string
}

interface AuthContextType {
  user: AuthUser | null
  token: string | null
  login: (username: string, password: string) => Promise<{ mfaRequired: boolean; preAuthToken?: string }>
  verifyMFA: (preAuthToken: string, code: string) => Promise<void>
  logout: () => Promise<void>
  isLoading: boolean
}

const AuthContext = createContext<AuthContextType | null>(null)

export function AuthProvider({ children }: { children: ReactNode }) {
  const [user, setUser] = useState<AuthUser | null>(null)
  const [token, setToken] = useState<string | null>(null)
  const [isLoading, setIsLoading] = useState(true)
  const router = useRouter()

  useEffect(() => {
    const storedToken = localStorage.getItem('edr_token')
    const storedUser = localStorage.getItem('edr_user')
    if (storedToken && storedUser) {
      try {
        const parsedUser = JSON.parse(storedUser)
        setToken(storedToken)
        setUser(parsedUser)
      } catch {
        localStorage.removeItem('edr_token')
        localStorage.removeItem('edr_user')
      }
    }
    setIsLoading(false)
  }, [])

  const login = async (username: string, password: string): Promise<{ mfaRequired: boolean; preAuthToken?: string }> => {
    const res = await fetch('/api/v1/auth/login', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ username, password }),
    })
    if (!res.ok) {
      const err = await res.json().catch(() => ({}))
      throw new Error(err.error || 'ログインに失敗しました')
    }
    const data = await res.json()
    if (data.mfa_required) {
      return { mfaRequired: true, preAuthToken: data.pre_auth_token }
    }
    localStorage.setItem('edr_token', data.token)
    localStorage.setItem('edr_user', JSON.stringify(data.user))
    setToken(data.token)
    setUser(data.user)
    if (data.must_change_password) {
      router.push('/change-password')
    } else {
      router.push('/dashboard')
    }
    return { mfaRequired: false }
  }

  const verifyMFA = async (preAuthToken: string, code: string) => {
    const res = await fetch('/api/v1/auth/mfa/verify', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ pre_auth_token: preAuthToken, code }),
    })
    if (!res.ok) {
      const err = await res.json().catch(() => ({}))
      throw new Error(err.error || 'MFA認証に失敗しました')
    }
    const data = await res.json()
    localStorage.setItem('edr_token', data.token)
    if (data.user) {
      localStorage.setItem('edr_user', JSON.stringify(data.user))
      setUser(data.user)
    }
    setToken(data.token)
    router.push('/dashboard')
  }

  const logout = async () => {
    const t = localStorage.getItem('edr_token')
    if (t) {
      try {
        await fetch('/api/v1/auth/logout', {
          method: 'POST',
          headers: { Authorization: `Bearer ${t}` },
        })
      } catch {
        // ネットワークエラーでもローカルの状態はクリアする
      }
    }
    localStorage.removeItem('edr_token')
    localStorage.removeItem('edr_user')
    setToken(null)
    setUser(null)
    router.push('/login')
  }

  return (
    <AuthContext.Provider value={{ user, token, login, verifyMFA, logout, isLoading }}>
      {children}
    </AuthContext.Provider>
  )
}

export function useAuth() {
  const ctx = useContext(AuthContext)
  if (!ctx) throw new Error('useAuth must be used within AuthProvider')
  return ctx
}

/** Returns true when the current user may perform write operations (non-viewer). */
export function useCanWrite(): boolean {
  const { user } = useAuth()
  return !!user && user.role !== 'viewer'
}

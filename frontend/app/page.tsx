'use client'

import { useEffect } from 'react'
import { useRouter } from 'next/navigation'
import { useAuth } from '@/lib/auth'

export default function RootPage() {
  const router = useRouter()
  const { token, isLoading } = useAuth()

  useEffect(() => {
    if (isLoading) return
    if (token) {
      router.replace('/dashboard')
    } else {
      router.replace('/landing')
    }
  }, [token, isLoading, router])

  return null
}

'use client'

// `/agents/{id}` is preserved as a redirect to `/endpoints/{id}` — the
// canonical agent-detail route. The previous in-place implementation
// shipped stub action buttons whose confirm handler never invoked the
// underlying API, so users saw "実行済み" without any backend effect.
// Rather than maintaining two parallel detail pages, all navigation is
// funneled through the fully-wired endpoints route.

import { useEffect } from 'react'
import { useRouter, useParams } from 'next/navigation'

export default function AgentDetailRedirect() {
  const router = useRouter()
  const params = useParams()
  const id = params.id as string

  useEffect(() => {
    if (id) {
      router.replace(`/endpoints/${id}`)
    }
  }, [router, id])

  return <div className="min-h-screen bg-[#070d19]" />
}

'use client'

import { useState, useEffect, useRef } from 'react'
import { useRouter } from 'next/navigation'
import { useQuery, useQueryClient } from '@tanstack/react-query'
import { apiFetch } from '@/lib/api'
import { ChevronDown, Building2, Check } from 'lucide-react'

interface Tenant {
  id: string
  name: string
  slug: string
}

export function TenantSwitcher() {
  const router = useRouter()
  const queryClient = useQueryClient()
  const [open, setOpen] = useState(false)
  const [currentId, setCurrentId] = useState<string | null>(null)
  const ref = useRef<HTMLDivElement>(null)

  useEffect(() => {
    if (typeof window !== 'undefined') {
      setCurrentId(localStorage.getItem('edr_tenant_id'))
    }
  }, [])

  const { data, isLoading } = useQuery<{ tenants: Tenant[] }>({
    queryKey: ['admin-tenants-switcher'],
    queryFn: () => apiFetch('/api/v1/admin/tenants'),
    staleTime: 60_000,
    retry: false,
  })

  const tenants = data?.tenants ?? []
  const current = tenants.find(t => t.id === currentId) ?? tenants[0] ?? null

  // Close dropdown when clicking outside
  useEffect(() => {
    function handleClick(e: MouseEvent) {
      if (ref.current && !ref.current.contains(e.target as Node)) {
        setOpen(false)
      }
    }
    if (open) document.addEventListener('mousedown', handleClick)
    return () => document.removeEventListener('mousedown', handleClick)
  }, [open])

  function selectTenant(id: string) {
    localStorage.setItem('edr_tenant_id', id)
    setCurrentId(id)
    setOpen(false)
    // Invalidate all queries so data is re-fetched with the new tenant context
    queryClient.invalidateQueries()
    router.refresh()
  }

  return (
    <div className="px-3 pt-3 pb-1" ref={ref}>
      <button
        onClick={() => setOpen(v => !v)}
        className="w-full flex items-center gap-2 bg-[#070d19] border border-falcon-border rounded px-3 py-2
                   hover:border-falcon-muted/40 hover:bg-falcon-surface transition-all duration-150 group"
        title="テナントを切り替え"
        disabled={isLoading}
      >
        <Building2 className="w-3.5 h-3.5 shrink-0 text-falcon-subtle group-hover:text-falcon-muted transition-colors" />
        <div className="flex-1 min-w-0 text-left">
          <p className="text-xs font-medium text-falcon-text truncate leading-none">
            {isLoading ? '読み込み中...' : (current?.name ?? 'テナント選択')}
          </p>
          {current?.slug && (
            <p className="text-[9px] text-falcon-subtle mt-0.5 truncate uppercase tracking-wide">
              {current.slug}
            </p>
          )}
        </div>
        <ChevronDown
          className={`w-3 h-3 shrink-0 text-falcon-subtle transition-transform duration-150 ${open ? 'rotate-180' : ''}`}
        />
      </button>

      {open && tenants.length > 0 && (
        <div className="mt-1 bg-falcon-surface border border-falcon-border rounded-sm shadow-lg overflow-hidden z-50">
          {tenants.map(t => {
            const isSelected = t.id === (currentId ?? tenants[0]?.id)
            return (
              <button
                key={t.id}
                onClick={() => selectTenant(t.id)}
                className={`w-full flex items-center gap-2 px-3 py-2 text-left
                            transition-colors duration-100 hover:bg-falcon-hover
                            ${isSelected ? 'bg-falcon-active' : ''}`}
              >
                <Building2 className={`w-3.5 h-3.5 shrink-0 ${isSelected ? 'text-falcon-red' : 'text-falcon-subtle'}`} />
                <div className="flex-1 min-w-0">
                  <p className="text-xs font-medium text-falcon-text truncate">{t.name}</p>
                  <p className="text-[9px] text-falcon-subtle uppercase tracking-wide">{t.slug}</p>
                </div>
                {isSelected && (
                  <Check className="w-3 h-3 text-falcon-red shrink-0" />
                )}
              </button>
            )
          })}
        </div>
      )}
    </div>
  )
}

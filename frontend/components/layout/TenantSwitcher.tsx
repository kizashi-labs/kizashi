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
        className="w-full flex items-center gap-2 bg-[#070d19] border border-[#1e2d42] rounded px-3 py-2
                   hover:border-[#7d92b0]/40 hover:bg-[#0d1220] transition-all duration-150 group"
        title="テナントを切り替え"
        disabled={isLoading}
      >
        <Building2 className="w-3.5 h-3.5 flex-shrink-0 text-[#3d5068] group-hover:text-[#7d92b0] transition-colors" />
        <div className="flex-1 min-w-0 text-left">
          <p className="text-xs font-medium text-[#e2e8f4] truncate leading-none">
            {isLoading ? '読み込み中...' : (current?.name ?? 'テナント選択')}
          </p>
          {current?.slug && (
            <p className="text-[9px] text-[#3d5068] mt-0.5 truncate uppercase tracking-wide">
              {current.slug}
            </p>
          )}
        </div>
        <ChevronDown
          className={`w-3 h-3 flex-shrink-0 text-[#3d5068] transition-transform duration-150 ${open ? 'rotate-180' : ''}`}
        />
      </button>

      {open && tenants.length > 0 && (
        <div className="mt-1 bg-[#0d1220] border border-[#1e2d42] rounded shadow-lg overflow-hidden z-50">
          {tenants.map(t => {
            const isSelected = t.id === (currentId ?? tenants[0]?.id)
            return (
              <button
                key={t.id}
                onClick={() => selectTenant(t.id)}
                className={`w-full flex items-center gap-2 px-3 py-2 text-left
                            transition-colors duration-100 hover:bg-[#19253d]
                            ${isSelected ? 'bg-[#1d2f4a]' : ''}`}
              >
                <Building2 className={`w-3.5 h-3.5 flex-shrink-0 ${isSelected ? 'text-[#e8002d]' : 'text-[#3d5068]'}`} />
                <div className="flex-1 min-w-0">
                  <p className="text-xs font-medium text-[#e2e8f4] truncate">{t.name}</p>
                  <p className="text-[9px] text-[#3d5068] uppercase tracking-wide">{t.slug}</p>
                </div>
                {isSelected && (
                  <Check className="w-3 h-3 text-[#e8002d] flex-shrink-0" />
                )}
              </button>
            )
          })}
        </div>
      )}
    </div>
  )
}

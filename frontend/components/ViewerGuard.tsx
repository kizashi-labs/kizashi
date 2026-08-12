'use client'

import { ReactNode } from 'react'
import { useCanWrite } from '@/lib/auth'

interface ViewerGuardProps {
  /** Content to render only for non-viewer roles (admin / analyst). */
  children: ReactNode
  /** If true, render children as disabled instead of hiding them. */
  disable?: boolean
  /** Fallback content for viewer role. Defaults to nothing. */
  fallback?: ReactNode
}

/**
 * Conditionally renders children based on user role.
 * Viewer-role users see nothing (or the fallback) by default.
 *
 * Usage:
 *   <ViewerGuard><button onClick={handleDelete}>削除</button></ViewerGuard>
 *   <ViewerGuard disable><button ...>保存</button></ViewerGuard>
 */
export function ViewerGuard({ children, disable, fallback }: ViewerGuardProps) {
  const canWrite = useCanWrite()

  if (canWrite) return <>{children}</>

  if (disable) {
    return (
      <div className="opacity-40 pointer-events-none select-none" title="閲覧専用ロールのため操作できません">
        {children}
      </div>
    )
  }

  return fallback ? <>{fallback}</> : null
}

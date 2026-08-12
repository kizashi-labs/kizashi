const getToken = (): string | null =>
  typeof window !== 'undefined' ? localStorage.getItem('edr_token') : null

// ── Rate-limit toast (singleton) ────────────────────────────────
let _rateLimitToast: ((msg: string, retryAfter?: number) => void) | null = null

export function registerRateLimitHandler(fn: (msg: string, retryAfter?: number) => void) {
  _rateLimitToast = fn
}

function notifyRateLimit(retryAfter?: number) {
  const secs = retryAfter ?? 60
  const msg = `リクエストが制限されました。${secs}秒後に再試行してください。`
  if (_rateLimitToast) {
    _rateLimitToast(msg, secs)
  } else if (typeof window !== 'undefined') {
    console.warn('[API] Rate limited:', msg)
  }
}

// ── Core fetch with 401/429 handling ────────────────────────────
export async function apiFetch<T>(path: string, options?: RequestInit): Promise<T> {
  const token = getToken()

  const res = await fetch(path, {
    ...options,
    headers: {
      'Content-Type': 'application/json',
      ...(token ? { Authorization: `Bearer ${token}` } : {}),
      ...options?.headers,
    },
  })

  if (res.status === 401) {
    if (typeof window !== 'undefined') {
      localStorage.removeItem('edr_token')
      localStorage.removeItem('edr_user')
      window.location.href = '/login'
    }
    throw new Error('認証が必要です')
  }

  if (res.status === 429) {
    const retryAfter = parseInt(res.headers.get('Retry-After') ?? '60', 10)
    notifyRateLimit(retryAfter)
    const err = await res.json().catch(() => ({}))
    const apiError = new Error((err as { error?: string }).error || 'レート制限超過') as Error & { status: number; retryAfter: number }
    apiError.status = 429
    apiError.retryAfter = retryAfter
    throw apiError
  }

  if (res.status === 403) {
    const err = await res.json().catch(() => ({}))
    const apiError = new Error((err as { error?: string }).error || 'アクセス権限がありません') as Error & { status: number }
    apiError.status = 403
    throw apiError
  }

  if (!res.ok) {
    const err = await res.json().catch(() => ({}))
    const apiError = new Error((err as { error?: string }).error || `HTTP ${res.status}`) as Error & { status: number }
    apiError.status = res.status
    throw apiError
  }

  return res.json() as Promise<T>
}

// Common keys used by backend responses that wrap arrays
const ARRAY_KEYS = ['items', 'data', 'results', 'list', 'records', 'rows', 'unread', 'entries', 'events', 'policies', 'agents', 'groups', 'rules', 'alerts', 'assignments', 'profiles', 'commands', 'apps', 'integrations', 'devices', 'tokens', 'kpis', 'jobs', 'patches', 'backups']

/**
 * Like apiFetch but always returns an array.
 * If the API response is already an array, returns it as-is.
 * If it's an object, tries common wrapper keys (items, data, results, …).
 */
export async function apiFetchList<T>(path: string, options?: RequestInit): Promise<T[]> {
  const res = await apiFetch<unknown>(path, options)
  if (Array.isArray(res)) return res as T[]
  if (res && typeof res === 'object') {
    for (const key of ARRAY_KEYS) {
      const val = (res as Record<string, unknown>)[key]
      if (Array.isArray(val)) return val as T[]
    }
  }
  return []
}

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

// ── Server-failure toast ────────────────────────────────────────
//
// サーバ側は、読み取りに失敗したときに 200 と空のリストを返すのをやめ、
// 500 を返すようになりました。ただし画面の大半は useQuery のエラー状態を
// 見ておらず、data が undefined になると `?? []` / `?? 0` で 0件・0 を
// そのまま描画します。つまりサーバが正直になっても、運用担当の目には
// 以前と同じ「該当なし」が映ります。
//
// ここで一度だけ通知することで、どの画面でも「この数字は取得できていない」
// ことが分かります。ページ側のエラー表示に置き換わるまでの下支えです。
let _serverErrorToast: ((msg: string) => void) | null = null

export function registerServerErrorHandler(fn: (msg: string) => void) {
  _serverErrorToast = fn
}

// 同じ画面から10本のクエリが同時に失敗しても通知は1つ。
let _lastServerErrorAt = 0
const SERVER_ERROR_QUIET_MS = 5000

function notifyServerError(path: string) {
  const now = Date.now()
  if (now - _lastServerErrorAt < SERVER_ERROR_QUIET_MS) return
  _lastServerErrorAt = now
  const msg = `サーバからデータを取得できませんでした (${path})。表示されている件数は実際の値ではありません。`
  if (_serverErrorToast) {
    _serverErrorToast(msg)
  } else if (typeof window !== 'undefined') {
    console.warn('[API]', msg)
  }
}

// ── Core fetch with 401/429/5xx handling ────────────────────────
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
    // 501 は「この機能はまだ実装されていません」で、障害ではありません。
    // 再試行を促す通知を出すと、決して直らないものを何度も試させます。
    if (res.status >= 500 && res.status !== 501) {
      notifyServerError(path)
    }
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

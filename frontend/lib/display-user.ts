const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i

/**
 * Converts a raw user identifier (UUID, email, or display name) into a
 * human-readable string for display in tables and cards.
 *
 * Priority: display name > email local-part > truncated UUID > fallback
 */
export function displayUser(value: string | null | undefined, fallback = '—'): string {
  if (!value || value.trim() === '') return fallback
  if (UUID_RE.test(value.trim())) return value.slice(0, 8) + '…'
  if (value.includes('@')) return value.split('@')[0]
  return value
}

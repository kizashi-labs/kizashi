/**
 * USE_MOCK: true  → use mock data as fallback (local development)
 * USE_MOCK: false → show real API data only (production / AWS)
 *
 * Set NEXT_PUBLIC_USE_MOCK=true in .env.local for local development.
 */
export const USE_MOCK = process.env.NEXT_PUBLIC_USE_MOCK === 'true'

/**
 * Returns `mock` when USE_MOCK is true, otherwise `fallback`.
 * Keeps TypeScript types consistent.
 */
export function mockOr<T>(mock: T, fallback: T): T {
  return USE_MOCK ? mock : fallback
}

/**
 * Returns `mock` when USE_MOCK is true, otherwise an empty value of the same type.
 * Arrays → [], objects → {} cast to T.
 * Type-safe: TypeScript infers T from `mock`.
 */
export function m<T>(mock: T): T {
  if (!USE_MOCK) return (Array.isArray(mock) ? [] : {}) as T
  return mock
}

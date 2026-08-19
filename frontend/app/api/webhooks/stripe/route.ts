// ── Stripe Webhook handler (Next.js App Router) ───────────────────────────────
// Verifies the Stripe signature and forwards the event to the Go API.
// The Go API handles DB updates and broadcasts SSE events to connected clients.
//
// Required env: STRIPE_WEBHOOK_SECRET

import { NextRequest, NextResponse } from 'next/server'

const STRIPE_WEBHOOK_SECRET = process.env.STRIPE_WEBHOOK_SECRET ?? ''
const API_INTERNAL_URL = process.env.API_INTERNAL_URL ?? 'http://localhost:8080'

// Stripe signature verification (without the stripe-node SDK dependency)
async function verifyStripeSignature(
  payload: string,
  sigHeader: string,
  secret: string,
): Promise<boolean> {
  if (!secret || !sigHeader) return false

  const parts = Object.fromEntries(
    sigHeader.split(',').map(p => {
      const [k, v] = p.split('=')
      return [k, v]
    }),
  )
  const timestamp = parts['t']
  const signature = parts['v1']
  if (!timestamp || !signature) return false

  // Reject if timestamp is > 5 minutes old
  const ts = parseInt(timestamp, 10)
  if (Math.abs(Date.now() / 1000 - ts) > 300) return false

  const signedPayload = `${timestamp}.${payload}`
  const key = await crypto.subtle.importKey(
    'raw',
    new TextEncoder().encode(secret),
    { name: 'HMAC', hash: 'SHA-256' },
    false,
    ['sign'],
  )
  const mac = await crypto.subtle.sign('HMAC', key, new TextEncoder().encode(signedPayload))
  const expected = Array.from(new Uint8Array(mac))
    .map(b => b.toString(16).padStart(2, '0'))
    .join('')

  return expected === signature
}

export async function POST(req: NextRequest) {
  const sigHeader = req.headers.get('stripe-signature') ?? ''
  const body = await req.text()

  // Verify signature
  if (STRIPE_WEBHOOK_SECRET) {
    const valid = await verifyStripeSignature(body, sigHeader, STRIPE_WEBHOOK_SECRET)
    if (!valid) {
      return NextResponse.json({ error: 'Invalid signature' }, { status: 400 })
    }
  }

  let event: { type: string; data: { object: Record<string, unknown> } }
  try {
    event = JSON.parse(body)
  } catch {
    return NextResponse.json({ error: 'Invalid JSON' }, { status: 400 })
  }

  // Forward to Go API for DB update and SSE broadcast
  // fetch は 4xx/5xx で reject しません。res.ok を見ないと、Go 側が 500 を
  // 返しても catch に入らず、課金の更新が行われないまま Stripe には 200 を
  // 返します。Stripe は 200 を受けたイベントを再送しないので、その支払いは
  // 二度と反映されません。
  //
  // 2xx を返す方針そのものは変えません（Stripe の再送を止めないため 5xx を
  // 返す選択肢もありますが、どちらが正しいかは課金の運用方針です）。
  // 変えるのは、転送できなかったことが記録に残るかどうかです。
  try {
    const res = await fetch(`${API_INTERNAL_URL}/api/v1/webhooks/stripe`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'X-Stripe-Signature': sigHeader,
        'X-Webhook-Source': 'nextjs-proxy',
      },
      body: JSON.stringify(event),
    })
    if (!res.ok) {
      console.error('[stripe-webhook] API rejected the forwarded event',
        { status: res.status, type: event.type })
    }
  } catch (err) {
    // Log but don't fail — Stripe requires a 2xx response
    console.error('[stripe-webhook] Failed to forward to API:', err)
  }

  // Handle events that can be acted on directly (e.g. cache invalidation)
  switch (event.type) {
    case 'customer.subscription.updated':
    case 'customer.subscription.deleted':
    case 'invoice.payment_succeeded':
    case 'invoice.payment_failed':
      // These are handled by the Go API; no frontend-only action needed
      break
    default:
      break
  }

  return NextResponse.json({ received: true })
}

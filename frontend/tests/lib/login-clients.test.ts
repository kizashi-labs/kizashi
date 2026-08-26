import { describe, it, expect } from 'vitest'
import { readFileSync, readdirSync, statSync, existsSync } from 'fs'
import { join } from 'path'
import { toPosix } from './route-scan'

// ログインを叩くクライアントが、MFA の2段目を扱っているか。
//
// サーバの `POST /api/v1/auth/login` は **200 を2通り**返します
// (server/internal/api/handlers/auth_handler.go:152):
//
//	{ token, expires_in, user }                              MFA 無効
//	{ mfa_required: true, mfa_type, pre_auth_token, user }   MFA 有効 ← token は無い
//
// 2通目を知らないクライアントは、`token` が undefined のまま先へ進みます。
// mobile はまさにそれで、`SecureStore.setItemAsync` が文字列以外を弾いて
// throw し、画面には **「Invalid credentials」** と出ていました —— パスワードは
// 合っているのに、資格情報が違うと言う。しかも mobile には
// `/auth/mfa/verify` を叩く場所が無く、**MFA を有効にした利用者は入れません**
// でした。
//
// 実測 (2026-08-13): ログインを叩くのは2つ（frontend/lib/auth.tsx,
// mobile/app/(auth)/login.tsx）、mfa_required を扱っていたのは1つ。
// SDK はログインしません（JWT を受け取るだけ）ので、対象外です。
//
// **0 が規則です。** ここは「まだ無い機能」ではなく、既にいる利用者を
// 締め出す欠陥なので、上限ではなく 0 を置きます。

const REPO = join(process.cwd(), '..')

/** 走査対象。node_modules と検査自身は見ません。 */
function sourcesUnder(dir: string, exts: string[], out: string[] = []): string[] {
  if (!existsSync(dir)) return out
  for (const name of readdirSync(dir)) {
    if (name === 'node_modules' || name === '.next' || name === 'coverage') continue
    const p = join(dir, name)
    if (statSync(p).isDirectory()) sourcesUnder(p, exts, out)
    else if (exts.some(e => p.endsWith(e))
             && !toPosix(p).includes('/tests/')
             && !toPosix(p).includes('/e2e/')) out.push(toPosix(p))
  }
  return out
}

export type LoginClient = { where: string; verifies: boolean }

/**
 * ログインを叩いている場所と、そこが2段目を扱っているか。
 *
 * 判定を関数に出しているのは、**緑のツリーでは違反が 0 件で、判定そのものに
 * 一度も届かないから**です。下で合成入力に当てます。
 */
/**
 * ログインを **叩いている** 形。
 *
 * 宛先を書いてあるだけの場所は対象外です。最初はただの文字列一致にして
 * いて、2件ひっかかりました —— どちらもログインしていません:
 *
 *	app/admin/api-docs/page.tsx  API 説明の `path:`（mfa_required の説明まで
 *	                             ちゃんと書いてあります）
 *	app/status/page.tsx          遅延を測る対象の一覧の `endpoint:`
 *
 * **叩いていない場所を「MFA 未対応」と呼べば、直しようがありません。**
 * 呼び出しの引数として渡っている形だけを見ます。
 */
const LOGIN_CALL =
  /\b(?:fetch|post|request|apiFetch|persist)\s*(?:<[^()]*>)?\(\s*['"`][^'"`]*\/auth\/login['"`]/

/** どの配布物のファイルか。**2段目は別の画面にあって構いません。** */
export function clientOf(where: string): string {
  return where.split('/')[0]
}

/**
 * 判定は **配布物ごと** です。file ごとではありません。
 *
 * 最初は「同じ file に mfa_required と verify の両方があること」を求めて
 * いました。**2段階ログインは2画面に分かれるのが普通の形**なので、正しく
 * 直した mobile が違反のまま残りました（login.tsx が1段目、mfa.tsx が
 * 2段目）。検査が、直したことを直っていないと言う状態です。
 */
export function loginClients(files: Array<{ where: string; src: string }>): LoginClient[] {
  const seen = new Map<string, { where: string; sawFlag: boolean; sawVerify: boolean }>()
  for (const { where, src } of files) {
    const client = clientOf(where)
    const entry = seen.get(client) ?? { where: '', sawFlag: false, sawVerify: false }
    if (LOGIN_CALL.test(src) && entry.where === '') entry.where = where
    if (src.includes('mfa_required')) entry.sawFlag = true
    if (/['"`][^'"`]*\/auth\/mfa\/verify['"`]/.test(src)) entry.sawVerify = true
    seen.set(client, entry)
  }
  const out: LoginClient[] = []
  for (const e of seen.values()) {
    // ログインを叩いていない配布物は対象外です。
    if (e.where === '') continue
    out.push({ where: e.where, verifies: e.sawFlag && e.sawVerify })
  }
  return out.sort((a, b) => a.where.localeCompare(b.where))
}

/** 2段目を扱っていない場所。 */
export function clientsMissingMFA(clients: LoginClient[]): string[] {
  return clients.filter(c => !c.verifies).map(c => c.where).sort()
}

function loginSources(): Array<{ where: string; src: string }> {
  const files = [
    ...sourcesUnder(join(REPO, 'frontend', 'lib'), ['.ts', '.tsx']),
    ...sourcesUnder(join(REPO, 'frontend', 'app'), ['.ts', '.tsx']),
    ...sourcesUnder(join(REPO, 'mobile'), ['.ts', '.tsx']),
  ]
  return files.map(f => ({
    where: toPosix(f).replace(toPosix(REPO) + '/', ''),
    src: readFileSync(f, 'utf8'),
  }))
}

// 実測 (2026-08-13)。**増えるのは構いませんが、黙って減るのは走査が壊れた
// 合図です。**
// この版は mobile を同梱しないので、ログインを叩く配布物はその分だけ少ない。
const LOGIN_CLIENT_FLOOR = 1

describe('ログインするクライアントは MFA の2段目を扱う', () => {
  const clients = loginClients(loginSources())

  it('走査がクライアントに届いている', () => {
    expect(LOGIN_CLIENT_FLOOR, '床そのものが消えています').toBeGreaterThan(0)
    expect(
      clients.map(c => c.where).sort(),
      'ログインを叩く場所が見つかりません（走査が壊れています）',
    ).toEqual(expect.arrayContaining(['frontend/lib/auth.tsx']))
    expect(clients.length).toBeGreaterThanOrEqual(LOGIN_CLIENT_FLOOR)
  })

  it('mfa_required を無視しているクライアントがいない', () => {
    const bad = clientsMissingMFA(clients)
    expect(bad, `MFA を有効にした利用者が入れません:\n  ${bad.join('\n  ')}`).toEqual([])
  })

  // 緑のツリーでは上の判定に届かないので、合成入力で直接見ます。
  it.each([
    {
      name: 'login だけ叩いて mfa_required を見ていない',
      src: `api.post('/auth/login', { email, password }); store(res.data.token)`,
      want: [{ where: 'app/x.tsx', verifies: false }],
    },
    {
      name: 'mfa_required を見ていても verify を叩けない',
      src: `fetch('/api/v1/auth/login'); if (data.mfa_required) { alert('未対応') }`,
      want: [{ where: 'app/x.tsx', verifies: false }],
    },
    {
      name: '両方そろっている',
      src: `fetch('/api/v1/auth/login'); if (data.mfa_required) fetch('/api/v1/auth/mfa/verify')`,
      want: [{ where: 'app/x.tsx', verifies: true }],
    },
    {
      name: 'ログインを叩かない場所は対象外',
      src: `fetch('/api/v1/alerts')`,
      want: [],
    },
    {
      name: '**API 説明に宛先を書いてあるだけ**',
      src: `{ method: 'POST', path: '/api/v1/auth/login', description: 'MFA が有効なら mfa_required' }`,
      want: [],
    },
    {
      name: '**監視対象の一覧に名前があるだけ**',
      src: `{ name: '認証', endpoint: '/api/v1/auth/login', method: 'POST', avgLatency: 0 }`,
      want: [],
    },
  ])('判定: $name', ({ src, want }) => {
    expect(loginClients([{ where: 'app/x.tsx', src }])).toEqual(want)
  })

  // **2段目は別の画面にあって構いません。** 同じ file に両方を求めていた
  // ときは、正しく直した mobile が違反のまま残りました。
  it('2段目が別の画面にあっても扱っていると見る', () => {
    expect(
      loginClients([
        { where: 'mobile/app/(auth)/login.tsx', src: `api.post('/auth/login', b); if (r.data.mfa_required) go()` },
        { where: 'mobile/app/(auth)/mfa.tsx', src: `api.post('/auth/mfa/verify', { code })` },
      ]),
    ).toEqual([{ where: 'mobile/app/(auth)/login.tsx', verifies: true }])
  })

  it('配布物が違えば足し合わせない', () => {
    expect(
      loginClients([
        { where: 'mobile/app/(auth)/login.tsx', src: `api.post('/auth/login', b); if (r.data.mfa_required) go()` },
        { where: 'frontend/lib/other.ts', src: `fetch('/api/v1/auth/mfa/verify')` },
      ]),
    ).toEqual([{ where: 'mobile/app/(auth)/login.tsx', verifies: false }])
  })

  it('違反の抜き出しは verifies=false だけを拾う', () => {
    expect(
      clientsMissingMFA([
        { where: 'b', verifies: false },
        { where: 'a', verifies: true },
        { where: 'c', verifies: false },
      ]),
    ).toEqual(['b', 'c'])
  })
})

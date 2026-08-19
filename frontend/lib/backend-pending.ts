// **「まだ無い」を1箇所で決めます。**
//
// 元はこの一覧が `BackendPendingBanner.tsx` の中だけにあり、**画面を
// 開いて初めて「準備中」と分かる**形でした。サイドバーには 292 項目が
// 並び、そのうち **60 がこの一覧に入っています**（実測 2026-08-12）——
// 動く 232 と見分けがつきません。担当者は開いて、戻って、また別のを
// 開きます。
//
// 一覧はここにあり、**バナーもサイドバーも同じものを読みます。**
// 写しを持つと、片方だけ増えて「バナーは出るのにサイドバーは普通の
// 顔をしている」画面ができます。

export function matchesRoute(pattern: string, pathname: string): boolean {
  if (!pattern.includes('[')) return pattern === pathname
  const a = pattern.split('/').filter(Boolean)
  const b = pathname.split('/').filter(Boolean)
  const catchAll = a.findIndex(s => s.startsWith('[...'))
  if (catchAll >= 0) {
    return b.length >= catchAll && a.slice(0, catchAll).every((s, i) => s === b[i] || s.startsWith('['))
  }
  if (a.length !== b.length) return false
  return a.every((s, i) => s === b[i] || s.startsWith('['))
}

// Routes whose primary data APIs are not implemented on the server yet
// (verified by probing every static endpoint the frontend references).
// Listed pages show an honest "backend pending" notice instead of silently
// rendering empty or mock data. Remove a route here once its backend ships.
// The nine added last are the ones this comment used to be silent about:
// every apiFetch call on each of those pages names an endpoint with no route
// in server/internal/api at all — 8/8 on /admin/custom-fields, 5/5 on
// /admin/security-budget, and so on. They were reachable from the sidebar with
// nothing to say they were incomplete, so they read as finished features.
//
// /admin/asset-criticality はここから外しました (2026-08-12)。3本とも
// サーバに届きます —— 一覧の `GET /endpoints/criticality` が無かったのを
// 足したためです。**告知は「まだ無い」ことを伝えるためのもので、
// 動いている画面に出し続けると、逆向きの嘘になります。**
//
// 同じ形（告知しているのに届く呼び出しがある）が **15 画面**残って
// います。`/admin/group-policies` は 9/10、`/yara` は 8/10、
// `/admin/oncall` は 7/8。下の検査が上限として留めています。
//
// **一度「`/alerts/rules` と `/admin/onboarding` は 1/1 届く」と
// 書きました。間違いでした。** 判定が `apiFetch<{ … }>(…)` の形を
// 1件も見ていなかったので、5本のうち1本しか数えていませんでした
// （実際は 4/5 と 2/3）。**全部届く画面は、いま1つもありません。**
//
// /admin/audit-export was the one a by-prefix scan missed and the per-page
// check in the test caught: /admin/audit does have routes — signed-export,
// events, stats, export — just not the two this page calls
// (/audit/export-history and /admin/audit/archive-config). A prefix with
// routes is not a page with routes.
// tests/lib/backend-pending-coverage.test.ts keeps that from recurring.
export const BACKEND_PENDING_ROUTES = new Set<string>([
  '/admin/agent-performance',
  '/admin/arch-review',
  '/admin/users/[id]/activity',
  '/forensics/artifacts',
  '/forensics/memory',
  '/forensics/network',
  '/ioc/import',
  '/soc/analytics',
  '/admin/audit-export',
  '/admin/auto-response',
  '/admin/awareness-campaigns',
  '/admin/behavioral-baseline',
  '/admin/compliance-remediation',
  '/admin/control-testing',
  '/admin/controls-monitoring',
  '/admin/custom-alert-rules',
  '/admin/custom-fields',
  '/admin/cyber-insurance',
  '/admin/dark-web',
  '/admin/data-lake',
  '/admin/data-viz',
  '/admin/deception-technology',
  '/admin/detection-studio',
  '/admin/encryption-mgmt',
  '/admin/file-hashes',
  '/admin/geo-blocking',
  // `/admin/group-policies` は「一部準備中」へ移しました (2026-08-17)。
  // 10 本中 9 本が届きます —— **「全部無い」と「ほぼ在る」を同じ告知で
  // 出していました。** （この註に経路を引用符で書かないこと ——
  // 判定はこの Set の範囲にある引用符付きの文字列を全部拾います）
  '/admin/identity-risk',
  '/admin/integrations/ldap',
  '/admin/log-forwarding',
  '/admin/marketplace',
  '/admin/maturity-model',
  '/admin/mfa-management',
  '/admin/migrations',
  '/admin/observability',
  '/admin/onboarding',
  '/admin/oncall',
  '/admin/orchestration',
  '/admin/pag',
  '/admin/playbook-builder',
  '/admin/privacy-assessment',
  '/admin/privileged-sessions',
  '/admin/quarantine',
  '/admin/rate-limits',
  '/admin/red-team',
  '/admin/runbook',
  '/admin/saved-searches',
  '/admin/security-budget',
  '/admin/security-champions',
  '/admin/security-dw',
  '/admin/security-governance',
  '/admin/security-roi',
  '/admin/siem-query-builder',
  '/admin/supply-chain',
  '/admin/supply-chain-risk',
  '/admin/tooling-inventory',
  '/admin/training-analytics',
  '/admin/training-mgmt',
  '/admin/user-behavior-analytics',
  '/admin/vendor-assessment',
  '/admin/webhook-tester',
  '/admin/webhooks',
  '/admin/zero-day',
  '/admin/ztna',
  '/alerts/correlation-v2',
  '/alerts/rules',
  '/assets/dependencies',
  '/assets/lifecycle',
  '/compliance/calendar',
  // 2026-08-12: `GET/PUT /compliance/regulatory` はサーバに handler が
  // ありません。**幻の経路（`cr` が4つの path に束ねられていた）に
  // 隠れて、「API はある」と判定されていました。**
  '/compliance/regulatory-mapping',
  // 2026-08-12: 唯一の呼び出しが `POST /webhooks/test` で、サーバに
  // あるのは `POST /webhooks/:id/test` です。**型引数を見るように
  // 直すまで、この画面の呼び出しは1本も数えられていませんでした。**
  '/admin/webhook-schemas',
  // 2026-08-12: 4本とも `/api/nta/…` で、サーバにその prefix はありません
  // （ITDR と違って、対応するハンドラ自体がありません）。**`/api/v1` で
  // 始まる宛先しか見ていなかったので、1本も数えられていませんでした。**
  // 2026-08-12: 宛先を直したら、その先が**作り物**でした（DB を1度も
  // 見ずに、実在しないインシデントを 200 で返していました）。サーバを
  // 501 にしたので、画面はここで「準備中」と言います。
  // **あの書き間違いだけが、作り物を画面に出さずに済ませていました。**
  '/admin/itdr',
  // 2026-08-12: ITDR と同じです。DB も外部の購読も見ずに
  // 「2時間前に認証情報の漏洩を検出、調査中」を返していました ——
  // **漏れていない認証情報の失効作業が走ります。** サーバを 501 に
  // したので、画面はここで「準備中」と言います。
  '/admin/drp',
  // 2026-08-12: 作り物を返していた9つを 501 にしました。画面から
  // 呼んでいるのはこの2つだけです（残り7つは呼び出し元がありません）。
  // `/admin/alert-routing` は「234件がこのルートで流れた」を、
  // `/admin/security-assessment` は「外部監査法人Aの診断が完了」を
  // 出していました —— **どちらも報告に使われる形です。**
  '/admin/alert-routing',
  '/admin/security-assessment',
  '/admin/nta',
  // 2026-08-12: 唯一の呼び出しが `GET /api/openapi` で、サーバに
  // ありません。**版のついていない宛先を見ていなかったので、この画面は
  // 「呼び出し0本」として判定を素通りしていました。**
  '/api-docs',
  // 2026-08-12: `GET /api/kb/articles`。同上。
  '/soc/knowledge-base',
  // 2026-08-12: `/api/soc/shift-manager/…` 3本。同上。
  '/soc/shift-manager',
  '/container-monitoring',
  '/malware-analysis/families',
  '/reports/builder',
  '/soc/shifts',
  '/threat-hunting/campaigns',
  '/wireless-security',
  // `/yara` も「一部準備中」へ (2026-08-17)。8/10 届きます。
])

// Pages that work overall but contain sections whose APIs are pending.
export const PARTIAL_PENDING_ROUTES = new Set<string>([
  // 2026-08-12: 25 本中 9 本が届きません。**4つのタブが丸ごと**です ——
  // 連絡記録（comms）・エスカレーション・対応者・事後検証。どれも
  // サーバに handler がありません（`incidents` にあるのは notes・
  // comments・timeline・alerts だけです）。
  //
  // **13 ある mutation のうち 11 は、失敗を出す手段を持ちません。**
  // 対応者が連絡記録を書いて保存を押すと、**何も起きません** ——
  // 見えるのは「反応が無い」だけなので、もう一度押します。
  '/incidents/[id]',
  '/profile/notifications',
  // '/admin/incidents' は #673 で一覧・詳細・ステータス遷移・相関ルールを
  // すべて実在するルートに結線したため外した。この取り込みでその結線
  // （PATCH /api/v1/incidents/:id/status と /api/v1/correlation-engine）を
  // 採ったので、もう「準備中」ではない。相関ルール表が空になるのは API 不在
  // ではなく DB にルールが 0 件なだけ。
  '/admin/cloud-siem',        // クエリ実行タブは実ログ検索エンジン準備中
  '/admin/incident-patterns', // 分析実行(相関エンジン)は準備中

  // ── 2026-08-17: 9割以上届く2画面を「全部準備中」から移しました ──
  //
  // **「全部無い」と「ほぼ在る」を同じ告知で出していました。** 告知は
  // 正しくても、利用者は動く機能を避けます —— 空の画面と結果は同じです。
  '/admin/group-policies',  // 10 本中 9 本が届きます
  '/yara',                  // 8/10

  // ── 2026-08-17: 一部だけ届かない 38 画面 ──
  //
  // **これまで見ていたのは「全部死んでいる画面」だけでした。** 一部
  // だけ死んでいる画面は、動く区画があるぶん見分けにくい形です ——
  // 押しても何も起きないボタンが1つ混ざっていても、画面全体は動いて
  // 見えます。目的は**どのボタンが何も起こさないか**を見せることです。
  //
  // 宛先を作る判断とは別です（`docs/判断待ちの一覧.md`）。作った画面は
  // ここから外してください —— `backend-pending-coverage.test.ts` が
  // 「一部だけ届かない画面」を **0 で留めています**。
  '/admin/ai-triage',                 // 2/11
  '/admin/alerts/[id]',               // 1/5 (POST /api/v1/ai/analyze-alert)
  '/admin/backups',                   // 1/4
  '/admin/bas',                       // 1/5
  '/admin/compliance-auto',           // 1/4
  '/admin/container-security',        // 1/7
  '/admin/deception',                 // 1/6
  '/admin/edr-policies',              // 1/10
  '/admin/enrollment',                // 1/5
  '/admin/feature-flags',             // 1/7
  '/admin/identity',                  // 1/4
  '/admin/integrations/elastic',      // 1/6
  '/admin/integrations/sentinel',     // 2/6
  '/admin/integrations/soar',         // 1/7
  '/admin/log-sources',               // 2/6
  '/admin/network-analysis',          // 1/4
  '/admin/network-topology',          // 1/3
  '/admin/patch-management',          // 1/7
  '/admin/playbooks',                 // 1/6
  '/admin/siem-integration',          // 1/4
  '/admin/users',                     // 3/11
  '/admin/version',                   // 1/2
  '/agent-health',                    // 1/3
  '/agents/[id]/config',              // 1/5
  '/dark-web',                        // 1/5
  '/endpoints/[id]/performance',      // 1/2
  '/endpoints/batch',                 // 1/3
  '/endpoints/bulk',                  // 1/4
  '/endpoints/tags',                  // 2/6
  '/fim',                             // 1/10
  '/groups/[id]/policy',              // 1/6
  '/playbooks/[id]',                  // 1/3
  '/reports/security-ops',            // 1/2
  '/soc/tickets',                     // 1/8
  '/software/diff',                   // 2/3
  '/suppressions',                    // 1/5
  '/threat-hunting/automated',        // 3/6
  '/threat-modeling/advanced',        // 2/3
  '/vulnerabilities',                 // 1/5
])

/**
 * 動的セグメントを含む経路も照合できるようにします。
 *
 * usePathname() が返すのは /admin/users/abc123/activity のような実際の
 * パスなので、Set の完全一致では [id] を含むページには一生当たりません。
 * このリストは長らく静的な経路だけで、当たらないことに気づく機会が
 * ありませんでした。[id] は1区間、[...slug] は残り全部に対応します。
 */


/** その path が「バックエンドまるごと準備中」か。 */
export function isBackendPending(pathname: string): boolean {
  return announcesPending(BACKEND_PENDING_ROUTES, pathname)
}

/** その path が「一部の機能だけ準備中」か。 */
export function isPartiallyPending(pathname: string): boolean {
  return !isBackendPending(pathname) && announcesPending(PARTIAL_PENDING_ROUTES, pathname)
}

export function announcesPending(routes: Set<string>, pathname: string): boolean {
  if (routes.has(pathname)) return true
  for (const r of routes) if (matchesRoute(r, pathname)) return true
  return false
}

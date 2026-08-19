// 1つの画面が複数の取得をまとめているとき、届かなかった部分の名前を残す。
//
// ページ単位の帯（PageDataUnavailable）は、react-query が失敗を知っている
// クエリしか見えません。ところが集約するクエリはこう書かれていました:
//
//   queryFn: async () => {
//     const [agents, detections, vulns] = await Promise.all([
//       apiFetch('/api/v1/metrics/agent-stats').catch(() => EMPTY.agentStats),
//       apiFetch('/api/v1/metrics/detection-stats').catch(() => EMPTY.detectionStats),
//       apiFetch('/api/v1/admin/vulnerabilities/stats').catch(() => EMPTY.vulnStats),
//     ])
//     return { ... }
//   }
//
// queryFn 自身が失敗を握りつぶしているので、Promise は解決し、
// status は 'success' になります。帯は何も出しません。画面には
// 「重大な脆弱性 0件」が出ます。取れなかったのに、です。
//
// かといって .catch を外すだけでは Promise.all ごと失敗して、届いていた
// 3つ分も消えます。役員向けダッシュボードが1本のAPIの不調で真っ白になる
// のは、直したい状態ではありません。
//
// readInto は届いたものを残したまま、届かなかったものの名前を集めます。
// 画面は PartialDataNotice でその名前を並べます。「0件」と
// 「取れていないので分からない」の区別が、画面の中で付きます。

/**
 * 取得できなければ fallback を返し、`missing` に名前を残す。
 *
 * `what` は画面に出る日本語の名前です（「脆弱性統計」など）。
 * 「vulnStats が失敗」ではなく「脆弱性統計が取れていない」と読める
 * ものにしてください。読むのは SOC の担当者です。
 */
export function readInto<T>(
  missing: string[],
  what: string,
  p: Promise<T>,
  fallback: T
): Promise<T> {
  return p.catch(() => {
    missing.push(what)
    return fallback
  })
}

/** 集約したクエリの戻り値が持つ、届かなかった部分の名前。 */
export interface WithMissing {
  missing: string[]
}

/**
 * サーバの ueba_anomalies が返す1行を、UEBA 画面が読む形にします。
 *
 * 画面は /admin/uba/anomalies を呼んでいました。サーバにあるのは
 * /admin/ueba/anomalies で、e が1文字足りないだけです。404 を
 * .catch(() => []) が飲み込むので、異常の一覧はいつも空でした。
 *
 * ただし経路を直すだけでは足りません。サーバは username / anomaly_type /
 * score / created_at という名前で返し、画面は user / type / risk_delta /
 * timestamp を読みます。名前を合わせずに 200 を受けると、空だった行が
 * 「空欄の行」に変わるだけで、むしろ悪くなります。
 *
 * ここに置いてあるのは、page.tsx から export できないからです。Next.js の
 * App Router はページファイルの export を default と決まった数個に限って
 * いて、それ以外があるとビルドが
 * 「"toAnomalyItem" is not a valid Page export field」で落ちます。
 */

export type AnomalyType =
  | 'impossible_travel'
  | 'off_hours_access'
  | 'data_exfil'
  | 'privilege_escalation'
  | 'unusual_app'

/** 画面が読む形。 */
export interface UBAAnomalyItem {
  id: string
  timestamp: string
  user: string
  type: AnomalyType
  description: string
  risk_delta: number
}

/** サーバが返す形（ueba_advanced_handler.go の json タグ）。 */
export interface UEBAAnomalyRow {
  id: string
  username: string
  anomaly_type: string
  description: string
  score: number
  created_at: string
}

export function toAnomalyItem(row: UEBAAnomalyRow): UBAAnomalyItem {
  return {
    id: row.id,
    timestamp: row.created_at,
    user: row.username,
    type: row.anomaly_type as AnomalyType,
    description: row.description,
    risk_delta: Math.round(row.score ?? 0),
  }
}

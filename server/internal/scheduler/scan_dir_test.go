// scan_dir_test.go — 走査系テストが共有する走査起点。
//
// schema_gate_test.go から切り出してある。あちらは公開版が同梱しない側
// （除外スケジューラ前提の契約検査）だが、bare_log_and_return / discarded_read
// など kept 側の走査テストもこの定数を使うため。
package scheduler

const schedulerDir = "."

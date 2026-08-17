package awsscan

// 1 アカウントを検査して結果を保存するまでの一連。
//
// 呼ぶ側は 2 つある — 画面からの手動実行 (internal/api/handlers の
// StartScan) と、定期実行 (internal/scheduler)。両者で挙動が変わっては
// いけないので、ここに 1 つだけ置く。特に「失敗を completed にしない」
// 「未計測の理由を 1 件ずつ出す」は、片方だけ抜けると片方の経路でだけ
// 静かに壊れる。

import (
	"context"
	"log/slog"
	"time"

	"github.com/edr-platform/server/internal/store"
)

// ScanTimeout は 1 回のスキャンの上限。リージョン数 × 項目数だけ
// AWS API を呼ぶので、極端な構成でも収まる長さにしてある。
const ScanTimeout = 15 * time.Minute

// statusWriteTimeout は終了状態を書くための、スキャンとは独立した期限。
const statusWriteTimeout = 10 * time.Second

// RunAndPersist は 1 アカウントを検査し、結果を保存し、scan_status を
// 確定させる。呼び出し元は事前に scan_status を 'scanning' にしておくこと。
//
// この関数は失敗しても scan_status を 'completed' にしない。「検査した
// 結果 0 件」と「検査できなかった」が区別できなくなり、権限設定のミスが
// 画面上は「問題なし」になる。
//
// 実行時間が長いので、呼び出し元の context は受け取らず自前で期限を持つ。
// HTTP ハンドラから呼ぶ場合、リクエストの context は応答を返した時点で
// 切れるため渡せない。
func RunAndPersist(cs *store.CSPMStore, accountUUID string, creds Credentials, regions []string) Outcome {
	ctx, cancel := context.WithTimeout(context.Background(), ScanTimeout)
	defer cancel()

	scanner := NewScanner()
	scanner.Regions = regions

	res, err := scanner.Scan(ctx, creds)
	if err != nil {
		slog.Error("CSPM(AWS): スキャンに失敗しました", "account", accountUUID, "error", err)
		setScanStatusDetached(cs, accountUUID, "error", err)
		return Outcome{Err: err}
	}

	pr, err := Persist(ctx, cs, accountUUID, res)
	if err != nil {
		slog.Error("CSPM(AWS): 所見の保存に失敗しました", "account", accountUUID, "error", err)
		setScanStatusDetached(cs, accountUUID, "error", err)
		return Outcome{Err: err}
	}

	slog.Info("CSPM(AWS): スキャンが完了しました",
		"account", accountUUID, "aws_account", res.AccountID,
		"regions", len(res.Regions), "findings", pr.Upserted, "new", len(pr.New),
		"resolved", pr.Resolved, "disappeared", pr.Disappeared,
		"unmeasured", len(res.Errors), "duration", res.FinishedAt.Sub(res.StartedAt))

	// 読めなかった項目は 1 件ずつ理由を出す。件数だけでは
	// 「権限が足りないのか」「応答の読み方が違うのか」を切り分けられず、
	// unknown のまま放置される。unknown は所見にならないので、
	// ここに出さないと存在自体が見えなくなる。
	for _, e := range res.Errors {
		slog.Warn("CSPM(AWS): 検査できなかった項目があります",
			"account", accountUUID, "check_id", e.CheckID,
			"region", e.Region, "reason", e.Message)
	}

	setScanStatusDetached(cs, accountUUID, "completed", nil)

	return Outcome{
		AWSAccountID: res.AccountID,
		Regions:      len(res.Regions),
		Persisted:    *pr,
		Unmeasured:   res.Errors,
		Duration:     res.FinishedAt.Sub(res.StartedAt),
	}
}

// Outcome は 1 回のスキャンで外に伝えるべきこと。
//
// ログにしか出さないと、24 時間おきに走る定期スキャンでは誰も気づかない。
// 「権限が外れて測れなくなった」が最も表に出にくいので、呼び出し側が
// 通知を判断できるだけの材料をここに載せる。
type Outcome struct {
	// Err はスキャン自体または保存が失敗した理由。nil なら完走している。
	Err error
	// AWSAccountID は検査した AWS アカウント (12 桁)。通知の宛名に使う。
	AWSAccountID string
	Regions      int
	Persisted    PersistResult
	// Unmeasured は検査できなかった項目。空でないなら、その項目は
	// 「問題なし」ではなく「測れていない」。
	Unmeasured []ScanError
	Duration   time.Duration
}

// Notable は通知に値することがあったか。
//
// 正常に完走して新しい所見も無い回は false になる。異常が無い回まで
// 毎日送ると通知そのものが読まれなくなり、本当に伝えたい回を埋もれさせる。
func (o Outcome) Notable() bool {
	return o.Err != nil || len(o.Unmeasured) > 0 || len(o.Persisted.New) > 0
}

// setScanStatusDetached は終了状態の記録を、スキャン用 context とは
// 切り離した短い context で行う。
//
// スキャンが締切超過で失敗した場合、その context は既に切れている。
// 同じ context で 'error' を書こうとすると書き込みも失敗し、行は
// 'scanning' のまま残る。以降このアカウントは「スキャン中」と表示され
// 続け、失敗したことも再実行が必要なことも画面から分からなくなる。
// 状態を記録できないことが最も表に出にくい失敗なので、ここだけは
// 独立した期限を持たせる。
func setScanStatusDetached(cs *store.CSPMStore, accountUUID, status string, scanErr error) {
	ctx, cancel := context.WithTimeout(context.Background(), statusWriteTimeout)
	defer cancel()
	if err := cs.SetScanStatus(ctx, accountUUID, status, scanErr); err != nil {
		slog.Error("CSPM(AWS): スキャン状態の記録に失敗しました",
			"account", accountUUID, "status", status, "error", err)
	}
}

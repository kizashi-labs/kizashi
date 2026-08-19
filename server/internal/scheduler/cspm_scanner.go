package scheduler

// CSPM の定期スキャン。
//
// これが無いと CSPM は「担当者が思い出して画面のボタンを押したときだけ
// 動く」機能になる。CSPM が捕まえるべきなのは「誰も見ていない間に
// 設定が変わって穴が開いた」ケースなので、手動実行しか無いと本来の
// 用途を満たさない。所見を閉じる側も同じで、資源を消して直した所見は
// 次のスキャンが走るまで一覧に残る。
//
// スキャン本体は awsscan.RunAndPersist に置いてある。画面からの手動実行
// (internal/api/handlers の StartScan) と同じ関数を呼ぶ ---「失敗を
// completed にしない」「未計測の理由を出す」といった約束が経路ごとに
// ずれると、片方でだけ静かに壊れるため。

import (
	"context"
	"log/slog"
	"time"

	"github.com/edr-platform/server/internal/cspm/awsscan"
	"github.com/edr-platform/server/internal/store"
)

const (
	// cspmClaimStaleAfter は 'scanning' のまま放置された占有を解放するまでの
	// 時間。awsscan.ScanTimeout (15 分) の 2 倍を取ってある。短すぎると
	// 実行中のスキャンを別レプリカが横取りし、長すぎると異常終了した
	// アカウントが長時間スキャンされないまま残る。
	cspmClaimStaleAfter = 30 * time.Minute

	// cspmMaxPerTick は 1 周回で処理するアカウント数の上限。
	// アカウントが多いときに 1 周回へ詰め込むと、AWS API の呼び出しが
	// 一時に集中してスロットリングを招く。次の周回に回せばよい。
	cspmMaxPerTick = 10
)

// CSPMScanner は引受情報が設定済みの AWS アカウントを定期的に検査する。
type CSPMScanner struct {
	store *store.CSPMStore
	// tick は対象を探しに行く間隔。個々のアカウントが実際に検査される
	// 頻度は interval で決まるので、これは「見に行く粒度」でしかない。
	tick time.Duration
	// interval は 1 アカウントあたりの最短間隔。
	interval time.Duration
	// notifier は結果の通知先。nil なら通知しない (通知チャンネルが 1 つも
	// 設定されていない環境でも定期スキャン自体は動かす)。
	notifier     Notifier
	dashboardURL string
}

func NewCSPMScanner(s *store.CSPMStore, tick, interval time.Duration) *CSPMScanner {
	if tick <= 0 {
		tick = 15 * time.Minute
	}
	if interval <= 0 {
		interval = 24 * time.Hour
	}
	return &CSPMScanner{store: s, tick: tick, interval: interval}
}

// WithNotifier は結果の通知先を設定する。
//
// 通知は定期実行にだけ付ける。画面から手動で走らせた場合は、押した本人が
// その場で結果を見るので通知は雑音になる。
func (s *CSPMScanner) WithNotifier(n Notifier, dashboardURL string) *CSPMScanner {
	s.notifier = n
	s.dashboardURL = dashboardURL
	return s
}

func (s *CSPMScanner) Run(ctx context.Context) {
	ticker := time.NewTicker(s.tick)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			trackRun(ctx, "cspm_scanner", s.sweep)
		}
	}
}

// sweep は対象を 1 件ずつ占有して検査する。
//
// 直列に回すのは意図的。並列にすると同一アカウントの複数リージョンに
// 加えてアカウント間でも同時に AWS を叩くことになり、スロットリングの
// 制御が難しくなる。CSPM は即時性を要求されない。
func (s *CSPMScanner) sweep(ctx context.Context) {
	for i := 0; i < cspmMaxPerTick; i++ {
		if ctx.Err() != nil {
			return
		}
		acct, err := s.store.ClaimNextScan(ctx, s.interval, cspmClaimStaleAfter)
		if err != nil {
			// この回は仕事を終えられていない。ログだけだと、外からは
			// 「対象が無かった」と区別が付かない。
			fail(ctx, err, "CSPM(定期): 対象の取得に失敗しました")
			return
		}
		if acct == nil {
			return // 対象なし
		}

		creds := awsscan.Credentials{RoleARN: acct.RoleARN, ExternalID: acct.ExternalID}
		if err := creds.Validate(); err != nil {
			// 占有した後で引受情報が不正だと分かった場合。ここで
			// 'error' に落とさないと scan_status が 'scanning' のまま残り、
			// 次に対象になるのは staleAfter 経過後になる。
			slog.Warn("CSPM(定期): 引受情報が不正なためスキャンできません",
				"account", acct.AccountUUID, "reason", err)
			if serr := s.store.SetScanStatus(ctx, acct.AccountUUID, "error", err); serr != nil {
				// ここだけはどこにも残らない。scan_status は 'scanning' の
				// まま据え置かれ、次に対象になるのは staleAfter 経過後で、
				// 画面上は「検査中」に見え続ける。
				fail(ctx, serr, "CSPM(定期): 失敗状態の記録にも失敗しました",
					"account", acct.AccountUUID)
			}
			// 引受情報が不正なら以降ずっと測れない。ログだけでは
			// 気づかれないので、スキャン失敗と同じ扱いで通知する。
			s.notifyCSPM(ctx, acct.AccountUUID, awsscan.Outcome{
				AWSAccountID: acct.AccountID, Err: err,
			})
			continue
		}

		slog.Info("CSPM(定期): スキャンを開始します",
			"account", acct.AccountUUID, "aws_account", acct.AccountID)
		// RunAndPersist が完了時に scan_status を確定させる。
		// 同期で呼ぶ ---次のアカウントを掴む前に 1 件を終わらせる。
		out := awsscan.RunAndPersist(s.store, acct.AccountUUID, creds, acct.Regions)
		s.notifyCSPM(ctx, acct.AccountUUID, out)
	}
	slog.Info("CSPM(定期): 1 周回の上限に達しました。残りは次の周回で処理します",
		"limit", cspmMaxPerTick)
}

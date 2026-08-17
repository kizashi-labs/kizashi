package awsscan

import (
	"context"
	"log/slog"
	"sync"
	"time"
)

// Scanner は 1 アカウントを検査する。
type Scanner struct {
	checks []Check
	// Regions を明示すると、その範囲だけを見る。空なら有効化されている
	// 全リージョン。SMB では東京 1 つだけという構成も多いので、
	// 絞れるようにしておく (呼び出し回数と所要時間が桁で変わる)。
	Regions []string
	// MaxParallelRegions はリージョンの同時実行数。
	// 増やしすぎると API のスロットリングに当たる。
	MaxParallelRegions int
}

// NewScanner は既定の項目一式でスキャナを作る。
func NewScanner() *Scanner {
	return &Scanner{checks: Checks(), MaxParallelRegions: 4}
}

// Scan はロールを引き受けて全項目を実行する。
//
// 引受に失敗した場合はここでエラーを返し、所見は 1 件も作らない。
// 接続不良を「不合格が大量にある」として記録すると、権限設定のミスが
// セキュリティ上の問題として報告されてしまう。
func (s *Scanner) Scan(ctx context.Context, creds Credentials) (*ScanResult, error) {
	started := time.Now().UTC()

	sess, err := Connect(ctx, creds)
	if err != nil {
		return nil, err
	}

	regions := s.Regions
	if len(regions) == 0 {
		regions, err = sess.Regions(ctx)
		if err != nil {
			return nil, err
		}
	}

	res := &ScanResult{
		AccountID: sess.AccountID(),
		StartedAt: started,
		Regions:   regions,
	}

	var mu sync.Mutex

	// アカウント単位の項目は 1 回だけ。既定リージョンのクライアントで実行する。
	home := sess.Clients(creds.region())
	for _, c := range s.checks {
		if c.Scope != ScopeAccount {
			continue
		}
		s.runOne(ctx, c, home, res, &mu)
	}

	// リージョン単位の項目。
	sem := make(chan struct{}, max(1, s.MaxParallelRegions))
	var wg sync.WaitGroup
	for _, region := range regions {
		wg.Add(1)
		go func(region string) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()

			clients := sess.Clients(region)
			for _, c := range s.checks {
				if c.Scope != ScopeRegion {
					continue
				}
				s.runOne(ctx, c, clients, res, &mu)
			}
		}(region)
	}
	wg.Wait()

	res.FinishedAt = time.Now().UTC()
	return res, nil
}

// runOne は 1 項目を実行し、結果を積む。
// パニックはスキャン全体を落とさず、その項目だけを「検査できなかった」に倒す。
func (s *Scanner) runOne(ctx context.Context, c Check, clients *Clients, res *ScanResult, mu *sync.Mutex) {
	defer func() {
		if r := recover(); r != nil {
			slog.Error("CSPM(AWS): チェックがパニックしました",
				"check_id", c.ID, "region", clients.Region, "panic", r)
			mu.Lock()
			res.Errors = append(res.Errors, ScanError{
				CheckID: c.ID, Region: clients.Region,
				Message: "チェックの実行中に異常終了しました",
			})
			mu.Unlock()
		}
	}()

	out := c.Run(ctx, clients)

	mu.Lock()
	defer mu.Unlock()
	for _, r := range out {
		if r.Status == StatusUnknown {
			// 未計測は所見にしない。件数に混ぜると
			// 「読めなかった」が「問題あり」または「問題なし」に化ける。
			res.Errors = append(res.Errors, ScanError{
				CheckID: c.ID, Region: r.Region, Message: r.Evidence,
			})
			continue
		}
		res.Results = append(res.Results, r)
	}
}

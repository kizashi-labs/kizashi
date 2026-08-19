// Package detection — auth_attack.go: stateful real-time authentication-attack
// detection (brute force + password spray).
//
// A brute-force or password-spray attack is a RATE/FAN-OUT phenomenon that no
// per-event rule can see: the built-in "Multiple Failed Login" Sigma rule fires
// on a single EventID 4625, so it neither counts nor distinguishes a fat-fingered
// password from an attack — it just alerts on every failure. The only prior
// counting lived in an OFFLINE batch job over audit_logs (insider_threat_detector),
// so nothing caught these live. This detector maintains bounded, windowed state
// over the auth event stream and fires on the two shapes that matter:
//
//   - Brute force (T1110): many failures against ONE account in a short window —
//     depth. Cleared on a subsequent success so an eventual correct login (the
//     forgot-my-password case) does not linger toward the threshold.
//   - Password spray (T1110.003): one SOURCE failing against MANY DISTINCT
//     accounts — breadth. The low-and-slow pattern (a few tries each across many
//     users) that single-account brute-force detectors miss entirely.
//   - Brute-force SUCCESS (T1110→T1078): the success that CLOSES a failure burst.
//     This is the account compromise itself, and it used to be the one thing the
//     detector deliberately threw away — clearing the counter on success (above)
//     discarded the state at the exact moment it became most interesting. The
//     attempts were alerted on; the breach that followed them was silent.
//
// Both map to the credential-access tactic, so via the engine's kill-chain feed a
// credential-access stage is contributed to the host's chain. Mirrors
// NetworkScanDetector's proven structure (sliding window, per-key state,
// fire-then-dedup, injected clock).
package detection

import (
	"fmt"
	"sync"
	"time"

	detectionrules "github.com/edr-platform/server/internal/detection/rules"
)

const (
	// authWindow is the sliding window for both brute-force and spray counting.
	authWindow = 5 * time.Minute
	// bruteMinFails is the number of failed logins against ONE account within the
	// window that trips a brute-force alert.
	bruteMinFails = 6
	// sprayMinAccounts is the number of DISTINCT accounts one source must fail
	// against within the window to trip a password-spray alert. Spray is wide and
	// shallow, so this keys on breadth, not per-account depth.
	sprayMinAccounts = 6
	// bruteSuccessMinFails is how many in-window failures a SUCCESS must follow to
	// be reported as a likely compromise. Deliberately ABOVE bruteMinFails: at 6 the
	// residual false positive (a human mistyping until they get it right) is common
	// enough that alerting on every one would train analysts to ignore the rule,
	// and this alert is high severity precisely because it should be believable.
	// Failures between the two thresholds still raise the T1110 attempt alert.
	bruteSuccessMinFails = 10
	// authDedup suppresses repeat alerts for the same key after it fires.
	authDedup = 10 * time.Minute
	// authMaxKeys bounds memory (tracked accounts + sources).
	authMaxKeys = 16384
)

type bruteState struct {
	failTimes []int64 // unix seconds of failed logins within the window
	lastAlert int64
}

type sprayState struct {
	accounts  map[string]int64 // account → last-failed unix seconds
	lastAlert int64
}

// AuthAttackScorer is a stateful, concurrency-safe brute-force / password-spray
// detector. Construct with newAuthAttackScorer; feed every auth event to Observe.
type AuthAttackScorer struct {
	mu    sync.Mutex
	brute map[string]*bruteState // key: agentID|username
	spray map[string]*sprayState // key: agentID|sourceIP
}

func newAuthAttackScorer() *AuthAttackScorer {
	return &AuthAttackScorer{
		brute: make(map[string]*bruteState),
		spray: make(map[string]*sprayState),
	}
}

// Observe records one authentication event and returns brute-force / spray
// matches when a threshold is crossed. success=true clears the account's
// brute-force counter (a legitimate login after retries). Empty agentID is
// tolerated (host-less auth sources still correlate by source/user). now is
// injected for deterministic tests.
func (a *AuthAttackScorer) Observe(agentID, sourceIP, username string, success bool, now time.Time) []*detectionrules.RuleMatch {
	nu := now.Unix()
	winSec := int64(authWindow / time.Second)
	acctKey := agentID + "|" + username
	srcKey := agentID + "|" + sourceIP

	a.mu.Lock()
	defer a.mu.Unlock()

	if len(a.brute) > authMaxKeys {
		a.evictBrute(nu, winSec*4)
	}
	if len(a.spray) > authMaxKeys {
		a.evictSpray(nu, winSec*4)
	}

	// A successful login clears the account's brute counter so a legitimate login
	// after a few typos does not accumulate toward the threshold. Before dropping
	// that state, check whether the success closed out a genuine failure burst —
	// that transition (T1110→T1078) is the compromise, and it is only visible here.
	if success {
		if username == "" {
			return nil
		}
		bs := a.brute[acctKey]
		delete(a.brute, acctKey)
		if bs == nil {
			return nil
		}
		// Count only failures still inside the window; the success branch never
		// pruned before, so an hours-old burst must not be credited to this login.
		n := len(pruneOlder(bs.failTimes, nu-winSec))
		if n < bruteSuccessMinFails {
			return nil
		}
		// No dedup timer needed: the account's state is deleted above, so re-firing
		// requires accumulating a whole new burst.
		return []*detectionrules.RuleMatch{{
			RuleName: "認証: ブルートフォース成功（アカウント侵害の疑い）",
			RuleType: "heuristic",
			Severity: 9,
			Title:    fmt.Sprintf("[HEURISTIC] ブルートフォース成功の疑い: '%s' が多数の失敗後にログイン成功", username),
			Description: fmt.Sprintf("アカウント '%s' が%d分以内に%d回の認証失敗の後にログインに成功 (ソース=%s)。失敗バースト(T1110)そのものは既存の試行アラートで見えていたが、それに続く成功=攻撃者が実際に認証を通った瞬間は今まで記録されていなかった。ブルートフォース/パスワードスプレーの成功はアカウント侵害の高信頼シグナル。",
				username, int(authWindow/time.Minute), n, sourceIP),
			// Both tactics deliberately: the burst is credential-access, and the
			// resulting session is valid-account initial-access. A compromise that
			// only ever registered as credential-access understates the kill chain.
			MITRETags: []string{"T1110", "T1078"},
			// AutoIsolate stays false. The residual false positive is a real user who
			// eventually remembered their password; that must be triaged by a human,
			// not met with an automatic host isolation.
		}}
	}

	var out []*detectionrules.RuleMatch

	// ── Brute force: failures against one account ────────────────
	if username != "" {
		bs := a.brute[acctKey]
		if bs == nil {
			bs = &bruteState{}
			a.brute[acctKey] = bs
		}
		bs.failTimes = pruneOlder(bs.failTimes, nu-winSec)
		bs.failTimes = append(bs.failTimes, nu)
		if len(bs.failTimes) >= bruteMinFails && nu-bs.lastAlert >= int64(authDedup/time.Second) {
			bs.lastAlert = nu
			n := len(bs.failTimes)
			out = append(out, &detectionrules.RuleMatch{
				RuleID:   "",
				RuleName: "ブルートフォース: 単一アカウントへの多数ログイン失敗",
				RuleType: "heuristic",
				Severity: 7,
				Title:    fmt.Sprintf("[HEURISTIC] ブルートフォースの疑い: アカウント '%s' に%d分内で多数のログイン失敗", username, int(authWindow/time.Minute)),
				Description: fmt.Sprintf("単一アカウント '%s' に対し%d分以内に%d回のログイン失敗(直近ソース=%s)。単発の失敗ではなく短時間の多数失敗=ブルートフォースの疑い。認証イベントのレートで判定するため、成功時はカウンタをリセットし正当な再試行を除外。",
					username, int(authWindow/time.Minute), n, sourceIP),
				MITRETags: []string{"T1110"},
			})
		}
	}

	// ── Password spray: one source, many distinct accounts ───────
	if sourceIP != "" {
		ss := a.spray[srcKey]
		if ss == nil {
			ss = &sprayState{accounts: make(map[string]int64)}
			a.spray[srcKey] = ss
		}
		for acct, ts := range ss.accounts {
			if nu-ts > winSec {
				delete(ss.accounts, acct)
			}
		}
		if username != "" {
			ss.accounts[username] = nu
		}
		if len(ss.accounts) >= sprayMinAccounts && nu-ss.lastAlert >= int64(authDedup/time.Second) {
			ss.lastAlert = nu
			n := len(ss.accounts)
			out = append(out, &detectionrules.RuleMatch{
				RuleID:   "",
				RuleName: "パスワードスプレー: 単一ソースから多数アカウントへの失敗",
				RuleType: "heuristic",
				Severity: 7,
				Title:    fmt.Sprintf("[HEURISTIC] パスワードスプレーの疑い: ソース %s が%d分内に複数の異なるアカウントでログイン失敗", sourceIP, int(authWindow/time.Minute)),
				Description: fmt.Sprintf("単一ソース %s が%d分以内に%d個の異なるアカウントに対しログイン失敗。1アカウントあたりの試行は少なく広く浅い=パスワードスプレーの疑い(単一アカウント型のブルートフォース検知が取りこぼす手口)。",
					sourceIP, int(authWindow/time.Minute), n),
				MITRETags: []string{"T1110.003"},
			})
		}
	}

	return out
}

// authSucceeded reports whether an auth event represents a successful login.
// Telemetry may express the outcome as a bool `success` or a string `action`
// ("failed"/"failure" = failure); anything else is treated as a failure only
// when an explicit failure signal is present, so an ambiguous event does not
// inflate the failure counters. An event with no failure signal counts as
// success (won't feed brute/spray).
func authSucceeded(flat map[string]interface{}) bool {
	if v, ok := flat["success"].(bool); ok {
		return v
	}
	switch act, _ := flat["action"].(string); act {
	case "failed", "failure", "fail":
		return false
	}
	if fr, _ := flat["failure_reason"].(string); fr != "" {
		return false
	}
	return true
}

// accountManagementAuthEventIDs はログオンではなく**アカウント操作**を表す
// Windows Security イベントID。ブルートフォース／スプレーの計数から外す。
//
// 4765 SID-History の付与成功 / 4766 付与失敗 (T1134.005)。
//
// 4766 は success=false を持つので、素通しすると authSucceeded() が失敗ログオンと
// して数える。**失敗の連続のあとの成功を「アカウント侵害」と判定する**のがこの
// 検知器なので、ログオンでないものを混ぜると偽の侵害アラートが出る。4648 を
// 取り込んで実際にそれを起こしたのが 2026-08-05 の実機事故である
// (agent/internal/platform/windows/auth_parse.go を参照)。
var accountManagementAuthEventIDs = map[uint64]bool{
	4765: true,
	4766: true,
}

// sigmaExposedAuthEventIDs は、Sigma の `EventID` フィールドに写してよい
// auth イベントIDの許可リスト。addPipelineSigmaAliases が参照する。
//
// ログオン系(4624/4625/4634/4672)は**入れていない**。curate は
// SupportedSigmaFields() を見て SigmaHQ の `service: security` ルールを enabled に
// しており、それらに EventID を与えると `EventID: 4624` を選ぶルール群が一斉に
// 生き返る——ログオンのたびに鳴る形が混ざるので、開けるならアラート量の実測が要る。
//
// アカウント操作(4765/4766)は正常系ではほぼ発生せず、かつ T1134.005 は
// この 2 つ以外に痕跡を残さないため、開けなければ検知手段が存在しない。
var sigmaExposedAuthEventIDs = map[uint64]bool{
	4765: true,
	4766: true,
}

// isAccountManagementAuth reports whether an auth event is an account-management
// record rather than a logon.
func isAccountManagementAuth(flat map[string]interface{}) bool {
	id, ok := toFloat64(flat["event_id"])
	if !ok {
		return false
	}
	return accountManagementAuthEventIDs[uint64(id)]
}

// pruneOlder drops timestamps at or before cutoff, preserving order.
func pruneOlder(times []int64, cutoff int64) []int64 {
	i := 0
	for i < len(times) && times[i] <= cutoff {
		i++
	}
	if i == 0 {
		return times
	}
	return append(times[:0], times[i:]...)
}

func (a *AuthAttackScorer) evictBrute(nowUnix, maxAgeSec int64) {
	for k, st := range a.brute {
		var newest int64
		for _, ts := range st.failTimes {
			if ts > newest {
				newest = ts
			}
		}
		if nowUnix-newest > maxAgeSec {
			delete(a.brute, k)
		}
	}
}

func (a *AuthAttackScorer) evictSpray(nowUnix, maxAgeSec int64) {
	for k, st := range a.spray {
		var newest int64
		for _, ts := range st.accounts {
			if ts > newest {
				newest = ts
			}
		}
		if nowUnix-newest > maxAgeSec {
			delete(a.spray, k)
		}
	}
}

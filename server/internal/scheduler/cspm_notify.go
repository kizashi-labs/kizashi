package scheduler

// 定期スキャンの結果を能動的に伝える経路。
//
// これが無いと CSPM は「誰かが画面を開いたときだけ分かる」機能のままになる。
// 24 時間おきに走らせる意味は、誰も見ていない間の変化を捕まえることなので、
// 変化を伝える先が無ければ定期実行そのものが半分しか働いていない。
//
// 送るのは「変化」か「測れなかった」だけ。異常なしの回まで毎日送ると、
// 通知は数日で読み飛ばされるようになり、本当に伝えたい回が埋もれる。
// 沈黙は「異常なし」を意味する ---ただし後述のとおり、測定経路が壊れた
// ときだけは沈黙させない。

import (
	"context"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"github.com/edr-platform/server/internal/cspm/awsscan"
	"github.com/edr-platform/server/internal/notification"
)

// Notifier は通知の送り先。*notification.Dispatcher が満たす。
// インターフェースで受けるのは、通知の判断と文面をスケジューラ側で
// テストできるようにするため (実際の送信は別の層の関心事)。
type Notifier interface {
	// Notify は送信を試み、実際に何件届いたかを返す。
	// **戻り値を捨ててはいけない** ---下の 2 つは設定の話しかしていないので、
	// 送信時に落ちたチャンネルはここでしか分からない。
	Notify(ctx context.Context, n *notification.AlertNotification) notification.NotifyResult
	// EnabledChannels は送信先の数。0 なら Notify は静かに何もしないので、
	// 呼ぶ前に確認して警告を出す。
	EnabledChannels() int
	// FailedChannels は有効なのに送信実装を作れなかったチャンネルの数。
	// 他に生きた送信先があると EnabledChannels は 0 にならないため、
	// これを見ないと「一部だけ届いていない」に気づけない。
	FailedChannels() int
}

// 通知の重大度。既存のアラートと同じ 1〜10 の尺度で、チャンネルごとの
// MinSeverity で絞り込まれる。
const (
	// sevUnmeasured は「測れなかった」。新しい high の所見 (7) より上に
	// 置いてある。所見は「見つかった 1 件」だが、未計測は「何件あるか
	// 分からない」状態だから ---権限が外れたまま放置されると、その項目は
	// 永久に「問題なし」に見え続ける。
	sevUnmeasured = 8
	// sevScanFailed はスキャン自体が失敗した場合。1 項目も測れていない。
	sevScanFailed = 8

	sevNewCritical = 9
	sevNewHigh     = 7
	sevNewMedium   = 5
	sevNewLow      = 4
)

// notifyListLimit は通知に並べる項目数の上限。全部並べると Slack で
// 折りたたまれて先頭しか読まれない。残りは画面で見てもらう。
const notifyListLimit = 5

// cspmScreenPath は CSPM の所見を表示している画面のパス。
//
// frontend/app/ の下のディレクトリ名がそのままルートになるので、
// ここを変えるときは frontend/app/cloud-security/ も一緒に見ること。
// 通知のリンクだけが取り残されると、押した先が 404 になる。
const cspmScreenPath = "/cloud-security"

// buildCSPMNotification は通知すべきことがあれば通知を組み立てる。
// 何も無ければ nil を返す。
//
// accountLabel は AWS アカウント ID (12 桁)。スキャンが失敗した場合は
// 引受ができていないので空になることがあり、そのときは内部 UUID を使う。
func buildCSPMNotification(accountUUID, dashboardURL string, out awsscan.Outcome, now time.Time) *notification.AlertNotification {
	if !out.Notable() {
		return nil
	}

	label := out.AWSAccountID
	if label == "" {
		label = accountUUID
	}

	var (
		title string
		sev   int
		body  strings.Builder
	)

	switch {
	case out.Err != nil:
		title = fmt.Sprintf("[CSPM] AWS %s のスキャンが失敗しました", label)
		sev = sevScanFailed
		body.WriteString("スキャンを完了できませんでした。**この回は 1 項目も測れていません。**\n")
		body.WriteString("画面の所見は前回の結果のままなので、現状を表していない可能性があります。\n\n")
		body.WriteString("理由: " + out.Err.Error() + "\n")

	case len(out.Unmeasured) > 0:
		title = fmt.Sprintf("[CSPM] AWS %s: 検査できなかった項目が %d 件あります", label, len(out.Unmeasured))
		sev = sevUnmeasured
		body.WriteString("次の項目は「問題なし」ではなく **「測れていない」** 状態です。\n")
		body.WriteString("多くは引受ロールの権限不足で、理由に出ている action を足せば解消します。\n\n")
		body.WriteString(formatUnmeasured(out.Unmeasured))

	default:
		title = fmt.Sprintf("[CSPM] AWS %s: 新しい所見が %d 件出ました", label, len(out.Persisted.New))
		sev = severityForNew(out.Persisted.New)
	}

	// 未計測やスキャン失敗があっても、同じ回に出た新しい所見は落とさない。
	// 別々に送ると 1 回のスキャンが 2 通になり、どちらも読まれにくくなる。
	if len(out.Persisted.New) > 0 && out.Err == nil {
		if body.Len() > 0 {
			body.WriteString("\n")
		}
		body.WriteString(fmt.Sprintf("新しい所見 %d 件:\n", len(out.Persisted.New)))
		body.WriteString(formatNewFindings(out.Persisted.New))
		if s := severityForNew(out.Persisted.New); s > sev {
			sev = s
		}
	}

	if out.Err == nil {
		// 件数は「今回のスキャンで不合格だった数」であって、アカウントが
		// 抱えている所見の総数ではない。読めなかった項目の分はここに
		// 現れない (所見自体は open のまま残っている)。
		//
		// 未計測がある回にこれをそのまま「所見 N 件」と出すと、前回の
		// 件数を知っている担当者には**減った = 改善した**と読める。
		// 実際に権限を 1 つ外した検証で、62 件が「所見 30 件」と表示された。
		// unknown を pass に寄せない設計にしておきながら、最後の 1 行で
		// 安心できる嘘を出していた。範囲を明示する。
		label := "所見"
		if len(out.Unmeasured) > 0 {
			label = "測れた範囲の所見"
		}
		body.WriteString(fmt.Sprintf("\n%s %d 件 / 解消 %d 件 / 消えた資源 %d 件 (%d リージョン, %.1f 秒)\n",
			label, out.Persisted.Upserted, out.Persisted.Resolved, out.Persisted.Disappeared,
			out.Regions, out.Duration.Seconds()))
		if len(out.Unmeasured) > 0 {
			body.WriteString("※ 未計測の項目があるため、この件数は前回と比較できません。" +
				"測れなかった項目の所見は閉じずに残しています。\n")
		}
	}

	return &notification.AlertNotification{
		AlertID:  "cspm-" + accountUUID,
		Title:    title,
		Severity: sev,
		Status:   "open",
		Hostname: "AWS " + label,
		OS:       "cloud",
		RuleName: "CSPM 定期スキャン",
		Summary:  body.String(),
		// 既定の /alerts/<id> ではなく CSPM の画面へ送る。
		// 存在しないアラート ID のリンクを踏ませない。
		//
		// 画面のパスは frontend/app/cloud-security/page.tsx。
		// "/cspm" ではない ---所見を表示しているのはこのページで、
		// /api/v1/cloud/posture を通して同じ cspm_findings を読んでいる。
		DashboardURL: strings.TrimSuffix(dashboardURL, "/") + cspmScreenPath,
		CreatedAt:    now,
	}
}

func formatUnmeasured(errs []awsscan.ScanError) string {
	var b strings.Builder
	for i, e := range errs {
		if i == notifyListLimit {
			fmt.Fprintf(&b, "  ... 他 %d 件\n", len(errs)-notifyListLimit)
			break
		}
		fmt.Fprintf(&b, "  - %s (%s): %s\n", e.CheckID, e.Region, e.Message)
	}
	return b.String()
}

func formatNewFindings(fs []awsscan.NewFinding) string {
	var b strings.Builder
	for i, f := range fs {
		if i == notifyListLimit {
			fmt.Fprintf(&b, "  ... 他 %d 件\n", len(fs)-notifyListLimit)
			break
		}
		fmt.Fprintf(&b, "  - [%s] %s — %s (%s)\n", f.Severity, f.CheckName, f.ResourceName, f.Region)
	}
	return b.String()
}

// severityForNew は新しい所見のうち最も重いものに合わせる。
// 平均や件数で決めると、critical 1 件が medium 20 件に薄められる。
func severityForNew(fs []awsscan.NewFinding) int {
	worst := 0
	for _, f := range fs {
		var s int
		switch f.Severity {
		case awsscan.SeverityCritical:
			s = sevNewCritical
		case awsscan.SeverityHigh:
			s = sevNewHigh
		case awsscan.SeverityMedium:
			s = sevNewMedium
		default:
			s = sevNewLow
		}
		if s > worst {
			worst = s
		}
	}
	return worst
}

// notifyCSPM は通知すべきことがあれば送る。
//
// 送信の失敗でスキャンを失敗扱いにはしない ---所見は既に保存されており、
// 通知が届かなかったことと検査できなかったことは別の問題。ただしログには
// 必ず残す。通知経路が壊れたまま気づかれないのが最悪なので。
func (s *CSPMScanner) notifyCSPM(ctx context.Context, accountUUID string, out awsscan.Outcome) {
	if s.notifier == nil {
		return
	}
	n := buildCSPMNotification(accountUUID, s.dashboardURL, out, time.Now())
	if n == nil {
		return
	}
	// 送信先が 0 件でも Dispatcher は静かに何もしない。定期実行は人が
	// 見ていないので、ここで言わないと「通知したつもり」のまま気づかれない。
	if s.notifier.EnabledChannels() == 0 {
		slog.Warn("CSPM(定期): 伝えるべき結果がありますが、通知チャンネルが 1 つも設定されていません",
			"account", accountUUID, "title", n.Title)
		return
	}
	// 一部のチャンネルだけ落ちている場合も言う。生きた送信先が 1 つでも
	// あれば EnabledChannels は 0 にならないので、これが無いと
	// 「届いているつもりで一部に届いていない」に気づけない。
	if failed := s.notifier.FailedChannels(); failed > 0 {
		slog.Warn("CSPM(定期): 送信先として使えない通知チャンネルがあります",
			"account", accountUUID, "failed", failed,
			"hint", "起動時の『通知チャンネルの初期化に失敗しました』を確認してください")
	}
	slog.Info("CSPM(定期): 結果を通知します",
		"account", accountUUID, "severity", n.Severity,
		"unmeasured", len(out.Unmeasured), "new", len(out.Persisted.New))

	// ここまでの 2 つの確認は「送れる設定になっているか」しか見ていない。
	// センダーが作れていても、webhook が 405 を返したり SMTP が 535 で
	// 認証を蹴ったりすれば 1 通も届かない。実際に有効 3 件のうち届いたのが
	// 1 件だけという状態が、EnabledChannels()=3 / FailedChannels()=0 の
	// まま何も言わずに通り過ぎた。送信の結末まで見て初めて言える。
	//
	// 送信の失敗そのものは Dispatcher が notification_delivery として
	// 数えて記録するので、ここでは重複させない。ここでしか言えないのは
	// 「重大度の下限で全部ふるい落とされた」場合 ---送信は 1 件も
	// 試行されず、Dispatcher から見れば失敗が 0 件だから、あちらは黙る。
	if r := s.notifier.Notify(ctx, n); r.Eligible == 0 {
		slog.Warn("CSPM(定期): 重大度が全チャンネルの下限に届かず、どこにも送られませんでした",
			"account", accountUUID, "severity", n.Severity, "title", n.Title,
			"hint", "チャンネルの最小重大度を確認してください")
	}
}

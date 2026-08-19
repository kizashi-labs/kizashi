package notification

// EmittedWebhookEvents lists every event name this notifier can ever dispatch
// to a `webhook_targets` row.
//
// **同じ一覧が3つありました。**
//
//	画面 (frontend/app/settings/webhooks/page.tsx ALL_EVENTS)
//	  alert.critical / alert.high / alert.any /
//	  incident.created / incident.updated / agent.offline
//	検査の写し (server/internal/store/webhooks_test.go)
//	  alert.created / alert.resolved / alert.any / agent.offline /
//	  agent.online / incident.created / incident.closed / ioc.matched
//	実際に送られるもの（ここ）
//	  alert.critical / alert.high / alert.any / agent.offline
//
// 検査の写しはどちらとも一致していません —— **3つ目の、誰とも合わない
// 一覧**でした。
//
// 画面が出しているもののうち `incident.created` と `incident.updated` は、
// **一度も送られません。** この通知器が購読しているのは `alerts.>` と
// `agent.events.>` だけで、インシデントを流す経路がありません。
// 担当者がインシデントだけを選ぶと、**その webhook は永久に鳴りません** ——
// 「インシデントが起きていない」と見分けが付きません。
//
// `alert.any` は問い合わせ側の特別扱いです:
//
//	WHERE $1 = ANY(events) OR 'alert.any' = ANY(events)
//
// 購読側に入っていれば、どのイベントでも一致します。
var EmittedWebhookEvents = []string{
	"alert.critical",
	"alert.high",
	"alert.any",
	"agent.offline",
}

// IsEmittedWebhookEvent reports whether the notifier can ever send this event.
func IsEmittedWebhookEvent(event string) bool {
	for _, e := range EmittedWebhookEvents {
		if e == event {
			return true
		}
	}
	return false
}

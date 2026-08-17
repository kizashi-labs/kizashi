package notification

import (
	"os"
	"regexp"
	"strings"
	"testing"
)

// 送られるイベント名の一覧が、実際の対応付けと揃っていること。
//
// **一覧と対応付けが別々にあると、片方だけが動きます。**

func TestEveryMappedEventIsListed(t *testing.T) {
	w := &WebhookNotifier{}
	subjects := []string{
		"alerts.critical", "alerts.high", "alerts.new", "alerts.medium",
		"alerts", "alerts.critical.extra", "ALERTS.CRITICAL",
	}
	for _, s := range subjects {
		got := w.alertEventType(s)
		if !IsEmittedWebhookEvent(got) {
			t.Errorf("alertEventType(%q) = %q は一覧にありません。"+
				"**一覧に無いイベントは、画面の選択肢とも照合できません**", s, got)
		}
	}
	for _, s := range []string{
		"agent.events.abc.offline", "agent.events.abc.offline.x",
	} {
		got := w.agentEventType(s)
		if got != "" && !IsEmittedWebhookEvent(got) {
			t.Errorf("agentEventType(%q) = %q は一覧にありません", s, got)
		}
	}
	// 送らないものは "" で、一覧にも入れません。
	if got := w.agentEventType("agent.events.abc.online"); got != "" {
		t.Errorf("agentEventType(online) = %q, want \"\"。"+
			"**agent.online を送る経路はありません**", got)
	}
}

// 一覧のどれもが、実際に作り出せること。
//
// **送られないものを一覧に置くと、画面の選択肢がまた増えます。**
func TestEveryListedEventIsProducible(t *testing.T) {
	w := &WebhookNotifier{}
	produced := map[string]bool{}
	for _, s := range []string{"alerts.critical", "alerts.high", "alerts.new"} {
		produced[w.alertEventType(s)] = true
	}
	produced[w.agentEventType("agent.events.abc.offline")] = true

	for _, e := range EmittedWebhookEvents {
		if !produced[e] {
			t.Errorf("%q は一覧にありますが、作り出せません。"+
				"**画面がそれを出すと、選んだ人には永久に届きません**", e)
		}
	}
}

// 画面が出す選択肢が、送られるイベントに収まっていること。
//
// **build tag も skip もありません。** 画面のファイルが読めなければ
// 落とします —— 読めないことを「一致した」と同じ結果にはしません。
func TestTheConsoleOffersOnlyEventsThatAreSent(t *testing.T) {
	const path = "../../../frontend/app/settings/webhooks/page.tsx"
	src, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("%s を読めません: %v。**画面の選択肢と照合できません**", path, err)
	}

	block := regexp.MustCompile(`(?s)const ALL_EVENTS = \[(.*?)\n\]`).FindSubmatch(src)
	if block == nil {
		t.Fatal("ALL_EVENTS が見つかりません。改名したのならこの検査も直してください")
	}
	values := regexp.MustCompile(`value:\s*'([^']+)'`).FindAllStringSubmatch(string(block[1]), -1)
	if len(values) == 0 {
		t.Fatal("ALL_EVENTS から選択肢を読み取れません")
	}

	var offeredButNeverSent []string
	for _, m := range values {
		if !IsEmittedWebhookEvent(m[1]) {
			offeredButNeverSent = append(offeredButNeverSent, m[1])
		}
	}
	if len(offeredButNeverSent) > 0 {
		t.Errorf("画面が出しているのに一度も送られないイベント: %s。"+
			"**選んだ担当者の webhook は永久に鳴りません** —— "+
			"「何も起きていない」と見分けが付きません",
			strings.Join(offeredButNeverSent, ", "))
	}
}

// 送られないイベントに、はっきり「送られない」と答えること。
//
// **これが無いと、判定が「何でも送られる」になっても気づけません** ——
// 画面の選択肢との照合は素通りし、また鳴らない選択肢が並びます
// （変異で1件生き残って分かりました）。
func TestIsEmittedWebhookEventSaysNo(t *testing.T) {
	for _, e := range []string{
		// 画面が出していて、送られなかったもの。
		"incident.created", "incident.updated",
		// 検査の写しにあって、どこにも無かったもの。
		"alert.created", "alert.resolved", "incident.closed",
		"ioc.matched", "agent.online",
		// そもそも別物。
		"webhook.test", "", "alert", "ALERT.ANY",
	} {
		if IsEmittedWebhookEvent(e) {
			t.Errorf("IsEmittedWebhookEvent(%q) = true。"+
				"**送られないものを「送られる」と答えると、画面が"+
				"それを選択肢に出せてしまいます**", e)
		}
	}
}

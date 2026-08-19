package main

import (
	"os"
	"regexp"
	"strings"
	"testing"
)

// The enrichment is only worth anything if the batching loop actually calls it.
//
// Everything else about the parent and the container context is covered by
// tests on ParentResolver and ContainerContext, and by the server-side gates on
// raw_data — but all of those pass with a resolver that is constructed and never
// used, which is a single deleted line away. Those fields would then be empty
// on every event the agent sends, the server would fall back to reconstructing
// the parent from ppid and would see no containers at all, and the outcome
// would look exactly like the state this work set out to fix: quiet, plausible,
// and wrong. Asserted structurally because the batching loop is a 300-line
// select over a dozen channels with no seam to test through.
func TestTheBatchingLoopEnrichesProcessEvents(t *testing.T) {
	b, err := os.ReadFile("main.go")
	if err != nil {
		t.Fatalf("read main.go: %v", err)
	}
	src := stripComments(string(b))

	if !strings.Contains(src, "collector.NewParentResolver()") {
		t.Fatal("ParentResolver を生成していません")
	}

	// The fill must happen on the process-event path.
	i := strings.Index(src, "case evt := <-processChan:")
	if i < 0 {
		t.Fatal("プロセスイベントの受信箇所が見つかりません")
	}
	branch := src[i:]
	if j := strings.Index(branch, "case evt := <-"); j > 0 {
		branch = branch[:j]
	}
	if !regexp.MustCompile(`parents\.EnrichProcess\(&evt\)`).MatchString(branch) {
		t.Error("プロセスイベントの受信時に parents.EnrichProcess を呼んでいません。" +
			"親プロセスは全イベントで空になり、コンテナ情報も付きません — " +
			"サーバ側は ppid からの再構成にフォールバックし、" +
			"コンテナ検知は直す前と同じく全滅します")
	}

	// And everything the endpoint resolved must reach the wire. Each of these
	// was read by the server off a key nothing wrote.
	for _, field := range []string{
		"ParentName:  p.ParentName",
		"ParentImage: p.ParentImage",
		"ContainerId:          p.Container.ID",
		"ContainerPrivileged:  p.Container.Privileged",
		"ContainerHostNetwork: p.Container.HostNetwork",
	} {
		if !strings.Contains(src, field) {
			t.Errorf("proto 変換で %s を設定していません。"+
				"エンドポイントで解決した値がサーバに届きません", field)
		}
	}
}

// stripComments removes Go comments before a source scan, so a comment
// describing the call is not mistaken for the call.
func stripComments(src string) string {
	src = regexp.MustCompile(`(?s)/\*.*?\*/`).ReplaceAllString(src, "")
	return regexp.MustCompile(`(?m)(^|[^:])//.*$`).ReplaceAllString(src, "$1")
}

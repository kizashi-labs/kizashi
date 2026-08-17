package store_test

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/edr-platform/server/internal/store"
)

// 待ち行列コマンドの Args の既定値。
//
// **検査ファイルには、`Create` の置き換えを検査の中で書き直したものが
// 置いてありました** —— `if in.Args == nil { in.Args = "{}" }` を本文で
// 実行して、そのあと `"{}"` になったことを確かめる。**製品を1行も
// 通りません。** 本物を当てます。
//
// `args` は jsonb 列で NOT NULL です。nil のまま入れると書き込みが失敗し、
// **コマンドが待ち行列に載りません** —— 画面からは、エージェントが
// 応答していないのと同じ姿になります。

func TestCreateFillsArgsWithEmptyObject(t *testing.T) {
	db := covTestDB(t)
	ctx := context.Background()
	const agentID = "44444444-4444-4444-4444-444444444444"

	exec := func(sql string, args ...any) {
		t.Helper()
		if _, err := db.Pool().Exec(ctx, sql, args...); err != nil {
			t.Fatalf("%s: %v", sql, err)
		}
	}
	exec(`INSERT INTO agents (id, hostname, os_type, status)
	      VALUES ($1::uuid, 'lr-probe', 'linux', 'online')
	      ON CONFLICT (id) DO NOTHING`, agentID)
	t.Cleanup(func() {
		_, _ = db.Pool().Exec(ctx, "DELETE FROM live_response_commands WHERE agent_id=$1::uuid", agentID)
		_, _ = db.Pool().Exec(ctx, "DELETE FROM agents WHERE id=$1::uuid", agentID)
	})

	s := store.NewCmdQueueStore(db.Pool())

	// Args を指定しない。**製品が "{}" を入れます。**
	got, err := s.Create(ctx, store.CreateQueuedCommandInput{
		AgentID: agentID, CommandType: "shell", Command: "ls",
	})
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if string(got.Args) != "{}" {
		t.Errorf("Args = %q, want \"{}\"。**jsonb は NOT NULL なので、"+
			"nil のままだと書き込みが落ち、コマンドが待ち行列に載りません**",
			string(got.Args))
	}

	// 指定した Args は、そのまま残ること。
	want := json.RawMessage(`{"pid": 1234}`)
	got, err = s.Create(ctx, store.CreateQueuedCommandInput{
		AgentID: agentID, CommandType: "kill_process", Command: "kill", Args: want,
	})
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	var round map[string]any
	if err := json.Unmarshal(got.Args, &round); err != nil {
		t.Fatalf("Args を読めません (%q): %v", got.Args, err)
	}
	if round["pid"] != float64(1234) {
		t.Errorf("指定した Args が失われています: %q", got.Args)
	}
}

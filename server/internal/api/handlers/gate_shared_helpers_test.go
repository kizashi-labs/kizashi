package handlers

import (
	"context"
	"go/ast"
	"os"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"
)

// ここは**共有ヘルパだけ**を置いています。
//
// 本流の部分同期 (#52) が持ち込んだ「正直さの台帳」ゲート一式は、本流の木に
// 較正されていてこのエディションでは数も一覧も合わないため、別 PR に分けました。
// ただし退避したファイルのうち 2 本が、残るテストから使われるヘルパを定義して
// いました。そこだけをここに移しています。
//
// **台帳ゲートを戻す PR では、あちら側のローカル定義を消してここを使うこと。**
// 両方に置くと重複定義でビルドが通りません。

// answersWithSuccess — その関数が 200/201/202 で答えるか。
// （元: discarded_write_test.go）
func answersWithSuccess(body *ast.BlockStmt) bool {
	found := false
	ast.Inspect(body, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok || len(call.Args) < 1 || found {
			return true
		}
		sel, ok := call.Fun.(*ast.SelectorExpr)
		if !ok || sel.Sel.Name != "JSON" {
			return true
		}
		st, ok := call.Args[0].(*ast.SelectorExpr)
		if !ok {
			return true
		}
		switch st.Sel.Name {
		case "StatusOK", "StatusCreated", "StatusAccepted":
			found = true
		}
		return true
	})
	return found
}

// exportPool — TEST_DATABASE_URL への接続。未設定なら Skip。
// （元: export_types_executable_test.go）
func exportPool(t *testing.T) *pgxpool.Pool {
	t.Helper()
	dsn := os.Getenv("TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("TEST_DATABASE_URL not set - skipping DB integration tests")
	}
	pool, err := pgxpool.New(context.Background(), dsn)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	t.Cleanup(pool.Close)
	return pool
}

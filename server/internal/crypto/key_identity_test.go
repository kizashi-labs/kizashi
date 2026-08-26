package tenantcrypto

import (
	"context"
	"errors"
	"go/ast"
	"go/parser"
	"go/printer"
	"go/token"
	"strings"
	"testing"
)

// 読めなかった鍵と、まだ無い鍵。
//
// GetKey は以前こう書かれていました:
//
//	err := s.db.QueryRow(ctx, query, tenantID).Scan(&encryptedKey)
//	if err != nil {
//	    // No row — generate and persist a fresh key.
//	    return s.createAndStoreKey(ctx, tenantID)
//	}
//
// コメントは「行が無い」ですが、条件は「どんな失敗でも」です。接続が一瞬
// 切れただけで新しい鍵が作られ、その鍵で暗号化が行われます。INSERT は
// ON CONFLICT DO NOTHING なので、保存済みの鍵はそのまま残ります。つまり
// 呼び出し側が受け取るのは、データベースのどこにも無い鍵です。それで
// 書いたデータは、あとから誰にも復号できません。
//
// 失敗する経路そのものはデータベースが要るので、ここでは形を留めます ——
// pgx.ErrNoRows とそれ以外が別の道に行くこと、そして鍵を作ったあとに
// 保存されたほうを読み直すこと。

func TestGetKeyDistinguishesAbsenceFromFailure(t *testing.T) {
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, "tenant_crypto.go", nil, parser.ParseComments)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}

	var getKey *ast.FuncDecl
	for _, d := range f.Decls {
		fn, ok := d.(*ast.FuncDecl)
		if !ok || fn.Name.Name != "GetKey" || fn.Recv == nil {
			continue
		}
		if star, ok := fn.Recv.List[0].Type.(*ast.StarExpr); ok {
			if id, ok := star.X.(*ast.Ident); ok && id.Name == "DBKeyStore" {
				getKey = fn
			}
		}
	}
	if getKey == nil {
		t.Fatal("DBKeyStore.GetKey が見つかりません。走査が届いていません")
	}

	var creates, propagates, checksNoRows int
	ast.Inspect(getKey.Body, func(n ast.Node) bool {
		is, ok := n.(*ast.IfStmt)
		if !ok {
			return true
		}
		cond := exprString(fset, is.Cond)
		if strings.Contains(cond, "pgx.ErrNoRows") {
			checksNoRows++
			if bodyString(fset, is.Body) != "" && strings.Contains(bodyString(fset, is.Body), "createAndStoreKey") {
				creates++
			}
			return true
		}
		if strings.Contains(cond, "err != nil") {
			b := bodyString(fset, is.Body)
			if strings.Contains(b, "createAndStoreKey") {
				t.Error("行が無いかどうかを見ずに新しい鍵を作っています。" +
					"読めなかっただけで、DB に無い鍵で暗号化することになります")
			}
			if strings.Contains(b, "return nil,") {
				propagates++
			}
		}
		return true
	})

	if checksNoRows == 0 {
		t.Error("pgx.ErrNoRows を見ていません。「まだ無い」と「読めなかった」が同じ扱いです")
	}
	if creates == 0 {
		t.Error("行が無いときに鍵を作る道がありません")
	}
	if propagates == 0 {
		t.Error("読めなかったときにエラーを返す道がありません")
	}
}

// 作ったあとは、保存されたほうを読み直すこと。ON CONFLICT DO NOTHING なので、
// 同時に2つ来たら片方の鍵しか入りません。生成したほうを返すと、負けた側は
// DB に無い鍵を持ちます。
func TestCreateAndStoreKeyReturnsWhatIsStored(t *testing.T) {
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, "tenant_crypto.go", nil, 0)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	var fn *ast.FuncDecl
	for _, d := range f.Decls {
		if x, ok := d.(*ast.FuncDecl); ok && x.Name.Name == "createAndStoreKey" {
			fn = x
		}
	}
	if fn == nil {
		t.Fatal("createAndStoreKey が見つかりません")
	}
	body := bodyString(fset, fn.Body)
	if !strings.Contains(body, "SELECT encrypted_key FROM tenant_encryption_keys") {
		t.Error("保存後に読み直していません。ON CONFLICT DO NOTHING で負けた側は、" +
			"データベースに無い鍵を受け取ります")
	}
}

// The in-memory store is the one path a unit test can drive end to end.
func TestInMemoryKeyIsStableAcrossCalls(t *testing.T) {
	s := NewInMemoryKeyStore()
	ctx := context.Background()
	a, err := s.GetKey(ctx, "t1")
	if err != nil {
		t.Fatalf("GetKey: %v", err)
	}
	b, err := s.GetKey(ctx, "t1")
	if err != nil {
		t.Fatalf("GetKey: %v", err)
	}
	if string(a) != string(b) {
		t.Error("同じテナントに2つの鍵を返しています。片方で書いたものは復号できません")
	}
	if err := s.RotateKey(ctx, "t1"); err != nil {
		t.Fatalf("RotateKey: %v", err)
	}
	c, err := s.GetKey(ctx, "t1")
	if err != nil {
		t.Fatalf("GetKey: %v", err)
	}
	if string(c) == string(a) {
		t.Error("ローテーションしても鍵が変わっていません")
	}
	_ = errors.New
}

func exprString(fset *token.FileSet, e ast.Expr) string { return nodeString(fset, e) }

func bodyString(fset *token.FileSet, b *ast.BlockStmt) string {
	if b == nil {
		return ""
	}
	return nodeString(fset, b)
}

func nodeString(fset *token.FileSet, n ast.Node) string {
	var sb strings.Builder
	if err := printer.Fprint(&sb, fset, n); err != nil {
		return ""
	}
	return sb.String()
}

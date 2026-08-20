// このファイルは、複数の走査ゲートが共有する AST の道具を置く場所です。
//
// **判定そのものを持つファイルには置かないこと。** 置くと、その 1 本を外した
// 配置（オープンソース版はラチェットを外します）で、共有している側が
// undefined になってコンパイルごと落ちます。実際に落ちました。
package handlers

import "go/ast"

// answersWithSuccess — その関数が 200/201/202 で答えるか。
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

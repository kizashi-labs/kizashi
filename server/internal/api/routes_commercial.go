package api

import "github.com/gin-gonic/gin"

// registerCommercialRoutes is the open source edition's no-op.
//
// ─── 公開版向けの差し替え（scripts/public-snapshot/overlay） ──────────────
//
// 本流の同名ファイルは、有償版だけが持つ経路の登録関数を呼ぶ。公開版には
// その実装（internal/saml, internal/oidc, …）が無いので、呼び出しごと空にする。
//
// **これが router.go を削らずに済ませるための継ぎ目。** 以前の公開版は router.go
// (5,985 行) と cmd/api/main.go (2,317 行) の**全文コピー**を overlay に持ち、
// 本流のどちらかが動くたびに全文をコピーし直してトリムしていた。維持コストが
// 差分の大小と無関係だったのはそのためで、実際 #813 の suppression 撤去に追随
// できず公開版はビルド不能のまま放置された（#842 で修復）。
//
// さらに、手作業のトリムは**必要以上に削っていた**。有償でも何でもない 3 経路
// （GET /ws/billing、POST /api/v1/cloud/findings/import、
// PUT /api/v1/admin/cspm-enhanced/accounts/{id}/credentials）が公開版から
// 落ちており、全文コピーをやめた時点で自然に戻った。
//
// 差し替えるのはこのファイルと wire_commercial.go / handlers_commercial.go の
// 3 つだけで、中身は「呼び出しの有無」しかない。本流で router.go や main.go が
// どれだけ動いても、ここは追随しなくてよい。

func (s *Server) registerCommercialRoutes(_, _ *gin.RouterGroup) {}

// alerts / rules グループの内側に混ざっていた有償ルート（AI 再分析・AI ルール
// 生成）の継ぎ目。公開版には AI ハンドラが無いので何も登録しない。
func (s *Server) registerCommercialAlertRoutes(_ *gin.RouterGroup) {}

func (s *Server) registerCommercialRuleRoutes(_ *gin.RouterGroup) {}

// routes_noncore.go — 公開版スタブ。
//
// 本流の同名ファイルは Free 版が同梱しないルート登録の束。この版はそれらの
// ハンドラを同梱しないため、登録は何も行わない。
package api

import "github.com/gin-gonic/gin"

func (s *Server) registerNoncoreRoutes(_, _ *gin.RouterGroup) {}

func (s *Server) registerPlatformUpgradeRoutes(_ *gin.RouterGroup) {}

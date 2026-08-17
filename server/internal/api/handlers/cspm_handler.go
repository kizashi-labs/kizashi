package handlers

import (
	"net/http"

	"github.com/edr-platform/server/internal/cspm"
	"github.com/gin-gonic/gin"
)

type CSPMHandler struct {
	checker *cspm.Checker
}

func NewCSPMHandler(checker *cspm.Checker) *CSPMHandler {
	return &CSPMHandler{checker: checker}
}

// Scan runs a CSPM scan
// POST /api/v1/admin/cspm/scan
//
// 注意: このハンドラはルーターに登録されていない。cspm.Checker の各チェックは
// クラウドへ接続せず、呼び出し元が渡す cfg.Settings を読むだけなので、
// 「設定値を渡すと判定してくれる」評価器であってスキャナではない。
//
// 以前はリクエストが空 (または不正) のとき、AWS アカウント 123456789012 の
// 「ルート MFA 無効・SSH 全開放・EBS 未暗号化」という設定値を勝手に埋めて
// 判定していた。誰も検査していないアカウントの不合格所見が返ることになり、
// 万一ルーティングされれば実所見と区別が付かない。判定材料が無いときは
// 判定せず 400 を返す。
func (h *CSPMHandler) Scan(c *gin.Context) {
	var cfg cspm.ProviderConfig
	if err := c.ShouldBindJSON(&cfg); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "検査対象の設定 (provider / account_id / settings) を指定してください",
		})
		return
	}
	if len(cfg.Settings) == 0 {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "settings が空です。各チェックは settings の値だけを見るため、" +
				"空のまま実行すると全項目が既定側 (多くは不合格) に倒れます",
		})
		return
	}

	result, err := h.checker.Scan(c.Request.Context(), cfg)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": dbErrMsg(err)})
		return
	}
	c.JSON(http.StatusOK, result)
}

// GetLastScans returns last scan results for all providers
// GET /api/v1/admin/cspm/scans
func (h *CSPMHandler) GetLastScans(c *gin.Context) {
	provider := c.Query("provider")
	if provider != "" {
		result := h.checker.GetLastScan(provider)
		if result == nil {
			c.JSON(http.StatusOK, gin.H{"message": "スキャン結果がありません"})
			return
		}
		c.JSON(http.StatusOK, result)
		return
	}
	results := h.checker.GetAllLastScans()
	c.JSON(http.StatusOK, gin.H{"scans": results, "count": len(results)})
}

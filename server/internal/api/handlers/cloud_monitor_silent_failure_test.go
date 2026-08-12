package handlers_test

// クラウド連携の更新・削除が「成功したふり」をしないこと。
//
// 以前は pool.Exec の戻り値を捨てて無条件に 200 を返していた:
//
//	h.pool.Exec(ctx, `UPDATE cloud_integrations SET enabled=$1 WHERE id=$2`, ...)
//	c.JSON(http.StatusOK, gin.H{"status": "updated"})
//
// UPDATE/DELETE が 1 行も更新しなくても画面には「更新しました」と出る。
// 消えた連携をいつまでも編集でき、失敗したことに誰も気付かない。
//
// errcheck が指摘していた「戻り値を捨てる」系のうち、実害が出ていた箇所。

import (
	"net/http"
	"testing"

	"github.com/edr-platform/server/internal/api/handlers"
	"github.com/gin-gonic/gin"
)

// 存在しない連携 ID。uuid 形式でないと型エラーで 500 になり、
// 「行が無い」ケースを検証できないので実在しない uuid を使う。
const missingIntegrationID = "00000000-0000-0000-0000-0000000000ff"

// TestUpdateIntegration_MissingIDIsNotFound は存在しない ID の更新が
// 404 になること。200 を返すと「更新できた」と誤認させる。
func TestUpdateIntegration_MissingIDIsNotFound(t *testing.T) {
	db := testDB(t)
	h := handlers.NewCloudMonitorHandler(db.Pool())
	r, _ := authRouter(t, db)
	r.PATCH("/cm/:id", h.UpdateIntegration)

	enabled := true
	w := jsonReq(r, http.MethodPatch, "/cm/"+missingIntegrationID, gin.H{"enabled": enabled})
	if w.Code != http.StatusNotFound {
		t.Errorf("status = %d, want 404 (存在しない連携に成功を返している). body=%s", w.Code, w.Body.String())
	}
}

// TestDeleteIntegration_MissingIDIsNotFound は存在しない ID の削除が
// 404 になること。
func TestDeleteIntegration_MissingIDIsNotFound(t *testing.T) {
	db := testDB(t)
	h := handlers.NewCloudMonitorHandler(db.Pool())
	r, _ := authRouter(t, db)
	r.DELETE("/cm/:id", h.DeleteIntegration)

	w := jsonReq(r, http.MethodDelete, "/cm/"+missingIntegrationID, nil)
	if w.Code != http.StatusNotFound {
		t.Errorf("status = %d, want 404 (存在しない連携に成功を返している). body=%s", w.Code, w.Body.String())
	}
}

// TestUpdateIntegration_ExistingIDSucceeds は実在する連携の更新が
// 通ること。404 化で正常系を壊していないことの確認。
func TestUpdateIntegration_ExistingIDSucceeds(t *testing.T) {
	db := testDB(t)
	h := handlers.NewCloudMonitorHandler(db.Pool())
	r, _ := authRouter(t, db)
	r.POST("/cm", h.CreateIntegration)
	r.PATCH("/cm/:id", h.UpdateIntegration)

	id := mutID(t, r, "/cm", gin.H{
		"name": "itest-cm-silent", "provider": "aws",
		"region": "us-east-1", "config": gin.H{},
	})

	w := jsonReq(r, http.MethodPatch, "/cm/"+id, gin.H{"enabled": false})
	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want 200. body=%s", w.Code, w.Body.String())
	}
}

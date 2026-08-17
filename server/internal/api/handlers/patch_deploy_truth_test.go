package handlers

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/jackc/pgx/v5/pgxpool"
)

// Deploying a patch reported that every agent had been patched.
//
// The handler inserted a 'pending' result per agent, then immediately ran:
//
//	UPDATE patch_deployment_results
//	SET status='success', ..., updated_at=$2
//
// patch_deployment_results has no updated_at column, so that failed with 42703
// into a Warn and the rows stayed pending. Removing the missing column — the
// obvious reading of the defect — would have made the claim work instead of
// removing it, because nothing in this repository applies a patch:
//
//	no agent code subscribes to patch.deploy.start
//	nothing writes patch_deployment_results but the INSERT in Deploy
//	no endpoint exists for an agent to report an outcome
//
// GetSummary divides successful results by total and successful agents by all
// agents, so every deployment would have produced a 100% success rate and full
// patch coverage for patches that were never applied. On an EDR product that
// number is one a customer acts on.
//
// These gates pin the honest states: dispatched, results pending, and a
// summary that does not credit anyone with a patch.

func patchPool(t *testing.T) *pgxpool.Pool {
	t.Helper()
	return exportPool(t) // same TEST_DATABASE_URL plumbing
}

// patchFixture seeds an agent and a deployment targeting it.
func patchFixture(t *testing.T) (*PatchHandler, *pgxpool.Pool, string, string) {
	t.Helper()
	pool := patchPool(t)
	ctx := context.Background()

	var agentID string
	if err := pool.QueryRow(ctx, `
		INSERT INTO agents (hostname, os_type, agent_version, status)
		VALUES ('patch-truth-host', 'linux', '1.0.0', 'online')
		RETURNING id::text`).Scan(&agentID); err != nil {
		t.Fatalf("seed agent: %v", err)
	}

	var deployID string
	if err := pool.QueryRow(ctx, `
		INSERT INTO patch_deployments (name, description, patch_type, severity, status, target_agents, target_os)
		VALUES ('patch-truth', 'd', 'os', 'high', 'scheduled', $1::jsonb, 'all')
		RETURNING id::text`, `["`+agentID+`"]`).Scan(&deployID); err != nil {
		t.Fatalf("seed deployment: %v", err)
	}

	t.Cleanup(func() {
		bg := context.Background()
		_, _ = pool.Exec(bg, `DELETE FROM patch_deployment_results WHERE deployment_id=$1`, deployID)
		_, _ = pool.Exec(bg, `DELETE FROM patch_deployments WHERE id=$1`, deployID)
		_, _ = pool.Exec(bg, `DELETE FROM agents WHERE id=$1::uuid`, agentID)
	})

	return &PatchHandler{pool: pool}, pool, deployID, agentID
}

// deploy invokes the deploy endpoint for one deployment.
func deploy(t *testing.T, h *PatchHandler, deployID string) (int, map[string]interface{}) {
	t.Helper()
	gin.SetMode(gin.TestMode)
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = httptest.NewRequest(http.MethodPost, "/api/v1/patches/"+deployID+"/deploy", nil)
	c.Params = gin.Params{{Key: "id", Value: deployID}}
	h.DeployNow(c)

	var decoded map[string]interface{}
	if w.Body.Len() > 0 {
		_ = json.Unmarshal(w.Body.Bytes(), &decoded)
	}
	return w.Code, decoded
}

// Dispatching must not mark any agent as patched.
func TestDeployingDoesNotClaimAgentsArePatched(t *testing.T) {
	h, pool, deployID, _ := patchFixture(t)

	if code, body := deploy(t, h, deployID); code != http.StatusOK {
		t.Fatalf("配信が %d を返しました: %v", code, body)
	}

	rows, err := pool.Query(context.Background(),
		`SELECT status FROM patch_deployment_results WHERE deployment_id=$1`, deployID)
	if err != nil {
		t.Fatalf("read results: %v", err)
	}
	defer rows.Close()

	n := 0
	for rows.Next() {
		var status string
		if err := rows.Scan(&status); err != nil {
			t.Fatalf("scan: %v", err)
		}
		n++
		if status != "pending" {
			t.Errorf("配信直後のエージェント結果が %q です。"+
				"適用を確認したエージェントは存在しません", status)
		}
	}
	if n == 0 {
		t.Fatal("結果行が作成されていません")
	}
}

// The deployment itself must not be called completed.
func TestADispatchedDeploymentIsNotCalledCompleted(t *testing.T) {
	h, pool, deployID, _ := patchFixture(t)

	deploy(t, h, deployID)

	var status string
	if err := pool.QueryRow(context.Background(),
		`SELECT status FROM patch_deployments WHERE id=$1`, deployID).Scan(&status); err != nil {
		t.Fatalf("read deployment: %v", err)
	}
	if status == "completed" {
		t.Error("配信しただけのデプロイメントが completed になりました。" +
			"適用を報告した経路は存在しません")
	}
	if status != "deploying" {
		t.Errorf("デプロイメントの状態が %q、期待は deploying", status)
	}
}

// The response must not tell the caller the deployment finished.
func TestTheDeployResponseDoesNotClaimCompletion(t *testing.T) {
	h, _, deployID, _ := patchFixture(t)

	_, body := deploy(t, h, deployID)

	if msg, _ := body["message"].(string); msg == "" {
		t.Fatal("レスポンスに message がありません")
	} else if strings.Contains(msg, "complete") {
		t.Errorf("レスポンスが完了を主張しています: %q", msg)
	}
	if s, _ := body["status"].(string); s == "completed" {
		t.Errorf("レスポンスの status が completed です")
	}
}

// The summary must not credit anyone with a patch that was only dispatched.
// This is the number the fabrication would have inflated.
func TestTheSummaryDoesNotCreditDispatchAsCoverage(t *testing.T) {
	h, pool, deployID, agentID := patchFixture(t)

	deploy(t, h, deployID)

	var successForAgent int
	if err := pool.QueryRow(context.Background(),
		`SELECT COUNT(*) FROM patch_deployment_results
		 WHERE agent_id=$1 AND status='success'`, agentID).Scan(&successForAgent); err != nil {
		t.Fatalf("count: %v", err)
	}
	if successForAgent != 0 {
		t.Errorf("配信しただけで %d 件の success が記録されました。"+
			"パッチ適用率とカバレッジが実態より高く出ます", successForAgent)
	}

	// And the deployment's own result rows are all pending, so a success rate
	// computed over them is 0 rather than 100.
	var total, success int
	if err := pool.QueryRow(context.Background(),
		`SELECT COUNT(*), COALESCE(SUM(CASE WHEN status='success' THEN 1 ELSE 0 END),0)
		 FROM patch_deployment_results WHERE deployment_id=$1`, deployID).Scan(&total, &success); err != nil {
		t.Fatalf("count: %v", err)
	}
	if total == 0 || success != 0 {
		t.Errorf("結果 %d 件のうち %d 件が success です", total, success)
	}
}

// Dispatching twice must not duplicate the per-agent rows.
func TestDeployingTwiceDoesNotDuplicateResults(t *testing.T) {
	h, pool, deployID, _ := patchFixture(t)

	deploy(t, h, deployID)
	deploy(t, h, deployID)

	var n int
	if err := pool.QueryRow(context.Background(),
		`SELECT COUNT(*) FROM patch_deployment_results WHERE deployment_id=$1`, deployID).Scan(&n); err != nil {
		t.Fatalf("count: %v", err)
	}
	if n != 1 {
		t.Errorf("2回配信して結果が %d 行になりました (期待 1)", n)
	}
}

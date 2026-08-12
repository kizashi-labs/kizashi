package handlers

import (
	"errors"
	"net/http"

	"github.com/edr-platform/server/internal/store"
	"github.com/gin-gonic/gin"
)

// CustomAlertRulesHandler handles custom alert rule endpoints.
type CustomAlertRulesHandler struct {
	store *store.CustomAlertRuleStore

	// onRulesChanged は書き込み後に検知パイプラインへ再読み込みを促す。
	// これが無いと、UI で作ったルールが API 再起動まで効かない
	// (SigmaRulesHandler と同じ仕組み)。
	onRulesChanged func()
}

// NewCustomAlertRulesHandler creates a new CustomAlertRulesHandler.
func NewCustomAlertRulesHandler(s *store.CustomAlertRuleStore) *CustomAlertRulesHandler {
	return &CustomAlertRulesHandler{store: s}
}

// SetReloadFunc registers a callback invoked after any rule write.
func (h *CustomAlertRulesHandler) SetReloadFunc(fn func()) {
	h.onRulesChanged = fn
}

// notifyChanged は登録されていれば再読み込みを呼ぶ。
func (h *CustomAlertRulesHandler) notifyChanged() {
	if h.onRulesChanged != nil {
		h.onRulesChanged()
	}
}

// List returns all custom alert rules.
func (h *CustomAlertRulesHandler) List(c *gin.Context) {
	rules, err := h.store.List(c.Request.Context())
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": dbErrMsg(err)})
		return
	}
	c.JSON(http.StatusOK, gin.H{"rules": rules})
}

// Create inserts a new custom alert rule.
func (h *CustomAlertRulesHandler) Create(c *gin.Context) {
	var in store.CreateCustomAlertRuleInput
	if err := c.ShouldBindJSON(&in); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	rule, err := h.store.Create(c.Request.Context(), in)
	if err != nil {
		if isConstraintViolation(err) {
			c.JSON(http.StatusBadRequest, gin.H{"error": "入力値が制約に違反しています（severity は 1〜10 で指定してください）"})
			return
		}
		c.JSON(http.StatusInternalServerError, gin.H{"error": dbErrMsg(err)})
		return
	}
	h.notifyChanged()
	c.JSON(http.StatusCreated, rule)
}

// Get returns a single custom alert rule by ID.
func (h *CustomAlertRulesHandler) Get(c *gin.Context) {
	id := c.Param("id")
	rule, err := h.store.Get(c.Request.Context(), id)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, rule)
}

// Update modifies an existing custom alert rule.
func (h *CustomAlertRulesHandler) Update(c *gin.Context) {
	id := c.Param("id")
	var in store.UpdateCustomAlertRuleInput
	if err := c.ShouldBindJSON(&in); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	rule, err := h.store.Update(c.Request.Context(), id, in)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			c.JSON(http.StatusNotFound, gin.H{"error": "カスタムアラートルールが見つかりません"})
			return
		}
		if isConstraintViolation(err) {
			c.JSON(http.StatusBadRequest, gin.H{"error": "入力値が制約に違反しています（severity は 1〜10 で指定してください）"})
			return
		}
		c.JSON(http.StatusInternalServerError, gin.H{"error": dbErrMsg(err)})
		return
	}
	h.notifyChanged()
	c.JSON(http.StatusOK, rule)
}

// Delete removes a custom alert rule by ID.
func (h *CustomAlertRulesHandler) Delete(c *gin.Context) {
	id := c.Param("id")
	if err := h.store.Delete(c.Request.Context(), id); err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": err.Error()})
		return
	}
	h.notifyChanged()
	c.JSON(http.StatusNoContent, nil)
}

// Toggle flips the enabled state of a custom alert rule.
func (h *CustomAlertRulesHandler) Toggle(c *gin.Context) {
	id := c.Param("id")
	rule, err := h.store.Toggle(c.Request.Context(), id)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": err.Error()})
		return
	}
	h.notifyChanged()
	c.JSON(http.StatusOK, rule)
}

package handlers

import (
	"net/http"

	"github.com/edr-platform/server/internal/support"
	"github.com/gin-gonic/gin"
)

// SupportHandler はサポートチケット関連のエンドポイントを提供する。
type SupportHandler struct {
	store *support.Store
}

// NewSupportHandler は SupportHandler を返す。
func NewSupportHandler(store *support.Store) *SupportHandler {
	return &SupportHandler{store: store}
}

// ListTickets GET /api/v1/support/tickets
func (h *SupportHandler) ListTickets(c *gin.Context) {
	userIDVal, _ := c.Get("user_id")
	userID, _ := userIDVal.(string)
	roleVal, _ := c.Get("user_role")
	role, _ := roleVal.(string)
	isAdmin := role == "admin"

	f := support.TicketFilter{
		Status:   c.Query("status"),
		Priority: c.Query("priority"),
		Category: c.Query("category"),
		Search:   c.Query("search"),
	}

	tickets, err := h.store.ListTickets(c.Request.Context(), f, isAdmin, userID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": dbErrMsg(err)})
		return
	}
	if tickets == nil {
		tickets = []*support.Ticket{}
	}
	c.JSON(http.StatusOK, tickets)
}

// GetTicket GET /api/v1/support/tickets/:id
func (h *SupportHandler) GetTicket(c *gin.Context) {
	id := c.Param("id")
	tk, err := h.store.GetTicket(c.Request.Context(), id)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "ticket not found"})
		return
	}
	// 非管理者は自分のチケットのみ参照可能
	roleVal, _ := c.Get("user_role")
	role, _ := roleVal.(string)
	if role != "admin" {
		userIDVal, _ := c.Get("user_id")
		userID, _ := userIDVal.(string)
		if tk.CreatedBy == nil || *tk.CreatedBy != userID {
			c.JSON(http.StatusForbidden, gin.H{"error": "forbidden"})
			return
		}
	}
	c.JSON(http.StatusOK, tk)
}

// CreateTicket POST /api/v1/support/tickets
func (h *SupportHandler) CreateTicket(c *gin.Context) {
	var req struct {
		Title       string `json:"title"       binding:"required"`
		Description string `json:"description" binding:"required"`
		Category    string `json:"category"    binding:"required"`
		Priority    string `json:"priority"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	userIDVal, _ := c.Get("user_id")
	userIDStr, _ := userIDVal.(string)
	tenantIDVal, _ := c.Get("tenant_id")
	tenantIDStr, _ := tenantIDVal.(string)

	priority := req.Priority
	if priority == "" {
		priority = "medium"
	}

	tk := &support.Ticket{
		Title:       req.Title,
		Description: req.Description,
		Category:    req.Category,
		Priority:    priority,
	}
	if userIDStr != "" {
		tk.CreatedBy = &userIDStr
	}
	if tenantIDStr != "" {
		tk.TenantID = &tenantIDStr
	}

	created, err := h.store.CreateTicket(c.Request.Context(), tk)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": dbErrMsg(err)})
		return
	}
	c.JSON(http.StatusCreated, created)
}

// UpdateTicket PATCH /api/v1/support/tickets/:id
func (h *SupportHandler) UpdateTicket(c *gin.Context) {
	id := c.Param("id")

	var req struct {
		Status     string  `json:"status"`
		Priority   string  `json:"priority"`
		AssignedTo *string `json:"assigned_to"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// 管理者のみステータス変更・担当者割り当て可能
	// ユーザーは自分のチケットのステータスを一部変更可
	roleVal, _ := c.Get("user_role")
	role, _ := roleVal.(string)
	if role != "admin" {
		// 管理者以外は assigned_to を変更不可
		req.AssignedTo = nil
		// closed/resolved への変更は管理者のみ
		if req.Status == "resolved" || req.Status == "closed" {
			c.JSON(http.StatusForbidden, gin.H{"error": "only admins can resolve or close tickets"})
			return
		}
	}

	updated, err := h.store.UpdateTicket(c.Request.Context(), id, req.Status, req.Priority, req.AssignedTo)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": dbErrMsg(err)})
		return
	}
	c.JSON(http.StatusOK, updated)
}

// ListComments GET /api/v1/support/tickets/:id/comments
func (h *SupportHandler) ListComments(c *gin.Context) {
	ticketID := c.Param("id")
	roleVal, _ := c.Get("user_role")
	role, _ := roleVal.(string)
	includeInternal := role == "admin"

	comments, err := h.store.ListComments(c.Request.Context(), ticketID, includeInternal)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": dbErrMsg(err)})
		return
	}
	if comments == nil {
		comments = []*support.Comment{}
	}
	c.JSON(http.StatusOK, comments)
}

// AddComment POST /api/v1/support/tickets/:id/comments
func (h *SupportHandler) AddComment(c *gin.Context) {
	ticketID := c.Param("id")

	var req struct {
		Body       string `json:"body"        binding:"required"`
		IsInternal bool   `json:"is_internal"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	roleVal, _ := c.Get("user_role")
	role, _ := roleVal.(string)
	// 内部メモは管理者のみ
	if req.IsInternal && role != "admin" {
		req.IsInternal = false
	}

	userIDVal, _ := c.Get("user_id")
	userIDStr, _ := userIDVal.(string)

	cm := &support.Comment{
		TicketID:   ticketID,
		Body:       req.Body,
		IsInternal: req.IsInternal,
	}
	if userIDStr != "" {
		cm.AuthorID = &userIDStr
	}

	added, err := h.store.AddComment(c.Request.Context(), cm)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": dbErrMsg(err)})
		return
	}
	c.JSON(http.StatusCreated, added)
}

// GetStats GET /api/v1/admin/support/stats
func (h *SupportHandler) GetStats(c *gin.Context) {
	st, err := h.store.GetStats(c.Request.Context())
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": dbErrMsg(err)})
		return
	}
	c.JSON(http.StatusOK, st)
}

package handlers

import (
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/edr-platform/server/internal/store"
	"github.com/gin-gonic/gin"
)

// IPBlockHandler manages the IP address / CIDR block and allow list.
type IPBlockHandler struct {
	Store *store.IPBlockStore
}

func NewIPBlockHandler(s *store.IPBlockStore) *IPBlockHandler {
	return &IPBlockHandler{Store: s}
}

// isValidIPOrCIDR reports whether v is a valid IPv4/IPv6 address or CIDR range.
func isValidIPOrCIDR(v string) bool {
	if strings.Contains(v, "/") {
		_, _, err := net.ParseCIDR(v)
		return err == nil
	}
	return net.ParseIP(v) != nil
}

// List returns every IP block/allow entry.
// GET /api/v1/ioc/ip-block
func (h *IPBlockHandler) List(c *gin.Context) {
	entries, total, err := h.Store.List(c.Request.Context())
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": dbErrMsg(err)})
		return
	}
	c.JSON(http.StatusOK, gin.H{"data": entries, "total": total})
}

// Create adds a new IP block/allow entry.
// POST /api/v1/ioc/ip-block
func (h *IPBlockHandler) Create(c *gin.Context) {
	var req struct {
		IPOrCIDR    string `json:"ip_or_cidr" binding:"required"`
		EntryType   string `json:"entry_type"`
		Description string `json:"description"`
		ExpiresAt   string `json:"expires_at"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "ip_or_cidr は必須です"})
		return
	}

	req.IPOrCIDR = strings.TrimSpace(req.IPOrCIDR)
	if !isValidIPOrCIDR(req.IPOrCIDR) {
		c.JSON(http.StatusBadRequest, gin.H{"error": "IPアドレスまたはCIDR形式が不正です"})
		return
	}

	entryType := req.EntryType
	if entryType != "allow" {
		entryType = "block"
	}

	var expiresAt *time.Time
	if req.ExpiresAt != "" {
		if t, err := time.Parse(time.RFC3339, req.ExpiresAt); err == nil {
			expiresAt = &t
		} else if t, err := time.Parse("2006-01-02", req.ExpiresAt); err == nil {
			expiresAt = &t
		} else {
			c.JSON(http.StatusBadRequest, gin.H{"error": "有効期限の形式が不正です"})
			return
		}
	}

	userID, _ := c.Get("user_id")
	uid, _ := userID.(string)

	entry := &store.IPBlockEntry{
		IPOrCIDR:    req.IPOrCIDR,
		EntryType:   entryType,
		Description: req.Description,
		ExpiresAt:   expiresAt,
		AddedBy:     &uid,
	}
	if err := h.Store.Insert(c.Request.Context(), entry); err != nil {
		if isDuplicateError(err) {
			c.JSON(http.StatusConflict, gin.H{"error": "同じIP/CIDRとタイプのエントリがすでに存在します"})
			return
		}
		if isConstraintViolation(err) {
			c.JSON(http.StatusBadRequest, gin.H{"error": "エントリの内容が不正です"})
			return
		}
		c.JSON(http.StatusInternalServerError, gin.H{"error": dbErrMsg(err)})
		return
	}
	c.JSON(http.StatusCreated, gin.H{"message": "エントリを追加しました", "id": entry.ID})
}

// Delete removes an IP block/allow entry.
// DELETE /api/v1/ioc/ip-block/:id
func (h *IPBlockHandler) Delete(c *gin.Context) {
	id := c.Param("id")
	if err := h.Store.Delete(c.Request.Context(), id); err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "エントリが見つかりません"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"message": "エントリを削除しました", "id": id})
}

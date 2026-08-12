package handlers

import (
	"encoding/json"
	"log"
	"net/http"

	"github.com/edr-platform/server/internal/store"
	"github.com/gin-gonic/gin"
)

type FavoritesHandler struct {
	prefs *store.UserPreferencesStore
}

func NewFavoritesHandler(prefs *store.UserPreferencesStore) *FavoritesHandler {
	return &FavoritesHandler{prefs: prefs}
}

func (h *FavoritesHandler) Get(c *gin.Context) {
	userID := c.GetString("user_id")
	items, err := h.prefs.GetFavorites(c.Request.Context(), userID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "お気に入りの取得に失敗しました"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"favorites": items})
}

func (h *FavoritesHandler) Set(c *gin.Context) {
	userID := c.GetString("user_id")

	var body struct {
		Favorites []store.FavoriteItem `json:"favorites"`
	}
	if err := json.NewDecoder(c.Request.Body).Decode(&body); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "リクエストの解析に失敗しました"})
		return
	}

	for _, f := range body.Favorites {
		if len(f.Href) > 200 {
			c.JSON(http.StatusBadRequest, gin.H{"error": "href は 200 文字以内で入力してください"})
			return
		}
		if len(f.Label) > 100 {
			c.JSON(http.StatusBadRequest, gin.H{"error": "label は 100 文字以内で入力してください"})
			return
		}
	}

	saved, err := h.prefs.SetFavorites(c.Request.Context(), userID, body.Favorites)
	if err != nil {
		log.Printf("ERROR SetFavorites userID=%s err=%v", userID, err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "お気に入りの保存に失敗しました"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"favorites": saved})
}

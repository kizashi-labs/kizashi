package handlers

import (
	"encoding/json"
	"log/slog"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"time"
	"unicode"

	"github.com/gin-gonic/gin"
	"github.com/jackc/pgx/v5/pgxpool"
)

// KnowledgeBaseHandler manages knowledge base article endpoints.
type KnowledgeBaseHandler struct {
	pool *pgxpool.Pool
}

// NewKnowledgeBaseHandler creates a new KnowledgeBaseHandler.
func NewKnowledgeBaseHandler(pool *pgxpool.Pool) *KnowledgeBaseHandler {
	return &KnowledgeBaseHandler{pool: pool}
}

func (h *KnowledgeBaseHandler) tableExists(c *gin.Context) bool {
	return tableIsThere(c.Request.Context(), h.pool, "kb_articles")
}

func generateSlug(title string) string {
	slug := strings.ToLower(title)
	// Replace spaces with hyphens
	slug = strings.ReplaceAll(slug, " ", "-")
	// Strip special chars, keep alphanumeric and hyphens
	re := regexp.MustCompile(`[^a-z0-9\-]`)
	slug = re.ReplaceAllString(slug, "")
	// Collapse multiple hyphens
	re2 := regexp.MustCompile(`-{2,}`)
	slug = re2.ReplaceAllString(slug, "-")
	slug = strings.Trim(slug, "-")
	return slug
}

func isAdminFromCtx(c *gin.Context) bool {
	role, _ := c.Get("role")
	roleStr, _ := role.(string)
	return roleStr == "admin"
}

type kbArticle struct {
	ID              string          `json:"id"`
	Title           string          `json:"title"`
	Slug            string          `json:"slug"`
	Category        string          `json:"category"`
	Content         string          `json:"content"`
	Tags            json.RawMessage `json:"tags"`
	AuthorID        *string         `json:"author_id"`
	ViewCount       int             `json:"view_count"`
	HelpfulCount    int             `json:"helpful_count"`
	NotHelpfulCount int             `json:"not_helpful_count"`
	Published       bool            `json:"published"`
	CreatedAt       time.Time       `json:"created_at"`
	UpdatedAt       time.Time       `json:"updated_at"`
}

func scanKBArticle(row interface{ Scan(...interface{}) error }, a *kbArticle) error {
	return row.Scan(&a.ID, &a.Title, &a.Slug, &a.Category, &a.Content, &a.Tags,
		&a.AuthorID, &a.ViewCount, &a.HelpfulCount, &a.NotHelpfulCount,
		&a.Published, &a.CreatedAt, &a.UpdatedAt)
}

const kbSelectCols = `id, title, slug, category, content, tags, author_id,
	view_count, helpful_count, not_helpful_count, published, created_at, updated_at`

// List GET /knowledge-base
func (h *KnowledgeBaseHandler) List(c *gin.Context) {
	if !h.tableExists(c) {
		c.JSON(http.StatusOK, gin.H{"articles": []interface{}{}, "total": 0})
		return
	}
	ctx := c.Request.Context()

	limit, _ := strconv.Atoi(c.DefaultQuery("per_page", "50"))
	page, _ := strconv.Atoi(c.DefaultQuery("page", "1"))
	page, limit, offset := clampPageParams(page, limit, 50, 200)

	isAdmin := isAdminFromCtx(c)

	where := " WHERE 1=1"
	args := []interface{}{}
	idx := 1

	if !isAdmin {
		where += " AND published=TRUE"
	}
	if category := c.Query("category"); category != "" {
		where += " AND category=$" + strconv.Itoa(idx)
		args = append(args, category)
		idx++
	}
	if tag := c.Query("tag"); tag != "" {
		where += " AND tags @> $" + strconv.Itoa(idx) + "::jsonb"
		tagJSON, _ := json.Marshal([]string{tag})
		args = append(args, string(tagJSON))
		idx++
	}

	countArgs := make([]interface{}, len(args))
	copy(countArgs, args)

	var total int
	if !ReadOK(c, h.pool.QueryRow(ctx, `SELECT COUNT(*) FROM kb_articles`+where, countArgs...).Scan(&total)) {
		return
	}

	args = append(args, limit, offset)
	query := `SELECT ` + kbSelectCols + ` FROM kb_articles` + where +
		` ORDER BY created_at DESC LIMIT $` + strconv.Itoa(idx) + ` OFFSET $` + strconv.Itoa(idx+1)

	rows, err := h.pool.Query(ctx, query, args...)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to list articles"})
		return
	}
	defer rows.Close()

	articles := []kbArticle{}
	for rows.Next() {
		var a kbArticle
		if err := scanKBArticle(rows, &a); err == nil {
			articles = append(articles, a)
		}
	}
	if err := rows.Err(); err != nil {
		slog.Error("rows.Err: 結果の読み出しが途中で失敗しました", "error", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to list articles"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"articles": articles, "total": total, "page": page, "per_page": limit})
}

// Search GET /knowledge-base/search
func (h *KnowledgeBaseHandler) Search(c *gin.Context) {
	if !h.tableExists(c) {
		c.JSON(http.StatusOK, gin.H{"articles": []interface{}{}, "total": 0})
		return
	}
	ctx := c.Request.Context()
	q := c.Query("q")
	if q == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "q parameter required"})
		return
	}

	isAdmin := isAdminFromCtx(c)

	publishedFilter := ""
	if !isAdmin {
		publishedFilter = " AND published=TRUE"
	}

	// Try full-text search first
	var rows interface {
		Next() bool
		Scan(...interface{}) error
		Close()
		Err() error
	}
	var qErr error

	rows, qErr = h.pool.Query(ctx,
		`SELECT `+kbSelectCols+`, ts_rank(to_tsvector('english', title || ' ' || content), plainto_tsquery('english', $1)) AS rank
		 FROM kb_articles
		 WHERE to_tsvector('english', title || ' ' || content) @@ plainto_tsquery('english', $1)`+publishedFilter+
			` ORDER BY rank DESC LIMIT 50`, q)
	if qErr != nil {
		// Fallback to ILIKE
		rows, qErr = h.pool.Query(ctx,
			`SELECT `+kbSelectCols+`, 0.0 AS rank FROM kb_articles
			 WHERE (title ILIKE $1 OR content ILIKE $1)`+publishedFilter+
				` ORDER BY view_count DESC LIMIT 50`, "%"+q+"%")
		if qErr != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "search failed"})
			return
		}
	}
	defer rows.Close()

	results := []map[string]interface{}{}
	for rows.Next() {
		var a kbArticle
		var rank float64
		if err := rows.Scan(&a.ID, &a.Title, &a.Slug, &a.Category, &a.Content, &a.Tags,
			&a.AuthorID, &a.ViewCount, &a.HelpfulCount, &a.NotHelpfulCount,
			&a.Published, &a.CreatedAt, &a.UpdatedAt, &rank); err == nil {
			results = append(results, map[string]interface{}{
				"id": a.ID, "title": a.Title, "slug": a.Slug, "category": a.Category,
				"content": a.Content, "tags": a.Tags, "author_id": a.AuthorID,
				"view_count": a.ViewCount, "helpful_count": a.HelpfulCount,
				"not_helpful_count": a.NotHelpfulCount, "published": a.Published,
				"created_at": a.CreatedAt, "updated_at": a.UpdatedAt, "rank": rank,
			})
		}
	}
	if err := rows.Err(); err != nil {
		slog.Error("rows.Err: 結果の読み出しが途中で失敗しました", "error", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "search failed"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"articles": results, "total": len(results), "query": q})
}

// Get GET /knowledge-base/:id
func (h *KnowledgeBaseHandler) Get(c *gin.Context) {
	if !h.tableExists(c) {
		c.JSON(http.StatusNotFound, gin.H{"error": "not found"})
		return
	}
	ctx := c.Request.Context()
	id := c.Param("id")

	var a kbArticle
	err := h.pool.QueryRow(ctx,
		`SELECT `+kbSelectCols+` FROM kb_articles WHERE id=$1`, id).Scan(
		&a.ID, &a.Title, &a.Slug, &a.Category, &a.Content, &a.Tags,
		&a.AuthorID, &a.ViewCount, &a.HelpfulCount, &a.NotHelpfulCount,
		&a.Published, &a.CreatedAt, &a.UpdatedAt)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "article not found"})
		return
	}

	// Increment view count
	if _, err := h.pool.Exec(ctx, `UPDATE kb_articles SET view_count=view_count+1, updated_at=NOW() WHERE id=$1`, id); !WriteOK(c, err) {
		return
	}
	a.ViewCount++

	c.JSON(http.StatusOK, gin.H{"article": a})
}

// GetBySlug GET /knowledge-base/slug/:slug
func (h *KnowledgeBaseHandler) GetBySlug(c *gin.Context) {
	if !h.tableExists(c) {
		c.JSON(http.StatusNotFound, gin.H{"error": "not found"})
		return
	}
	ctx := c.Request.Context()
	slug := c.Param("slug")

	var a kbArticle
	err := h.pool.QueryRow(ctx,
		`SELECT `+kbSelectCols+` FROM kb_articles WHERE slug=$1`, slug).Scan(
		&a.ID, &a.Title, &a.Slug, &a.Category, &a.Content, &a.Tags,
		&a.AuthorID, &a.ViewCount, &a.HelpfulCount, &a.NotHelpfulCount,
		&a.Published, &a.CreatedAt, &a.UpdatedAt)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "article not found"})
		return
	}

	if _, err := h.pool.Exec(ctx, `UPDATE kb_articles SET view_count=view_count+1, updated_at=NOW() WHERE id=$1`, a.ID); !WriteOK(c, err) {
		return
	}
	a.ViewCount++

	c.JSON(http.StatusOK, gin.H{"article": a})
}

// Create POST /knowledge-base (admin only)
func (h *KnowledgeBaseHandler) Create(c *gin.Context) {
	if !h.tableExists(c) {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "knowledge base not available"})
		return
	}
	ctx := c.Request.Context()

	var body struct {
		Title     string          `json:"title" binding:"required"`
		Category  string          `json:"category"`
		Content   string          `json:"content" binding:"required"`
		Tags      json.RawMessage `json:"tags"`
		Published bool            `json:"published"`
	}
	if err := c.ShouldBindJSON(&body); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	if body.Title == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "title is required"})
		return
	}
	if body.Category == "" {
		body.Category = "general"
	}
	if body.Tags == nil {
		body.Tags = json.RawMessage("[]")
	}

	slug := generateSlug(body.Title)
	// Ensure slug uniqueness by appending timestamp if needed
	var count int
	if !ReadOK(c, h.pool.QueryRow(ctx, `SELECT COUNT(*) FROM kb_articles WHERE slug=$1`, slug).Scan(&count)) {
		return
	}
	if count > 0 {
		slug = slug + "-" + strconv.FormatInt(time.Now().UnixMilli(), 36)
		// Remove non-ASCII
		slug = strings.Map(func(r rune) rune {
			if unicode.IsLetter(r) || unicode.IsDigit(r) || r == '-' {
				return r
			}
			return -1
		}, slug)
	}

	userID, _ := c.Get("user_id")
	userIDStr, _ := userID.(string)

	var id string
	err := h.pool.QueryRow(ctx,
		`INSERT INTO kb_articles (title, slug, category, content, tags, author_id, published)
		 VALUES ($1,$2,$3,$4,$5,$6,$7) RETURNING id`,
		body.Title, slug, body.Category, body.Content, body.Tags, userIDStr, body.Published).Scan(&id)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to create article"})
		return
	}

	c.JSON(http.StatusCreated, gin.H{"id": id, "slug": slug, "message": "article created"})
}

// Update PUT /knowledge-base/:id (admin only)
func (h *KnowledgeBaseHandler) Update(c *gin.Context) {
	if !h.tableExists(c) {
		c.JSON(http.StatusNotFound, gin.H{"error": "not found"})
		return
	}
	ctx := c.Request.Context()
	id := c.Param("id")

	var body struct {
		Title     string          `json:"title"`
		Category  string          `json:"category"`
		Content   string          `json:"content"`
		Tags      json.RawMessage `json:"tags"`
		Published bool            `json:"published"`
	}
	if err := c.ShouldBindJSON(&body); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	if body.Tags == nil {
		body.Tags = json.RawMessage("[]")
	}

	_, err := h.pool.Exec(ctx,
		`UPDATE kb_articles SET title=$1, category=$2, content=$3, tags=$4, published=$5, updated_at=NOW()
		 WHERE id=$6`,
		body.Title, body.Category, body.Content, body.Tags, body.Published, id)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to update article"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "article updated"})
}

// Delete DELETE /knowledge-base/:id (admin only)
func (h *KnowledgeBaseHandler) Delete(c *gin.Context) {
	if !h.tableExists(c) {
		c.JSON(http.StatusNotFound, gin.H{"error": "not found"})
		return
	}
	ctx := c.Request.Context()
	id := c.Param("id")

	_, err := h.pool.Exec(ctx, `DELETE FROM kb_articles WHERE id=$1`, id)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to delete article"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "article deleted"})
}

// Vote POST /knowledge-base/:id/vote
func (h *KnowledgeBaseHandler) Vote(c *gin.Context) {
	if !h.tableExists(c) {
		c.JSON(http.StatusNotFound, gin.H{"error": "not found"})
		return
	}
	ctx := c.Request.Context()
	id := c.Param("id")

	var body struct {
		Helpful bool `json:"helpful"`
	}
	if err := c.ShouldBindJSON(&body); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	col := "not_helpful_count"
	if body.Helpful {
		col = "helpful_count"
	}

	_, err := h.pool.Exec(ctx,
		`UPDATE kb_articles SET `+col+`=`+col+`+1, updated_at=NOW() WHERE id=$1`, id)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to record vote"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "vote recorded"})
}

// GetStats GET /knowledge-base/stats
func (h *KnowledgeBaseHandler) GetStats(c *gin.Context) {
	if !h.tableExists(c) {
		c.JSON(http.StatusOK, gin.H{
			"total":       0,
			"published":   0,
			"by_category": map[string]int{},
			"top_viewed":  []interface{}{},
		})
		return
	}
	ctx := c.Request.Context()

	var total, published int
	if !ReadOK(c, h.pool.QueryRow(ctx, `SELECT COUNT(*), COALESCE(SUM(CASE WHEN published THEN 1 ELSE 0 END), 0) FROM kb_articles`).Scan(&total, &published)) {
		return
	}

	// By category
	catRows, err := h.pool.Query(ctx, `SELECT category, COUNT(*) FROM kb_articles GROUP BY category ORDER BY category`)
	byCategory := map[string]int{}
	if err == nil {
		defer catRows.Close()
		for catRows.Next() {
			var cat string
			var cnt int
			if scanErr := catRows.Scan(&cat, &cnt); scanErr == nil {
				byCategory[cat] = cnt
			}
		}
		if err := catRows.Err(); err != nil {
			slog.Warn("row iteration error", "error", err)
		}
	}

	// Top viewed
	type TopArticle struct {
		ID        string `json:"id"`
		Title     string `json:"title"`
		Slug      string `json:"slug"`
		ViewCount int    `json:"view_count"`
	}
	topRows, err := h.pool.Query(ctx,
		`SELECT id, title, slug, view_count FROM kb_articles WHERE published=TRUE ORDER BY view_count DESC LIMIT 10`)
	topViewed := []TopArticle{}
	if err == nil {
		defer topRows.Close()
		for topRows.Next() {
			var a TopArticle
			if scanErr := topRows.Scan(&a.ID, &a.Title, &a.Slug, &a.ViewCount); scanErr == nil {
				topViewed = append(topViewed, a)
			}
		}
		if err := topRows.Err(); err != nil {
			slog.Warn("row iteration error", "error", err)
		}
	}

	c.JSON(http.StatusOK, gin.H{
		"total":       total,
		"published":   published,
		"by_category": byCategory,
		"top_viewed":  topViewed,
	})
}

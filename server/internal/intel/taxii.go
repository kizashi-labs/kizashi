package intel

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

// TAXII 2.1 クライアント: 外部 TAXII サーバ(AlienVault OTX DirectConnect,
// MISP の TAXII モジュール, Anomali Limo, OpenTAXII 等)のコレクションを pull
// 購読して STIX Indicator を IOC として取り込む。既存の HTTP フィード同期
// (feed_scheduler.go)に source_format="taxii21" として組み込まれる。
//
// TAXII 2.1 の Get Objects エンドポイントは Envelope
// ({"objects":[...],"more":bool,"next":"..."}) を返す。more=true の間 next
// カーソルで追走し、added_after で前回同期以降の差分だけを取得する。

const (
	taxiiAcceptHeader    = "application/taxii+json;version=2.1"
	taxiiDefaultPageSize = 100
	taxiiDefaultMaxObj   = 50000 // 1 回の poll で取り込む STIX オブジェクトの安全上限
	taxiiMaxPages        = 1000  // more/next の無限ループ防止
)

// TAXIIPollConfig configures a single collection poll.
type TAXIIPollConfig struct {
	// CollectionURL is the TAXII 2.1 collection endpoint, e.g.
	// https://host/taxii2/api1/collections/<id>/ — the client appends
	// "objects/" when the URL does not already target the objects resource.
	CollectionURL string
	// APIKey authenticates the request. A value containing ":" is treated as
	// "user:pass" and sent as HTTP Basic (Anomali Limo uses guest:guest);
	// otherwise it is sent as a Bearer token.
	APIKey string
	// Headers are extra request headers and override the defaults (including
	// Authorization) when they collide — this lets operators express
	// non-standard auth schemes (e.g. OTX's "X-OTX-API-KEY").
	Headers map[string]string
	// AddedAfter requests only objects added to the collection after this
	// instant (incremental sync). Nil pulls the full collection.
	AddedAfter *time.Time
	// PageLimit is the requested objects-per-page; the server may return fewer.
	PageLimit int
	// MaxObjects caps the total objects pulled in one poll.
	MaxObjects int
}

// TAXIIClient polls TAXII 2.1 collections.
type TAXIIClient struct {
	client *http.Client
}

// NewTAXIIClient returns a TAXIIClient with a 60s per-request timeout.
func NewTAXIIClient() *TAXIIClient {
	return &TAXIIClient{client: &http.Client{Timeout: 60 * time.Second}}
}

// taxiiEnvelope is the TAXII 2.1 Get Objects response body.
type taxiiEnvelope struct {
	Objects []json.RawMessage `json:"objects"`
	More    bool              `json:"more"`
	Next    string            `json:"next"`
}

// taxiiSTIXObject is the subset of a STIX 2.1 SDO the client consumes.
type taxiiSTIXObject struct {
	Type       string   `json:"type"`
	Pattern    string   `json:"pattern"`
	Name       string   `json:"name"`
	Labels     []string `json:"labels"`
	ValidUntil string   `json:"valid_until"`
}

// PollCollection pulls indicators from a TAXII 2.1 collection and returns them
// as FeedEntry values ready for upsert. Pagination and added_after filtering
// are handled internally.
func (t *TAXIIClient) PollCollection(ctx context.Context, cfg TAXIIPollConfig) ([]FeedEntry, error) {
	objectsURL, err := taxiiObjectsURL(cfg.CollectionURL)
	if err != nil {
		return nil, err
	}
	pageSize := cfg.PageLimit
	if pageSize <= 0 {
		pageSize = taxiiDefaultPageSize
	}
	maxObj := cfg.MaxObjects
	if maxObj <= 0 {
		maxObj = taxiiDefaultMaxObj
	}

	var entries []FeedEntry
	next := ""
	for page := 0; page < taxiiMaxPages; page++ {
		env, err := t.fetchPage(ctx, objectsURL, cfg, pageSize, next)
		if err != nil {
			// Return what we have so a mid-pull failure still persists earlier
			// pages, but surface the error so the caller logs it.
			if len(entries) > 0 {
				return entries, fmt.Errorf("taxii poll (partial, %d entries): %w", len(entries), err)
			}
			return nil, err
		}
		for _, raw := range env.Objects {
			if e, ok := taxiiObjectToEntry(raw); ok {
				entries = append(entries, e)
				if len(entries) >= maxObj {
					return entries, nil
				}
			}
		}
		if !env.More || env.Next == "" {
			break
		}
		next = env.Next
	}
	return entries, nil
}

// fetchPage performs one Get Objects request.
func (t *TAXIIClient) fetchPage(ctx context.Context, objectsURL string, cfg TAXIIPollConfig, pageSize int, next string) (*taxiiEnvelope, error) {
	q := url.Values{}
	q.Set("limit", strconv.Itoa(pageSize))
	if cfg.AddedAfter != nil {
		q.Set("added_after", cfg.AddedAfter.UTC().Format(time.RFC3339))
	}
	if next != "" {
		q.Set("next", next)
	}
	reqURL := objectsURL
	if enc := q.Encode(); enc != "" {
		reqURL += "?" + enc
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, reqURL, nil)
	if err != nil {
		return nil, fmt.Errorf("create request: %w", err)
	}
	req.Header.Set("Accept", taxiiAcceptHeader)
	req.Header.Set("User-Agent", "EDR-Platform-TAXII/1.0")
	applyTAXIIAuth(req, cfg)

	resp, err := t.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("fetch: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return nil, fmt.Errorf("HTTP %d from %s: %s", resp.StatusCode, objectsURL, strings.TrimSpace(string(body)))
	}

	var env taxiiEnvelope
	if err := json.NewDecoder(io.LimitReader(resp.Body, 64*1024*1024)).Decode(&env); err != nil {
		return nil, fmt.Errorf("decode envelope: %w", err)
	}
	return &env, nil
}

// applyTAXIIAuth sets the Authorization header from cfg.APIKey (Basic when the
// key looks like user:pass, else Bearer), then applies cfg.Headers so operators
// can override the scheme entirely.
func applyTAXIIAuth(req *http.Request, cfg TAXIIPollConfig) {
	if cfg.APIKey != "" {
		if u, p, ok := strings.Cut(cfg.APIKey, ":"); ok {
			creds := base64.StdEncoding.EncodeToString([]byte(u + ":" + p))
			req.Header.Set("Authorization", "Basic "+creds)
		} else {
			req.Header.Set("Authorization", "Bearer "+cfg.APIKey)
		}
	}
	for k, v := range cfg.Headers {
		req.Header.Set(k, v)
	}
}

// taxiiObjectToEntry converts one raw STIX object into a FeedEntry. Only
// indicator SDOs with an extractable pattern yield an entry.
func taxiiObjectToEntry(raw json.RawMessage) (FeedEntry, bool) {
	var obj taxiiSTIXObject
	if err := json.Unmarshal(raw, &obj); err != nil {
		return FeedEntry{}, false
	}
	if !strings.EqualFold(obj.Type, "indicator") || obj.Pattern == "" {
		return FeedEntry{}, false
	}
	iocType, value, ok := ExtractIOCFromSTIXPattern(obj.Pattern)
	if !ok {
		return FeedEntry{}, false
	}
	// FeedEntry.Type is the canonical ip|domain|url|hash convention shared with
	// the other feed parsers; collapse the hash sub-types here so downstream
	// upsert/normalisation stays uniform.
	switch iocType {
	case "sha256", "sha1", "md5":
		iocType = "hash"
	}

	threat := "taxii-indicator"
	if len(obj.Labels) > 0 && obj.Labels[0] != "" {
		threat = obj.Labels[0]
	} else if obj.Name != "" {
		threat = obj.Name
	}

	entry := FeedEntry{Type: iocType, Value: value, Threat: threat, Source: "taxii"}
	if obj.ValidUntil != "" {
		if ts, err := time.Parse(time.RFC3339, obj.ValidUntil); err == nil {
			entry.ExpiresAt = &ts
		}
	}
	return entry, true
}

// taxiiObjectsURL normalises a collection URL to its Get Objects resource,
// appending "objects/" unless the URL already targets it.
func taxiiObjectsURL(collectionURL string) (string, error) {
	collectionURL = strings.TrimSpace(collectionURL)
	if collectionURL == "" {
		return "", fmt.Errorf("empty TAXII collection URL")
	}
	if _, err := url.ParseRequestURI(collectionURL); err != nil {
		return "", fmt.Errorf("invalid TAXII collection URL: %w", err)
	}
	// Drop any query string: fetchPage owns the TAXII query params (limit,
	// added_after, next), and a leftover "?" here would collide with them.
	base, _, _ := strings.Cut(collectionURL, "?")
	trimmed := strings.TrimRight(base, "/")
	if strings.HasSuffix(trimmed, "/objects") {
		return trimmed + "/", nil
	}
	return trimmed + "/objects/", nil
}

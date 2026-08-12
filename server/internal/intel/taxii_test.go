package intel

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func indicatorObj(pattern, label, validUntil string) map[string]interface{} {
	o := map[string]interface{}{
		"type":         "indicator",
		"spec_version": "2.1",
		"id":           "indicator--" + pattern,
		"pattern":      pattern,
		"pattern_type": "stix",
	}
	if label != "" {
		o["labels"] = []string{label}
	}
	if validUntil != "" {
		o["valid_until"] = validUntil
	}
	return o
}

func writeEnvelope(w http.ResponseWriter, objects []interface{}, more bool, next string) {
	w.Header().Set("Content-Type", taxiiAcceptHeader)
	env := map[string]interface{}{"objects": objects, "more": more}
	if next != "" {
		env["next"] = next
	}
	_ = json.NewEncoder(w).Encode(env)
}

func TestTAXIIClient_PollCollection_Basic(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasSuffix(r.URL.Path, "/objects/") {
			t.Errorf("expected objects path, got %s", r.URL.Path)
		}
		if got := r.Header.Get("Accept"); got != taxiiAcceptHeader {
			t.Errorf("Accept = %q, want %q", got, taxiiAcceptHeader)
		}
		writeEnvelope(w, []interface{}{
			indicatorObj("[ipv4-addr:value = '1.2.3.4']", "c2", ""),
			indicatorObj("[file:hashes.'SHA-256' = 'deadbeef']", "malware", ""),
			indicatorObj("[url:value = 'http://bad/x']", "", ""),
			// non-indicator + unsupported pattern → skipped
			map[string]interface{}{"type": "malware", "name": "X"},
			indicatorObj("[email-addr:value = 'a@b.c']", "", ""),
		}, false, "")
	}))
	defer srv.Close()

	entries, err := NewTAXIIClient().PollCollection(context.Background(), TAXIIPollConfig{
		CollectionURL: srv.URL + "/collections/abc/",
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 3 {
		t.Fatalf("got %d entries, want 3: %+v", len(entries), entries)
	}
	if entries[0].Type != "ip" || entries[0].Value != "1.2.3.4" || entries[0].Threat != "c2" {
		t.Errorf("entry0 = %+v", entries[0])
	}
	// Hash sub-type collapses to canonical "hash".
	if entries[1].Type != "hash" || entries[1].Value != "deadbeef" {
		t.Errorf("entry1 = %+v", entries[1])
	}
	// No label falls back to the default threat tag.
	if entries[2].Type != "url" || entries[2].Threat != "taxii-indicator" {
		t.Errorf("entry2 = %+v", entries[2])
	}
}

func TestTAXIIClient_PollCollection_Pagination(t *testing.T) {
	var seenNext []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		next := r.URL.Query().Get("next")
		seenNext = append(seenNext, next)
		switch next {
		case "":
			writeEnvelope(w, []interface{}{indicatorObj("[ipv4-addr:value = '1.1.1.1']", "", "")}, true, "cursor2")
		case "cursor2":
			writeEnvelope(w, []interface{}{indicatorObj("[ipv4-addr:value = '2.2.2.2']", "", "")}, true, "cursor3")
		case "cursor3":
			writeEnvelope(w, []interface{}{indicatorObj("[ipv4-addr:value = '3.3.3.3']", "", "")}, false, "")
		default:
			t.Errorf("unexpected next cursor %q", next)
		}
	}))
	defer srv.Close()

	entries, err := NewTAXIIClient().PollCollection(context.Background(), TAXIIPollConfig{
		CollectionURL: srv.URL + "/collections/abc",
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 3 {
		t.Fatalf("got %d entries across pages, want 3", len(entries))
	}
	if len(seenNext) != 3 || seenNext[0] != "" || seenNext[1] != "cursor2" || seenNext[2] != "cursor3" {
		t.Errorf("pagination cursors = %v", seenNext)
	}
}

func TestTAXIIClient_PollCollection_AddedAfterAndMax(t *testing.T) {
	var gotAddedAfter, gotLimit string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAddedAfter = r.URL.Query().Get("added_after")
		gotLimit = r.URL.Query().Get("limit")
		// Return more objects than MaxObjects to prove the cap stops the pull.
		objs := []interface{}{
			indicatorObj("[ipv4-addr:value = '1.1.1.1']", "", ""),
			indicatorObj("[ipv4-addr:value = '2.2.2.2']", "", ""),
			indicatorObj("[ipv4-addr:value = '3.3.3.3']", "", ""),
		}
		writeEnvelope(w, objs, true, "more") // more=true, but cap should stop us
	}))
	defer srv.Close()

	after := time.Date(2026, 7, 1, 12, 0, 0, 0, time.UTC)
	entries, err := NewTAXIIClient().PollCollection(context.Background(), TAXIIPollConfig{
		CollectionURL: srv.URL + "/collections/abc/",
		AddedAfter:    &after,
		PageLimit:     50,
		MaxObjects:    2,
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 2 {
		t.Fatalf("MaxObjects=2 not enforced: got %d", len(entries))
	}
	if gotLimit != "50" {
		t.Errorf("limit param = %q, want 50", gotLimit)
	}
	if gotAddedAfter != "2026-07-01T12:00:00Z" {
		t.Errorf("added_after param = %q", gotAddedAfter)
	}
}

func TestTAXIIClient_Auth(t *testing.T) {
	t.Run("bearer", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if got := r.Header.Get("Authorization"); got != "Bearer sekret" {
				t.Errorf("Authorization = %q, want Bearer sekret", got)
			}
			writeEnvelope(w, nil, false, "")
		}))
		defer srv.Close()
		if _, err := NewTAXIIClient().PollCollection(context.Background(), TAXIIPollConfig{
			CollectionURL: srv.URL + "/c/", APIKey: "sekret",
		}); err != nil {
			t.Fatal(err)
		}
	})

	t.Run("basic", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			u, p, ok := r.BasicAuth()
			if !ok || u != "guest" || p != "guest" {
				t.Errorf("basic auth = (%q,%q,%v)", u, p, ok)
			}
			writeEnvelope(w, nil, false, "")
		}))
		defer srv.Close()
		if _, err := NewTAXIIClient().PollCollection(context.Background(), TAXIIPollConfig{
			CollectionURL: srv.URL + "/c/", APIKey: "guest:guest",
		}); err != nil {
			t.Fatal(err)
		}
	})

	t.Run("custom header overrides", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if got := r.Header.Get("X-OTX-API-KEY"); got != "otxkey" {
				t.Errorf("X-OTX-API-KEY = %q", got)
			}
			writeEnvelope(w, nil, false, "")
		}))
		defer srv.Close()
		if _, err := NewTAXIIClient().PollCollection(context.Background(), TAXIIPollConfig{
			CollectionURL: srv.URL + "/c/",
			Headers:       map[string]string{"X-OTX-API-KEY": "otxkey"},
		}); err != nil {
			t.Fatal(err)
		}
	})
}

func TestTAXIIClient_ValidUntil(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		writeEnvelope(w, []interface{}{
			indicatorObj("[ipv4-addr:value = '1.1.1.1']", "", "2027-01-01T00:00:00Z"),
		}, false, "")
	}))
	defer srv.Close()

	entries, err := NewTAXIIClient().PollCollection(context.Background(), TAXIIPollConfig{
		CollectionURL: srv.URL + "/c/",
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 || entries[0].ExpiresAt == nil {
		t.Fatalf("expected ExpiresAt set, got %+v", entries)
	}
	if !entries[0].ExpiresAt.Equal(time.Date(2027, 1, 1, 0, 0, 0, 0, time.UTC)) {
		t.Errorf("ExpiresAt = %v", entries[0].ExpiresAt)
	}
}

func TestTAXIIClient_HTTPError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "forbidden", http.StatusForbidden)
	}))
	defer srv.Close()
	_, err := NewTAXIIClient().PollCollection(context.Background(), TAXIIPollConfig{
		CollectionURL: srv.URL + "/c/",
	})
	if err == nil {
		t.Fatal("expected error on HTTP 403")
	}
}

func TestTAXIIObjectsURL(t *testing.T) {
	cases := map[string]string{
		"https://h/taxii2/api1/collections/x/":         "https://h/taxii2/api1/collections/x/objects/",
		"https://h/taxii2/api1/collections/x":          "https://h/taxii2/api1/collections/x/objects/",
		"https://h/taxii2/api1/collections/x/objects/": "https://h/taxii2/api1/collections/x/objects/",
		"https://h/taxii2/api1/collections/x/objects":  "https://h/taxii2/api1/collections/x/objects/",
	}
	for in, want := range cases {
		got, err := taxiiObjectsURL(in)
		if err != nil || got != want {
			t.Errorf("taxiiObjectsURL(%q) = (%q,%v), want %q", in, got, err, want)
		}
	}
	if _, err := taxiiObjectsURL(""); err == nil {
		t.Error("expected error for empty URL")
	}
}

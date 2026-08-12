package intel

import (
	"bufio"
	"context"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

type FeedEntry struct {
	Type      string // ip | domain | url | hash
	Value     string
	Threat    string
	Source    string
	ExpiresAt *time.Time
}

type FeedImporter struct {
	client *http.Client
}

func NewFeedImporter() *FeedImporter {
	return &FeedImporter{
		client: &http.Client{Timeout: 60 * time.Second},
	}
}

func (fi *FeedImporter) Import(ctx context.Context, feedURL, format, apiKey string) ([]FeedEntry, error) {
	req, err := http.NewRequestWithContext(ctx, "GET", feedURL, nil)
	if err != nil {
		return nil, fmt.Errorf("create request: %w", err)
	}
	if apiKey != "" {
		req.Header.Set("X-OTX-API-KEY", apiKey)
		req.Header.Set("Authorization", "Bearer "+apiKey)
		// abuse.ch (ThreatFox/URLhaus/MalwareBazaar) gates downloads behind an
		// Auth-Key header. Setting all three is harmless: each service reads only
		// the header it recognises and ignores the rest.
		req.Header.Set("Auth-Key", apiKey)
	}
	req.Header.Set("User-Agent", "EDR-Platform-TI/1.0")

	resp, err := fi.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("fetch: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("HTTP %d from %s", resp.StatusCode, feedURL)
	}

	switch format {
	case "otx_reputation":
		return parseOTXReputation(resp.Body)
	case "urlhaus_csv":
		return parseURLhausCSV(resp.Body)
	case "malwarebazaar_csv":
		return parseMalwareBazaarCSV(resp.Body)
	case "feodo_csv":
		return parseFeodoCSV(resp.Body)
	case "threatfox_csv":
		return parseThreatFoxCSV(resp.Body)
	case "misp_json":
		return parseMISPJSON(resp.Body)
	default:
		return parsePlainList(resp.Body, format)
	}
}

func parseOTXReputation(r io.Reader) ([]FeedEntry, error) {
	var entries []FeedEntry
	scanner := bufio.NewScanner(r)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		// AlienVault's reputation.data is "#"-delimited:
		//   IP # reliability # risk # type # country # city # lat,lon # …
		// Older/plain OTX exports are whitespace-delimited. Detect the "#" form
		// and pull the IP (field 0) and threat type (field 3); fall back to
		// whitespace splitting otherwise.
		var ip, threat string
		if strings.Contains(line, "#") {
			f := strings.Split(line, "#")
			ip = strings.TrimSpace(f[0])
			if len(f) >= 4 && strings.TrimSpace(f[3]) != "" {
				threat = strings.TrimSpace(f[3])
			}
		} else {
			parts := strings.Fields(line)
			if len(parts) < 1 {
				continue
			}
			ip = parts[0]
			if len(parts) >= 3 {
				threat = parts[2]
			}
		}
		if ip == "" {
			continue
		}
		if threat == "" {
			threat = "malicious"
		}
		entries = append(entries, FeedEntry{Type: "ip", Value: ip, Threat: threat, Source: "otx"})
	}
	return entries, scanner.Err()
}

func parseURLhausCSV(r io.Reader) ([]FeedEntry, error) {
	cr := csv.NewReader(r)
	cr.Comment = '#'
	cr.LazyQuotes = true
	var entries []FeedEntry
	for {
		rec, err := cr.Read()
		if err == io.EOF {
			break
		}
		if err != nil || len(rec) < 3 {
			continue
		}
		// id, dateadded, url, url_status, ...
		url := strings.TrimSpace(rec[2])
		if url == "" || url == "url" {
			continue
		}
		entries = append(entries, FeedEntry{Type: "url", Value: url, Threat: "malware_distribution", Source: "urlhaus"})
	}
	return entries, nil
}

func parseMalwareBazaarCSV(r io.Reader) ([]FeedEntry, error) {
	cr := csv.NewReader(r)
	cr.Comment = '#'
	cr.LazyQuotes = true
	cr.TrimLeadingSpace = true // rows are `"a", "b", …` — strip the space after each comma
	cr.FieldsPerRecord = -1    // trailing columns vary across export versions
	var entries []FeedEntry
	for {
		rec, err := cr.Read()
		if err == io.EOF {
			break
		}
		if err != nil || len(rec) < 2 {
			continue
		}
		// first_seen, sha256_hash, md5_hash, sha1_hash, ...
		hash := strings.Trim(strings.TrimSpace(rec[1]), `"`)
		if hash == "" || hash == "sha256_hash" || len(hash) != 64 {
			continue
		}
		entries = append(entries, FeedEntry{Type: "hash", Value: hash, Threat: "malware", Source: "malwarebazaar"})
	}
	return entries, nil
}

func parseFeodoCSV(r io.Reader) ([]FeedEntry, error) {
	cr := csv.NewReader(r)
	cr.Comment = '#'
	cr.LazyQuotes = true
	var entries []FeedEntry
	for {
		rec, err := cr.Read()
		if err == io.EOF {
			break
		}
		if err != nil || len(rec) < 2 {
			continue
		}
		ip := strings.TrimSpace(rec[1])
		if ip == "" || ip == "ip_address" {
			continue
		}
		entries = append(entries, FeedEntry{Type: "ip", Value: ip, Threat: "c2", Source: "feodo"})
	}
	return entries, nil
}

// parseThreatFoxCSV parses the abuse.ch ThreatFox recent-IOC CSV export
// (https://threatfox.abuse.ch/export/csv/recent/). Unlike the single-type
// abuse.ch feeds, ThreatFox mixes indicator kinds in one file: the per-row
// ioc_type column (col 3) decides the type, so mapping happens row by row.
//
// Columns: 0 first_seen_utc, 1 ioc_id, 2 ioc_value, 3 ioc_type,
//
//	4 threat_type, 5 fk_malware, 6 malware_alias, 7 malware_printable, ...
//
// ioc_type values: ip:port | domain | url | sha256_hash | md5_hash | sha1_hash.
func parseThreatFoxCSV(r io.Reader) ([]FeedEntry, error) {
	cr := csv.NewReader(r)
	cr.Comment = '#' // header/legend lines are prefixed with '#'
	cr.LazyQuotes = true
	cr.TrimLeadingSpace = true // rows are formatted as `"a", "b", ...`
	cr.FieldsPerRecord = -1    // trailing columns vary across export versions
	var entries []FeedEntry
	for {
		rec, err := cr.Read()
		if err == io.EOF {
			break
		}
		if err != nil || len(rec) < 4 {
			continue
		}
		value := strings.TrimSpace(rec[2])
		iocType := strings.TrimSpace(rec[3])
		if value == "" || value == "ioc_value" {
			continue
		}

		var t string
		switch iocType {
		case "ip:port":
			t = "ip"
			// Strip the ":port" suffix so the value matches network IOC lookups.
			if i := strings.LastIndex(value, ":"); i > 0 {
				value = value[:i]
			}
		case "domain":
			t = "domain"
		case "url":
			t = "url"
		case "sha256_hash", "md5_hash", "sha1_hash":
			t = "hash"
		default:
			continue // unknown indicator kind — skip rather than misclassify
		}

		// Prefer the human-readable malware name; fall back to the threat_type.
		threat := "malware"
		if len(rec) >= 8 && strings.TrimSpace(rec[7]) != "" {
			threat = strings.TrimSpace(rec[7])
		} else if len(rec) >= 5 && strings.TrimSpace(rec[4]) != "" {
			threat = strings.TrimSpace(rec[4])
		}

		entries = append(entries, FeedEntry{Type: t, Value: value, Threat: threat, Source: "threatfox"})
	}
	return entries, nil
}

func parseMISPJSON(r io.Reader) ([]FeedEntry, error) {
	var result struct {
		Event struct {
			Attribute []struct {
				Type  string `json:"type"`
				Value string `json:"value"`
			} `json:"Attribute"`
		} `json:"Event"`
	}
	if err := json.NewDecoder(r).Decode(&result); err != nil {
		return nil, err
	}
	var entries []FeedEntry
	for _, attr := range result.Event.Attribute {
		entryType := ""
		switch attr.Type {
		case "ip-dst", "ip-src", "ip-dst|port":
			entryType = "ip"
		case "domain", "hostname":
			entryType = "domain"
		case "url":
			entryType = "url"
		case "sha256", "md5", "sha1":
			entryType = "hash"
		}
		if entryType != "" && attr.Value != "" {
			val := attr.Value
			if strings.Contains(val, "|") {
				val = strings.Split(val, "|")[0]
			}
			entries = append(entries, FeedEntry{Type: entryType, Value: val, Threat: "indicator", Source: "misp"})
		}
	}
	return entries, nil
}

func parsePlainList(r io.Reader, format string) ([]FeedEntry, error) {
	entryType := "ip"
	if strings.Contains(format, "domain") {
		entryType = "domain"
	} else if strings.Contains(format, "url") {
		entryType = "url"
	} else if strings.Contains(format, "hash") {
		entryType = "hash"
	}
	var entries []FeedEntry
	scanner := bufio.NewScanner(r)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, "//") {
			continue
		}
		entries = append(entries, FeedEntry{Type: entryType, Value: line, Threat: "indicator", Source: "custom"})
	}
	return entries, scanner.Err()
}

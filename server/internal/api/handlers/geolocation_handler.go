package handlers

import (
	"context"
	"encoding/json"
	"net"
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/jackc/pgx/v5/pgxpool"
)

// GeolocationHandler provides GeoIP lookup endpoints.
type GeolocationHandler struct {
	pool *pgxpool.Pool
}

// NewGeolocationHandler creates a new GeolocationHandler.
func NewGeolocationHandler(pool *pgxpool.Pool) *GeolocationHandler {
	return &GeolocationHandler{pool: pool}
}

// GeoIPResult holds geo-location data for a single IP address.
type GeoIPResult struct {
	IP          string  `json:"ip"`
	Country     string  `json:"country"`
	CountryCode string  `json:"country_code"`
	City        string  `json:"city"`
	ASN         string  `json:"asn"`
	ISP         string  `json:"isp"`
	IsPrivate   bool    `json:"is_private"`
	IsTor       bool    `json:"is_tor"`
	IsProxy     bool    `json:"is_proxy"`
	IsHosting   bool    `json:"is_hosting"`
	Latitude    float64 `json:"latitude"`
	Longitude   float64 `json:"longitude"`
}

// isPrivateIP reports whether the parsed IP falls in a private/loopback/link-local range.
func isPrivateIP(ip net.IP) bool {
	if ip == nil {
		return false
	}
	privateRanges := []string{
		"10.0.0.0/8",
		"172.16.0.0/12",
		"192.168.0.0/16",
		"127.0.0.0/8",
		"::1/128",
		"fc00::/7",
		"fe80::/10",
		"169.254.0.0/16",
	}
	for _, cidr := range privateRanges {
		_, network, err := net.ParseCIDR(cidr)
		if err != nil {
			continue
		}
		if network.Contains(ip) {
			return true
		}
	}
	return false
}

// lookupIP resolves a single IP string into a GeoIPResult via ip-api.com.
// Private/loopback IPs are handled locally without an external call.
func lookupIP(ctx context.Context, rawIP string) GeoIPResult {
	rawIP = strings.TrimSpace(rawIP)
	result := GeoIPResult{IP: rawIP}

	ip := net.ParseIP(rawIP)
	if ip == nil {
		result.Country = "Invalid"
		return result
	}

	if isPrivateIP(ip) {
		result.IsPrivate = true
		result.Country = "Private"
		result.CountryCode = "PRIVATE"
		result.City = "Local Network"
		return result
	}

	// Use the shared ip-api.com client from alert_enrichment_pipeline.go.
	geo := lookupGeoIP(ctx, rawIP)
	if geo == nil {
		result.Country = "Unknown"
		result.CountryCode = "XX"
		result.City = "Unknown"
		result.ISP = "Unknown"
		return result
	}

	return GeoIPResult{
		IP:          rawIP,
		Country:     geo.Country,
		CountryCode: geo.CountryCode,
		City:        geo.City,
		ISP:         geo.ISP,
		IsProxy:     geo.IsProxy,
		IsTor:       geo.IsTor,
		Latitude:    geo.Lat,
		Longitude:   geo.Lon,
	}
}

// Lookup handles GET /api/v1/geo/lookup?ip=<address>
func (h *GeolocationHandler) Lookup(c *gin.Context) {
	ipParam := c.Query("ip")
	if ipParam == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "ip query parameter is required"})
		return
	}

	result := lookupIP(c.Request.Context(), ipParam)
	c.JSON(http.StatusOK, result)
}

// bulkLookupRequest is the request body for the bulk lookup endpoint.
type bulkLookupRequest struct {
	IPs []string `json:"ips" binding:"required"`
}

// BulkLookup handles POST /api/v1/geo/lookup/bulk
// Body: {"ips":["1.2.3.4","5.6.7.8"]}
// Response: {"results":[...]}
func (h *GeolocationHandler) BulkLookup(c *gin.Context) {
	var req bulkLookupRequest
	if err := json.NewDecoder(c.Request.Body).Decode(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request body"})
		return
	}

	if len(req.IPs) == 0 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "ips array must not be empty"})
		return
	}

	const maxBulk = 100
	if len(req.IPs) > maxBulk {
		c.JSON(http.StatusBadRequest, gin.H{"error": "too many IPs; maximum is 100 per request"})
		return
	}

	results := make([]GeoIPResult, 0, len(req.IPs))
	for _, ip := range req.IPs {
		results = append(results, lookupIP(c.Request.Context(), ip))
	}

	c.JSON(http.StatusOK, gin.H{"results": results})
}

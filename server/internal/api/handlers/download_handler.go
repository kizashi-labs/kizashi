package handlers

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/gin-gonic/gin"
)

// DownloadHandler serves pre-built agent binaries for self-update.
type DownloadHandler struct {
	binDir string // directory containing edr-agent-* binaries
}

func NewDownloadHandler(binDir string) *DownloadHandler {
	return &DownloadHandler{binDir: binDir}
}

// allowedVariants are the build variants that may be requested. A variant names
// a differently-compiled build of the same version, not a different version:
//
//	""      default build (telemetry only)
//	"ebpf"  edr-agent-linux-amd64-ebpf — eBPF/LSM exec prevention, tamper
//	        protection and credential-access auditing compiled in
//	"esf"   edr-agent-darwin-<arch>-esf — Apple Endpoint Security Framework
//	        collector (and AUTH_EXEC prevention with the approved entitlement)
//
// It is an allowlist rather than a sanitised passthrough because the value
// lands in a filename; anything outside this set is rejected before it can
// reach the filesystem.
var allowedVariants = map[string]bool{"": true, "ebpf": true, "esf": true}

// binaryFilename returns the filename and full path for the requested binary.
// binary is "agent" or "watchdog"; platform is "linux"/"windows"/"darwin"; arch
// is "amd64"/"arm64"; variant is "" or a key of allowedVariants.
//
// Only the agent has variant builds. A watchdog request carrying a variant
// resolves to the plain watchdog rather than 404-ing: the watchdog contains no
// prevention code, so one binary serves both variants and install/update must
// not fail merely because it was asked with the agent's variant.
func (h *DownloadHandler) binaryFilename(binary, platform, arch, variant string) (filename, fullPath string, err error) {
	suffix := ""
	if platform == "windows" {
		suffix = ".exe"
	}
	variantPart := ""
	if variant != "" && binary == "agent" {
		variantPart = "-" + variant
	}
	filename = fmt.Sprintf("edr-%s-%s-%s%s%s", binary, platform, arch, variantPart, suffix)
	fullPath = filepath.Join(h.binDir, filename)

	// Prevent path traversal
	if !strings.HasPrefix(filepath.Clean(fullPath), filepath.Clean(h.binDir)) {
		return "", "", fmt.Errorf("forbidden")
	}
	return filename, fullPath, nil
}

// GET /api/v1/agents/download?platform=linux&arch=amd64[&binary=agent][&variant=ebpf]
// Returns the latest agent (or watchdog) binary for the requested platform.
func (h *DownloadHandler) GetBinary(c *gin.Context) {
	platform := c.DefaultQuery("platform", runtime.GOOS)
	arch := c.DefaultQuery("arch", runtime.GOARCH)
	binary := c.DefaultQuery("binary", "agent")
	variant := c.Query("variant")

	allowed := map[string]bool{
		"linux": true, "windows": true, "darwin": true,
		"amd64": true, "arm64": true,
	}
	allowedBinary := map[string]bool{"agent": true, "watchdog": true}

	if !allowed[platform] || !allowed[arch] {
		c.JSON(http.StatusBadRequest, gin.H{"error": "unsupported platform/arch"})
		return
	}
	if !allowedBinary[binary] {
		c.JSON(http.StatusBadRequest, gin.H{"error": "unsupported binary"})
		return
	}
	if !allowedVariants[variant] {
		c.JSON(http.StatusBadRequest, gin.H{"error": "unsupported variant"})
		return
	}

	filename, fullPath, err := h.binaryFilename(binary, platform, arch, variant)
	if err != nil {
		c.JSON(http.StatusForbidden, gin.H{"error": "forbidden"})
		return
	}

	if _, err := os.Stat(fullPath); os.IsNotExist(err) {
		c.JSON(http.StatusNotFound, gin.H{"error": "binary not available"})
		return
	}

	c.Header("Content-Disposition", fmt.Sprintf(`attachment; filename="%s"`, filename))
	c.Header("Cache-Control", "no-cache")
	c.File(fullPath)
}

// GET /api/v1/agents/download/checksum?platform=linux&arch=amd64[&binary=agent][&variant=ebpf]
// Returns the SHA-256 checksum of the binary.
// Reads from a pre-computed .sha256 file if present; otherwise computes on the fly.
func (h *DownloadHandler) GetChecksum(c *gin.Context) {
	platform := c.DefaultQuery("platform", runtime.GOOS)
	arch := c.DefaultQuery("arch", runtime.GOARCH)
	binary := c.DefaultQuery("binary", "agent")
	variant := c.Query("variant")

	allowed := map[string]bool{
		"linux": true, "windows": true, "darwin": true,
		"amd64": true, "arm64": true,
	}
	allowedBinary := map[string]bool{"agent": true, "watchdog": true}

	if !allowed[platform] || !allowed[arch] {
		c.JSON(http.StatusBadRequest, gin.H{"error": "unsupported platform/arch"})
		return
	}
	if !allowedBinary[binary] {
		c.JSON(http.StatusBadRequest, gin.H{"error": "unsupported binary"})
		return
	}
	if !allowedVariants[variant] {
		c.JSON(http.StatusBadRequest, gin.H{"error": "unsupported variant"})
		return
	}

	_, fullPath, err := h.binaryFilename(binary, platform, arch, variant)
	if err != nil {
		c.JSON(http.StatusForbidden, gin.H{"error": "forbidden"})
		return
	}

	if _, err := os.Stat(fullPath); os.IsNotExist(err) {
		c.JSON(http.StatusNotFound, gin.H{"error": "binary not available"})
		return
	}

	hash, err := computeOrReadSHA256(fullPath)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "could not compute checksum"})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"platform": platform,
		"arch":     arch,
		"binary":   binary,
		"variant":  variant,
		"checksum": hash,
	})
}

// computeOrReadSHA256 returns the hex SHA-256 of the file at path.
// It first tries to read a pre-computed "<path>.sha256" sidecar file (sha256sum format);
// if that is absent or unreadable it computes the hash on the fly.
func computeOrReadSHA256(path string) (string, error) {
	sidecar := path + ".sha256"
	if data, err := os.ReadFile(sidecar); err == nil {
		// sha256sum format: "<hex>  <filename>\n" — take first whitespace-delimited field
		fields := strings.Fields(string(data))
		if len(fields) > 0 && len(fields[0]) == 64 {
			return strings.ToLower(fields[0]), nil
		}
	}

	// Fall back to computing on the fly
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()

	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

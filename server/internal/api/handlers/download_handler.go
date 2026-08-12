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

// binaryFilename returns the filename and full path for the requested binary.
// binary is "agent" or "watchdog"; platform is "linux"/"windows"/"darwin"; arch is "amd64"/"arm64".
func (h *DownloadHandler) binaryFilename(binary, platform, arch string) (filename, fullPath string, err error) {
	suffix := ""
	if platform == "windows" {
		suffix = ".exe"
	}
	filename = fmt.Sprintf("edr-%s-%s-%s%s", binary, platform, arch, suffix)
	fullPath = filepath.Join(h.binDir, filename)

	// Prevent path traversal
	if !strings.HasPrefix(filepath.Clean(fullPath), filepath.Clean(h.binDir)) {
		return "", "", fmt.Errorf("forbidden")
	}
	return filename, fullPath, nil
}

// GET /api/v1/agents/download?platform=linux&arch=amd64[&binary=agent]
// Returns the latest agent (or watchdog) binary for the requested platform.
func (h *DownloadHandler) GetBinary(c *gin.Context) {
	platform := c.DefaultQuery("platform", runtime.GOOS)
	arch := c.DefaultQuery("arch", runtime.GOARCH)
	binary := c.DefaultQuery("binary", "agent")

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

	filename, fullPath, err := h.binaryFilename(binary, platform, arch)
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

// GET /api/v1/agents/download/checksum?platform=linux&arch=amd64[&binary=agent]
// Returns the SHA-256 checksum of the binary.
// Reads from a pre-computed .sha256 file if present; otherwise computes on the fly.
func (h *DownloadHandler) GetChecksum(c *gin.Context) {
	platform := c.DefaultQuery("platform", runtime.GOOS)
	arch := c.DefaultQuery("arch", runtime.GOARCH)
	binary := c.DefaultQuery("binary", "agent")

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

	_, fullPath, err := h.binaryFilename(binary, platform, arch)
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

package handlers

import (
	"bytes"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
)

// DownloadPDF generates and streams a completed report as a PDF file.
// GET /api/v1/reports/:id/pdf
func (h *ReportHandler) DownloadPDF(c *gin.Context) {
	id := c.Param("id")

	if h.ReportStore == nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "レポートストアが設定されていません"})
		return
	}

	job, err := h.ReportStore.Get(c.Request.Context(), id)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "レポートが見つかりません"})
		return
	}

	if job.Status != "completed" {
		c.JSON(http.StatusAccepted, gin.H{
			"message": "レポートはまだ生成中です",
			"status":  job.Status,
			"id":      id,
		})
		return
	}

	title := fmt.Sprintf("EDR Platform Report - %s", typeLabel(job.Type))

	var lines []string
	lines = append(lines, fmt.Sprintf("Report ID    : %s", job.ID))
	lines = append(lines, fmt.Sprintf("Type         : %s (%s)", typeLabel(job.Type), job.Type))
	lines = append(lines, fmt.Sprintf("Status       : %s", job.Status))
	lines = append(lines, fmt.Sprintf("Requested By : %s", job.RequestedBy))
	lines = append(lines, fmt.Sprintf("Requested At : %s", job.RequestedAt.Format(time.RFC3339)))
	if job.CompletedAt != nil {
		lines = append(lines, fmt.Sprintf("Completed At : %s", job.CompletedAt.Format(time.RFC3339)))
	}
	lines = append(lines, "")
	lines = append(lines, strings.Repeat("-", 72))
	lines = append(lines, "")

	if job.Content != nil {
		flattenContent("", job.Content, &lines, 0)
	}

	pdf := buildPDF(title, lines)
	filename := fmt.Sprintf("edr-report-%s.pdf", job.ID[:8])

	c.Header("Content-Disposition", fmt.Sprintf(`attachment; filename="%s"`, filename))
	c.Header("Content-Length", fmt.Sprintf("%d", len(pdf)))
	c.Data(http.StatusOK, "application/pdf", pdf)
}

func typeLabel(t string) string {
	switch t {
	case "alert_summary":
		return "Alert Summary"
	case "agent_status":
		return "Agent Status"
	case "threat_report":
		return "Threat Report"
	default:
		return t
	}
}

// flattenContent recursively flattens a map/slice into text lines.
func flattenContent(prefix string, v interface{}, lines *[]string, depth int) {
	if depth >= 5 {
		return
	}
	indent := strings.Repeat("  ", depth)
	switch val := v.(type) {
	case map[string]interface{}:
		for k, vv := range val {
			switch vv.(type) {
			case map[string]interface{}, []interface{}:
				*lines = append(*lines, fmt.Sprintf("%s%s:", indent, k))
				flattenContent(k, vv, lines, depth+1)
			default:
				*lines = append(*lines, fmt.Sprintf("%s%-20s %v", indent, k+":", vv))
			}
		}
	case []interface{}:
		for i, item := range val {
			if i >= 25 {
				*lines = append(*lines, fmt.Sprintf("%s  ... and %d more items", indent, len(val)-25))
				break
			}
			switch item.(type) {
			case map[string]interface{}:
				*lines = append(*lines, fmt.Sprintf("%s[%d]", indent, i+1))
				flattenContent("", item, lines, depth+1)
			default:
				*lines = append(*lines, fmt.Sprintf("%s  %v", indent, item))
			}
		}
	default:
		*lines = append(*lines, fmt.Sprintf("%s%v", indent, val))
	}
}

// buildPDF creates a minimal but valid PDF-1.4 document with the given title and body lines.
func buildPDF(title string, lines []string) []byte {
	// ─── Content stream ────────────────────────────────────────
	var cs strings.Builder
	cs.WriteString("BT\n")

	// Title in Helvetica-Bold 14pt
	cs.WriteString("/F1 14 Tf\n")
	cs.WriteString(fmt.Sprintf("50 790 Td\n(%s) Tj\n", pdfEscape(sanitizeLine(title))))

	// Subtitle line
	cs.WriteString("/F2 9 Tf\n")
	cs.WriteString(fmt.Sprintf("0 -20 Td\n(%s) Tj\n", pdfEscape(fmt.Sprintf("Generated: %s", time.Now().Format("2006-01-02 15:04:05 UTC")))))

	// Divider
	cs.WriteString(fmt.Sprintf("0 -10 Td\n(%s) Tj\n", pdfEscape(strings.Repeat("-", 72))))

	// Body lines at 11pt leading
	const maxLines = 80
	for i, line := range lines {
		if i >= maxLines {
			cs.WriteString(fmt.Sprintf("0 -11 Td\n(%s) Tj\n",
				pdfEscape(fmt.Sprintf("... (%d more lines omitted)", len(lines)-maxLines))))
			break
		}
		safe := sanitizeLine(line)
		if safe == "" {
			safe = " "
		}
		cs.WriteString(fmt.Sprintf("0 -11 Td\n(%s) Tj\n", pdfEscape(safe)))
	}
	cs.WriteString("ET\n")

	content := []byte(cs.String())

	// ─── Build PDF objects ────────────────────────────────────
	var buf bytes.Buffer
	offsets := make([]int, 7) // objects 1–6

	buf.WriteString("%PDF-1.4\n")

	// Obj 1: Catalog
	offsets[1] = buf.Len()
	buf.WriteString("1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\n")

	// Obj 2: Pages
	offsets[2] = buf.Len()
	buf.WriteString("2 0 obj\n<< /Type /Pages /Kids [3 0 R] /Count 1 >>\nendobj\n")

	// Obj 3: Page (A4 = 595 x 842 pt)
	offsets[3] = buf.Len()
	buf.WriteString("3 0 obj\n" +
		"<< /Type /Page /Parent 2 0 R\n" +
		"   /MediaBox [0 0 595 842]\n" +
		"   /Contents 4 0 R\n" +
		"   /Resources << /Font << /F1 5 0 R /F2 6 0 R >> >>\n" +
		">>\nendobj\n")

	// Obj 4: Content stream
	offsets[4] = buf.Len()
	buf.WriteString(fmt.Sprintf("4 0 obj\n<< /Length %d >>\nstream\n", len(content)))
	buf.Write(content)
	buf.WriteString("\nendstream\nendobj\n")

	// Obj 5: Font Helvetica-Bold (title)
	offsets[5] = buf.Len()
	buf.WriteString("5 0 obj\n<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica-Bold >>\nendobj\n")

	// Obj 6: Font Helvetica (body)
	offsets[6] = buf.Len()
	buf.WriteString("6 0 obj\n<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>\nendobj\n")

	// ─── xref table ───────────────────────────────────────────
	xrefOffset := buf.Len()
	buf.WriteString("xref\n0 7\n")
	buf.WriteString("0000000000 65535 f \n")
	for i := 1; i <= 6; i++ {
		buf.WriteString(fmt.Sprintf("%010d 00000 n \n", offsets[i]))
	}

	// Trailer
	buf.WriteString(fmt.Sprintf("trailer\n<< /Size 7 /Root 1 0 R >>\nstartxref\n%d\n%%%%EOF\n", xrefOffset))

	return buf.Bytes()
}

// pdfEscape escapes special characters in a PDF string literal.
func pdfEscape(s string) string {
	s = strings.ReplaceAll(s, `\`, `\\`)
	s = strings.ReplaceAll(s, `(`, `\(`)
	s = strings.ReplaceAll(s, `)`, `\)`)
	return s
}

// sanitizeLine keeps only printable ASCII (32–126) to ensure PDF compatibility.
func sanitizeLine(s string) string {
	var b strings.Builder
	for _, r := range s {
		if r >= 32 && r <= 126 {
			b.WriteRune(r)
		} else if r == '\t' {
			b.WriteString("  ")
		}
	}
	// Truncate long lines
	result := b.String()
	if len(result) > 100 {
		result = result[:97] + "..."
	}
	return result
}

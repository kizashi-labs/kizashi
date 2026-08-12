package scheduler

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// validDump builds a plausible plain-format pg_dump body ending with the
// completion marker, padded past minBackupBytes.
func validDump() string {
	body := strings.Repeat("-- table data ...\n", 100)
	return body + "\n--\n-- " + pgDumpCompleteMarker + "\n--\n"
}

func writeTemp(t *testing.T, content string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "backup.sql")
	if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
		t.Fatalf("write temp: %v", err)
	}
	return p
}

func TestVerifyBackupIntegrity_Valid(t *testing.T) {
	size, err := verifyBackupIntegrity(writeTemp(t, validDump()))
	if err != nil {
		t.Fatalf("valid dump rejected: %v", err)
	}
	if size < minBackupBytes {
		t.Errorf("size %d unexpectedly below floor", size)
	}
}

func TestVerifyBackupIntegrity_Empty(t *testing.T) {
	if _, err := verifyBackupIntegrity(writeTemp(t, "")); err == nil {
		t.Error("empty dump should be rejected")
	}
}

func TestVerifyBackupIntegrity_TooSmall(t *testing.T) {
	// Has the marker but is below the size floor → still rejected.
	if _, err := verifyBackupIntegrity(writeTemp(t, pgDumpCompleteMarker)); err == nil {
		t.Error("sub-floor dump should be rejected")
	}
}

func TestVerifyBackupIntegrity_Truncated(t *testing.T) {
	// Large enough but missing the completion marker (killed mid-write).
	truncated := strings.Repeat("-- table data ...\n", 100)
	if _, err := verifyBackupIntegrity(writeTemp(t, truncated)); err == nil {
		t.Error("dump missing completion marker should be rejected")
	} else if !strings.Contains(err.Error(), "completion marker") {
		t.Errorf("expected completion-marker error, got: %v", err)
	}
}

func TestVerifyBackupIntegrity_Missing(t *testing.T) {
	if _, err := verifyBackupIntegrity(filepath.Join(t.TempDir(), "nope.sql")); err == nil {
		t.Error("missing file should error")
	}
}

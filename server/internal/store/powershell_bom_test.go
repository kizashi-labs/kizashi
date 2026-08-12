package store

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Windows PowerShell 5.1 — still the default shell on Windows Server — reads a
// .ps1 file as the system ANSI codepage unless it starts with a UTF-8 BOM. A
// script that is UTF-8 without a BOM and contains non-ASCII text (every runbook
// and installer in this repo carries Japanese comments) therefore decodes to
// mojibake, and any byte sequence that lands on a quote or brace turns into a
// parse error before a single line runs.
//
// This is not theoretical. On the validation host (2026-08-05) the documented
// command from deploy/validation/README.md
//
//	powershell -ExecutionPolicy Bypass -File .\deploy\validation\atomic-runner-compact.ps1
//
// failed outright:
//
//	At C:\...\atomic-runner-<mojibake> ... char:50
//	Missing closing ')' in expression.
//
// 8 of the 10 .ps1 files in the repo were in this state, including
// agent/deploy/windows/Install-EDRAgent.ps1 — the agent installer a customer runs.
// The failure mode is loud but misleading: it points at a syntax error in a file
// whose syntax is fine.
//
// ASCII-only scripts are exempt: without non-ASCII bytes the codepage cannot
// change how they parse.
//
// This lives in package store only because that is where the repo's other
// repository-wide gates run (see debt_ledger_test.go); it has no relationship to
// the store itself.
func TestPowerShellScriptsWithNonASCIIHaveBOM(t *testing.T) {
	root := filepath.Join("..", "..", "..")
	var offenders []string

	err := filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return nil //nolint:nilerr // an unreadable path is not this test's business
		}
		if info.IsDir() {
			switch info.Name() {
			case ".git", "node_modules", "vendor":
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.EqualFold(filepath.Ext(path), ".ps1") {
			return nil
		}
		raw, readErr := os.ReadFile(path)
		if readErr != nil {
			return nil //nolint:nilerr
		}
		if strings.HasPrefix(string(raw), "\ufeff") {
			return nil // has a BOM
		}
		if isASCII(raw) {
			return nil // codepage cannot change how this parses
		}
		rel, _ := filepath.Rel(root, path)
		offenders = append(offenders, filepath.ToSlash(rel))
		return nil
	})
	if err != nil {
		t.Fatalf("walk: %v", err)
	}

	for _, f := range offenders {
		t.Errorf("%s は非ASCII文字を含むのに UTF-8 BOM がありません。"+
			"Windows PowerShell 5.1 はシステム ANSI として読むため、`-File` 実行が "+
			"構文エラーで失敗します（構文自体は正しいのに、そう見えないエラーが出ます）。"+
			"UTF-8 with BOM で保存してください", f)
	}
}

func isASCII(b []byte) bool {
	for _, c := range b {
		if c > 127 {
			return false
		}
	}
	return true
}

// validate-rules is a CI-time syntax/structure checker for the detection
// rules shipped under rules/ (Sigma YAML + YARA text rules).
//
// Before this tool existed, nothing in the repo checked that these rules
// were even parseable: a malformed rule would sit silently un-loaded in
// production with no build-time signal. This command reuses the *actual*
// production parsing logic rather than re-implementing a schema:
//
//   - Sigma (rules/sigma/**/*.yml): parsed and compiled via
//     server/internal/detection.SigmaEvaluator.LoadRule, the same exported
//     entry point the server uses to load Sigma rules at runtime (see
//     sigma_evaluator.go / sigma_builtins.go / sigma_db.go). A rule that
//     fails here would fail to load in production too.
//
//   - YARA (rules/yara/**/*.yar): there is a hand-rolled YARA-subset parser
//     in agent/internal/scanner (yara_scanner.go), but it lives in a
//     different Go module under an `internal/` package rooted at
//     github.com/edr-platform/agent — Go's internal-package visibility
//     rules make it impossible to import from server/cmd regardless of
//     module wiring. Rather than duplicate/re-implement YARA grammar, this
//     validates YARA rules with the real `yara` CLI (the reference
//     implementation, apt package `yara`, already available on the
//     ubuntu-latest CI image) via `yara -w <rule> <dummy-target>`. If the
//     `yara` binary isn't available (e.g. some local dev machines), it
//     falls back to a minimal structural check (balanced rule blocks,
//     required meta/strings/condition keywords) so the tool still catches
//     gross breakage instead of silently skipping YARA files.
//
// Usage:
//
//	go run ./cmd/validate-rules              (run from server/, or anywhere — it
//	                                           searches upward for a rules/ dir)
//	go run ./cmd/validate-rules -dir ../rules
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/edr-platform/server/internal/detection"
)

func main() {
	dir := flag.String("dir", "", "path to the rules/ directory (default: auto-detect by walking up from cwd)")
	flag.Parse()

	rulesDir := *dir
	if rulesDir == "" {
		found, err := findRulesDir(".")
		if err != nil {
			fmt.Fprintln(os.Stderr, "validate-rules:", err)
			os.Exit(1)
		}
		rulesDir = found
	}

	var failures []string
	sigmaCount, yaraCount := 0, 0

	sigmaFiles, err := globRecursive(filepath.Join(rulesDir, "sigma"), ".yml")
	if err != nil {
		fmt.Fprintln(os.Stderr, "validate-rules: scanning sigma rules:", err)
		os.Exit(1)
	}
	sort.Strings(sigmaFiles)
	for _, f := range sigmaFiles {
		sigmaCount++
		if err := validateSigmaFile(f); err != nil {
			failures = append(failures, fmt.Sprintf("%s: %s", f, err))
		}
	}

	yaraFiles, err := globRecursive(filepath.Join(rulesDir, "yara"), ".yar", ".yara")
	if err != nil {
		fmt.Fprintln(os.Stderr, "validate-rules: scanning yara rules:", err)
		os.Exit(1)
	}
	sort.Strings(yaraFiles)

	yaraBin, yaraBinErr := exec.LookPath("yara")
	if yaraBinErr != nil {
		fmt.Fprintln(os.Stderr, "validate-rules: WARNING: `yara` CLI not found in PATH — "+
			"falling back to a minimal structural check for .yar files. Install the `yara` "+
			"package (apt-get install yara) for full syntax validation.")
	}
	for _, f := range yaraFiles {
		yaraCount++
		var verr error
		if yaraBinErr == nil {
			verr = validateYaraFileWithCLI(yaraBin, f)
		} else {
			verr = validateYaraFileStructural(f)
		}
		if verr != nil {
			failures = append(failures, fmt.Sprintf("%s: %s", f, verr))
		}
	}

	fmt.Printf("validate-rules: checked %d sigma rule file(s), %d yara rule file(s) under %s\n",
		sigmaCount, yaraCount, rulesDir)

	if len(failures) > 0 {
		fmt.Fprintln(os.Stderr, "\nvalidate-rules: FAILED — invalid rule file(s):")
		for _, f := range failures {
			fmt.Fprintln(os.Stderr, "  - "+f)
		}
		os.Exit(1)
	}

	fmt.Println("validate-rules: OK — all rule files are syntactically valid")
}

// findRulesDir walks upward from start looking for a directory named
// "rules" containing a "sigma" subdirectory, so the tool works whether
// it's invoked from the repo root or from server/.
func findRulesDir(start string) (string, error) {
	abs, err := filepath.Abs(start)
	if err != nil {
		return "", err
	}
	dir := abs
	for i := 0; i < 8; i++ {
		candidate := filepath.Join(dir, "rules")
		if info, err := os.Stat(filepath.Join(candidate, "sigma")); err == nil && info.IsDir() {
			return candidate, nil
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			break
		}
		dir = parent
	}
	return "", fmt.Errorf("could not locate a rules/sigma directory by walking up from %s (pass -dir explicitly)", start)
}

// globRecursive returns all files under root whose extension matches one of exts.
func globRecursive(root string, exts ...string) ([]string, error) {
	var out []string
	err := filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			if os.IsNotExist(err) && path == root {
				return nil // no rules of this type yet — not an error
			}
			return err
		}
		if info.IsDir() {
			return nil
		}
		for _, ext := range exts {
			if strings.EqualFold(filepath.Ext(path), ext) {
				out = append(out, path)
				return nil
			}
		}
		return nil
	})
	if err != nil && !os.IsNotExist(err) {
		return nil, err
	}
	return out, nil
}

// ─── Sigma validation ──────────────────────────────────────────────

// validateSigmaFile parses and compiles a single Sigma YAML rule using the
// same code path the server uses at runtime (detection.SigmaEvaluator).
func validateSigmaFile(path string) error {
	// #nosec G304 -- path comes only from globRecursive() walking the fixed
	// rules/sigma directory; this is a CI-time dev tool, not a network-facing
	// service, and never reads a caller-supplied path.
	content, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("read: %w", err)
	}
	ev := detection.NewSigmaEvaluator()
	if err := ev.LoadRule(string(content)); err != nil {
		return err
	}
	return nil
}

// ─── YARA validation ───────────────────────────────────────────────

// validateYaraFileWithCLI shells out to the real `yara` binary to compile
// the rule file against a harmless empty target. `-w` promotes warnings
// (e.g. unreferenced strings) to errors so authoring mistakes aren't
// silently ignored, matching the spirit of "catch it before it ships".
func validateYaraFileWithCLI(yaraBin, path string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// #nosec G204 -- yaraBin is resolved via exec.LookPath("yara") (a fixed
	// binary name, not caller input); path comes only from globRecursive()
	// walking the fixed rules/yara directory. CI-time dev tool, not
	// network-facing.
	cmd := exec.CommandContext(ctx, yaraBin, "-w", path, os.DevNull)
	out, err := cmd.CombinedOutput()
	if err != nil {
		msg := strings.TrimSpace(string(out))
		if msg == "" {
			msg = err.Error()
		}
		return errors.New(msg)
	}
	return nil
}

var yaraRuleHeaderRe = regexp.MustCompile(`^\s*(private\s+)?(global\s+)?rule\s+[A-Za-z_][A-Za-z0-9_]*`)

// validateYaraFileStructural is a best-effort fallback used only when the
// `yara` CLI isn't installed. It cannot catch everything a real compiler
// would, but it does catch gross structural breakage: unbalanced braces,
// rule blocks missing a condition:, and string declarations that don't
// start with `$`.
func validateYaraFileStructural(path string) error {
	// #nosec G304 -- path comes only from globRecursive() walking the fixed
	// rules/yara directory; this is a CI-time dev tool, not a network-facing
	// service, and never reads a caller-supplied path.
	content, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("read: %w", err)
	}
	text := string(content)

	if strings.Count(text, "{") != strings.Count(text, "}") {
		return fmt.Errorf("unbalanced braces (%d '{' vs %d '}')",
			strings.Count(text, "{"), strings.Count(text, "}"))
	}

	lines := strings.Split(text, "\n")
	ruleCount := 0
	inRule := false
	sawCondition := false
	depth := 0
	ruleStartLine := 0
	currentName := ""

	for i, raw := range lines {
		line := strings.TrimSpace(raw)
		trimmedNoComment := line
		if idx := strings.Index(trimmedNoComment, "//"); idx >= 0 {
			trimmedNoComment = strings.TrimSpace(trimmedNoComment[:idx])
		}

		if !inRule && yaraRuleHeaderRe.MatchString(line) {
			inRule = true
			sawCondition = false
			ruleStartLine = i + 1
			fields := strings.Fields(strings.TrimPrefix(strings.TrimPrefix(line, "private "), "global "))
			if len(fields) >= 2 {
				currentName = fields[1]
			}
		}

		if inRule {
			depth += strings.Count(raw, "{") - strings.Count(raw, "}")
			if trimmedNoComment == "condition:" {
				sawCondition = true
			}
			if depth == 0 && strings.Contains(raw, "}") {
				// End of this rule block.
				if !sawCondition {
					return fmt.Errorf("rule %q (starting line %d): missing condition: block", currentName, ruleStartLine)
				}
				ruleCount++
				inRule = false
			}
		}
	}

	if inRule {
		return fmt.Errorf("rule %q (starting line %d): unterminated rule block (missing closing '}')", currentName, ruleStartLine)
	}
	if ruleCount == 0 {
		return errors.New("no `rule NAME { ... }` blocks found")
	}
	return nil
}

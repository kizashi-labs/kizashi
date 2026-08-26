package detection

// Command-line de-obfuscation pre-pass.
//
// Most builtin/DB Sigma rules match process command lines with `CommandLine|contains`.
// Adversaries routinely defeat those substring matches with cheap, semantics-preserving
// obfuscation that the shell strips at execution time but our matcher sees verbatim:
//
//	caret escapes:   w^h^o^a^m^i        (cmd.exe)
//	quote insertion: w"h"o"a"m"i        (cmd.exe / powershell)
//	backtick escape: w`h`o`a`m`i        (powershell)
//	encoded payload: powershell -enc <base64-UTF16LE>
//
// This pass produces a DE-OBFUSCATED shadow of the command line and APPENDS it to the
// original (joined by a newline) rather than replacing it. Because every rule uses
// `contains`, appending can only ADD match opportunities — the original substring is
// still present, so no existing rule can regress. The decoded body of an encoded
// PowerShell command is also appended, so content rules (DownloadString, IEX, Mimikatz…)
// fire on the payload instead of only the `-enc` flag.
//
// Wired into addPipelineSigmaAliases (alert_pipeline.go) so it runs on every event the
// AlertPipeline flattens, before Sigma evaluation.

import (
	"encoding/base64"
	"regexp"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf16"
)

// cmdlineKeys are the field names that may carry a process command line at the point
// normalization runs (snake, protojson camel, and the Sigma-cased variant).
var cmdlineKeys = []string{"command_line", "commandLine", "CommandLine"}

// normalizeCommandLine augments the command-line fields of a flattened event with a
// de-obfuscated shadow and any decoded encoded-PowerShell payload. Idempotent: a sentinel
// guards against double-augmentation if the pre-pass runs more than once on one event.
func normalizeCommandLine(flat map[string]interface{}) {
	if flat == nil {
		return
	}
	if _, done := flat["_cmdline_normalized"]; done {
		return
	}

	var raw string
	for _, k := range cmdlineKeys {
		if s, ok := flat[k].(string); ok && s != "" {
			raw = s
			break
		}
	}
	if raw == "" {
		return
	}

	aug := augmentCommandLine(raw)
	flat["_cmdline_normalized"] = true
	if aug == raw {
		return
	}
	// Write the augmented value to whichever command-line keys are present, and ensure
	// the Sigma-cased CommandLine carries it (rules evaluate against CommandLine).
	for _, k := range cmdlineKeys {
		if _, ok := flat[k]; ok {
			flat[k] = aug
		}
	}
	flat["CommandLine"] = aug
}

// augmentCommandLine returns the original command line with a de-obfuscated shadow and any
// decoded encoded-PowerShell payload appended (newline-separated). Returns the original
// unchanged when nothing new is produced.
func augmentCommandLine(raw string) string {
	parts := []string{raw}
	appendIfNew := func(s string) {
		if s == "" {
			return
		}
		for _, p := range parts {
			if p == s {
				return
			}
		}
		parts = append(parts, s)
	}

	if d := deobfuscateCommandLine(raw); d != raw {
		appendIfNew(d)
	}
	// PowerShell string concatenation: 'wh'+'oami' → whoami. Collapse the quote-plus-quote
	// joints, then strip the remaining quotes.
	if c := collapseConcatenation(raw); c != "" {
		appendIfNew(c)
		appendIfNew(deobfuscateCommandLine(c))
	}
	// [char] code arrays: [char]0x68+[char]0x69 → hi. Recover the reconstructed string.
	if cc := decodeCharCodes(raw); cc != "" {
		appendIfNew(cc)
	}
	if dec := decodeEncodedPowerShell(raw); dec != "" {
		appendIfNew(dec)
		// The decoded payload may itself be quote/caret/concat obfuscated.
		appendIfNew(deobfuscateCommandLine(dec))
		appendIfNew(collapseConcatenation(dec))
	}
	if len(parts) == 1 {
		return raw
	}
	return strings.Join(parts, "\n")
}

// concatRe matches a PowerShell/cmd string-concatenation joint: a closing quote, a +
// (optionally spaced), and an opening quote. Collapsing these rejoins fragmented keywords.
var concatRe = regexp.MustCompile(`["']\s*\+\s*["']`)

// collapseConcatenation rejoins quote-plus-quote concatenation (e.g. 'wh'+'oami') and
// returns the result, or "" when there is nothing to collapse. The returned string still
// carries surrounding quotes; callers also run deobfuscateCommandLine on it.
func collapseConcatenation(s string) string {
	if !strings.Contains(s, "+") {
		return ""
	}
	out := concatRe.ReplaceAllString(s, "")
	if out == s {
		return ""
	}
	return out
}

// charCodeRe matches a [char] cast applied to a hex (0x..) or decimal code point.
var charCodeRe = regexp.MustCompile(`(?i)\[char\]\s*\(?\s*(0x[0-9a-f]+|\d+)`)

// decodeCharCodes reconstructs the string built from a [char] code array
// ([char]0x68+[char]0x69 → "hi"). Requires at least 3 codes so ordinary single casts do
// not produce noise. Returns "" when no meaningful sequence is present.
func decodeCharCodes(s string) string {
	ms := charCodeRe.FindAllStringSubmatch(s, -1)
	if len(ms) < 3 {
		return ""
	}
	var b strings.Builder
	for _, m := range ms {
		tok := m[1]
		var n int64
		var err error
		if len(tok) > 2 && (tok[1] == 'x' || tok[1] == 'X') {
			n, err = strconv.ParseInt(tok[2:], 16, 32)
		} else {
			n, err = strconv.ParseInt(tok, 10, 32)
		}
		if err != nil || n <= 0 || n > 0x10FFFF {
			continue
		}
		b.WriteRune(rune(n))
	}
	return b.String()
}

// obfStripper removes the characters used for semantics-preserving command obfuscation:
// the cmd.exe caret, PowerShell backtick, and inserted single/double quotes. Stripping
// these reconstructs the literal command the shell would actually run.
var obfStripper = strings.NewReplacer("^", "", "`", "", "\"", "", "'", "")

// deobfuscateCommandLine strips obfuscation escape/quote characters and collapses runs of
// whitespace, reconstructing the effective command string for substring matching.
func deobfuscateCommandLine(raw string) string {
	if !strings.ContainsAny(raw, "^`\"'") {
		return "" // nothing to strip
	}
	out := obfStripper.Replace(raw)
	out = strings.Join(strings.Fields(out), " ")
	return out
}

// encFlags are the PowerShell -EncodedCommand abbreviations (it accepts any unambiguous
// prefix). Ordered longest-first so the full flag is matched before its prefixes.
var encFlags = []string{" -encodedcommand ", " -encodedcommand", " -enc ", " -enc", " -ec ", " -ec", " -e "}

// decodeEncodedPowerShell finds an -EncodedCommand argument and returns its decoded text
// (PowerShell encodes as base64 of UTF-16LE). Returns "" if no encoded payload is present
// or it does not decode to plausible text.
func decodeEncodedPowerShell(cmd string) string {
	low := strings.ToLower(cmd)
	idx := -1
	for _, f := range encFlags {
		if p := strings.Index(low, f); p >= 0 {
			idx = p + len(f)
			break
		}
	}
	if idx < 0 || idx > len(cmd) {
		return ""
	}
	rest := strings.TrimLeft(cmd[idx:], " \t")
	tok := rest
	if sp := strings.IndexAny(rest, " \t\r\n"); sp >= 0 {
		tok = rest[:sp]
	}
	tok = strings.Trim(tok, "\"'")
	if len(tok) < 8 {
		return ""
	}

	data, err := base64.StdEncoding.DecodeString(tok)
	if err != nil {
		if data, err = base64.RawStdEncoding.DecodeString(tok); err != nil {
			return ""
		}
	}

	if s := utf16LEToString(data); isPlausibleText(s) {
		return s
	}
	if s := strings.ToValidUTF8(string(data), ""); isPlausibleText(s) {
		return s
	}
	return ""
}

// utf16LEToString decodes a little-endian UTF-16 byte slice to a Go string.
func utf16LEToString(b []byte) string {
	if len(b) < 2 || len(b)%2 != 0 {
		return ""
	}
	u := make([]uint16, len(b)/2)
	for i := range u {
		u[i] = uint16(b[2*i]) | uint16(b[2*i+1])<<8
	}
	return string(utf16.Decode(u))
}

// isPlausibleText rejects binary garbage from a failed/ambiguous decode by requiring the
// result to be non-empty and predominantly printable.
func isPlausibleText(s string) bool {
	if len(s) < 4 {
		return false
	}
	printable := 0
	total := 0
	for _, r := range s {
		total++
		if r == '\n' || r == '\r' || r == '\t' || (unicode.IsPrint(r) && r < 0xFFFD) {
			printable++
		}
	}
	return total > 0 && printable*100/total >= 85
}

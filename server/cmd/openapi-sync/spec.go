package main

import (
	"fmt"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

// ─── openapi.yaml の走査 ─────────────────────────────────────────────────────
//
// YAML ライブラリで読み書きすると、手書きのコメント・キー順・整形が全部
// 消える。ここは行ベースで扱い、手書きブロックはバイト列のまま持ち回す。

const generatedMarker = "x-generated: true"

// generatedBanner 以降が自動生成パスの置き場。手書きの並び（コメントで
// セクション分けされている）を壊さないよう、新規パスはここへ集める。
const generatedBanner = "  # ══════════════════════════════════════════════════════════════════\n" +
	"  # 以下は openapi-sync による自動生成。手で編集しないこと（次回の\n" +
	"  # 同期で消えます）。中身を書くときは、この操作を上の手書きセクションへ\n" +
	"  # 移してから書いてください。移した時点で自動生成の対象から外れます。\n" +
	"  #\n" +
	"  # 保証するのは「パス・メソッド・認証要否・パスパラメータが router.go と\n" +
	"  # 一致すること」だけです。要求/応答の形状は未記載です。\n" +
	"  # ══════════════════════════════════════════════════════════════════\n"

type methodBlock struct {
	method    string // 小文字（yaml のキーそのまま）
	lines     []string
	generated bool
}

type pathBlock struct {
	path    string   // "/api/v1/agents/{id}"
	lead    []string // このパスブロックの直前にあったコメント・空行
	methods []methodBlock
	// パスキー以外の行（parameters: など、メソッドと同階層のキー）。
	// 現状の openapi.yaml には無いが、あれば温存する。
	extras []string
}

// Spec は openapi.yaml を「ヘッダ / paths / フッタ」に割ったもの。
type Spec struct {
	header    []string // "paths:" の行まで含む
	blocks    []*pathBlock
	tailLead  []string // 最後のパスブロックの後、フッタの前に残ったコメント・空行
	footer    []string // "components:" 以降
	generated []*pathBlock
}

var (
	specPathRe   = regexp.MustCompile(`^  (/\S*):\s*$`)
	specMethodRe = regexp.MustCompile(`^    (get|post|put|delete|patch|head|options):\s*$`)
	specOtherRe  = regexp.MustCompile(`^    (\w[\w-]*):`)
	normParamRe  = regexp.MustCompile(`\{[^}]*\}`)
)

// normPath はパラメータ名の差を吸収する。`/agents/{id}` と `/agents/{agent_id}`
// は同じ操作を指すので、突合ではこちらを使う。
func normPath(p string) string { return normParamRe.ReplaceAllString(p, "{}") }

// ParseSpec は openapi.yaml を分解する。
func ParseSpec(src string) (*Spec, error) {
	lines := strings.Split(src, "\n")

	pathsIdx := -1
	for i, l := range lines {
		if l == "paths:" {
			pathsIdx = i
			break
		}
	}
	if pathsIdx < 0 {
		return nil, fmt.Errorf("`paths:` の行が見つかりません")
	}

	sp := &Spec{header: lines[:pathsIdx+1]}

	var lead []string
	var cur *pathBlock
	var curMethod *methodBlock

	flushMethod := func() {
		if cur != nil && curMethod != nil {
			curMethod.generated = containsMarker(curMethod.lines)
			cur.methods = append(cur.methods, *curMethod)
			curMethod = nil
		}
	}
	flushPath := func() {
		flushMethod()
		if cur != nil {
			sp.blocks = append(sp.blocks, cur)
			cur = nil
		}
	}

	i := pathsIdx + 1
	for ; i < len(lines); i++ {
		l := lines[i]

		// フッタ開始: インデント 0 の非空行
		if l != "" && !strings.HasPrefix(l, " ") {
			flushPath()
			break
		}

		if m := specPathRe.FindStringSubmatch(l); m != nil {
			flushPath()
			cur = &pathBlock{path: m[1], lead: lead}
			lead = nil
			continue
		}

		if cur == nil {
			// パスブロックの外＝次のブロックに付けるコメント・空行
			lead = append(lead, l)
			continue
		}

		if m := specMethodRe.FindStringSubmatch(l); m != nil {
			flushMethod()
			curMethod = &methodBlock{method: m[1], lines: []string{l}}
			continue
		}

		if strings.TrimSpace(l) == "" {
			// 空行は保留する。直後に本文が続けばブロックに戻し、
			// 別のブロックが始まるなら次ブロックの lead になる。
			lead = append(lead, l)
			continue
		}

		// メソッド本文はインデント 6 以上。それより浅い非空行
		// （`  # ── セクション ──` のようなコメント）はブロックの外。
		// ここで切らないと、区切りコメントが直前のメソッド本文に
		// 吸い込まれ、再生成のたびにコメントが増殖する。
		if !strings.HasPrefix(l, "      ") {
			flushMethod()
			if specOtherRe.MatchString(l) {
				cur.extras = append(cur.extras, lead...)
				cur.extras = append(cur.extras, l)
				lead = nil
				continue
			}
			lead = append(lead, l)
			continue
		}

		if curMethod == nil {
			cur.extras = append(cur.extras, lead...)
			cur.extras = append(cur.extras, l)
			lead = nil
			continue
		}
		if len(lead) > 0 {
			curMethod.lines = append(curMethod.lines, lead...)
			lead = nil
		}
		curMethod.lines = append(curMethod.lines, l)
	}

	sp.tailLead = lead
	if i < len(lines) {
		sp.footer = lines[i:]
	}
	return sp, nil
}

func containsMarker(lines []string) bool {
	for _, l := range lines {
		if strings.TrimSpace(l) == generatedMarker {
			return true
		}
	}
	return false
}

// handwritten は手書き操作の集合（正規化パス + メソッド）を返す。
func (s *Spec) handwritten() map[string]bool {
	out := map[string]bool{}
	for _, b := range s.blocks {
		for _, mb := range b.methods {
			if !mb.generated {
				out[strings.ToUpper(mb.method)+" "+normPath(b.path)] = true
			}
		}
	}
	return out
}

// HandwrittenDrift は「手書きで書かれているのに router.go に無い」操作を返す。
func (s *Spec) HandwrittenDrift(routes []Route) []string {
	real := map[string]bool{}
	for _, r := range routes {
		real[r.Method+" "+normPath(r.Path)] = true
	}
	var out []string
	for _, b := range s.blocks {
		for _, mb := range b.methods {
			if mb.generated {
				continue
			}
			key := strings.ToUpper(mb.method) + " " + normPath(b.path)
			if !real[key] {
				out = append(out, strings.ToUpper(mb.method)+" "+b.path)
			}
		}
	}
	return out
}

// PruneOrphans は「手書きで書かれているのに実装に無い」操作を仕様から落とし、
// 落とした数を返す。メソッドが全滅したパスブロックはブロックごと落とす。
//
// **公開版スナップショットの生成専用**（-prune-orphans）。本流では手書きの
// 乖離は人が読む誤りなので、黙って消さず HandwrittenDrift で止める。
func (s *Spec) PruneOrphans(routes []Route) int {
	real := map[string]bool{}
	for _, r := range routes {
		real[r.Method+" "+normPath(r.Path)] = true
	}
	dropped := 0
	var keptBlocks []*pathBlock
	for _, b := range s.blocks {
		var kept []methodBlock
		for _, mb := range b.methods {
			key := strings.ToUpper(mb.method) + " " + normPath(b.path)
			if !mb.generated && !real[key] {
				dropped++
				continue
			}
			kept = append(kept, mb)
		}
		b.methods = kept
		if len(b.methods) > 0 || len(b.extras) > 0 {
			keptBlocks = append(keptBlocks, b)
		}
	}
	s.blocks = keptBlocks
	return dropped
}

// Coverage は「手書きで形状まで書かれている操作数」と「実装の総操作数」を返す。
func (s *Spec) Coverage(routes []Route) (int, int) {
	hw := s.handwritten()
	n := 0
	for _, r := range routes {
		if hw[r.Method+" "+normPath(r.Path)] {
			n++
		}
	}
	return n, len(routes)
}

// Sync は自動生成ブロックを作り直し、ファイル全体の文字列を返す。
func (s *Spec) Sync(routes []Route) string {
	// operationId は仕様全体で一意でなければならない。手書きの ID を先に
	// 押さえ、自動生成分はそこと衝突しないよう連番で逃がす。routes は
	// ソート済みなので、採番は実行のたびに同じになる。
	usedIDs := map[string]bool{}
	for _, id := range regexp.MustCompile(`(?m)^\s+operationId:\s*(\S+)`).FindAllStringSubmatch(strings.Join(s.allLines(), "\n"), -1) {
		usedIDs[id[1]] = true
	}

	// 1. 既存の自動生成ブロックを落とす
	var kept []*pathBlock
	for _, b := range s.blocks {
		var ms []methodBlock
		for _, mb := range b.methods {
			if !mb.generated {
				ms = append(ms, mb)
			}
		}
		b.methods = ms
		if len(ms) > 0 || len(b.extras) > 0 {
			kept = append(kept, b)
		} else if len(b.lead) > 0 {
			// ブロックごと消えるなら、直前のコメントも一緒に落とす
			// （自動生成バナーだけが残るのを防ぐ）
			continue
		}
	}
	s.blocks = kept

	byNorm := map[string]*pathBlock{}
	for _, b := range s.blocks {
		byNorm[normPath(b.path)] = b
	}

	documented := s.handwritten()

	// 2. 足りない操作をスタブで埋める
	newBlocks := map[string]*pathBlock{}
	var newOrder []string
	for _, r := range routes {
		key := r.Method + " " + normPath(r.Path)
		if documented[key] {
			continue
		}
		if b, ok := byNorm[normPath(r.Path)]; ok {
			b.methods = append(b.methods, stubBlock(r, b.path, usedIDs))
			continue
		}
		b, ok := newBlocks[r.Path]
		if !ok {
			b = &pathBlock{path: r.Path}
			newBlocks[r.Path] = b
			newOrder = append(newOrder, r.Path)
		}
		b.methods = append(b.methods, stubBlock(r, r.Path, usedIDs))
	}
	sort.Strings(newOrder)
	for _, p := range newOrder {
		s.generated = append(s.generated, newBlocks[p])
	}

	// 3. 書き出し
	var out []string
	out = append(out, s.header...)
	for _, b := range s.blocks {
		out = append(out, b.lead...)
		out = append(out, "  "+b.path+":")
		out = append(out, b.extras...)
		sortMethods(b.methods)
		for _, mb := range b.methods {
			out = append(out, mb.lines...)
		}
	}
	if len(s.generated) > 0 {
		out = append(out, "")
		out = append(out, strings.Split(strings.TrimRight(generatedBanner, "\n"), "\n")...)
		for _, b := range s.generated {
			out = append(out, "")
			out = append(out, "  "+b.path+":")
			sortMethods(b.methods)
			for _, mb := range b.methods {
				out = append(out, mb.lines...)
			}
		}
	}
	out = append(out, s.tailLead...)
	out = append(out, s.footer...)

	return strings.Join(collapseBlankRuns(out), "\n")
}

func sortMethods(ms []methodBlock) {
	sort.SliceStable(ms, func(i, j int) bool {
		return methodOrder(strings.ToUpper(ms[i].method)) < methodOrder(strings.ToUpper(ms[j].method))
	})
}

// collapseBlankRuns は空行が 2 行以上続くのを 1 行に潰す。
// ブロックの出し入れで空行が増減しても、出力が安定するようにする。
func collapseBlankRuns(lines []string) []string {
	out := make([]string, 0, len(lines))
	blank := 0
	for _, l := range lines {
		if strings.TrimSpace(l) == "" {
			blank++
			if blank > 1 {
				continue
			}
		} else {
			blank = 0
		}
		out = append(out, l)
	}
	return out
}

// stubBlock は 1 操作分の自動生成ブロックを組み立てる。
// blockPath はパスキー側の綴り。パラメータ名が router 側と食い違う場合
// （`{id}` と `{agent_id}`）、parameters はキー側に合わせないと不整合になる。
func stubBlock(r Route, blockPath string, usedIDs map[string]bool) methodBlock {
	oid := uniqueID(operationID(r.Method, blockPath), usedIDs)
	lines := []string{
		"    " + strings.ToLower(r.Method) + ":",
		"      tags: [" + tagFor(r.Path) + "]",
		"      summary: " + r.Method + " " + blockPath,
		"      description: 実装の存在のみ自動検証。要求/応答の形状は未記載。",
		"      operationId: " + oid,
		"      " + generatedMarker,
	}
	if r.Public {
		lines = append(lines, "      security: []")
	}
	if params := pathParams(blockPath); len(params) > 0 {
		lines = append(lines, "      parameters:")
		for _, p := range params {
			lines = append(lines,
				`        - { name: `+p+`, in: path, required: true, schema: { type: string } }`)
		}
	}
	lines = append(lines,
		"      responses:",
		`        "200": { $ref: "#/components/responses/Undocumented" }`)
	return methodBlock{method: strings.ToLower(r.Method), lines: lines, generated: true}
}

// tagFor は /api/v1/<seg>/... の <seg> をタグにする。
// /api/v1 の外（/healthz, /taxii2/... など）は "other"。
func tagFor(p string) string {
	rest, ok := strings.CutPrefix(p, "/api/v1/")
	if !ok {
		return "other"
	}
	seg, _, _ := strings.Cut(rest, "/")
	if seg == "" {
		return "other"
	}
	return seg
}

// allLines はヘッダ・手書きパス・フッタの全行を返す（ID の重複判定用）。
func (s *Spec) allLines() []string {
	var out []string
	out = append(out, s.header...)
	for _, b := range s.blocks {
		for _, mb := range b.methods {
			if !mb.generated {
				out = append(out, mb.lines...)
			}
		}
	}
	out = append(out, s.footer...)
	return out
}

// uniqueID は衝突したら 2, 3, ... を足して一意にする。
// `/agents-risk-scores` と `/agents/risk-scores` のように、記号違いで
// 同じ camelCase に潰れるパスが実在する。
func uniqueID(base string, used map[string]bool) string {
	id := base
	for n := 2; used[id]; n++ {
		id = base + strconv.Itoa(n)
	}
	used[id] = true
	return id
}

var nonWord = regexp.MustCompile(`[^A-Za-z0-9]+`)

// operationID は (メソッド, パス) から一意な camelCase の ID を作る。
func operationID(method, path string) string {
	var b strings.Builder
	b.WriteString(strings.ToLower(method))
	for _, part := range nonWord.Split(path, -1) {
		if part == "" || part == "api" || part == "v1" {
			continue
		}
		b.WriteString(strings.ToUpper(part[:1]))
		b.WriteString(part[1:])
	}
	return b.String()
}

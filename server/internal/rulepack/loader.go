package rulepack

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"sort"
)

// Upserter is the storage contract the loader needs. Concrete implementation
// is *store.RulesStore; defined as an interface so the loader can be tested
// without a database.
type Upserter interface {
	UpsertPackRule(ctx context.Context, packKey string, r Rule) (inserted bool, err error)
}

// LoadResult reports what one directory of packs produced.
type LoadResult struct {
	Packs    int
	Rules    int
	Inserted int
	Updated  int

	// Skipped は書き込めなかったルール。1件ずつ理由を持つ。
	//
	// ★ **1つのルールが取り込めないことは、パック全体を落とす理由にならない。**
	// 実機で core パックを初めて読ませたとき、DB に同名の未所有ルールが2件あった
	// 1ルールのせいで残り 338 件が丸ごと入らず、しかも呼び出し側がそれを致命として
	// 扱ったため **API が起動できなくなった**。検知コンテンツの不備が管理面を
	// 落としてはいけない。
	Skipped []SkippedRule
}

// SkippedRule is one rule that could not be written, and why.
type SkippedRule struct {
	Pack   string
	Rule   string
	Reason string
}

// LoadDir reads every *.json pack in dir and upserts its rules.
//
// Absent or empty directories are not an error. The open source edition ships
// no packs at all and must start normally without them — it runs the builtin
// rules compiled into the binary. Treating "no content" as a failure would make
// the engine refuse to run in exactly the configuration it is published in.
//
// A pack that is present but broken IS an error, and no rules from it are
// applied. Half-loading a detection library is worse than not loading it: the
// operator sees rules appear and has no reason to suspect the rest are missing.
func LoadDir(ctx context.Context, up Upserter, dir string) (LoadResult, error) {
	var res LoadResult
	if dir == "" {
		return res, nil
	}

	paths, err := filepath.Glob(filepath.Join(dir, "*.json"))
	if err != nil {
		return res, fmt.Errorf("scan pack directory %s: %w", dir, err)
	}
	if len(paths) == 0 {
		slog.Info("no rule packs found; running with builtin rules only", "dir", dir)
		return res, nil
	}
	sort.Strings(paths) // deterministic order, so repeated loads log identically

	// Parse everything before writing anything. A directory with one bad pack
	// should change nothing, rather than leaving whichever packs sorted earlier
	// applied and the rest not.
	packs := make([]*Pack, 0, len(paths))
	for _, path := range paths {
		pack, perr := parseFile(path)
		if perr != nil {
			return res, perr
		}
		packs = append(packs, pack)
	}

	// 書き込みは1件ずつ独立に扱う。ここで最初の失敗で抜けると、後続のルールが
	// 丸ごと入らないまま「読み込み失敗」だけが残る——実機ではそれが起きて、
	// 1ルールの重複が 338 件の取り込みを止めた。
	for _, pack := range packs {
		for _, rule := range pack.Rules {
			inserted, uerr := up.UpsertPackRule(ctx, pack.PackKey(rule.Name), rule)
			if uerr != nil {
				res.Skipped = append(res.Skipped, SkippedRule{
					Pack: pack.Name, Rule: rule.Name, Reason: uerr.Error(),
				})
				slog.Warn("rule pack: このルールは取り込めませんでした（他のルールは続行します）",
					"pack", pack.Name, "rule", rule.Name, "error", uerr)
				continue
			}
			res.Rules++
			if inserted {
				res.Inserted++
			} else {
				res.Updated++
			}
		}
		res.Packs++
		slog.Info("rule pack loaded",
			"pack", pack.Name, "version", pack.Version,
			"rules", len(pack.Rules), "skipped", len(res.Skipped))
	}

	// 取り込めなかったルールがあれば**エラーとして返す**。続行することと、
	// 失敗を無かったことにすることは別で、ここを nil にすると保存側の障害
	// （DB が落ちている等）まで黙って消える。
	//
	// 返り値の res は使える状態で返す——呼び出し側は「入った分は入った」
	// うえで失敗を報告できる必要がある。**エラーであることと、続行できることは
	// 両立する。**
	if len(res.Skipped) > 0 {
		first := res.Skipped[0]
		return res, fmt.Errorf("pack %q rule %q: %s (取り込めなかったルール %d 件)",
			first.Pack, first.Rule, first.Reason, len(res.Skipped))
	}
	return res, nil
}

func parseFile(path string) (*Pack, error) {
	f, err := os.Open(path) // #nosec G304 -- path comes from Glob over the configured pack dir
	if err != nil {
		return nil, fmt.Errorf("open pack %s: %w", path, err)
	}
	defer func() { _ = f.Close() }()

	pack, err := Parse(f)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", filepath.Base(path), err)
	}
	return pack, nil
}

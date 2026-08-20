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

	for _, pack := range packs {
		for _, rule := range pack.Rules {
			inserted, uerr := up.UpsertPackRule(ctx, pack.PackKey(rule.Name), rule)
			if uerr != nil {
				return res, fmt.Errorf("pack %q rule %q: %w", pack.Name, rule.Name, uerr)
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
			"pack", pack.Name, "version", pack.Version, "rules", len(pack.Rules))
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

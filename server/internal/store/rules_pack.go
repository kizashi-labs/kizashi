package store

import (
	"context"
	"fmt"

	"github.com/edr-platform/server/internal/rulepack"
)

// UpsertPackRule writes one rule from a pack, keyed by pack_key.
//
// Idempotent by construction: pack_key carries a partial unique index
// (migration 449), so re-reading an unchanged pack updates rows to the values
// they already hold, and an updated pack updates in place rather than adding a
// second copy under the same name.
//
// Deliberately narrow. It never touches:
//
//   - id — an existing rule keeps it, so alerts.rule_id keeps pointing at the
//     same rule across pack updates. Replacing rules wholesale would sever
//     every historical alert from the rule that raised it.
//   - curate_state / quarantined_at — set by the curation pipeline and by
//     operators quarantining a noisy rule. A pack reload must not silently
//     un-quarantine something an operator switched off after a false-positive
//     storm.
//   - tenant_id — pack content is platform-wide.
//
// enabled IS overwritten, because that is the pack's statement about whether
// the rule should run. An operator who disables a pack rule by hand will see it
// re-enabled on the next load; quarantine (which pack loading does not touch)
// is the durable way to hold a rule down.
//
// # Adoption
//
// Rules used to arrive as INSERT statements in migrations, so every existing
// deployment already holds rows with pack_key IS NULL. Inserting the pack's
// copy alongside them would leave two rows with the same name — one the pack
// maintains and one nothing does — and both would be evaluated. The duplicate
// would be invisible except as alerts firing twice.
//
// So a pack claims the migration's row rather than shadowing it: if exactly one
// unclaimed row carries this name, it becomes the pack's, keeping its id and
// therefore every alert that references it.
//
// An ambiguous name is an error, not a guess. rules has no unique constraint on
// name and does contain duplicates; picking one arbitrarily would leave the
// other orphaned and still firing.
func (s *RuleStore) UpsertPackRule(ctx context.Context, packKey string, r rulepack.Rule) (bool, error) {
	if packKey == "" {
		return false, fmt.Errorf("pack key is empty")
	}

	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return false, fmt.Errorf("begin: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	// Refuse before writing anything if the name cannot identify one row.
	var unclaimed int
	if err := tx.QueryRow(ctx,
		`SELECT count(*) FROM rules WHERE pack_key IS NULL AND name = $1`, r.Name).
		Scan(&unclaimed); err != nil {
		return false, fmt.Errorf("count unclaimed rules named %q: %w", r.Name, err)
	}
	if unclaimed > 1 {
		return false, fmt.Errorf("%d rules already exist named %q with no pack, so the pack "+
			"cannot tell which one it replaces; resolve the duplicate before loading",
			unclaimed, r.Name)
	}

	// Claim the migration's row, unless this pack already owns one.
	claimTag, err := tx.Exec(ctx, `
		UPDATE rules SET pack_key = $1
		WHERE pack_key IS NULL AND name = $2
		  AND NOT EXISTS (SELECT 1 FROM rules WHERE pack_key = $1)
	`, packKey, r.Name)
	if err != nil {
		return false, fmt.Errorf("adopt existing rule %q: %w", r.Name, err)
	}
	claimed := claimTag.RowsAffected() > 0

	var inserted bool
	err = tx.QueryRow(ctx, `
		INSERT INTO rules (
			pack_key, name, type, platform, severity, content,
			description, source, mitre_tags, ref_links, tags,
			enabled, auto_isolate, auto_kill, auto_quarantine,
			created_at, updated_at
		) VALUES (
			$1, $2, $3, $4, $5, $6,
			$7, $8, $9, $10, $11,
			$12, $13, $14, $15,
			NOW(), NOW()
		)
		ON CONFLICT (pack_key) WHERE pack_key IS NOT NULL DO UPDATE SET
			name            = EXCLUDED.name,
			type            = EXCLUDED.type,
			platform        = EXCLUDED.platform,
			severity        = EXCLUDED.severity,
			content         = EXCLUDED.content,
			description     = EXCLUDED.description,
			source          = EXCLUDED.source,
			mitre_tags      = EXCLUDED.mitre_tags,
			ref_links       = EXCLUDED.ref_links,
			tags            = EXCLUDED.tags,
			enabled         = EXCLUDED.enabled,
			auto_isolate    = EXCLUDED.auto_isolate,
			auto_kill       = EXCLUDED.auto_kill,
			auto_quarantine = EXCLUDED.auto_quarantine,
			-- The rule body changed, so anything compiled from the old body is
			-- stale. Clearing it makes the engines recompile rather than keep
			-- evaluating the previous version of the rule under the new name.
			compiled        = NULL,
			updated_at      = NOW()
		RETURNING (xmax = 0) AS inserted
	`,
		packKey, r.Name, r.Type, r.Platform, r.Severity, r.Content,
		r.Description, r.ResolvedSource(), r.MitreTags, r.RefLinks, r.Tags,
		r.ResolvedEnabled(), r.AutoIsolate, r.AutoKill, r.AutoQuarantine,
	).Scan(&inserted)
	if err != nil {
		return false, fmt.Errorf("upsert pack rule %q: %w", packKey, err)
	}

	if err := tx.Commit(ctx); err != nil {
		return false, fmt.Errorf("commit: %w", err)
	}
	// A claimed row already existed, so it is an update even though this pack
	// had not seen it before. "Inserted" counts rules that were not there.
	return inserted && !claimed, nil
}

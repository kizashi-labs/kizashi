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
func (s *RuleStore) UpsertPackRule(ctx context.Context, packKey string, r rulepack.Rule) (bool, error) {
	if packKey == "" {
		return false, fmt.Errorf("pack key is empty")
	}

	var inserted bool
	err := s.pool.QueryRow(ctx, `
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
	return inserted, nil
}

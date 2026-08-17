package store

import (
	"reflect"
	"testing"
)

// TestNormalizeMITRETags pins the conversion that keeps rule attribution working.
//
// mitre_tags is compared by exact string when a detection is credited to a
// technique, so a rule carrying "attack.t1059.004" fires and contributes NOTHING:
// the alert appears, the analyst sees it, and the technique silently goes
// unattributed. Worse, a tactic tag left in the list can surface as the alert's
// mitre_technique — "attack.execution" is not a technique at all. 25 enabled rules
// were in that state on 2026-08-03.
func TestNormalizeMITRETags(t *testing.T) {
	cases := []struct {
		name string
		in   []string
		want []string
	}{
		{"生の技術タグを正規化", []string{"attack.t1059.004"}, []string{"T1059.004"}},
		{"サブ技術なし", []string{"attack.t1486"}, []string{"T1486"}},
		{"戦術タグは落とす", []string{"attack.execution", "attack.t1059.004"}, []string{"T1059.004"}},
		{"既に正しい行は触らない", []string{"T1003.008", "T1136.001"}, []string{"T1003.008", "T1136.001"}},
		{"正規化で生じた重複は畳む", []string{"T1059.004", "attack.t1059.004"}, []string{"T1059.004"}},
		// A rule whose only tags were tactics has no technique. Emptying it is the
		// honest outcome; keeping the tactic would put a tactic name where every
		// consumer expects a technique ID.
		{"戦術しか無ければ空になる", []string{"attack.persistence"}, []string{}},
		{"空はそのまま", []string{}, []string{}},
		// Order carries meaning: the first technique is treated as the rule's primary
		// one (detection/sigma_builtins.go), so normalization must not reorder.
		{"順序を保持する",
			[]string{"attack.t1003.008", "attack.credential_access", "T1136.001"},
			[]string{"T1003.008", "T1136.001"}},
		// Not every "attack."-prefixed string is a technique; only the tNNNN shape is.
		{"技術に見えないものは落とす", []string{"attack.g0016", "attack.s0002"}, []string{}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := normalizeMITRETags(c.in)
			if len(got) == 0 && len(c.want) == 0 {
				return
			}
			if !reflect.DeepEqual(got, c.want) {
				t.Errorf("normalizeMITRETags(%v) = %v, want %v", c.in, got, c.want)
			}
		})
	}
}

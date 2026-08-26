package detection

import "testing"

// `not` binds to ONE operand, not to the rest of the expression.
//
// The parser used to recurse into the full-expression parser after `not`, so
//
//	selection and not download and not certconv
//
// compiled as `selection and not (download and not certconv)`. That inverts the
// meaning of the second exclusion: with download absent and certconv present the
// rule fires, which is exactly the input the exclusion was added to suppress.
//
// Nothing caught it because every other `not` in the shipped corpus sits at the
// END of its condition, where "the rest of the expression" is empty and both
// readings agree. The bug only becomes reachable when a rule carries two
// exclusions — so a test that only exercises the shipped shapes would stay green
// through the regression. These cases deliberately use two.
func TestSigmaConditionNotBindsToOneOperand(t *testing.T) {
	sel := func(key string) func(map[string]interface{}) bool {
		return func(e map[string]interface{}) bool { return e[key] == true }
	}
	funcs := map[string]func(map[string]interface{}) bool{
		"selection": sel("selection"),
		"download":  sel("download"),
		"certconv":  sel("certconv"),
	}

	compile := func(t *testing.T, cond string) func(map[string]interface{}) bool {
		t.Helper()
		fn, err := compileConditionExpr(cond, funcs, "test")
		if err != nil {
			t.Fatalf("compile %q: %v", cond, err)
		}
		return fn
	}

	t.Run("two exclusions", func(t *testing.T) {
		fn := compile(t, "selection and not download and not certconv")
		for _, c := range []struct {
			name  string
			event map[string]interface{}
			want  bool
		}{
			// The case that regressed: one exclusion present, the other absent.
			{"certconv only", map[string]interface{}{"selection": true, "certconv": true}, false},
			{"download only", map[string]interface{}{"selection": true, "download": true}, false},
			{"both exclusions", map[string]interface{}{"selection": true, "download": true, "certconv": true}, false},
			{"neither exclusion", map[string]interface{}{"selection": true}, true},
			{"no selection", map[string]interface{}{"certconv": true}, false},
		} {
			if got := fn(c.event); got != c.want {
				t.Errorf("%s: got %v, want %v", c.name, got, c.want)
			}
		}
	})

	// The shape the whole corpus uses. It must keep behaving identically —
	// the fix is only allowed to change the two-exclusion reading.
	t.Run("single trailing exclusion is unchanged", func(t *testing.T) {
		fn := compile(t, "selection and not download")
		for _, c := range []struct {
			name  string
			event map[string]interface{}
			want  bool
		}{
			{"selection only", map[string]interface{}{"selection": true}, true},
			{"selection and download", map[string]interface{}{"selection": true, "download": true}, false},
			{"download only", map[string]interface{}{"download": true}, false},
		} {
			if got := fn(c.event); got != c.want {
				t.Errorf("%s: got %v, want %v", c.name, got, c.want)
			}
		}
	})

	// Parentheses must still override the default binding.
	t.Run("explicit grouping still wins", func(t *testing.T) {
		fn := compile(t, "selection and not (download and not certconv)")
		ev := map[string]interface{}{"selection": true, "download": true, "certconv": true}
		if !fn(ev) {
			t.Error("not (download and not certconv) with both present should be true")
		}
		ev2 := map[string]interface{}{"selection": true, "download": true}
		if fn(ev2) {
			t.Error("not (download and not certconv) with download only should be false")
		}
	})

	t.Run("or still reachable", func(t *testing.T) {
		fn := compile(t, "selection or download")
		if !fn(map[string]interface{}{"download": true}) {
			t.Error("or should fire on the right operand alone")
		}
		if fn(map[string]interface{}{}) {
			t.Error("or should not fire with neither operand")
		}
	})
}

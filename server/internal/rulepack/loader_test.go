package rulepack

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// fakeUpserter records what the loader wrote and can fail on demand.
type fakeUpserter struct {
	keys     []string
	rules    []Rule
	failOn   string
	existing map[string]bool
}

func (f *fakeUpserter) UpsertPackRule(_ context.Context, key string, r Rule) (bool, error) {
	if f.failOn != "" && strings.Contains(key, f.failOn) {
		return false, fmt.Errorf("boom")
	}
	f.keys = append(f.keys, key)
	f.rules = append(f.rules, r)
	return !f.existing[key], nil
}

func writePack(t *testing.T, dir, file, body string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(dir, file), []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
}

func packJSON(name string, ruleNames ...string) string {
	var rules []string
	for _, rn := range ruleNames {
		rules = append(rules, fmt.Sprintf(
			`{"name":%q,"type":"sigma","platform":["linux"],"severity":5,"content":"title: x"}`, rn))
	}
	return fmt.Sprintf(`{"name":%q,"version":"1","rules":[%s]}`, name, strings.Join(rules, ","))
}

func TestLoadDir_LoadsPacks(t *testing.T) {
	dir := t.TempDir()
	writePack(t, dir, "core.json", packJSON("core", "a", "b"))
	writePack(t, dir, "extra.json", packJSON("extra", "c"))

	up := &fakeUpserter{}
	res, err := LoadDir(context.Background(), up, dir)
	if err != nil {
		t.Fatal(err)
	}
	if res.Packs != 2 || res.Rules != 3 {
		t.Errorf("got packs=%d rules=%d, want 2/3", res.Packs, res.Rules)
	}
	want := []string{"core/a", "core/b", "extra/c"}
	if len(up.keys) != len(want) {
		t.Fatalf("keys = %v, want %v", up.keys, want)
	}
	for i := range want {
		if up.keys[i] != want[i] {
			t.Errorf("keys = %v, want %v", up.keys, want)
			break
		}
	}
}

// The open source edition ships no packs. Starting must not be an error there,
// or the engine refuses to run in the configuration it is published in.
func TestLoadDir_NoPacksIsNotAnError(t *testing.T) {
	up := &fakeUpserter{}
	res, err := LoadDir(context.Background(), up, t.TempDir())
	if err != nil {
		t.Fatalf("an empty pack directory must not fail startup: %v", err)
	}
	if res.Packs != 0 || res.Rules != 0 {
		t.Errorf("nothing should have loaded, got %+v", res)
	}
}

func TestLoadDir_UnsetDirIsNotAnError(t *testing.T) {
	if _, err := LoadDir(context.Background(), &fakeUpserter{}, ""); err != nil {
		t.Errorf("an unset pack directory must not fail startup: %v", err)
	}
}

// One broken pack must leave the database untouched. Applying whichever packs
// sorted earlier would give the operator a partly-loaded detection library and
// no signal that the rest is missing.
func TestLoadDir_BadPackAppliesNothing(t *testing.T) {
	dir := t.TempDir()
	writePack(t, dir, "aaa-good.json", packJSON("good", "a"))
	writePack(t, dir, "zzz-broken.json", `{"name":"broken","version":"1","rules":[{"name":"x","type":"snort","platform":["linux"],"severity":5,"content":"y"}]}`)

	up := &fakeUpserter{}
	_, err := LoadDir(context.Background(), up, dir)
	if err == nil {
		t.Fatal("a broken pack must fail the load")
	}
	if len(up.keys) != 0 {
		t.Errorf("nothing should have been written, got %v", up.keys)
	}
	if !strings.Contains(err.Error(), "zzz-broken.json") {
		t.Errorf("the error should name the offending file, got: %v", err)
	}
}

func TestLoadDir_CountsInsertsAndUpdates(t *testing.T) {
	dir := t.TempDir()
	writePack(t, dir, "core.json", packJSON("core", "a", "b"))

	up := &fakeUpserter{existing: map[string]bool{"core/a": true}}
	res, err := LoadDir(context.Background(), up, dir)
	if err != nil {
		t.Fatal(err)
	}
	if res.Inserted != 1 || res.Updated != 1 {
		t.Errorf("got inserted=%d updated=%d, want 1/1", res.Inserted, res.Updated)
	}
}

func TestLoadDir_ReportsStorageFailure(t *testing.T) {
	dir := t.TempDir()
	writePack(t, dir, "core.json", packJSON("core", "a"))

	up := &fakeUpserter{failOn: "core/a"}
	_, err := LoadDir(context.Background(), up, dir)
	if err == nil {
		t.Fatal("a storage failure must not be swallowed")
	}
	if !strings.Contains(err.Error(), "core") {
		t.Errorf("the error should name the pack and rule, got: %v", err)
	}
}

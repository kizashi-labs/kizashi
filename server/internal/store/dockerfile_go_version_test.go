package store_test

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// Dockerfiles that build Go code from server/go.mod must name a Go version at
// least as new as the module requires. Nothing else enforces this: each
// Dockerfile pins its own base image, and a `go` directive bump lands without
// touching any of them.
//
// The drift is not cosmetic. server/Dockerfile tracked the module to 1.26.6
// while deploy/docker/updater.Dockerfile stayed on 1.25, so the updater image
// alone stopped building:
//
//	go: go.mod requires go >= 1.26.6 (running go 1.25.13; GOTOOLCHAIN=local)
//
// The updater is the component that delivers updates. An updater image that
// cannot be rebuilt means fixes to the update path cannot be shipped through
// the update path — including the fix for that very problem. It went unnoticed
// because the running container had been built months earlier, and nothing
// rebuilds it until someone needs to.
func TestDockerfilesMatchGoModVersion(t *testing.T) {
	root := filepath.Join("..", "..", "..")

	required := readGoDirective(t, filepath.Join(root, "server", "go.mod"))

	// Dockerfiles that compile server/ code.
	dockerfiles := []string{
		filepath.Join("server", "Dockerfile"),
		filepath.Join("deploy", "docker", "updater.Dockerfile"),
	}

	golangRe := regexp.MustCompile(`(?m)^\s*(?:ARG\s+GO_VERSION=|FROM\s+golang:)([0-9][0-9.]*)`)

	for _, rel := range dockerfiles {
		t.Run(rel, func(t *testing.T) {
			path := filepath.Join(root, rel)
			data, err := os.ReadFile(path) //nolint:gosec // fixed repo-relative path
			if err != nil {
				t.Fatalf("read %s: %v", rel, err)
			}
			matches := golangRe.FindAllStringSubmatch(string(data), -1)
			if len(matches) == 0 {
				t.Fatalf("%s names no Go version; if it stopped building Go code, drop it from this list", rel)
			}
			for _, m := range matches {
				got := m[1]
				if compareVersions(got, required) < 0 {
					t.Errorf("%s pins Go %s but server/go.mod requires %s — "+
						"`go mod download` will fail with GOTOOLCHAIN=local",
						rel, got, required)
				}
			}
		})
	}
}

// readGoDirective returns the version on go.mod's `go` line.
func readGoDirective(t *testing.T, path string) string {
	t.Helper()
	data, err := os.ReadFile(path) //nolint:gosec // fixed repo-relative path
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	re := regexp.MustCompile(`(?m)^go\s+([0-9][0-9.]*)\s*$`)
	m := re.FindStringSubmatch(string(data))
	if m == nil {
		t.Fatalf("no `go` directive in %s", path)
	}
	return m[1]
}

// compareVersions compares dotted numeric versions of possibly differing
// length. A shorter version is treated as having zeros appended, so "1.25"
// sorts below "1.26.6" and "1.26" sorts below "1.26.6".
func compareVersions(a, b string) int {
	as, bs := strings.Split(a, "."), strings.Split(b, ".")
	for i := 0; i < len(as) || i < len(bs); i++ {
		av, bv := 0, 0
		if i < len(as) {
			av = atoiOrZero(as[i])
		}
		if i < len(bs) {
			bv = atoiOrZero(bs[i])
		}
		if av != bv {
			if av < bv {
				return -1
			}
			return 1
		}
	}
	return 0
}

func atoiOrZero(s string) int {
	n := 0
	for _, r := range s {
		if r < '0' || r > '9' {
			return n
		}
		n = n*10 + int(r-'0')
	}
	return n
}

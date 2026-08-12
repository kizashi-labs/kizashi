// Package backup implements the copy-on-write pre-image backup store that backs the
// rollback (SentinelOne Storyline–equivalent) feature — Ph4a-1 of
// docs/design/ロールバック(Storyline相当)設計.md. It captures a file's content BEFORE a
// suspicious process modifies/deletes it, so the pre-incident content can later be
// restored (ransomware rollback). This is the packet/kernel-independent file-I/O half;
// the fanotify/minifilter pre-write hook that decides WHEN to back up is a later phase.
//
// The store reuses the quarantine store's shape (a directory + generated ref + a JSON
// index) but COPIES rather than moves, and enforces a byte quota with oldest-first
// eviction so pre-image backups cannot grow without bound.
//
// SECURITY: paths come from telemetry about an active attacker. Reads and restores
// refuse to traverse a symlink (O_NOFOLLOW where the OS provides it, plus an explicit
// Lstat check) so a swapped symlink cannot redirect the copy or the restore (TOCTOU),
// matching the quarantine store's protections.
package backup

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"time"
)

// ErrSymlink is returned when a source or restore target is (or became) a symlink.
var ErrSymlink = errors.New("backup: refusing to follow symlink")

// Entry is one pre-image backup's metadata (persisted in index.json).
type Entry struct {
	Ref       string    `json:"ref"`
	OrigPath  string    `json:"orig_path"`
	Size      int64     `json:"size"`
	CreatedAt time.Time `json:"created_at"`
}

// Store is a quota-bounded copy-on-write pre-image backup store.
type Store struct {
	dir   string
	quota int64 // max total bytes across backups; 0 = unlimited
	mu    sync.Mutex
	index map[string]*Entry
	total int64
}

// NewStore opens (creating if needed) a backup store rooted at dir with the given byte
// quota (0 = unlimited). It loads any existing index so backups survive a restart.
func NewStore(dir string, quotaBytes int64) (*Store, error) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, fmt.Errorf("backup: mkdir: %w", err)
	}
	s := &Store{dir: dir, quota: quotaBytes, index: make(map[string]*Entry)}
	s.load()
	return s, nil
}

// Backup copies path's current content into the store and returns a ref used later to
// restore it. Refuses to follow a symlink at path.
func (s *Store) Backup(path string) (string, error) {
	src, err := s.openForRead(path)
	if err != nil {
		return "", err
	}
	defer src.Close()

	ref := newRef()
	dst := filepath.Join(s.dir, ref+".bak")
	out, err := os.OpenFile(dst, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		return "", fmt.Errorf("backup: create: %w", err)
	}
	n, copyErr := io.Copy(out, src)
	closeErr := out.Close()
	if copyErr != nil || closeErr != nil {
		_ = os.Remove(dst)
		if copyErr != nil {
			return "", fmt.Errorf("backup: copy: %w", copyErr)
		}
		return "", fmt.Errorf("backup: close: %w", closeErr)
	}

	s.mu.Lock()
	s.index[ref] = &Entry{Ref: ref, OrigPath: path, Size: n, CreatedAt: time.Now()}
	s.total += n
	s.enforceQuotaLocked()
	s.save()
	s.mu.Unlock()
	return ref, nil
}

// Restore writes the backed-up pre-image (ref) to restorePath, truncating any current
// content. Refuses to write through a symlink at restorePath.
func (s *Store) Restore(ref, restorePath string) error {
	s.mu.Lock()
	_, ok := s.index[ref]
	s.mu.Unlock()
	if !ok {
		return fmt.Errorf("backup: unknown ref %q", ref)
	}
	src, err := os.Open(filepath.Join(s.dir, ref+".bak"))
	if err != nil {
		return fmt.Errorf("backup: open ref: %w", err)
	}
	defer src.Close()

	if fi, err := os.Lstat(restorePath); err == nil && fi.Mode()&os.ModeSymlink != 0 {
		return ErrSymlink
	}
	out, err := os.OpenFile(restorePath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC|oNoFollow, 0o600)
	if err != nil {
		return fmt.Errorf("backup: open restore target: %w", err)
	}
	_, copyErr := io.Copy(out, src)
	closeErr := out.Close()
	if copyErr != nil {
		return fmt.Errorf("backup: restore copy: %w", copyErr)
	}
	return closeErr
}

// Evict removes a backup ref (e.g. after its change is reverted, or manually).
func (s *Store) Evict(ref string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.evictLocked(ref)
	s.save()
}

// Len reports how many backups are currently held.
func (s *Store) Len() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.index)
}

// TotalBytes reports the current total size of held backups.
func (s *Store) TotalBytes() int64 {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.total
}

func (s *Store) evictLocked(ref string) {
	e, ok := s.index[ref]
	if !ok {
		return
	}
	_ = os.Remove(filepath.Join(s.dir, ref+".bak"))
	s.total -= e.Size
	delete(s.index, ref)
}

// enforceQuotaLocked evicts oldest-first until the total is within quota.
func (s *Store) enforceQuotaLocked() {
	if s.quota <= 0 || s.total <= s.quota {
		return
	}
	es := make([]*Entry, 0, len(s.index))
	for _, e := range s.index {
		es = append(es, e)
	}
	sort.Slice(es, func(i, j int) bool { return es[i].CreatedAt.Before(es[j].CreatedAt) })
	for _, e := range es {
		if s.total <= s.quota {
			break
		}
		s.evictLocked(e.Ref)
	}
}

// openForRead opens path for reading, refusing a symlink (Lstat check + O_NOFOLLOW).
func (s *Store) openForRead(path string) (*os.File, error) {
	fi, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if fi.Mode()&os.ModeSymlink != 0 {
		return nil, ErrSymlink
	}
	return os.OpenFile(path, os.O_RDONLY|oNoFollow, 0)
}

func (s *Store) indexPath() string { return filepath.Join(s.dir, "index.json") }

func (s *Store) save() {
	data, err := json.Marshal(s.index)
	if err != nil {
		return
	}
	_ = os.WriteFile(s.indexPath(), data, 0o600)
}

func (s *Store) load() {
	data, err := os.ReadFile(s.indexPath())
	if err != nil {
		return
	}
	if json.Unmarshal(data, &s.index) != nil {
		s.index = make(map[string]*Entry)
		return
	}
	for _, e := range s.index {
		s.total += e.Size
	}
}

func newRef() string {
	var b [16]byte
	_, _ = rand.Read(b[:])
	return hex.EncodeToString(b[:])
}

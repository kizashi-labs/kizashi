// Package transport provides the gRPC transport layer with offline buffering.
package transport

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"time"
)

// RingBuffer is a size-limited disk-backed event buffer for offline operation.
// Events are written when the server is unreachable and drained on reconnection.
// When key is non-nil, segments are encrypted with AES-256-GCM at rest.
type RingBuffer struct {
	mu        sync.Mutex
	dir       string
	maxBytes  int64
	maxFiles  uint64 // cap on segment COUNT (byte cap alone lets tiny batches bloat the dir)
	shrinkAt  uint64 // recreate the dir on drain-to-empty if peak file count reached this
	key       []byte // 32-byte AES-256 key; nil = plaintext
	used      atomic.Int64
	head      uint64 // next sequence to drain
	tail      uint64 // next sequence to write
	peakFiles uint64 // max (tail-head) since last shrink — drives the shrink heuristic
}

const (
	// defaultMaxFiles bounds the segment count regardless of bytes. The byte cap
	// (local_buffer_size_mb) does NOT bound file count: a long disconnect writing
	// many small batches accumulates one file each. run1 reached 71,446 files, which
	// bloated the ext4 directory inode to ~17MB (ext4 never shrinks a directory) and
	// slowed recover()/ReadDir. At ~10KB/segment this matches the 100MB default cap.
	defaultMaxFiles = 10000
	// defaultShrinkAt: after the buffer drains fully (reconnect → drain → Ack), if it
	// had grown past this many files, recreate the directory to shed inode bloat.
	defaultShrinkAt = 1000
)

// NewRingBuffer creates a new ring buffer backed by files in dir.
// maxMB limits total disk usage. Segments are stored as plaintext.
func NewRingBuffer(dir string, maxMB int) (*RingBuffer, error) {
	return newRingBuffer(dir, maxMB, nil)
}

// NewEncryptedRingBuffer creates a ring buffer that encrypts each segment
// with AES-256-GCM using the provided 32-byte key.
// Use crypto/sha256 or HKDF to derive the key from the agent ID.
func NewEncryptedRingBuffer(dir string, maxMB int, key []byte) (*RingBuffer, error) {
	if len(key) != 32 {
		return nil, fmt.Errorf("encryption key must be 32 bytes (got %d)", len(key))
	}
	return newRingBuffer(dir, maxMB, key)
}

func newRingBuffer(dir string, maxMB int, key []byte) (*RingBuffer, error) {
	if err := os.MkdirAll(dir, 0700); err != nil {
		return nil, fmt.Errorf("create buffer dir: %w", err)
	}

	rb := &RingBuffer{
		dir:      dir,
		maxBytes: int64(maxMB) * 1024 * 1024,
		maxFiles: defaultMaxFiles,
		shrinkAt: defaultShrinkAt,
		key:      key,
	}

	// Recover state from existing files
	rb.recover()
	return rb, nil
}

// Write saves pre-serialized bytes to the buffer.
// The caller is responsible for serialization (use protojson.Marshal for proto messages).
// Returns an error if the disk write fails.
func (rb *RingBuffer) Write(data []byte) error {
	rb.mu.Lock()
	defer rb.mu.Unlock()

	// Make room by dropping oldest entries until the new one fits (or the buffer is
	// empty). A SINGLE drop is not enough under sustained pressure with variable-size
	// segments: each Write would drop one (possibly small) old segment but append a
	// larger new one, so `used` overshoots maxBytes badly (observed ~10x over a small
	// cap during a flood). Loop so the disk spool stays bounded — drop-oldest keeps
	// accepting new events (never the run1-style "full → stop writing" silent stall).
	// An oversized single batch (needed > maxBytes) empties the buffer then writes
	// anyway; the next Write reclaims it.
	needed := int64(len(data) + 8) // 8 bytes for header
	for (rb.used.Load()+needed > rb.maxBytes || (rb.maxFiles > 0 && rb.tail-rb.head >= rb.maxFiles)) && rb.head < rb.tail {
		if err := rb.dropOldest(); err != nil {
			break
		}
	}

	// Write to file: <tail>.buf
	path := rb.segmentPath(rb.tail)
	if err := rb.writeSegment(path, data); err != nil {
		return err
	}

	rb.used.Add(needed)
	rb.tail++
	if n := rb.tail - rb.head; n > rb.peakFiles {
		rb.peakFiles = n
	}
	return nil
}

// ReadBatch reads up to n items from the head of the buffer.
// Items are NOT removed; call Ack() after successful delivery.
func (rb *RingBuffer) ReadBatch(n int) ([][]byte, error) {
	rb.mu.Lock()
	defer rb.mu.Unlock()

	var batch [][]byte
	seq := rb.head

	for i := 0; i < n && seq < rb.tail; i++ {
		data, err := rb.readSegment(rb.segmentPath(seq))
		if err != nil {
			break
		}
		batch = append(batch, data)
		seq++
	}

	return batch, nil
}

// Ack removes the first n items from the head (call after successful delivery).
func (rb *RingBuffer) Ack(n int) {
	rb.mu.Lock()
	defer rb.mu.Unlock()

	for i := 0; i < n && rb.head < rb.tail; i++ {
		path := rb.segmentPath(rb.head)
		info, err := os.Stat(path)
		if err == nil {
			rb.used.Add(-(info.Size() + 8))
		}
		_ = os.Remove(path)
		rb.head++
	}
	rb.shrinkIfDrained()
}

// shrinkIfDrained recreates the buffer directory once it has fully drained, IF it
// had grown large. ext4 never shrinks a directory in place, so a transient burst of
// many small segments (run1: 71k files) leaves the directory inode permanently
// bloated (~17MB) — wasting space and slowing recover()/ReadDir. Recreating the empty
// directory resets the inode and the sequence counters. Caller must hold rb.mu.
func (rb *RingBuffer) shrinkIfDrained() {
	if rb.head != rb.tail || rb.peakFiles < rb.shrinkAt {
		return
	}
	if err := os.RemoveAll(rb.dir); err != nil {
		return
	}
	if err := os.MkdirAll(rb.dir, 0700); err != nil {
		return
	}
	rb.head, rb.tail = 0, 0
	rb.used.Store(0)
	rb.peakFiles = 0
}

// Len returns the number of buffered items.
func (rb *RingBuffer) Len() int {
	rb.mu.Lock()
	defer rb.mu.Unlock()
	return int(rb.tail - rb.head)
}

// BytesUsed returns total disk usage in bytes.
func (rb *RingBuffer) BytesUsed() int64 {
	return rb.used.Load()
}

// ─── Internal helpers ─────────────────────────────────────────

func (rb *RingBuffer) segmentPath(seq uint64) string {
	return filepath.Join(rb.dir, fmt.Sprintf("%020d.buf", seq))
}

func (rb *RingBuffer) writeSegment(path string, data []byte) error {
	payload := data
	if rb.key != nil {
		var err error
		payload, err = encryptGCM(rb.key, data)
		if err != nil {
			return fmt.Errorf("encrypt segment: %w", err)
		}
	}

	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0600)
	if err != nil {
		return err
	}
	defer f.Close()

	// Write length prefix
	var hdr [8]byte
	binary.LittleEndian.PutUint64(hdr[:], uint64(len(payload)))
	if _, err := f.Write(hdr[:]); err != nil {
		return err
	}
	_, err = f.Write(payload)
	return err
}

func (rb *RingBuffer) readSegment(path string) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var hdr [8]byte
	if _, err := f.Read(hdr[:]); err != nil {
		return nil, err
	}
	size := binary.LittleEndian.Uint64(hdr[:])

	payload := make([]byte, size)
	if _, err := f.Read(payload); err != nil {
		return nil, err
	}

	if rb.key != nil {
		plain, err := decryptGCM(rb.key, payload)
		if err != nil {
			return nil, fmt.Errorf("decrypt segment: %w", err)
		}
		return plain, nil
	}
	return payload, nil
}

// ─── AES-256-GCM helpers ──────────────────────────────────────

// encryptGCM encrypts plaintext with AES-256-GCM.
// Output format: nonce (12 bytes) || ciphertext+tag.
func encryptGCM(key, plaintext []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err = io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}
	return gcm.Seal(nonce, nonce, plaintext, nil), nil
}

// decryptGCM decrypts AES-256-GCM ciphertext produced by encryptGCM.
func decryptGCM(key, ciphertext []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	if len(ciphertext) < gcm.NonceSize() {
		return nil, fmt.Errorf("ciphertext too short")
	}
	nonce, ct := ciphertext[:gcm.NonceSize()], ciphertext[gcm.NonceSize():]
	return gcm.Open(nil, nonce, ct, nil)
}

func (rb *RingBuffer) dropOldest() error {
	if rb.head >= rb.tail {
		return fmt.Errorf("buffer empty")
	}
	path := rb.segmentPath(rb.head)
	info, err := os.Stat(path)
	if err == nil {
		rb.used.Add(-(info.Size() + 8))
	}
	_ = os.Remove(path)
	rb.head++
	return nil
}

func (rb *RingBuffer) recover() {
	entries, err := os.ReadDir(rb.dir)
	if err != nil {
		return
	}

	var min, max uint64 = ^uint64(0), 0
	var total int64
	found := false

	for _, e := range entries {
		if filepath.Ext(e.Name()) != ".buf" {
			continue
		}
		var seq uint64
		if _, err := fmt.Sscanf(e.Name(), "%d.buf", &seq); err != nil {
			continue
		}
		if seq < min {
			min = seq
		}
		if seq > max {
			max = seq
		}
		if info, err := e.Info(); err == nil {
			total += info.Size() + 8
		}
		found = true
	}

	if found {
		rb.head = min
		rb.tail = max + 1
		rb.used.Store(total)
	}
}

// ─── Batch Metrics ────────────────────────────────────────────

// Metrics holds buffer statistics.
type Metrics struct {
	Buffered  int
	BytesUsed int64
	Timestamp time.Time
}

func (rb *RingBuffer) Metrics() Metrics {
	return Metrics{
		Buffered:  rb.Len(),
		BytesUsed: rb.BytesUsed(),
		Timestamp: time.Now(),
	}
}

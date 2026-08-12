package scheduler

import (
	"context"
	"errors"
	"testing"

	edrsync "github.com/edr-platform/server/internal/sync"
)

type fakeSyncer struct {
	running bool
	err     error
	status  *edrsync.SyncStatus
	calls   int
}

func (f *fakeSyncer) IsRunning() bool { return f.running }
func (f *fakeSyncer) Sync(_ context.Context, _ bool, _ []string) error {
	f.calls++
	return f.err
}
func (f *fakeSyncer) Status() *edrsync.SyncStatus { return f.status }

type fakePublisher struct{ published int }

func (p *fakePublisher) Publish(subject string, _ []byte) error {
	if subject == "rules.invalidate" {
		p.published++
	}
	return nil
}

// TestSigmaSyncRunOnce verifies the reload-only-on-change discipline: publish
// rules.invalidate after a sync that changed rules, but NOT on no-change, error,
// or already-running (so the engine isn't churned needlessly).
func TestSigmaSyncRunOnce(t *testing.T) {
	cases := []struct {
		name          string
		syncer        *fakeSyncer
		wantSync      int
		wantPublished int
	}{
		{
			name:     "imported rules -> reload",
			syncer:   &fakeSyncer{status: &edrsync.SyncStatus{Imported: 5}},
			wantSync: 1, wantPublished: 1,
		},
		{
			name:     "updated rules -> reload",
			syncer:   &fakeSyncer{status: &edrsync.SyncStatus{Updated: 3}},
			wantSync: 1, wantPublished: 1,
		},
		{
			name:     "no change -> no reload",
			syncer:   &fakeSyncer{status: &edrsync.SyncStatus{Skipped: 10}},
			wantSync: 1, wantPublished: 0,
		},
		{
			name:     "sync error -> no reload",
			syncer:   &fakeSyncer{err: errors.New("network"), status: &edrsync.SyncStatus{}},
			wantSync: 1, wantPublished: 0,
		},
		{
			name:     "already running -> skip",
			syncer:   &fakeSyncer{running: true, status: &edrsync.SyncStatus{Imported: 9}},
			wantSync: 0, wantPublished: 0,
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			pub := &fakePublisher{}
			s := &SigmaSyncScheduler{syncer: c.syncer, publisher: pub}
			s.runOnce(context.Background())
			if c.syncer.calls != c.wantSync {
				t.Errorf("Sync calls = %d, want %d", c.syncer.calls, c.wantSync)
			}
			if pub.published != c.wantPublished {
				t.Errorf("rules.invalidate published = %d, want %d", pub.published, c.wantPublished)
			}
		})
	}
}

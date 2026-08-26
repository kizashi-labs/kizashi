package natsstream

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/nats-io/nats.go/jetstream"
)

type fakeJS struct {
	createErr  error
	updateErr  error
	creates    []jetstream.StreamConfig
	updates    []jetstream.StreamConfig
	createOnce bool
}

func (f *fakeJS) CreateOrUpdateStream(_ context.Context, cfg jetstream.StreamConfig) (jetstream.Stream, error) {
	f.creates = append(f.creates, cfg)
	if f.createOnce {
		f.createOnce = false
		return nil, f.createErr
	}
	if f.createErr != nil {
		return nil, f.createErr
	}
	return nil, nil
}

func (f *fakeJS) UpdateStream(_ context.Context, cfg jetstream.StreamConfig) (jetstream.Stream, error) {
	f.updates = append(f.updates, cfg)
	return nil, f.updateErr
}

// The whole point of the package: one definition, and every service that
// bootstraps gets the same bytes. If a field is ever moved back out of Config()
// into a caller, this is what notices.
func TestConfigIsFullySpecified(t *testing.T) {
	for _, d := range Definitions {
		cfg := d.Config()
		switch {
		case cfg.Name != d.Name:
			t.Errorf("%s: name mismatch", d.Name)
		case len(cfg.Subjects) == 0:
			t.Errorf("%s: subjects が空", d.Name)
		case cfg.MaxAge != d.MaxAge:
			t.Errorf("%s: MaxAge mismatch", d.Name)
		case cfg.Storage != jetstream.FileStorage:
			t.Errorf("%s: ストレージがファイルでない", d.Name)
		case cfg.Retention != jetstream.LimitsPolicy:
			t.Errorf("%s: 保持ポリシーが Limits でない", d.Name)
		case cfg.MaxBytes != -1:
			t.Errorf("%s: MaxBytes が -1 でない", d.Name)
		case cfg.Replicas != 1:
			t.Errorf("%s: Replicas が 1 でない", d.Name)
		case cfg.Duplicates != 5*time.Minute:
			t.Errorf("%s: 重複除去の窓が既定でない", d.Name)
		}
	}
}

// The three streams the platform actually needs, so a rename or a deletion is a
// deliberate act rather than an accident.
func TestDefinitionsCoverTheRequiredStreams(t *testing.T) {
	want := map[string]string{
		"EVENTS":   "events.>",
		"ALERTS":   "alerts.>",
		"COMMANDS": "commands.>",
	}
	if len(Definitions) != len(want) {
		t.Fatalf("ストリーム数が変わっている: %d", len(Definitions))
	}
	for _, d := range Definitions {
		subj, ok := want[d.Name]
		if !ok {
			t.Errorf("未知のストリーム: %s", d.Name)
			continue
		}
		if len(d.Subjects) != 1 || d.Subjects[0] != subj {
			t.Errorf("%s: subject が %v", d.Name, d.Subjects)
		}
	}
}

// The race this package exists to survive: the other service created the stream
// between our update and our create. The stream we wanted now exists, so this
// must not be an error.
func TestEnsureOneToleratesLosingTheCreateRace(t *testing.T) {
	js := &fakeJS{createErr: jetstream.ErrStreamNameAlreadyInUse}

	if err := ensureOne(context.Background(), js, Definitions[0]); err != nil {
		t.Fatalf("競合負けを失敗として扱った: %v", err)
	}
	if len(js.updates) != 1 {
		t.Errorf("競合後に UpdateStream を呼んでいない: %d", len(js.updates))
	}
}

// Any other error is real and must surface — swallowing it would leave a service
// running against a stream that does not exist.
func TestEnsureOneSurfacesRealErrors(t *testing.T) {
	boom := errors.New("connection refused")
	js := &fakeJS{createErr: boom}

	err := ensureOne(context.Background(), js, Definitions[0])
	if err == nil {
		t.Fatal("本物のエラーを握り潰した")
	}
	if !errors.Is(err, boom) {
		t.Errorf("原因が失われている: %v", err)
	}
	if len(js.updates) != 0 {
		t.Error("競合以外で UpdateStream を呼んだ")
	}
}

// Losing the race and then failing the update is still a failure.
func TestEnsureOneSurfacesUpdateFailureAfterRace(t *testing.T) {
	boom := errors.New("stream config mismatch")
	js := &fakeJS{createErr: jetstream.ErrStreamNameAlreadyInUse, updateErr: boom}

	if err := ensureOne(context.Background(), js, Definitions[0]); !errors.Is(err, boom) {
		t.Fatalf("競合後の更新失敗を報告していない: %v", err)
	}
}

package telemetry

import "testing"

func TestAggregate(t *testing.T) {
	tests := []struct {
		name string
		in   map[string]SensorState
		want Mode
	}{
		{
			// Platforms whose collectors never register (Windows/macOS today) must
			// report nothing rather than "off", which would read as "no telemetry"
			// for agents that are collecting fine over ETW/ESF.
			name: "no sensors recorded reports nothing, not off",
			in:   map[string]SensorState{},
			want: "",
		},
		{
			name: "all eBPF",
			in: map[string]SensorState{
				"process": {Mode: ModeEBPF},
				"network": {Mode: ModeEBPF},
			},
			want: ModeEBPF,
		},
		{
			// The case that motivated this package: the process sensor loads fine
			// while the network sensor is dead code, so the agent looks healthy
			// unless partial degradation is reported as degraded.
			name: "one sensor degraded drags the aggregate down",
			in: map[string]SensorState{
				"process": {Mode: ModeEBPF},
				"network": {Mode: ModePoll, Reason: "built without the ebpf tag"},
			},
			want: ModePoll,
		},
		{
			name: "all polling",
			in: map[string]SensorState{
				"process": {Mode: ModePoll},
				"network": {Mode: ModePoll},
			},
			want: ModePoll,
		},
		{
			name: "disabled sensors are ignored, not counted as degraded",
			in: map[string]SensorState{
				"process": {Mode: ModeEBPF},
				"network": {Mode: ModeOff},
			},
			want: ModeEBPF,
		},
		{
			name: "every sensor disabled reports off, not ebpf",
			in: map[string]SensorState{
				"process": {Mode: ModeOff},
				"network": {Mode: ModeOff},
			},
			want: ModeOff,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := aggregate(tt.in); got != tt.want {
				t.Errorf("aggregate() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestSetAndSnapshotAreOrderedAndOverwrite(t *testing.T) {
	mu.Lock()
	sensors = map[string]SensorState{}
	mu.Unlock()

	Set("network", ModePoll, "built without the ebpf tag")
	Set("process", ModeEBPF, "")
	// A sensor that recovers (or is re-recorded) must replace, not duplicate.
	Set("network", ModeEBPF, "")

	got := Snapshot()
	if len(got) != 2 {
		t.Fatalf("Snapshot() returned %d sensors, want 2: %+v", len(got), got)
	}
	if got[0].Sensor != "network" || got[1].Sensor != "process" {
		t.Errorf("Snapshot() not name-ordered: %+v", got)
	}
	if got[0].Mode != ModeEBPF || got[0].Reason != "" {
		t.Errorf("re-Set did not overwrite: %+v", got[0])
	}
	if Aggregate() != ModeEBPF {
		t.Errorf("Aggregate() = %q, want %q", Aggregate(), ModeEBPF)
	}
}

func TestStringIncludesReasonOnlyWhenPresent(t *testing.T) {
	mu.Lock()
	sensors = map[string]SensorState{}
	mu.Unlock()

	Set("network", ModePoll, "no ebpf tag")
	Set("process", ModeEBPF, "")

	want := "network=poll(no ebpf tag) process=ebpf"
	if got := String(); got != want {
		t.Errorf("String() = %q, want %q", got, want)
	}
}

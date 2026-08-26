package main

import "testing"

func TestConvertCalderaReport(t *testing.T) {
	report := []byte(`{
	  "name": "Discovery Chain",
	  "steps": {
	    "paw123": {
	      "steps": [
	        {"name":"Whoami","attack":{"technique_id":"T1033","technique_name":"System Owner/User Discovery","tactic":"discovery"},"status":0,"time_decided":"2026-06-27T10:00:00Z","time_completed":"2026-06-27T10:00:02Z"},
	        {"name":"Collect file","attack":{"technique_id":""},"status":0,"time_decided":"2026-06-27T10:00:05Z"},
	        {"name":"PowerShell","ability":{"technique_id":"T1059.001"},"status":1,"decide":"2026-06-27 10:00:10","finish":"2026-06-27 10:00:12"}
	      ]
	    }
	  }
	}`)
	runs, err := convertCalderaReport(report)
	if err != nil {
		t.Fatal(err)
	}
	// The technique-less link is dropped; two graded links remain.
	if len(runs) != 2 {
		t.Fatalf("got %d runs, want 2 (technique-less link dropped)", len(runs))
	}
	byTech := map[string]runEntry{}
	for _, r := range runs {
		byTech[r.Technique] = r
		if r.Scenario != "Discovery Chain" {
			t.Errorf("scenario = %q, want 'Discovery Chain'", r.Scenario)
		}
	}
	t1033, ok := byTech["T1033"]
	if !ok || t1033.TestName != "Whoami" || t1033.ExitCode != "0" {
		t.Errorf("T1033 = %+v, want Whoami exit 0", t1033)
	}
	if t1033.End.Sub(t1033.Start).Seconds() != 2 {
		t.Errorf("T1033 duration = %v, want 2s", t1033.End.Sub(t1033.Start))
	}
	// Alternate keys: ability.technique_id + decide/finish with space-format time.
	ps, ok := byTech["T1059.001"]
	if !ok || ps.ExitCode != "1" {
		t.Errorf("T1059.001 = %+v, want present exit 1", ps)
	}
	if ps.Start.IsZero() || ps.End.Before(ps.Start) {
		t.Errorf("T1059.001 times not parsed: start=%v end=%v", ps.Start, ps.End)
	}
}

// TestConvertCalderaReport_V5RunKey locks in support for Caldera v5.x reports,
// which key each link's timestamps as "run" (executed) / "agent_reported_time"
// (reported) instead of the older decide/finish/time_* keys. A live v5.3.0 run
// regressed to "runlog にエントリがありません" because every link was skipped as
// time-less; this fixture guards against that.
func TestConvertCalderaReport_V5RunKey(t *testing.T) {
	report := []byte(`{
	  "name": "edr-eval-discovery-1",
	  "steps": {
	    "bidroq": {
	      "steps": [
	        {"name":"Identify local users","attack":{"technique_id":"T1087.001","technique_name":"Account Discovery: Local Account","tactic":"discovery"},"status":0,"run":"2026-06-29T03:17:49Z","agent_reported_time":"2026-06-29T03:17:51Z"},
	        {"name":"Find user processes","attack":{"technique_id":"T1057","tactic":"discovery"},"status":0,"run":"2026-06-29T03:19:18Z"}
	      ]
	    }
	  }
	}`)
	runs, err := convertCalderaReport(report)
	if err != nil {
		t.Fatal(err)
	}
	if len(runs) != 2 {
		t.Fatalf("got %d runs, want 2 (v5 'run'-keyed links must be graded, not skipped)", len(runs))
	}
	byTech := map[string]runEntry{}
	for _, r := range runs {
		byTech[r.Technique] = r
	}
	u, ok := byTech["T1087.001"]
	if !ok || u.Start.IsZero() {
		t.Fatalf("T1087.001 not parsed from 'run' key: %+v", u)
	}
	// end ('agent_reported_time') is 2s after start ('run').
	if u.End.Sub(u.Start).Seconds() != 2 {
		t.Errorf("T1087.001 duration = %v, want 2s (run→agent_reported_time)", u.End.Sub(u.Start))
	}
	// A link with only 'run' (no agent_reported_time) still grades, end==start.
	p, ok := byTech["T1057"]
	if !ok || p.Start.IsZero() || !p.End.Equal(p.Start) {
		t.Errorf("T1057 run-only link = %+v, want start==end non-zero", p)
	}
}

func TestConvertCalderaReport_Empty(t *testing.T) {
	runs, err := convertCalderaReport([]byte(`{"name":"x","steps":{}}`))
	if err != nil || len(runs) != 0 {
		t.Fatalf("empty report: runs=%v err=%v", runs, err)
	}
	if _, err := convertCalderaReport([]byte(`not json`)); err == nil {
		t.Fatal("expected error on malformed JSON")
	}
}

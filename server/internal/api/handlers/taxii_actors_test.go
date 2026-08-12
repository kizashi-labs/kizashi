package handlers

import (
	"testing"
	"time"
)

func TestStixTypeForActor(t *testing.T) {
	cases := map[string]string{
		"threat-actor":  "threat-actor",
		"intrusion-set": "intrusion-set",
		"malware":       "malware",
		"tool":          "tool",
		"campaign":      "campaign",
		"":              "threat-actor",
		"unknown":       "threat-actor",
	}
	for in, want := range cases {
		if got := stixTypeForActor(in); got != want {
			t.Errorf("stixTypeForActor(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestBuildStixActor(t *testing.T) {
	ts := time.Date(2026, 7, 6, 12, 0, 0, 0, time.UTC)

	// threat-actor: keeps aliases, no malware fields, reuses stored stix_id.
	ta := buildStixActor("row1", "threat-actor--abc", "APT99", "threat-actor", "desc",
		[]string{"GhostViper"}, nil, []string{"apt"}, ts, ts)
	if ta.Type != "threat-actor" || ta.ID != "threat-actor--abc" {
		t.Errorf("threat-actor type/id = %q/%q", ta.Type, ta.ID)
	}
	if len(ta.Aliases) != 1 || ta.IsFamily != nil {
		t.Errorf("threat-actor aliases/is_family wrong: %+v", ta)
	}

	// malware: carries malware_types + is_family=false, drops aliases; derives id.
	mw := buildStixActor("row2", "", "Emotet", "malware", "",
		[]string{"ignored"}, []string{"trojan"}, nil, ts, ts)
	if mw.Type != "malware" || mw.ID != "malware--row2" {
		t.Errorf("malware type/id = %q/%q", mw.Type, mw.ID)
	}
	if mw.IsFamily == nil || *mw.IsFamily != false {
		t.Errorf("malware is_family = %v, want &false", mw.IsFamily)
	}
	if len(mw.Aliases) != 0 || len(mw.MalwareTypes) != 1 {
		t.Errorf("malware aliases/types wrong: %+v", mw)
	}
}

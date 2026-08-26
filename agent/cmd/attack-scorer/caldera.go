package main

import (
	"encoding/json"
	"fmt"
	"os"
	"strconv"
	"time"
)

// Caldera adapter: convert a MITRE Caldera operation report into the same runEntry
// list the Atomic runlog produces, so the existing scorer (attribute/printScorecard)
// grades a full multi-stage Caldera emulation in ATT&CK-Evaluations style without
// any change to the scoring core. Each executed link (ability) becomes one runEntry;
// the whole operation shares one Scenario (its name) so it is also chain-scored.
//
// Input is the report from Caldera's `GET /api/v2/operations/{id}/report` (v4/v5)
// or the equivalent "Download report" JSON from the Operations UI.

// calderaReport is the subset of the operation report we read. Caldera groups the
// executed links per agent paw under "steps".
type calderaReport struct {
	Name  string `json:"name"`
	Steps map[string]struct {
		Steps []calderaLink `json:"steps"`
	} `json:"steps"`
}

// calderaLink is one ability execution. Timestamp and technique key names have
// drifted across Caldera versions, so we accept several and pick the first present.
type calderaLink struct {
	Name    string `json:"name"`
	Ability struct {
		Name        string `json:"name"`
		TechniqueID string `json:"technique_id"`
	} `json:"ability"`
	Attack struct {
		TechniqueID   string `json:"technique_id"`
		TechniqueName string `json:"technique_name"`
		Tactic        string `json:"tactic"`
	} `json:"attack"`
	Status int `json:"status"`

	// start-ish / end-ish timestamps (version-variant)
	TimeDecided   string `json:"time_decided"`
	Decide        string `json:"decide"`
	TimeCompleted string `json:"time_completed"`
	Finish        string `json:"finish"`
	Collect       string `json:"collect"`
	// Caldera v5.x report keys: "run" = when the link executed (start-ish),
	// "agent_reported_time" = when the agent reported the result (end-ish).
	Run               string `json:"run"`
	AgentReportedTime string `json:"agent_reported_time"`
}

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if v != "" {
			return v
		}
	}
	return ""
}

// calderaTimeLayouts are the timestamp formats Caldera reports have used.
var calderaTimeLayouts = []string{
	time.RFC3339Nano, time.RFC3339,
	"2006-01-02 15:04:05", "2006-01-02T15:04:05Z",
}

func parseCalderaTime(s string) (time.Time, bool) {
	if s == "" {
		return time.Time{}, false
	}
	for _, l := range calderaTimeLayouts {
		if t, err := time.Parse(l, s); err == nil {
			return t.UTC(), true
		}
	}
	return time.Time{}, false
}

// loadCalderaReport reads a Caldera operation report file and converts it to runs.
func loadCalderaReport(path string) ([]runEntry, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return convertCalderaReport(data)
}

// convertCalderaReport maps a Caldera report to runEntry list. Links without an
// ATT&CK technique or without a usable timestamp are skipped (they cannot be
// time-correlated to detections). The operation name becomes the chain Scenario.
func convertCalderaReport(data []byte) ([]runEntry, error) {
	var rep calderaReport
	if err := json.Unmarshal(data, &rep); err != nil {
		return nil, fmt.Errorf("レポートの JSON 解析に失敗しました (Caldera): %w", err)
	}
	scenario := rep.Name
	if scenario == "" {
		scenario = "caldera-operation"
	}
	var runs []runEntry
	for _, agent := range rep.Steps {
		for _, l := range agent.Steps {
			tech := firstNonEmpty(l.Attack.TechniqueID, l.Ability.TechniqueID)
			if tech == "" {
				continue // 非ATT&CKのリンク(コレクタ等)は採点対象外
			}
			start, ok := parseCalderaTime(firstNonEmpty(l.TimeDecided, l.Decide, l.Run, l.TimeCompleted, l.Finish, l.AgentReportedTime, l.Collect))
			if !ok {
				continue // 時刻が無いと検知窓に突合できない
			}
			end, ok := parseCalderaTime(firstNonEmpty(l.TimeCompleted, l.Finish, l.AgentReportedTime, l.Collect, l.Run, l.TimeDecided, l.Decide))
			if !ok || end.Before(start) {
				end = start
			}
			name := firstNonEmpty(l.Name, l.Ability.Name, tech)
			runs = append(runs, runEntry{
				Technique: tech,
				TestName:  name,
				Start:     start,
				End:       end,
				ExitCode:  strconv.Itoa(l.Status),
				Scenario:  scenario,
			})
		}
	}
	return runs, nil
}

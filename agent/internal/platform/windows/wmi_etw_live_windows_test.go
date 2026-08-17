//go:build windows

package windows

import (
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"strings"
	"sync"
	"testing"
	"time"

	v1 "github.com/edr-platform/proto/agent/v1"
)

// Live verification of the WMI-Activity ETW sensor.
//
// The sensor shipped in PR #636 carrying an explicit "NOT LIVE-VERIFIED" note:
// the payload → flatten → rule half was proven by server-side tests, but nothing
// had ever confirmed that Microsoft-Windows-WMI-Activity actually delivers the
// properties the collector reads. That gap could not be closed from the Linux CI
// container, and the runbook (docs/ETW検証ランブック.md) called for a manual VM.
//
// It does not need one. The `Windows platform tests` job already runs this
// package's tests on a GitHub-hosted windows-latest runner, and that runner is
// an administrator — which is the whole requirement for opening an ETW real-time
// session and for writing to root\subscription. So the live check runs on every
// agent PR instead of waiting for someone to book a VM.
//
// The test registers a real WMI event subscription (filter + CommandLineEvent-
// Consumer + binding), which is exactly what T1546.003 does, and asserts the
// sensor emits a wmi_activity event carrying the consumer. Everything it creates
// is removed again in a defer.
//
// ⚠️ It must never silently skip on CI. A skipped live test looks identical to a
// passing one in the job summary and would put the sensor right back into the
// "unverified but assumed working" state this test exists to end. Outside CI it
// skips (a developer running `go test ./...` on their own box should not get a
// WMI subscription written into their registry); on CI it is mandatory and any
// failure to establish the session is a test failure, not a skip.
func TestWMIActivityCollectorEmitsOnLiveETW(t *testing.T) {
	onCI := os.Getenv("GITHUB_ACTIONS") == "true"
	if !onCI {
		t.Skip("live ETW check runs on the CI windows runner only; " +
			"it writes a real WMI subscription and needs administrator rights")
	}

	// The collector honours the sensor opt-out; the live check must not be
	// affected by whatever the ambient environment says.
	t.Setenv("EDR_AGENT_ETW_SENSORS", "1")

	sink := &capturingSender{}
	c := NewETWWMIActivityCollector()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Start returns nil even when the ETW session cannot be opened — that is
	// deliberate in production (an unavailable provider must not stop the agent)
	// but it means Start's error tells us nothing here. Check the session itself.
	if err := c.Start(ctx, "live-test-agent", sink); err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer func() { _ = c.Stop() }()

	if c.etwConsumer == nil || c.etwSession == nil {
		t.Fatal("the ETW session for Microsoft-Windows-WMI-Activity was not established. " +
			"On the CI windows runner this is a real failure, not an environment limitation: " +
			"the runner is an administrator, so the provider GUID, the session name, or the " +
			"golang-etw call sequence is wrong")
	}

	// Give the consumer a moment to attach before generating the event.
	time.Sleep(2 * time.Second)

	name := "EDRLiveTest_" + strings.ReplaceAll(t.Name(), "/", "_")
	cleanup := createWMISubscription(t, name)
	defer cleanup()

	// Wait for 5861 SPECIFICALLY — the binding registration. 5858 (operation) is
	// not interchangeable with it: 5858 records who called WMI and from where, and
	// carries no Consumer or Namespace at all. Taking whichever event arrives first
	// made this test fail intermittently (2026-07-27, 08-10, 08-13), because the
	// PowerShell calls that create the subscription generate 5858 traffic of their
	// own and often win the race. The assertions below only make sense for 5861.
	var got wmiLiveEvent
	deadline := time.Now().Add(45 * time.Second)
	for time.Now().Before(deadline) {
		if ev, ok := sink.findWMIBinding(); ok {
			got = ev
			break
		}
		time.Sleep(500 * time.Millisecond)
	}

	if got.EventType == "" {
		// Distinguish the two failures that look identical from here: the provider
		// never emitted 5861, or it did and the collector dropped it (handleETWEvent
		// returns early when both query and consumer read back empty — the silent
		// shape etwProp exists to guard against). The Operational log is written
		// from the same manifest, so it answers which side is at fault.
		logDetail := countSubscriptionEventsInLog(t)
		byID := sink.countsByEventID()
		t.Fatalf("no 5861 (subscription) wmi_activity event within 45s of registering a WMI "+
			"event subscription.\n"+
			"  emitted by the collector, by event id: %v (total batches %d)\n"+
			"  5861 records in Microsoft-Windows-WMI-Activity/Operational: %s\n"+
			"If the log shows 5861 but the collector emitted none, the provider spelling changed "+
			"and etwProp/handleETWEvent dropped it (query and consumer both read back empty). "+
			"If the log shows none either, this Windows build no longer emits 5861 for "+
			"__FilterToConsumerBinding creation and the sensor's persistence signal is gone.",
			byID, sink.count(), logDetail)
	}

	t.Logf("live wmi_activity event: type=%q event_id=%d consumer=%q query=%q namespace=%q user=%q",
		got.EventType, got.EventID, got.Consumer, got.Query, got.Namespace, got.User)
	if ops := sink.countsByEventID()[5858]; ops > 0 {
		t.Logf("also observed %d 5858 (operation) events — expected, the subscription is created "+
			"over WMI. They carry Operation/ClientMachine, never Consumer.", ops)
	}

	// The consumer is the one field the detection rule selects on. Everything
	// else in the payload is context.
	if got.Consumer == "" {
		t.Error("consumer is empty on a 5861 — the detection rule keys on the consumer TYPE, so " +
			"an event without it is stored, counted, and matched by nothing. Either the provider " +
			"stopped populating Consumer on this Windows build or etwProp needs another spelling")
	}
	if !strings.Contains(got.Consumer, "CommandLineEventConsumer") {
		t.Errorf("consumer = %q, want it to name CommandLineEventConsumer — the test registers "+
			"exactly that, so a different value means the property is being read from the "+
			"wrong place", got.Consumer)
	}
	if got.Namespace != `//./root/subscription` {
		t.Errorf("namespace = %q, want //./root/subscription", got.Namespace)
	}

	// Observed reality on the 2026-08-04 runner, recorded so a change is visible
	// rather than absorbed. These are NOT requirements — the rule does not select
	// on either — but both were assumed to hold something else before this test
	// existed, and a rule author reading the payload would guess wrong:
	//
	//   query carries the FILTER NAME, not the WQL text
	//   user  comes back empty
	//
	// If a future Windows build starts populating them properly, that is an
	// improvement worth noticing, not a silent change.
	if strings.Contains(strings.ToUpper(got.Query), "SELECT ") {
		t.Logf("NOTE: query now carries WQL (%q). On 2026-08-04 it carried the filter name "+
			"instead. Rules may now be able to select on the query text.", got.Query)
	}
	if got.User != "" {
		t.Logf("NOTE: user is now populated (%q). It was empty on 2026-08-04.", got.User)
	}
}

// wmiLiveEvent mirrors the collector's payload for assertion purposes.
type wmiLiveEvent struct {
	EventType string `json:"event_type"`
	Query     string `json:"query"`
	Consumer  string `json:"consumer"`
	Namespace string `json:"namespace"`
	User      string `json:"user"`
	EventID   int    `json:"event_id"`
}

type capturingSender struct {
	mu      sync.Mutex
	batches []*v1.EventBatch
}

func (s *capturingSender) SendEvents(_ context.Context, batch *v1.EventBatch) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.batches = append(s.batches, batch)
	return nil
}

func (s *capturingSender) count() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.batches)
}

// eachWMIActivity decodes every captured wmi_activity payload. The wire form is
// "wmi_activity:<uuid>:<json>", the same prefix promotion the ingestion side
// splits on, so decoding it here also checks that the ID stayed parseable.
func (s *capturingSender) eachWMIActivity(fn func(wmiLiveEvent) bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, b := range s.batches {
		for _, e := range b.GetEvents() {
			parts := strings.SplitN(e.GetId(), ":", 3)
			if len(parts) != 3 || parts[0] != "wmi_activity" {
				continue
			}
			var out wmiLiveEvent
			if err := json.Unmarshal([]byte(parts[2]), &out); err != nil {
				continue
			}
			if out.EventType == "" {
				continue
			}
			if !fn(out) {
				return
			}
		}
	}
}

// findWMIBinding returns the first captured 5861 (subscription registration).
// Deliberately not "the first wmi_activity of any kind": see the polling loop.
func (s *capturingSender) findWMIBinding() (wmiLiveEvent, bool) {
	var found wmiLiveEvent
	var ok bool
	s.eachWMIActivity(func(ev wmiLiveEvent) bool {
		if ev.EventID == 5861 {
			found, ok = ev, true
			return false
		}
		return true
	})
	return found, ok
}

func (s *capturingSender) countsByEventID() map[int]int {
	counts := map[int]int{}
	s.eachWMIActivity(func(ev wmiLiveEvent) bool {
		counts[ev.EventID]++
		return true
	})
	return counts
}

// countSubscriptionEventsInLog asks the Windows event log whether the provider
// wrote any 5861 records recently. The ETW session and the Operational log are
// fed from the same manifest, so this separates "the provider never emitted it"
// from "it was emitted and the collector dropped it" — two failures that look
// identical from inside the test. Diagnostic only: never fails the test.
func countSubscriptionEventsInLog(t *testing.T) string {
	t.Helper()
	const ps = `
$ErrorActionPreference = 'SilentlyContinue'
$evts = Get-WinEvent -FilterHashtable @{
  LogName   = 'Microsoft-Windows-WMI-Activity/Operational'
  Id        = 5861
  StartTime = (Get-Date).AddMinutes(-5)
} -MaxEvents 5
if ($null -eq $evts) { Write-Output 'none' } else { Write-Output ("{0} found" -f @($evts).Count) }
`
	out, err := exec.Command("powershell", "-NoProfile", "-NonInteractive", "-Command", ps).CombinedOutput()
	if err != nil {
		return "could not read the log: " + err.Error()
	}
	if s := strings.TrimSpace(string(out)); s != "" {
		return s
	}
	return "no output from Get-WinEvent"
}

// createWMISubscription registers filter + CommandLineEventConsumer + binding —
// the T1546.003 shape — and returns a cleanup that removes all three.
//
// The instances are created with PowerShell rather than wmic because wmic is
// deprecated and absent from newer Windows images; relying on it would make this
// check quietly stop generating the event it is supposed to generate.
func createWMISubscription(t *testing.T, name string) func() {
	t.Helper()

	create := `
$ErrorActionPreference = 'Stop'
$name = '` + name + `'
$filter = Set-WmiInstance -Namespace root\subscription -Class __EventFilter -Arguments @{
  Name = $name
  EventNameSpace = 'root\cimv2'
  QueryLanguage = 'WQL'
  Query = "SELECT * FROM __InstanceModificationEvent WITHIN 60 WHERE TargetInstance ISA 'Win32_PerfFormattedData_PerfOS_System'"
}
$consumer = Set-WmiInstance -Namespace root\subscription -Class CommandLineEventConsumer -Arguments @{
  Name = $name
  CommandLineTemplate = 'cmd.exe /c echo edr-live-test'
}
Set-WmiInstance -Namespace root\subscription -Class __FilterToConsumerBinding -Arguments @{
  Filter = $filter
  Consumer = $consumer
} | Out-Null
Write-Output 'created'
`
	out, err := exec.Command("powershell", "-NoProfile", "-NonInteractive", "-Command", create).CombinedOutput()
	if err != nil {
		t.Fatalf("could not register the WMI subscription that this test observes: %v\n%s\n"+
			"Without it there is nothing for the sensor to report, so a pass would be vacuous.",
			err, out)
	}
	t.Logf("registered WMI subscription %q", name)

	return func() {
		del := `
$ErrorActionPreference = 'SilentlyContinue'
$name = '` + name + `'
Get-WmiObject -Namespace root\subscription -Class __FilterToConsumerBinding |
  Where-Object { $_.Filter -match [regex]::Escape($name) } | Remove-WmiObject
Get-WmiObject -Namespace root\subscription -Class __EventFilter |
  Where-Object { $_.Name -eq $name } | Remove-WmiObject
Get-WmiObject -Namespace root\subscription -Class CommandLineEventConsumer |
  Where-Object { $_.Name -eq $name } | Remove-WmiObject
`
		if out, err := exec.Command("powershell", "-NoProfile", "-NonInteractive", "-Command", del).CombinedOutput(); err != nil {
			t.Logf("cleanup of WMI subscription %q reported: %v\n%s", name, err, out)
		}
	}
}

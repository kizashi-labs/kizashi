package config

import "testing"

// ApplyRemote overwrites the whole collection block, so a caller that builds a
// fresh RemoteConfig from a partial policy would wipe the monitored and excluded
// paths and clear AutoResponseEnabled as a side effect. This pins that behaviour
// so the hazard stays visible to whoever adds the next caller.
func TestApplyRemoteOverwritesTheWholeCollectionBlock(t *testing.T) {
	m := &Manager{current: &Config{}}
	m.current.Collection = CollectionConfig{
		ProcessMonitoring: true,
		FileMonitoring:    true,
		MonitoredPaths:    []string{"/etc", "/home"},
		ExcludedPaths:     []string{"/var/lib/docker"},
	}
	m.current.Response.AutoResponseEnabled = true

	// A caller that sets only the two flags it cares about loses everything else.
	m.ApplyRemote(&RemoteConfig{NetworkMonitoring: true, DNSMonitoring: true})

	got := m.Get()
	if got.Collection.ProcessMonitoring || got.Collection.FileMonitoring {
		t.Error("process/file monitoring survived — update this test AND the callers if the semantics change")
	}
	if len(got.Collection.MonitoredPaths) != 0 || len(got.Collection.ExcludedPaths) != 0 {
		t.Error("paths survived — update this test AND the callers if the semantics change")
	}
	if got.Response.AutoResponseEnabled {
		t.Error("AutoResponseEnabled survived — update this test AND the callers if the semantics change")
	}
}

// The safe pattern: carry every unrelated field through from the current config.
// This is what applyServerPolicy does, and it is the only way a policy push that
// names just {"network","dns"} does not silently disable the rest of the sensor.
func TestApplyRemotePreservesWhatTheCallerCarriesThrough(t *testing.T) {
	m := &Manager{current: &Config{}}
	m.current.Collection = CollectionConfig{
		ProcessMonitoring:    true,
		FileMonitoring:       true,
		MonitoredPaths:       []string{"/etc"},
		ExcludedPaths:        []string{"/tmp/spool"},
		ExcludedProcesses:    []string{"edr-agent"},
		EventBatchIntervalMS: 500,
	}
	m.current.Response.AutoResponseEnabled = true

	cur := m.Get()
	m.ApplyRemote(&RemoteConfig{
		ProcessMonitoring:    cur.Collection.ProcessMonitoring,
		FileMonitoring:       cur.Collection.FileMonitoring,
		NetworkMonitoring:    true,
		DNSMonitoring:        false,
		MonitoredPaths:       cur.Collection.MonitoredPaths,
		ExcludedPaths:        cur.Collection.ExcludedPaths,
		ExcludedProcesses:    cur.Collection.ExcludedProcesses,
		EventBatchIntervalMS: cur.Collection.EventBatchIntervalMS,
		AutoResponseEnabled:  cur.Response.AutoResponseEnabled,
	})

	got := m.Get()
	if !got.Collection.ProcessMonitoring || !got.Collection.FileMonitoring {
		t.Error("a policy naming only network/dns must not disable process or file monitoring")
	}
	if !got.Collection.NetworkMonitoring || got.Collection.DNSMonitoring {
		t.Errorf("network/dns = %v/%v, want true/false",
			got.Collection.NetworkMonitoring, got.Collection.DNSMonitoring)
	}
	if len(got.Collection.MonitoredPaths) != 1 || len(got.Collection.ExcludedPaths) != 1 {
		t.Error("paths must survive a policy push")
	}
	if got.Collection.EventBatchIntervalMS != 500 {
		t.Errorf("EventBatchIntervalMS = %d, want 500", got.Collection.EventBatchIntervalMS)
	}
	if !got.Response.AutoResponseEnabled {
		t.Error("a policy push must not clear the auto-response kill switch")
	}
}

// DNSMonitoring was not in RemoteConfig before this change: the server's policy
// names "dns" as a module, so without the field the toggle could not be honoured.
func TestApplyRemoteCarriesDNSMonitoring(t *testing.T) {
	m := &Manager{current: &Config{}}
	m.ApplyRemote(&RemoteConfig{DNSMonitoring: true})
	if !m.Get().Collection.DNSMonitoring {
		t.Error("DNSMonitoring must be applied from the remote config")
	}
}

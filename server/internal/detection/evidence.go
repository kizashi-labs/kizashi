package detection

// evidenceEventIDs returns the events.event_id list to record on an alert as the
// evidence it fired on.
//
// alerts.event_ids is UUID[], so an empty id must become a nil slice rather than
// a one-element slice containing "" — the latter fails to encode. An id is absent
// whenever the publishing ingestion predates the envelope's event_id field, which
// must degrade to "no evidence recorded", not to a write error that would lose the
// whole alert.
//
// Before this existed, alerts.event_ids was never populated by ANY detection path
// even though the column and the StoredAlert field both existed, so no alert could
// be traced back to the event that produced it. That is what made the ransomware
// correlator's reachability unprovable from the database — the correlator windows
// on event time, and event time was only reachable through this link.
// See docs/死蔵経路の全数棚卸し_20260810.md §8.
func evidenceEventIDs(eventID string) []string {
	if eventID == "" {
		return nil
	}
	return []string{eventID}
}

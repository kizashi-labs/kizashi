package handlers

import (
	"reflect"
	"testing"
)

func TestStixMITREIDs(t *testing.T) {
	obj := stixObject{
		ExternalReferences: []stixExternalReference{
			{SourceName: "mitre-attack", ExternalID: "T1055"},
			{SourceName: "capec", ExternalID: "CAPEC-100"}, // ignored
			{SourceName: "mitre-attack", ExternalID: "G0016"},
			{SourceName: "mitre-attack", ExternalID: ""}, // empty ignored
		},
	}
	got := stixMITREIDs(obj)
	want := []string{"T1055", "G0016"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("stixMITREIDs = %v, want %v", got, want)
	}
	if ids := stixMITREIDs(stixObject{}); len(ids) != 0 {
		t.Errorf("expected no ids for empty object, got %v", ids)
	}
}

func TestNonNilStrs(t *testing.T) {
	if got := nonNilStrs(nil); got == nil || len(got) != 0 {
		t.Errorf("nonNilStrs(nil) = %v, want empty non-nil slice", got)
	}
	in := []string{"a", "b"}
	if got := nonNilStrs(in); !reflect.DeepEqual(got, in) {
		t.Errorf("nonNilStrs(%v) = %v", in, got)
	}
}

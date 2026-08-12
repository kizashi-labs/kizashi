package detection

import "testing"

// TestPSModuleAliasFromPayload guards the PowerShell Module Logging (4103)
// translation: SigmaHQ ps_module rules select on Payload/ContextInfo, but the
// agent emits the raw JSON keys payload/context_info. Measured 2026-07-13 as the
// field-gap canary's top residual inert cause (Payload=22, ContextInfo=3 enabled
// rules referenced these with no source field).
func TestPSModuleAliasFromPayload(t *testing.T) {
	flat := map[string]interface{}{
		"type":         "ps_module",
		"payload":      "CommandInvocation(Add-Type): ...",
		"context_info": "Command Name = Add-Type",
	}
	addPipelineSigmaAliases(flat)
	if got, _ := flat["Payload"].(string); got != "CommandInvocation(Add-Type): ..." {
		t.Errorf("payload → Payload = %q, want the payload text", got)
	}
	if got, _ := flat["ContextInfo"].(string); got != "Command Name = Add-Type" {
		t.Errorf("context_info → ContextInfo = %q, want the context text", got)
	}
}

// TestPSModuleFieldsSupported ensures the aliases make Payload/ContextInfo
// supported fields, so the curate field-gate stops classifying the ps_module
// rules as unsupported (false-green) and they become genuinely enable-able.
func TestPSModuleFieldsSupported(t *testing.T) {
	sup := SupportedSigmaFields()
	if !sup["Payload"] && !sup["payload"] {
		t.Error("Payload must be in SupportedSigmaFields (via the payload→Payload alias) " +
			"so ps_module rules using it are field-supported")
	}
	if !sup["ContextInfo"] && !sup["contextinfo"] {
		t.Error("ContextInfo must be in SupportedSigmaFields (via the context_info→ContextInfo alias)")
	}
}

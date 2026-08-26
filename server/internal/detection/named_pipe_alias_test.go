package detection

import "testing"

// TestPipeNameAlias guards the named-pipe (pipe_created) translation: SigmaHQ
// pipe_created rules select on PipeName, but the agent emits the raw JSON key
// pipe_name. The shipped "Cobalt Strike Beacon via Named Pipe" rule (critical,
// auto-isolate) matches PipeName|contains and was the last field-gap lever (2026-07-13).
func TestPipeNameAlias(t *testing.T) {
	flat := map[string]interface{}{
		"type":       "pipe_created",
		"pipe_name":  `\msagent_5x`,
		"image_path": `C:\Temp\beacon.exe`,
	}
	addPipelineSigmaAliases(flat)
	if got, _ := flat["PipeName"].(string); got != `\msagent_5x` {
		t.Errorf("pipe_name → PipeName = %q, want the pipe name", got)
	}
	// image_path → Image alias is pre-existing; confirm it still covers the pipe event.
	if got, _ := flat["Image"].(string); got != `C:\Temp\beacon.exe` {
		t.Errorf("image_path → Image = %q, want the image path", got)
	}
}

// TestPipeNameFieldSupported ensures the alias makes PipeName a supported field, so
// the curate field-gate stops classifying the Cobalt Strike named-pipe rule as
// unsupported (false-green) and it becomes genuinely enable-able / fires.
func TestPipeNameFieldSupported(t *testing.T) {
	sup := SupportedSigmaFields()
	if !sup["PipeName"] && !sup["pipename"] {
		t.Error("PipeName must be in SupportedSigmaFields (via the pipe_name→PipeName alias) " +
			"so pipe_created rules using it are field-supported")
	}
}

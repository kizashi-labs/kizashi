package ingestion

import (
	"context"
	"strings"
	"testing"

	v1 "github.com/edr-platform/proto/agent/v1"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// The identifier reaches uuid columns (agents.id, events.agent_id), so anything
// that is not a UUID cannot be stored. It used to get that far anyway: the
// batch was published to NATS first, so detection raised alerts for an endpoint
// whose events were then dropped by Postgres and which never appeared in the
// console because its registration failed the same way.
func TestValidAgentID(t *testing.T) {
	cases := []struct {
		name string
		id   string
		want bool
	}{
		{"uuid v4", "9ed28fec-3e61-4f7f-8626-d1a782e6ae9c", true},
		{"uuid uppercase", "9ED28FEC-3E61-4F7F-8626-D1A782E6AE9C", true},
		{"the value seen live", "exfil-test", false},
		{"hostname", "ubuntu-srv", false},
		{"empty", "", false},
		{"almost a uuid", "9ed28fec-3e61-4f7f-8626", false},
		{"sql-ish", "'; DROP TABLE agents; --", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := validAgentID(tc.id); got != tc.want {
				t.Errorf("validAgentID(%q) = %v, want %v", tc.id, got, tc.want)
			}
		})
	}
}

// The rejection has to say which value was wrong and be classified as the
// caller's fault, or an operator reading one log line cannot act on it.
func TestRejectNonUUIDAgentID_IsActionable(t *testing.T) {
	err := rejectNonUUIDAgentID("exfil-test")
	if err == nil {
		t.Fatal("expected an error")
	}
	st, ok := status.FromError(err)
	if !ok {
		t.Fatalf("expected a gRPC status, got %T", err)
	}
	if st.Code() != codes.InvalidArgument {
		t.Errorf("code = %v, want InvalidArgument", st.Code())
	}
	if !strings.Contains(st.Message(), "exfil-test") {
		t.Errorf("the message must name the offending value, got: %q", st.Message())
	}
	if !strings.Contains(st.Message(), "UUID") {
		t.Errorf("the message must say what is required, got: %q", st.Message())
	}
}

// Heartbeat is the path that produced most of the live noise — one rejected
// update per agent per interval, forever.
func TestHeartbeat_RejectsNonUUIDAgentID(t *testing.T) {
	s := &Server{}
	_, err := s.Heartbeat(context.Background(), &v1.HeartbeatRequest{AgentId: "exfil-test"})
	if err == nil {
		t.Fatal("a non-UUID agent ID must be rejected before it reaches the database")
	}
	if status.Code(err) != codes.InvalidArgument {
		t.Errorf("code = %v, want InvalidArgument", status.Code(err))
	}
}

func TestGetConfig_RejectsNonUUIDAgentID(t *testing.T) {
	s := &Server{}
	_, err := s.GetConfig(context.Background(), &v1.ConfigRequest{AgentId: "exfil-test"})
	if err == nil {
		t.Fatal("a non-UUID agent ID must be rejected")
	}
	if status.Code(err) != codes.InvalidArgument {
		t.Errorf("code = %v, want InvalidArgument", status.Code(err))
	}
}

// A well-formed identifier must still get through: rejecting the malformed case
// is only safe because it was never storable, and that argument collapses if
// valid agents are turned away too.
func TestGetConfig_AcceptsUUIDAgentID(t *testing.T) {
	s := &Server{}
	cfg, err := s.GetConfig(context.Background(),
		&v1.ConfigRequest{AgentId: "9ed28fec-3e61-4f7f-8626-d1a782e6ae9c"})
	if err != nil {
		t.Fatalf("a valid agent ID must be accepted: %v", err)
	}
	if cfg == nil {
		t.Fatal("expected a config")
	}
}

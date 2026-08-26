package collector

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"time"

	"github.com/edr-platform/agent/internal/ja3"
	v1 "github.com/edr-platform/proto/agent/v1"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// tlsHandshakePayload is the JSON carried by a tls_handshake event: the JA3/JA3S
// fingerprints computed from an observed TLS ClientHello/ServerHello (see
// internal/ja3). The server's detection engine matches ja3/ja3s against its C2
// framework blocklist — catching implants (Cobalt Strike, Metasploit, Sliver, …)
// whose TLS stack fingerprints consistently even though their destination IP,
// domain, and command line reveal nothing. sni/dst_ip are context for the analyst.
type tlsHandshakePayload struct {
	DstIP       string `json:"dst_ip"`
	DstPort     int    `json:"dst_port"`
	SNI         string `json:"sni"`          // server_name from the ClientHello, if present
	JA3         string `json:"ja3"`          // MD5 of the JA3 string (client fingerprint)
	JA3S        string `json:"ja3s"`         // MD5 of the JA3S string (server fingerprint), if seen
	ProcessName string `json:"process_name"` // best-effort owning process
	PID         int    `json:"pid"`
}

// TLSHandshakePayload constructs the payload for a tls_handshake event.
func TLSHandshakePayload(dstIP string, dstPort int, sni, ja3, ja3s, processName string, pid int) tlsHandshakePayload {
	return tlsHandshakePayload{
		DstIP:       dstIP,
		DstPort:     dstPort,
		SNI:         sni,
		JA3:         ja3,
		JA3S:        ja3s,
		ProcessName: processName,
		PID:         pid,
	}
}

// ProcessTLSHandshake is the integration seam a TLS-capture sensor calls: given the raw
// ClientHello and/or ServerHello bytes observed on a connection (either may be nil) plus
// the connection context, it computes the JA3/JA3S fingerprints and returns the emittable
// event, or nil if neither handshake yielded a fingerprint.
//
// The capture of the handshake bytes themselves is platform-specific (eBPF socket-payload
// program on Linux, an ETW/AFD or WFP tap on Windows) and is the remaining live-verified
// work; this function is the tested boundary between that capture and the fingerprinting +
// wire-emission, so the fingerprint logic is exercised end-to-end independent of capture.
func ProcessTLSHandshake(agentID, dstIP string, dstPort int, sni, processName string, pid int, clientHello, serverHello []byte) *v1.EventBatch {
	var ja3md5, ja3smd5 string
	if len(clientHello) > 0 {
		if _, md5hex, err := ja3.FromClientHello(clientHello); err == nil {
			ja3md5 = md5hex
		}
		if sni == "" {
			sni = ja3.ServerName(clientHello) // best-effort context from the ClientHello
		}
	}
	if len(serverHello) > 0 {
		if _, md5hex, err := ja3.FromServerHello(serverHello); err == nil {
			ja3smd5 = md5hex
		}
	}
	return BuildTLSHandshakeEvent(agentID, TLSHandshakePayload(dstIP, dstPort, sni, ja3md5, ja3smd5, processName, pid))
}

// BuildTLSHandshakeEvent encodes a TLS fingerprint into an EventBatch using the same
// "<type>:<uuid>:<json>" ID wire format as credential_access / create_remote_thread
// (EVENT_TYPE_LOG), so it flows through the existing ingestion prefix-promotion with no
// proto change. Returns nil if the payload has no fingerprint or cannot be serialised.
func BuildTLSHandshakeEvent(agentID string, payload tlsHandshakePayload) *v1.EventBatch {
	if payload.JA3 == "" && payload.JA3S == "" {
		return nil // nothing to fingerprint
	}
	data, err := json.Marshal(payload)
	if err != nil {
		slog.Warn("[tls_handshake] イベントのシリアライズ失敗", "error", err)
		return nil
	}
	eventID := fmt.Sprintf("tls_handshake:%s:%s", newEventID(), string(data))
	return &v1.EventBatch{
		AgentId: agentID,
		Events: []*v1.Event{{
			Id:        eventID,
			Timestamp: timestamppb.New(time.Now()),
			Type:      v1.EventType_EVENT_TYPE_LOG,
		}},
	}
}

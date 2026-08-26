// Command ruleverify is a manual end-to-end verification helper for the detection
// rules added in migrations 343-351. It sends one EventBatch of representative
// process/auth events straight to the ingestion gRPC EventStream (like exfilinject),
// so an operator can confirm the full agent->ingestion->NATS->detection->alert path
// fires each rule on a live server WITHOUT a real agent.
//
// Run it from a container ATTACHED to the ingestion's docker network:
//
//	CGO_ENABLED=0 go build -o /tmp/ruleverify ./cmd/ruleverify
//	docker run --rm --network <proj>_kizashi-external -v /tmp/ruleverify:/rv:ro \
//	  alpine /rv -addr kizashi-ingestion:9091 -agent <a-registered-UUID>
//
// The -agent value MUST be a UUID that exists in the agents table (events.agent_id /
// alerts.agent_id are uuid columns); reuse an enrolled agent's ID. Then check:
//
//	SELECT created_at, severity, mitre_technique, title FROM alerts
//	WHERE created_at > now() - interval '2 minutes' ORDER BY created_at DESC;
//
// Expected titles: the LD_PRELOAD runtime injection, container escape, UPX packing,
// cleartext network logon, and private-key harvesting rules (343/346/350/347/351),
// plus a [RANSOMWARE] behavioral alert from the extension-agnostic FileBurstDetector
// (a burst of MODIFY events across several directories from one process) and a
// [LATERAL] alert from the LateralFanoutDetector (SMB connections to many internal hosts).
package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/metadata"
	"google.golang.org/protobuf/types/known/timestamppb"

	v1 "github.com/edr-platform/proto/agent/v1"
)

func proc(id, image, cmd string, env []string) *v1.Event {
	return &v1.Event{
		Id:        id,
		Timestamp: timestamppb.New(time.Now()),
		Type:      v1.EventType_EVENT_TYPE_PROCESS,
		Payload: &v1.Event_Process{Process: &v1.ProcessEvent{
			Pid: 4242, Ppid: 1, ProcessName: "verify", ImagePath: image,
			CommandLine: cmd, Action: v1.ProcessEvent_PROCESS_ACTION_CREATE, EnvVars: env,
		}},
	}
}

func auth(id, method string) *v1.Event {
	return &v1.Event{
		Id:        id,
		Timestamp: timestamppb.New(time.Now()),
		Type:      v1.EventType_EVENT_TYPE_AUTH,
		Payload: &v1.Event_Auth{Auth: &v1.AuthEvent{
			Username: "verify", Action: v1.AuthEvent_AUTH_ACTION_LOGIN,
			Success: true, SourceIp: "203.0.113.50", AuthMethod: method,
		}},
	}
}

// fileMod builds a MODIFY file event for one process — the unit the FileBurstDetector
// (extension-agnostic ransomware detection) counts. A burst of these across several
// directories from one pid trips the behavioral detector.
func fileMod(id, path, proc string, pid uint32) *v1.Event {
	return &v1.Event{
		Id:        id,
		Timestamp: timestamppb.New(time.Now()),
		Type:      v1.EventType_EVENT_TYPE_FILE,
		Payload: &v1.Event_File{File: &v1.FileEvent{
			Path: path, ProcessName: proc, Pid: pid,
			Action: v1.FileEvent_FILE_ACTION_MODIFY,
		}},
	}
}

// ransomwareBurst returns a batch of MODIFY events for one process spanning several
// directories — enough distinct files across enough directories to trip the
// FileBurstDetector's behavioral ransomware alert (T1486). Extension-agnostic: the paths
// deliberately keep an ordinary .dat extension to prove the detector does NOT rely on the
// known-ransomware-extension list that migration 267 uses.
func ransomwareBurst(agentID string) *v1.EventBatch {
	// Must exceed the server-side FileBurstScorer threshold (fileBurstMinFiles=60
	// distinct destructively-touched files per process within a 30s window).
	const files, dirs = 70, 5
	evts := make([]*v1.Event, 0, files)
	for i := 0; i < files; i++ {
		path := fmt.Sprintf("/home/victim/Documents/dir%d/report_%d.dat", i%dirs, i)
		evts = append(evts, fileMod(fmt.Sprintf("rv-ransom-%d", i), path, "cryptor", 6666))
	}
	return &v1.EventBatch{
		AgentId:    agentID,
		SequenceId: 3,
		Platform:   v1.Platform_PLATFORM_LINUX,
		Events:     evts,
	}
}

// netConn builds an outbound network connection event to one internal host/port — the
// unit the LateralFanoutDetector counts distinct internal destinations from.
func netConn(id, dstIP string, dstPort uint32, proc string) *v1.Event {
	return &v1.Event{
		Id:        id,
		Timestamp: timestamppb.New(time.Now()),
		Type:      v1.EventType_EVENT_TYPE_NETWORK,
		Payload: &v1.Event_Network{Network: &v1.NetworkEvent{
			SrcIp: "10.0.99.99", DstIp: dstIP, DstPort: dstPort, Protocol: "tcp",
			Direction: v1.NetworkEvent_NETWORK_DIRECTION_OUTBOUND, ProcessName: proc, Pid: 7777,
		}},
	}
}

// lateralBurst returns a batch of outbound SMB (445) connections to distinct INTERNAL
// hosts from one agent — enough distinct internal destinations to trip the
// LateralFanoutDetector's tool-agnostic lateral-movement alert (T1021). The port is a
// remote-admin service and the destinations are RFC1918, the two properties that
// distinguish lateral spread from a busy client fanning out to external IPs.
func lateralBurst(agentID string) *v1.EventBatch {
	const hosts = 12 // >10 distinct internal hosts on one remote-admin service, within one window
	evts := make([]*v1.Event, 0, hosts)
	for i := 0; i < hosts; i++ {
		dst := fmt.Sprintf("10.10.0.%d", i+1)
		evts = append(evts, netConn(fmt.Sprintf("rv-lateral-%d", i), dst, 445, "implant"))
	}
	return &v1.EventBatch{
		AgentId:    agentID,
		SequenceId: 4,
		Platform:   v1.Platform_PLATFORM_LINUX,
		Events:     evts,
	}
}

func main() {
	addr := flag.String("addr", "kizashi-ingestion:9091", "ingestion gRPC address (host:port)")
	agentID := flag.String("agent", "", "REQUIRED: a registered agent UUID (events/alerts agent_id is uuid)")
	flag.Parse()
	if *agentID == "" {
		log.Fatal("-agent <registered-UUID> is required")
	}

	conn, err := grpc.NewClient(*addr, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		log.Fatalf("dial %s: %v", *addr, err)
	}
	defer func() { _ = conn.Close() }() // 検証用の使い捨て接続。閉じる失敗に伝える情報は無い

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	ctx = metadata.AppendToOutgoingContext(ctx, "x-agent-id", *agentID)

	stream, err := v1.NewIngestionServiceClient(conn).EventStream(ctx)
	if err != nil {
		log.Fatalf("open EventStream: %v", err)
	}

	// Linux process events (343/346/350/351 are linux/multi-platform rules). The
	// RuleEngine gates rules by the event's platform, so events must carry the
	// platform their target rules are scoped to.
	linuxBatch := &v1.EventBatch{
		AgentId:    *agentID,
		SequenceId: 1,
		Platform:   v1.Platform_PLATFORM_LINUX,
		Events: []*v1.Event{
			// 343 runtime dynamic-linker injection (env_vars -> environment)
			proc("rv-343", "/bin/cat", "cat /etc/passwd", []string{"LD_PRELOAD=/dev/shm/evil.so"}),
			// 346 container escape to host
			proc("rv-346", "/usr/bin/nsenter", "nsenter --target 1 --mount --net --pid -- /bin/bash", nil),
			// 350 UPX packing
			proc("rv-350", "/usr/bin/upx", "upx --brute -o /tmp/packed /tmp/payload", nil),
			// 351 private-key harvesting
			proc("rv-351", "/bin/tar", "tar czf /tmp/k.tgz /home/u/.ssh/", nil),
		},
	}
	// Windows auth event — 347 (cleartext network logon) is a Windows-only rule
	// because auth_method is derived from the Windows LogonType, so it must ride a
	// windows-platform batch to pass the platform gate.
	winBatch := &v1.EventBatch{
		AgentId:    *agentID,
		SequenceId: 2,
		Platform:   v1.Platform_PLATFORM_WINDOWS,
		Events:     []*v1.Event{auth("rv-347", "network_cleartext")},
	}

	sent := 0
	for _, b := range []*v1.EventBatch{linuxBatch, winBatch, ransomwareBurst(*agentID), lateralBurst(*agentID)} {
		if err := stream.Send(b); err != nil {
			log.Fatalf("send batch: %v", err)
		}
		sent += len(b.Events)
	}
	_ = stream.CloseSend()
	log.Printf("sent %d verification events as agent=%s — check the alerts table", sent, *agentID)
	if _, err := stream.Recv(); err != nil {
		log.Printf("stream recv (expected EOF): %v", err)
	}
	time.Sleep(2 * time.Second)
	log.Println("done")
}

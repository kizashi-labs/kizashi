// Command fleet-sim drives a fleet of simulated endpoints against a live EDR
// server so the platform's FALSE-POSITIVE rate can be measured.
//
// Why this exists
//
//	attack-scorer measures the other half of detection quality — given an attack,
//	does an alert fire (true positives). Nothing measured the converse: given a
//	fleet doing nothing but ordinary business, how many alerts fire anyway. That
//	number, normalised as alerts per 1000 hosts per day, is the figure commercial
//	EDR vendors are judged on in production and the one this platform had never
//	produced, because there was no way to generate the input: the k6 suite loads
//	the REST API only and never touches gRPC ingestion or the detection engine.
//
// How a run works
//
//	fleet-sim enrols N virtual agents through the real Enroll RPC (so real rows
//	land in `agents` and alerts can reference them), opens a real EventStream per
//	host, and streams profile-driven benign telemetry at a configured per-host
//	hourly rate. Every event is benign by construction, so every alert the run
//	produces is a false positive — that is the ground truth, and it is what makes
//	unattended labelling possible. At the end a JSON manifest records the agent
//	IDs, the event tallies and the simulated host-days; server/cmd/fpsoak-report
//	consumes it and turns the alerts those agents produced into a per-rule
//	FP/1000 hosts/day scorecard.
//
// Usage
//
//	go run ./cmd/fleet-sim -server edr.example.com -token "$ENROLL_TOKEN" \
//	  -agents 20 -profiles ../tests/fpsoak/profiles -duration 10m -speed 12 \
//	  -manifest /tmp/soak-manifest.json
//
// -speed compresses time: 12 means each wallclock minute delivers 12 minutes of
// telemetry per host, so a 10-minute run yields 20 hosts × 2h = 1.67 host-days.
//
// Do NOT reach for a high -speed to buy host-days cheaply. The profiles emit
// roughly 3,600 events per simulated host-hour, which makes the send rate almost
// exactly agents × speed events/second, and the detection engine consumes far
// less than ingestion can absorb. Past its throughput the events still land in
// the database but detection falls minutes behind, so the alerts a soak is
// trying to count simply have not been produced when it is time to score.
// Prefer more hosts and more wallclock. See docs/ops/FPソーク運用.md §3-3.
package main

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	v1 "github.com/edr-platform/proto/agent/v1"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/metadata"
)

// streamDrainTimeout bounds how long a host waits, after CloseSend, for the server
// to finish consuming its stream. Long enough that a final partial batch is never
// abandoned; short enough that a wedged ingestion cannot hold the run open.
const streamDrainTimeout = 15 * time.Second

type options struct {
	server      string
	enrollPort  int
	streamPort  int
	token       string
	caCert      string
	insecureTLS bool

	agents      int
	profileDir  string
	hostPrefix  string
	duration    time.Duration
	speed       float64
	seed        uint64
	batchSize   int
	batchWindow time.Duration
	conns       int
	enrollJobs  int

	statePath    string
	manifestPath string
	verbose      bool
}

func main() {
	opts := parseFlags()

	profiles, err := LoadProfiles(opts.profileDir)
	if err != nil {
		log.Fatalf("プロファイルの読み込みに失敗しました: %v", err)
	}
	log.Printf("プロファイルを %d 件読み込みました (%s)", len(profiles), opts.profileDir)

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	runner, err := newRunner(opts, profiles)
	if err != nil {
		log.Fatalf("初期化に失敗しました: %v", err)
	}

	if err := runner.Enroll(ctx); err != nil {
		log.Fatalf("エージェント登録に失敗しました: %v", err)
	}

	runner.Run(ctx)

	manifest := runner.Manifest()
	if err := writeManifest(opts.manifestPath, manifest); err != nil {
		log.Fatalf("マニフェストの書き出しに失敗しました: %v", err)
	}
	log.Printf("マニフェストを書き出しました: %s", opts.manifestPath)
	manifest.PrintSummary(os.Stdout)

	if manifest.EventsTotal == 0 {
		// A run that sent nothing measures nothing, but every downstream step
		// (report, gate) would still report a clean zero-FP result and pass.
		// Fail loudly instead — this is exactly the silent-success class the
		// detection reachability work was built to eliminate.
		log.Fatalf("イベントが1件も送信されませんでした — 測定は無効です")
	}
}

func parseFlags() options {
	var o options
	flag.StringVar(&o.server, "server", "localhost", "EDRサーバのホスト名またはIP")
	flag.IntVar(&o.enrollPort, "enroll-port", 9091, "Enroll RPC のポート")
	flag.IntVar(&o.streamPort, "stream-port", 9091, "EventStream のポート")
	flag.StringVar(&o.token, "token", "", "エージェント登録トークン (必須、-state 再利用時は省略可)")
	flag.StringVar(&o.caCert, "ca-cert", "", "CA証明書パス。指定時は mTLS、未指定なら平文gRPC")
	flag.BoolVar(&o.insecureTLS, "insecure-skip-verify", false, "サーバ証明書の検証を省略する (検証環境専用)")

	flag.IntVar(&o.agents, "agents", 50, "シミュレートするエージェント数")
	flag.StringVar(&o.profileDir, "profiles", "tests/fpsoak/profiles", "プロファイル(*.toml)のディレクトリ")
	flag.StringVar(&o.hostPrefix, "hostname-prefix", "fpsim", "シミュレート host 名の接頭辞。レポート側の識別キーになる")
	flag.DurationVar(&o.duration, "duration", 10*time.Minute, "実時間での実行時間")
	flag.Float64Var(&o.speed, "speed", 1.0, "時間圧縮率。48 なら実時間1分あたり48分ぶんのテレメトリ")
	flag.Uint64Var(&o.seed, "seed", 20260728, "乱数シード。同一シード・同一プロファイルなら再現する")
	flag.IntVar(&o.batchSize, "batch-size", 50, "1バッチあたりの最大イベント数")
	flag.DurationVar(&o.batchWindow, "batch-window", 2*time.Second, "バッチを送出する最大待ち時間")
	flag.IntVar(&o.conns, "conns", 0, "平文モードで共有する gRPC コネクション数 (0 = 自動)")
	flag.IntVar(&o.enrollJobs, "enroll-jobs", 16, "登録の並列度")

	flag.StringVar(&o.statePath, "state", "", "登録済みエージェントの保存先JSON。再実行で同じ台を使い回す")
	flag.StringVar(&o.manifestPath, "manifest", "fpsoak-manifest.json", "実行マニフェストの出力先")
	flag.BoolVar(&o.verbose, "v", false, "詳細ログ")
	flag.Parse()

	if o.agents <= 0 {
		log.Fatalf("-agents は 1 以上である必要があります")
	}
	if o.speed <= 0 {
		log.Fatalf("-speed は正の値である必要があります")
	}
	if o.duration <= 0 {
		log.Fatalf("-duration は正の値である必要があります")
	}
	if o.batchSize <= 0 {
		log.Fatalf("-batch-size は 1 以上である必要があります")
	}
	if o.conns == 0 {
		o.conns = min(o.agents, 32)
	}
	return o
}

// ─── simulated host ───────────────────────────────────────────

type simAgent struct {
	AgentID  string `json:"agent_id"`
	Hostname string `json:"hostname"`
	Profile  string `json:"profile"`
	CertPEM  string `json:"cert_pem,omitempty"`
	KeyPEM   string `json:"key_pem,omitempty"`

	gen *Generator
}

type runner struct {
	opts     options
	profiles []*Profile
	agents   []*simAgent

	startedAt time.Time
	endedAt   time.Time

	mu         sync.Mutex
	eventsSent map[string]int64
	batches    atomic.Int64
	sendErrs   atomic.Int64
}

func newRunner(opts options, profiles []*Profile) (*runner, error) {
	r := &runner{
		opts:       opts,
		profiles:   profiles,
		eventsSent: map[string]int64{},
	}

	// Hosts are dealt by fleet_weight in filename order, so host #k always gets
	// the same profile for a given profile set — a prerequisite for comparing a
	// run against a committed baseline.
	assignment := AllocateFleet(profiles, opts.agents)
	for i := 0; i < opts.agents; i++ {
		prof := assignment[i]
		prefix := prof.HostPrefix
		if prefix == "" {
			prefix = prof.Name
		}
		hostname := fmt.Sprintf("%s-%s-%04d", opts.hostPrefix, prefix, i)
		gen, err := NewGenerator(prof, hostname, i, opts.seed)
		if err != nil {
			return nil, err
		}
		r.agents = append(r.agents, &simAgent{
			Hostname: hostname,
			Profile:  prof.Name,
			gen:      gen,
		})
	}
	return r, nil
}

// Enroll registers every simulated host, reusing a saved state file when one is
// present so repeated soaks measure the same fleet instead of piling up new
// agent rows on every run.
func (r *runner) Enroll(ctx context.Context) error {
	if r.opts.statePath != "" {
		if n, err := r.loadState(); err != nil {
			return err
		} else if n > 0 {
			log.Printf("保存済みの登録情報を %d 台ぶん再利用します (%s)", n, r.opts.statePath)
		}
	}

	pending := make([]*simAgent, 0, len(r.agents))
	for _, a := range r.agents {
		if a.AgentID == "" {
			pending = append(pending, a)
		}
	}
	if len(pending) == 0 {
		return nil
	}
	if r.opts.token == "" {
		return errors.New("-token が未指定です (登録が必要な台が残っています)")
	}

	conn, err := r.dialEnroll(ctx)
	if err != nil {
		return err
	}
	defer conn.Close()
	client := v1.NewIngestionServiceClient(conn)

	log.Printf("%d 台を登録します (並列度 %d)…", len(pending), r.opts.enrollJobs)
	var (
		wg       sync.WaitGroup
		jobs     = make(chan *simAgent)
		errOnce  sync.Once
		firstErr error
		done     atomic.Int64
	)
	for w := 0; w < max(1, r.opts.enrollJobs); w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for a := range jobs {
				if err := r.enrollOne(ctx, client, a); err != nil {
					errOnce.Do(func() { firstErr = err })
					return
				}
				if n := done.Add(1); n%50 == 0 {
					log.Printf("  登録済み %d/%d", n, len(pending))
				}
			}
		}()
	}
	for _, a := range pending {
		select {
		case jobs <- a:
		case <-ctx.Done():
		}
	}
	close(jobs)
	wg.Wait()
	if firstErr != nil {
		return firstErr
	}
	log.Printf("登録完了: %d 台", len(pending))

	if r.opts.statePath != "" {
		if err := r.saveState(); err != nil {
			return err
		}
	}
	return nil
}

func (r *runner) enrollOne(ctx context.Context, client v1.IngestionServiceClient, a *simAgent) error {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return fmt.Errorf("鍵の生成に失敗しました: %w", err)
	}
	csrDER, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		Subject: pkix.Name{CommonName: a.Hostname, Organization: []string{"EDR Fleet Sim"}},
	}, key)
	if err != nil {
		return fmt.Errorf("CSRの生成に失敗しました: %w", err)
	}
	csrPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csrDER})

	prof := r.profileByName(a.Profile)
	rpcCtx, cancel := context.WithTimeout(ctx, 60*time.Second)
	defer cancel()
	resp, err := client.Enroll(rpcCtx, &v1.EnrollRequest{
		EnrollmentToken: r.opts.token,
		Hostname:        a.Hostname,
		OsType:          prof.OS,
		OsVersion:       prof.OSVersion,
		AgentVersion:    "fleet-sim",
		IpAddresses:     []string{a.gen.SrcIP()},
		Csr:             string(csrPEM),
	})
	if err != nil {
		return fmt.Errorf("%s の登録に失敗しました: %w", a.Hostname, err)
	}

	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return fmt.Errorf("秘密鍵のエンコードに失敗しました: %w", err)
	}
	a.AgentID = resp.GetAgentId()
	a.CertPEM = resp.GetSignedCert()
	a.KeyPEM = string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}))
	return nil
}

func (r *runner) profileByName(name string) *Profile {
	for _, p := range r.profiles {
		if p.Name == name {
			return p
		}
	}
	return r.profiles[0]
}

// ─── run loop ─────────────────────────────────────────────────

// Run streams telemetry for the configured duration and returns when the run
// ends or the context is cancelled.
func (r *runner) Run(ctx context.Context) {
	r.startedAt = time.Now()
	runCtx, cancel := context.WithTimeout(ctx, r.opts.duration)
	defer cancel()

	shared, err := r.sharedConns(runCtx)
	if err != nil {
		log.Fatalf("gRPC接続に失敗しました: %v", err)
	}
	defer func() {
		for _, c := range shared {
			_ = c.Close()
		}
	}()

	log.Printf("ソークを開始します: %d 台 / %s / speed×%g (シミュレート %.2f ホスト日)",
		len(r.agents), r.opts.duration, r.opts.speed, r.simulatedHostDays(r.opts.duration))

	var wg sync.WaitGroup
	for i, a := range r.agents {
		wg.Add(1)
		go func(i int, a *simAgent) {
			defer wg.Done()
			r.runAgent(runCtx, i, a, shared)
		}(i, a)
	}

	progress := time.NewTicker(30 * time.Second)
	defer progress.Stop()
	go func() {
		for {
			select {
			case <-runCtx.Done():
				return
			case <-progress.C:
				r.mu.Lock()
				var total int64
				for _, v := range r.eventsSent {
					total += v
				}
				r.mu.Unlock()
				log.Printf("  進捗: events=%d batches=%d send_errors=%d",
					total, r.batches.Load(), r.sendErrs.Load())
			}
		}
	}()

	wg.Wait()
	r.endedAt = time.Now()
}

// sharedConns dials the connection pool used in plaintext mode. Under mTLS each
// host needs its own connection because the client certificate is bound to the
// transport, so no pool is created and runAgent dials per host.
func (r *runner) sharedConns(ctx context.Context) ([]*grpc.ClientConn, error) {
	if r.opts.caCert != "" {
		return nil, nil
	}
	addr := fmt.Sprintf("%s:%d", r.opts.server, r.opts.streamPort)
	conns := make([]*grpc.ClientConn, 0, r.opts.conns)
	for i := 0; i < r.opts.conns; i++ {
		c, err := grpc.NewClient(addr, grpc.WithTransportCredentials(insecure.NewCredentials()))
		if err != nil {
			for _, done := range conns {
				_ = done.Close()
			}
			return nil, fmt.Errorf("dial %s: %w", addr, err)
		}
		conns = append(conns, c)
	}
	return conns, nil
}

func (r *runner) runAgent(ctx context.Context, index int, a *simAgent, shared []*grpc.ClientConn) {
	conn, ownConn, err := r.connFor(a, shared, index)
	if err != nil {
		log.Printf("[%s] 接続に失敗しました: %v", a.Hostname, err)
		return
	}
	if ownConn {
		defer conn.Close()
	}
	client := v1.NewIngestionServiceClient(conn)

	// The stream outlives the run deadline on purpose. Deriving it from ctx would
	// cancel the transport at the same instant the run ends, so the final partial
	// batch — up to batch-size events per host — could never be sent and would be
	// counted as a send error instead. Events already generated must reach the
	// server, or the manifest's host-day denominator no longer matches the
	// telemetry the fleet actually delivered.
	streamCtx, endStream := streamContext(ctx, r.opts.caCert, a.AgentID)
	defer endStream()
	stream, err := client.EventStream(streamCtx)
	if err != nil {
		log.Printf("[%s] ストリームの確立に失敗しました: %v", a.Hostname, err)
		return
	}
	// Drain server->agent frames (keepalives and any commands) so the server's
	// stream does not stall on an unread downstream.
	//
	// drained closes when the server ends its side of the stream, which for a bidi
	// RPC happens after it has consumed everything the client sent. That is the only
	// signal available that the final batch was actually processed rather than
	// merely queued, so the shutdown path below waits for it.
	drained := make(chan struct{})
	go func() {
		defer close(drained)
		for {
			if _, err := stream.Recv(); err != nil {
				return
			}
		}
	}()

	go r.heartbeatLoop(ctx, client, a)

	// Per-host inter-event delay from the profile's hourly rate, compressed by
	// -speed. A 600 events/hour profile at speed 48 emits one event every 75ms.
	perHour := a.gen.prof.Rates.Total() * r.opts.speed
	if perHour <= 0 {
		return
	}
	interval := time.Duration(float64(time.Hour) / perHour)
	if interval < time.Millisecond {
		interval = time.Millisecond
	}

	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	flush := time.NewTicker(r.opts.batchWindow)
	defer flush.Stop()

	var (
		pending []*v1.Event
		seq     uint64
	)
	send := func() {
		if len(pending) == 0 {
			return
		}
		seq++
		batch := &v1.EventBatch{
			AgentId:    a.AgentID,
			Events:     pending,
			SequenceId: seq,
			Platform:   a.gen.Platform(),
		}
		if err := stream.Send(batch); err != nil {
			r.sendErrs.Add(1)
			if r.opts.verbose {
				log.Printf("[%s] 送信に失敗しました: %v", a.Hostname, err)
			}
			return
		}
		r.batches.Add(1)
		r.record(pending)
		pending = pending[:0]
	}

	for {
		select {
		case <-ctx.Done():
			send()
			_ = stream.CloseSend()
			// Returning here fires `defer endStream()`, which cancels the transport.
			// Do that before the server has drained what CloseSend flushed and the
			// last frames die in the socket — counted as sent, never ingested.
			// Wait for the server to close its side, which it does only after
			// consuming the client's stream. Bounded so a wedged server cannot hang
			// the whole run; the timeout is generous relative to a final partial
			// batch and is reported so a silent stall cannot look like a clean exit.
			select {
			case <-drained:
			case <-time.After(streamDrainTimeout):
				log.Printf("[%s] ストリームの終了確認が %s でタイムアウトしました"+
					"（最終バッチが取り込まれていない可能性があります）",
					a.Hostname, streamDrainTimeout)
			}
			return
		case <-ticker.C:
			if evt := a.gen.Next(a.gen.PickKind()); evt != nil {
				pending = append(pending, evt)
			}
			if len(pending) >= r.opts.batchSize {
				send()
			}
		case <-flush.C:
			send()
		}
	}
}

// streamContext derives the context for a host's event stream.
//
// The stream deliberately outlives the run deadline. Deriving it from ctx would
// cancel the transport at the same instant the run ends, so the final partial
// batch — up to batch-size events per host — could never be sent and would be
// counted as a send error instead. Events already generated must reach the
// server, or the manifest's host-day denominator no longer matches the telemetry
// the fleet actually delivered.
//
// The plaintext branch is where this went wrong. It appended the agent-id header
// to ctx rather than to the already-derived context, throwing the WithoutCancel
// away and putting the transport back on the run deadline — in exactly the mode
// the FP soak uses (it passes no -ca-cert). At the deadline the context cancelled
// and the transport was torn down while frames were still queued: gRPC's Send
// returns nil once a message is handed to the transport, not once the server has
// it, so those events were counted as sent and never arrived. That is the
// 0〜0.27% ingest loss tracked as P2-7 — including why it varied run to run (how
// many frames happened to be in flight at the instant of cancel) and why one run
// lost nothing at all.
func streamContext(ctx context.Context, caCert, agentID string) (context.Context, context.CancelFunc) {
	streamCtx, cancel := context.WithCancel(context.WithoutCancel(ctx))
	if caCert == "" {
		// Plaintext mode: the server resolves the agent from this header instead of
		// the client-certificate CN (ingestion extractAgentIDFromCert).
		streamCtx = metadata.AppendToOutgoingContext(streamCtx, "x-agent-id", agentID)
	}
	return streamCtx, cancel
}

func (r *runner) connFor(a *simAgent, shared []*grpc.ClientConn, index int) (*grpc.ClientConn, bool, error) {
	addr := fmt.Sprintf("%s:%d", r.opts.server, r.opts.streamPort)
	if r.opts.caCert == "" {
		if len(shared) == 0 {
			return nil, false, errors.New("共有コネクションがありません")
		}
		return shared[index%len(shared)], false, nil
	}
	tlsCfg, err := r.clientTLS(a)
	if err != nil {
		return nil, false, err
	}
	conn, err := grpc.NewClient(addr, grpc.WithTransportCredentials(credentials.NewTLS(tlsCfg)))
	if err != nil {
		return nil, false, err
	}
	return conn, true, nil
}

func (r *runner) clientTLS(a *simAgent) (*tls.Config, error) {
	cert, err := tls.X509KeyPair([]byte(a.CertPEM), []byte(a.KeyPEM))
	if err != nil {
		return nil, fmt.Errorf("%s のクライアント証明書の読み込みに失敗しました: %w", a.Hostname, err)
	}
	caPEM, err := os.ReadFile(r.opts.caCert)
	if err != nil {
		return nil, fmt.Errorf("CA証明書の読み込みに失敗しました: %w", err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(caPEM) {
		return nil, errors.New("CA証明書のパースに失敗しました")
	}
	return &tls.Config{
		Certificates:       []tls.Certificate{cert},
		RootCAs:            pool,
		MinVersion:         tls.VersionTLS13,
		InsecureSkipVerify: r.opts.insecureTLS, //nolint:gosec // 検証環境専用フラグ
	}, nil
}

func (r *runner) heartbeatLoop(ctx context.Context, client v1.IngestionServiceClient, a *simAgent) {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()
	prof := r.profileByName(a.Profile)
	beat := func() {
		hbCtx, cancel := context.WithTimeout(ctx, 15*time.Second)
		defer cancel()
		_, _ = client.Heartbeat(hbCtx, &v1.HeartbeatRequest{
			AgentId:      a.AgentID,
			AgentVersion: "fleet-sim",
			IpAddresses:  []string{a.gen.SrcIP()},
			// 負荷試験の合成エージェント。測ったことにして送ります。
			CpuUsage:      simCPUUsage(),
			MemoryUsageMb: simMemUsedMB(),
			TotalMemoryMb: simMemTotalMB(),
			Status:        v1.HeartbeatRequest_AGENT_STATUS_ONLINE,
			Hostname:      a.Hostname,
			OsVersion:     prof.OSVersion,
		})
	}
	beat()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			beat()
		}
	}
}

func (r *runner) record(events []*v1.Event) {
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, e := range events {
		r.eventsSent[eventTypeName(e.GetType())]++
	}
}

func eventTypeName(t v1.EventType) string {
	switch t {
	case v1.EventType_EVENT_TYPE_PROCESS:
		return "process"
	case v1.EventType_EVENT_TYPE_FILE:
		return "file"
	case v1.EventType_EVENT_TYPE_NETWORK:
		return "network"
	case v1.EventType_EVENT_TYPE_DNS:
		return "dns"
	case v1.EventType_EVENT_TYPE_REGISTRY:
		return "registry"
	case v1.EventType_EVENT_TYPE_AUTH:
		return "auth"
	case v1.EventType_EVENT_TYPE_IMAGE_LOAD:
		return "image_load"
	case v1.EventType_EVENT_TYPE_SCRIPT:
		return "script"
	}
	return "unknown"
}

func (r *runner) dialEnroll(ctx context.Context) (*grpc.ClientConn, error) {
	addr := fmt.Sprintf("%s:%d", r.opts.server, r.opts.enrollPort)
	var creds grpc.DialOption
	if r.opts.caCert == "" {
		creds = grpc.WithTransportCredentials(insecure.NewCredentials())
	} else {
		caPEM, err := os.ReadFile(r.opts.caCert)
		if err != nil {
			return nil, fmt.Errorf("CA証明書の読み込みに失敗しました: %w", err)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(caPEM) {
			return nil, errors.New("CA証明書のパースに失敗しました")
		}
		creds = grpc.WithTransportCredentials(credentials.NewTLS(&tls.Config{
			RootCAs:            pool,
			MinVersion:         tls.VersionTLS13,
			InsecureSkipVerify: r.opts.insecureTLS, //nolint:gosec // 検証環境専用フラグ
		}))
	}
	conn, err := grpc.NewClient(addr, creds)
	if err != nil {
		return nil, fmt.Errorf("dial %s: %w", addr, err)
	}
	_ = ctx
	return conn, nil
}

// ─── state persistence ────────────────────────────────────────

func (r *runner) loadState() (int, error) {
	data, err := os.ReadFile(r.opts.statePath)
	if errors.Is(err, os.ErrNotExist) {
		return 0, nil
	}
	if err != nil {
		return 0, fmt.Errorf("state の読み込みに失敗しました: %w", err)
	}
	var saved []simAgent
	if err := json.Unmarshal(data, &saved); err != nil {
		return 0, fmt.Errorf("state のパースに失敗しました: %w", err)
	}
	byHost := make(map[string]simAgent, len(saved))
	for _, s := range saved {
		byHost[s.Hostname] = s
	}
	n := 0
	for _, a := range r.agents {
		s, ok := byHost[a.Hostname]
		if !ok || s.AgentID == "" {
			continue
		}
		a.AgentID, a.CertPEM, a.KeyPEM = s.AgentID, s.CertPEM, s.KeyPEM
		n++
	}
	return n, nil
}

func (r *runner) saveState() error {
	out := make([]simAgent, 0, len(r.agents))
	for _, a := range r.agents {
		out = append(out, simAgent{
			AgentID: a.AgentID, Hostname: a.Hostname, Profile: a.Profile,
			CertPEM: a.CertPEM, KeyPEM: a.KeyPEM,
		})
	}
	data, err := json.MarshalIndent(out, "", "  ")
	if err != nil {
		return err
	}
	// 0600: the file holds agent private keys.
	if err := os.WriteFile(r.opts.statePath, data, 0o600); err != nil {
		return fmt.Errorf("state の保存に失敗しました: %w", err)
	}
	return nil
}

// ─── manifest ─────────────────────────────────────────────────

func (r *runner) simulatedHostDays(wall time.Duration) float64 {
	simulated := wall.Seconds() * r.opts.speed
	return float64(len(r.agents)) * simulated / (24 * 3600)
}

// Manifest builds the run record consumed by fpsoak-report.
func (r *runner) Manifest() *Manifest {
	r.mu.Lock()
	events := make(map[string]int64, len(r.eventsSent))
	var total int64
	for k, v := range r.eventsSent {
		events[k] = v
		total += v
	}
	r.mu.Unlock()

	wall := r.endedAt.Sub(r.startedAt)
	agents := make([]ManifestAgent, 0, len(r.agents))
	profiles := map[string]int{}
	for _, a := range r.agents {
		agents = append(agents, ManifestAgent{
			AgentID: a.AgentID, Hostname: a.Hostname, Profile: a.Profile,
		})
		profiles[a.Profile]++
	}

	return &Manifest{
		SchemaVersion:     1,
		StartedAt:         r.startedAt.UTC(),
		EndedAt:           r.endedAt.UTC(),
		HostnamePrefix:    r.opts.hostPrefix,
		Seed:              r.opts.seed,
		Speed:             r.opts.speed,
		WallclockSeconds:  wall.Seconds(),
		SimulatedHostDays: r.simulatedHostDays(wall),
		AgentCount:        len(r.agents),
		Profiles:          profiles,
		Agents:            agents,
		EventsByType:      events,
		EventsTotal:       total,
		Batches:           r.batches.Load(),
		SendErrors:        r.sendErrs.Load(),
	}
}

// ManifestAgent identifies one simulated host in the run record.
type ManifestAgent struct {
	AgentID  string `json:"agent_id"`
	Hostname string `json:"hostname"`
	Profile  string `json:"profile"`
}

// Manifest is the run record fpsoak-report reads to scope and normalise the
// alerts a soak produced. It is the ground truth of the measurement: which
// agent IDs were simulated (so their alerts are false positives by definition)
// and how many simulated host-days those alerts should be divided by.
type Manifest struct {
	SchemaVersion     int              `json:"schema_version"`
	StartedAt         time.Time        `json:"started_at"`
	EndedAt           time.Time        `json:"ended_at"`
	HostnamePrefix    string           `json:"hostname_prefix"`
	Seed              uint64           `json:"seed"`
	Speed             float64          `json:"speed"`
	WallclockSeconds  float64          `json:"wallclock_seconds"`
	SimulatedHostDays float64          `json:"simulated_host_days"`
	AgentCount        int              `json:"agent_count"`
	Profiles          map[string]int   `json:"profiles"`
	Agents            []ManifestAgent  `json:"agents"`
	EventsByType      map[string]int64 `json:"events_by_type"`
	EventsTotal       int64            `json:"events_total"`
	Batches           int64            `json:"batches"`
	SendErrors        int64            `json:"send_errors"`
}

// PrintSummary writes a short human-readable run summary.
func (m *Manifest) PrintSummary(w *os.File) {
	fmt.Fprintf(w, "\n─── FPソーク実行サマリ ───\n")
	fmt.Fprintf(w, "エージェント数        : %d\n", m.AgentCount)
	fmt.Fprintf(w, "実時間               : %.0fs (speed×%g)\n", m.WallclockSeconds, m.Speed)
	fmt.Fprintf(w, "シミュレートホスト日  : %.2f\n", m.SimulatedHostDays)
	fmt.Fprintf(w, "送信イベント          : %d (バッチ %d / 送信エラー %d)\n",
		m.EventsTotal, m.Batches, m.SendErrors)
	for _, k := range []string{"process", "file", "network", "dns", "registry", "auth", "image_load"} {
		if n, ok := m.EventsByType[k]; ok {
			fmt.Fprintf(w, "  %-11s: %d\n", k, n)
		}
	}
}

func writeManifest(path string, m *Manifest) error {
	data, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0o644)
}

// simCPUUsage returns the synthetic agent's reported CPU, as a measured value.
//
// **合成なので「測れた」で正しい**です。実機の未実装（Windows / macOS）は
// 欄ごと送らないので、この2つは混ざりません。
func simCPUUsage() *float64 { v := 0.5; return &v }

// simMemUsedMB / simMemTotalMB — 合成エージェントのメモリ。
// 使用率が出せるよう、分母も送ります。
func simMemUsedMB() *float64  { v := 42.0; return &v }
func simMemTotalMB() *float64 { v := 8192.0; return &v }

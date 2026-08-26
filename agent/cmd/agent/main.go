// EDR Platform Agent - Main Entry Point
//
// Usage:
//
//	edr-agent --config /etc/edr-agent/config.toml
//	edr-agent --version
//	edr-agent --enroll --server https://edr.company.com --token TOKEN
package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"syscall"
	"time"

	v1 "github.com/edr-platform/proto/agent/v1"
	"github.com/google/uuid"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/edr-platform/agent/internal/collector"
	"github.com/edr-platform/agent/internal/config"
	"github.com/edr-platform/agent/internal/encryption"
	"github.com/edr-platform/agent/internal/forensics"
	"github.com/edr-platform/agent/internal/hardening"
	"github.com/edr-platform/agent/internal/heartbeat"
	"github.com/edr-platform/agent/internal/integrity"
	"github.com/edr-platform/agent/internal/protection"
	"github.com/edr-platform/agent/internal/resource"
	"github.com/edr-platform/agent/internal/response"
	"github.com/edr-platform/agent/internal/scanner"
	"github.com/edr-platform/agent/internal/software"
	"github.com/edr-platform/agent/internal/telemetry"
	"github.com/edr-platform/agent/internal/transport"
	"github.com/edr-platform/agent/internal/updater"
)

// version is injected at build time via -ldflags "-X main.version=x.y.z"
var version = "0.1.0"

// scanCancelSentinel is a ScanCommand.Target value that means "cancel the
// in-flight scan" rather than "scan this path". Reusing the existing scan
// command avoids a proto change for the stop action.
const scanCancelSentinel = "__cancel__"

// errScanCancelled is returned by the walk function to abort a scan.
var errScanCancelled = fmt.Errorf("scan cancelled")

// scanCanceller serialises scan cancellation. A single agent runs at most one
// scan at a time; starting a new scan supersedes (cancels) any prior one, and a
// stop request cancels the in-flight scan.
type scanCanceller struct {
	mu     sync.Mutex
	cancel context.CancelFunc
}

// begin starts a fresh scan context, cancelling any prior in-flight scan. The
// returned cancel func must be deferred by the caller to release the context; it
// does not clear the global state (the next begin overwrites it), so a stale
// stop() after completion is a harmless no-op.
func (c *scanCanceller) begin() (context.Context, context.CancelFunc) {
	ctx, cancel := context.WithCancel(context.Background())
	c.mu.Lock()
	if c.cancel != nil {
		c.cancel()
	}
	c.cancel = cancel
	c.mu.Unlock()
	return ctx, cancel
}

// stop cancels the in-flight scan. It returns true if a scan cancel func was
// registered (a scan is, or recently was, running), false if none.
func (c *scanCanceller) stop() bool {
	c.mu.Lock()
	cancel := c.cancel
	c.mu.Unlock()
	if cancel != nil {
		cancel()
		return true
	}
	return false
}

// canceller holds the process-wide running-scan cancellation state.
var canceller scanCanceller

// scanMatch is one YARA hit reported to the server.
type scanMatch struct {
	File   string `json:"file"`
	Rule   string `json:"rule"`
	SHA256 string `json:"sha256,omitempty"`
	Size   int64  `json:"size,omitempty"`
}

// fetchServerYARARules retrieves the server's enabled YARA rule set (a single
// concatenated blob) for agent-side scanning via the public, agent-facing
// endpoint. Returns "" on any error so the scan proceeds with built-in rules
// only. The pure-Go scanner parses rules tolerantly, so a large community rule
// set loads without aborting on rules it cannot fully model.
// 戻り値を (string, error) にしてあるのは、**空文字が2つの違う事実を
// 表していたから**です。「サーバに有効なルールが1本も無い」と「取りに
// 行けなかった」が同じ "" で、呼び出し側はどちらも同じように読み飛ばし、
// スキャンは組み込みの EICAR 判定だけで走ります。
//
// その結果は「スキャン完了・検出0件」です。運用者が読むのは、**キュレート
// されたルール一式で調べて何も無かった**という報告に見えます。実際には
// ルールを1本も積まずに走っただけです。
func fetchServerYARARules(serverURL, agentID string) (string, error) {
	url := fmt.Sprintf("%s/api/v1/agents/%s/yara-rules", serverURL, agentID)
	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Get(url)
	if err != nil {
		return "", fmt.Errorf("サーバのYARAルールを取得できません: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("サーバのYARAルール取得が HTTP %d を返しました", resp.StatusCode)
	}
	var out struct {
		Rules string `json:"rules"`
		Count int    `json:"count"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return "", fmt.Errorf("サーバのYARAルール応答を読めません: %w", err)
	}
	slog.Info("[scan] サーバのYARAルールを取得しました", "count", out.Count)
	return out.Rules, nil
}

// scanFilesWithCancel walks each target path, invoking scanFile for every
// regular file no larger than maxSize, and aborts promptly when ctx is
// cancelled. scanFile returns the file's matches and whether it was successfully
// scanned (counted). Returns the scanned/matched counts, the collected matches,
// and whether the walk was cancelled before completing.
func scanFilesWithCancel(
	ctx context.Context,
	targets []string,
	maxSize int64,
	scanFile func(path string, info os.FileInfo) (matches []scanMatch, counted bool),
) (scanned, matched int, matches []scanMatch, cancelled bool) {
	for _, target := range targets {
		werr := filepath.Walk(target, func(path string, info os.FileInfo, err error) error {
			// Abort promptly when a stop is requested.
			select {
			case <-ctx.Done():
				return errScanCancelled
			default:
			}
			if err != nil || info.IsDir() || info.Size() > maxSize {
				return nil
			}
			ms, counted := scanFile(path, info)
			if !counted {
				return nil
			}
			scanned++
			if len(ms) > 0 {
				matched++
				matches = append(matches, ms...)
			}
			return nil
		})
		if werr == errScanCancelled {
			cancelled = true
			break
		}
	}
	return
}

func main() {
	// ─── CLI flags ────────────────────────────────────────────
	var (
		configPath  = flag.String("config", defaultConfigPath(), "設定ファイルのパス")
		showVersion = flag.Bool("version", false, "バージョンを表示")
		enrollMode  = flag.Bool("enroll", false, "エージェント登録モード")
		serverURL   = flag.String("server", "", "EDRサーバーURL (enroll時)")
		enrollToken = flag.String("token", "", "登録トークン (enroll時)")

		// Uninstall protection. The uninstall scripts call this and refuse to
		// remove anything unless it exits 0. Password comes from
		// EDR_UNINSTALL_PASSWORD or stdin — never an argument, which would put
		// it in the process list for the duration of the key derivation.
		verifyUninstall = flag.Bool("verify-uninstall", false,
			"アンインストールパスワードを検証して終了 (0=許可 2=拒否 3=判定不能)")

		// First-run config generation, called by the OS packages (MSI custom
		// action / deb+rpm postinstall / macOS pkg postinstall). Refuses to
		// overwrite an existing config, so packages can call it unconditionally.
		writeConfig = flag.Bool("write-config", false,
			"初回設定ファイルを生成して終了 (既存ファイルがあれば何もしない)")

		// Standalone memory-scan cost measurement (#511). Needs no config or
		// enrollment and sends no events, so it can be run on any host — including
		// alongside an installed agent — to check what the scanner costs there.
		memscanBench    = flag.Int("memscan-bench", 0, "メモリスキャン負荷計測: 指定周回だけ実行して終了 (#511検証用)")
		memscanBenchInt = flag.Duration("memscan-bench-interval", 0, "計測時の周回間隔 (例 60s。既定0は連続実行)")
		memscanBenchSD  = flag.Bool("memscan-bench-sedebug", false, "計測時にSeDebugPrivilegeを有効化 (本番エージェント相当の対象範囲)")
		memscanBenchV   = flag.Bool("memscan-bench-verbose", false, "計測時に毎周期の送信対象findingを一覧表示")
	)
	flag.Parse()

	// ─── Context + signal handling ────────────────────────────
	// Created early so Windows SCM can be registered before the
	// 30-second startup timeout expires.
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		sig := <-sigCh
		slog.Info("シャットダウンシグナルを受信しました", "signal", sig)
		cancel()
	}()

	// Windows: register with SCM before heavy initialization
	startWindowsServiceIfNeeded(cancel)

	if *showVersion {
		fmt.Printf("edr-agent v%s (%s/%s)\n", version, runtime.GOOS, runtime.GOARCH)
		os.Exit(0)
	}

	// Before logging setup and any collector initialisation: this mode answers
	// one question and exits, and must not start monitoring on a host that is
	// being decommissioned.
	if *verifyUninstall {
		os.Exit(runVerifyUninstall(*configPath))
	}

	if *writeConfig {
		os.Exit(runWriteConfig(*configPath, *serverURL))
	}

	// ─── Logging setup ────────────────────────────────────────
	var logger *slog.Logger
	logger = slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{
		Level: slog.LevelInfo,
	}))
	slog.SetDefault(logger)

	// Measure-only mode (#511): run the memory scanner N times, print
	// the cost, exit. Placed before config load so it works on a host with no
	// agent config and no server.
	if *memscanBench > 0 {
		runMemscanBench(*memscanBench, *memscanBenchInt, *memscanBenchSD, *memscanBenchV)
		os.Exit(0)
	}

	slog.Info("EDR Agent を起動中",
		"version", version,
		"os", runtime.GOOS,
		"arch", runtime.GOARCH,
	)

	// ─── Load Config ──────────────────────────────────────────
	cfgMgr := config.NewManager(*configPath)
	if err := cfgMgr.Load(); err != nil {
		if *enrollMode {
			// Config doesn't exist yet during enrollment - OK
			slog.Warn("設定ファイルが見つかりません", "path", *configPath)
		} else {
			slog.Error("設定の読み込みに失敗しました", "error", err)
			os.Exit(1)
		}
	}

	// ─── Enrollment mode ──────────────────────────────────────
	if *enrollMode {
		if *serverURL == "" || *enrollToken == "" {
			slog.Error("--server と --token が必要です")
			os.Exit(1)
		}
		if err := runEnrollment(*serverURL, *enrollToken, *configPath); err != nil {
			slog.Error("登録に失敗しました", "error", err)
			os.Exit(1)
		}
		slog.Info("登録が完了しました")
		return
	}

	cfg := cfgMgr.Get()

	// ─── Reinitialize logger with config settings ─────────────
	// The initial logger (above) writes to stdout only.
	// Once config is loaded, redirect to the configured log file (+ stdout).
	// Use bestEffortWriter so that a failed stdout write (e.g. Windows service)
	// does not prevent the file from being written.
	if cfg.Logging.File != "" {
		if err := os.MkdirAll(filepath.Dir(cfg.Logging.File), 0755); err == nil {
			if lf, err := os.OpenFile(cfg.Logging.File, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0640); err == nil {
				level := slog.LevelInfo
				switch cfg.Logging.Level {
				case "debug":
					level = slog.LevelDebug
				case "warn":
					level = slog.LevelWarn
				case "error":
					level = slog.LevelError
				}
				w := &bestEffortWriter{writers: []io.Writer{os.Stdout, lf}}
				logger = slog.New(slog.NewJSONHandler(w, &slog.HandlerOptions{Level: level}))
				slog.SetDefault(logger)
				slog.Info("ファイルロガーを初期化しました", "file", cfg.Logging.File)
			}
		}
	}

	// ─── Self-integrity check ──────────────────────────────────
	// The result is kept rather than only logged: the gRPC client does not exist
	// yet at this point, so the finding is handed to runTamperSelfProtect below,
	// which reports it once the transport is up. This is the only check that spans
	// a restart — the monitor's baseline is taken in memory at start, so a binary
	// swapped while the agent was down is invisible to it and visible here.
	dataDir := filepath.Dir(*configPath)
	startupIntegrityErr := integrity.Check(dataDir)
	if startupIntegrityErr != nil {
		slog.Error("バイナリ整合性チェックに失敗しました。エージェントが改ざんされた可能性があります",
			"error", startupIntegrityErr)
		// Continue running but flag as potentially tampered.
		// In a production hardened build you would os.Exit(1) here.
	}

	// ─── Resource throttle ────────────────────────────────────
	maxEPS := cfg.Collection.MaxEventsPerSecond
	if maxEPS <= 0 {
		maxEPS = 1000
	}
	throttle := resource.New(
		resource.DefaultMaxCPUPercent,
		resource.DefaultMaxMemoryMB,
		maxEPS,
	)

	// ─── Build platform-specific components ───────────────────
	isolation, procMgr, quarantine := buildPlatformComponents(cfg)

	// ─── Offline buffer (AES-256-GCM encrypted) ───────────────
	bufDir := cfg.Quarantine.Dir + "/buffer"
	// Derive a 32-byte buffer encryption key from the agent ID using SHA-256.
	// The key never leaves the endpoint; it only protects data at rest.
	bufKey := deriveBufferKey(cfg.Agent.ID)
	buf, err := transport.NewEncryptedRingBuffer(bufDir, cfg.Collection.LocalBufferSizeMB, bufKey)
	if err != nil {
		slog.Error("バッファの初期化に失敗しました", "error", err)
		os.Exit(1)
	}

	// ─── gRPC client ──────────────────────────────────────────
	// ack の送信先は grpcClient だが、grpcClient はコマンドハンドラで executor を
	// 参照するため相互に必要になる。間に薄い転送を挟んで循環を解く。
	ackSender := &deferredAckSender{}
	executor := response.NewExecutor(
		isolation, procMgr, quarantine,
		cfg.Agent.ID, cfg.Server.URL,
		ackSender, // 下で grpcClient を代入する
	)

	var grpcClient *transport.GRPCClient
	grpcClient = transport.NewGRPCClient(cfg, buf, func(cmd *transport.ServerCommand) {
		ctx := context.Background()
		switch cmd.Type {
		case transport.CmdIsolate:
			if c, ok := cmd.Payload.(response.IsolateCmd); ok {
				executor.Isolate(ctx, c)
			}
		case transport.CmdUnisolate:
			if c, ok := cmd.Payload.(response.UnisolateCmd); ok {
				executor.Unisolate(ctx, c)
			}
		case transport.CmdKillProcess:
			if c, ok := cmd.Payload.(response.KillProcessCmd); ok {
				executor.KillProcess(ctx, c)
			}
		case transport.CmdQuarantineFile:
			if c, ok := cmd.Payload.(response.QuarantineFileCmd); ok {
				executor.QuarantineFile(ctx, c)
			}
		case transport.CmdApplyPolicy:
			if c, ok := cmd.Payload.(transport.ApplyPolicyCmd); ok {
				applyServerPolicy(cfgMgr, c)
			}
		case transport.CmdRestoreFile:
			if c, ok := cmd.Payload.(response.RestoreFileCmd); ok {
				executor.RestoreFile(ctx, c)
			}
		case transport.CmdScan:
			if payload, ok := cmd.Payload.(transport.ScanCmd); ok {
				// Cancel sentinel: stop the in-flight scan instead of starting one.
				if payload.Target == scanCancelSentinel {
					if canceller.stop() {
						slog.Info("[scan] スキャン停止要求を受信しました")
					} else {
						slog.Info("[scan] 停止要求を受信しましたが、実行中のスキャンはありません")
					}
					break
				}
				go func(p transport.ScanCmd) {
					// Register this scan, superseding any prior one; release on exit.
					scanCtx, release := canceller.begin()
					defer release()
					s := scanner.NewYARAScanner()
					// Built-in rules — always available for testing
					_ = s.LoadRules(`rule EICAR_Test {
    meta:
        description = "EICAR Anti-Virus Test File"
    strings:
        $eicar = "X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"
    condition:
        any of them
}
rule Malware_Test_Content {
    meta:
        description = "Test malware content marker"
    strings:
        $s = "malware_test_content"
    condition:
        any of them
}`)
					// Load the operator's enabled YARA rules (distributed by the
					// server) on top of the built-in test rules, so scans use the
					// curated rule set rather than only EICAR/test markers.
					content, ferr := fetchServerYARARules(cfg.Server.URL, cfg.Agent.ID)
					switch {
					case ferr != nil:
						// **これは「検出0件」とは違います。** 組み込みの
						// EICAR 判定だけで走るので、キュレートされたルールで
						// 調べた結果ではありません。
						slog.Error("[scan] サーバのYARAルールを積めませんでした。"+
							"組み込みルールのみでスキャンします。"+
							"この結果は「ルール一式で調べて何も無かった」ではありません",
							"error", ferr)
					case content == "":
						slog.Info("[scan] サーバに有効なYARAルールがありません。" +
							"組み込みルールのみでスキャンします")
					default:
						if err := s.LoadRules(content); err != nil {
							slog.Warn("[scan] サーバYARAルールのロードに一部失敗しました", "error", err)
						}
					}
					var scanTargets []string
					if p.Target != "" {
						scanTargets = []string{p.Target}
					} else if runtime.GOOS == "windows" {
						scanTargets = []string{
							`C:\Users`, `C:\temp`, `C:\Windows\Temp`, `C:\ProgramData`,
						}
					} else {
						scanTargets = []string{"/tmp", "/home", "/var/tmp"}
					}
					slog.Info("[scan] YARAスキャンを開始します", "targets", scanTargets, "rules", s.RuleCount())
					scanned, matched, allMatches, cancelled := scanFilesWithCancel(
						scanCtx, scanTargets, 64*1024*1024,
						func(path string, info os.FileInfo) ([]scanMatch, bool) {
							matches, err := s.ScanFile(path)
							if err != nil {
								return nil, false
							}
							if len(matches) == 0 {
								return nil, true
							}
							// Compute the file hash once per matched file even if
							// multiple rules fire on it — gives the server a stable
							// IOC for blocklist lookup and dashboard correlation.
							hash := hashFileSHA256(path)
							out := make([]scanMatch, 0, len(matches))
							for _, m := range matches {
								slog.Warn("[scan] YARA一致を検出しました",
									"file", path, "rule", m.RuleName, "sha256", hash)
								out = append(out, scanMatch{
									File:   path,
									Rule:   m.RuleName,
									SHA256: hash,
									Size:   info.Size(),
								})
							}
							return out, true
						})
					if cancelled {
						slog.Info("[scan] スキャンが停止されました",
							"targets", scanTargets, "scanned", scanned, "matched", matched)
					} else {
						slog.Info("[scan] スキャンが完了しました",
							"targets", scanTargets, "scanned", scanned, "matched", matched)
					}

					// Report results back to the server with a bounded, retried POST.
					// The previous plain http.Post had no timeout and no retry, so a
					// hung connection blocked this goroutine forever and a single
					// transient failure silently dropped the scan_result — the UI
					// then showed the scan stuck with no result (observed on the
					// verification EC2). A timeout + bounded retry + explicit error
					// log fixes the silent loss and surfaces the real cause.
					reportURL := fmt.Sprintf("%s/api/v1/agents/%s/scan-results", cfg.Server.URL, cfg.Agent.ID)
					body, _ := json.Marshal(map[string]interface{}{
						"target":    strings.Join(scanTargets, ","),
						"scanned":   scanned,
						"matched":   matched,
						"matches":   allMatches,
						"cancelled": cancelled,
					})
					client := &http.Client{Timeout: 30 * time.Second}
					reported := false
					for attempt := 1; attempt <= 4; attempt++ {
						resp, err := client.Post(reportURL, "application/json", bytes.NewReader(body))
						if err == nil {
							code := resp.StatusCode
							resp.Body.Close()
							if code < 400 {
								slog.Info("[scan] 結果をサーバーに送信しました",
									"scanned", scanned, "matched", matched, "attempt", attempt)
								reported = true
								break
							}
							err = fmt.Errorf("HTTP %d", code)
						}
						slog.Warn("[scan] 結果送信に失敗。リトライします",
							"url", reportURL, "attempt", attempt, "error", err)
						if attempt < 4 {
							time.Sleep(time.Duration(attempt*attempt) * time.Second) // 1s, 4s, 9s backoff
						}
					}
					if !reported {
						slog.Error("[scan] 結果の送信に最終的に失敗しました（結果は破棄されます）",
							"url", reportURL, "scanned", scanned, "matched", matched)
					}
				}(payload)
			}
		case transport.CmdReloadConfig:
			if err := cfgMgr.Load(); err != nil {
				slog.Error("設定の再読み込みに失敗しました", "error", err)
			}
		case transport.CmdLiveResponseStart:
			if payload, ok := cmd.Payload.(response.LiveResponseStartPayload); ok {
				response.StartLiveResponse(ctx, payload)
			}
		case transport.CmdForensicsJob:
			if payload, ok := cmd.Payload.(transport.ForensicsJobPayload); ok {
				req := &forensics.JobRequest{
					JobID:     payload.JobID,
					Type:      payload.JobType,
					ProcessID: payload.ProcessID,
				}
				go func() {
					collector := forensics.New(cfg.Server.URL, cfg.Agent.ID, "")
					if err := collector.Execute(ctx, req); err != nil {
						slog.Error("[forensics] job failed",
							"job_id", req.JobID,
							"type", req.Type,
							"error", err,
						)
					} else {
						slog.Info("[forensics] job completed",
							"job_id", req.JobID,
							"type", req.Type,
						)
					}
				}()
			}
		case transport.CmdCertRenew:
			if payload, ok := cmd.Payload.(transport.CertRenewCmd); ok {
				go func(p transport.CertRenewCmd) {
					if err := grpcClient.RenewCertificate(ctx, p.RenewalToken); err != nil {
						slog.Error("[cert_renew] 証明書更新に失敗しました", "error", err)
						return
					}
					slog.Info("[cert_renew] 証明書を更新しました — 再接続します")
					// Close the current connection; RunWithReconnect will re-dial
					// with the new certificate that was written to disk.
					grpcClient.Reconnect()
				}(payload)
			}
		}
	})
	ackSender.set(grpcClient) // ここで実際の送信先が決まる

	// 隔離ルールの継続監視。
	//
	// 隔離は一度掛けたら効き続けるものではない。iptables -F、ポリシーの再適用、
	// ファイアウォールサービスの再起動——ルールが消える経路はいくらでもある。
	// 適用直後の検証 (#733) はその後の消失を捕まえられないので、定期的に
	// 実態を読み返し、消えていれば同じ条件で貼り直す。
	// EDR_ISOLATION_DRIFT_INTERVAL で調整可（既定 2 分、0 で無効）。
	driftInterval := 2 * time.Minute
	if v := os.Getenv("EDR_ISOLATION_DRIFT_INTERVAL"); v != "" {
		if d, err := time.ParseDuration(v); err == nil && d >= 0 {
			driftInterval = d
		} else {
			slog.Warn("EDR_ISOLATION_DRIFT_INTERVAL が不正です。既定(2m)を使います", "値", v)
		}
	}
	if driftInterval > 0 {
		go func() {
			ticker := time.NewTicker(driftInterval)
			defer ticker.Stop()
			for {
				select {
				case <-ctx.Done():
					return
				case <-ticker.C:
					executor.CheckIsolationDrift(ctx)
				}
			}
		}()
		slog.Info("隔離ルールの継続監視を開始しました", "間隔", driftInterval)
	}

	// ─── Local ML anomaly detector ────────────────────────────
	mlDetector := scanner.NewLocalAnomalyDetector()

	// ─── Collectors ───────────────────────────────────────────
	processChan := make(chan collector.ProcessEvent, 1000)
	fileChan := make(chan collector.FileEvent, 1000)
	networkChan := make(chan collector.NetworkEvent, 1000)
	dnsChan := make(chan collector.DNSEvent, 500)
	registryChan := make(chan collector.RegistryEvent, 500)
	authChan := make(chan collector.AuthEvent, 500)
	imageLoadChan := make(chan collector.ImageLoadEvent, 1000)
	scriptChan := make(chan collector.ScriptContentEvent, 1000)

	processCollector, fileCollector, networkCollector, dnsCollector,
		registryCollector, authCollector := buildCollectors(cfg)
	imageLoadCollector := newPlatformImageLoadCollector()
	scriptCollector := newPlatformScriptCollector()

	// Start resource throttle (memory monitor + token bucket)
	throttle.Start(ctx)
	_ = throttle // throttle.Acquire(ctx) should be called in hot event paths

	// Periodic per-action file-event tallies. These answer a question the server
	// side cannot: whether the sensor ever PRODUCED a delete/rename, as opposed to
	// producing one that was lost downstream. Logged rather than served, because
	// the health server that would expose them is never started (nothing imports
	// internal/health).
	go collector.ReportFileEmitStats(ctx, 5*time.Minute)

	// ─── Start services ───────────────────────────────────────
	var wg sync.WaitGroup

	// gRPC connection with auto-reconnect
	wg.Add(1)
	go func() {
		defer wg.Done()
		grpcClient.RunWithReconnect(ctx)
	}()

	// Detect kernel-protection capability (Ph1: detect + report, no enforcement).
	// On Linux this classifies eBPF LSM readiness (enforce/observe/poll); the
	// result is logged once and reported each heartbeat so fleet prevention
	// readiness is visible. See docs/design/Linux改ざん防止と実行前防御設計.md.
	protCaps := protection.Detect()
	slog.Info("保護能力を検出しました", "mode", string(protCaps.Mode), "detail", protCaps.String())

	// Heartbeat reporter — gRPC primary, HTTP fallback
	wg.Add(1)
	go func() {
		defer wg.Done()
		httpSender := heartbeat.NewHTTPSender(cfg.Server.URL, cfg.Agent.ID)
		sender := heartbeat.NewFallbackSender(grpcClient, httpSender)
		hbReporter := heartbeat.NewReporter(
			cfg.Agent.ID, version, osVersionString, cfg.Agent.Hostname,
			sender,
			30*time.Second,
			func() bool { return isolation.IsIsolated() },
			func() int { return buf.Len() },
			func() error { return isolation.Unisolate() },
		)
		// **隔離の巻き戻しは片側しかありませんでした。** 指示が届かない
		// まま DB だけが「隔離済み」になると、その端末は二度と隔離
		// されません。EDR サーバへの経路は残します —— 残さないと、次の
		// ハートビートも届かず、解除の指示も受け取れません。
		hbReporter.SetIsolateFunc(func(string) error {
			return isolation.Isolate([]string{response.ServerHost(cfg.Server.URL)}, nil)
		})
		hbReporter.SetProtectionMode(string(protCaps.Mode))
		hbReporter.SetTelemetryModeFunc(func() string { return string(telemetry.Aggregate()) })
		hbReporter.SetTelemetryDetailFunc(telemetry.String)
		hbReporter.SetUninstallGuardApplier(makeUninstallGuardApplier(*configPath))
		hbReporter.Run(ctx)
	}()

	// Process monitoring
	if cfg.Collection.ProcessMonitoring && processCollector != nil {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := processCollector.Start(ctx, processChan); err != nil {
				slog.Error("プロセス監視の開始に失敗しました", "error", err)
			}
		}()
	}

	// Image-load (DLL) monitoring — Windows ETW, opt-in via EDR_AGENT_ETW;
	// no-op collector on other platforms or when disabled.
	if imageLoadCollector != nil {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := imageLoadCollector.Start(ctx, imageLoadChan); err != nil {
				slog.Error("イメージロード監視の開始に失敗しました", "error", err)
			}
		}()
	}

	// Script content (PowerShell ScriptBlock / AMSI) — Windows ETW, opt-in.
	if scriptCollector != nil {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := scriptCollector.Start(ctx, scriptChan); err != nil {
				slog.Error("スクリプト監視の開始に失敗しました", "error", err)
			}
		}()
	}

	// CreateRemoteThread injection (T1055) — Windows ETW, opt-in via EDR_AGENT_ETW;
	// no-op collector on other platforms or when disabled. Emits findings directly
	// through the event sender.
	if remoteThreadCollector := newPlatformRemoteThreadCollector(); remoteThreadCollector != nil {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := remoteThreadCollector.Start(ctx, cfg.Agent.ID, grpcClient); err != nil {
				slog.Error("リモートスレッド監視の開始に失敗しました", "error", err)
			}
		}()
	}

	// TLS-handshake fingerprint (JA3/JA3S) — Linux eBPF kprobe capture of the
	// ClientHello/ServerHello; no-op sensor on other platforms or without the ebpf
	// tag. Emits tls_handshake findings directly through the event sender for the
	// server's C2-framework fingerprint blocklist.
	if tlsSensor := newPlatformTLSSensor(); tlsSensor != nil {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := tlsSensor.Start(ctx, cfg.Agent.ID, grpcClient); err != nil {
				slog.Debug("TLSフィンガープリント監視は無効です", "error", err)
			}
		}()
	}

	// PowerShell Module Logging (4103) — Windows ETW, opt-in via EDR_AGENT_ETW;
	// no-op collector on other platforms or when disabled. Emits ps_module findings
	// (Payload / ContextInfo) directly through the event sender for SigmaHQ
	// ps_module category rules.
	if psModuleCollector := newPlatformPSModuleCollector(); psModuleCollector != nil {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := psModuleCollector.Start(ctx, cfg.Agent.ID, grpcClient); err != nil {
				slog.Error("PowerShellモジュールログ監視の開始に失敗しました", "error", err)
			}
		}()
	}

	// WMI activity (event-subscription persistence T1546.003 / remote WMI T1047) —
	// Windows ETW, opt-out via EDR_AGENT_ETW_SENSORS=0; no-op collector on other
	// platforms. Emits wmi_activity findings with SigmaHQ wmi_event field names.
	if wmiCollector := newPlatformWMIActivityCollector(); wmiCollector != nil {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := wmiCollector.Start(ctx, cfg.Agent.ID, grpcClient); err != nil {
				slog.Error("WMI監視の開始に失敗しました", "error", err)
			}
		}()
	}

	// Named-pipe creation (C2 named-pipe / Cobalt Strike) — Windows ETW, opt-in via
	// EDR_AGENT_ETW; no-op collector on other platforms or when disabled. Emits
	// pipe_created findings (PipeName) directly through the event sender for SigmaHQ
	// pipe_created category rules.
	if namedPipeCollector := newPlatformNamedPipeCollector(); namedPipeCollector != nil {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := namedPipeCollector.Start(ctx, cfg.Agent.ID, grpcClient); err != nil {
				slog.Error("名前付きパイプ監視の開始に失敗しました", "error", err)
			}
		}()
	}

	// Audit-log-clear monitoring (Windows Security 1102 / System 104 → T1070.001).
	// Emits eventlog_cleared findings directly through the event sender.
	if eventLogClearCollector := newPlatformEventLogClearCollector(); eventLogClearCollector != nil {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := eventLogClearCollector.Start(ctx, cfg.Agent.ID, grpcClient); err != nil {
				slog.Error("イベントログ消去監視の開始に失敗しました", "error", err)
			}
		}()
	}

	// Service-installation monitoring (Windows System EID 7045 → T1543.003).
	// Emits service_installed findings directly through the event sender.
	if serviceInstallCollector := newPlatformServiceInstallCollector(); serviceInstallCollector != nil {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := serviceInstallCollector.Start(ctx, cfg.Agent.ID, grpcClient); err != nil {
				slog.Error("サービスインストール監視の開始に失敗しました", "error", err)
			}
		}()
	}

	// File monitoring
	if cfg.Collection.FileMonitoring && fileCollector != nil {
		// The agent's own spool and log directories are always excluded, on top of
		// whatever the operator configured. Watching them is a feedback loop: the
		// spool write becomes a file event, which is queued into the spool, which
		// produces another write. See collector.SelfExclusions.
		excludedPaths := append(
			append([]string{}, cfg.Collection.ExcludedPaths...),
			collector.SelfExclusions(cfg.Quarantine.Dir, cfg.Logging.File)...,
		)
		wg.Add(1)
		go func() {
			defer wg.Done()
			fileCollector.SetPaths(cfg.Collection.MonitoredPaths, excludedPaths)
			if err := fileCollector.Start(ctx, fileChan); err != nil {
				slog.Error("ファイル監視の開始に失敗しました", "error", err)
			}
		}()
	}

	// Network monitoring
	if cfg.Collection.NetworkMonitoring && networkCollector != nil {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := networkCollector.Start(ctx, networkChan); err != nil {
				slog.Error("ネットワーク監視の開始に失敗しました", "error", err)
			}
		}()
	}

	// DNS monitoring
	if cfg.Collection.DNSMonitoring && dnsCollector != nil {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := dnsCollector.Start(ctx, dnsChan); err != nil {
				slog.Warn("DNS監視の開始に失敗しました", "error", err)
			}
		}()
	}

	// Registry monitoring (Windows only)
	if cfg.Collection.RegistryMonitoring && registryCollector != nil {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := registryCollector.Start(ctx, registryChan); err != nil {
				slog.Warn("レジストリ監視の開始に失敗しました", "error", err)
			}
		}()
	}

	// Auth monitoring
	if cfg.Collection.AuthMonitoring && authCollector != nil {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := authCollector.Start(ctx, authChan); err != nil {
				slog.Warn("認証イベント監視の開始に失敗しました", "error", err)
			}
		}()
	}

	// Resource usage collector (CPU, memory, disk every 30s)
	wg.Add(1)
	go func() {
		defer wg.Done()
		resourceCollector := collector.NewResourceCollector(grpcClient, cfg.Agent.ID)
		resourceCollector.Run(ctx)
	}()

	// Per-process CPU and memory stats collector (every 30s)
	wg.Add(1)
	go func() {
		defer wg.Done()
		psCollector := collector.NewProcessStatsCollector(grpcClient, cfg.Agent.ID)
		slog.Info("[process_stats] プロセスリソースコレクターを起動しました")
		psCollector.Run(ctx)
	}()

	// File Integrity Monitoring (FIM) collector — SHA-256 polling, no cgo.
	// Enabled when cfg.FIM.Enabled == true OR FIM_ENABLED env var is "true".
	fimEnabled := cfg.FIM.Enabled || os.Getenv("FIM_ENABLED") == "true"
	if fimEnabled {
		wg.Add(1)
		go func() {
			defer wg.Done()
			fimInterval := time.Duration(cfg.FIM.IntervalSec) * time.Second
			fimCollector := collector.NewFIMCollector(grpcClient, cfg.Agent.ID, fimInterval)
			slog.Info("[fim] FIMコレクターを起動しました", "interval", fimInterval)
			fimCollector.Run(ctx)
		}()
	}

	// Software inventory reporter — reads installed software and sends to server.
	// Reports on startup then every 6 hours.
	wg.Add(1)
	go func() {
		defer wg.Done()
		swReporter := software.NewReporter(cfg.Server.URL, cfg.Agent.ID, 6*time.Hour)
		slog.Info("[software] ソフトウェアインベントリレポーターを起動しました")
		swReporter.Run(ctx)
	}()

	// Disk-encryption reporter — probes LUKS/BitLocker/FileVault status and
	// sends it to the server. Reports on startup then every 12 hours.
	wg.Add(1)
	go func() {
		defer wg.Done()
		encReporter := encryption.NewReporter(cfg.Server.URL, cfg.Agent.ID, 12*time.Hour)
		slog.Info("[encryption] 暗号化ステータスレポーターを起動しました")
		encReporter.Run(ctx)
	}()

	// Hardening reporter — runs builtin CIS-style config checks and sends the
	// baseline to the server. Reports on startup then every 24 hours.
	wg.Add(1)
	go func() {
		defer wg.Done()
		hdReporter := hardening.NewReporter(cfg.Server.URL, cfg.Agent.ID, 24*time.Hour)
		slog.Info("[hardening] ハードニング評価レポーターを起動しました")
		hdReporter.Run(ctx)
	}()

	// Device collector — USB/external device connect/disconnect monitoring.
	// Always started; uses /sys/bus/usb/devices on Linux, drive-letter polling
	// on Windows.  Darwin returns zero events (no cgo/system_profiler).
	wg.Add(1)
	go func() {
		defer wg.Done()
		deviceCollector := collector.NewDeviceCollector(grpcClient, cfg.Agent.ID, 10*time.Second)
		slog.Info("[device] デバイスコレクターを起動しました")
		deviceCollector.Run(ctx)
	}()

	// Process execution block monitor — polls running processes every 5s and
	// checks against deny rules fetched from the server every 60s.
	wg.Add(1)
	go func() {
		defer wg.Done()
		pm := collector.NewProcessMonitor(
			grpcClient,
			cfg.Agent.ID,
			cfg.Server.URL,
			5*time.Second,
			60*time.Second,
		)
		slog.Info("[process_monitor] プロセス監視ブロッカーを起動しました")
		pm.Run(ctx)
	}()

	// eBPF LSM 実行前防御（Ph2 audit）— Linux + build tag "prevention" でのみ実体。
	// 既存の process_block deny ルール(絶対パス)を blocklist に投入し、exec を
	// カーネルで監視。auditモードのため拒否はせず process_block イベントで申告。
	// 非対応ホスト/タグ無しビルドでは no-op。
	wg.Add(1)
	go func() {
		defer wg.Done()
		runPreventionService(ctx, grpcClient, cfg.Agent.ID, cfg.Server.URL)
	}()

	// エージェント自己保護（Ph4 tamper）— Linux + build tag "prevention" でのみ実体。
	// eBPF LSM task_kill フックで agent への kill 試行を検知（audit、許可）。
	// 非対応ホスト/タグ無しビルドでは no-op。
	wg.Add(1)
	go func() {
		defer wg.Done()
		runTamperService(ctx, grpcClient, cfg.Agent.ID)
	}()

	// エージェント自己保護（ユーザーランド）— 全OS・全ビルドで実体がある唯一の経路。
	// カーネル層（上の runTamperService）は kill を拒否できるが prevention タグ配下で
	// 出荷ビルドに入らない。こちらは拒否はできないが、ウォッチドッグが記録した
	// エージェントの不審な停止・バイナリ/設定の改ざん・ウォッチドッグ自身の消滅を
	// 検知してサーバへ届ける。
	wg.Add(1)
	go func() {
		defer wg.Done()
		runTamperSelfProtect(ctx, grpcClient, cfg.Agent.ID, *configPath, startupIntegrityErr)
	}()

	// LSASS認証情報アクセス検知 M3（Windows + build tag "prevention" でのみ実体）。
	// ドライバの ObRegisterCallbacks で lsass への PROCESS_VM_READ（認証情報ダンプ）を
	// 検知し credential_access イベントで申告。非対応/タグ無しビルドでは no-op。
	wg.Add(1)
	go func() {
		defer wg.Done()
		runCredService(ctx, grpcClient, cfg.Agent.ID)
	}()

	// メモリ/インジェクション検知 M1（Linux + EDR_MEMORY_SCAN=1 でのみ実体）。
	// /proc/<pid>/maps の RWX/非バック実行領域をスキャンし memory イベントで申告。
	// 既定 off（負荷管理のため opt-in）。他プラットフォームでは no-op。
	wg.Add(1)
	go func() {
		defer wg.Done()
		runMemoryScanService(ctx, grpcClient, cfg.Agent.ID, cfg.Server.URL)
	}()

	// Fileless / in-memory execution detection (Linux eBPF, `-tags "ebpf prevention"`):
	// reports execveat(AT_EMPTY_PATH) — running code straight from a memfd/fd with no
	// file on disk (T1620/T1055). No-op on other builds/platforms.
	wg.Add(1)
	go func() {
		defer wg.Done()
		runFilelessService(ctx, grpcClient, cfg.Agent.ID)
	}()

	// ホスト整合性検知(Linux eBPF, `-tags "ebpf prevention"`): カーネルモジュール
	// ロード(init_module/finit_module, T1547.006)・namespace操作(unshare/setns,
	// T1611)・capability変更(capset, T1548.001)をsyscallレベルで検知。既存の
	// insmod/nsenter/chmod +s 等のCommandLineベースルールは、自作/リネームした
	// バイナリから直接syscallを呼ばれると回避されるため、その穴を塞ぐ。他プラット
	// フォームでは no-op。
	wg.Add(1)
	go func() {
		defer wg.Done()
		runHostIntegrityService(ctx, grpcClient, cfg.Agent.ID)
	}()

	// Event aggregator + sender
	wg.Add(1)
	go func() {
		defer wg.Done()
		runEventAggregator(ctx, cfg, grpcClient, mlDetector,
			processChan, fileChan, networkChan, dnsChan, registryChan, authChan, imageLoadChan, scriptChan)
	}()

	// Config file watcher
	go cfgMgr.WatchFile(60*time.Second, func() {
		slog.Info("設定ファイルが変更されました、再読み込みします")
	})

	slog.Info("EDR Agent が起動しました",
		"agent_id", cfg.Agent.ID,
		"hostname", cfg.Agent.Hostname,
		"server", cfg.Server.URL,
	)

	// ─── Auto-update loop ─────────────────────────────────────
	upd := updater.New(cfg.Server.URL, cfg.Agent.ID, version, dataDir)

	// checkAndApplyUpdate performs one update check cycle.
	checkAndApplyUpdate := func(label string) {
		info, err := upd.Check(ctx)
		if err != nil {
			slog.Warn("[updater] バージョンチェックに失敗しました", "label", label, "error", err)
			return
		}
		if info == nil {
			return
		}
		slog.Info("[updater] 新バージョンが利用可能です", "label", label, "version", info.Version)
		if err := upd.Apply(ctx, info); err != nil {
			slog.Error("[updater] アップデートの適用に失敗しました", "error", err)
			return
		}
		slog.Info("[updater] アップデートを適用しました。ウォッチドッグによる再起動を待機します")
		// The .update-pending marker file has already been written by Apply().
		os.Exit(0)
	}

	go func() {
		// 起動直後チェック: 接続が安定するまで30秒待機してから実行。
		// 停止中にサーバー側でバージョンアップされていた場合に即対応する。
		select {
		case <-time.After(30 * time.Second):
			checkAndApplyUpdate("startup")
		case <-ctx.Done():
			return
		}

		// 以降は1時間ごとに定期チェック
		ticker := time.NewTicker(1 * time.Hour)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				checkAndApplyUpdate("periodic")
			case <-ctx.Done():
				return
			}
		}
	}()

	<-ctx.Done()
	slog.Info("シャットダウン中...")

	wg.Wait()

	// Collector Start() returns as soon as its supervisor goroutine is spawned, so
	// wg above says nothing about whether ETW sessions have been torn down. Wait for
	// them explicitly: a session that outlives the process stays registered with the
	// OS and can break the NEXT start, silently.
	waitPlatformShutdown(10 * time.Second)

	_ = grpcClient.Close()
	slog.Info("EDR Agent を停止しました")
}

// runEventAggregator batches events from all collectors and sends them.
func runEventAggregator(
	ctx context.Context,
	cfg *config.Config,
	client *transport.GRPCClient,
	ml *scanner.LocalAnomalyDetector,
	processChan <-chan collector.ProcessEvent,
	fileChan <-chan collector.FileEvent,
	networkChan <-chan collector.NetworkEvent,
	dnsChan <-chan collector.DNSEvent,
	registryChan <-chan collector.RegistryEvent,
	authChan <-chan collector.AuthEvent,
	imageLoadChan <-chan collector.ImageLoadEvent,
	scriptChan <-chan collector.ScriptContentEvent,
) {
	const maxBatchEvents = 10_000

	batchInterval := time.Duration(cfg.Collection.EventBatchIntervalMS) * time.Millisecond
	ticker := time.NewTicker(batchInterval)
	defer ticker.Stop()

	type batchState struct {
		processes  []collector.ProcessEvent
		files      []collector.FileEvent
		networks   []collector.NetworkEvent
		dns        []collector.DNSEvent
		registries []collector.RegistryEvent
		auths      []collector.AuthEvent
		imageLoads []collector.ImageLoadEvent
		scripts    []collector.ScriptContentEvent
		seqID      uint64
	}

	batchLen := func(b *batchState) int {
		return len(b.processes) + len(b.files) + len(b.networks) +
			len(b.dns) + len(b.registries) + len(b.auths) + len(b.imageLoads) + len(b.scripts)
	}

	var current batchState
	var seqID uint64

	// ローカルアラート (異常スコアが閾値超え) は次の ticker を待たずに送る。
	alertGate := newLocalAlertGate(localAlertFlushGap)

	// 親プロセスの解決はエンドポイント側でしかできない。ppid は再利用される
	// 番号で、サーバ側でクエリを流す頃には親は終了している。エージェントは
	// 生成イベントを親が生きているうちに受け取る。
	parents := collector.NewParentResolver()

	flush := func() {
		if len(current.processes)+len(current.files)+len(current.networks)+len(current.dns)+
			len(current.registries)+len(current.auths)+len(current.imageLoads)+len(current.scripts) == 0 {
			return
		}
		seqID++

		var events []*v1.Event

		// ProcessEvents を変換
		//
		// スコアリングは受信時 (select の各 case) に済ませてある。flush の中で
		// 採点していた頃は、閾値を超えたことに気付くのがバッチ組み立て後 —
		// つまり「即時送信するかどうか」を決めるには手遅れだった。
		for _, p := range current.processes {
			evt := &v1.Event{
				Id:        p.ID,
				Timestamp: timestamppb.New(p.Timestamp),
				Type:      v1.EventType_EVENT_TYPE_PROCESS,
				Payload: &v1.Event_Process{
					Process: &v1.ProcessEvent{
						Pid:         p.PID,
						Ppid:        p.PPID,
						ProcessName: p.ProcessName,
						CommandLine: p.CommandLine,
						ImagePath:   p.ImagePath,
						Username:    p.Username,
						Action:      processAction(p.Action),
						EnvVars:     p.EnvVars,
						// PE VERSIONINFO (Windows renamed-binary / LOLBin Sigma rules).
						OriginalFileName: p.OriginalFileName,
						FileDescription:  p.FileDescription,
						ProductName:      p.ProductName,
						CompanyName:      p.CompanyName,
						// Token integrity level (Windows UAC-bypass / privesc rules).
						IntegrityLevel: p.IntegrityLevel,
						// Logon session ID (Windows elevated-shell / privesc rules).
						LogonId: p.LogonID,
						// Parent, resolved on the endpoint (Sigma ParentImage).
						ParentName:  p.ParentName,
						ParentImage: p.ParentImage,
						// 実行ファイルのハッシュ。
						//
						// **計算はしていましたが、載せていませんでした。**
						// エージェントは起動するプロセスごとに実行ファイルを
						// 最大 50 MB 読んで MD5・SHA1・SHA256 を計算し、
						// `evt.Hashes` に入れて、ここで捨てていました。
						// proto には `FileHashes hashes = 8` があります。
						//
						// サーバのハッシュ IOC 照合は、**照合するものを一度も
						// 受け取っていません。** 一致しなかったのではなく、
						// 材料が届いていませんでした。
						Hashes: protoHashes(p.Hashes),
						// Containment, from /proc (Linux).
						ContainerId:          p.Container.ID,
						ContainerPrivileged:  p.Container.Privileged,
						ContainerHostNetwork: p.Container.HostNetwork,
					},
				},
			}
			events = append(events, evt)
		}

		// FileEvents を変換
		for _, f := range current.files {
			evt := &v1.Event{
				Id:        f.ID,
				Timestamp: timestamppb.New(f.Timestamp),
				Type:      v1.EventType_EVENT_TYPE_FILE,
				Payload: &v1.Event_File{
					File: &v1.FileEvent{
						Path:        f.Path,
						OldPath:     f.OldPath,
						Action:      fileAction(f.Action),
						Pid:         f.PID,
						ProcessName: f.ProcessName,
						FileSize:    f.FileSize,
						// ファイルイベントのハッシュも同じく捨てられていました。
						Hashes: protoHashes(f.Hashes),
					},
				},
			}
			events = append(events, evt)
		}

		// NetworkEvents を変換
		for _, n := range current.networks {
			evt := &v1.Event{
				Id:        n.ID,
				Timestamp: timestamppb.New(n.Timestamp),
				Type:      v1.EventType_EVENT_TYPE_NETWORK,
				Payload: &v1.Event_Network{
					Network: &v1.NetworkEvent{
						SrcIp:       n.SrcIP,
						SrcPort:     uint32(n.SrcPort),
						DstIp:       n.DstIP,
						DstPort:     uint32(n.DstPort),
						Protocol:    n.Protocol,
						Direction:   networkDirection(n.Direction),
						BytesSent:   n.BytesSent,
						BytesRecv:   n.BytesRecv,
						Pid:         n.PID,
						ProcessName: n.ProcessName,
					},
				},
			}
			events = append(events, evt)
		}

		// DNSEvents を変換
		for _, d := range current.dns {
			evt := &v1.Event{
				Id:        d.ID,
				Timestamp: timestamppb.New(d.Timestamp),
				Type:      v1.EventType_EVENT_TYPE_DNS,
				Payload: &v1.Event_Dns{
					Dns: &v1.DnsEvent{
						Query:       d.Query,
						QueryType:   d.QueryType,
						Answers:     d.Answers,
						Pid:         d.PID,
						ProcessName: d.ProcessName,
					},
				},
			}
			events = append(events, evt)
		}

		// RegistryEvents を変換
		for _, r := range current.registries {
			evt := &v1.Event{
				Id:        r.ID,
				Timestamp: timestamppb.New(r.Timestamp),
				Type:      v1.EventType_EVENT_TYPE_REGISTRY,
				Payload: &v1.Event_Registry{
					Registry: &v1.RegistryEvent{
						KeyPath:     r.KeyPath,
						ValueName:   r.ValueName,
						ValueData:   r.ValueData,
						Action:      registryAction(r.Action),
						Pid:         r.PID,
						ProcessName: r.ProcessName,
					},
				},
			}
			events = append(events, evt)
		}

		// AuthEvents を変換
		for _, a := range current.auths {
			evt := &v1.Event{
				Id:        a.ID,
				Timestamp: timestamppb.New(a.Timestamp),
				Type:      v1.EventType_EVENT_TYPE_AUTH,
				Payload: &v1.Event_Auth{
					Auth: &v1.AuthEvent{
						Username:      a.Username,
						Action:        authAction(a.Action),
						Success:       a.Success,
						SourceIp:      a.SourceIP,
						AuthMethod:    a.AuthMethod,
						FailureReason: a.FailReason,
						LogonType:     a.LogonType,
						EventId:       a.EventID,
						// Kerberos service ticket (4769) — the Kerberoasting input.
						TargetSpn:            a.TargetSPN,
						TicketEncryptionType: a.TicketEncryptionType,
					},
				},
			}
			events = append(events, evt)
		}

		// ImageLoadEvents を変換
		for _, il := range current.imageLoads {
			evt := &v1.Event{
				Id:        il.ID,
				Timestamp: timestamppb.New(il.Timestamp),
				Type:      v1.EventType_EVENT_TYPE_IMAGE_LOAD,
				Payload: &v1.Event_ImageLoad{
					ImageLoad: &v1.ImageLoadEvent{
						ImagePath:       il.ImagePath,
						Pid:             il.PID,
						ProcessName:     il.ProcessName,
						Signed:          il.Signed,
						SignatureStatus: il.SignatureStatus,
						Signer:          il.Signer,
					},
				},
			}
			events = append(events, evt)
		}

		// ScriptContentEvents を変換
		for _, s := range current.scripts {
			evt := &v1.Event{
				Id:        s.ID,
				Timestamp: timestamppb.New(s.Timestamp),
				Type:      v1.EventType_EVENT_TYPE_SCRIPT,
				Payload: &v1.Event_Script{
					Script: &v1.ScriptContentEvent{
						Engine:      s.Engine,
						Content:     s.Content,
						Pid:         s.PID,
						ProcessName: s.ProcessName,
						ContentHash: s.ContentHash,
						BlockNumber: s.BlockNumber,
						BlockTotal:  s.BlockTotal,
					},
				},
			}
			events = append(events, evt)
		}

		// Scrub invalid UTF-8 from all string fields before marshaling. Linux eBPF
		// argv and inotify filenames can carry arbitrary bytes; proto3 string fields
		// require valid UTF-8, so a single bad event makes the WHOLE batch fail to
		// marshal — silently dropping the clean events batched with it AND looping on
		// reconnect (observed: thousands of marshal failures poisoning telemetry).
		for _, e := range events {
			sanitizeEventStrings(e)
		}

		batch := &v1.EventBatch{
			AgentId:    cfg.Agent.ID,
			SequenceId: seqID,
			Platform:   currentPlatform(),
			Events:     events,
		}

		if err := client.SendEvents(ctx, batch); err != nil {
			slog.Warn("イベント送信に失敗しました", "error", err, "count", len(events))
		}

		current = batchState{seqID: seqID}
	}

	for {
		select {
		case <-ctx.Done():
			flush() // Final flush
			return

		case evt := <-processChan:
			// Name the parent and read the container context here, while the
			// process is still alive. Downstream nothing can: ppid is reused,
			// and /proc/<pid> is gone the moment the process exits. See
			// collector.ParentResolver and collector.ContainerContext.
			parents.EnrichProcess(&evt)
			current.processes = append(current.processes, evt)
			urgent := noteAnomaly(alertGate, time.Now(), "process", ml.ScoreProcess(evt),
				"process", evt.ProcessName, "pid", evt.PID, "cmdline", evt.CommandLine)
			if urgent || batchLen(&current) >= maxBatchEvents {
				flush()
			}

		case evt := <-fileChan:
			current.files = append(current.files, evt)
			urgent := noteAnomaly(alertGate, time.Now(), "file", ml.ScoreFile(evt),
				"path", evt.Path, "action", evt.Action, "process", evt.ProcessName)
			if urgent || batchLen(&current) >= maxBatchEvents {
				flush()
			}

		case evt := <-networkChan:
			current.networks = append(current.networks, evt)
			urgent := noteAnomaly(alertGate, time.Now(), "network", ml.ScoreNetwork(evt),
				"process", evt.ProcessName, "dst", evt.DstIP, "dst_port", evt.DstPort)
			if urgent || batchLen(&current) >= maxBatchEvents {
				flush()
			}

		case evt := <-dnsChan:
			current.dns = append(current.dns, evt)
			if batchLen(&current) >= maxBatchEvents {
				flush()
			}

		case evt := <-registryChan:
			current.registries = append(current.registries, evt)
			if batchLen(&current) >= maxBatchEvents {
				flush()
			}

		case evt := <-authChan:
			current.auths = append(current.auths, evt)
			if batchLen(&current) >= maxBatchEvents {
				flush()
			}

		case evt := <-imageLoadChan:
			current.imageLoads = append(current.imageLoads, evt)
			if batchLen(&current) >= maxBatchEvents {
				flush()
			}

		case evt := <-scriptChan:
			current.scripts = append(current.scripts, evt)
			if batchLen(&current) >= maxBatchEvents {
				flush()
			}

		case <-ticker.C:
			flush()
		}
	}
}

// ─── Helper conversion functions ──────────────────────────────

// sanitizeEventStrings scrubs invalid UTF-8 from an event's string fields so the
// proto batch always marshals. Sources like Linux eBPF argv and inotify filenames
// can contain arbitrary bytes; an unsanitized field fails the whole-batch marshal
// (both wire send and disk-buffer), dropping clean events and triggering reconnect
// churn. Scrubbed at the send boundary so every source/type is covered. (Surfaced
// by deploy/robustness/run-robustness.sh — the half-open/burst test showed clean
// marker events vanishing because they were batched with invalid-UTF8 container argv.)
func sanitizeEventStrings(e *v1.Event) {
	clean := func(s string) string { return strings.ToValidUTF8(s, "") }
	switch p := e.Payload.(type) {
	case *v1.Event_Process:
		if p.Process != nil {
			p.Process.ProcessName = clean(p.Process.ProcessName)
			p.Process.CommandLine = clean(p.Process.CommandLine)
			p.Process.ImagePath = clean(p.Process.ImagePath)
			p.Process.Username = clean(p.Process.Username)
			p.Process.OriginalFileName = clean(p.Process.OriginalFileName)
			p.Process.FileDescription = clean(p.Process.FileDescription)
			p.Process.ProductName = clean(p.Process.ProductName)
			p.Process.CompanyName = clean(p.Process.CompanyName)
			for i, ev := range p.Process.EnvVars {
				p.Process.EnvVars[i] = clean(ev)
			}
		}
	case *v1.Event_File:
		if p.File != nil {
			p.File.Path = clean(p.File.Path)
			p.File.OldPath = clean(p.File.OldPath)
			p.File.ProcessName = clean(p.File.ProcessName)
		}
	case *v1.Event_Network:
		if p.Network != nil {
			p.Network.ProcessName = clean(p.Network.ProcessName)
		}
	case *v1.Event_Dns:
		if p.Dns != nil {
			p.Dns.Query = clean(p.Dns.Query)
			p.Dns.ProcessName = clean(p.Dns.ProcessName)
		}
	}
}

func processAction(a string) v1.ProcessEvent_ProcessAction {
	switch a {
	case "create":
		return v1.ProcessEvent_PROCESS_ACTION_CREATE
	case "terminate":
		return v1.ProcessEvent_PROCESS_ACTION_TERMINATE
	case "inject":
		return v1.ProcessEvent_PROCESS_ACTION_INJECT
	case "hollow":
		return v1.ProcessEvent_PROCESS_ACTION_HOLLOW
	default:
		return v1.ProcessEvent_PROCESS_ACTION_UNSPECIFIED
	}
}

// applyServerPolicy applies an admin-console policy push.
//
// Only the toggles the server actually sends are touched. buildEnabledModules on
// the server emits at most {"network","dns"}; process, file, registry and auth
// monitoring are never named. Treating "absent" as "disable" would therefore turn
// OFF process and file collection the moment any policy is assigned — the whole
// sensor, silently, from a UI that never offered that choice. So the list is read
// as "these two, set to on/off" and everything else is preserved verbatim.
func applyServerPolicy(cfgMgr *config.Manager, p transport.ApplyPolicyCmd) {
	if cfgMgr == nil {
		return
	}
	cur := cfgMgr.Get()
	if cur == nil {
		return
	}
	network, dns := false, false
	var unknown []string
	for _, m := range p.EnabledModules {
		switch strings.ToLower(strings.TrimSpace(m)) {
		case "network":
			network = true
		case "dns":
			dns = true
		default:
			unknown = append(unknown, m)
		}
	}
	// Carry every other field through unchanged: ApplyRemote overwrites the whole
	// collection block, so building a fresh RemoteConfig would wipe the monitored
	// and excluded paths and clear AutoResponseEnabled as a side effect.
	cfgMgr.ApplyRemote(&config.RemoteConfig{
		ProcessMonitoring:    cur.Collection.ProcessMonitoring,
		FileMonitoring:       cur.Collection.FileMonitoring,
		NetworkMonitoring:    network,
		DNSMonitoring:        dns,
		MonitoredPaths:       cur.Collection.MonitoredPaths,
		ExcludedPaths:        cur.Collection.ExcludedPaths,
		ExcludedProcesses:    cur.Collection.ExcludedProcesses,
		EventBatchIntervalMS: cur.Collection.EventBatchIntervalMS,
		AutoResponseEnabled:  cur.Response.AutoResponseEnabled,
	})
	slog.Info("[apply_policy] ポリシーを適用しました",
		"policy", p.PolicyID, "network", network, "dns", dns)
	if len(unknown) > 0 {
		slog.Warn("[apply_policy] 未対応のモジュール名を無視しました", "modules", unknown)
	}
	// Reported, not applied: the agent has no scan scheduler, and the CPU ceiling
	// is fixed at construction (resource.New) with no setter — and the throttle is
	// created but never consulted on the event path (`_ = throttle`). Logging the
	// gap beats pretending the knob took effect.
	if p.ScanIntervalMin > 0 || p.CPULimitPct > 0 {
		slog.Warn("[apply_policy] 未対応の項目があります(受信のみ)",
			"scan_interval_min", p.ScanIntervalMin, "cpu_limit_pct", p.CPULimitPct)
	}
}

func fileAction(a string) v1.FileEvent_FileAction {
	switch a {
	case "create":
		return v1.FileEvent_FILE_ACTION_CREATE
	case "modify":
		return v1.FileEvent_FILE_ACTION_MODIFY
	case "delete":
		return v1.FileEvent_FILE_ACTION_DELETE
	case "rename":
		return v1.FileEvent_FILE_ACTION_RENAME
	case "execute":
		return v1.FileEvent_FILE_ACTION_EXECUTE
	default:
		return v1.FileEvent_FILE_ACTION_UNSPECIFIED
	}
}

func registryAction(a string) v1.RegistryEvent_RegistryAction {
	switch a {
	case "create":
		return v1.RegistryEvent_REGISTRY_ACTION_CREATE
	case "modify":
		return v1.RegistryEvent_REGISTRY_ACTION_MODIFY
	case "delete":
		return v1.RegistryEvent_REGISTRY_ACTION_DELETE
	case "query":
		return v1.RegistryEvent_REGISTRY_ACTION_QUERY
	default:
		return v1.RegistryEvent_REGISTRY_ACTION_UNSPECIFIED
	}
}

func authAction(a string) v1.AuthEvent_AuthAction {
	switch a {
	case "login":
		return v1.AuthEvent_AUTH_ACTION_LOGIN
	case "logout":
		return v1.AuthEvent_AUTH_ACTION_LOGOUT
	case "privilege":
		return v1.AuthEvent_AUTH_ACTION_PRIVILEGE
	case "failed":
		return v1.AuthEvent_AUTH_ACTION_FAILED
	case "kerberos_service_ticket":
		return v1.AuthEvent_AUTH_ACTION_SERVICE_TICKET
	default:
		return v1.AuthEvent_AUTH_ACTION_UNSPECIFIED
	}
}

func networkDirection(d string) v1.NetworkEvent_NetworkDirection {
	switch d {
	case "inbound":
		return v1.NetworkEvent_NETWORK_DIRECTION_INBOUND
	case "outbound":
		return v1.NetworkEvent_NETWORK_DIRECTION_OUTBOUND
	default:
		return v1.NetworkEvent_NETWORK_DIRECTION_UNSPECIFIED
	}
}

func currentPlatform() v1.Platform {
	switch runtime.GOOS {
	case "linux":
		return v1.Platform_PLATFORM_LINUX
	case "windows":
		return v1.Platform_PLATFORM_WINDOWS
	case "darwin":
		return v1.Platform_PLATFORM_DARWIN
	default:
		return v1.Platform_PLATFORM_UNSPECIFIED
	}
}

// ─── Platform-specific component factories ────────────────────

// buildPlatformComponents creates platform-specific implementations.
// The actual implementations are in platform/windows, platform/linux, platform/darwin
// and are selected at compile time via build tags.
func buildPlatformComponents(cfg *config.Config) (
	collector.IsolationManager,
	collector.ProcessManager,
	collector.FileQuarantine,
) {
	return newPlatformIsolation(cfg), newPlatformProcessMgr(), newPlatformQuarantine(cfg)
}

func buildCollectors(cfg *config.Config) (
	collector.ProcessCollector,
	collector.FileCollector,
	collector.NetworkCollector,
	collector.DNSCollector,
	collector.RegistryCollector,
	collector.AuthCollector,
) {
	return newPlatformProcessCollector(), newPlatformFileCollector(),
		newPlatformNetworkCollector(), newPlatformDNSCollector(),
		newPlatformRegistryCollector(), newPlatformAuthCollector()
}

// ─── Enrollment ───────────────────────────────────────────────

func runEnrollment(serverURL, token, configPath string) error {
	slog.Info("エージェントを登録中", "server", serverURL)

	agentID := uuid.New().String()
	hostname, err := os.Hostname()
	if err != nil {
		hostname = agentID[:8]
	}

	// Generate 2048-bit RSA key pair
	privKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return fmt.Errorf("generate key pair: %w", err)
	}

	// Create certificate signing request
	csrTemplate := &x509.CertificateRequest{
		Subject: pkix.Name{
			CommonName:   hostname,
			Organization: []string{"EDR Agent"},
		},
	}
	csrDER, err := x509.CreateCertificateRequest(rand.Reader, csrTemplate, privKey)
	if err != nil {
		return fmt.Errorf("create CSR: %w", err)
	}
	csrPEM := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csrDER}))

	// Build a minimal config for the enrollment gRPC call
	enrollCfg := &config.Config{
		Server: config.ServerConfig{
			URL:               serverURL,
			GRPCPort:          9091,
			ConnectTimeoutSec: 60,
		},
	}

	buf, _ := transport.NewRingBuffer(os.TempDir()+"/edr-enroll-buf", 10)
	enrollClient := transport.NewGRPCClient(enrollCfg, buf, nil)

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	resp, err := enrollClient.Enroll(ctx, &transport.EnrollRequest{
		Token:     token,
		Hostname:  hostname,
		OSType:    runtime.GOOS,
		OSVersion: osVersionString(),
		IPs:       getLocalIPs(),
		CSR:       csrPEM,
	})
	if err != nil {
		return fmt.Errorf("enrollment RPC: %w", err)
	}

	// Save certificates and config
	certDir := filepath.Dir(configPath)
	if err := os.MkdirAll(certDir, 0755); err != nil {
		return fmt.Errorf("create config directory: %w", err)
	}

	keyPath := filepath.Join(certDir, "agent.key")
	keyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(privKey),
	})
	if err := os.WriteFile(keyPath, keyPEM, 0600); err != nil {
		return fmt.Errorf("write private key: %w", err)
	}

	certPath := filepath.Join(certDir, "agent.crt")
	if err := os.WriteFile(certPath, []byte(resp.SignedCert), 0644); err != nil {
		return fmt.Errorf("write certificate: %w", err)
	}

	caPath := filepath.Join(certDir, "ca.crt")
	if err := os.WriteFile(caPath, []byte(resp.CACert), 0644); err != nil {
		return fmt.Errorf("write CA certificate: %w", err)
	}

	// Write config file using the assigned agent ID from server
	if resp.AgentID != "" {
		agentID = resp.AgentID
	}

	quarantineDir := "/var/lib/edr-agent/quarantine"
	logFile := "/var/log/edr-agent/agent.log"
	if runtime.GOOS == "windows" {
		quarantineDir = `C:\ProgramData\EDRAgent\quarantine`
		logFile = `C:\ProgramData\EDRAgent\logs\agent.log`
	}

	// Only enable mTLS if the server URL uses HTTPS (plaintext gRPC when http://)
	cfgCACert, cfgClientCert, cfgClientKey := caPath, certPath, keyPath
	if strings.HasPrefix(serverURL, "http://") {
		cfgCACert, cfgClientCert, cfgClientKey = "", "", ""
	}

	cfgContent := fmt.Sprintf(`[agent]
id = %q
hostname = %q

[server]
url = %q
ca_cert = %q
client_cert = %q
client_key = %q
grpc_port = 9091
connect_timeout_sec = 30

[collection]
process_monitoring = true
file_monitoring = true
network_monitoring = true
dns_monitoring = true
registry_monitoring = true
auth_monitoring = true
yara_scan_on_exec = true
event_batch_interval_ms = 500
local_buffer_size_mb = 100
max_events_per_second = 1000

[response]
auto_response_enabled = true

[logging]
level = "info"
file = %q
max_size_mb = 100
max_backups = 5

[quarantine]
dir = %q
`, agentID, hostname, serverURL, cfgCACert, cfgClientCert, cfgClientKey, logFile, quarantineDir)

	if err := os.WriteFile(configPath, []byte(cfgContent), 0644); err != nil {
		return fmt.Errorf("write config file: %w", err)
	}

	slog.Info("エンロールメント完了",
		"agent_id", agentID,
		"hostname", hostname,
		"config", configPath,
	)
	return nil
}

// getLocalIPs returns all non-loopback IPv4 addresses, plus public IP if available.
func getLocalIPs() []string {
	var ips []string
	ifaces, err := net.Interfaces()
	if err != nil {
		return ips
	}
	for _, iface := range ifaces {
		if iface.Flags&net.FlagLoopback != 0 {
			continue
		}
		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}
		for _, addr := range addrs {
			var ip net.IP
			switch v := addr.(type) {
			case *net.IPNet:
				ip = v.IP
			case *net.IPAddr:
				ip = v.IP
			}
			if ip != nil && ip.To4() != nil {
				ips = append(ips, ip.String())
			}
		}
	}

	// クラウド環境ではNICにパブリックIPが見えないため、メタデータサービスから取得する
	if pub := fetchPublicIPFromMetadata(); pub != "" {
		for _, existing := range ips {
			if existing == pub {
				return ips
			}
		}
		ips = append(ips, pub)
	}
	return ips
}

// fetchPublicIPFromMetadata はEC2/Azure/GCPのメタデータサービスからパブリックIPを取得する。
func fetchPublicIPFromMetadata() string {
	client := &http.Client{Timeout: time.Second}

	// AWS EC2 IMDSv2
	tokenReq, err := http.NewRequest(http.MethodPut, "http://169.254.169.254/latest/api/token", nil)
	if err == nil {
		tokenReq.Header.Set("X-aws-ec2-metadata-token-ttl-seconds", "21600")
		tokenResp, err := client.Do(tokenReq)
		if err == nil && tokenResp.StatusCode == http.StatusOK {
			defer tokenResp.Body.Close()
			tokenBytes, err := io.ReadAll(tokenResp.Body)
			if err == nil {
				token := strings.TrimSpace(string(tokenBytes))
				ipReq, err := http.NewRequest(http.MethodGet, "http://169.254.169.254/latest/meta-data/public-ipv4", nil)
				if err == nil {
					ipReq.Header.Set("X-aws-ec2-metadata-token", token)
					ipResp, err := client.Do(ipReq)
					if err == nil && ipResp.StatusCode == http.StatusOK {
						defer ipResp.Body.Close()
						ipBytes, err := io.ReadAll(ipResp.Body)
						if err == nil {
							if ip := strings.TrimSpace(string(ipBytes)); ip != "" {
								return ip
							}
						}
					}
				}
			}
		}
	}

	// AWS EC2 IMDSv1 フォールバック
	resp, err := client.Get("http://169.254.169.254/latest/meta-data/public-ipv4")
	if err == nil && resp.StatusCode == http.StatusOK {
		defer resp.Body.Close()
		b, err := io.ReadAll(resp.Body)
		if err == nil {
			if ip := strings.TrimSpace(string(b)); ip != "" {
				return ip
			}
		}
	}

	return ""
}

// ─── Defaults ─────────────────────────────────────────────────

func defaultConfigPath() string {
	switch runtime.GOOS {
	case "windows":
		return `C:\ProgramData\EDRAgent\config\config.toml`
	case "darwin":
		return "/etc/edr-agent/config.toml"
	default:
		return "/etc/edr-agent/config.toml"
	}
}

// deriveBufferKey derives a 32-byte AES-256 key from the agent ID using SHA-256.
// The key is deterministic per-agent and never transmitted.
// bestEffortWriter writes to all sub-writers, ignoring individual errors.
// This is used for the log output so that a failed stdout write (e.g. when
// running as a Windows service) does not prevent writing to the log file.
type bestEffortWriter struct {
	writers []io.Writer
}

func (b *bestEffortWriter) Write(p []byte) (int, error) {
	for _, w := range b.writers {
		_, _ = w.Write(p)
	}
	return len(p), nil
}

func deriveBufferKey(agentID string) []byte {
	// Import crypto/sha256 at the top of the file.
	// We embed a fixed domain separator to prevent key reuse.
	const domain = "edr-agent-buffer-key-v1:"
	h := sha256.New()
	h.Write([]byte(domain + agentID))
	return h.Sum(nil) // 32 bytes
}

// hashFileSHA256 returns the hex-encoded SHA-256 of a file. Returns an empty
// string on error so the caller can include a best-effort hash in the scan
// report without aborting the whole result on a single unreadable file.
// The scanner has already validated that the file exists and is <64MB at
// the call site, so this only needs to handle transient I/O errors.
func hashFileSHA256(path string) string {
	f, err := os.Open(path)
	if err != nil {
		return ""
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return ""
	}
	return hex.EncodeToString(h.Sum(nil))
}

// protoHashes converts the agent's hashes for the wire, or nil when there are
// none.
//
// **空のハッシュを送らないのは意図です。** 3つとも空の FileHashes を
// 載せると、サーバからは「ハッシュを取ったが空だった」に見えます。
// 取れなかったものは、欄ごと出しません —— 未測定を測定値にしない、
// という同じ規則です。
func protoHashes(h collector.FileHashes) *v1.FileHashes {
	if h.MD5 == "" && h.SHA1 == "" && h.SHA256 == "" {
		return nil
	}
	return &v1.FileHashes{Md5: h.MD5, Sha1: h.SHA1, Sha256: h.SHA256}
}

// deferredAckSender は response.Executor と GRPCClient の相互依存を解く。
//
// Executor はコマンド実行結果を送るために AckSender を必要とし、GRPCClient は
// 受け取ったコマンドを実行するために Executor を必要とする。生成順をどちらに
// しても片方が先に要る。薄い転送を挟み、grpcClient が出来た時点で差し込む。
//
// これが無かったために NewExecutor へ nil が渡され（"ack sender set below" と
// あるが、その "below" は存在しなかった）、エージェントはコマンドの実行結果を
// 一度も返していなかった。AckSender の実装型が agent 内に 1 つも無い状態だった。
type deferredAckSender struct {
	mu     sync.Mutex
	target response.AckSender
}

func (d *deferredAckSender) set(target response.AckSender) {
	d.mu.Lock()
	d.target = target
	d.mu.Unlock()
}

func (d *deferredAckSender) SendAck(ctx context.Context, commandID string, success bool, errMsg string, result []byte) error {
	d.mu.Lock()
	t := d.target
	d.mu.Unlock()
	if t == nil {
		// 起動直後にコマンドが来た場合。送れないことを黙らせない。
		slog.Warn("ACK の送信先が未設定です", "command_id", commandID)
		return nil
	}
	return t.SendAck(ctx, commandID, success, errMsg, result)
}

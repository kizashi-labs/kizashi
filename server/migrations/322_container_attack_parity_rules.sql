-- 322: detection-server (DB RuleEngine) パリティ 第5弾 — コンテナ攻撃面。
--
-- api-server ビルトインにあるがDBエンジンに全く無いコンテナ/K8s攻撃検知を移植し、
-- コンテナ侵害チェーン(特権コンテナ起動→ホストエスケープ→SAトークン窃取→
-- クラスタ横展開、悪性イメージのホスト内ビルド)を両エンジンで被覆する。
-- ビルトインは Image|endswith を併用するが、DB エンジンでは CommandLine|contains のみで
-- 等価に表現する(コンテナランナー名・危険フラグ・機微パスは必ずコマンドラインに現れる)。
--
-- platform は linux/windows/macos を明示(docker/podman は Docker Desktop 経由で
-- 各OSに存在。イベントOS未設定でも取りこぼさないようフェイルオープン)。
-- 冪等化は WHERE NOT EXISTS。回帰は migration_rules_test.go 群 + migration_parity_test.go。

-- ── T1610 : コンテナのデプロイ(特権/ホスト名前空間) ─────────
INSERT INTO rules (name, type, platform, severity, content, source, mitre_tags, description, enabled)
SELECT 'Privileged Container Deployment (DB)', 'sigma', ARRAY['linux','windows','macos'], 7,
$$title: Privileged Container Deployment (DB)
description: Detects launching a container with host-escape options (--privileged, host PID/network namespace, host-root bind mount, or the docker socket), a common container breakout and host-compromise setup.
status: stable
level: high
tags:
  - attack.t1610
  - attack.execution
  - attack.privilege_escalation
logsource:
  category: process_creation
detection:
  privileged_run:
    CommandLine|contains|all:
      - " run "
    CommandLine|contains:
      - "--privileged"
      - "--pid=host"
      - "--net=host"
      - "-v /:/"
      - "--volume=/:/"
      - "/var/run/docker.sock"
  condition: privileged_run
falsepositives:
  - Legitimate privileged containers (CI runners, monitoring/security agents)
$$,
'builtin-parity', ARRAY['T1610'],
'Two-engine parity: privileged/host-namespace container deployment', true
WHERE NOT EXISTS (SELECT 1 FROM rules WHERE name = 'Privileged Container Deployment (DB)');

-- ── T1611 : ホストへのエスケープ(コンテナブレイクアウト) ─────
INSERT INTO rules (name, type, platform, severity, content, source, mitre_tags, description, enabled)
SELECT 'Container Escape to Host (DB)', 'sigma', ARRAY['linux','windows','macos'], 8,
$$title: Container Escape to Host (DB)
description: Detects container-breakout tradecraft — entering host namespaces via nsenter --target 1, or abusing runc /proc/self/exe overwrite (CVE-2019-5736), cgroup release_agent escape, unshare, or cap_sys_admin to reach the host from inside a container.
status: stable
level: high
tags:
  - attack.t1611
  - attack.privilege_escalation
logsource:
  category: process_creation
detection:
  nsenter:
    CommandLine|contains|all:
      - "nsenter"
    CommandLine|contains:
      - "--target 1"
      - "-t 1"
  breakout:
    CommandLine|contains:
      - "/proc/1/root"
      - "unshare -r"
      - "cap_sys_admin"
      - "/proc/self/exe"
      - "release_agent"
  condition: nsenter or breakout
falsepositives:
  - Legitimate privileged container operations by platform admins
$$,
'builtin-parity', ARRAY['T1611'],
'Two-engine parity: container escape to host (nsenter/runc/cgroup)', true
WHERE NOT EXISTS (SELECT 1 FROM rules WHERE name = 'Container Escape to Host (DB)');

-- ── T1612 : ホスト内でのイメージビルド(スキャン回避) ─────────
INSERT INTO rules (name, type, platform, severity, content, source, mitre_tags, description, enabled)
SELECT 'Container Image Build on Host (DB)', 'sigma', ARRAY['linux','windows','macos'], 5,
$$title: Container Image Build on Host (DB)
description: Detects building a container image directly on a host (docker/podman/nerdctl build, buildah bud/build, kaniko executor). Adversaries build malicious images locally to bypass registry-side image scanning and admission controls before deploying them.
status: stable
level: medium
tags:
  - attack.t1612
  - attack.defense_evasion
logsource:
  category: process_creation
detection:
  buildah_kaniko:
    CommandLine|contains:
      - "buildah bud"
      - "buildah build"
      - "/kaniko/executor"
      - "kaniko-project"
  docker_build:
    CommandLine|contains|all:
      - "docker"
      - " build"
  podman_build:
    CommandLine|contains|all:
      - "podman"
      - " build"
  nerdctl_build:
    CommandLine|contains|all:
      - "nerdctl"
      - " build"
  condition: buildah_kaniko or docker_build or podman_build or nerdctl_build
falsepositives:
  - Legitimate CI/CD image builds on build agents
$$,
'builtin-parity', ARRAY['T1612'],
'Two-engine parity: container image build on host (scan bypass)', true
WHERE NOT EXISTS (SELECT 1 FROM rules WHERE name = 'Container Image Build on Host (DB)');

-- ── T1609 : コンテナ管理コマンド実行(exec) ──────────────────
INSERT INTO rules (name, type, platform, severity, content, source, mitre_tags, description, enabled)
SELECT 'Container Administration Command (DB)', 'sigma', ARRAY['linux','windows','macos'], 4,
$$title: Container Administration Command (DB)
description: Detects entering a running container via kubectl/docker/podman/crictl exec, used to run commands inside containers, including by attackers who have compromised the orchestration plane.
status: experimental
level: low
tags:
  - attack.t1609
  - attack.execution
logsource:
  category: process_creation
detection:
  exec_into:
    CommandLine|contains|all:
      - " exec "
    CommandLine|contains:
      - "kubectl"
      - "docker"
      - "podman"
      - "crictl"
  condition: exec_into
falsepositives:
  - Legitimate operator or CI access into containers
$$,
'builtin-parity', ARRAY['T1609'],
'Two-engine parity: container administration command (exec)', true
WHERE NOT EXISTS (SELECT 1 FROM rules WHERE name = 'Container Administration Command (DB)');

-- ── T1552.007 : Kubernetes サービスアカウントトークン窃取 ─────
INSERT INTO rules (name, type, platform, severity, content, source, mitre_tags, description, enabled)
SELECT 'Kubernetes Service Account Token Access (DB)', 'sigma', ARRAY['linux','windows','macos'], 7,
$$title: Kubernetes Service Account Token Access (DB)
description: Detects reading of the in-pod Kubernetes service-account token or kubelet credentials (serviceaccount token path, kubelet PKI, admin.conf, kubelet.conf), used to escalate from a compromised container to the cluster API.
status: stable
level: high
tags:
  - attack.t1552.007
  - attack.credential_access
logsource:
  category: process_creation
detection:
  token_path:
    CommandLine|contains:
      - "/var/run/secrets/kubernetes.io/serviceaccount"
      - "/var/lib/kubelet/pki"
      - "/etc/kubernetes/admin.conf"
      - "serviceaccount/token"
      - "kubelet.conf"
  condition: token_path
falsepositives:
  - In-cluster tooling reading its own service-account token
$$,
'builtin-parity', ARRAY['T1552.007'],
'Two-engine parity: Kubernetes service-account token theft', true
WHERE NOT EXISTS (SELECT 1 FROM rules WHERE name = 'Kubernetes Service Account Token Access (DB)');

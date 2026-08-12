//go:build linux && ebpf && !prevention

package linux

// prevention を外したビルドでは credential-access / host-integrity の
// フィルタ自体が存在しないため、常に 0 を返す。
// 定期レポート側 (linux && ebpf) をタグで分岐させないための受け皿。

func preventionNoiseFiltered() (cred, hostIntegrity uint64) {
	return 0, 0
}

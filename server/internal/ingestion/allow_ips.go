package ingestion

import (
	"fmt"
	"net"
	"strings"
)

// ParseAllowIPs turns the ISOLATION_ALLOW_IPS value into the list sent to agents
// as IsolateCommand.allow_ips, together with the entries it could not accept.
//
// **起動時に弾くのが要点。** 受け側（agent の computeBlockRanges）も解釈できない
// 項目を落としてログに出すが、それが読まれるのは端末が隔離されたあとで、
// そのときには「除外したはずのセグメントが遮断されている」状態になっている。
// 隔離は外から取り消せないので、書き間違いに気づく場所は起動時でなければ遅い。
//
// 受け付けるのは IPv4 の単一アドレスと CIDR のみ。IPv6 を除くのは、agent 側の
// ブロック範囲計算が uint32 で、IPv6 を載せられないため（隔離は元から IPv4
// のみを対象にしている）。ここで通してしまうと、agent まで運ばれてから捨てられる。
func ParseAllowIPs(raw string) (accepted []string, rejected []string) {
	for _, entry := range strings.Split(raw, ",") {
		entry = strings.TrimSpace(entry)
		if entry == "" {
			continue
		}
		if err := validateAllowIP(entry); err != nil {
			rejected = append(rejected, fmt.Sprintf("%s (%v)", entry, err))
			continue
		}
		accepted = append(accepted, entry)
	}
	return accepted, rejected
}

func validateAllowIP(entry string) error {
	if strings.Contains(entry, "/") {
		ip, ipnet, err := net.ParseCIDR(entry)
		if err != nil {
			return err
		}
		if ip.To4() == nil || ipnet.IP.To4() == nil {
			return fmt.Errorf("IPv4 の CIDR ではありません")
		}
		return nil
	}
	ip := net.ParseIP(entry)
	if ip == nil {
		return fmt.Errorf("IP アドレスとして解釈できません")
	}
	if ip.To4() == nil {
		return fmt.Errorf("IPv4 アドレスではありません")
	}
	return nil
}

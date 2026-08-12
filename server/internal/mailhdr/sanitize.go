// Package mailhdr はメールヘッダに値を埋める前の無害化を提供する。
//
// RFC 5322 のヘッダは CRLF で区切られる。値に改行が混ざると、そこから先が
// 新しいヘッダとして解釈される — いわゆるヘッダインジェクション。
//
//	Subject: <組織名>\r\nBcc: attacker@example.com
//
// のような値を通すと、通知メールの宛先を攻撃者が追加できてしまう。
//
// 本プラットフォームのメール送信経路はいずれも fmt.Sprintf でヘッダを
// 組み立てており、埋める値には利用者が設定できるものが含まれる:
//
//   - 組織名 (ライセンス期限通知の Subject)
//   - 管理者のメールアドレス (DB から読んだ To)
//   - レポート名・ダイジェストの件名
//
// 「入力時に検証しているはず」に頼らず、ヘッダを組み立てる直前で落とす。
// 検証を通り抜ける経路 (直接 DB 投入、移行、外部連携) が 1 つでもあれば
// 入力側の検証は破れるが、ここは全経路が必ず通る。
package mailhdr

import "strings"

// Sanitize はヘッダ値として安全な形に落とす。
//
// CR / LF / NUL を取り除く。折り返し (obs-fold) を許すと結局 CRLF を
// 通すことになるため、正当な折り返しも認めない — 本プラットフォームが
// 生成するヘッダに折り返しが必要な長さのものは無い。
//
// 値を切り詰めるのではなく除去するのは、末尾を落とすと「なぜか件名が
// 途中で切れる」という分かりにくい症状になるため。除去なら注入部分の
// 痕跡が件名に残り、気付ける。
func Sanitize(s string) string {
	if !strings.ContainsAny(s, "\r\n\x00") {
		return s // 大多数はここで抜ける (割り当てなし)
	}
	return strings.Map(func(r rune) rune {
		switch r {
		case '\r', '\n', 0:
			return -1
		}
		return r
	}, s)
}

// SanitizeAll は複数の値をまとめて無害化する。To に複数アドレスを
// 並べる箇所で使う。
func SanitizeAll(values []string) []string {
	out := make([]string, len(values))
	for i, v := range values {
		out[i] = Sanitize(v)
	}
	return out
}

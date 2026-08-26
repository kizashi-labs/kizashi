package scheduler

// このファイルはオープンソース版でのみ使われる補助関数です。
// 商用版では、ここにある関数は AI トリアージ側で定義されています。

// ptrOrEmpty は nil ポインタを空文字列として扱います。
func ptrOrEmpty(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}

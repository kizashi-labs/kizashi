// shared_small_helpers.go — 除外側のスケジューラから切り出した小さな共有ヘルパ。
package scheduler

// itoa is a minimal integer-to-string helper to avoid importing strconv.
func itoa(i int) string {
	if i == 0 {
		return "0"
	}
	neg := false
	if i < 0 {
		neg = true
		i = -i
	}
	buf := [20]byte{}
	pos := len(buf)
	for i > 0 {
		pos--
		buf[pos] = byte('0' + i%10)
		i /= 10
	}
	if neg {
		pos--
		buf[pos] = '-'
	}
	return string(buf[pos:])
}

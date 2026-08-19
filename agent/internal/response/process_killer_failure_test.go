package response

import (
	"context"
	"errors"
	"testing"
)

// 見つけたのに1つも停止できなかったとき、成功を返さないこと。
//
// 以前は殺せた PID だけを積み、err には nil を返していました。5件見つけて
// 5件とも権限で失敗しても戻り値は ([], nil) で、**「その名前のプロセスは
// 動いていなかった」とまったく同じ**でした。
//
// 呼び出し側 (manager.ExecuteCommand) はそれを成功として記録します。
// サーバには「対処済み」が残り、コンソールにもそう出て、プロセスは
// 動き続けます。**対応アクションで、これがいちばん直接的な形です。**
//
// kill そのものを差し替えて確かめます。最初は PID 1 を使っていましたが、
// root で走る環境では skip され、**判定を消す変異を素通りさせました。**
func TestKillingNothingOfWhatWeFoundIsNotSuccess(t *testing.T) {
	orig := killProcess
	killProcess = func(int) error { return errors.New("operation not permitted") }
	t.Cleanup(func() { killProcess = orig })

	k := &ProcessKiller{}
	killed, err := k.killPIDs(context.Background(), "malware", []int{101, 102, 103})

	if err == nil {
		t.Error("1件も停止できなかったのに成功を返しています。" +
			"呼び出し側は「対処済み」として記録し、プロセスは動き続けます")
	}
	if len(killed) != 0 {
		t.Errorf("停止していないのに killed=%v を返しています", killed)
	}
}

// 一部でも停止できたら、成功のままにすること。部分的な対処は対処です。
func TestKillingSomeIsStillSuccess(t *testing.T) {
	orig := killProcess
	killProcess = func(pid int) error {
		if pid == 101 {
			return nil
		}
		return errors.New("operation not permitted")
	}
	t.Cleanup(func() { killProcess = orig })

	k := &ProcessKiller{}
	killed, err := k.killPIDs(context.Background(), "malware", []int{101, 102})
	if err != nil {
		t.Errorf("1件は停止できているのに失敗を返しています: %v", err)
	}
	if len(killed) != 1 || killed[0] != 101 {
		t.Errorf("killed = %v, want [101]", killed)
	}
}

// 一致するプロセスが無かったときは、失敗ではありません。
// 「居なかった」と「殺せなかった」を取り違えると、今度は逆の嘘になります。
func TestNoMatchingProcessIsNotAFailure(t *testing.T) {
	k := &ProcessKiller{}
	killed, err := k.killPIDs(context.Background(), "no-such-process", nil)
	if err != nil {
		t.Errorf("一致するプロセスが無いのを失敗として返しています: %v", err)
	}
	if len(killed) != 0 {
		t.Errorf("killed = %v, want empty", killed)
	}
}

package store_test

import (
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"sort"
	"strings"
	"testing"

	"github.com/edr-platform/server/internal/store"
)

// 抑制条件のキーは 2 箇所にある。
//
//	store.SuppressionConditions            画面が読み書きする形 (jsonb を marshal して列ごと置換)
//	detection.PoolSuppressionLoader の SQL  検知エンジンが実際に読む形 (conditions->>'...')
//
// **書き手が知らないキーは、更新のたびに消える。** conditions は jsonb 一列で、
// 更新は構造体を marshal した結果で置き換えるので、読み手だけが知っているキーは
// 画面から名前を直しただけの操作で静かに落ちる。条件が減った抑制ルールは
// 減った分だけ広く当たる —— **消えたアラートは後から取り戻せない。**
//
// 実際 command_line_contains と parent_process が読み手にだけあり、
// 画面の編集を実装した時点でこの穴が開いた（同じ PR で塞いだ）。
//
// この検査はソースを読んで突き合わせる。DB もサーバも要らないので CI で毎回走る。
func TestSuppressionConditionKeysMatchTheReader(t *testing.T) {
	// 読み手が読むキー。SQL の写しではなく本番のソースそのものから抜く。
	path := filepath.Join("..", "detection", "suppression_loader.go")
	src, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("読み手のソースを読めません (%s): %v", path, err)
	}
	re := regexp.MustCompile(`conditions->>'([a-z_]+)'`)
	readerKeys := map[string]bool{}
	for _, m := range re.FindAllStringSubmatch(string(src), -1) {
		readerKeys[m[1]] = true
	}
	if len(readerKeys) == 0 {
		t.Fatalf("%s から conditions のキーを 1 つも抜けませんでした。"+
			"読み手の書き方が変わったなら、この検査も直すこと "+
			"—— **抜けなくなったことに気づかないと、この検査は永久に緑になります**", path)
	}

	// 書き手が知っているキー。
	writerKeys := map[string]bool{}
	rt := reflect.TypeOf(store.SuppressionConditions{})
	for i := 0; i < rt.NumField(); i++ {
		tag := rt.Field(i).Tag.Get("json")
		name := strings.Split(tag, ",")[0]
		if name != "" && name != "-" {
			writerKeys[name] = true
		}
	}

	var missing, extra []string
	for k := range readerKeys {
		if !writerKeys[k] {
			missing = append(missing, k)
		}
	}
	for k := range writerKeys {
		if !readerKeys[k] {
			extra = append(extra, k)
		}
	}
	sort.Strings(missing)
	sort.Strings(extra)

	if len(missing) > 0 {
		t.Errorf("検知エンジンが読むのに store.SuppressionConditions に無い条件: %v。"+
			"**この条件を持つルールを画面から編集すると、条件だけが静かに消えます** "+
			"—— 抑制の範囲が広がり、消えたアラートは戻りません", missing)
	}
	if len(extra) > 0 {
		t.Errorf("store.SuppressionConditions にあるのに検知エンジンが読まない条件: %v。"+
			"**画面では設定できるのに何の効果もありません** —— "+
			"運用者は絞り込んだつもりで、実際は絞り込めていません", extra)
	}
}

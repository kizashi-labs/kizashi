package geoip

import (
	"errors"
	"testing"
)

// 引けなかった宛先が、地図から黙って消えないこと。
//
// 脅威マップは CountryCode == "XX" の行を読み飛ばします。以前は引けな
// かった IP も "XX" だったので、ip-api.com が詰まっている（無料枠は毎分
// 45件）あいだ、宛先は地図から消えました。地図は「その国への通信は無い」
// ように見えます。無いのと、見えていないのは別です。
func TestAnUnresolvedDestinationIsNotTheSameAsNoTraffic(t *testing.T) {
	for _, c := range []struct {
		name string
		loc  *Location
		want mapPlacement
	}{
		{"引けた", &Location{CountryCode: "JP", Country: "Japan"}, mapPlot},
		{"内部アドレス", &Location{CountryCode: "INT"}, mapSkip},
		{"引けたが国が分からなかった", &Location{CountryCode: "XX"}, mapSkip},
		{"引けなかった", unavailableLocation("203.0.113.1", errors.New("timeout")), mapUnresolved},
		{"位置そのものが無い", nil, mapUnresolved},
	} {
		t.Run(c.name, func(t *testing.T) {
			if got := classifyForMap(c.loc); got != c.want {
				t.Errorf("classifyForMap = %v, want %v", got, c.want)
			}
		})
	}
}

// 引けなかったことが Location に残ること。理由が消えると、記録に
// 「何件消えたか」しか残りません。
func TestAnUnavailableLocationCarriesItsReason(t *testing.T) {
	loc := unavailableLocation("203.0.113.1", errors.New("dial tcp: timeout"))
	if !loc.Unavailable {
		t.Error("Unavailable が立っていません")
	}
	if loc.UnavailableReason == "" {
		t.Error("理由がありません")
	}
	if loc.CountryCode != "XX" {
		t.Errorf("CountryCode = %q, want XX", loc.CountryCode)
	}
}

package detection

import (
	"strings"
	"testing"
)

// The false positives this change exists to remove. Both are AWS agent traffic
// observed on a live Windows endpoint (2026-08-05); the second one was the C2
// axis that escalated a benign Amazon Inspector run to a severity-10 correlation
// and auto-isolated the host.
func TestAnalyzeDNSQueryAcceptsAWSServiceEndpoints(t *testing.T) {
	benign := []string{
		"inspector2-oval-prod-ap-northeast-1.s3.dualstack.ap-northeast-1.amazonaws.com",
		"aws-ssm-document-attachments-ap-northeast-1.s3.ap-northeast-1.amazonaws.com",
		"my-company-backups.s3.amazonaws.com",
		"ssmmessages.ap-northeast-1.amazonaws.com",
		"ec2messages.ap-northeast-1.amazonaws.com",
		"settings-win.data.microsoft.com",
		"myaccount.blob.core.windows.net",
		"release-artifacts-bucket.storage.googleapis.com",
	}
	for _, q := range benign {
		if v := AnalyzeDNSQuery(q); v.Suspicious {
			t.Errorf("良性を検知した: %s (score=%d, %s)", q, v.Score, strings.Join(v.Reasons, ", "))
		}
	}
}

// The property that makes the change safe: dropping the service suffix from the
// payload must not let an encoded chunk hide behind it. The bucket-name label is
// still scored, so exfil dressed as an S3 bucket still fires.
func TestAnalyzeDNSQueryStillCatchesExfilBehindAServiceSuffix(t *testing.T) {
	malicious := []string{
		"mfzg63tbm5sw4ylsmvxgg33nmfzg63tbm5sw4yls.s3.ap-northeast-1.amazonaws.com",
		"kzrxk3tdnfxgs3ldnbxxezlsmvxgg33n.kzrxk3tdnfxgs3ldnbxxezlsmvxgg33n.t.evil.com",
		"nbswy3dpfqqho33snrscc.mzxw6ytboi.mfrggzdfmztwq2lk.tunnel.attacker.net",
	}
	for _, q := range malicious {
		if v := AnalyzeDNSQuery(q); !v.Suspicious {
			t.Errorf("悪性を見逃した: %s (score=%d, %s)", q, v.Score, strings.Join(v.Reasons, ", "))
		}
	}
}

// A long label only counts as an encoded chunk when it looks encoded. Hyphenated
// words are how cloud buckets are named; base32 is how payloads are carried.
func TestLongLabelSignalRequiresEncodedLooking(t *testing.T) {
	words := AnalyzeDNSQuery("aws-ssm-document-attachments-ap-northeast-1.s3.ap-northeast-1.amazonaws.com")
	for _, r := range words.Reasons {
		if strings.Contains(r, "label >40") {
			t.Errorf("ハイフン区切りの語に符号化ラベルとして加点した: %v", words.Reasons)
		}
	}

	encoded := AnalyzeDNSQuery("mfzg63tbm5sw4ylsmvxgg33nmfzg63tbm5sw4ylsmvxgg33n.s3.ap-northeast-1.amazonaws.com")
	var got bool
	for _, r := range encoded.Reasons {
		if strings.Contains(r, "label >40") {
			got = true
		}
	}
	if !got {
		t.Errorf("符号化された長ラベルに加点していない: %v", encoded.Reasons)
	}
}

func TestExfilPayloadLabels(t *testing.T) {
	cases := []struct {
		q    string
		want []string
	}{
		{"inspector2-oval-prod-ap-northeast-1.s3.dualstack.ap-northeast-1.amazonaws.com",
			[]string{"inspector2-oval-prod-ap-northeast-1"}},
		{"bucket.s3.ap-northeast-1.amazonaws.com", []string{"bucket"}},
		{"a.b.bucket.s3.amazonaws.com", []string{"a", "b", "bucket"}},
		{"acct.blob.core.windows.net", []string{"acct"}},
		// 未知のサフィックスは従来どおり末尾2ラベルを落とす
		{"a.b.example.com", []string{"a", "b"}},
		{"example.com", nil},
		// サービスサフィックス規則は payload が残る場合のみ適用する。
		// s3.amazonaws.com 自体は汎用フォールバック（末尾2ラベル落とし）で扱われる。
		{"s3.amazonaws.com", []string{"s3"}},
	}
	for _, c := range cases {
		got := exfilPayloadLabels(c.q)
		if strings.Join(got, ".") != strings.Join(c.want, ".") {
			t.Errorf("%s: got %v, want %v", c.q, got, c.want)
		}
	}
}

// A region label must not be matched by anything else, and a longer suffix must
// win over a shorter one that also matches.
func TestServiceSuffixMatchingIsSpecific(t *testing.T) {
	// s3.dualstack.<region>.amazonaws.com must win over s3.*.amazonaws.com,
	// otherwise "dualstack" would be counted as payload.
	if got := exfilPayloadLabels("b.s3.dualstack.eu-west-1.amazonaws.com"); len(got) != 1 || got[0] != "b" {
		t.Errorf("最長一致になっていない: %v", got)
	}
	// A name that merely contains an "s3" label must fall back to the generic
	// two-label rule, not be treated as an AWS endpoint (which would hide the
	// attacker-chosen "s3" label from scoring).
	if got := exfilPayloadLabels("b.s3.attacker.com"); len(got) != 2 || got[0] != "b" || got[1] != "s3" {
		t.Errorf("無関係な名前にサービスサフィックスを適用した: %v", got)
	}
}

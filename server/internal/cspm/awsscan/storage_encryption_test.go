package awsscan

// RDS / EFS の保管データ暗号化。
//
// 判定自体は真偽値 1 つだが、AWS SDK では **ポインタ** で来るので
// 「false」と「値が無い」が別物になる。nil を false に丸めると、応答に
// 含まれなかっただけの資源に対して「暗号化されていません」という所見が
// 立つ。RDS も EFS も後から暗号化できないので、その所見が指示する是正は
// 「作り直し」になる ---存在しない問題のために本番 DB の移行を検討させる
// ことになるため、ここは unknown に倒す。

import (
	"context"
	"strings"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/efs"
	efstypes "github.com/aws/aws-sdk-go-v2/service/efs/types"
	"github.com/aws/aws-sdk-go-v2/service/rds"
	rdstypes "github.com/aws/aws-sdk-go-v2/service/rds/types"
)

type fakeRDS struct {
	instances []rdstypes.DBInstance
	page2     []rdstypes.DBInstance
	err       error
	calls     *int
}

func (f fakeRDS) DescribeDBInstances(_ context.Context, in *rds.DescribeDBInstancesInput, _ ...func(*rds.Options)) (*rds.DescribeDBInstancesOutput, error) {
	if f.err != nil {
		return nil, f.err
	}
	if f.calls != nil {
		*f.calls++
	}
	if f.page2 != nil && in.Marker == nil {
		return &rds.DescribeDBInstancesOutput{DBInstances: f.instances, Marker: aws.String("next")}, nil
	}
	if in.Marker != nil {
		return &rds.DescribeDBInstancesOutput{DBInstances: f.page2}, nil
	}
	return &rds.DescribeDBInstancesOutput{DBInstances: f.instances}, nil
}

type fakeEFS struct {
	systems []efstypes.FileSystemDescription
	page2   []efstypes.FileSystemDescription
	err     error
}

func (f fakeEFS) DescribeFileSystems(_ context.Context, in *efs.DescribeFileSystemsInput, _ ...func(*efs.Options)) (*efs.DescribeFileSystemsOutput, error) {
	if f.err != nil {
		return nil, f.err
	}
	if f.page2 != nil && in.Marker == nil {
		return &efs.DescribeFileSystemsOutput{FileSystems: f.systems, NextMarker: aws.String("next")}, nil
	}
	if in.Marker != nil {
		return &efs.DescribeFileSystemsOutput{FileSystems: f.page2}, nil
	}
	return &efs.DescribeFileSystemsOutput{FileSystems: f.systems}, nil
}

func db(id string, encrypted *bool) rdstypes.DBInstance {
	return rdstypes.DBInstance{
		DBInstanceIdentifier: aws.String(id),
		Engine:               aws.String("postgres"),
		StorageEncrypted:     encrypted,
	}
}

func fs(id, name string, encrypted *bool) efstypes.FileSystemDescription {
	out := efstypes.FileSystemDescription{
		FileSystemId: aws.String(id),
		Encrypted:    encrypted,
	}
	if name != "" {
		out.Name = aws.String(name)
	}
	return out
}

func TestRDSEncryption(t *testing.T) {
	for _, tc := range []struct {
		name      string
		encrypted *bool
		want      Status
	}{
		{"暗号化済みは合格", aws.Bool(true), StatusPass},
		{"未暗号化は不合格", aws.Bool(false), StatusFail},
		// nil を false に丸めると、応答に含まれなかっただけの DB に
		// 「暗号化されていません」が立つ。RDS は後から暗号化できないので、
		// その所見が指示するのは本番 DB の作り直しになる。
		{"値が無ければ unknown", nil, StatusUnknown},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := baseClients()
			c.RDS = fakeRDS{instances: []rdstypes.DBInstance{db("prod-db", tc.encrypted)}}
			got := onlyResult(t, runCheck(t, "aws-rds-storage-encrypted", c))
			if got.Status != tc.want {
				t.Errorf("status = %q, want %q (evidence: %s)", got.Status, tc.want, got.Evidence)
			}
			if got.ResourceID != "prod-db" {
				t.Errorf("resource_id = %q, want prod-db", got.ResourceID)
			}
		})
	}
}

func TestEFSEncryption(t *testing.T) {
	for _, tc := range []struct {
		name      string
		encrypted *bool
		want      Status
	}{
		{"暗号化済みは合格", aws.Bool(true), StatusPass},
		{"未暗号化は不合格", aws.Bool(false), StatusFail},
		{"値が無ければ unknown", nil, StatusUnknown},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := baseClients()
			c.EFS = fakeEFS{systems: []efstypes.FileSystemDescription{fs("fs-1", "shared", tc.encrypted)}}
			got := onlyResult(t, runCheck(t, "aws-efs-encrypted", c))
			if got.Status != tc.want {
				t.Errorf("status = %q, want %q (evidence: %s)", got.Status, tc.want, got.Evidence)
			}
			if got.ResourceID != "fs-1" || got.ResourceName != "shared" {
				t.Errorf("資源の識別がおかしい: %+v", got)
			}
		})
	}
}

// Name タグが無い EFS は珍しくない。名前が空だと一覧で識別できないので
// ID を代わりに使う。
func TestEFSWithoutNameTagUsesID(t *testing.T) {
	c := baseClients()
	c.EFS = fakeEFS{systems: []efstypes.FileSystemDescription{fs("fs-noname", "", aws.Bool(false))}}
	got := onlyResult(t, runCheck(t, "aws-efs-encrypted", c))
	if got.ResourceName != "fs-noname" {
		t.Errorf("resource_name = %q, want fs-noname (名前が空のまま)", got.ResourceName)
	}
}

// 2 ページ目を取り逃がすと「見えていない資源は問題なし」になる。
func TestStorageEncryptionPaginates(t *testing.T) {
	t.Run("RDS", func(t *testing.T) {
		c := baseClients()
		c.RDS = fakeRDS{
			instances: []rdstypes.DBInstance{db("db-1", aws.Bool(true))},
			page2:     []rdstypes.DBInstance{db("db-2", aws.Bool(false))},
		}
		got := runCheck(t, "aws-rds-storage-encrypted", c)
		if len(got) != 2 {
			t.Fatalf("結果が %d 件, want 2: %+v", len(got), got)
		}
		if got[1].ResourceID != "db-2" || got[1].Status != StatusFail {
			t.Errorf("2 ページ目が取れていない: %+v", got[1])
		}
	})

	t.Run("EFS", func(t *testing.T) {
		c := baseClients()
		c.EFS = fakeEFS{
			systems: []efstypes.FileSystemDescription{fs("fs-1", "a", aws.Bool(true))},
			page2:   []efstypes.FileSystemDescription{fs("fs-2", "b", aws.Bool(false))},
		}
		got := runCheck(t, "aws-efs-encrypted", c)
		if len(got) != 2 {
			t.Fatalf("結果が %d 件, want 2: %+v", len(got), got)
		}
		if got[1].ResourceID != "fs-2" || got[1].Status != StatusFail {
			t.Errorf("2 ページ目が取れていない: %+v", got[1])
		}
	})
}

// 一覧が取れなければ unknown。pass に倒すと「DB は全部暗号化済み」という
// 最も安心できる表示になる。
func TestStorageEncryptionListFailureIsUnknown(t *testing.T) {
	t.Run("RDS", func(t *testing.T) {
		c := baseClients()
		c.RDS = fakeRDS{err: errAccessDenied{}}
		if got := onlyResult(t, runCheck(t, "aws-rds-storage-encrypted", c)); got.Status != StatusUnknown {
			t.Errorf("status = %q, want unknown", got.Status)
		}
	})
	t.Run("EFS", func(t *testing.T) {
		c := baseClients()
		c.EFS = fakeEFS{err: errAccessDenied{}}
		if got := onlyResult(t, runCheck(t, "aws-efs-encrypted", c)); got.Status != StatusUnknown {
			t.Errorf("status = %q, want unknown", got.Status)
		}
	})
}

// 資源が 0 件なら結果も 0 件。これは「完走した上で対象なし」なので、
// runOne 側で Completed に記録され、消えた資源の掃除が働く。
func TestStorageEncryptionEmptyIsNoResults(t *testing.T) {
	c := baseClients()
	c.RDS = fakeRDS{}
	c.EFS = fakeEFS{}
	if got := runCheck(t, "aws-rds-storage-encrypted", c); len(got) != 0 {
		t.Errorf("RDS: 結果が %d 件, want 0", len(got))
	}
	if got := runCheck(t, "aws-efs-encrypted", c); len(got) != 0 {
		t.Errorf("EFS: 結果が %d 件, want 0", len(got))
	}
}

// 是正手順に「作り直しが要る」ことが書かれていること。
// RDS も EFS も後から暗号化できないので、「設定を変えれば済む」と
// 誤解させると担当者が作業量を見誤る。
func TestStorageEncryptionRemediationMentionsRecreate(t *testing.T) {
	byID := ChecksByID()
	for _, id := range []string{"aws-rds-storage-encrypted", "aws-efs-encrypted"} {
		c, ok := byID[id]
		if !ok {
			t.Errorf("%s が Checks() に登録されていない", id)
			continue
		}
		if !strings.Contains(c.Remediation, "作成後に暗号化を有効にできません") {
			t.Errorf("%s の Remediation に作り直しが要ることが書かれていない: %s", id, c.Remediation)
		}
	}
}

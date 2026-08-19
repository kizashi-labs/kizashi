package awsscan

// 保管データの暗号化。RDS インスタンスと EFS ファイルシステム。
//
// どちらもリージョン単位で、資源 1 件につき 1 判定。EBS の既定暗号化
// (aws-ec2-ebs-default-encryption) が「これから作るものが暗号化されるか」を
// 見るのに対し、こちらは「既にある資源が暗号化されているか」を見る。
// 既定を有効にしても、それ以前に作った資源は暗号化されないので両方要る。
//
// 重要な性質: RDS も EFS も**作成後に暗号化を有効にできない**。是正は
// スナップショット/バックアップからの作り直しになるため、所見の重大度は
// high にし、Remediation にもその手順を書く。「設定を変えれば済む」と
// 誤解させると、担当者は実際の作業量を見誤る。

import (
	"context"
	"fmt"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/efs"
	"github.com/aws/aws-sdk-go-v2/service/rds"
	rdstypes "github.com/aws/aws-sdk-go-v2/service/rds/types"
)

func checkRDSEncryption() Check {
	const id = "aws-rds-storage-encrypted"
	return Check{
		ID:          id,
		Title:       "RDS インスタンスのストレージが暗号化されている",
		Description: "暗号化されていない DB は、スナップショットやバックアップが渡っただけで中身を読まれる。",
		Severity:    SeverityHigh,
		Scope:       ScopeRegion,
		Service:     "RDS",
		Frameworks:  []string{"CIS-AWS-2.3.1"},
		// 作成後に有効化できないことを明記する。設定変更で済むと誤解すると
		// 作業量の見積もりを誤る。
		Remediation: "RDS は作成後に暗号化を有効にできません。スナップショットを取り、暗号化を有効にしてコピーしてから復元し、接続先を切り替えてください。",
		Run: func(ctx context.Context, c *Clients) []Result {
			instances, err := allDBInstances(ctx, c)
			if err != nil {
				return unknownOne(id, c, "RDS インスタンス一覧の取得に失敗: "+err.Error())
			}
			var out []Result
			for _, db := range instances {
				name := aws.ToString(db.DBInstanceIdentifier)
				res := Result{
					CheckID: id, ResourceID: name, ResourceName: name,
					ResourceType: "AwsRdsDbInstance", Region: c.Region,
				}
				engine := aws.ToString(db.Engine)
				// StorageEncrypted が nil のときは「暗号化されていない」と
				// 断じない。AWS が返さない状況で fail を作ると、実在しない
				// 是正作業 (作り直し) を指示することになる。
				if db.StorageEncrypted == nil {
					res.Status = StatusUnknown
					res.Evidence = "StorageEncrypted が応答に含まれていません"
				} else if *db.StorageEncrypted {
					res.Status = StatusPass
					res.Evidence = fmt.Sprintf("ストレージは暗号化されています (%s)", engine)
				} else {
					res.Status = StatusFail
					res.Evidence = fmt.Sprintf("ストレージが暗号化されていません (%s)", engine)
				}
				out = append(out, res)
			}
			return out
		},
	}
}

// allDBInstances は全ページ取る。取りこぼすと
// 「見えていないインスタンスは問題なし」になる。
func allDBInstances(ctx context.Context, c *Clients) ([]rdstypes.DBInstance, error) {
	var out []rdstypes.DBInstance
	var marker *string
	for {
		page, err := c.RDS.DescribeDBInstances(ctx, &rds.DescribeDBInstancesInput{Marker: marker})
		if err != nil {
			return nil, err
		}
		out = append(out, page.DBInstances...)
		if page.Marker == nil || *page.Marker == "" {
			return out, nil
		}
		marker = page.Marker
	}
}

func checkEFSEncryption() Check {
	const id = "aws-efs-encrypted"
	return Check{
		ID:          id,
		Title:       "EFS ファイルシステムが暗号化されている",
		Description: "共有ファイルシステムは複数のホストから読まれるため、暗号化されていないと影響範囲が広い。",
		Severity:    SeverityHigh,
		Scope:       ScopeRegion,
		Service:     "EFS",
		Frameworks:  []string{"CIS-AWS-2.4.1"},
		Remediation: "EFS は作成後に暗号化を有効にできません。暗号化を有効にした新しいファイルシステムを作り、AWS DataSync 等で内容を移してからマウント先を切り替えてください。",
		Run: func(ctx context.Context, c *Clients) []Result {
			var out []Result
			var marker *string
			for {
				page, err := c.EFS.DescribeFileSystems(ctx, &efs.DescribeFileSystemsInput{Marker: marker})
				if err != nil {
					return unknownOne(id, c, "EFS ファイルシステム一覧の取得に失敗: "+err.Error())
				}
				for _, fs := range page.FileSystems {
					fsID := aws.ToString(fs.FileSystemId)
					// Name タグが無いファイルシステムは珍しくない。
					// その場合は ID を名前に使う (空欄だと一覧で識別できない)。
					name := aws.ToString(fs.Name)
					if name == "" {
						name = fsID
					}
					res := Result{
						CheckID: id, ResourceID: fsID, ResourceName: name,
						ResourceType: "AwsEfsFileSystem", Region: c.Region,
					}
					switch {
					case fs.Encrypted == nil:
						res.Status = StatusUnknown
						res.Evidence = "Encrypted が応答に含まれていません"
					case *fs.Encrypted:
						res.Status = StatusPass
						res.Evidence = "暗号化されています"
					default:
						res.Status = StatusFail
						res.Evidence = "暗号化されていません"
					}
					out = append(out, res)
				}
				if page.NextMarker == nil || *page.NextMarker == "" {
					return out
				}
				marker = page.NextMarker
			}
		},
	}
}

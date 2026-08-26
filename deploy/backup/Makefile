# EDR Platform — バックアップ操作 Makefile

DATABASE_URL   ?= postgresql://edr:edr@localhost:5432/edr
BACKUP_DEST    ?= local
RETENTION_DAYS ?= 30
BACKUP_DIR     ?= /var/backups/edr

# スクリプトに実行権限を付与するターゲット
SCRIPTS := backup.sh restore.sh cleanup.sh

.PHONY: all backup restore cleanup docker-backup docker-restore docker-cleanup \
        docker-scheduler chmod-scripts help

# ---------------------------------------------------------------------------
# デフォルトターゲット
# ---------------------------------------------------------------------------
all: help

# ---------------------------------------------------------------------------
# スクリプトに実行権限を付与
# ---------------------------------------------------------------------------
chmod-scripts:
	@chmod +x $(SCRIPTS)
	@echo "実行権限を付与しました: $(SCRIPTS)"

# ---------------------------------------------------------------------------
# ローカルバックアップ実行
# ---------------------------------------------------------------------------
backup: chmod-scripts
	DATABASE_URL=$(DATABASE_URL) \
	BACKUP_DEST=$(BACKUP_DEST) \
	BACKUP_DIR=$(BACKUP_DIR) \
	RETENTION_DAYS=$(RETENTION_DAYS) \
	./backup.sh

# ---------------------------------------------------------------------------
# バックアップのリストア
# 使用例: make restore FILE=/path/to/backup.dump.gz
#         make restore FILE=s3://bucket/key
#         make restore FILE=gs://bucket/key FORCE=--force
# ---------------------------------------------------------------------------
restore: chmod-scripts
	@if [ -z "$(FILE)" ]; then \
		echo "エラー: FILE が指定されていません。"; \
		echo "使用法: make restore FILE=<パスまたはs3://またはgs://URI>"; \
		exit 1; \
	fi
	DATABASE_URL=$(DATABASE_URL) \
	BACKUP_DIR=$(BACKUP_DIR) \
	./restore.sh $(FORCE) $(FILE)

# ---------------------------------------------------------------------------
# 古いバックアップのクリーンアップ
# 使用例: make cleanup
#         make cleanup DRY_RUN=--dry-run
# ---------------------------------------------------------------------------
cleanup: chmod-scripts
	BACKUP_DIR=$(BACKUP_DIR) \
	RETENTION_DAYS=$(RETENTION_DAYS) \
	./cleanup.sh $(DRY_RUN)

# ---------------------------------------------------------------------------
# Docker 経由でバックアップ実行
# ---------------------------------------------------------------------------
docker-backup:
	docker compose \
		-f docker-compose.backup.yml \
		--profile backup \
		run --rm backup

# ---------------------------------------------------------------------------
# Docker 経由でリストア実行
# 使用例: make docker-restore FILE=edr_backup_20260101_120000.dump.gz
# ---------------------------------------------------------------------------
docker-restore:
	@if [ -z "$(FILE)" ]; then \
		echo "エラー: FILE が指定されていません。"; \
		echo "使用法: make docker-restore FILE=<ファイル名>"; \
		exit 1; \
	fi
	docker compose \
		-f docker-compose.backup.yml \
		--profile restore \
		run --rm restore /restore.sh $(FORCE) /backups/$(FILE)

# ---------------------------------------------------------------------------
# Docker 経由でクリーンアップ実行
# ---------------------------------------------------------------------------
docker-cleanup:
	docker compose \
		-f docker-compose.backup.yml \
		--profile cleanup \
		run --rm cleanup

# ---------------------------------------------------------------------------
# バックアップスケジューラ起動 (ofelia)
# ---------------------------------------------------------------------------
docker-scheduler:
	docker compose \
		-f docker-compose.backup.yml \
		--profile backup-scheduler \
		up -d backup-scheduler
	@echo "バックアップスケジューラを起動しました。"
	@echo "ログ確認: docker compose -f docker-compose.backup.yml logs -f backup-scheduler"

# ---------------------------------------------------------------------------
# バックアップスケジューラ停止
# ---------------------------------------------------------------------------
docker-scheduler-stop:
	docker compose \
		-f docker-compose.backup.yml \
		--profile backup-scheduler \
		down
	@echo "バックアップスケジューラを停止しました。"

# ---------------------------------------------------------------------------
# バックアップボリュームの一覧表示
# ---------------------------------------------------------------------------
list-backups:
	@echo "=== ローカルバックアップ一覧 ==="
	@if [ -d "$(BACKUP_DIR)" ]; then \
		ls -lh $(BACKUP_DIR)/edr_backup_*.dump.gz 2>/dev/null \
			|| echo "バックアップファイルが見つかりません: $(BACKUP_DIR)"; \
	else \
		echo "バックアップディレクトリが存在しません: $(BACKUP_DIR)"; \
	fi

# ---------------------------------------------------------------------------
# ヘルプ
# ---------------------------------------------------------------------------
help:
	@echo ""
	@echo "EDR Platform — バックアップ操作"
	@echo ""
	@echo "使用法: make <ターゲット> [変数=値 ...]"
	@echo ""
	@echo "ターゲット:"
	@echo "  backup                  ローカルで pg_dump を実行"
	@echo "  restore FILE=<path>     バックアップをリストア"
	@echo "  cleanup                 古いバックアップを削除"
	@echo "  docker-backup           Docker 経由でバックアップ実行"
	@echo "  docker-restore FILE=<f> Docker 経由でリストア実行"
	@echo "  docker-cleanup          Docker 経由でクリーンアップ実行"
	@echo "  docker-scheduler        ofelia スケジューラを起動"
	@echo "  docker-scheduler-stop   ofelia スケジューラを停止"
	@echo "  list-backups            バックアップファイルを一覧表示"
	@echo "  chmod-scripts           スクリプトに実行権限を付与"
	@echo ""
	@echo "変数 (デフォルト値):"
	@echo "  DATABASE_URL   = $(DATABASE_URL)"
	@echo "  BACKUP_DEST    = $(BACKUP_DEST)   (local|s3|gcs)"
	@echo "  BACKUP_DIR     = $(BACKUP_DIR)"
	@echo "  RETENTION_DAYS = $(RETENTION_DAYS)"
	@echo "  FILE           = (リストア時に必須)"
	@echo "  FORCE          = (--force でプロンプトをスキップ)"
	@echo "  DRY_RUN        = (--dry-run でクリーンアップのドライラン)"
	@echo ""
	@echo "例:"
	@echo "  make backup DATABASE_URL=postgresql://user:pass@host/db"
	@echo "  make backup BACKUP_DEST=s3 S3_BUCKET=my-bucket"
	@echo "  make restore FILE=/var/backups/edr/edr_backup_20260101_120000.dump.gz"
	@echo "  make restore FILE=s3://my-bucket/edr-backups/edr_backup_20260101_120000.dump.gz"
	@echo "  make cleanup DRY_RUN=--dry-run"
	@echo "  make docker-backup"
	@echo ""

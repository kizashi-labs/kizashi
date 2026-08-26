#!/usr/bin/env bash
# EDR Platform — PostgreSQL Backup Script
# 使用法: ./backup.sh [--s3|--gcs|--local]
# 環境変数:
#   DATABASE_URL         PostgreSQL接続URL (必須)
#   BACKUP_DEST          バックアップ保存先: local|s3|gcs (デフォルト: local)
#   BACKUP_DIR           ローカル保存ディレクトリ (デフォルト: /var/backups/edr)
#   S3_BUCKET            S3バケット名 (s3使用時)
#   S3_PREFIX            S3プレフィックス (デフォルト: edr-backups)
#   GCS_BUCKET           GCSバケット名 (gcs使用時)
#   RETENTION_DAYS       保持日数 (デフォルト: 30)

set -euo pipefail

# ---------------------------------------------------------------------------
# 定数 / デフォルト値
# ---------------------------------------------------------------------------
BACKUP_DEST="${BACKUP_DEST:-local}"
BACKUP_DIR="${BACKUP_DIR:-/var/backups/edr}"
S3_PREFIX="${S3_PREFIX:-edr-backups}"
RETENTION_DAYS="${RETENTION_DAYS:-30}"
TIMESTAMP="$(date +%Y%m%d_%H%M%S)"
BACKUP_FILENAME="edr_backup_${TIMESTAMP}.dump.gz"
CHECKSUM_FILENAME="${BACKUP_FILENAME}.sha256"
LOG_PREFIX="[$(date '+%Y-%m-%d %H:%M:%S')] [backup]"

# ---------------------------------------------------------------------------
# ヘルパー関数
# ---------------------------------------------------------------------------
log_info()  { echo "${LOG_PREFIX} [INFO]  $*"; }
log_error() { echo "${LOG_PREFIX} [ERROR] $*" >&2; }

die() {
    log_error "$*"
    exit 1
}

usage() {
    cat <<EOF
使用法: $(basename "$0") [--s3|--gcs|--local]

オプション:
  --s3      S3 へアップロード (S3_BUCKET 必須)
  --gcs     GCS へアップロード (GCS_BUCKET 必須)
  --local   ローカル保存のみ (デフォルト)

環境変数:
  DATABASE_URL     PostgreSQL接続URL (必須)
  BACKUP_DEST      バックアップ保存先: local|s3|gcs
  BACKUP_DIR       ローカル保存ディレクトリ (デフォルト: /var/backups/edr)
  S3_BUCKET        S3バケット名
  S3_PREFIX        S3プレフィックス (デフォルト: edr-backups)
  GCS_BUCKET       GCSバケット名
  RETENTION_DAYS   保持日数 (デフォルト: 30)
EOF
    exit 0
}

# ---------------------------------------------------------------------------
# 引数解析
# ---------------------------------------------------------------------------
while [[ $# -gt 0 ]]; do
    case "$1" in
        --s3)    BACKUP_DEST="s3";    shift ;;
        --gcs)   BACKUP_DEST="gcs";   shift ;;
        --local) BACKUP_DEST="local"; shift ;;
        --help|-h) usage ;;
        *) die "不明なオプション: $1" ;;
    esac
done

# ---------------------------------------------------------------------------
# 前提条件チェック
# ---------------------------------------------------------------------------
check_prerequisites() {
    log_info "前提条件を確認中..."

    [[ -z "${DATABASE_URL:-}" ]] && die "DATABASE_URL が設定されていません。"

    if ! command -v pg_dump &>/dev/null; then
        die "pg_dump が見つかりません。PostgreSQL クライアントをインストールしてください。"
    fi

    if ! command -v gzip &>/dev/null; then
        die "gzip が見つかりません。"
    fi

    if ! command -v sha256sum &>/dev/null && ! command -v shasum &>/dev/null; then
        die "sha256sum / shasum が見つかりません。"
    fi

    case "${BACKUP_DEST}" in
        s3)
            [[ -z "${S3_BUCKET:-}" ]] && die "S3_BUCKET が設定されていません。"
            command -v aws &>/dev/null || die "AWS CLI が見つかりません。"
            ;;
        gcs)
            [[ -z "${GCS_BUCKET:-}" ]] && die "GCS_BUCKET が設定されていません。"
            command -v gsutil &>/dev/null || die "gsutil が見つかりません。"
            ;;
        local) ;;
        *) die "BACKUP_DEST の値が無効です: ${BACKUP_DEST} (local|s3|gcs)" ;;
    esac

    log_info "前提条件チェック完了。"
}

# ---------------------------------------------------------------------------
# ローカルバックアップディレクトリ準備
# ---------------------------------------------------------------------------
prepare_local_dir() {
    if [[ ! -d "${BACKUP_DIR}" ]]; then
        log_info "バックアップディレクトリを作成: ${BACKUP_DIR}"
        mkdir -p "${BACKUP_DIR}" || die "ディレクトリの作成に失敗: ${BACKUP_DIR}"
    fi
}

# ---------------------------------------------------------------------------
# SHA-256 チェックサム生成
# ---------------------------------------------------------------------------
generate_checksum() {
    local file="$1"
    local checksum_file="${file}.sha256"

    log_info "チェックサムを生成: ${checksum_file}"

    if command -v sha256sum &>/dev/null; then
        sha256sum "${file}" > "${checksum_file}"
    else
        # macOS の shasum
        shasum -a 256 "${file}" > "${checksum_file}"
    fi

    log_info "チェックサム: $(cat "${checksum_file}")"
}

# ---------------------------------------------------------------------------
# pg_dump 実行 (--format=custom + gzip)
# ---------------------------------------------------------------------------
run_pg_dump() {
    local output_path="${BACKUP_DIR}/${BACKUP_FILENAME}"

    log_info "pg_dump を開始: ${output_path}"
    log_info "バックアップ保存先: ${BACKUP_DEST}"
    log_info "保持日数: ${RETENTION_DAYS} 日"

    # pg_dump --format=custom の出力を gzip で圧縮
    if pg_dump --format=custom --no-password "${DATABASE_URL}" \
        | gzip -9 > "${output_path}"; then
        log_info "pg_dump 完了: ${output_path} ($(du -sh "${output_path}" | cut -f1))"
    else
        # 不完全なファイルを削除
        rm -f "${output_path}"
        die "pg_dump が失敗しました。"
    fi

    generate_checksum "${output_path}"

    echo "${output_path}"
}

# ---------------------------------------------------------------------------
# S3 アップロード
# ---------------------------------------------------------------------------
upload_to_s3() {
    local local_file="$1"
    local filename
    filename="$(basename "${local_file}")"
    local s3_key="${S3_PREFIX}/${filename}"
    local s3_uri="s3://${S3_BUCKET}/${s3_key}"

    log_info "S3 へアップロード: ${s3_uri}"
    aws s3 cp "${local_file}" "${s3_uri}" \
        || die "S3 へのアップロードに失敗: ${s3_uri}"
    log_info "S3 アップロード完了: ${s3_uri}"

    # チェックサムファイルもアップロード
    local checksum_file="${local_file}.sha256"
    if [[ -f "${checksum_file}" ]]; then
        local checksum_s3_uri="s3://${S3_BUCKET}/${s3_key}.sha256"
        log_info "チェックサムを S3 へアップロード: ${checksum_s3_uri}"
        aws s3 cp "${checksum_file}" "${checksum_s3_uri}" \
            || log_error "チェックサムの S3 アップロードに失敗 (継続します)"
    fi
}

# ---------------------------------------------------------------------------
# GCS アップロード
# ---------------------------------------------------------------------------
upload_to_gcs() {
    local local_file="$1"
    local filename
    filename="$(basename "${local_file}")"
    local gcs_uri="gs://${GCS_BUCKET}/edr-backups/${filename}"

    log_info "GCS へアップロード: ${gcs_uri}"
    gsutil cp "${local_file}" "${gcs_uri}" \
        || die "GCS へのアップロードに失敗: ${gcs_uri}"
    log_info "GCS アップロード完了: ${gcs_uri}"

    # チェックサムファイルもアップロード
    local checksum_file="${local_file}.sha256"
    if [[ -f "${checksum_file}" ]]; then
        local checksum_gcs_uri="${gcs_uri}.sha256"
        log_info "チェックサムを GCS へアップロード: ${checksum_gcs_uri}"
        gsutil cp "${checksum_file}" "${checksum_gcs_uri}" \
            || log_error "チェックサムの GCS アップロードに失敗 (継続します)"
    fi
}

# ---------------------------------------------------------------------------
# 古いローカルバックアップを削除
# ---------------------------------------------------------------------------
cleanup_old_backups() {
    log_info "ローカルの古いバックアップを削除 (${RETENTION_DAYS} 日以上前)..."

    local deleted=0
    while IFS= read -r -d '' old_file; do
        log_info "削除: ${old_file}"
        rm -f "${old_file}"
        ((deleted++)) || true
    done < <(find "${BACKUP_DIR}" \
        -maxdepth 1 \
        -name 'edr_backup_*.dump.gz' \
        -mtime "+${RETENTION_DAYS}" \
        -print0 2>/dev/null)

    # 対応するチェックサムファイルも削除
    while IFS= read -r -d '' old_checksum; do
        log_info "削除 (checksum): ${old_checksum}"
        rm -f "${old_checksum}"
    done < <(find "${BACKUP_DIR}" \
        -maxdepth 1 \
        -name 'edr_backup_*.dump.gz.sha256' \
        -mtime "+${RETENTION_DAYS}" \
        -print0 2>/dev/null)

    log_info "古いバックアップ削除完了: ${deleted} ファイル削除"
}

# ---------------------------------------------------------------------------
# メイン処理
# ---------------------------------------------------------------------------
main() {
    log_info "=========================================="
    log_info "EDR Platform PostgreSQL バックアップ開始"
    log_info "=========================================="

    check_prerequisites
    prepare_local_dir

    # バックアップ実行
    local backup_file
    backup_file="$(run_pg_dump)"

    # クラウドへのアップロード
    case "${BACKUP_DEST}" in
        s3)    upload_to_s3 "${backup_file}" ;;
        gcs)   upload_to_gcs "${backup_file}" ;;
        local) log_info "ローカル保存のみ: ${backup_file}" ;;
    esac

    # 古いバックアップの削除
    cleanup_old_backups

    log_info "=========================================="
    log_info "バックアップ正常完了"
    log_info "  ファイル : ${backup_file}"
    log_info "  保存先   : ${BACKUP_DEST}"
    log_info "=========================================="
    exit 0
}

main "$@"

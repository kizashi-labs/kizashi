#!/usr/bin/env bash
# EDR Platform — PostgreSQL Restore Script
# 使用法: ./restore.sh [--force] <backup_file>
#   backup_file: ローカルパスまたは s3://bucket/key または gs://bucket/key
# 環境変数:
#   DATABASE_URL   PostgreSQL接続URL (必須)
#   BACKUP_DIR     ダウンロード先ディレクトリ (デフォルト: /tmp/edr-restore)

set -euo pipefail

# ---------------------------------------------------------------------------
# 定数 / デフォルト値
# ---------------------------------------------------------------------------
BACKUP_DIR="${BACKUP_DIR:-/tmp/edr-restore}"
LOG_PREFIX="[$(date '+%Y-%m-%d %H:%M:%S')] [restore]"
FORCE=false
BACKUP_SOURCE=""

# ---------------------------------------------------------------------------
# ヘルパー関数
# ---------------------------------------------------------------------------
log_info()  { echo "${LOG_PREFIX} [INFO]  $*"; }
log_warn()  { echo "${LOG_PREFIX} [WARN]  $*"; }
log_error() { echo "${LOG_PREFIX} [ERROR] $*" >&2; }

die() {
    log_error "$*"
    exit 1
}

usage() {
    cat <<EOF
使用法: $(basename "$0") [--force] <backup_file>

引数:
  backup_file   ローカルファイルパス、s3://bucket/key、または gs://bucket/key

オプション:
  --force       確認プロンプトをスキップして自動的に復元を実行
  --help, -h    このヘルプを表示

環境変数:
  DATABASE_URL   PostgreSQL接続URL (必須)
  BACKUP_DIR     ダウンロード先ディレクトリ (デフォルト: /tmp/edr-restore)

例:
  ./restore.sh /var/backups/edr/edr_backup_20260101_120000.dump.gz
  ./restore.sh s3://my-bucket/edr-backups/edr_backup_20260101_120000.dump.gz
  ./restore.sh --force gs://my-gcs-bucket/edr-backups/edr_backup_20260101_120000.dump.gz
EOF
    exit 0
}

# ---------------------------------------------------------------------------
# 引数解析
# ---------------------------------------------------------------------------
while [[ $# -gt 0 ]]; do
    case "$1" in
        --force)   FORCE=true;  shift ;;
        --help|-h) usage ;;
        -*)        die "不明なオプション: $1" ;;
        *)
            if [[ -z "${BACKUP_SOURCE}" ]]; then
                BACKUP_SOURCE="$1"
                shift
            else
                die "引数が多すぎます: $1"
            fi
            ;;
    esac
done

[[ -z "${BACKUP_SOURCE}" ]] && { log_error "backup_file が指定されていません。"; usage; }

# ---------------------------------------------------------------------------
# 前提条件チェック
# ---------------------------------------------------------------------------
check_prerequisites() {
    log_info "前提条件を確認中..."

    [[ -z "${DATABASE_URL:-}" ]] && die "DATABASE_URL が設定されていません。"

    if ! command -v pg_restore &>/dev/null; then
        die "pg_restore が見つかりません。PostgreSQL クライアントをインストールしてください。"
    fi

    if ! command -v gunzip &>/dev/null; then
        die "gunzip が見つかりません。"
    fi

    # S3 / GCS ツールチェック
    case "${BACKUP_SOURCE}" in
        s3://*)
            command -v aws &>/dev/null || die "AWS CLI が見つかりません。"
            ;;
        gs://*)
            command -v gsutil &>/dev/null || die "gsutil が見つかりません。"
            ;;
    esac

    log_info "前提条件チェック完了。"
}

# ---------------------------------------------------------------------------
# S3 からダウンロード
# ---------------------------------------------------------------------------
download_from_s3() {
    local s3_uri="$1"
    local dest_dir="$2"
    local filename
    filename="$(basename "${s3_uri%%\?*}")"
    local local_path="${dest_dir}/${filename}"

    log_info "S3 からダウンロード: ${s3_uri}"
    aws s3 cp "${s3_uri}" "${local_path}" \
        || die "S3 からのダウンロードに失敗: ${s3_uri}"
    log_info "ダウンロード完了: ${local_path}"

    # チェックサムファイルのダウンロードを試みる (なければスキップ)
    local checksum_uri="${s3_uri}.sha256"
    local checksum_local="${local_path}.sha256"
    if aws s3 cp "${checksum_uri}" "${checksum_local}" &>/dev/null; then
        log_info "チェックサムファイルもダウンロードしました: ${checksum_local}"
    else
        log_warn "チェックサムファイルが見つかりません (スキップ): ${checksum_uri}"
    fi

    echo "${local_path}"
}

# ---------------------------------------------------------------------------
# GCS からダウンロード
# ---------------------------------------------------------------------------
download_from_gcs() {
    local gcs_uri="$1"
    local dest_dir="$2"
    local filename
    filename="$(basename "${gcs_uri}")"
    local local_path="${dest_dir}/${filename}"

    log_info "GCS からダウンロード: ${gcs_uri}"
    gsutil cp "${gcs_uri}" "${local_path}" \
        || die "GCS からのダウンロードに失敗: ${gcs_uri}"
    log_info "ダウンロード完了: ${local_path}"

    # チェックサムファイルのダウンロードを試みる (なければスキップ)
    local checksum_uri="${gcs_uri}.sha256"
    local checksum_local="${local_path}.sha256"
    if gsutil cp "${checksum_uri}" "${checksum_local}" &>/dev/null; then
        log_info "チェックサムファイルもダウンロードしました: ${checksum_local}"
    else
        log_warn "チェックサムファイルが見つかりません (スキップ): ${checksum_uri}"
    fi

    echo "${local_path}"
}

# ---------------------------------------------------------------------------
# SHA-256 チェックサム検証
# ---------------------------------------------------------------------------
verify_checksum() {
    local backup_file="$1"
    local checksum_file="${backup_file}.sha256"

    if [[ ! -f "${checksum_file}" ]]; then
        log_warn "チェックサムファイルが存在しません。検証をスキップします: ${checksum_file}"
        return 0
    fi

    log_info "チェックサムを検証中: ${checksum_file}"

    local verify_result=0
    if command -v sha256sum &>/dev/null; then
        sha256sum --check "${checksum_file}" || verify_result=$?
    else
        # macOS の shasum
        shasum -a 256 --check "${checksum_file}" || verify_result=$?
    fi

    if [[ "${verify_result}" -ne 0 ]]; then
        die "チェックサム検証に失敗しました。バックアップファイルが破損している可能性があります。"
    fi

    log_info "チェックサム検証OK。"
}

# ---------------------------------------------------------------------------
# データベース情報を DATABASE_URL から取得
# ---------------------------------------------------------------------------
parse_database_url() {
    # postgresql://user:pass@host:port/dbname
    local url="${DATABASE_URL}"
    # dbname: URL の最後のパスコンポーネント
    DB_NAME="$(echo "${url}" | sed 's|.*://[^/]*/||' | sed 's|[?#].*||')"
    DB_HOST="$(echo "${url}" | sed 's|.*@||' | sed 's|:.*||' | sed 's|/.*||')"
    DB_PORT="$(echo "${url}" | sed 's|.*@[^:]*:||' | sed 's|/.*||')"
    DB_USER="$(echo "${url}" | sed 's|.*://||' | sed 's|:.*||')"

    # ポートが含まれない場合のデフォルト
    if [[ "${DB_PORT}" == "${DB_NAME}" ]] || [[ -z "${DB_PORT}" ]]; then
        DB_PORT="5432"
    fi
}

# ---------------------------------------------------------------------------
# 既存 DB の確認プロンプト
# ---------------------------------------------------------------------------
confirm_restore() {
    parse_database_url

    log_warn "=========================================="
    log_warn "警告: 既存のデータベースにリストアします"
    log_warn "  データベース : ${DB_NAME}"
    log_warn "  ホスト       : ${DB_HOST}:${DB_PORT}"
    log_warn "  ユーザー     : ${DB_USER}"
    log_warn "  バックアップ : ${BACKUP_SOURCE}"
    log_warn "=========================================="

    if [[ "${FORCE}" == "true" ]]; then
        log_info "--force フラグが指定されているため、自動的に続行します。"
        return 0
    fi

    echo ""
    read -r -p "本当に続行しますか？ [yes/N]: " answer
    case "${answer}" in
        yes|YES) log_info "ユーザーが承認しました。続行します。" ;;
        *)        die "ユーザーによってキャンセルされました。" ;;
    esac
}

# ---------------------------------------------------------------------------
# pg_restore 実行
# ---------------------------------------------------------------------------
run_pg_restore() {
    local local_file="$1"

    log_info "gzip を展開して pg_restore を実行中..."
    log_info "バックアップファイル: ${local_file}"

    # gzip 展開しながら pg_restore へパイプ
    if gunzip -c "${local_file}" \
        | pg_restore \
            --no-password \
            --clean \
            --if-exists \
            --no-owner \
            --no-privileges \
            --dbname="${DATABASE_URL}" \
            --verbose 2>&1 | while IFS= read -r line; do
                log_info "pg_restore: ${line}"
            done; then
        log_info "pg_restore 完了。"
    else
        # pg_restore は警告でも非ゼロを返すことがある
        log_warn "pg_restore が非ゼロで終了しました。ログを確認してください。"
    fi
}

# ---------------------------------------------------------------------------
# 一時ダウンロードディレクトリのクリーンアップ
# ---------------------------------------------------------------------------
cleanup_temp() {
    local temp_dir="$1"
    if [[ "${temp_dir}" == /tmp/* ]]; then
        log_info "一時ディレクトリを削除: ${temp_dir}"
        rm -rf "${temp_dir}"
    fi
}

# ---------------------------------------------------------------------------
# メイン処理
# ---------------------------------------------------------------------------
main() {
    log_info "=========================================="
    log_info "EDR Platform PostgreSQL リストア開始"
    log_info "=========================================="

    check_prerequisites

    local local_backup_file=""
    local temp_dir=""

    # ソースに応じてダウンロードまたはローカルファイルを使用
    case "${BACKUP_SOURCE}" in
        s3://*)
            temp_dir="${BACKUP_DIR}/tmp_$$"
            mkdir -p "${temp_dir}"
            local_backup_file="$(download_from_s3 "${BACKUP_SOURCE}" "${temp_dir}")"
            ;;
        gs://*)
            temp_dir="${BACKUP_DIR}/tmp_$$"
            mkdir -p "${temp_dir}"
            local_backup_file="$(download_from_gcs "${BACKUP_SOURCE}" "${temp_dir}")"
            ;;
        *)
            local_backup_file="${BACKUP_SOURCE}"
            [[ -f "${local_backup_file}" ]] \
                || die "バックアップファイルが見つかりません: ${local_backup_file}"
            ;;
    esac

    # チェックサム検証
    verify_checksum "${local_backup_file}"

    # 確認プロンプト
    confirm_restore

    # リストア実行
    run_pg_restore "${local_backup_file}"

    # 一時ファイルのクリーンアップ
    if [[ -n "${temp_dir}" ]]; then
        cleanup_temp "${temp_dir}"
    fi

    log_info "=========================================="
    log_info "リストア正常完了"
    log_info "  ソース     : ${BACKUP_SOURCE}"
    log_info "=========================================="
    exit 0
}

main "$@"

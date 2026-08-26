#!/usr/bin/env bash
# EDR Platform — バックアップクリーンアップスクリプト
# 古いバックアップファイルのクリーンアップ
# 環境変数:
#   BACKUP_DIR       クリーンアップ対象ディレクトリ (デフォルト: /var/backups/edr)
#   RETENTION_DAYS   保持日数 (デフォルト: 30)

set -euo pipefail

# ---------------------------------------------------------------------------
# 定数 / デフォルト値
# ---------------------------------------------------------------------------
BACKUP_DIR="${BACKUP_DIR:-/var/backups/edr}"
RETENTION_DAYS="${RETENTION_DAYS:-30}"
LOG_PREFIX="[$(date '+%Y-%m-%d %H:%M:%S')] [cleanup]"

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
使用法: $(basename "$0") [--dry-run]

オプション:
  --dry-run    実際には削除せず、削除対象ファイルのみ表示
  --help, -h   このヘルプを表示

環境変数:
  BACKUP_DIR       クリーンアップ対象ディレクトリ (デフォルト: /var/backups/edr)
  RETENTION_DAYS   保持日数 (デフォルト: 30)
EOF
    exit 0
}

# ---------------------------------------------------------------------------
# 引数解析
# ---------------------------------------------------------------------------
DRY_RUN=false
while [[ $# -gt 0 ]]; do
    case "$1" in
        --dry-run) DRY_RUN=true; shift ;;
        --help|-h) usage ;;
        *) die "不明なオプション: $1" ;;
    esac
done

# ---------------------------------------------------------------------------
# 前提条件チェック
# ---------------------------------------------------------------------------
check_prerequisites() {
    if [[ ! -d "${BACKUP_DIR}" ]]; then
        log_warn "バックアップディレクトリが存在しません: ${BACKUP_DIR}"
        log_info "クリーンアップする対象がないため終了します。"
        exit 0
    fi

    if ! [[ "${RETENTION_DAYS}" =~ ^[0-9]+$ ]]; then
        die "RETENTION_DAYS は正の整数でなければなりません: ${RETENTION_DAYS}"
    fi
}

# ---------------------------------------------------------------------------
# ファイルサイズ取得 (クロスプラットフォーム対応)
# ---------------------------------------------------------------------------
get_file_size() {
    local file="$1"
    if command -v du &>/dev/null; then
        du -sh "${file}" 2>/dev/null | cut -f1
    else
        echo "不明"
    fi
}

# ---------------------------------------------------------------------------
# 古いバックアップダンプファイルの削除
# ---------------------------------------------------------------------------
cleanup_dump_files() {
    local deleted_count=0
    local deleted_size_total=0
    local skipped_count=0

    log_info "バックアップダンプファイルをスキャン中..."
    log_info "  対象ディレクトリ : ${BACKUP_DIR}"
    log_info "  保持日数         : ${RETENTION_DAYS} 日"
    log_info "  ドライラン       : ${DRY_RUN}"

    # .dump.gz ファイルを検索
    while IFS= read -r -d '' old_file; do
        local file_size
        file_size="$(get_file_size "${old_file}")"
        local mod_time
        mod_time="$(date -r "${old_file}" '+%Y-%m-%d %H:%M:%S' 2>/dev/null || stat -c '%y' "${old_file}" 2>/dev/null | cut -d'.' -f1 || echo '不明')"

        if [[ "${DRY_RUN}" == "true" ]]; then
            log_info "[DRY-RUN] 削除対象: ${old_file} (サイズ: ${file_size}, 更新日時: ${mod_time})"
            ((skipped_count++)) || true
        else
            log_info "削除: ${old_file} (サイズ: ${file_size}, 更新日時: ${mod_time})"
            rm -f "${old_file}"
            ((deleted_count++)) || true
        fi
    done < <(find "${BACKUP_DIR}" \
        -maxdepth 1 \
        -name 'edr_backup_*.dump.gz' \
        -mtime "+${RETENTION_DAYS}" \
        -print0 2>/dev/null)

    echo "${deleted_count}:${skipped_count}"
}

# ---------------------------------------------------------------------------
# 古いチェックサムファイルの削除
# ---------------------------------------------------------------------------
cleanup_checksum_files() {
    local deleted_count=0
    local skipped_count=0

    log_info "チェックサムファイルをスキャン中..."

    while IFS= read -r -d '' old_checksum; do
        if [[ "${DRY_RUN}" == "true" ]]; then
            log_info "[DRY-RUN] 削除対象 (checksum): ${old_checksum}"
            ((skipped_count++)) || true
        else
            log_info "削除 (checksum): ${old_checksum}"
            rm -f "${old_checksum}"
            ((deleted_count++)) || true
        fi
    done < <(find "${BACKUP_DIR}" \
        -maxdepth 1 \
        -name 'edr_backup_*.dump.gz.sha256' \
        -mtime "+${RETENTION_DAYS}" \
        -print0 2>/dev/null)

    echo "${deleted_count}:${skipped_count}"
}

# ---------------------------------------------------------------------------
# 孤立したチェックサムファイルの削除
# (対応する .dump.gz が存在しない .sha256 ファイル)
# ---------------------------------------------------------------------------
cleanup_orphaned_checksums() {
    local deleted_count=0

    log_info "孤立したチェックサムファイルをスキャン中..."

    while IFS= read -r checksum_file; do
        local dump_file="${checksum_file%.sha256}"
        if [[ ! -f "${dump_file}" ]]; then
            if [[ "${DRY_RUN}" == "true" ]]; then
                log_info "[DRY-RUN] 孤立ファイル削除対象: ${checksum_file}"
            else
                log_info "孤立ファイル削除: ${checksum_file}"
                rm -f "${checksum_file}"
                ((deleted_count++)) || true
            fi
        fi
    done < <(find "${BACKUP_DIR}" \
        -maxdepth 1 \
        -name 'edr_backup_*.dump.gz.sha256' \
        2>/dev/null)

    echo "${deleted_count}"
}

# ---------------------------------------------------------------------------
# ディレクトリ使用状況の表示
# ---------------------------------------------------------------------------
show_disk_usage() {
    log_info "現在のバックアップディレクトリ使用状況:"

    local total_files
    total_files="$(find "${BACKUP_DIR}" -maxdepth 1 -name 'edr_backup_*.dump.gz' 2>/dev/null | wc -l | tr -d ' ')"

    local total_size
    if [[ "${total_files}" -gt 0 ]]; then
        total_size="$(du -sh "${BACKUP_DIR}" 2>/dev/null | cut -f1 || echo '不明')"
    else
        total_size="0"
    fi

    log_info "  残存バックアップ数 : ${total_files} ファイル"
    log_info "  ディレクトリサイズ : ${total_size}"
}

# ---------------------------------------------------------------------------
# メイン処理
# ---------------------------------------------------------------------------
main() {
    log_info "=========================================="
    log_info "EDR Platform バックアップクリーンアップ開始"
    log_info "=========================================="

    check_prerequisites

    # ダンプファイルのクリーンアップ
    local dump_result
    dump_result="$(cleanup_dump_files)"
    local dump_deleted="${dump_result%%:*}"
    local dump_skipped="${dump_result##*:}"

    # チェックサムファイルのクリーンアップ
    local checksum_result
    checksum_result="$(cleanup_checksum_files)"
    local checksum_deleted="${checksum_result%%:*}"

    # 孤立チェックサムのクリーンアップ
    local orphan_deleted
    orphan_deleted="$(cleanup_orphaned_checksums)"

    # ディスク使用状況表示
    show_disk_usage

    log_info "=========================================="
    if [[ "${DRY_RUN}" == "true" ]]; then
        log_info "ドライラン完了 (実際の削除は行われていません)"
        log_info "  削除対象ダンプファイル     : ${dump_skipped} ファイル"
        log_info "  削除対象チェックサムファイル : ${checksum_deleted} ファイル"
    else
        local total_deleted=$(( dump_deleted + checksum_deleted + orphan_deleted ))
        log_info "クリーンアップ完了"
        log_info "  削除したダンプファイル     : ${dump_deleted} ファイル"
        log_info "  削除したチェックサムファイル : ${checksum_deleted} ファイル"
        log_info "  削除した孤立ファイル        : ${orphan_deleted} ファイル"
        log_info "  合計削除ファイル数          : ${total_deleted} ファイル"
    fi
    log_info "=========================================="
    exit 0
}

main "$@"

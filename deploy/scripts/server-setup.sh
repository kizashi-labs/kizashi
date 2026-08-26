#!/bin/bash
# EDR Platform サーバーセットアップスクリプト
# 使用方法: curl -fsSL https://raw.githubusercontent.com/.../server-setup.sh | bash

set -euo pipefail

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; CYAN='\033[0;36m'; NC='\033[0m'
info()    { echo -e "${GREEN}[INFO]${NC} $*"; }
warn()    { echo -e "${YELLOW}[WARN]${NC} $*"; }
section() { echo -e "\n${CYAN}═══ $* ═══${NC}"; }
error()   { echo -e "${RED}[ERROR]${NC} $*"; exit 1; }

[[ $EUID -ne 0 ]] && error "root権限が必要です"

section "EDR Platform サーバーセットアップ"

# ─── Collect Configuration ────────────────────────────────────
read -rp "ドメイン名 (例: edr.company.com): " EDR_DOMAIN
read -rp "管理者メールアドレス: " ADMIN_EMAIL
read -rsp "管理者パスワード: " ADMIN_PASSWORD; echo
read -rsp "Anthropic Claude API Key: " CLAUDE_API_KEY; echo

# Generate secrets
POSTGRES_PASSWORD=$(openssl rand -base64 32 | tr -d '+/=' | head -c 32)
REDIS_PASSWORD=$(openssl rand -base64 24 | tr -d '+/=' | head -c 24)
JWT_SECRET=$(openssl rand -base64 64 | tr -d '+/=\n' | head -c 64)
NEXTAUTH_SECRET=$(openssl rand -base64 32 | tr -d '+/=' | head -c 32)
ENROLL_TOKEN=$(openssl rand -hex 32)

# ─── Install Docker ───────────────────────────────────────────
section "Dockerをインストール中"
if ! command -v docker &>/dev/null; then
    curl -fsSL https://get.docker.com | sh
    systemctl enable --now docker
    info "Dockerをインストールしました"
else
    info "Dockerは既にインストールされています"
fi

if ! command -v docker-compose &>/dev/null; then
    curl -fsSL "https://github.com/docker/compose/releases/latest/download/docker-compose-$(uname -s)-$(uname -m)" \
        -o /usr/local/bin/docker-compose
    chmod +x /usr/local/bin/docker-compose
fi

# ─── Clone Repository ─────────────────────────────────────────
section "EDR Platformをダウンロード中"
INSTALL_DIR="/opt/edr-platform"

if [[ -d "$INSTALL_DIR" ]]; then
    warn "$INSTALL_DIR は既に存在します。更新します..."
    cd "$INSTALL_DIR" && git pull
else
    git clone https://github.com/edr-platform/edr-platform.git "$INSTALL_DIR"
    cd "$INSTALL_DIR"
fi

# ─── Generate TLS Certificates ────────────────────────────────
section "TLS証明書を生成中"
mkdir -p "$INSTALL_DIR/certs"

# CA certificate (used for agent mTLS)
openssl genrsa -out "$INSTALL_DIR/certs/ca.key" 4096 2>/dev/null
openssl req -new -x509 -days 3650 -key "$INSTALL_DIR/certs/ca.key" \
    -out "$INSTALL_DIR/certs/ca.crt" \
    -subj "/CN=EDR-Platform-CA/O=EDR Platform" 2>/dev/null

# Server certificate for gRPC
openssl genrsa -out "$INSTALL_DIR/certs/server.key" 2048 2>/dev/null
openssl req -new -key "$INSTALL_DIR/certs/server.key" \
    -out "$INSTALL_DIR/certs/server.csr" \
    -subj "/CN=$EDR_DOMAIN/O=EDR Platform" 2>/dev/null
openssl x509 -req -days 365 \
    -in "$INSTALL_DIR/certs/server.csr" \
    -CA "$INSTALL_DIR/certs/ca.crt" \
    -CAkey "$INSTALL_DIR/certs/ca.key" \
    -CAcreateserial \
    -out "$INSTALL_DIR/certs/server.crt" 2>/dev/null

chmod 600 "$INSTALL_DIR/certs"/*.key
info "TLS証明書を生成しました"

# ─── Write .env File ──────────────────────────────────────────
section "環境設定を作成中"
cat > "$INSTALL_DIR/.env" <<EOF
# EDR Platform Environment Configuration
# 生成日時: $(date)

EDR_DOMAIN=${EDR_DOMAIN}
EDR_BASE_URL=https://${EDR_DOMAIN}

# Database
POSTGRES_PASSWORD=${POSTGRES_PASSWORD}
REDIS_PASSWORD=${REDIS_PASSWORD}

# JWT
JWT_SECRET=${JWT_SECRET}
NEXTAUTH_SECRET=${NEXTAUTH_SECRET}

# AI
CLAUDE_API_KEY=${CLAUDE_API_KEY}

# Admin
ADMIN_EMAIL=${ADMIN_EMAIL}
ADMIN_PASSWORD_HASH=$(echo -n "${ADMIN_PASSWORD}" | python3 -c "import sys,hashlib; print(hashlib.sha256(sys.stdin.buffer.read()).hexdigest())" 2>/dev/null || echo "changeme")

# Enrollment
ENROLLMENT_TOKEN=${ENROLL_TOKEN}
EOF

chmod 600 "$INSTALL_DIR/.env"

# ─── Start Services ───────────────────────────────────────────
section "サービスを起動中"
cd "$INSTALL_DIR"
docker-compose -f docker-compose.yml -f docker-compose.prod.yml pull
docker-compose -f docker-compose.yml -f docker-compose.prod.yml up -d

# Wait for services to be healthy
info "データベースの起動を待機中..."
for i in $(seq 1 30); do
    if docker-compose exec -T postgres pg_isready -U edr -d edrplatform &>/dev/null; then
        info "データベースが起動しました"
        break
    fi
    sleep 2
done

# ─── Print Summary ────────────────────────────────────────────
section "セットアップ完了"
echo ""
echo -e "${GREEN}✓ EDR Platform が正常にセットアップされました${NC}"
echo ""
echo "ダッシュボード URL : https://${EDR_DOMAIN}"
echo "管理者メール       : ${ADMIN_EMAIL}"
echo "エージェント登録トークン: ${ENROLL_TOKEN}"
echo ""
echo "エージェントのインストール方法:"
echo "  Linux/macOS:"
echo "    curl -fsSL https://${EDR_DOMAIN}/install.sh | bash -s -- \\"
echo "      --server https://${EDR_DOMAIN} --token ${ENROLL_TOKEN}"
echo ""
echo "  Windows (管理者PowerShell):"
echo "    iwr https://${EDR_DOMAIN}/install.ps1 | iex \\"
echo "      -Server https://${EDR_DOMAIN} -Token ${ENROLL_TOKEN}"
echo ""
warn "重要: .env ファイルを安全な場所にバックアップしてください"
warn "ファイルパス: $INSTALL_DIR/.env"

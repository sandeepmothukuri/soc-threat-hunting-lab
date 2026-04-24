#!/usr/bin/env bash
# =============================================================================
# install-misp.sh — MISP Threat Intelligence Platform
# Target: Ubuntu 22.04 (192.168.60.10)
# MISP: Share IOCs, threat feeds, malware samples, threat actor profiles
# =============================================================================
set -euo pipefail

GREEN='\033[0;32m'; BLUE='\033[0;34m'; RED='\033[0;31m'; YELLOW='\033[1;33m'; NC='\033[0m'
info()    { echo -e "${GREEN}[INFO]${NC}  $*"; }
step()    { echo -e "\n${BLUE}══ $* ══${NC}"; }
warn()    { echo -e "${YELLOW}[WARN]${NC}  $*"; }
error()   { echo -e "${RED}[ERROR]${NC} $*"; exit 1; }

[[ $EUID -ne 0 ]] && error "Run as root: sudo $0"

MISP_IP="${MISP_IP:-192.168.60.10}"
MISP_BASE_URL="https://${MISP_IP}"
MISP_ADMIN_EMAIL="${MISP_ADMIN_EMAIL:-admin@soc-lab.local}"
MISP_ADMIN_PASS="${MISP_ADMIN_PASS:-$(openssl rand -base64 20 | tr -d '/+='| head -c 20)}"

step "1/6 — Install Dependencies"
apt-get update -qq
apt-get install -y \
    curl git wget gnupg2 apt-transport-https \
    mariadb-server mariadb-client \
    redis-server \
    python3-pip python3-venv \
    php8.1 php8.1-fpm php8.1-mysql php8.1-redis php8.1-xml \
    php8.1-mbstring php8.1-gd php8.1-curl php8.1-zip php8.1-intl \
    php8.1-bcmath php8.1-json php8.1-gnupg \
    nginx \
    supervisor \
    ssdeep libfuzzy-dev libmagic-dev

step "2/6 — Install MISP via Official Installer"
# Use MISP's official automated installer for Ubuntu 22.04
wget -O /tmp/INSTALL.sh https://raw.githubusercontent.com/MISP/MISP/2.4/INSTALL/INSTALL.sh
chmod +x /tmp/INSTALL.sh

# Set environment variables for unattended install
export MISP_USER="www-data"
export MISP_PATH="/var/www/MISP"
export MISP_BASEURL="${MISP_BASE_URL}"
export MISP_EMAIL="${MISP_ADMIN_EMAIL}"

# Run installer (automated mode)
/tmp/INSTALL.sh -A --mysql_innodb_buffer_pool_size="256M" 2>&1 | tee /var/log/misp-install.log
info "MISP core installed"

step "3/6 — Configure Database"
mysql -u root << SQL
CREATE DATABASE IF NOT EXISTS misp CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
CREATE USER IF NOT EXISTS 'misp'@'localhost' IDENTIFIED BY 'MISPpassword123!';
GRANT ALL ON misp.* TO 'misp'@'localhost';
FLUSH PRIVILEGES;
SQL

info "Database configured"

step "4/6 — Configure MISP Settings"
cd /var/www/MISP

# Core config
sudo -u www-data php /var/www/MISP/app/Console/cake Admin setSetting "MISP.baseurl" "${MISP_BASE_URL}"
sudo -u www-data php /var/www/MISP/app/Console/cake Admin setSetting "MISP.email" "${MISP_ADMIN_EMAIL}"
sudo -u www-data php /var/www/MISP/app/Console/cake Admin setSetting "MISP.org" "SOC-Lab"
sudo -u www-data php /var/www/MISP/app/Console/cake Admin setSetting "MISP.host_org_id" "1"

# Security settings
sudo -u www-data php /var/www/MISP/app/Console/cake Admin setSetting "Security.password_policy_length" "12"
sudo -u www-data php /var/www/MISP/app/Console/cake Admin setSetting "Security.rest_client_baseurl" "${MISP_BASE_URL}"
sudo -u www-data php /var/www/MISP/app/Console/cake Admin setSetting "Plugin.Enrichment_services_enable" true

# Enable feeds
sudo -u www-data php /var/www/MISP/app/Console/cake Admin setSetting "Plugin.Feed_services_enable" true

# Set admin password
sudo -u www-data php /var/www/MISP/app/Console/cake User change_pw "${MISP_ADMIN_EMAIL}" "${MISP_ADMIN_PASS}"
info "Admin password set"

step "5/6 — Enable Threat Feeds"
# Import our SOC lab feed list
cp /tmp/feed-list.json /var/www/MISP/app/files/ 2>/dev/null || true

# Enable default MISP feeds via CLI
sudo -u www-data php /var/www/MISP/app/Console/cake Server enable_feeds 2>/dev/null || true

# Configure MISP feeds from our custom list
python3 /etc/misp/scripts/enable-feeds.py 2>/dev/null || warn "Feed script not yet deployed"

step "6/6 — Configure Workers and Nginx"
# Supervisor for background workers
cat > /etc/supervisor/conf.d/misp-workers.conf << 'SUPERVISOR'
[program:misp-workers]
command=/var/www/MISP/app/Console/cake CakeResque.CakeResque start --interval 5 --queue default
directory=/var/www/MISP
user=www-data
autostart=true
autorestart=true
stdout_logfile=/var/log/misp/workers.log
stderr_logfile=/var/log/misp/workers-error.log
SUPERVISOR

mkdir -p /var/log/misp
supervisorctl reread && supervisorctl update && supervisorctl start misp-workers

# Nginx SSL config
openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
    -keyout /etc/ssl/private/misp.key \
    -out /etc/ssl/certs/misp.crt \
    -subj "/CN=${MISP_IP}/O=SOC-Lab/C=US"

cat > /etc/nginx/sites-available/misp << NGINX
server {
    listen 443 ssl;
    server_name ${MISP_IP};

    ssl_certificate /etc/ssl/certs/misp.crt;
    ssl_certificate_key /etc/ssl/private/misp.key;
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers ECDHE-RSA-AES256-GCM-SHA512:DHE-RSA-AES256-GCM-SHA512;

    root /var/www/MISP/app/webroot;
    index index.php;

    location / { try_files \$uri \$uri/ /index.php?\$args; }
    location ~ \.php$ {
        fastcgi_pass unix:/var/run/php/php8.1-fpm.sock;
        fastcgi_param SCRIPT_FILENAME \$document_root\$fastcgi_script_name;
        include fastcgi_params;
    }
}
server { listen 80; server_name ${MISP_IP}; return 301 https://\$host\$request_uri; }
NGINX

ln -sf /etc/nginx/sites-available/misp /etc/nginx/sites-enabled/
rm -f /etc/nginx/sites-enabled/default
nginx -t && systemctl reload nginx

# Cron for automated feed pulls
(crontab -u www-data -l 2>/dev/null; echo "0 */6 * * * /var/www/MISP/app/Console/cake Server fetch_feeds") | crontab -u www-data -

echo ""
echo -e "${GREEN}╔══════════════════════════════════════════════════════════════╗${NC}"
echo -e "${GREEN}║  MISP Threat Intelligence Platform Ready!                    ║${NC}"
echo -e "${GREEN}╠══════════════════════════════════════════════════════════════╣${NC}"
echo -e "${GREEN}║  URL:      https://${MISP_IP}                         ║${NC}"
echo -e "${GREEN}║  Email:    ${MISP_ADMIN_EMAIL}                 ║${NC}"
echo -e "${GREEN}║  Password: ${MISP_ADMIN_PASS}                             ║${NC}"
echo -e "${GREEN}╠══════════════════════════════════════════════════════════════╣${NC}"
echo -e "${GREEN}║  API Key:  Admin → My Profile → Auth Key                     ║${NC}"
echo -e "${GREEN}║  Feeds:    /feeds → Enable all CIRCL and MISP default feeds  ║${NC}"
echo -e "${GREEN}╚══════════════════════════════════════════════════════════════╝${NC}"

# Save credentials
echo "MISP_URL=https://${MISP_IP}" > /root/.misp-creds
echo "MISP_EMAIL=${MISP_ADMIN_EMAIL}" >> /root/.misp-creds
echo "MISP_PASS=${MISP_ADMIN_PASS}" >> /root/.misp-creds
chmod 600 /root/.misp-creds

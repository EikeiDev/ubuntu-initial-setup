#!/bin/bash

set -euo pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

log_info() { echo -e "${GREEN}[INFO]${NC} $1"; }
log_warn() { echo -e "${YELLOW}[WARN]${NC} $1"; }
log_err()  { echo -e "${RED}[ERROR]${NC} $1"; }
log_step() { echo -e "\n${YELLOW}=== $1 ===${NC}"; }

safe_ssh_restart() {
    if [ ! -d /run/sshd ]; then
        mkdir -p /run/sshd
        chmod 0755 /run/sshd
    fi

    log_info "Валидация конфигурации SSH..."
    if sshd -t; then
        if systemctl is-active --quiet ssh.socket; then
            systemctl daemon-reload
            systemctl restart ssh.socket
        fi
        systemctl restart ssh
        log_info "Служба SSH успешно перезапущена."
    else
        log_err "Конфигурация SSH содержит ошибки!"
        log_err "Рестарт отменен во избежание потери доступа."
        exit 1
    fi
}

backup_file() {
    if [ -f "$1" ]; then
        cp "$1" "$1.bak.$(date +%F_%H%M%S)"
        log_info "Бэкап конфига: $1.bak..."
    fi
}

# 1) === Проверка Root прав ===
if [ "$EUID" -ne 0 ]; then
    log_err "Пожалуйста запустите скрипт от имени root."
    exit 1
fi

user_exists() { id "$1" &>/dev/null; }

# 2) === Установка зависимостей ===
log_step "Проверка зависимостей"
apt-get update -qq

MISSING_DEPS=""
for cmd in lsb_release bc; do
    if ! command -v $cmd &> /dev/null; then
        MISSING_DEPS="$MISSING_DEPS $cmd"
    fi
done

if [ -n "$MISSING_DEPS" ]; then
    log_warn "Установка зависимостей: $MISSING_DEPS"
    apt-get install -y lsb-release bc
fi

# === Шаг 1: Обновление системы ===
log_step "Шаг 1: Обновление системы"
export DEBIAN_FRONTEND=noninteractive
apt-get full-upgrade -y && apt-get autoremove -y

# === Шаг 1.1: Автоматические обновления ===
log_step "Шаг 1.1: Настройка автоматических обновлений"
if ! dpkg -l | grep -q "unattended-upgrades"; then
    apt-get install -y unattended-upgrades
fi

if ! grep -q "APT::Periodic::Unattended-Upgrade" /etc/apt/apt.conf.d/20auto-upgrades 2>/dev/null; then
    cat > /etc/apt/apt.conf.d/20auto-upgrades << EOF
APT::Periodic::Update-Package-Lists "1";
APT::Periodic::Unattended-Upgrade "1";
EOF
    dpkg-reconfigure -plow unattended-upgrades
    log_info "Автообновления безопасности включены."
else
    log_info "Уже настроено."
fi

# === Шаг 2: Установка UFW и Fail2Ban ===
log_step "Шаг 2: Установка UFW и Fail2Ban"
apt-get install -y ufw fail2ban

# === Шаг 3: Создание пользователя ===
log_step "Шаг 3: Создание пользователя"
new_user=""
while [[ -z "$new_user" ]]; do
    read -p "Введите имя нового пользователя: " new_user
    if [[ -z "$new_user" ]]; then log_warn "Имя не может быть пустым."; fi
done

if ! user_exists "$new_user"; then
    adduser --gecos "" "$new_user"
    usermod -aG sudo "$new_user"
    log_info "Пользователь $new_user создан."
else
    log_info "Пользователь $new_user уже существует."
fi

# === Шаг 4: Генерация SSH ключей ===
log_step "Шаг 4: Генерация SSH ключей"
SSH_DIR="/home/$new_user/.ssh"
if [[ ! -f "$SSH_DIR/id_ed25519" ]]; then
    mkdir -p "$SSH_DIR"
    chmod 700 "$SSH_DIR"
    ssh-keygen -t ed25519 -f "$SSH_DIR/id_ed25519" -N ""
    cat "$SSH_DIR/id_ed25519.pub" > "$SSH_DIR/authorized_keys"
    chmod 600 "$SSH_DIR/authorized_keys"
    chown -R "$new_user:$new_user" "$SSH_DIR"
    log_info "Ключи Ed25519 сгенерированы."
else
    log_info "Ключи уже существуют."
fi

# === Шаг 5: Смена порта SSH ===
log_step "Шаг 5: Смена порта SSH"
os_version=$(lsb_release -sr)
sshport="" 

while true; do
    read -p "Новый порт SSH (1024-65535): " sshport
    if [[ "$sshport" =~ ^[0-9]+$ ]] && [ "$sshport" -gt 1023 ] && [ "$sshport" -lt 65536 ]; then
        break
    else
        log_warn "Некорректный порт."
    fi
done

backup_file "/etc/ssh/sshd_config"

if (( $(echo "$os_version >= 22.10" | bc -l) )); then
    mkdir -p /etc/systemd/system/ssh.socket.d
    OVERRIDE_FILE="/etc/systemd/system/ssh.socket.d/override.conf"

    cat > "$OVERRIDE_FILE" <<EOF
[Socket]
ListenStream=
ListenStream=0.0.0.0:$sshport
Accept=no
FreeBind=yes
EOF
    log_info "Systemd Override применен (Port $sshport, IPv4)."
else
    if ! grep -q "^Port $sshport" /etc/ssh/sshd_config; then
        sed -i "s/^#Port 22/Port $sshport/" /etc/ssh/sshd_config
        sed -i "s/^Port 22/Port $sshport/" /etc/ssh/sshd_config
        log_info "sshd_config обновлен (Port $sshport)."
    fi
fi

safe_ssh_restart

# === Шаг 6: Настройка безопасности ===
log_step "Шаг 6: Настройка безопасности"

# Чистка cloud-init конфигов
[ -f "/etc/ssh/sshd_config.d/50-cloud-init.conf" ] && echo "PasswordAuthentication no" > "/etc/ssh/sshd_config.d/50-cloud-init.conf"

CONFIG_FILE="/etc/ssh/sshd_config.d/99-hardening.conf"
cat > "$CONFIG_FILE" << EOF
PermitRootLogin no
PasswordAuthentication no
ChallengeResponseAuthentication no
PubkeyAuthentication yes
AddressFamily inet
EOF

log_info "Конфигурация безопасности применена."
safe_ssh_restart

# === Шаг 7: Настройка UFW ===
log_step "Шаг 7: Настройка UFW"
if ! ufw status | grep -q "$sshport/tcp"; then
    ufw allow "$sshport"/tcp
    log_info "Порт $sshport/tcp разрешен."
fi

if [[ $(ufw status | head -n1) == "Status: inactive" ]]; then
    echo "y" | ufw enable
    log_info "UFW активирован."
fi

# === Шаг 7.1: Настройка ICMP ===
log_step "Шаг 7.1: Настройка ICMP"
UFW_RULES="/etc/ufw/before.rules"
backup_file "$UFW_RULES"

if grep -q "icmp-type echo-request -j ACCEPT" "$UFW_RULES"; then
    sed -i 's/-A ufw-before-input -p icmp --icmp-type echo-request -j ACCEPT/-A ufw-before-input -p icmp --icmp-type echo-request -j DROP/g' "$UFW_RULES"
    ufw reload
    log_info "ICMP Echo Request: DROP (Сервер скрыт от пинга)."
elif grep -q "icmp-type echo-request -j DROP" "$UFW_RULES"; then
    log_info "Ping уже отключен."
else
    log_warn "Правило ICMP не найдено автоматически. Проверьте $UFW_RULES."
fi

# === Шаг 7.2: Настройка Fail2Ban ===
log_step "Шаг 7.2: Настройка Fail2Ban"
JAIL_LOCAL="/etc/fail2ban/jail.local"
if ! grep -q "port = $sshport" "$JAIL_LOCAL" 2>/dev/null; then
    cat > "$JAIL_LOCAL" << EOF
[DEFAULT]
bantime = 1h
findtime = 10m
maxretry = 5
[sshd]
enabled = true
port = $sshport
EOF
    systemctl restart fail2ban
    log_info "Jail для SSH настроен."
fi

# === Шаг 7.3: Настройка Sysctl ===
log_step "Шаг 7.3: Настройка Sysctl"
SYSCTL_FILE="/etc/sysctl.d/99-hardening.conf"
if ! grep -q "net.ipv6.conf.all.disable_ipv6 = 1" "$SYSCTL_FILE" 2>/dev/null; then
    cat > "$SYSCTL_FILE" << EOF
net.ipv6.conf.all.disable_ipv6 = 1
net.ipv6.conf.default.disable_ipv6 = 1
net.ipv6.conf.lo.disable_ipv6 = 1
net.ipv4.conf.all.rp_filter = 1
net.ipv4.conf.default.rp_filter = 1
net.ipv4.tcp_syncookies = 1
net.ipv4.conf.all.accept_redirects = 0
EOF
    sysctl -p "$SYSCTL_FILE" > /dev/null
    log_info "IPv6 отключен, защита от спуфинга включена."
fi

# === Шаг 8: Отключение учетной записи root ===
log_step "Шаг 8: Отключение учетной записи root"
if [ "$(passwd -S root | awk '{print $2}')" != "L" ]; then
    read -p "Отключить учетную запись root? (yes/no): " confirm
    if [[ "$confirm" == "yes" ]]; then
        passwd -l root
        log_info "Учетная запись root отключена."
    fi
else
    log_info "Учетная запись root уже отключена."
fi

# === Завершение настройки ===
echo ""
echo "========================================================"
log_info "НАСТРОЙКА ЗАВЕРШЕНА."
echo "--------------------------------------------------------"
echo -e "User: ${YELLOW}$new_user${NC}"
echo -e "Port: ${YELLOW}$sshport${NC}"
echo "--------------------------------------------------------"
log_warn "СКОПИРУЙТЕ ПРИВАТНЫЙ КЛЮЧ:"
echo "--------------------------------------------------------"

cat "$SSH_DIR/id_ed25519"

echo ""
echo "--------------------------------------------------------"
read -p "Скопировали? Нажмите ENTER для удаления ключа с сервера..." confirm_del

rm -f "$SSH_DIR/id_ed25519"

if [ ! -f "$SSH_DIR/id_ed25519" ]; then
    log_info "Приватный ключ удален."
else
    log_err "Ошибка удаления. Удалите вручную: rm $SSH_DIR/id_ed25519"
fi

echo "========================================================"

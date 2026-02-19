#!/bin/bash

set -euo pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

export DEBIAN_FRONTEND=noninteractive
APT_OPTS="-o DPkg::Lock::Timeout=60 -o Dpkg::Options::=--force-confdef -o Dpkg::Options::=--force-confold"

LOG_FILE="/var/log/setup-$(date +%F_%H%M%S).log"
exec > >(tee -a "$LOG_FILE") 2>&1

LOCKFILE="/var/run/setup.lock"
exec 200>"$LOCKFILE"
flock -n 200 || { echo -e "${RED}[ERROR]${NC} Скрипт уже запущен."; exit 1; }

cleanup() {
    rm -f /tmp/setup_*.tmp 2>/dev/null || true
}
trap cleanup EXIT

show_spinner() {
    local pid=$1
    local delay=0.1
    local spinstr='|/-\'
    while kill -0 "$pid" 2>/dev/null; do
        local temp=${spinstr#?}
        printf " [%c] " "$spinstr"
        local spinstr=$temp${spinstr%"$temp"}
        sleep $delay
        printf "\b\b\b\b\b"
    done
    printf "     \b\b\b\b\b"
}

run_silent() {
    local desc="$1"
    shift
    local log_file=$(mktemp)

    echo -n -e "${GREEN}[INFO]${NC} ${desc}..."

    "$@" > "$log_file" 2>&1 &
    local pid=$!
    show_spinner "$pid"

    local exit_code=0
    wait $pid || exit_code=$?

    if [ $exit_code -eq 0 ]; then
        echo -e "${GREEN}[OK]${NC}"
        rm -f "$log_file"
    else
        echo -e "${RED}[FAIL]${NC}"
        echo -e "${RED}Command failed with exit code $exit_code:${NC}"
        cat "$log_file"
        rm -f "$log_file"
        exit $exit_code
    fi
}

apply_sysctl() {
    local key="$1"
    local value="$2"
    local file="${3:-/etc/sysctl.d/99-hardening.conf}"

    if sysctl -w "$key=$value" >/dev/null 2>&1; then
        if ! grep -qF "$key = $value" "$file" 2>/dev/null; then
            echo "$key = $value" >> "$file"
        fi
        return 0
    else
        log_warn "Не удалось применить $key=$value (возможно, ограничение контейнера). Пропускаем."
        return 0
    fi
}

create_swap_file() {
    local size="$1"
    local size_num
    size_num=$(echo "$size" | sed 's/[Gg]//')
    local size_mb=$((size_num * 1024))

    if [ -f /swapfile ]; then
        swapoff /swapfile 2>/dev/null || true
        rm -f /swapfile
    fi

    if ! fallocate -l "$size" /swapfile 2>/dev/null; then
        dd if=/dev/zero of=/swapfile bs=1M count=$size_mb status=none
    fi
    chmod 600 /swapfile
    mkswap /swapfile >/dev/null
    swapon /swapfile
}

log_info() { echo -e "${GREEN}[INFO]${NC} $1"; }
log_warn() { echo -e "${YELLOW}[WARN]${NC} $1"; }
log_err()  { echo -e "${RED}[ERROR]${NC} $1"; }
log_step() { echo -e "\n${YELLOW}=== $1 ===${NC}"; }

if systemctl cat sshd.service &>/dev/null; then
    SSH_SERVICE="sshd"
else
    SSH_SERVICE="ssh"
fi

safe_ssh_restart() {
    if [ ! -d /run/sshd ]; then
        mkdir -p /run/sshd
        chmod 0755 /run/sshd
    fi

    log_info "Валидация конфигурации SSH (sshd -t)..."
    if sshd -t; then
        if systemctl is-active --quiet ssh.socket 2>/dev/null; then
            systemctl daemon-reload
            systemctl restart ssh.socket
        fi
        systemctl restart "$SSH_SERVICE"
        log_info "Служба $SSH_SERVICE успешно перезапущена."
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

if [ "$(id -u)" -ne 0 ]; then
    log_err "Пожалуйста запустите скрипт от имени root."
    exit 1
fi

if [ -f /etc/os-release ]; then
    . /etc/os-release
    OS_ID="$ID"
    OS_VERSION="$VERSION_ID"
    OS_NAME="$PRETTY_NAME"
else
    OS_ID="unknown"
    OS_VERSION="unknown"
    OS_NAME="Unknown OS"
fi

if [[ "$OS_ID" != "ubuntu" && "$OS_ID" != "debian" ]]; then
    log_warn "Обнаружена ОС: $OS_NAME"
    log_warn "Скрипт разработан для Ubuntu/Debian. Продолжение на свой страх и риск."
    read -p "Продолжить? (y/n): " os_confirm
    if [[ ! "$os_confirm" =~ ^[Yy]$ ]]; then
        log_err "Установка отменена."
        exit 1
    fi
else
    log_info "Обнаружена ОС: $OS_NAME"
fi

user_exists() { id "$1" &>/dev/null; }

log_step "Шаг 1: Обновление системы"
run_silent "Обновление списка пакетов" apt-get $APT_OPTS update -qq
run_silent "Полное обновление системы" bash -c "apt-get $APT_OPTS full-upgrade -y && apt-get $APT_OPTS autoremove -y"

if [ -f /var/run/reboot-required ]; then
    log_warn "Обнаружено обновление ядра. Рекомендуется reboot после завершения скрипта."
fi

log_step "Шаг 1.1: Настройка автоматических обновлений"
if ! dpkg -s unattended-upgrades &>/dev/null; then
    apt-get $APT_OPTS install -y unattended-upgrades
fi

if ! grep -q "APT::Periodic::Unattended-Upgrade" /etc/apt/apt.conf.d/20auto-upgrades 2>/dev/null; then
    cat > /etc/apt/apt.conf.d/20auto-upgrades <<EOF
APT::Periodic::Update-Package-Lists "1";
APT::Periodic::Unattended-Upgrade "1";
EOF
    dpkg-reconfigure -f noninteractive unattended-upgrades
    log_info "Автообновления безопасности включены."
else
    log_info "Уже настроено."
fi

log_step "Шаг 2: Установка UFW и Fail2Ban"
run_silent "Установка пакетов безопасности" apt-get $APT_OPTS install -y ufw fail2ban

log_step "Шаг 3: Создание пользователя"
new_user=""
while [[ -z "$new_user" ]]; do
    read -p "Введите имя нового пользователя: " new_user
    if [[ -z "$new_user" ]]; then
        log_warn "Имя не может быть пустым."
        continue
    fi
    if [[ ! "$new_user" =~ ^[a-z_][a-z0-9_-]{0,31}$ ]]; then
        log_warn "Некорректное имя (только a-z, 0-9, _, -). Первый символ — буква или _."
        new_user=""
        continue
    fi
    if [[ "$new_user" == "root" ]]; then
        log_warn "Нельзя использовать 'root' как имя пользователя."
        new_user=""
        continue
    fi
done

if ! user_exists "$new_user"; then
    log_info "Создание пользователя $new_user..."
    log_warn "Вам будет предложено ввести пароль для нового пользователя."
    adduser --gecos "" "$new_user"
    usermod -aG sudo "$new_user"
    log_info "Пользователь $new_user успешно создан."
else
    log_info "Пользователь $new_user уже существует."
fi

log_step "Шаг 4: Генерация SSH ключей"
SSH_DIR="/home/$new_user/.ssh"
if [[ ! -f "$SSH_DIR/id_ed25519" ]]; then
    mkdir -p "$SSH_DIR"
    chmod 700 "$SSH_DIR"
    ssh-keygen -t ed25519 -f "$SSH_DIR/id_ed25519" -N "" -C "$new_user@$(hostname)"

    if [ -f "$SSH_DIR/authorized_keys" ]; then
        if ! grep -qF "$(cat "$SSH_DIR/id_ed25519.pub")" "$SSH_DIR/authorized_keys"; then
            cat "$SSH_DIR/id_ed25519.pub" >> "$SSH_DIR/authorized_keys"
        fi
    else
        cat "$SSH_DIR/id_ed25519.pub" > "$SSH_DIR/authorized_keys"
    fi
    chmod 600 "$SSH_DIR/authorized_keys"
    chown -R "$new_user:$new_user" "$SSH_DIR"
    log_info "Ключи Ed25519 сгенерированы."

    echo ""
    echo "========================================================"
    log_warn "СКОПИРУЙТЕ ПРИВАТНЫЙ КЛЮЧ ПРЯМО СЕЙЧАС!"
    echo "--------------------------------------------------------"
    exec 3>&1
    exec 1>/dev/tty 2>/dev/tty
    cat "$SSH_DIR/id_ed25519"
    exec 1>&3 3>&-
    exec > >(tee -a "$LOG_FILE") 2>&1
    echo ""
    echo "--------------------------------------------------------"
    log_warn "Ключ будет УДАЛЁН в конце настройки."
    log_warn "Убедитесь, что вы его скопировали!"
    read -p "Скопировали ключ? (yes для продолжения): " key_copied
    while [[ "$key_copied" != "yes" ]]; do
        log_warn "Введите 'yes' для продолжения."
        read -p "Скопировали ключ? (yes для продолжения): " key_copied
    done
    echo "========================================================"
else
    log_info "Ключи уже существуют."
fi

log_step "Шаг 5: Смена порта SSH"
os_version="${OS_VERSION:-0}"
sshport=""

while true; do
    read -p "Новый порт SSH (1024-65535): " sshport
    if [[ ! "$sshport" =~ ^[0-9]+$ ]] || [ "$sshport" -le 1023 ] || [ "$sshport" -ge 65536 ]; then
        log_warn "Некорректный порт. Допустимый диапазон: 1024-65535."
        continue
    fi
    if ss -tlnp 2>/dev/null | grep -v "sshd" | grep -q ":$sshport "; then
        log_warn "Порт $sshport уже занят другим сервисом!"
        continue
    fi
    break
done

echo ""
echo "========================================================"
log_info "ПРЕДВАРИТЕЛЬНАЯ СВОДКА"
echo "--------------------------------------------------------"
echo -e "ОС:            ${YELLOW}${OS_NAME}${NC}"
echo -e "Пользователь:  ${YELLOW}${new_user}${NC}"
echo -e "SSH порт:      ${YELLOW}${sshport}${NC}"
echo "--------------------------------------------------------"
echo -e "Будут выполнены:"
echo -e "  • Настройка UFW (default deny) + rate-limit SSH"
echo -e "  • Смена SSH порта и hardening"
echo -e "  • Настройка Fail2Ban"
echo -e "  • Блокировка ICMP (ping)"
echo -e "  • Опционально: IPv6, Swap, BBR, Docker, Chrony"
echo -e "  • Отключение root-доступа"
echo "========================================================"
read -p "Продолжить настройку? (y/n, default: y): " start_confirm
start_confirm=${start_confirm:-y}
if [[ ! "$start_confirm" =~ ^[Yy]$ ]]; then
    log_err "Установка отменена пользователем."
    exit 0
fi

log_step "Шаг 5.1: Настройка UFW"

ufw default deny incoming >/dev/null 2>&1
ufw default allow outgoing >/dev/null 2>&1
log_info "UFW: default deny incoming, allow outgoing."

if ! ufw status 2>/dev/null | grep -q "$sshport/tcp"; then
    ufw limit "$sshport"/tcp
    log_info "Порт $sshport/tcp разрешен (rate-limited)."
fi

if [[ $(ufw status 2>/dev/null | head -n1) == "Status: inactive" ]]; then
    echo "y" | ufw enable
    log_info "UFW активирован."
fi

log_step "Шаг 5.2: Применение нового порта SSH"
backup_file "/etc/ssh/sshd_config"

os_version_num=$(echo "$os_version" | awk -F. '{printf "%d%02d", $1, $2}')
if [[ "$os_version" =~ ^[0-9]+(\.[0-9]+)?$ ]] && [ "$os_version_num" -ge 2210 ]; then
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
        if ! grep -q "^Port " /etc/ssh/sshd_config; then
            echo "Port $sshport" >> /etc/ssh/sshd_config
        fi
        log_info "sshd_config обновлен (Port $sshport)."
    fi
fi

safe_ssh_restart

log_step "Шаг 6: Настройка безопасности SSH"

if [ -f "/etc/ssh/sshd_config.d/50-cloud-init.conf" ]; then
    echo "PasswordAuthentication no" > "/etc/ssh/sshd_config.d/50-cloud-init.conf"
fi

CONFIG_FILE="/etc/ssh/sshd_config.d/99-hardening.conf"
cat > "$CONFIG_FILE" <<EOF
PermitRootLogin no
PasswordAuthentication no
ChallengeResponseAuthentication no
KbdInteractiveAuthentication no
PubkeyAuthentication yes
AddressFamily inet
MaxAuthTries 3
LoginGraceTime 30
X11Forwarding no
AllowUsers $new_user
ClientAliveInterval 300
ClientAliveCountMax 2
LogLevel VERBOSE
UseDNS no
PermitEmptyPasswords no
EOF

log_info "Конфигурация безопасности применена."
safe_ssh_restart

log_step "Шаг 7: Настройка ICMP"
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

log_step "Шаг 7.1: Настройка Fail2Ban"
JAIL_FILE="/etc/fail2ban/jail.d/ssh-hardening.conf"
if ! grep -qF "port = $sshport" "$JAIL_FILE" 2>/dev/null; then
    mkdir -p /etc/fail2ban/jail.d
    cat > "$JAIL_FILE" <<EOF
[DEFAULT]
bantime = 1h
findtime = 10m
maxretry = 5
backend = systemd
[sshd]
enabled = true
port = $sshport
EOF
    systemctl restart fail2ban
    log_info "Jail для SSH настроен ($JAIL_FILE)."
fi

log_step "Шаг 7.2: Настройка Sysctl"
read -p "Отключить IPv6? (y/n, default: y): " disable_ipv6
disable_ipv6=${disable_ipv6:-y}

if [[ "$disable_ipv6" =~ ^[Yy]$ ]]; then
    SYSCTL_FILE="/etc/sysctl.d/99-hardening.conf"
    if ! grep -q "net.ipv6.conf.all.disable_ipv6 = 1" "$SYSCTL_FILE" 2>/dev/null; then

        apply_sysctl "net.ipv6.conf.all.disable_ipv6" "1"
        apply_sysctl "net.ipv6.conf.default.disable_ipv6" "1"
        apply_sysctl "net.ipv6.conf.lo.disable_ipv6" "1"
        apply_sysctl "net.ipv4.conf.all.rp_filter" "1"
        apply_sysctl "net.ipv4.conf.default.rp_filter" "1"
        apply_sysctl "net.ipv4.tcp_syncookies" "1"
        apply_sysctl "net.ipv4.conf.all.accept_redirects" "0"
        apply_sysctl "net.ipv4.conf.default.accept_redirects" "0"
        apply_sysctl "net.ipv4.conf.all.send_redirects" "0"
        apply_sysctl "net.ipv4.icmp_ignore_bogus_error_responses" "1"
        apply_sysctl "net.ipv4.conf.all.log_martians" "1"

        sysctl --system > /dev/null 2>&1 || true
        log_info "Параметры безопасности применены (где возможно)."
    fi
else
    log_info "Отключение IPv6 пропущено пользователем."
fi

log_step "Шаг 8: Настройка Swap"
if ! swapon --show 2>/dev/null | grep -q "partition\|file"; then
    read -p "Создать Swap файл? (y/n, default: y): " create_swap
    create_swap=${create_swap:-y}

    if [[ "$create_swap" =~ ^[Yy]$ ]]; then
        SWAP_SIZE="2G"

        avail_mb=$(df -BM / | tail -1 | awk '{print $4}' | sed 's/M//')
        if [ "$avail_mb" -lt 2560 ]; then
            log_warn "Недостаточно места на диске (${avail_mb}MB свободно). Swap не создан."
        elif run_silent "Создание файла Swap ($SWAP_SIZE)" create_swap_file "$SWAP_SIZE"; then
            if ! grep -qF '/swapfile' /etc/fstab; then
                echo '/swapfile none swap sw 0 0' >> /etc/fstab
            fi

            apply_sysctl "vm.swappiness" "10"
            apply_sysctl "vm.vfs_cache_pressure" "50"

            log_info "Swap ($SWAP_SIZE) создан и настроен."
        else
            log_err "Не удалось создать Swap."
        fi
    fi
else
    log_info "Swap уже активен."
fi

log_step "Шаг 9: Включение TCP BBR"
read -p "Включить TCP BBR? (y/n, default: y): " enable_bbr
enable_bbr=${enable_bbr:-y}

if [[ "$enable_bbr" =~ ^[Yy]$ ]]; then
    if ! grep -q "tcp_congestion_control = bbr" /etc/sysctl.conf /etc/sysctl.d/*.conf 2>/dev/null; then
        apply_sysctl "net.core.default_qdisc" "fq"
        apply_sysctl "net.ipv4.tcp_congestion_control" "bbr"
        sysctl --system > /dev/null 2>&1 || true
        log_info "TCP BBR включен (где возможно)."
    else
        log_info "BBR уже включен."
    fi
fi

log_step "Шаг 10: Установка дополнительного ПО"

BASE_UTILS="htop iotop ncdu tmux curl wget net-tools"
MISSING_UTILS=""
for util in $BASE_UTILS; do
    if ! dpkg -s "$util" &>/dev/null; then
        MISSING_UTILS="$MISSING_UTILS $util"
    fi
done
if [ -n "$MISSING_UTILS" ]; then
    run_silent "Установка базовых утилит" apt-get $APT_OPTS install -y $MISSING_UTILS
    log_info "Установлены утилиты:$MISSING_UTILS"
else
    log_info "Базовые утилиты уже установлены."
fi

read -p "Установить Docker? (y/n, default: n): " install_docker
install_docker=${install_docker:-n}

if [[ "$install_docker" =~ ^[Yy]$ ]]; then
    log_info "Установка Docker..."
    if command -v docker &> /dev/null; then
        log_warn "Docker уже установлен."
    else
        curl -fsSL https://get.docker.com -o /tmp/get-docker.sh
        run_silent "Установка Docker" sh /tmp/get-docker.sh
        rm -f /tmp/get-docker.sh
        usermod -aG docker "$new_user"
        log_info "Пользователь $new_user добавлен в группу docker."
        log_warn "ВНИМАНИЕ: Docker модифицирует iptables напрямую, минуя UFW."
        log_warn "Порты контейнеров (-p) будут открыты снаружи несмотря на UFW."
        log_warn "Для защиты используйте: 127.0.0.1:PORT:PORT вместо PORT:PORT."
    fi
fi

read -p "Установить NTP (Chrony) для синхронизации времени? (y/n, default: y): " install_ntp
install_ntp=${install_ntp:-y}

if [[ "$install_ntp" =~ ^[Yy]$ ]]; then
    run_silent "Установка Chrony" apt-get $APT_OPTS install -y chrony
    systemctl enable chrony > /dev/null 2>&1
    systemctl start chrony > /dev/null 2>&1
    log_info "Chrony установлен и запущен."
fi

log_step "Шаг 10.3: Настройка hostname"
current_hostname=$(hostname)
log_info "Текущий hostname: $current_hostname"
read -p "Изменить hostname? (введите новый или нажмите ENTER для пропуска): " new_hostname
if [[ -n "$new_hostname" ]]; then
    hostnamectl set-hostname "$new_hostname"
    log_info "Hostname изменен на: $new_hostname"
else
    log_info "Hostname оставлен без изменений."
fi

log_step "Шаг 10.4: Настройка часового пояса"
current_tz=$(timedatectl show --property=Timezone --value 2>/dev/null || echo "неизвестно")
log_info "Текущий часовой пояс: $current_tz"
read -p "Изменить часовой пояс? (например, Europe/Moscow, или ENTER для пропуска): " new_tz
if [[ -n "$new_tz" ]]; then
    if timedatectl set-timezone "$new_tz" 2>/dev/null; then
        log_info "Часовой пояс установлен: $new_tz"
    else
        log_warn "Не удалось установить часовой пояс '$new_tz'. Проверьте правильность."
    fi
else
    log_info "Часовой пояс оставлен без изменений."
fi

log_step "Шаг 10.5: Отключение ненужных сервисов"
for svc in snapd cups; do
    if systemctl is-active --quiet "$svc" 2>/dev/null; then
        systemctl disable --now "$svc" 2>/dev/null || true
        log_info "Сервис $svc отключен."
    fi
done

log_step "Шаг 11: Отключение учетной записи root"
root_status=$(passwd -S root 2>/dev/null | awk '{print $2}' || echo "unknown")
if [ "$root_status" != "L" ]; then
    read -p "Отключить учетную запись root? (yes/no): " confirm
    if [[ "$confirm" == "yes" ]]; then
        passwd -l root
        log_info "Учетная запись root отключена."
    fi
else
    log_info "Учетная запись root уже отключена."
fi

echo ""
echo "========================================================"
log_info "НАСТРОЙКА ПОЧТИ ЗАВЕРШЕНА."
echo "--------------------------------------------------------"
echo -e "User: ${YELLOW}$new_user${NC}"
echo -e "Port: ${YELLOW}$sshport${NC}"
echo "--------------------------------------------------------"
log_warn "ПРОВЕРЬТЕ ДОСТУП ПЕРЕД УДАЛЕНИЕМ КЛЮЧА!"
echo ""
echo -e "Откройте ${YELLOW}ВТОРУЮ${NC} SSH-сессию и подключитесь:"
echo -e "  ${GREEN}ssh -i <путь_к_ключу> -p $sshport $new_user@<IP>${NC}"
echo ""
echo -e "Убедитесь, что:"
echo -e "  1. Подключение успешно"
echo -e "  2. ${YELLOW}sudo whoami${NC} возвращает ${GREEN}root${NC}"
echo "--------------------------------------------------------"
read -p "Подключение во второй сессии успешно? (yes/no): " access_ok

if [[ "$access_ok" != "yes" ]]; then
    log_warn "Приватный ключ НЕ удалён. Файл: $SSH_DIR/id_ed25519"
    log_warn "Разберитесь с доступом и удалите ключ вручную: rm $SSH_DIR/id_ed25519"
    echo "========================================================"
    log_info "Лог-файл сохранен: $LOG_FILE"
    exit 0
fi

if [ -f "$SSH_DIR/id_ed25519" ]; then
    rm -f "$SSH_DIR/id_ed25519"
    if [ ! -f "$SSH_DIR/id_ed25519" ]; then
        log_info "Приватный ключ удален."
    else
        log_err "Ошибка удаления. Удалите вручную: rm $SSH_DIR/id_ed25519"
    fi
else
    log_info "Приватный ключ уже отсутствует."
fi

echo "========================================================"
log_info "НАСТРОЙКА ПОЛНОСТЬЮ ЗАВЕРШЕНА."
log_info "Лог-файл сохранен: $LOG_FILE"
if [ -f /var/run/reboot-required ]; then
    echo ""
    log_warn "РЕКОМЕНДУЕТСЯ ПЕРЕЗАГРУЗКА: обновлено ядро."
    log_warn "Выполните: sudo reboot"
fi

#!/bin/bash

set -e

# === Вспомогательные функции ===
user_exists() { id "$1" &>/dev/null; }
port_in_use() { ss -tulpn | grep -q ":$1 "; }

# === 1. Обновление системы ===
echo "=== Шаг 1: Обновление системы ==="
apt-get update && apt full-upgrade -y && apt autoremove -y

# === 2. Установка UFW и bc ===
echo "=== Шаг 2: Установка UFW и bc ==="
apt-get install -y ufw bc

# === 3. Создание нового пользователя ===
echo "=== Шаг 3: Создание нового пользователя ==="
read -p "Введите имя нового пользователя: " new_user
if ! user_exists "$new_user"; then
    adduser "$new_user"
    usermod -aG sudo "$new_user"
else
    echo "Пользователь $new_user уже существует. Пропускаем."
fi

# === 4. Генерация SSH ключей ===
echo "=== Шаг 4: Генерация SSH ключей ==="
SSH_DIR="/home/$new_user/.ssh"
if [[ ! -f "$SSH_DIR/id_ed25519" ]]; then
    mkdir -p "$SSH_DIR"
    chmod 700 "$SSH_DIR"
    ssh-keygen -t ed25519 -f "$SSH_DIR/id_ed25519" -N ""
    cat "$SSH_DIR/id_ed25519.pub" > "$SSH_DIR/authorized_keys"
    chmod 600 "$SSH_DIR/authorized_keys"
    chown -R "$new_user:$new_user" "$SSH_DIR"
else
    echo "SSH ключи для $new_user уже существуют. Пропускаем."
fi

# === 5. Настройка SSH ===
echo "=== Шаг 5: Настройка SSH ==="
os_version=$(lsb_release -sr)
read -p "Введите новый порт SSH: " sshport

if (( $(echo "$os_version >= 22.10" | bc -l) )); then
    # ---- Используем systemd socket override ----
    mkdir -p /etc/systemd/system/ssh.socket.d
    OVERRIDE_FILE="/etc/systemd/system/ssh.socket.d/override.conf"

    if ! grep -q "0.0.0.0:$sshport" "$OVERRIDE_FILE" 2>/dev/null; then
        cat > "$OVERRIDE_FILE" <<EOF
[Socket]
ListenStream=
ListenStream=0.0.0.0:$sshport
BindIPv6Only=both
FreeBind=yes
Backlog=128
ReusePort=yes
EOF
        echo "Создан override для ssh.socket на порт $sshport"
    else
        echo "Override уже содержит порт $sshport. Пропускаем."
    fi

    systemctl daemon-reload
    systemctl restart ssh.socket
    systemctl restart ssh

    echo "SSH socket успешно перезапущен и слушает порт $sshport (только IPv4)"
else
    # ---- Старый способ для систем без socket activation ----
    if ! grep -q "^Port $sshport" /etc/ssh/sshd_config; then
        sed -i "s/^#Port 22/Port $sshport/" /etc/ssh/sshd_config
        systemctl restart ssh
        echo "sshd_config настроен на порт $sshport"
    else
        echo "sshd_config уже настроен на этот порт. Пропускаем."
    fi
fi

# === 6. Безопасность SSH ===
echo "=== Шаг 6: Настройка безопасности SSH ==="
sed -i -e '/^#PasswordAuthentication/ c\PasswordAuthentication no' \
       -e '/^PasswordAuthentication/ c\PasswordAuthentication no' \
       -e '/^#PermitRootLogin/ c\PermitRootLogin no' \
       -e '/^PermitRootLogin/ c\PermitRootLogin no' \
       -e '/^#PubkeyAuthentication/ c\PubkeyAuthentication yes' \
       /etc/ssh/sshd_config

echo "PasswordAuthentication no" > /etc/ssh/sshd_config.d/50-cloud-init.conf

# === 7. UFW ===
echo "=== Шаг 7: Настройка UFW ==="
if ! ufw status | grep -q "$sshport/tcp"; then
    ufw allow "$sshport"/tcp
fi

ufw_status=$(ufw status | head -n1)
if [[ "$ufw_status" == "Status: inactive" ]]; then
    ufw --force enable
fi

# === 7.1 Отключение ICMP (ping) ===
echo "=== Шаг 7.1: Отключение ICMP (ping) ==="
UFW_RULES="/etc/ufw/before.rules"

if grep -q -- "--icmp-type echo-request -j ACCEPT" "$UFW_RULES"; then
    cp "$UFW_RULES" "${UFW_RULES}.bak.$(date +%F_%T)"
    echo "Создана резервная копия ${UFW_RULES}.bak.$(date +%F_%T)"

    # Заменяем ACCEPT на DROP в ICMP блоках
    sed -i '/# ok icmp codes for INPUT/,/# ok icmp code for FORWARD/ s/-j ACCEPT/-j DROP/g' "$UFW_RULES"
    sed -i '/# ok icmp code for FORWARD/,/-A ufw-before-forward -p icmp --icmp-type echo-request/ s/-j ACCEPT/-j DROP/g' "$UFW_RULES"

    # Добавляем строку DROP первой в блок INPUT (если её нет)
    if ! grep -q -- "-A ufw-before-input -p icmp --icmp-type source-quench -j DROP" "$UFW_RULES"; then
        sed -i '/# ok icmp codes for INPUT/a -A ufw-before-input -p icmp --icmp-type source-quench -j DROP' "$UFW_RULES"
    fi

    echo "ICMP (ping) отключён через UFW."
    ufw disable && ufw --force enable
else
    echo "ICMP уже отключён или правила не найдены. Пропускаем."
fi

# === 7.2 Установка и настройка Fail2Ban ===
echo "=== Шаг 7.2: Установка и настройка Fail2Ban ==="
JAIL_LOCAL="/etc/fail2ban/jail.local"

# 1. Установка
if ! dpkg -l | grep -q "fail2ban"; then
    echo "Установка Fail2Ban..."
    apt-get install -y fail2ban
    systemctl enable --now fail2ban
else
    echo "Fail2Ban уже установлен."
fi

# 2. Настройка
# (Используем переменную $sshport из Шага 5)
if [[ -z "$sshport" ]]; then
    echo "Критическая ошибка: Переменная \$sshport не найдена. Пропуск настройки Fail2Ban."
else
    # Проверяем, существует ли файл и настроен ли он уже на наш порт
    if ! grep -q -E "^\s*port\s*=\s*$sshport" "$JAIL_LOCAL" 2>/dev/null; then
        echo "Настройка Fail2Ban для порта $sshport..."
        cat > "$JAIL_LOCAL" << EOF
[DEFAULT]
bantime = 1h

[sshd]
enabled = true
port = $sshport
EOF
        systemctl restart fail2ban
        echo "Fail2Ban настроен."
    else
        echo "Fail2Ban уже настроен на порт $sshport. Пропускаем."
    fi
fi

# === 8. Проверка SSH перед отключением root ===
echo "=== Шаг 8: Проверка SSH подключения ==="
echo "Проверь подключение к серверу новым пользователем и портом $sshport (не закрывай текущую сессию)."

# === 9. Отключение root ===
echo "=== Шаг 9: Отключение root ==="
if ! grep -q "^root:.*nologin" /etc/passwd; then
    read -p "Если вы проверили подключение, введите 'yes' для отключения root: " confirm
    if [[ "$confirm" == "yes" ]]; then
        usermod -s /usr/sbin/nologin root
        echo "Root отключен."
    else
        echo "Root не отключен. Сделай это вручную после проверки SSH."
    fi
else
    echo "Root уже отключен. Пропускаем."
fi

# === 10. Приватный ключ ===
echo "=== Шаг 10: Приватный ключ нового пользователя ==="
cat "$SSH_DIR/id_ed25519"
echo -e "\nНастройка завершена. Подключайся через порт $sshport новым пользователем."

#!/bin/bash
# Мониторинг Stack Deployment Script для Fedora
# Компоненты: Harvest + Prometheus + Grafana
# Версия: 3.4 (Jenkins)
set -euo pipefail

# ============================================
# КОНФИГУРАЦИОННЫЕ ПЕРЕМЕННЫЕ
# ============================================
: "${RLM_API_URL:=}"
: "${RLM_TOKEN:=}"
: "${NETAPP_API_ADDR:=}"
: "${GRAFANA_USER:=}"
: "${GRAFANA_PASSWORD:=}"
: "${SEC_MAN_ROLE_ID:=}"
: "${SEC_MAN_SECRET_ID:=}"
: "${SEC_MAN_ADDR:=}"
: "${NAMESPACE_CI:=}"
: "${VAULT_AGENT_KV:=}"
: "${RPM_URL_KV:=}"
: "${TUZ_KV:=}"
: "${NETAPP_SSH_KV:=}"
: "${MON_SSH_KV:=}"
: "${NETAPP_API_KV:=}"
: "${GRAFANA_WEB_KV:=}"
: "${SBERCA_CERT_KV:=}"
: "${ADMIN_EMAIL:=}"
: "${GRAFANA_PORT:=}"
: "${PROMETHEUS_PORT:=}"
: "${NETAPP_POLLER_NAME:=}"

WRAPPERS_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/wrappers"

# Конфигурация
SEC_MAN_ADDR="${SEC_MAN_ADDR^^}"
SCRIPT_NAME="$(basename "$0")"
DATE_INSTALL=$(date '+%Y%m%d_%H%M%S')
INSTALL_DIR="/opt/mon_distrib/mon_rpm_${DATE_INSTALL}"
LOG_FILE="$HOME/monitoring_deployment_${DATE_INSTALL}.log"
STATE_FILE="/var/lib/monitoring_deployment_state"
ENV_FILE="/etc/environment.d/99-monitoring-vars.conf"
HARVEST_CONFIG="/opt/harvest/harvest.yml"
VAULT_CONF_DIR="/opt/vault/conf"
VAULT_LOG_DIR="/opt/vault/log"
VAULT_CERTS_DIR="/opt/vault/certs"
VAULT_AGENT_HCL="${VAULT_CONF_DIR}/agent.hcl"
VAULT_ROLE_ID_FILE="${VAULT_CONF_DIR}/role_id.txt"
VAULT_SECRET_ID_FILE="${VAULT_CONF_DIR}/secret_id.txt"
VAULT_DATA_CRED_JS="${VAULT_CONF_DIR}/data_cred.js"
LOCAL_CRED_JSON="/tmp/temp_data_cred.json"

# URLs для загрузки пакетов (берутся из параметров Jenkins)
PROMETHEUS_URL="${PROMETHEUS_URL:-}"
HARVEST_URL="${HARVEST_URL:-}"
GRAFANA_URL="${GRAFANA_URL:-}"

# Глобальные переменные (будут инициализированы в detect_network_info)
SERVER_IP=""
SERVER_DOMAIN=""
VAULT_CRT_FILE=""
VAULT_KEY_FILE=""
GRAFANA_BEARER_TOKEN=""

# Порты сервисов
PROMETHEUS_PORT="${PROMETHEUS_PORT:-9090}"
GRAFANA_PORT="${GRAFANA_PORT:-3000}"
HARVEST_UNIX_PORT=12991
HARVEST_NETAPP_PORT=12990

# Функции для вывода без цветового форматирования
print_header() {
    echo "================================================="
    echo "деплой Harvest + Prometheus + Grafana в пипилине"
    echo "================================================="
    echo
}

install_vault_via_rlm() {
    print_step "Установка и настройка Vault через RLM"
    ensure_working_directory

    if [[ -z "$RLM_TOKEN" || -z "$RLM_API_URL" || -z "$SEC_MAN_ADDR" || -z "$NAMESPACE_CI" || -z "$SERVER_IP" ]]; then
        print_error "Отсутствуют обязательные параметры для установки Vault (RLM_API_URL/RLM_TOKEN/SEC_MAN_ADDR/NAMESPACE_CI/SERVER_IP)"
        exit 1
    fi

    # Нормализуем SEC_MAN_ADDR в верхний регистр для единообразия
    local SEC_MAN_ADDR_UPPER
    SEC_MAN_ADDR_UPPER="${SEC_MAN_ADDR^^}"

    # Формируем KAE_SERVER из NAMESPACE_CI
    local KAE_SERVER
    KAE_SERVER=$(echo "$NAMESPACE_CI" | cut -d'_' -f2)
    print_info "Создание задачи RLM для Vault (tenant=$NAMESPACE_CI, v_url=$SEC_MAN_ADDR_UPPER, host=$SERVER_IP)"

    # Формируем JSON-пейлоад через jq (надежное экранирование)
    local payload vault_create_resp vault_task_id
    payload=$(jq -n       --arg v_url "$SEC_MAN_ADDR_UPPER"       --arg tenant "$NAMESPACE_CI"       --arg kae "$KAE_SERVER"       --arg ip "$SERVER_IP"       '{
        params: {
          v_url: $v_url,
          tenant: $tenant,
          start_after_configuration: false,
          approle: "approle/vault-agent",
          templates: [
            {
              source: { file_name: null, content: null },
              destination: { path: null }
            }
          ],
          serv_user: ($kae + "-lnx-va-start"),
          serv_group: ($kae + "-lnx-va-read"),
          read_user: ($kae + "-lnx-va-start"),
          log_num: 5,
          log_size: 5,
          log_level: "info",
          config_unwrapped: true,
          skip_sm_conflicts: false
        },
        start_at: "now",
        service: "vault_agent_config",
        items: [
          {
            table_id: "secmanserver",
            invsvm_ip: $ip
          }
        ]
      }')

    if [[ ! -x "$WRAPPERS_DIR/rlm_launcher.sh" ]]; then
        print_error "Лаунчер rlm_launcher.sh не найден или не исполняемый в $WRAPPERS_DIR"
        exit 1
    fi

    vault_create_resp=$(printf '%s' "$payload" | "$WRAPPERS_DIR/rlm_launcher.sh" create_vault_task "$RLM_API_URL" "$RLM_TOKEN") || true

    vault_task_id=$(echo "$vault_create_resp" | jq -r '.id // empty')
    if [[ -z "$vault_task_id" || "$vault_task_id" == "null" ]]; then
        print_error "❌ Ошибка при создании задачи Vault: $vault_create_resp"
        exit 1
    fi
    print_success "✅ Задача Vault создана. ID: $vault_task_id"

    # Мониторинг статуса задачи Vault
    local max_attempts=120
    local attempt=1
    local current_v_status=""
    while [[ $attempt -le $max_attempts ]]; do
        print_info "Проверка статуса Vault (попытка $attempt/$max_attempts)..."
        local vault_status_resp
        vault_status_resp=$("$WRAPPERS_DIR/rlm_launcher.sh" get_vault_status "$RLM_API_URL" "$RLM_TOKEN" "$vault_task_id") || true

        if echo "$vault_status_resp" | grep -q '"status":"success"'; then
            print_success "🎉 Задача Vault успешно завершена"
            sleep 10
            break
        fi

        # Текущий статус для информации (approved/performing/etc.)
        current_v_status=$(echo "$vault_status_resp" | jq -r '.status // empty' 2>/dev/null || echo "$vault_status_resp" | grep -o '"status":"[^"]*"' | head -1 | cut -d'"' -f4)
        if [[ -n "$current_v_status" ]]; then
            print_info "Текущий статус Vault: $current_v_status"
        else
            print_info "Статус Vault: в процессе..."
        fi

        if echo "$vault_status_resp" | grep -q '"status":"failed"'; then
            print_error "💥 Задача Vault завершилась с ошибкой"
            print_error "Ответ RLM: $vault_status_resp"
            exit 1
        elif echo "$vault_status_resp" | grep -q '"status":"error"'; then
            print_error "💥 Задача Vault завершилась с ошибкой"
            print_error "Ответ RLM: $vault_status_resp"
            exit 1
        fi

        sleep 10
        attempt=$((attempt + 1))
    done

    if [[ $attempt -gt $max_attempts ]]; then
        print_error "⏰ Задача Vault: таймаут ожидания (300 секунд). Последний статус: ${current_v_status:-unknown}"
        exit 1
    fi
}

print_step() {
    echo "[STEP] $1"
    log_message "[STEP] $1"
}

print_success() {
    echo "[SUCCESS] $1"
    log_message "[SUCCESS] $1"
}

print_error() {
    echo "[ERROR] $1" >&2
    log_message "[ERROR] $1"
}

print_warning() {
    echo "[WARNING] $1"
    log_message "[WARNING] $1"
}

print_info() {
    echo "[INFO] $1"
    log_message "[INFO] $1"
}

# Функция логирования
log_message() {
    local log_dir
    log_dir=$(dirname "$LOG_FILE")
    mkdir -p "$log_dir" 2>/dev/null || true
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $1" >> "$LOG_FILE" 2>/dev/null || true
}

# Функция для проверки и установки рабочей директории
ensure_working_directory() {
    local target_dir="/tmp"
    if ! pwd >/dev/null 2>&1; then
        print_warning "Текущая директория недоступна, переключаемся на $target_dir"
        cd "$target_dir" || {
            print_error "Не удалось переключиться на $target_dir"
            exit 1
        }
    fi
    local current_dir
    current_dir=$(pwd)
    print_info "Текущая рабочая директория: $current_dir"
}

# Функция проверки прав sudo
check_sudo() {
    print_step "Проверка прав администратора"
    ensure_working_directory
    if [[ $EUID -ne 0 ]]; then
        print_error "Этот скрипт должен запускаться с правами root (sudo)"
        print_info "Используйте: sudo $SCRIPT_NAME"
        exit 1
    fi
    print_success "Права администратора подтверждены"
}

# Функция проверки и закрытия портов
check_and_close_ports() {
    print_step "Проверка и закрытие используемых портов"
    ensure_working_directory
    local ports=(
        "$PROMETHEUS_PORT:Prometheus"
        "$GRAFANA_PORT:Grafana"
        "$HARVEST_UNIX_PORT:Harvest-Unix"
        "$HARVEST_NETAPP_PORT:Harvest-NetApp"
    )
    local port_in_use=false

    for port_info in "${ports[@]}"; do
        IFS=':' read -r port name <<< "$port_info"
        if ss -tln | grep -q ":$port "; then
            print_warning "$name (порт $port) уже используется"
            port_in_use=true
            print_info "Поиск процессов, использующих порт $port..."
            local pids
            pids=$(ss -tlnp | grep ":$port " | awk -F, '{for(i=1;i<=NF;i++) if ($i ~ /pid=/) {print $i}}' | awk -F= '{print $2}' | sort -u)
            if [[ -n "$pids" ]]; then
                for pid in $pids; do
                    print_info "Информация о процессе с PID $pid:"
                    ps -p "$pid" -o pid,ppid,cmd --no-headers | while read -r pid ppid cmd; do
                        print_info "PID: $pid, PPID: $ppid, Команда: $cmd"
                        log_message "PID: $pid, PPID: $ppid, Команда: $cmd"
                    done
                    print_info "Попытка завершения процесса с PID $pid"
                    kill -TERM "$pid" 2>/dev/null || print_warning "Не удалось отправить SIGTERM процессу $pid"
                    sleep 2
                    if kill -0 "$pid" 2>/dev/null; then
                        print_info "Процесс $pid не завершился, отправляем SIGKILL"
                        kill -9 "$pid" 2>/dev/null || print_warning "Не удалось завершить процесс $pid с SIGKILL"
                    fi
                done
                sleep 2
                if ! ss -tln | grep -q ":$port "; then
                    print_success "Порт $port успешно освобожден"
                else
                    print_error "Не удалось освободить порт $port"
                    ss -tlnp | grep ":$port " | while read -r line; do
                        print_info "$line"
                        log_message "Порт $port все еще занят: $line"
                    done
                    exit 1
                fi
            else
                print_warning "Не удалось найти процессы для порта $port"
                ss -tlnp | grep ":$port " | while read -r line; do
                    print_info "$line"
                    log_message "Порт $port занят, но PID не найден: $line"
                done
            fi
        else
            print_success "$name (порт $port) свободен"
        fi
    done

    if [[ "$port_in_use" == true ]]; then
        print_info "Все используемые порты были закрыты"
    else
        print_success "Все порты свободны, дополнительных действий не требуется"
    fi
}

# Функция определения IP и домена
detect_network_info() {
    print_step "Определение IP адреса и домена сервера"
    ensure_working_directory
    print_info "Определение IP адреса..."
    SERVER_IP=$(hostname -I | awk '{print $1}')
    if [[ -z "$SERVER_IP" ]]; then
        print_error "Не удалось определить IP адрес"
        exit 1
    fi
    print_success "IP адрес определен: $SERVER_IP"

    print_info "Определение домена через nslookup..."
    if command -v nslookup &> /dev/null; then
        SERVER_DOMAIN=$(nslookup "$SERVER_IP" 2>/dev/null | grep 'name =' | awk '{print $4}' | sed 's/\.$//' | head -1)
        if [[ -z "$SERVER_DOMAIN" ]]; then
            SERVER_DOMAIN=$(nslookup "$SERVER_IP" 2>/dev/null | grep -E "^$SERVER_IP" | awk '{print $2}' | sed 's/\.$//' | head -1)
        fi
    fi

    if [[ -z "$SERVER_DOMAIN" ]]; then
        print_warning "Не удалось определить домен через nslookup"
        SERVER_DOMAIN=$(hostname -f 2>/dev/null || hostname)
        print_info "Используется hostname: $SERVER_DOMAIN"
    else
        print_success "Домен определен: $SERVER_DOMAIN"
    fi

    # Инициализация путей к сертификатам после определения домена
    VAULT_CRT_FILE="${VAULT_CERTS_DIR}/server.crt"
    VAULT_KEY_FILE="${VAULT_CERTS_DIR}/server.key"

    save_environment_variables
}

save_environment_variables() {
    print_step "Сохранение сетевых переменных в окружение"
    ensure_working_directory
    local env_dir
    env_dir=$(dirname "$ENV_FILE")
    mkdir -p "$env_dir"
    "$WRAPPERS_DIR/config_writer_launcher.sh" "$ENV_FILE" << EOF
# Мониторинговые переменные сервера (создано $(date))
MONITOR_SERVER_IP=$SERVER_IP
MONITOR_SERVER_DOMAIN=$SERVER_DOMAIN
MONITOR_INSTALL_DATE=$DATE_INSTALL
MONITOR_INSTALL_DIR=$INSTALL_DIR
EOF
    export MONITOR_SERVER_IP="$SERVER_IP"
    export MONITOR_SERVER_DOMAIN="$SERVER_DOMAIN"
    export MONITOR_INSTALL_DATE="$DATE_INSTALL"
    export MONITOR_INSTALL_DIR="$INSTALL_DIR"
    print_success "Переменные сохранены в $ENV_FILE"
    print_info "IP: $SERVER_IP, Домен: $SERVER_DOMAIN"
}

cleanup_all_previous() {
    print_step "Полная очистка предыдущих установок"
    ensure_working_directory
    local services=("prometheus" "grafana-server" "harvest" "harvest-prometheus")
    for service in "${services[@]}"; do
        if systemctl is-active --quiet "$service" 2>/dev/null; then
            print_info "Остановка сервиса: $service"
            systemctl stop "$service" || true
        fi
        if systemctl is-enabled --quiet "$service" 2>/dev/null; then
            print_info "Отключение автозапуска: $service"
            systemctl disable "$service" || true
        fi
    done

    # Убираем остановку vault - он уже установлен и работает
    print_info "Vault оставляем без изменений (предполагается что уже установлен и настроен)"

    if command -v harvest &> /dev/null; then
        print_info "Остановка Harvest через команду"
        harvest stop --config "$HARVEST_CONFIG" 2>/dev/null || true
    fi

    local packages=("prometheus" "grafana" "harvest")
    for package in "${packages[@]}"; do
        if rpm -q "$package" &>/dev/null; then
            print_info "Удаление пакета: $package"
            rpm -e "$package" --nodeps >/dev/null 2>&1 || true
        fi
    done

    local dirs_to_clean=(
        "/etc/prometheus"
        "/etc/grafana"
        "/etc/harvest"
        "/opt/harvest"
        "/var/lib/prometheus"
        "/var/lib/grafana"
        "/var/lib/harvest"
        "/usr/share/grafana"
        "/usr/share/prometheus"
    )


    for dir in "${dirs_to_clean[@]}"; do
        if [[ -d "$dir" ]]; then
            print_info "Удаление директории: $dir"
            rm -rf "$dir" || true
        fi
    done

    local files_to_clean=(
        "/usr/lib/systemd/system/prometheus.service"
        "/usr/lib/systemd/system/grafana-server.service"
        "/usr/lib/systemd/system/harvest.service"
        "/usr/lib/systemd/system/harvest-prometheus.service"
        "/etc/systemd/system/prometheus.service"
        "/etc/systemd/system/grafana-server.service"
        "/etc/systemd/system/harvest.service"
        "/usr/bin/harvest"
        "/usr/local/bin/harvest"
    )

    for file in "${files_to_clean[@]}"; do
        if [[ -f "$file" ]]; then
            print_info "Удаление файла: $file"
            rm -rf "$file" || true
        fi
    done




    systemctl daemon-reload >/dev/null 2>&1
    print_success "Полная очистка завершена"
}

check_dependencies() {
    print_step "Проверка необходимых зависимостей"
    ensure_working_directory
    local missing_deps=()
    # УБИРАЕМ vault из списка зависимостей
    local deps=("curl" "rpm" "systemctl" "nslookup" "iptables" "jq" "ss" "openssl")

    for dep in "${deps[@]}"; do
        if ! command -v "$dep" &> /dev/null; then
            missing_deps+=("$dep")
        fi
    done

    if [[ ${#missing_deps[@]} -gt 0 ]]; then
        print_error "Отсутствуют необходимые зависимости: ${missing_deps[*]}"
        exit 1
    fi

    print_success "Все зависимости доступны"
}

create_directories() {
    print_step "Создание рабочих директорий"
    ensure_working_directory
    print_info "Создание директории: $INSTALL_DIR"
    mkdir -p "$INSTALL_DIR" || {
        print_error "Ошибка создания $INSTALL_DIR"
        return 1
    }
    print_success "Рабочие директории созданы"
}

setup_vault_config() {
    print_step "Настройка Vault конфигурации"
    ensure_working_directory

    # Проверяем, что SERVER_DOMAIN определен
    if [[ -z "$SERVER_DOMAIN" ]]; then
        print_error "SERVER_DOMAIN не определен. Запустите detect_network_info() сначала."
        exit 1
    fi

    mkdir -p "$VAULT_CONF_DIR" "$VAULT_LOG_DIR" "$VAULT_CERTS_DIR"
    # Ищем временный JSON с cred в известных местах (учитываем запуск под sudo)
    local cred_json_path=""
    for candidate in "$LOCAL_CRED_JSON" "$PWD/temp_data_cred.json" "$(dirname "$0")/temp_data_cred.json" "/home/${SUDO_USER:-}/temp_data_cred.json" "/tmp/temp_data_cred.json"; do
        if [[ -n "$candidate" && -f "$candidate" ]]; then
            cred_json_path="$candidate"
            break
        fi
    done
    if [[ -z "$cred_json_path" ]]; then
        print_error "Временный файл с учетными данными не найден (проверены стандартные пути)"
        exit 1
    fi
    # Пишем role_id/secret_id напрямую из JSON в файлы, без использования переменных
    jq -re '."vault-agent".role_id' "$cred_json_path" > "$VAULT_ROLE_ID_FILE" || {
        print_error "Не удалось извлечь role_id из $LOCAL_CRED_JSON"
        exit 1
    }
    jq -re '."vault-agent".secret_id' "$cred_json_path" > "$VAULT_SECRET_ID_FILE" || {
        print_error "Не удалось извлечь secret_id из $LOCAL_CRED_JSON"
        exit 1
    }
    # Права только на файлы (директории оставляем как настроил RLM)
    chmod 640 "$VAULT_ROLE_ID_FILE" "$VAULT_SECRET_ID_FILE" 2>/dev/null || true
    # Приводим владельца/группу каталога certs и файлов role_id/secret_id к тем же, что у conf
    if [[ -d "$VAULT_CONF_DIR" && -d "$VAULT_CERTS_DIR" ]]; then
        /usr/bin/chown --reference=/opt/vault/conf /opt/vault/certs 2>/dev/null || true
        /usr/bin/chmod --reference=/opt/vault/conf /opt/vault/certs 2>/dev/null || true
        /usr/bin/chown --reference=/opt/vault/conf /opt/vault/conf/role_id.txt /opt/vault/conf/secret_id.txt 2>/dev/null || true
    fi

    "$WRAPPERS_DIR/config_writer_launcher.sh" "$VAULT_AGENT_HCL" << EOF
pid_file = "/opt/vault/log/vault-agent.pidfile"
vault {
 address = "https://$SEC_MAN_ADDR"
 tls_skip_verify = "false"
 ca_path = "/opt/vault/conf/ca-trust"
}
auto_auth {
 method "approle" {
 namespace = "$NAMESPACE_CI"
 mount_path = "auth/approle"

 config = {
 role_id_file_path = "/opt/vault/conf/role_id.txt"
 secret_id_file_path = "/opt/vault/conf/secret_id.txt"
 remove_secret_id_file_after_reading = false
}
}
}
log_destination "Tengry" {
 log_format = "json"
 log_path = "/opt/vault/log"
 log_rotate = "5"
 log_max_size = "5mb"
 log_level = "trace"
 log_file = "agent.log"
}

template {
  destination = "/tmp/data_sec.json"
  contents    = <<EOT
{
  "rpm_url": {
    {{ with secret "$RPM_URL_KV" }}
    "harvest": {{ .Data.harvest | toJSON }},
    "prometheus": {{ .Data.prometheus | toJSON }},
    "grafana": {{ .Data.grafana | toJSON }}
    {{ end }}
  },
  "tuz": {
    {{ with secret "$TUZ_KV" }}
    "pass": {{ .Data.pass | toJSON }},
    "user": {{ .Data.user | toJSON }}
    {{ end }}
  },
  "netapp_ssh": {
    {{ with secret "$NETAPP_SSH_KV" }}
    "addr": {{ .Data.addr | toJSON }},
    "user": {{ .Data.user | toJSON }},
    "pass": {{ .Data.pass | toJSON }}
    {{ end }}
  },
  "mon_ssh": {
    {{ with secret "$MON_SSH_KV" }}
    "addr": {{ .Data.addr | toJSON }},
    "user": {{ .Data.user | toJSON }},
    "pass": {{ .Data.pass | toJSON }}
    {{ end }}
  },
  "netapp_api": {
    {{ with secret "$NETAPP_API_KV" }}
    "addr": {{ .Data.addr | toJSON }},
    "user": {{ .Data.user | toJSON }},
    "pass": {{ .Data.pass | toJSON }}
    {{ end }}
  },
  "grafana_web": {
    {{ with secret "$GRAFANA_WEB_KV" }}
    "user": {{ .Data.user | toJSON }},
    "pass": {{ .Data.pass | toJSON }}
    {{ end }}
  },
  "vault-agent": {
    {{ with secret "$VAULT_AGENT_KV" }}
    "role_id": {{ .Data.role_id | toJSON }},
    "secret_id": {{ .Data.secret_id | toJSON }}
    {{ end }}
  }
}
  EOT
  perms = "0640"
  # Если какой-то из KV/ключей отсутствует, не роняем vault-agent,
  # а просто пропускаем этот блок. Обязательные значения (role_id/secret_id)
  # дополнительно проверяются в bash перед перезапуском агента.
  error_on_missing_key = false
}

template {
  destination = "/opt/vault/certs/server_bundle.pem"
  contents    = <<EOT
{{- with secret "$SBERCA_CERT_KV" "common_name=${SERVER_DOMAIN}" "email=$ADMIN_EMAIL" "alt_names=${SERVER_DOMAIN}" -}}
{{ .Data.private_key }}
{{ .Data.certificate }}
{{ .Data.issuing_ca }}
{{- end -}}
  EOT
  perms = "0600"
}

template {
  destination = "/opt/vault/certs/ca_chain.crt"
  contents = <<EOT
{{- with secret "$SBERCA_CERT_KV" "common_name=${SERVER_DOMAIN}" "email=$ADMIN_EMAIL" -}}
{{ .Data.issuing_ca }}
{{- end -}}
  EOT
  perms = "0640"
}

template {
  destination = "/opt/vault/certs/grafana-client.pem"
  contents = <<EOT
{{- with secret "$SBERCA_CERT_KV" "common_name=${SERVER_DOMAIN}" "email=$ADMIN_EMAIL" "alt_names=${SERVER_DOMAIN}" -}}
{{ .Data.private_key }}
{{ .Data.certificate }}
{{ .Data.issuing_ca }}
{{- end -}}
  EOT
  perms = "0600"
}

EOF

    # Перезапуск vault-agent с проверкой
    print_step "Перезапуск vault-agent"

    if systemctl restart vault-agent; then
        sleep 5
        if systemctl is-active --quiet vault-agent; then
            print_success "Vault конфигурация создана и сервис перезапущен"
            # Удаляем временный файл с чувствительными данными (возможные локации)
            rm -rf "$LOCAL_CRED_JSON" "/home/${SUDO_USER:-}/temp_data_cred.json" "$PWD/temp_data_cred.json" "$(dirname "$0")/temp_data_cred.json" "/tmp/temp_data_cred.json" || true
        else
            print_error "vault-agent не активен после перезапуска"
            systemctl status vault-agent --no-pager
            exit 1
        fi
    else
        print_error "Ошибка при перезапуске vault-agent"
        systemctl status vault-agent --no-pager
        exit 1
    fi
}

load_config_from_json() {
    print_step "Загрузка конфигурации из параметров Jenkins"
    ensure_working_directory
    local missing=()
    [[ -z "$NETAPP_API_ADDR" ]] && missing+=("NETAPP_API_ADDR")
    [[ -z "$GRAFANA_URL" ]] && missing+=("GRAFANA_URL")
    [[ -z "$PROMETHEUS_URL" ]] && missing+=("PROMETHEUS_URL")
    [[ -z "$HARVEST_URL" ]] && missing+=("HARVEST_URL")

    if (( ${#missing[@]} > 0 )); then
        print_error "Не заданы обязательные параметры Jenkins: ${missing[*]}"
        exit 1
    fi

    NETAPP_POLLER_NAME=$(echo "$NETAPP_API_ADDR" | awk -F'.' '{print toupper(substr($1,1,1)) tolower(substr($1,2))}')
    print_success "Конфигурация загружена из параметров Jenkins"
    print_info "NETAPP_API_ADDR=$NETAPP_API_ADDR, NETAPP_POLLER_NAME=$NETAPP_POLLER_NAME"
}

copy_certs_to_dirs() {
    print_step "Копирование сертификатов в целевые директории"
    ensure_working_directory

    # Создание папок и копирование для harvest
    mkdir -p /opt/harvest/cert
    if id harvest >/dev/null 2>&1; then
        chown harvest:harvest /opt/harvest/cert
    else
        print_warning "Пользователь harvest не найден, пропускаем chown для /opt/harvest/cert"
    fi
    # Разрезаем PEM на crt/key, чтобы гарантировать соответствие пары
    if [[ -f "/opt/vault/certs/server_bundle.pem" ]]; then
        openssl pkey -in "/opt/vault/certs/server_bundle.pem" -out "/opt/harvest/cert/harvest.key" 2>/dev/null
        openssl crl2pkcs7 -nocrl -certfile "/opt/vault/certs/server_bundle.pem" | openssl pkcs7 -print_certs -out "/opt/harvest/cert/harvest.crt" 2>/dev/null
    else
        cp "$VAULT_CRT_FILE" /opt/harvest/cert/harvest.crt
        cp "$VAULT_KEY_FILE" /opt/harvest/cert/harvest.key
    fi
    if id harvest >/dev/null 2>&1; then
        chown harvest:harvest /opt/harvest/cert/harvest.*
    fi
    chmod 640 /opt/harvest/cert/harvest.crt
    chmod 600 /opt/harvest/cert/harvest.key

    # Для grafana
    mkdir -p /etc/grafana/cert
    if id grafana >/dev/null 2>&1; then
        chown root:grafana /etc/grafana/cert
    else
        print_warning "Пользователь grafana не найден, пропускаем chown для /etc/grafana/cert"
    fi
    if [[ -f "/opt/vault/certs/server_bundle.pem" ]]; then
        openssl pkey -in "/opt/vault/certs/server_bundle.pem" -out "/etc/grafana/cert/key.key" 2>/dev/null
        openssl crl2pkcs7 -nocrl -certfile "/opt/vault/certs/server_bundle.pem" | openssl pkcs7 -print_certs -out "/etc/grafana/cert/crt.crt" 2>/dev/null
    else
        cp "$VAULT_CRT_FILE" /etc/grafana/cert/crt.crt
        cp "$VAULT_KEY_FILE" /etc/grafana/cert/key.key
    fi
    if id grafana >/dev/null 2>&1; then
        /usr/bin/chown root:grafana /etc/grafana/cert/crt.crt
        /usr/bin/chown root:grafana /etc/grafana/cert/key.key
    fi
    chmod 640 /etc/grafana/cert/crt.crt
    chmod 640 /etc/grafana/cert/key.key

    # Для prometheus
    mkdir -p /etc/prometheus/cert
    if id prometheus >/dev/null 2>&1; then
        chown prometheus:prometheus /etc/prometheus/cert
    else
        print_warning "Пользователь prometheus не найден, пропускаем chown для /etc/prometheus/cert"
    fi
    if [[ -f "/opt/vault/certs/server_bundle.pem" ]]; then
        openssl pkey -in "/opt/vault/certs/server_bundle.pem" -out "/etc/prometheus/cert/server.key" 2>/dev/null
        openssl crl2pkcs7 -nocrl -certfile "/opt/vault/certs/server_bundle.pem" | openssl pkcs7 -print_certs -out "/etc/prometheus/cert/server.crt" 2>/dev/null
    else
        cp "$VAULT_CRT_FILE" /etc/prometheus/cert/server.crt
        cp "$VAULT_KEY_FILE" /etc/prometheus/cert/server.key
    fi
    if id prometheus >/dev/null 2>&1; then
        chown prometheus:prometheus /etc/prometheus/cert/server.*
    fi
    chmod 640 /etc/prometheus/cert/server.crt
    chmod 600 /etc/prometheus/cert/server.key
    # Копируем CA-цепочку для проверки клиентских сертификатов
    local ca_src=""
    if [[ -f /opt/vault/certs/ca_chain.crt ]]; then
        ca_src="/opt/vault/certs/ca_chain.crt"
    elif [[ -f /opt/vault/certs/ca_chain ]]; then
        ca_src="/opt/vault/certs/ca_chain"
    fi
    if [[ -n "$ca_src" ]]; then
        cp "$ca_src" /etc/prometheus/cert/ca_chain.crt
        if id prometheus >/dev/null 2>&1; then
            chown prometheus:prometheus /etc/prometheus/cert/ca_chain.crt
        fi
        chmod 644 /etc/prometheus/cert/ca_chain.crt
    else
        print_warning "CA chain не найдена (/opt/vault/certs/ca_chain[.crt])"
    fi

    # Для Grafana client cert (используется в secureJsonData)
    if [[ -f "/opt/vault/certs/grafana-client.pem" ]]; then
        chmod 600 "/opt/vault/certs/grafana-client.pem" || true
        # Также подготовим .crt/.key рядом для curl/диагностики
        openssl pkey -in "/opt/vault/certs/grafana-client.pem" -out "/opt/vault/certs/grafana-client.key" 2>/dev/null || true
        openssl crl2pkcs7 -nocrl -certfile "/opt/vault/certs/grafana-client.pem" | openssl pkcs7 -print_certs -out "/opt/vault/certs/grafana-client.crt" 2>/dev/null || true
    fi

    print_success "Сертификаты скопированы и проверены"
}

configure_grafana_ini() {
    print_step "Конфигурация grafana.ini"
    ensure_working_directory
    "$WRAPPERS_DIR/config_writer_launcher.sh" /etc/grafana/grafana.ini << EOF
[server]
protocol = https
http_port = ${GRAFANA_PORT}
domain = ${SERVER_DOMAIN}
 cert_file = /etc/grafana/cert/crt.crt
 cert_key = /etc/grafana/cert/key.key

[security]
allow_embedding = true
EOF
    /usr/bin/chown root:grafana /etc/grafana/grafana.ini
    chmod 640 /etc/grafana/grafana.ini
    print_success "grafana.ini настроен"
}

configure_grafana_ini_no_ssl() {
    print_step "Конфигурация grafana.ini (без SSL)"
    ensure_working_directory
    "$WRAPPERS_DIR/config_writer_launcher.sh" /etc/grafana/grafana.ini << EOF
[server]
protocol = http
http_port = ${GRAFANA_PORT}
domain = ${SERVER_DOMAIN}

[security]
allow_embedding = true
EOF
    /usr/bin/chown root:grafana /etc/grafana/grafana.ini
    chmod 640 /etc/grafana/grafana.ini
    print_success "grafana.ini настроен (без SSL)"
}

configure_prometheus_files() {
    print_step "Создание файлов для Prometheus"
    ensure_working_directory
    "$WRAPPERS_DIR/config_writer_launcher.sh" /etc/prometheus/web-config.yml << EOF
tls_server_config:
  cert_file: /etc/prometheus/cert/server.crt
  key_file: /etc/prometheus/cert/server.key
  min_version: "TLS12"
  # Внимание: список cipher_suites применяется только к TLS 1.2 (TLS 1.3 не настраивается в Go)
  cipher_suites:
    - TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
    - TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256
  client_auth_type: "RequireAndVerifyClientCert"
  client_ca_file: "/etc/prometheus/cert/ca_chain.crt"
  client_allowed_sans:
    - "${SERVER_DOMAIN}"
EOF
    "$WRAPPERS_DIR/config_writer_launcher.sh" /etc/prometheus/prometheus.env << EOF
PROMETHEUS_OPTS="--config.file=/etc/prometheus/prometheus.yml --storage.tsdb.path=/var/lib/prometheus/data --web.console.templates=/etc/prometheus/consoles --web.console.libraries=/etc/prometheus/console_libraries --web.config.file=/etc/prometheus/web-config.yml --web.external-url=https://${SERVER_DOMAIN}:${PROMETHEUS_PORT}/ --web.listen-address=0.0.0.0:${PROMETHEUS_PORT}"
EOF
    chown prometheus:prometheus /etc/prometheus/web-config.yml /etc/prometheus/prometheus.env
    chmod 640 /etc/prometheus/web-config.yml /etc/prometheus/prometheus.env
    print_success "Файлы Prometheus созданы"
}

configure_prometheus_files_no_ssl() {
    print_step "Создание файлов для Prometheus (без SSL)"
    ensure_working_directory
    "$WRAPPERS_DIR/config_writer_launcher.sh" /etc/prometheus/prometheus.env << EOF
PROMETHEUS_OPTS="--config.file=/etc/prometheus/prometheus.yml --storage.tsdb.path=/var/lib/prometheus/data --web.console.templates=/etc/prometheus/consoles --web.console.libraries=/etc/prometheus/console_libraries --web.external-url=http://${SERVER_DOMAIN}:${PROMETHEUS_PORT}/ --web.listen-address=0.0.0.0:${PROMETHEUS_PORT}"
EOF
    chown prometheus:prometheus /etc/prometheus/prometheus.env
    chmod 640 /etc/prometheus/prometheus.env
    print_success "Файлы Prometheus созданы (без SSL)"
}

create_rlm_install_tasks() {
    print_step "Создание задач RLM для установки пакетов"
    ensure_working_directory

    if [[ -z "$RLM_TOKEN" || -z "$RLM_API_URL" ]]; then
        print_error "RLM API токен или URL не задан (RLM_TOKEN/RLM_API_URL)"
        exit 1
    fi

    # Создание задач для всех RPM пакетов
    local packages=(
        "$GRAFANA_URL|Grafana"
        "$PROMETHEUS_URL|Prometheus"
        "$HARVEST_URL|Harvest"
    )

    for package in "${packages[@]}"; do
        IFS='|' read -r url name <<< "$package"

        print_info "Создание задачи для $name..."
        if [[ -z "$url" ]]; then
            print_warning "URL пакета для $name не задан (пусто)"
        else
            print_info "📦 Устанавливаемый RPM: $url"
        fi

        local response
        local payload
        payload=$(jq -n           --arg url "$url"           --arg ip "$SERVER_IP"           '{
            params: { url: $url, reinstall_is_allowed: true },
            start_at: "now",
            service: "LINUX_RPM_INSTALLER",
            items: [ { table_id: "linuxrpminstallertable", invsvm_ip: $ip } ]
          }')
        if [[ ! -x "$WRAPPERS_DIR/rlm_launcher.sh" ]]; then
            print_error "Лаунчер rlm_launcher.sh не найден или не исполняемый в $WRAPPERS_DIR"
            exit 1
        fi

        response=$(printf '%s' "$payload" | "$WRAPPERS_DIR/rlm_launcher.sh" create_rpm_task "$RLM_API_URL" "$RLM_TOKEN") || true

        # Получаем ID задачи
        local task_id
        task_id=$(echo "$response" | jq -r '.id // empty')
        if [[ -z "$task_id" || "$task_id" == "null" ]]; then
            print_error "❌ Ошибка при создании задачи для $name: $response"
            print_error "❌ URL пакета: ${url:-не задан}"
            exit 1
        fi
        print_success "✅ Задача создана для $name. ID: $task_id"
        print_info "📦 Устанавливаемый RPM: $url"

        # Мониторинг статуса задачи (последовательно)
        print_step "Мониторинг статуса задачи RLM: $name (ID: $task_id)"
        local max_attempts=30
        local attempt=1
        while [[ $attempt -le $max_attempts ]]; do
            print_info "Проверка статуса $name (попытка $attempt/$max_attempts)..."
            local status_response
            status_response=$("$WRAPPERS_DIR/rlm_launcher.sh" get_rpm_status "$RLM_API_URL" "$RLM_TOKEN" "$task_id") || true

            if echo "$status_response" | grep -q '"status":"success"'; then
                print_success "🎉 ЗАДАЧА $name УСПЕШНО ЗАВЕРШЕНА!"
                # Сохраняем ID задачи по имени
                case "$name" in
                    "Grafana")
                        RLM_ID_TASK_GRAFANA="$task_id"
                        export RLM_ID_TASK_GRAFANA
                        ;;
                    "Prometheus")
                        RLM_ID_TASK_PROMETHEUS="$task_id"
                        export RLM_ID_TASK_PROMETHEUS
                        ;;
                    "Harvest")
                        RLM_ID_TASK_HARVEST="$task_id"
                        export RLM_ID_TASK_HARVEST
                        ;;
                esac
                break
            elif echo "$status_response" | grep -q '"status":"failed"'; then
                print_error "💥 ЗАДАЧА $name ЗАВЕРШИЛАСЬ С ОШИБКОЙ"
                print_error "❌ URL пакета: $url"
                print_error "📋 Ответ RLM: $status_response"
                exit 1
            elif echo "$status_response" | grep -q '"status":"error"'; then
                print_error "💥 ЗАДАЧА $name ЗАВЕРШИЛАСЬ С ОШИБКОЙ"
                print_error "❌ URL пакета: $url"
                print_error "📋 Ответ RLM: $status_response"
                exit 1
            else
                local current_status
                current_status=$(echo "$status_response" | jq -r '.status // empty' 2>/dev/null ||                     echo "$status_response" | grep -o '"status":"[^"]*"' | head -1 | cut -d'"' -f4 | tr -d '
' | xargs)
                if [[ -n "$current_status" ]]; then
                    print_info "Текущий статус $name: $current_status"
                else
                    print_info "Статус $name: в процессе..."
                fi
            fi

            attempt=$((attempt + 1))
            sleep 10
        done

        if [[ $attempt -gt $max_attempts ]]; then
            print_error "⏰ $name: ТАЙМАУТ (ID: $task_id)"
            print_error "   Превышено время ожидания (300 секунд)"
            exit 1
        fi

        # Пауза 3 секунды после успешной задачи
        sleep 3
    done

    print_success "🎉 ВСЕ ЗАДАЧИ УСПЕШНО ЗАВЕРШЕНЫ!"
    print_success "✅ Все RPM пакеты успешно установлены на сервер $SERVER_IP"

    # Настройка PATH для Harvest (как в локальной установке)
    print_info "Настройка PATH для Harvest"
    if [[ -f "/opt/harvest/bin/harvest" ]]; then
        ln -sf /opt/harvest/bin/harvest /usr/local/bin/harvest || true
        print_success "Создана символическая ссылка для harvest в /usr/local/bin/"
    elif [[ -f "/opt/harvest/harvest" ]]; then
        ln -sf /opt/harvest/harvest /usr/local/bin/harvest || true
        print_success "Создана символическая ссылка для harvest в /usr/local/bin/"
    else
        print_warning "Исполняемый файл harvest не найден в стандартных путях"
    fi
    cat > /etc/profile.d/harvest.sh << 'HARVEST_EOF'
# Harvest PATH configuration
export PATH=$PATH:/opt/harvest/bin:/opt/harvest
HARVEST_EOF
    chmod +x /etc/profile.d/harvest.sh
    export PATH=$PATH:/usr/local/bin:/opt/harvest/bin:/opt/harvest
    print_success "PATH настроен для доступа к harvest из любого места"
}

setup_certificates_after_install() {
    print_step "Настройка сертификатов после установки пакетов"
    ensure_working_directory

    # Проверяем наличие сертификатов от vault-agent (.pem) или пары .crt/.key
    if [[ -f "/opt/vault/certs/server_bundle.pem" || ( -f "$VAULT_CRT_FILE" && -f "$VAULT_KEY_FILE" ) ]]; then
        print_success "Найдены сертификаты, копируем в целевые директории"
        copy_certs_to_dirs
        # Верифицируем наличие файлов для Prometheus
        if [[ -f "/etc/prometheus/cert/server.crt" && -f "/etc/prometheus/cert/server.key" ]]; then
            print_success "Проверка Prometheus сертификатов: файлы присутствуют"
        else
            print_error "Отсутствуют файлы Prometheus сертификатов в /etc/prometheus/cert/"
            print_error "Ожидались: server.crt и server.key"
            ls -l /etc/prometheus/cert || true
            exit 1
        fi
    else
        print_error "Сертификаты от Vault не найдены: ожидается /opt/vault/certs/server_bundle.pem или пара $VAULT_CRT_FILE/$VAULT_KEY_FILE"
        exit 1
    fi
}

configure_harvest() {
    print_step "Настройка Harvest"
    ensure_working_directory
    local harvest_config="$HARVEST_CONFIG"

    if [[ ! -d "/opt/harvest" ]]; then
        print_warning "Директория /opt/harvest еще не существует, пропускаем настройку"
        return 0
    fi

    if [[ -f "$harvest_config" ]]; then
        cp "$harvest_config" "${harvest_config}.bak.${DATE_INSTALL}"
        print_info "Создана резервная копия: ${harvest_config}.bak.${DATE_INSTALL}"
    fi

    cat > "$harvest_config" << HARVEST_CONFIG_EOF
Exporters:
    prometheus_unix:
        exporter: Prometheus
        local_http_addr: 0.0.0.0
        port: ${HARVEST_UNIX_PORT}
    prometheus_netapp_https:
        exporter: Prometheus
        local_http_addr: 0.0.0.0
        port: ${HARVEST_NETAPP_PORT}
        tls:
            cert_file: /opt/harvest/cert/harvest.crt
            key_file: /opt/harvest/cert/harvest.key
        http_listen_ssl: true
Defaults:
    collectors:
        - Zapi
        - ZapiPerf
        - Ems
    use_insecure_tls: false
Pollers:
    unix:
        datacenter: local
        addr: localhost
        collectors:
            - Unix
        exporters:
            - prometheus_unix
    ${NETAPP_POLLER_NAME}:
        datacenter: DC1
        addr: ${NETAPP_API_ADDR}
        auth_style: certificate_auth
        ssl_cert: /opt/harvest/cert/harvest.crt
        ssl_key: /opt/harvest/cert/harvest.key
        use_insecure_tls: false
        collectors:
            - Rest
            - RestPerf
        exporters:
            - prometheus_netapp_https
HARVEST_CONFIG_EOF

    print_success "Конфигурация Harvest обновлена в $HARVEST_CONFIG"

    print_info "Создание systemd сервиса для Harvest"
    "$WRAPPERS_DIR/config_writer_launcher.sh" /etc/systemd/system/harvest.service << 'HARVEST_SERVICE_EOF'
[Unit]
Description=NetApp Harvest Poller
After=network.target
[Service]
Type=oneshot
User=root
WorkingDirectory=/opt/harvest
ExecStart=/opt/harvest/bin/harvest start
ExecStop=/opt/harvest/bin/harvest stop
RemainAfterExit=yes
Environment="PATH=/usr/local/bin:/usr/bin:/bin:/opt/harvest/bin"
[Install]
WantedBy=multi-user.target
HARVEST_SERVICE_EOF

    systemctl daemon-reload >/dev/null 2>&1
    print_success "Systemd сервис для Harvest создан"
}

configure_prometheus() {
    print_step "Настройка Prometheus"
    ensure_working_directory
    local prometheus_config="/etc/prometheus/prometheus.yml"

    "$WRAPPERS_DIR/config_writer_launcher.sh" "$prometheus_config" << PROMETHEUS_CONFIG_EOF
global:
  scrape_interval: 60s
  evaluation_interval: 60s
  scrape_timeout: 30s

scrape_configs:
  - job_name: 'prometheus'
    scheme: https
    tls_config:
      cert_file: /etc/prometheus/cert/server.crt
      key_file: /etc/prometheus/cert/server.key
      ca_file: /etc/prometheus/cert/ca_chain.crt
      insecure_skip_verify: false
    static_configs:
      - targets: ['${SERVER_DOMAIN}:${PROMETHEUS_PORT}']
    metrics_path: /metrics
    scrape_interval: 60s

  - job_name: 'harvest-unix'
    static_configs:
      - targets: ['localhost:${HARVEST_UNIX_PORT}']
    metrics_path: /metrics
    scrape_interval: 30s

  - job_name: 'harvest-netapp-https'
    scheme: https
    tls_config:
      cert_file: /etc/prometheus/cert/server.crt
      key_file: /etc/prometheus/cert/server.key
      ca_file: /etc/prometheus/cert/ca_chain.crt
      insecure_skip_verify: false
    static_configs:
      - targets: ['${SERVER_DOMAIN}:${HARVEST_NETAPP_PORT}']
    metrics_path: /metrics
    scrape_interval: 60s
PROMETHEUS_CONFIG_EOF

    print_success "Конфигурация Prometheus обновлена"
}

configure_grafana_datasource() {
    print_step "Настройка Prometheus Data Source в Grafana"
    ensure_working_directory

    local grafana_url="https://${SERVER_DOMAIN}:${GRAFANA_PORT}"

    if [[ -z "$GRAFANA_BEARER_TOKEN" ]]; then
        print_error "GRAFANA_BEARER_TOKEN пуст. Сначала вызовите ensure_grafana_token"
        return 1
    fi

    if [[ ! -x "$WRAPPERS_DIR/grafana_launcher.sh" ]]; then
        print_error "Лаунчер grafana_launcher.sh не найден или не исполняемый в $WRAPPERS_DIR"
        exit 1
    fi

    # Проверяем наличие источника данных через API (по токену)
    local ds_status
    ds_status=$("$WRAPPERS_DIR/grafana_launcher.sh" ds_status_by_name "$grafana_url" "$GRAFANA_BEARER_TOKEN" "prometheus")

    local create_payload update_payload http_code
    create_payload=$(jq -n \
        --arg url "https://${SERVER_DOMAIN}:${PROMETHEUS_PORT}" \
        --arg sn  "${SERVER_DOMAIN}" \
        '{name:"prometheus", type:"prometheus", access:"proxy", url:$url, isDefault:true,
          jsonData:{httpMethod:"POST", serverName:$sn, tlsAuth:true, tlsAuthWithCACert:true, tlsSkipVerify:false}}')

    if [[ "$ds_status" == "200" ]]; then
        update_payload=$(jq -n \
            --arg url "https://${SERVER_DOMAIN}:${PROMETHEUS_PORT}" \
            --arg sn  "${SERVER_DOMAIN}" \
            '{name:"prometheus", type:"prometheus", access:"proxy", url:$url, isDefault:true,
              jsonData:{httpMethod:"POST", serverName:$sn, tlsAuth:true, tlsAuthWithCACert:true, tlsSkipVerify:false}}')
        http_code=$(printf '%s' "$update_payload" | \
            "$WRAPPERS_DIR/grafana_launcher.sh" ds_update_by_name "$grafana_url" "$GRAFANA_BEARER_TOKEN" "prometheus")
        if [[ "$http_code" == "200" || "$http_code" == "202" ]]; then
            print_success "Prometheus Data Source обновлён через API"
        else
            print_warning "Не удалось обновить Data Source через API (код $http_code)"
        fi
    else
        http_code=$(printf '%s' "$create_payload" | \
            "$WRAPPERS_DIR/grafana_launcher.sh" ds_create "$grafana_url" "$GRAFANA_BEARER_TOKEN")
        if [[ "$http_code" == "200" || "$http_code" == "202" ]]; then
            print_success "Prometheus Data Source создан через API"
        else
            print_error "Не удалось создать Data Source через API (код $http_code)"
            return 1
        fi
    fi
}

ensure_grafana_token() {
    print_step "Получение API токена Grafana (service account)"
    ensure_working_directory

    local grafana_url="https://${SERVER_DOMAIN}:${GRAFANA_PORT}"
    local grafana_user=""
    local grafana_password=""

    if [[ -n "$GRAFANA_BEARER_TOKEN" ]]; then
        print_info "Токен Grafana уже получен"
        return 0
    fi

    # Читаем учётные данные Grafana из файла, сформированного vault-agent (без использования env)
    local cred_json="/tmp/data_sec.json"
    if [[ ! -f "$cred_json" ]]; then
        print_error "Файл с секретами Vault (/tmp/data_sec.json) не найден"
        return 1
    fi

    grafana_user=$(jq -r '.grafana_web.user // empty' "$cred_json" 2>/dev/null || echo "")
    grafana_password=$(jq -r '.grafana_web.pass // empty' "$cred_json" 2>/dev/null || echo "")

    if [[ -z "$grafana_user" || -z "$grafana_password" ]]; then
        print_error "Не удалось получить учётные данные Grafana из /tmp/data_sec.json"
        return 1
    fi

    if [[ ! -x "$WRAPPERS_DIR/grafana_launcher.sh" ]]; then
        print_error "Лаунчер grafana_launcher.sh не найден или не исполняемый в $WRAPPERS_DIR"
        exit 1
    fi

    local timestamp service_account_name token_name payload_sa payload_token resp http_code body sa_id
    timestamp=$(date +%s)
    service_account_name="harvest-service-account_$timestamp"
    token_name="harvest-token_$timestamp"

    # Создаём сервисный аккаунт и извлекаем его id из ответа
    payload_sa=$(jq -n --arg name "$service_account_name" --arg role "Admin" '{name:$name, role:$role}')
    resp=$(printf '%s' "$payload_sa" | \
        "$WRAPPERS_DIR/grafana_launcher.sh" sa_create "$grafana_url" "$grafana_user" "$grafana_password") || true
    http_code="${resp##*$'\n'}"
    body="${resp%$'\n'*}"

    if [[ "$http_code" == "200" || "$http_code" == "201" ]]; then
        sa_id=$(echo "$body" | jq -r '.id // empty')
    elif [[ "$http_code" == "409" ]]; then
        # Уже существует; найдём id по имени
        local list_resp list_code list_body
        list_resp=$("$WRAPPERS_DIR/grafana_launcher.sh" sa_list "$grafana_url" "$grafana_user" "$grafana_password") || true
        list_code="${list_resp##*$'\n'}"
        list_body="${list_resp%$'\n'*}"
        if [[ "$list_code" == "200" ]]; then
            sa_id=$(echo "$list_body" | jq -r '.[] | select(.name=="'"$service_account_name"'") | .id' | head -1)
        fi
    else
        print_error "Не удалось создать сервисный аккаунт Grafana (HTTP $http_code)"
        return 1
    fi

    if [[ -z "$sa_id" || "$sa_id" == "null" ]]; then
        print_error "ID сервисного аккаунта не получен"
        return 1
    fi

    # Создаём токен и извлекаем ключ
    payload_token=$(jq -n --arg name "$token_name" '{name:$name}')
    local tok_resp tok_code tok_body token_value
    tok_resp=$(printf '%s' "$payload_token" | \
        "$WRAPPERS_DIR/grafana_launcher.sh" sa_token_create "$grafana_url" "$grafana_user" "$grafana_password" "$sa_id") || true
    tok_code="${tok_resp##*$'\n'}"
    tok_body="${tok_resp%$'\n'*}"

    if [[ "$tok_code" == "200" || "$tok_code" == "201" ]]; then
        token_value=$(echo "$tok_body" | jq -r '.key // empty')
    else
        print_error "Не удалось создать токен сервисного аккаунта (HTTP $tok_code)"
        return 1
    fi

    if [[ -z "$token_value" || "$token_value" == "null" ]]; then
        print_error "Пустой токен сервисного аккаунта"
        return 1
    fi

    GRAFANA_BEARER_TOKEN="$token_value"
    export GRAFANA_BEARER_TOKEN
    print_success "Получен токен Grafana"
}

configure_iptables() {
    print_step "Настройка iptables для мониторинговых сервисов"
    ensure_working_directory

    if [[ ! -x "$WRAPPERS_DIR/iptables_launcher.sh" ]]; then
        print_error "Лаунчер iptables_launcher.sh не найден или не исполняемый в $WRAPPERS_DIR"
        exit 1
    fi

    # Передаём параметры в обёртку, где реализована валидация и настройка
    "$WRAPPERS_DIR/iptables_launcher.sh" \
        "$PROMETHEUS_PORT" \
        "$GRAFANA_PORT" \
        "$HARVEST_UNIX_PORT" \
        "$HARVEST_NETAPP_PORT" \
        "$SERVER_IP"

    print_success "Настройка iptables завершена (через скрипт-обёртку)"
}

configure_services() {
    print_step "Настройка и запуск сервисов мониторинга"
    ensure_working_directory

    print_info "Проверка наличия сертификатов от Vault (обязательно для TLS)"
    if { [[ -f "$VAULT_CRT_FILE" && -f "$VAULT_KEY_FILE" ]] || [[ -f "/opt/vault/certs/server_bundle.pem" ]]; } && { [[ -f "/opt/vault/certs/ca_chain.crt" ]] || [[ -f "/opt/vault/certs/ca_chain" ]]; }; then
        print_success "Найдены сертификаты и CA chain"
        configure_grafana_ini
        configure_prometheus_files
    else
        print_error "Сертификаты не найдены. TLS обязателен согласно требованиям. Останавливаемся."
        exit 1
    fi

    print_info "Настройка сервиса: prometheus"
    systemctl enable prometheus >/dev/null 2>&1 || print_error "Ошибка включения автозапуска prometheus"
    systemctl restart prometheus >/dev/null 2>&1 || print_error "Ошибка запуска prometheus"
    sleep 2
    if systemctl is-active --quiet prometheus; then
        print_success "prometheus успешно запущен и настроен на автозапуск"
    else
        print_error "prometheus не удалось запустить"
        systemctl status prometheus --no-pager | while IFS= read -r line; do
            print_info "$line"
            log_message "[PROMETHEUS SYSTEMD STATUS] $line"
        done
    fi
    echo

    print_info "Настройка сервиса: grafana-server"
    systemctl enable grafana-server >/dev/null 2>&1 || print_error "Ошибка включения автозапуска grafana-server"
    systemctl restart grafana-server >/dev/null 2>&1 || print_error "Ошибка запуска grafana-server"
    sleep 2
    if systemctl is-active --quiet grafana-server; then
        print_success "grafana-server успешно запущен и настроен на автозапуск"
        # Ранее здесь был configure_grafana_datasource — перенесено после получения токена
    else
        print_error "grafana-server не удалось запустить"
        systemctl status grafana-server --no-pager | while IFS= read -r line; do
            print_info "$line"
            log_message "[GRAFANA SYSTEMD STATUS] $line"
        done
    fi
    echo

    print_info "Настройка и запуск Harvest..."
    if systemctl is-active --quiet harvest 2>/dev/null; then
        print_info "Остановка текущего сервиса harvest"
        systemctl stop harvest >/dev/null 2>&1 || print_warning "Не удалось остановить сервис harvest"
        sleep 2
    fi

    if command -v harvest &> /dev/null; then
        print_info "Остановка любых существующих процессов Harvest через команду"
        harvest stop --config "$HARVEST_CONFIG" >/dev/null 2>&1 || true
        sleep 2
    fi

    print_info "Проверка порта $HARVEST_NETAPP_PORT перед запуском Harvest"
    if ss -tln | grep -q ":$HARVEST_NETAPP_PORT "; then
        print_warning "Порт $HARVEST_NETAPP_PORT все еще занят"
        local pids
        pids=$(ss -tlnp | grep ":$HARVEST_NETAPP_PORT " | awk -F, '{for(i=1;i<=NF;i++) if ($i ~ /pid=/) {print $i}}' | awk -F= '{print $2}' | sort -u)
        if [[ -n "$pids" ]]; then
            for pid in $pids; do
                print_info "Завершение процесса с PID $pid, использующего порт $HARVEST_NETAPP_PORT"
                ps -p "$pid" -o pid,ppid,cmd --no-headers | while read -r pid ppid cmd; do
                    print_info "PID: $pid, PPID: $ppid, Команда: $cmd"
                    log_message "PID: $pid, PPID: $ppid, Команда: $cmd"
                done
                kill -TERM "$pid" 2>/dev/null || print_warning "Не удалось отправить SIGTERM процессу $pid"
                sleep 2
                if kill -0 "$pid" 2>/dev/null; then
                    print_info "Процесс $pid не завершился, отправляем SIGKILL"
                    kill -9 "$pid" 2>/dev/null || print_warning "Не удалось завершить процесс $pid с SIGKILL"
                fi
            done
            sleep 2
            if ss -tln | grep -q ":$HARVEST_NETAPP_PORT "; then
                print_error "Не удалось освободить порт $HARVEST_NETAPP_PORT"
                ss -tlnp | grep ":$HARVEST_NETAPP_PORT " | while read -r line; do
                    print_info "$line"
                    log_message "Порт $HARVEST_NETAPP_PORT все еще занят: $line"
                done
                exit 1
            fi
        else
            print_warning "Не удалось найти процессы для порта $HARVEST_NETAPP_PORT"
        fi
    fi

    print_info "Запуск сервиса harvest через systemd"
    systemctl enable harvest >/dev/null 2>&1 || print_warning "Не удалось включить автозапуск harvest"
    systemctl restart harvest >/dev/null 2>&1 || print_error "Ошибка запуска harvest"
    sleep 10

    if systemctl is-active --quiet harvest; then
        print_success "harvest успешно запущен и настроен на автозапуск"
        print_info "Проверка статуса поллеров Harvest:"
        harvest status --config "$HARVEST_CONFIG" 2>/dev/null | while IFS= read -r line; do
            print_info "$line"
            log_message "[HARVEST STATUS] $line"
        done
        if harvest status --config "$HARVEST_CONFIG" 2>/dev/null | grep -q "${NETAPP_POLLER_NAME}.*not running"; then
            print_error "Поллер ${NETAPP_POLLER_NAME} не запущен"
            print_info "Лог Harvest для ${NETAPP_POLLER_NAME}: /var/log/harvest/poller_${NETAPP_POLLER_NAME}.log"
            exit 1
        fi
    else
        print_error "harvest не удалось запустить"
        systemctl status harvest --no-pager | while IFS= read -r line; do
            print_info "$line"
            log_message "[HARVEST SYSTEMD STATUS] $line"
        done
        exit 1
    fi
}

import_grafana_dashboards() {
    print_step "Импорт дашбордов Harvest в Grafana"
    ensure_working_directory
    print_info "Ожидание запуска Grafana..."
    sleep 10

    local grafana_url="https://${SERVER_DOMAIN}:${GRAFANA_PORT}"

    # Обеспечим наличие токена (если ещё не получен)
    if [[ -z "$GRAFANA_BEARER_TOKEN" ]]; then
        ensure_grafana_token || return 1
    fi

    if [[ ! -x "$WRAPPERS_DIR/grafana_launcher.sh" ]]; then
        print_error "Лаунчер grafana_launcher.sh не найден или не исполняемый в $WRAPPERS_DIR"
        return 1
    fi

    print_info "Получение UID источника данных..."
    local ds_resp uid_datasource
    ds_resp=$("$WRAPPERS_DIR/grafana_launcher.sh" ds_list "$grafana_url" "$GRAFANA_BEARER_TOKEN" || true)
    uid_datasource=$(echo "$ds_resp" | jq -er '.[0].uid' 2>/dev/null || echo "")

    if [[ "$uid_datasource" == "null" || -z "$uid_datasource" ]]; then
        print_warning "UID источника данных не получен (продолжаем)"
        log_message "[GRAFANA IMPORT WARNING] Не удалось разобрать ответ /api/datasources"
    else
        print_success "UID источника данных: $uid_datasource"
    fi

    # Устанавливаем secureJsonData (mTLS) через API
    print_info "Обновление Prometheus datasource через API для установки mTLS..."
    local ds_obj ds_id payload update_resp
    ds_obj=$("$WRAPPERS_DIR/grafana_launcher.sh" ds_get_by_name "$grafana_url" "$GRAFANA_BEARER_TOKEN" "prometheus" || true)
    ds_id=$(echo "$ds_obj" | jq -er '.id' 2>/dev/null || echo "")

    if [[ -z "$ds_id" ]]; then
        print_warning "Не удалось получить ID источника данных по имени, пробуем список"
        ds_id=$("$WRAPPERS_DIR/grafana_launcher.sh" ds_list "$grafana_url" "$GRAFANA_BEARER_TOKEN" | jq -er '.[] | select(.name=="prometheus") | .id' 2>/dev/null || echo "")
    fi

    if [[ -n "$ds_id" ]]; then
        payload=$(jq -n \
            --arg url "https://${SERVER_DOMAIN}:${PROMETHEUS_PORT}" \
            --arg sn  "${SERVER_DOMAIN}" \
            --rawfile tlsClientCert "/opt/vault/certs/grafana-client.crt" \
            --rawfile tlsClientKey  "/opt/vault/certs/grafana-client.key" \
            --rawfile tlsCACert     "/etc/prometheus/cert/ca_chain.crt" \
            '{name:"prometheus", type:"prometheus", access:"proxy", url:$url, isDefault:false,
              jsonData:{httpMethod:"POST", serverName:$sn, tlsAuth:true, tlsAuthWithCACert:true, tlsSkipVerify:false},
              secureJsonData:{tlsClientCert:$tlsClientCert, tlsClientKey:$tlsClientKey, tlsCACert:$tlsCACert}}')
        update_resp=$(printf '%s' "$payload" | \
            "$WRAPPERS_DIR/grafana_launcher.sh" ds_update_by_id "$grafana_url" "$GRAFANA_BEARER_TOKEN" "$ds_id")
        if [[ "$update_resp" == "200" || "$update_resp" == "202" ]]; then
            print_success "Datasource обновлен через API (mTLS установлен)"
        else
            print_warning "Не удалось обновить datasource через API, код $update_resp"
        fi
    else
        print_warning "ID источника данных не найден, пропускаем установку secureJsonData"
    fi

    print_info "Импортируем дашборды в Grafana..."
    if [[ ! -d "/opt/harvest" ]]; then
        print_error "Директория /opt/harvest не найдена"
        log_message "[GRAFANA IMPORT ERROR] Директория /opt/harvest не найдена"
        return 1
    fi

    cd /opt/harvest || {
        print_error "Не удалось перейти в директорию /opt/harvest"
        log_message "[GRAFANA IMPORT ERROR] Не удалось перейти в директорию /opt/harvest"
        return 1
    }

    if [[ ! -f "$HARVEST_CONFIG" ]]; then
        print_error "Файл конфигурации $HARVEST_CONFIG не найден"
        log_message "[GRAFANA IMPORT ERROR] Файл конфигурации $HARVEST_CONFIG не найден"
        return 1
    fi

    if [[ ! -x "./bin/harvest" ]]; then
        print_error "Исполняемый файл harvest не найден или не имеет прав на выполнение"
        log_message "[GRAFANA IMPORT ERROR] Исполняемый файл harvest не найден или не имеет прав на выполнение"
        return 1
    fi

    if echo "Y" | ./bin/harvest --config "$HARVEST_CONFIG" grafana import --addr "$grafana_url" --token "$GRAFANA_BEARER_TOKEN" --insecure >/dev/null 2>&1; then
        print_success "Дашборды успешно импортированы"
    else
        print_error "Не удалось импортировать дашборды автоматически"
        log_message "[GRAFANA IMPORT ERROR] Не удалось импортировать дашборды"
        print_info "Вы можете импортировать их позже командой:"
        print_info "cd /opt/harvest && echo 'Y' | ./bin/harvest --config \"$HARVEST_CONFIG\" grafana import --addr $grafana_url --token <YOUR_TOKEN> --insecure"
        return 1
    fi
    print_success "Процесс импорта дашбордов завершен"
}

verify_installation() {
    print_step "Проверка установки и доступности сервисов"
    ensure_working_directory
    echo
    print_info "Проверка статуса сервисов:"
    local services=("prometheus" "grafana-server")
    local failed_services=()

    for service in "${services[@]}"; do
        if systemctl is-active --quiet "$service"; then
            print_success "$service: активен"
        else
            print_error "$service: не активен"
            failed_services+=("$service")
        fi
    done

    if command -v harvest &> /dev/null; then
        if harvest status --config "$HARVEST_CONFIG" 2>/dev/null | grep -q "running"; then
            print_success "harvest: активен"
        else
            print_error "harvest: не активен"
            failed_services+=("harvest")
        fi
    fi

    echo
    print_info "Проверка открытых портов:"
    local ports=(
        "$PROMETHEUS_PORT:Prometheus"
        "$GRAFANA_PORT:Grafana"
        "$HARVEST_UNIX_PORT:Harvest-Unix"
        "$HARVEST_NETAPP_PORT:Harvest-NetApp"
    )

    for port_info in "${ports[@]}"; do
        IFS=':' read -r port name <<< "$port_info"
        if ss -tln | grep -q ":$port "; then
            print_success "$name (порт $port): доступен"
        else
            print_error "$name (порт $port): недоступен"
        fi
    done

    echo
    print_info "Проверка HTTP ответов:"
    local services_to_check=(
        "$PROMETHEUS_PORT:Prometheus"
        "$GRAFANA_PORT:Grafana"
    )

    for service_info in "${services_to_check[@]}"; do
        IFS=':' read -r port name <<< "$service_info"
        local https_url="https://127.0.0.1:${port}"
        local http_url="http://127.0.0.1:${port}"

        # Сначала пробуем HTTPS
        if "$WRAPPERS_DIR/grafana_launcher.sh" http_check "$https_url" "https"; then
            print_success "$name: HTTPS ответ получен"
        # Если HTTPS не работает, пробуем HTTP
        elif "$WRAPPERS_DIR/grafana_launcher.sh" http_check "$http_url" "http"; then
            print_success "$name: HTTP ответ получен"
        else
            print_warning "$name: HTTP/HTTPS ответ не получен (но сервис работает по портам)"
        fi
    done

    if [[ ${#failed_services[@]} -eq 0 ]]; then
        print_success "Все сервисы успешно установлены и запущены!"
    else
        print_warning "Некоторые сервисы требуют внимания: ${failed_services[*]}"
    fi
}

save_installation_state() {
    print_step "Сохранение состояния установки"
    ensure_working_directory
    "$WRAPPERS_DIR/config_writer_launcher.sh" "$STATE_FILE" << STATE_EOF
# Состояние установки мониторинговой системы
INSTALL_DATE=$DATE_INSTALL
SERVER_IP=$SERVER_IP
SERVER_DOMAIN=$SERVER_DOMAIN
INSTALL_DIR=$INSTALL_DIR
LOG_FILE=$LOG_FILE
PROMETHEUS_PORT=$PROMETHEUS_PORT
GRAFANA_PORT=$GRAFANA_PORT
HARVEST_UNIX_PORT=$HARVEST_UNIX_PORT
HARVEST_NETAPP_PORT=$HARVEST_NETAPP_PORT
NETAPP_API_ADDR=$NETAPP_API_ADDR
STATE_EOF
    chmod 600 "$STATE_FILE"
    print_success "Состояние установки сохранено в $STATE_FILE"
}

# Основная функция
main() {
    log_message "=== Начало развертывания мониторинговой системы v3.4 ==="
    ensure_working_directory
    print_header
    check_sudo
    check_dependencies
    check_and_close_ports
    detect_network_info
    cleanup_all_previous
    create_directories

    # При необходимости можно пропустить установку Vault через RLM,
    # если vault-agent уже установлен и настроен на целевом сервере.
    if [[ "${SKIP_VAULT_INSTALL:-false}" == "true" ]]; then
        print_warning "SKIP_VAULT_INSTALL=true: пропускаем install_vault_via_rlm, используем уже установленный vault-agent"
    else
        install_vault_via_rlm
    fi

    setup_vault_config
    load_config_from_json
    create_rlm_install_tasks
    setup_certificates_after_install
    configure_harvest
    configure_prometheus
    configure_iptables
    configure_services
    ensure_grafana_token
    configure_grafana_datasource
    import_grafana_dashboards

    # Явная очистка чувствительных переменных окружения после операций с RLM и Grafana
    unset RLM_TOKEN GRAFANA_USER GRAFANA_PASSWORD GRAFANA_BEARER_TOKEN || true

    save_installation_state
    verify_installation
    print_info "Удаление лог-файла установки"
    rm -rf "$LOG_FILE" || true
}

if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    main "$@"
fi
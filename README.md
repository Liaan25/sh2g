## Проект развертывания мониторинга (Harvest + Prometheus + Grafana)

Этот репозиторий содержит **полностью автоматизированный и усиленный по требованиям ИБ** сценарий развертывания стека мониторинга (Harvest, Prometheus, Grafana) на Linux‑сервере через Jenkins и HashiCorp Vault.

Проект спроектирован так, чтобы:

- **Jenkins** под обычной учётной записью (`mvp_dev`) выполнял только копирование файлов и один контролируемый `sudo`.
- Все опасные операции (`iptables`, `curl`, запись в `/etc`, работа с RLM/Grafana API) выполнялись через **скрипты‑обёртки с белыми списками и проверкой `sha256`**.
- Секреты **не попадали в окружение shell и логи**, а читались из Vault через `vault-agent` во временные файлы/локальные переменные с последующей очисткой.

Подробные технические детали для ИБ см. в `SECURITY_IB_NOTES.md`.

---

## Структура репозитория

- **`deploy_monitoring_script.sh`**  
  Основной скрипт развертывания. На целевом сервере копируется Jenkins в `/tmp/deploy-monitoring/deploy_monitoring_script.sh` и запускается от `root` через `sudo`.

- **`Jenkinsfile`**  
  Декларативный Jenkins Pipeline:
  - получает секреты из Vault в `temp_data_cred.json`,
  - генерирует лаунчеры с проверкой `sha256`,
  - копирует скрипт и обёртки на удалённый сервер,
  - запускает развертывание с единственным `sudo`,
  - выполняет проверку и очистку.

- **`wrappers/`** – каталог скриптов‑обёрток:
  - `iptables_wrapper.sh` – безопасная настройка `iptables` по белым спискам портов и IP.
  - `rlm_task_wrapper.sh` – работа с RLM API (создание задач, опрос статусов) с валидацией URL и токена.
  - `grafana_wrapper.sh` – взаимодействие с Grafana API и HTTP‑проверки с валидацией URL и портов.
  - `config_writer.sh` – запись конфигурационных файлов только по белому списку путей.
  - `generate_launchers.sh` – генерация лаунчеров `*_launcher.sh` с проверкой `sha256` для каждой обёртки.

- **`sudoers`**  
  Минимальный рабочий фрагмент `sudoers` (без комментариев) с одним правилом на запуск скрипта развертывания.

- **`sudoers.txt`**  
  Развёрнутый шаблон для ИБ: список всех команд из скрипта, рекомендации по sudo‑правам и примеры.

- **`SECURITY_IB_NOTES.md`**  
  Конспект по мерам безопасности: белые списки, обёртки, работа с секретами, `NOEXEC`, hash‑контроль и пр.

---

## Поток развертывания (Jenkins → сервер)

### 1. Источник пайплайна

В настройках Jenkins job:

- **Pipeline script from SCM**
- SCM: Git
- Репозиторий: `deploy-mon-sh-2.git` (этот проект)
- Скрипт пайплайна: `Jenkinsfile`

### 2. Параметры пайплайна

В `Jenkinsfile` определены параметры:

- **SERVER_ADDRESS** – адрес целевого сервера (FQDN/IP).
- **SSH_CREDENTIALS_ID** – Jenkins Credentials с SSH‑ключом (`SSH Username with private key`) для `mvp_dev`.
- **SEC_MAN_ADDR** – FQDN SecMan/Vault (`https://...`).
- **NAMESPACE_CI** – namespace в Vault (`CI04523276_CI10742292` и т.п.).
- **NETAPP_API_ADDR** – FQDN NetApp API.
- **HARVEST_RPM_URL` / `PROMETHEUS_RPM_URL` / `GRAFANA_RPM_URL`** – RPM‑URL‑ы (используются через Vault).
- **VAULT_AGENT_KV`, `RPM_URL_KV`, `TUZ_KV`, `NETAPP_SSH_KV`, `MON_SSH_KV`, `NETAPP_API_KV`, `GRAFANA_WEB_KV`, `SBERCA_CERT_KV`** – пути KV‑секретов в Vault (см. `SECURITY_IB_NOTES.md`).
- **ADMIN_EMAIL** – email администратора, передаётся в SberCA при выпуске сертификата.
- **GRAFANA_PORT / PROMETHEUS_PORT** – порты сервисов (по умолчанию 3000/9090).
- **RLM_API_URL** – whitelisted базовый URL RLM API (`https://simple-api.rlm.apps.prom-terra000049-ebm.ocp.sigma.sbrf.ru`).
- **SKIP_VAULT_INSTALL (boolean)** – если `true`, пропустить установку Vault через RLM и использовать уже установленный `vault-agent`.

### 3. Стадии пайплайна

#### 3.1. `Проверка параметров`

Проверяет, что указаны `SERVER_ADDRESS` и `SSH_CREDENTIALS_ID`. При отсутствии – завершает пайплайн с ошибкой.

#### 3.2. `Получение данных из Vault в temp_data_cred.json`

- Через `withVault` читает указанные `*_KV` пути.
- Записывает агрегированный JSON в файл **`temp_data_cred.json`** на агенте Jenkins. Структура:

```json
{
  "vault-agent": { "role_id": "...", "secret_id": "..." },
  "rpm_url": { "harvest": "...", "prometheus": "...", "grafana": "..." },
  "tuz": { "user": "...", "pass": "..." },
  "netapp_ssh": { "addr": "...", "user": "...", "pass": "..." },
  "mon_ssh": { "addr": "...", "user": "...", "pass": "..." },
  "netapp_api": { "addr": "...", "user": "...", "pass": "..." },
  "grafana_web": { "user": "...", "pass": "..." }
}
```

Секреты **не выводятся в лог** Jenkins, используются только внутри стадии.

#### 3.3. `Копирование скрипта на удаленный сервер`

Внутри создаются временные скрипты:

- `prep_clone.sh`  
  Запускает `wrappers/generate_launchers.sh`, чтобы в каталоге `wrappers/` сгенерировались:
  - `iptables_launcher.sh`
  - `rlm_launcher.sh`
  - `grafana_launcher.sh`
  - `config_writer_launcher.sh`  
  Каждый лаунчер:
  - считает `sha256` от обёртки,
  - сравнивает с ожидаемым хешем,
  - при несоответствии завершает работу с ошибкой.

- `scp_script.sh`  
  Выполняет:

  ```bash
  ssh ... "rm -rf /tmp/deploy-monitoring && mkdir -p /tmp/deploy-monitoring"
  scp ... deploy_monitoring_script.sh \
       mvp_dev@SERVER:/tmp/deploy-monitoring/deploy_monitoring_script.sh
  scp ... -r wrappers \
       mvp_dev@SERVER:/tmp/deploy-monitoring/
  scp ... temp_data_cred.json \
       mvp_dev@SERVER:/tmp/
  ```

  В результате на целевом сервере появляется:

  - `/tmp/deploy-monitoring/deploy_monitoring_script.sh`
  - `/tmp/deploy-monitoring/wrappers/*`
  - `/tmp/temp_data_cred.json`

- `verify_script.sh`  
  Проверяет наличие основного скрипта:

  ```bash
  ls -l /tmp/deploy-monitoring/deploy_monitoring_script.sh
  ```

После выполнения временные скрипты на агенте Jenkins удаляются.

#### 3.4. `Выполнение развертывания`

Генерируется `deploy_script.sh`, который:

- Подключается по SSH к `SERVER_ADDRESS` под `mvp_dev`.
- Проверяет:

  ```bash
  REMOTE_SCRIPT_PATH="/tmp/deploy-monitoring/deploy_monitoring_script.sh"
  chmod +x "$REMOTE_SCRIPT_PATH"
  dos2unix/sed -i 's/\r$//' "$REMOTE_SCRIPT_PATH"
  ```

- Из `/tmp/temp_data_cred.json` на сервере **однократно** достаёт URL‑ы RPM.
- Проверяет, что настроен passwordless `sudo`:

  ```bash
  sudo -n true
  ```

- Запускает основной скрипт от `root`:

  ```bash
  sudo -n env \
    SEC_MAN_ADDR="..." \
    NAMESPACE_CI="..." \
    RLM_API_URL="..." \
    RLM_TOKEN="..." \
    NETAPP_API_ADDR="..." \
    GRAFANA_PORT="..." \
    PROMETHEUS_PORT="..." \
    VAULT_AGENT_KV="..." \
    RPM_URL_KV="..." \
    ... \
    GRAFANA_URL="$RPM_GRAFANA" \
    PROMETHEUS_URL="$RPM_PROMETHEUS" \
    HARVEST_URL="$RPM_HARVEST" \
    /bin/bash "$REMOTE_SCRIPT_PATH"
  ```

Это **единственный `sudo`**, который требуется для работы пайплайна.

#### 3.5. `Проверка результатов`

Через SSH:

- проверяет активность сервисов `prometheus`, `grafana-server`,
- проверяет открытые порты (9090, 3000, 12990, 12991).

#### 3.6. `Очистка`

Удаляет временные файлы:

- на Jenkins‑агенте: `temp_data_cred.json`;
- на целевом сервере: `/tmp/deploy-monitoring`, `/tmp/monitoring_deployment.sh` (старый путь), `/tmp/temp_data_cred.json`, временные RPM.

#### 3.7. `Получение сведений о развертывании`

Через `nslookup` и `hostname -I` получает FQDN и IP целевого сервера и выводит удобные ссылки:

- `https://<IP>:PROMETHEUS_PORT`
- `https://<FQDN>:PROMETHEUS_PORT`
- `https://<IP>:GRAFANA_PORT`
- `https://<FQDN>:GRAFANA_PORT`

---

## Что происходит на целевом сервере

Все шаги выполняет `deploy_monitoring_script.sh`, запущенный от `root`.

### 1. Проверки и подготовка

- **`check_sudo`** – убеждается, что скрипт запущен под `root` (через `sudo`).
- **`check_dependencies`** – проверяет наличие:

  - `curl`, `rpm`, `systemctl`, `nslookup`, `iptables`, `jq`, `ss`, `openssl`

- **`check_and_close_ports`** – проверка и освобождение портов:
  - Prometheus: `PROMETHEUS_PORT` (по умолчанию 9090)
  - Grafana: `GRAFANA_PORT` (по умолчанию 3000)
  - Harvest Unix: `12991`
  - Harvest NetApp: `12990`

  При необходимости:
  - ищет процессы, использующие порт, через `ss`/`awk`/`ps`,
  - завершает их (TERM, затем KILL).

- **`detect_network_info`** – определяет:
  - `SERVER_IP` через `hostname -I`,
  - `SERVER_DOMAIN` через `nslookup` или `hostname -f`,
  - записывает сетевые переменные в `/etc/environment.d/99-monitoring-vars.conf` через `config_writer_launcher.sh`.

- **`cleanup_all_previous`** – останавливает и отключает автозапуск старых сервисов:
  - `prometheus`, `grafana-server`, `harvest`, `harvest-prometheus`
  - удаляет старые конфиги/каталоги/юниты (`/etc/prometheus`, `/etc/grafana`, `/opt/harvest` и т.п.),
  - делает `systemctl daemon-reload`.

### 2. Работа с Vault и RLM

- **`install_vault_via_rlm`** (если не включён `SKIP_VAULT_INSTALL`)  
  Через `rlm_launcher.sh` создаёт задачу в RLM на конфигурацию Vault (`vault_agent_config`) и ждёт её успешного выполнения.

- **`setup_vault_config`**:

  - Ищет `temp_data_cred.json` в нескольких стандартных местах (учитывая запуск под `sudo`).
  - Извлекает `role_id` и `secret_id` в файлы:
    - `/opt/vault/conf/role_id.txt`
    - `/opt/vault/conf/secret_id.txt`
  - Ставит корректные права и владельцев (по образцу `/opt/vault/conf`).
  - Через **`config_writer_launcher.sh`** записывает `agent.hcl`:
    - `auto_auth` через `approle` (namespace, mount_path, пути к файлам с creds),
    - `log_destination` Tengry (JSON‑логи в `/opt/vault/log/agent.log`),
    - `template` для:
      - `/opt/vault/conf/data_sec.json` (секреты RPM, TUZ, NetApp, Grafana, vault-agent),
      - `/opt/vault/certs/server_bundle.pem` (серверный cert+key),
      - `/opt/vault/certs/ca_chain.crt` (CA‑цепочка),
      - `/opt/vault/certs/grafana-client.pem` (клиентский сертификат для Grafana).
  - Перезапускает `vault-agent` и убеждается, что он активен.
  - Удаляет временные файлы с чувствительными данными (`temp_data_cred.json` и его копии).

### 3. Загрузка RPM через RLM

- **`load_config_from_json`** – читает обязательные параметры из Jenkins env (URL‑ы RPM).
- **`create_rlm_install_tasks`** – через `rlm_launcher.sh` создаёт три задачи:
  - `Grafana`, `Prometheus`, `Harvest` (service `LINUX_RPM_INSTALLER`),
  - отслеживает их статусы до `success`,
  - настраивает `PATH` для `harvest` и создаёт `/etc/profile.d/harvest.sh`.

### 4. Сертификаты

- **`setup_certificates_after_install`**:
  - Берёт либо `server_bundle.pem`, либо `server.crt`/`server.key` из `/opt/vault/certs`.
  - Раскладывает по каталогам:
    - `/opt/harvest/cert/harvest.crt/key`
    - `/etc/grafana/cert/crt.crt/key.key`
    - `/etc/prometheus/cert/server.crt/server.key/ca_chain.crt`
  - Выставляет владельцев (`harvest`, `grafana`, `prometheus`) и права (`640/600`).

### 5. Конфигурация сервисов

- **Harvest**
  - `configure_harvest` пишет `/opt/harvest/harvest.yml` и `harvest.service` (через `config_writer_launcher.sh`).
  - В `harvest.yml` настраивает:
    - `Exporters` (Prometheus Unix / NetApp HTTPS),
    - `Pollers` (локальный Unix, NetApp poller по `NETAPP_API_ADDR`),
    - TLS с использованием сертификатов.

- **Prometheus**
  - `configure_prometheus_files` создаёт:
    - `/etc/prometheus/web-config.yml` – TLS‑конфиг и требование client‑cert,
    - `/etc/prometheus/prometheus.env` – параметры запуска (путь к конфигу, TLS, listen‑address).
  - `configure_prometheus` создаёт `prometheus.yml`:
    - job `prometheus` (scrape самого себя по HTTPS),
    - job `harvest-unix` (localhost:12991),
    - job `harvest-netapp-https` (SERVER_DOMAIN:12990 по HTTPS с cert‑ами).

- **Grafana**
  - `configure_grafana_ini`/`configure_grafana_ini_no_ssl` создают `/etc/grafana/grafana.ini`:
    - секция `[server]` (protocol, port, domain, cert_file/key_file),
    - секция `[security]` (allow_embedding).

### 6. Firewall (`iptables`)

- **`configure_iptables`**  
  Вызывает:

  ```bash
  /tmp/deploy-monitoring/wrappers/iptables_launcher.sh \
    "$PROMETHEUS_PORT" "$GRAFANA_PORT" \
    "$HARVEST_UNIX_PORT" "$HARVEST_NETAPP_PORT" "$SERVER_IP"
  ```

  Внутри `iptables_wrapper.sh`:

  - Валидация портов и IP по белым спискам/регуляркам.
  - Добавление/проверка правил `INPUT` для:
    - Prometheus, Grafana, Harvest,
    - диапазона портов `13000:14000` (если требуется).
  - Сохранение правил в `/etc/sysconfig/iptables`.

### 7. Настройка и запуск сервисов

- **`configure_services`**:

  - Проверяет наличие сертификатов и CA chain.
  - Настраивает `grafana.ini` и файлы Prometheus.
  - Включает и перезапускает:
    - `prometheus`,
    - `grafana-server`,
    - `harvest` (через `systemctl` и встроенную команду `harvest`).
  - Проверяет статусы и наличие нужных портов.

- **Grafana + DataSource + дашборды**

  - `ensure_grafana_token`:
    - читает `grafana_web.user/pass` из `/opt/vault/conf/data_sec.json` (без env),
    - через `grafana_launcher.sh` создаёт service account и токен,
    - сохраняет токен в `GRAFANA_BEARER_TOKEN` (с последующим `unset`).

  - `configure_grafana_datasource`:
    - через API Grafana создаёт/обновляет Prometheus data source.

  - `import_grafana_dashboards`:
    - ждёт запуска Grafana,
    - с помощью `harvest grafana import` импортирует дашборды.

### 8. Финализация

- **`save_installation_state`**:
  - записывает в `/var/lib/monitoring_deployment_state`:
    - дату установки,
    - IP/домен,
    - директорию установки,
    - порты и NetApp API.

- **`verify_installation`**:
  - проверяет статусы сервисов,
  - проверяет открытые порты,
  - делает HTTP/HTTPS‑проверки через `grafana_launcher.sh http_check`.

- Удаляет лог установки (`$HOME/monitoring_deployment_*.log`).
- Явно **очищает чувствительные переменные окружения**:

  ```bash
  unset RLM_TOKEN GRAFANA_USER GRAFANA_PASSWORD GRAFANA_BEARER_TOKEN || true
  ```

---

## Sudo‑права и безопасность

### Минимальный `sudoers`

Для работы пайплайна достаточно одного правила (плюс дефолты):

```text
Defaults    env_reset
Defaults    secure_path="/usr/sbin:/usr/bin:/sbin:/bin"

ALL=(ALL:ALL) NOEXEC: NOPASSWD: /bin/bash /tmp/deploy-monitoring/deploy_monitoring_script.sh
```

- Это правило разрешает **только запуск** основного скрипта от `root`.
- Внутри скрипта **нет `sudo`**, всё выполняется уже с правами `root`.
- Скрипты‑обёртки (`*_wrapper.sh`, `*_launcher.sh`) вызываются **без дополнительных sudo‑прав**.

Для просмотра логов `vault-agent` рекомендуется добавить `mvp_dev` в группу `systemd-journal`, а не выдавать `sudo journalctl`.

Более детальные обоснования по ИБ, запрету `*` и переменных в sudoers, требованиям к `NOEXEC` и т.п. – в `SECURITY_IB_NOTES.md`.

---

## Что остаётся после развёртывания

**Постоянные файлы (боевое состояние):**

- Vault:
  - `/opt/vault/conf/agent.hcl`
  - `/opt/vault/conf/role_id.txt`
  - `/opt/vault/conf/secret_id.txt`
  - `/opt/vault/conf/data_sec.json` (агрегированные секреты от Vault для deploy‑скрипта)
  - `/opt/vault/certs/*` (серверные/клиентские cert/key/CA)

- Harvest / Prometheus / Grafana:
  - `/opt/harvest/harvest.yml`, `/etc/systemd/system/harvest.service`
  - `/etc/prometheus/prometheus.yml`, `web-config.yml`, `prometheus.env`, cert‑ы
  - `/etc/grafana/grafana.ini`, cert‑ы

- Состояние:
  - `/var/lib/monitoring_deployment_state`

**Временные файлы (очищаются):**

- На Jenkins‑агенте: `temp_data_cred.json`.
- На сервере: `/tmp/deploy-monitoring`, `/tmp/temp_data_cred.json`, временные RPM, лог установки.

---

## Дополнительные материалы и ссылки

- Подробности по требованиям ИБ и реализованным мерам:
  - `SECURITY_IB_NOTES.md`
  - `sudoers.txt`

- Документация продуктов:
  - HashiCorp Vault Agent – `https://www.vaultproject.io/docs/agent`
  - Prometheus – `https://prometheus.io/docs/`
  - Grafana – `https://grafana.com/docs/`
  - NetApp Harvest – `https://github.com/NetApp/harvest`

Если требуется отдельная документация именно для службы ИБ (описание белых списков, примеры логов и т.п.), ориентируйтесь на `SECURITY_IB_NOTES.md` как на основной конспект. 



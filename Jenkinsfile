pipeline {
    agent { label 'linux' }

    parameters {
        string(name: 'SERVER_ADDRESS', defaultValue: params.SERVER_ADDRESS ?: '', description: 'Адрес сервера для подключения по SSH')
        string(name: 'SSH_CREDENTIALS_ID', defaultValue: params.SSH_CREDENTIALS_ID ?: '', description: 'ID Jenkins Credentials (SSH Username with private key)')
        string(name: 'SEC_MAN_ADDR', defaultValue: params.SEC_MAN_ADDR ?: '', description: 'Адрес Vault для SecMan')
        string(name: 'NAMESPACE_CI', defaultValue: params.NAMESPACE_CI ?: '', description: 'Namespace для CI в Vault')
        string(name: 'NETAPP_API_ADDR', defaultValue: params.NETAPP_API_ADDR ?: '', description: 'FQDN/IP NetApp API (например, cl01-mgmt.example.org)')
        string(name: 'HARVEST_RPM_URL', defaultValue: params.HARVEST_RPM_URL ?: '', description: 'Полная ссылка на RPM Harvest')
        string(name: 'PROMETHEUS_RPM_URL', defaultValue: params.PROMETHEUS_RPM_URL ?: '', description: 'Полная ссылка на RPM Prometheus')
        string(name: 'GRAFANA_RPM_URL', defaultValue: params.GRAFANA_RPM_URL ?: '', description: 'Полная ссылка на RPM Grafana')
        string(name: 'VAULT_AGENT_KV', defaultValue: params.VAULT_AGENT_KV ?: '', description: 'Путь KV в Vault для AppRole: secret "vault-agent" с ключами role_id, secret_id')
        string(name: 'RPM_URL_KV', defaultValue: params.RPM_URL_KV ?: '', description: 'Путь KV в Vault для RPM URL')
        string(name: 'TUZ_KV', defaultValue: params.TUZ_KV ?: '', description: 'Путь KV в Vault для TUZ')
        string(name: 'NETAPP_SSH_KV', defaultValue: params.NETAPP_SSH_KV ?: '', description: 'Путь KV в Vault для NetApp SSH')
        string(name: 'MON_SSH_KV', defaultValue: params.MON_SSH_KV ?: '', description: 'Путь KV в Vault для Mon SSH')
        string(name: 'NETAPP_API_KV', defaultValue: params.NETAPP_API_KV ?: '', description: 'Путь KV в Vault для NetApp API')
        string(name: 'GRAFANA_WEB_KV', defaultValue: params.GRAFANA_WEB_KV ?: '', description: 'Путь KV в Vault для Grafana Web')
        string(name: 'SBERCA_CERT_KV', defaultValue: params.SBERCA_CERT_KV ?: '', description: 'Путь KV в Vault для SberCA Cert')
        string(name: 'ADMIN_EMAIL', defaultValue: params.ADMIN_EMAIL ?: '', description: 'Email администратора для сертификатов')
        string(name: 'GRAFANA_PORT', defaultValue: params.GRAFANA_PORT ?: '3000', description: 'Порт Grafana')
        string(name: 'PROMETHEUS_PORT', defaultValue: params.PROMETHEUS_PORT ?: '9090', description: 'Порт Prometheus')
        string(name: 'RLM_API_URL', defaultValue: params.RLM_API_URL ?: '', description: 'Базовый URL RLM API (например, https://api.rlm.sbrf.ru)')
    }

    environment {
        DATE_INSTALL = sh(script: "date '+%Y%m%d_%H%M%S'", returnStdout: true).trim()
    }

    stages {
        stage('Проверка параметров') {
            steps {
                script {
                    echo "================================================"
                    echo "Целевой сервер: ${params.SERVER_ADDRESS}"
                    echo "SSH Credentials: ${params.SSH_CREDENTIALS_ID}"
                    echo "================================================"
                    if (!params.SERVER_ADDRESS || !params.SSH_CREDENTIALS_ID) {
                        error("ОШИБКА: Не указаны обязательные параметры (SERVER_ADDRESS или SSH_CREDENTIALS_ID)")
                    }
                }
            }
        }

        stage('Получение данных из Vault в temp_data_cred.json') {
            steps {
                script {
                    echo "[STEP] Получение чувствительных данных из Vault (без вывода содержимого)"
                    withVault([
                        configuration: [
                            vaultUrl: "https://${params.SEC_MAN_ADDR}",
                            engineVersion: 1,
                            skipSslVerification: false,
                            vaultCredentialId: 'vault-agent-dev'
                        ],
                        vaultSecrets: [
                            [path: params.VAULT_AGENT_KV, secretValues: [
                                [envVar: 'VA_ROLE_ID', vaultKey: 'role_id'],
                                [envVar: 'VA_SECRET_ID', vaultKey: 'secret_id']
                            ]],
                            [path: params.RPM_URL_KV, secretValues: [
                                [envVar: 'VA_RPM_HARVEST', vaultKey: 'harvest'],
                                [envVar: 'VA_RPM_PROMETHEUS', vaultKey: 'prometheus'],
                                [envVar: 'VA_RPM_GRAFANA', vaultKey: 'grafana']
                            ]],
                            [path: params.TUZ_KV, secretValues: [
                                [envVar: 'VA_TUZ_USER', vaultKey: 'user'],
                                [envVar: 'VA_TUZ_PASS', vaultKey: 'pass']
                            ]],
                            [path: params.NETAPP_SSH_KV, secretValues: [
                                [envVar: 'VA_NETAPP_SSH_ADDR', vaultKey: 'addr'],
                                [envVar: 'VA_NETAPP_SSH_USER', vaultKey: 'user'],
                                [envVar: 'VA_NETAPP_SSH_PASS', vaultKey: 'pass']
                            ]],
                            [path: params.MON_SSH_KV, secretValues: [
                                [envVar: 'VA_MON_SSH_ADDR', vaultKey: 'addr'],
                                [envVar: 'VA_MON_SSH_USER', vaultKey: 'user'],
                                [envVar: 'VA_MON_SSH_PASS', vaultKey: 'pass']
                            ]],
                            [path: params.NETAPP_API_KV, secretValues: [
                                [envVar: 'VA_NETAPP_API_ADDR', vaultKey: 'addr'],
                                [envVar: 'VA_NETAPP_API_USER', vaultKey: 'user'],
                                [envVar: 'VA_NETAPP_API_PASS', vaultKey: 'pass']
                            ]],
                            [path: params.GRAFANA_WEB_KV, secretValues: [
                                [envVar: 'VA_GRAFANA_WEB_USER', vaultKey: 'user'],
                                [envVar: 'VA_GRAFANA_WEB_PASS', vaultKey: 'pass']
                            ]]
                        ]
                    ]) {
                        def data = [
                          "vault-agent": [
                            role_id: (env.VA_ROLE_ID ?: ''),
                            secret_id: (env.VA_SECRET_ID ?: '')
                          ],
                          "rpm_url": [
                            harvest: (env.VA_RPM_HARVEST ?: ''),
                            prometheus: (env.VA_RPM_PROMETHEUS ?: ''),
                            grafana: (env.VA_RPM_GRAFANA ?: '')
                          ],
                          "tuz": [
                            pass: (env.VA_TUZ_PASS ?: ''),
                            user: (env.VA_TUZ_USER ?: '')
                          ],
                          "netapp_ssh": [
                            addr: (env.VA_NETAPP_SSH_ADDR ?: ''),
                            user: (env.VA_NETAPP_SSH_USER ?: ''),
                            pass: (env.VA_NETAPP_SSH_PASS ?: '')
                          ],
                          "mon_ssh": [
                            addr: (env.VA_MON_SSH_ADDR ?: ''),
                            user: (env.VA_MON_SSH_USER ?: ''),
                            pass: (env.VA_MON_SSH_PASS ?: '')
                          ],
                          "netapp_api": [
                            addr: (env.VA_NETAPP_API_ADDR ?: ''),
                            user: (env.VA_NETAPP_API_USER ?: ''),
                            pass: (env.VA_NETAPP_API_PASS ?: '')
                          ],
                          "grafana_web": [
                            user: (env.VA_GRAFANA_WEB_USER ?: ''),
                            pass: (env.VA_GRAFANA_WEB_PASS ?: '')
                          ]
                        ]
                        writeFile file: 'temp_data_cred.json', text: groovy.json.JsonOutput.toJson(data)
                    }
                    def checkStatus = sh(script: 'test -s temp_data_cred.json', returnStatus: true)
                    if (checkStatus != 0) {
                        error("ОШИБКА: Не удалось получить данные из Vault (temp_data_cred.json пустой или отсутствует)")
                    }
                }
            }
        }

        stage('Копирование скрипта на удаленный сервер') {
            steps {
                script {
                    echo "[STEP] Клонирование репозитория и копирование на сервер ${params.SERVER_ADDRESS}..."
                    withCredentials([
                        sshUserPrivateKey(credentialsId: params.SSH_CREDENTIALS_ID, keyFileVariable: 'SSH_KEY', usernameVariable: 'SSH_USER'),
                        sshUserPrivateKey(credentialsId: 'bitbucket-ssh-dev-ift', keyFileVariable: 'BITBUCKET_SSH_KEY', usernameVariable: 'BITBUCKET_SSH_USER')
                    ]) {
                        writeFile file: 'prep_clone.sh', text: '''#!/bin/bash
set -e
rm -rf deploy-monitoring
GIT_SSH_COMMAND='ssh -i "$BITBUCKET_SSH_KEY" -o StrictHostKeyChecking=no' git clone ssh://git@stash.delta.sbrf.ru:7999/infranas/deploy-monitoring.git deploy-monitoring >/dev/null 2>&1
test -s deploy-monitoring/monitoring_deployment.sh

# Генерируем лаунчеры с проверкой sha256 для обёрток
if [ -x deploy-monitoring/wrappers/generate_launchers.sh ]; then
  (cd deploy-monitoring/wrappers && ./generate_launchers.sh)
fi
'''
                        writeFile file: 'scp_script.sh', text: '''#!/bin/bash
scp -i "$SSH_KEY" -q -o StrictHostKeyChecking=no -r deploy-monitoring "$SSH_USER"@''' + params.SERVER_ADDRESS + ''':/tmp/ >/dev/null 2>&1
scp -i "$SSH_KEY" -q -o StrictHostKeyChecking=no temp_data_cred.json "$SSH_USER"@''' + params.SERVER_ADDRESS + ''':/tmp/ >/dev/null 2>&1
'''
                        writeFile file: 'verify_script.sh', text: '''#!/bin/bash
ssh -i "$SSH_KEY" -q -o StrictHostKeyChecking=no \
    "$SSH_USER"@''' + params.SERVER_ADDRESS + ''' \
    "ls -l /tmp/deploy-monitoring/monitoring_deployment.sh || echo '[ERROR] Скрипт не найден на удаленном сервере'" \
    2>/dev/null
'''
                        sh 'chmod +x prep_clone.sh scp_script.sh verify_script.sh'
                        withEnv(['SSH_KEY=' + env.SSH_KEY, 'SSH_USER=' + env.SSH_USER, 'BITBUCKET_SSH_KEY=' + env.BITBUCKET_SSH_KEY]) {
                            sh './prep_clone.sh'
                            sh './scp_script.sh'
                            sh './verify_script.sh'
                        }
                        sh 'rm -f prep_clone.sh scp_script.sh verify_script.sh'
                    }
                    echo "[SUCCESS] Репозиторий скопирован на сервер"
                }
            }
        }

        stage('Выполнение развертывания') {
        stage('Выполнение развертывания') {
        stage('Выполнение развертывания') {
            steps {
                script {
                    echo "[STEP] Запуск развертывания на удаленном сервере..."
                    withCredentials([
                        sshUserPrivateKey(credentialsId: params.SSH_CREDENTIALS_ID, keyFileVariable: 'SSH_KEY', usernameVariable: 'SSH_USER'),
                        string(credentialsId: 'rlm-token', variable: 'RLM_TOKEN')
                    ]) {
                        def scriptTpl = '''#!/bin/bash
ssh -i "$SSH_KEY" -q -o StrictHostKeyChecking=no -o BatchMode=yes -o ServerAliveInterval=30 -o ServerAliveCountMax=3 "$SSH_USER"@__SERVER_ADDRESS__ RLM_TOKEN="$RLM_TOKEN" /bin/bash -s <<'REMOTE_EOF'
set -e
USERNAME=$(whoami)
REMOTE_SCRIPT_PATH="/tmp/deploy-monitoring/monitoring_deployment.sh"
if [ ! -f "$REMOTE_SCRIPT_PATH" ]; then
    echo "[ERROR] Скрипт $REMOTE_SCRIPT_PATH не найден" && exit 1
fi
chmod +x "$REMOTE_SCRIPT_PATH"
echo "[INFO] sha256sum $REMOTE_SCRIPT_PATH:"
sha256sum "$REMOTE_SCRIPT_PATH" || echo "[WARNING] Не удалось вычислить sha256sum"
echo "[INFO] Нормализация перевода строк (CRLF -> LF)..."
if command -v dos2unix >/dev/null 2>&1; then
    dos2unix "$REMOTE_SCRIPT_PATH" || true
else
    sed -i 's/\r$//' "$REMOTE_SCRIPT_PATH" || true
fi
# Извлекаем значения из переданного JSON (если есть)
RPM_GRAFANA=$(jq -r '.rpm_url.grafana // empty' /tmp/temp_data_cred.json 2>/dev/null || echo "")
RPM_PROMETHEUS=$(jq -r '.rpm_url.prometheus // empty' /tmp/temp_data_cred.json 2>/dev/null || echo "")
RPM_HARVEST=$(jq -r '.rpm_url.harvest // empty' /tmp/temp_data_cred.json 2>/dev/null || echo "")

echo "[INFO] Проверка passwordless sudo..."
if ! sudo -n true 2>/dev/null; then
    echo "[ERROR] Требуется passwordless sudo (NOPASSWD) для пользователя $USERNAME" && exit 1
fi

echo "[INFO] Запуск скрипта с правами sudo..."
sudo -n env \
  SEC_MAN_ADDR="__SEC_MAN_ADDR__" \
  NAMESPACE_CI="__NAMESPACE_CI__" \
  RLM_API_URL="__RLM_API_URL__" \
  RLM_TOKEN="$RLM_TOKEN" \
  NETAPP_API_ADDR="__NETAPP_API_ADDR__" \
  GRAFANA_PORT="__GRAFANA_PORT__" \
  PROMETHEUS_PORT="__PROMETHEUS_PORT__" \
  VAULT_AGENT_KV="__VAULT_AGENT_KV__" \
  RPM_URL_KV="__RPM_URL_KV__" \
  TUZ_KV="__TUZ_KV__" \
  NETAPP_SSH_KV="__NETAPP_SSH_KV__" \
  MON_SSH_KV="__MON_SSH_KV__" \
  NETAPP_API_KV="__NETAPP_API_KV__" \
  GRAFANA_WEB_KV="__GRAFANA_WEB_KV__" \
  SBERCA_CERT_KV="__SBERCA_CERT_KV__" \
  ADMIN_EMAIL="__ADMIN_EMAIL__" \
  GRAFANA_URL="$RPM_GRAFANA" \
  PROMETHEUS_URL="$RPM_PROMETHEUS" \
  HARVEST_URL="$RPM_HARVEST" \
  bash "$REMOTE_SCRIPT_PATH"
REMOTE_EOF
'''
                        def finalScript = scriptTpl
                            .replace('__SERVER_ADDRESS__', params.SERVER_ADDRESS ?: '')
                            .replace('__SEC_MAN_ADDR__', params.SEC_MAN_ADDR ?: '')
                            .replace('__NAMESPACE_CI__', params.NAMESPACE_CI ?: '')
                            .replace('__RLM_API_URL__', params.RLM_API_URL ?: '')
                            .replace('__NETAPP_API_ADDR__', params.NETAPP_API_ADDR ?: '')
                            .replace('__GRAFANA_PORT__', params.GRAFANA_PORT ?: '3000')
                            .replace('__PROMETHEUS_PORT__', params.PROMETHEUS_PORT ?: '9090')
                            .replace('__VAULT_AGENT_KV__', params.VAULT_AGENT_KV ?: '')
                            .replace('__RPM_URL_KV__', params.RPM_URL_KV ?: '')
                            .replace('__TUZ_KV__', params.TUZ_KV ?: '')
                            .replace('__NETAPP_SSH_KV__', params.NETAPP_SSH_KV ?: '')
                            .replace('__MON_SSH_KV__', params.MON_SSH_KV ?: '')
                            .replace('__NETAPP_API_KV__', params.NETAPP_API_KV ?: '')
                            .replace('__GRAFANA_WEB_KV__', params.GRAFANA_WEB_KV ?: '')
                            .replace('__SBERCA_CERT_KV__', params.SBERCA_CERT_KV ?: '')
                            .replace('__ADMIN_EMAIL__', params.ADMIN_EMAIL ?: '')
                        writeFile file: 'deploy_script.sh', text: finalScript
                        sh 'chmod +x deploy_script.sh'
                        withEnv(['SSH_KEY=' + env.SSH_KEY, 'SSH_USER=' + env.SSH_USER]) {
                            sh './deploy_script.sh'
                        }
                        sh 'rm -f deploy_script.sh'
                    }
                }
            }
        }

        stage('Проверка результатов') {
            steps {
                script {
                    echo "[STEP] Проверка результатов развертывания..."
                    withCredentials([sshUserPrivateKey(credentialsId: params.SSH_CREDENTIALS_ID, keyFileVariable: 'SSH_KEY', usernameVariable: 'SSH_USER')]) {
                        writeFile file: 'check_results.sh', text: '''#!/bin/bash
ssh -i "$SSH_KEY" -q -o StrictHostKeyChecking=no \
    "$SSH_USER"@''' + params.SERVER_ADDRESS + ''' << 'ENDSSH'
echo "================================================"
echo "ПРОВЕРКА СЕРВИСОВ:"
echo "================================================"
systemctl is-active prometheus && echo "[OK] Prometheus активен" || echo "[FAIL] Prometheus не активен"
systemctl is-active grafana-server && echo "[OK] Grafana активен" || echo "[FAIL] Grafana не активен"
echo ""
echo "================================================"
echo "ПРОВЕРКА ПОРТОВ:"
echo "================================================"
ss -tln | grep -q ":''' + (params.PROMETHEUS_PORT ?: '9090') + ''' " && echo "[OK] Порт ''' + (params.PROMETHEUS_PORT ?: '9090') + ''' (Prometheus) открыт" || echo "[FAIL] Порт ''' + (params.PROMETHEUS_PORT ?: '9090') + ''' не открыт"
ss -tln | grep -q ":''' + (params.GRAFANA_PORT ?: '3000') + ''' " && echo "[OK] Порт ''' + (params.GRAFANA_PORT ?: '3000') + ''' (Grafana) открыт" || echo "[FAIL] Порт ''' + (params.GRAFANA_PORT ?: '3000') + ''' не открыт"
ss -tln | grep -q ":12990 " && echo "[OK] Порт 12990 (Harvest-NetApp) открыт" || echo "[FAIL] Порт 12990 не открыт"
ss -tln | grep -q ":12991 " && echo "[OK] Порт 12991 (Harvest-Unix) открыт" || echo "[FAIL] Порт 12991 не открыт"
exit 0
ENDSSH
'''
                        sh 'chmod +x check_results.sh'
                        def result
                        withEnv(['SSH_KEY=' + env.SSH_KEY, 'SSH_USER=' + env.SSH_USER]) {
                            result = sh(script: './check_results.sh', returnStdout: true).trim()
                        }
                        sh 'rm -f check_results.sh'
                        echo result
                    }
                }
            }
        }

        stage('Очистка') {
            steps {
                script {
                    echo "[STEP] Очистка временных файлов..."
                    sh "rm -rf temp_data_cred.json"
                    withCredentials([sshUserPrivateKey(credentialsId: params.SSH_CREDENTIALS_ID, keyFileVariable: 'SSH_KEY', usernameVariable: 'SSH_USER')]) {
                        writeFile file: 'cleanup_script.sh', text: '''#!/bin/bash
ssh -i "$SSH_KEY" -q -o StrictHostKeyChecking=no \
    "$SSH_USER"@''' + params.SERVER_ADDRESS + ''' \
    "rm -rf /tmp/deploy-monitoring /tmp/monitoring_deployment.sh /tmp/temp_data_cred.json /opt/mon_distrib/mon_rpm_''' + env.DATE_INSTALL + '''/*.rpm" || true
'''
                        sh 'chmod +x cleanup_script.sh'
                        withEnv(['SSH_KEY=' + env.SSH_KEY, 'SSH_USER=' + env.SSH_USER]) {
                            sh './cleanup_script.sh'
                        }
                        sh 'rm -f cleanup_script.sh'
                    }
                    echo "[SUCCESS] Очистка завершена"
                }
            }
        }

        stage('Получение сведений о развертывании системы') {
            steps {
                script {
                    def domainName = ''
                    withCredentials([sshUserPrivateKey(credentialsId: params.SSH_CREDENTIALS_ID, keyFileVariable: 'SSH_KEY', usernameVariable: 'SSH_USER')]) {
                        writeFile file: 'get_domain.sh', text: '''#!/bin/bash
ssh -i "$SSH_KEY" -q -o StrictHostKeyChecking=no \
    "$SSH_USER"@''' + params.SERVER_ADDRESS + ''' \
    "nslookup ''' + params.SERVER_ADDRESS + ''' 2>/dev/null | grep 'name =' | awk '{print \\$4}' | sed 's/\\.$//' || echo ''"
'''
                        sh 'chmod +x get_domain.sh'
                        withEnv(['SSH_KEY=' + env.SSH_KEY, 'SSH_USER=' + env.SSH_USER]) {
                            domainName = sh(script: './get_domain.sh', returnStdout: true).trim()
                        }
                        sh 'rm -f get_domain.sh'
                    }
                    if (domainName == '') {
                        domainName = params.SERVER_ADDRESS
                    }
                    def serverIp = ''
                    withCredentials([sshUserPrivateKey(credentialsId: params.SSH_CREDENTIALS_ID, keyFileVariable: 'SSH_KEY', usernameVariable: 'SSH_USER')]) {
                        writeFile file: 'get_ip.sh', text: '''#!/bin/bash
ssh -i "$SSH_KEY" -q -o StrictHostKeyChecking=no \
    "$SSH_USER"@''' + params.SERVER_ADDRESS + ''' \
    "hostname -I | awk '{print \\$1}' || echo ''' + (params.SERVER_ADDRESS ?: '') + '''"
'''
                        sh 'chmod +x get_ip.sh'
                        withEnv(['SSH_KEY=' + env.SSH_KEY, 'SSH_USER=' + env.SSH_USER]) {
                            serverIp = sh(script: './get_ip.sh', returnStdout: true).trim()
                        }
                        sh 'rm -f get_ip.sh'
                    }
                    echo "[SUCCESS] Развертывание мониторинговой системы завершено!"
                    echo "[INFO] Доступ к сервисам:"
                    echo " • Prometheus: https://${serverIp}:${params.PROMETHEUS_PORT}"
                    echo " • Prometheus: https://${domainName}:${params.PROMETHEUS_PORT}"
                    echo " • Grafana: https://${serverIp}:${params.GRAFANA_PORT}"
                    echo " • Grafana: https://${domainName}:${params.GRAFANA_PORT}"
                    echo "[INFO] Информация о сервере:"
                    echo " • IP адрес: ${serverIp}"
                    echo " • Домен: ${domainName}"
                    echo "==============================="
                }
            }
        }
    }

    post {
        success {
            echo "================================================"
            echo "✅ Pipeline (external) успешно завершен!"
            echo "================================================"
        }
        failure {
            echo "================================================"
            echo "❌ Pipeline (external) завершился с ошибкой!"
            echo "Проверьте логи для диагностики проблемы"
            echo "================================================"
        }
        always {
            echo "Время выполнения: ${currentBuild.durationString}"
        }
    }
}
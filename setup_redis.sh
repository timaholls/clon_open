#!/bin/bash

# Цвета для вывода
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
BLUE='\033[0;34m'
NC='\033[0m'

# Функция для вывода сообщений
function log() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

function success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

function warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

function error() {
    echo -e "${RED}[ERROR]${NC} $1"
    exit 1
}

# Проверка запуска от имени root
if [ "$(id -u)" != "0" ]; then
    error "Этот скрипт должен быть запущен от имени root или с sudo"
fi

# Настройки Redis
REDIS_PASSWORD=$(openssl rand -base64 24)
REDIS_PORT=6379
REDIS_BIND_IP="127.0.0.1" # Меняйте на 0.0.0.0 для доступа из внешней сети
REDIS_MAX_MEMORY="256mb"
REDIS_MAX_MEMORY_POLICY="allkeys-lru"
REDIS_CONFIG_FILE="/etc/redis/redis.conf"
REDIS_LOG_FILE="/var/log/redis/redis-server.log"

log "Начинаем установку и настройку Redis для CSRF-защиты..."

# Обновление списка пакетов
log "Обновление списка пакетов..."
apt-get update -y || error "Не удалось обновить список пакетов"

# Установка Redis
log "Установка Redis..."
apt-get install redis-server -y || error "Не удалось установить Redis"

# Остановка сервиса Redis перед настройкой
log "Остановка Redis для настройки..."
systemctl stop redis-server || warning "Не удалось остановить Redis, возможно сервис еще не запущен"

# Создание резервной копии оригинального файла конфигурации
log "Создание резервной копии оригинального конфига Redis..."
if [ -f "$REDIS_CONFIG_FILE" ]; then
    cp "$REDIS_CONFIG_FILE" "$REDIS_CONFIG_FILE.backup.$(date +%Y%m%d%H%M%S)" || warning "Не удалось создать резервную копию конфига"
else
    warning "Файл конфигурации Redis не найден по пути $REDIS_CONFIG_FILE"
fi

# Настройка Redis
log "Настройка Redis..."

# Создаем временный файл конфигурации
TMP_CONFIG=$(mktemp)

cat > "$TMP_CONFIG" << EOF
# Redis configuration for CSRF protection
# Generated automatically $(date)

# Network
bind $REDIS_BIND_IP
port $REDIS_PORT
protected-mode yes
tcp-backlog 511
timeout 0
tcp-keepalive 300

# General
daemonize yes
supervised systemd
pidfile /var/run/redis/redis-server.pid
loglevel notice
logfile $REDIS_LOG_FILE
syslog-enabled no
databases 16

# Security
requirepass $REDIS_PASSWORD

# Memory management (optimized for CSRF tokens)
maxmemory $REDIS_MAX_MEMORY
maxmemory-policy $REDIS_MAX_MEMORY_POLICY
maxmemory-samples 5

# Snapshotting (for CSRF tokens not critical)
save 900 1
save 300 10
save 60 10000
stop-writes-on-bgsave-error yes
rdbcompression yes
rdbchecksum yes
dbfilename dump.rdb
dir /var/lib/redis

# Append only mode (for CSRF tokens not critical)
appendonly no
appendfilename "appendonly.aof"
appendfsync everysec
no-appendfsync-on-rewrite no
auto-aof-rewrite-percentage 100
auto-aof-rewrite-min-size 64mb
aof-load-truncated yes
aof-use-rdb-preamble yes

# LUA scripting
lua-time-limit 5000

# Slow log
slowlog-log-slower-than 10000
slowlog-max-len 128

# Latency monitoring
latency-monitor-threshold 0

# Event notification
notify-keyspace-events ""

# Advanced config
hash-max-ziplist-entries 512
hash-max-ziplist-value 64
list-max-ziplist-size -2
list-compress-depth 0
set-max-intset-entries 512
zset-max-ziplist-entries 128
zset-max-ziplist-value 64
hll-sparse-max-bytes 3000
stream-node-max-bytes 4096
stream-node-max-entries 100
activerehashing yes
client-output-buffer-limit normal 0 0 0
client-output-buffer-limit replica 256mb 64mb 60
client-output-buffer-limit pubsub 32mb 8mb 60
hz 10
dynamic-hz yes
aof-rewrite-incremental-fsync yes
rdb-save-incremental-fsync yes
jemalloc-bg-thread yes
EOF

# Проверка временного файла конфигурации
if [ ! -s "$TMP_CONFIG" ]; then
    error "Ошибка при создании файла конфигурации Redis"
fi

# Копирование файла конфигурации
mv "$TMP_CONFIG" "$REDIS_CONFIG_FILE" || error "Не удалось заменить файл конфигурации Redis"
chown redis:redis "$REDIS_CONFIG_FILE" || warning "Не удалось изменить права на файл конфигурации"
chmod 640 "$REDIS_CONFIG_FILE" || warning "Не удалось установить права на файл конфигурации"

# Создание директории для логов если она не существует
if [ ! -d "/var/log/redis" ]; then
    mkdir -p /var/log/redis
    chown redis:redis /var/log/redis
fi

# Запуск и включение Redis в автозагрузку
log "Запуск Redis и добавление в автозагрузку..."
systemctl daemon-reload
systemctl restart redis-server || error "Не удалось запустить Redis"
systemctl enable redis-server || warning "Не удалось добавить Redis в автозагрузку"

# Проверка статуса Redis
log "Проверка статуса Redis..."
if systemctl is-active --quiet redis-server; then
    success "Redis успешно запущен и работает"
else
    error "Redis не запустился после настройки. Проверьте логи: 'journalctl -u redis-server'"
fi

# Настройка брандмауэра для Redis (только для локального доступа)
if command -v ufw &>/dev/null; then
    log "Настройка брандмауэра UFW для Redis..."
    if [ "$REDIS_BIND_IP" = "127.0.0.1" ]; then
        # Для локального доступа
        ufw allow from 127.0.0.1 to any port $REDIS_PORT comment "Redis local access" || warning "Не удалось настроить UFW для Redis"
    elif [ "$REDIS_BIND_IP" = "0.0.0.0" ]; then
        # Предупреждение для открытых подключений
        warning "Redis настроен для приема внешних подключений! Рекомендуется ограничить доступ к определенным IP-адресам!"
        read -p "Хотите ли вы открыть порт Redis ($REDIS_PORT) для всех соединений? (y/n): " -n 1 -r
        echo
        if [[ $REPLY =~ ^[Yy]$ ]]; then
            ufw allow $REDIS_PORT/tcp comment "Redis external access" || warning "Не удалось настроить UFW для Redis"
        else
            log "Пропуск настройки брандмауэра для Redis"
        fi
    fi
else
    warning "UFW не установлен. Пропуск настройки брандмауэра."
fi

# Создание конфигурационного файла для Django
log "Создание конфигурационного файла для Django..."

DJANGO_REDIS_CONFIG=$(mktemp)
cat > "$DJANGO_REDIS_CONFIG" << EOF
# Django Redis configuration for CSRF protection
# Generated automatically $(date)

# Redis connection settings
REDIS_HOST = '${REDIS_BIND_IP}'
REDIS_PORT = ${REDIS_PORT}
REDIS_DB = 0
REDIS_PASSWORD = '${REDIS_PASSWORD}'

# Cache settings for Django
CACHES = {
    'default': {
        'BACKEND': 'django_redis.cache.RedisCache',
        'LOCATION': f'redis://{REDIS_HOST}:{REDIS_PORT}/{REDIS_DB}',
        'OPTIONS': {
            'CLIENT_CLASS': 'django_redis.client.DefaultClient',
            'PASSWORD': REDIS_PASSWORD,
            'SOCKET_CONNECT_TIMEOUT': 5,
            'SOCKET_TIMEOUT': 5,
        }
    }
}

# CSRF settings
CSRF_TOKEN_EXPIRY = 24 * 60 * 60  # 24 hours in seconds
CSRF_STRICT_VERIFICATION = True
CSRF_VALIDATE_IP = False
CSRF_VALIDATE_USER_AGENT = True
CSRF_ROTATE_TOKENS = False  # Set to True for higher security with token rotation
EOF

# Отображаем информацию о настройках
success "Redis успешно установлен и настроен! Вот ваши данные для подключения:"
echo -e "Хост: ${YELLOW}${REDIS_BIND_IP}${NC}"
echo -e "Порт: ${YELLOW}${REDIS_PORT}${NC}"
echo -e "Пароль: ${YELLOW}${REDIS_PASSWORD}${NC}"
echo -e "Максимальная память: ${YELLOW}${REDIS_MAX_MEMORY}${NC}"
echo -e "Политика вытеснения: ${YELLOW}${REDIS_MAX_MEMORY_POLICY}${NC}"

# Сохраняем настройки для Django
echo -e "Настройки Django для Redis сохранены в файл: ${YELLOW}${DJANGO_REDIS_CONFIG}${NC}"

# Тестовое подключение
log "Выполнение тестового подключения к Redis..."
REDIS_CLI_TEST=$(redis-cli -h $REDIS_BIND_IP -p $REDIS_PORT -a $REDIS_PASSWORD ping 2>&1)

if [[ "$REDIS_CLI_TEST" == "PONG" ]]; then
    success "Тестовое подключение к Redis выполнено успешно!"
else
    warning "Не удалось подключиться к Redis. Ошибка: $REDIS_CLI_TEST"
fi

# Демонстрация команд для управления Redis
echo -e "\n${BLUE}Команды для управления Redis:${NC}"
echo -e "Остановить Redis: ${YELLOW}sudo systemctl stop redis-server${NC}"
echo -e "Запустить Redis: ${YELLOW}sudo systemctl start redis-server${NC}"
echo -e "Перезапустить Redis: ${YELLOW}sudo systemctl restart redis-server${NC}"
echo -e "Проверить статус Redis: ${YELLOW}sudo systemctl status redis-server${NC}"
echo -e "Подключиться к Redis CLI: ${YELLOW}redis-cli -a $REDIS_PASSWORD${NC}"
echo -e "Мониторинг Redis: ${YELLOW}redis-cli -a $REDIS_PASSWORD monitor${NC}"
echo -e "Просмотр статистики памяти: ${YELLOW}redis-cli -a $REDIS_PASSWORD info memory${NC}"

echo -e "\n${GREEN}Установка и настройка Redis завершена успешно!${NC}"
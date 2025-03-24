#!/bin/sh

# Скрипт для настройки Nginx и SSL для Django-проекта
# Запускать с правами sudo: sudo sh setup_nginx.sh

# Цвета для вывода
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Функция для вывода статуса
echo_status() {
    printf "${GREEN}[INFO]${NC} %s\n" "$1"
}

# Функция для вывода ошибок
echo_error() {
    printf "${RED}[ERROR]${NC} %s\n" "$1"
}

# Функция для вывода предупреждений
echo_warning() {
    printf "${YELLOW}[WARNING]${NC} %s\n" "$1"
}

# Проверка прав администратора
if [ "$(id -u)" -ne 0 ]; then
    echo_error "Пожалуйста, запустите скрипт с правами администратора (sudo)"
    exit 1
fi

# Получаем текущую директорию проекта
PROJECT_DIR=$(pwd)
echo_status "Директория проекта: $PROJECT_DIR"

# Установка Nginx
echo_status "Установка Nginx..."
apt update
apt install -y nginx
systemctl enable nginx
systemctl start nginx

# Проверка успешности установки Nginx
if ! command -v nginx > /dev/null 2>&1; then
    echo_error "Не удалось установить Nginx. Пожалуйста, установите его вручную."
    exit 1
fi
echo_status "Nginx успешно установлен"

# Создание директории для SSL-сертификатов
echo_status "Создание директории для SSL-сертификатов..."
mkdir -p /etc/nginx/ssl

# Генерация самоподписанных SSL-сертификатов
echo_status "Генерация самоподписанных SSL-сертификатов..."
openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
    -keyout /etc/nginx/ssl/nginx.key \
    -out /etc/nginx/ssl/nginx.crt \
    -subj "/C=US/ST=State/L=City/O=Organization/CN=localhost"

# Проверка успешности генерации сертификатов
if [ ! -f /etc/nginx/ssl/nginx.crt ] || [ ! -f /etc/nginx/ssl/nginx.key ]; then
    echo_error "Не удалось создать SSL-сертификаты. Пожалуйста, создайте их вручную."
    exit 1
fi
echo_status "SSL-сертификаты успешно созданы"

# Копирование конфигурации Nginx
echo_status "Копирование конфигурации Nginx..."
cp "$PROJECT_DIR/nginx_config.conf" /etc/nginx/sites-available/django_proxy

# Обновление путей в конфигурационном файле
echo_status "Обновление путей в конфигурационном файле..."
sed -i "s|/путь/к/вашему/проекту/clon_open|$PROJECT_DIR|g" /etc/nginx/sites-available/django_proxy

# Создание символической ссылки на конфигурацию
echo_status "Активация конфигурации Nginx..."
ln -sf /etc/nginx/sites-available/django_proxy /etc/nginx/sites-enabled/
rm -f /etc/nginx/sites-enabled/default

# Проверка конфигурации Nginx
echo_status "Проверка конфигурации Nginx..."
nginx -t

NGINX_TEST_RESULT=$?
if [ $NGINX_TEST_RESULT -ne 0 ]; then
    echo_error "Ошибка в конфигурации Nginx. Пожалуйста, исправьте ошибки и перезапустите Nginx."
    exit 1
fi

# Перезапуск Nginx
echo_status "Перезапуск Nginx..."
systemctl restart nginx

# Открытие портов в брандмауэре (если есть ufw)
if command -v ufw > /dev/null 2>&1; then
    echo_status "Открытие портов 80 и 443 в брандмауэре..."
    ufw allow 80
    ufw allow 443
fi

# Проверка, запущен ли Nginx
if systemctl is-active --quiet nginx; then
    echo_status "Nginx успешно запущен"
else
    echo_error "Не удалось запустить Nginx. Пожалуйста, проверьте журналы ошибок."
    exit 1
fi

echo_status "Настройка завершена!"
echo_status "Теперь вы можете запустить Django-сервер командой:"
echo_status "cd $PROJECT_DIR && python manage.py runserver 0.0.0.0:8000"
echo ""
echo_warning "Важно: Перед использованием в производственной среде,"
echo_warning "замените самоподписанные сертификаты на доверенные SSL-сертификаты"
echo_warning "и настройте соответствующим образом файрволл."
echo ""
echo_status "Для просмотра логов Nginx используйте:"
echo_status "sudo tail -f /var/log/nginx/django_access.log"
echo_status "sudo tail -f /var/log/nginx/django_error.log"
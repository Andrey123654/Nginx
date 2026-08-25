#!/bin/sh
set -eu

if [ "$(id -u)" -ne 0 ]; then
  echo "Запустите скрипт от root: sudo ./deploy/install-ubuntu.sh" >&2
  exit 1
fi

. /etc/os-release
if [ "${ID:-}" != "ubuntu" ] || [ "${VERSION_ID:-}" != "26.04" ]; then
  echo "Поддерживаемая ОС: Ubuntu Server 26.04 LTS; обнаружено ${PRETTY_NAME:-unknown}" >&2
  exit 1
fi

PROJECT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
apt-get update
apt-get install -y --no-install-recommends python3 python3-venv nginx ca-certificates

if ! getent group nginxscope >/dev/null; then
  addgroup --system nginxscope
fi
if ! getent passwd nginxscope >/dev/null; then
  adduser --system --ingroup nginxscope --home /opt/nginx-scope --no-create-home --disabled-login nginxscope
fi

install -d -o nginxscope -g nginxscope -m 0750 /opt/nginx-scope
install -o nginxscope -g nginxscope -m 0640 "$PROJECT_DIR/audit.py" /opt/nginx-scope/audit.py
install -d -o nginxscope -g nginxscope -m 0750 /opt/nginx-scope/web /opt/nginx-scope/web/static
install -o nginxscope -g nginxscope -m 0640 "$PROJECT_DIR/web/__init__.py" "$PROJECT_DIR/web/app.py" /opt/nginx-scope/web/
install -o nginxscope -g nginxscope -m 0640 "$PROJECT_DIR"/web/static/* /opt/nginx-scope/web/static/
install -o nginxscope -g nginxscope -m 0640 "$PROJECT_DIR/requirements.txt" /opt/nginx-scope/requirements.txt

python3 -m venv /opt/nginx-scope/.venv
/opt/nginx-scope/.venv/bin/pip install --no-cache-dir --upgrade pip
/opt/nginx-scope/.venv/bin/pip install --no-cache-dir -r /opt/nginx-scope/requirements.txt
chown -R nginxscope:nginxscope /opt/nginx-scope
chmod -R o-rwx /opt/nginx-scope

install -o root -g root -m 0644 "$PROJECT_DIR/deploy/nginx-scope.service" /etc/systemd/system/nginx-scope.service
systemctl daemon-reload
systemctl enable nginx-scope.service
systemctl restart nginx-scope.service
echo "Сервис слушает 0.0.0.0:8080; откройте http://<IP-СЕРВЕРА>:8080"
echo "Настройте TLS reverse proxy по образцу deploy/nginx-scope.conf.example"

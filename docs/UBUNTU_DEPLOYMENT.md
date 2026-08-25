# Развёртывание на Ubuntu Server 26.04 LTS

Ubuntu 26.04 LTS выбрана как актуальная LTS-версия для production. Сервис не требует базы данных: загруженные конфигурации анализируются в памяти и не сохраняются.

## Вариант 1: Docker Compose

Требования: Ubuntu Server 26.04 LTS, Docker Engine с Compose plugin, отдельное DNS-имя и TLS-сертификат.

```bash
git clone https://github.com/Andrey123654/Nginx.git
cd Nginx
docker compose build --pull
PUBLIC_ORIGIN=https://scope.example.org docker compose up -d
curl --fail http://127.0.0.1:8080/healthz
```

Контейнер запускается без root, с read-only filesystem и без Linux capabilities. Порт `8080` публикуется на всех интерфейсах. До запуска ограничьте доступ доверенной корпоративной подсетью (пример для `10.20.0.0/16`):

```bash
sudo ufw allow from 10.20.0.0/16 to any port 8080 proto tcp
sudo ufw deny 8080/tcp
```

Для production предпочтителен HTTPS reverse proxy. Скопируйте `deploy/nginx-scope.conf.example` в `/etc/nginx/sites-available/nginx-scope`, замените домен и пути сертификатов, затем включите сайт:

```bash
sudo ln -s /etc/nginx/sites-available/nginx-scope /etc/nginx/sites-enabled/nginx-scope
sudo nginx -t
sudo systemctl reload nginx
```

## Вариант 2: systemd

```bash
git clone https://github.com/Andrey123654/Nginx.git
cd Nginx
sudo ./deploy/install-ubuntu.sh
curl --fail http://127.0.0.1:8080/healthz
```

Скрипт прекращает работу, если ОС отличается от Ubuntu 26.04. Он создаёт непривилегированного пользователя `nginxscope`, виртуальное окружение и hardened systemd unit. Перед production-запуском замените `PUBLIC_ORIGIN` в `/etc/systemd/system/nginx-scope.service` на реальный HTTPS origin и выполните `sudo systemctl daemon-reload && sudo systemctl restart nginx-scope`. TLS reverse proxy настраивается отдельно по примеру выше.

Systemd-сервис запускает Uvicorn с `--host 0.0.0.0 --port 8080`. Для обращения с другой машины используйте `http://<IP-СЕРВЕРА>:8080` и убедитесь, что firewall/security group разрешает входящий TCP/8080 только из доверенных сетей.

## Обновление

Для Docker:

```bash
git pull --ff-only
docker compose build --pull
docker compose up -d
```

Для systemd повторно запустите `sudo ./deploy/install-ubuntu.sh` после `git pull --ff-only`. Установщик копирует обновлённые файлы и принудительно перезапускает уже работающий `nginx-scope.service`.

Если код был обновлён вручную в `/opt/nginx-scope`, обязательно перезапустите процесс:

```bash
sudo systemctl restart nginx-scope
sudo systemctl status nginx-scope --no-pager
```

## Контроль после установки

```bash
systemctl status nginx-scope --no-pager
journalctl -u nginx-scope --since today
curl -I https://scope.example.org/
```

Проверьте HSTS, CSP, `X-Content-Type-Options`, ограничение размера upload и rate limit. Размещайте сервис во внутреннем административном сегменте или защищайте его корпоративным SSO/WAF. Не публикуйте его анонимно в интернет.

## Датчики областей видимости

Команда `bin/run-sensor.sh` запускается отдельно в каждой зоне. Внешний датчик не должен использовать корпоративный DNS/VPN, внутренний — должен находиться в контролируемом внутреннем сегменте. Полученные `sensor.json` вместе с `inventory.json` загружаются в веб-интерфейс.

## Резервное копирование

Пользовательские файлы и отчёты сервером не сохраняются, поэтому резервируется только Git-репозиторий и локальная конфигурация reverse proxy/TLS. Экспортированный JSON-отчёт храните в утверждённом защищённом хранилище или SIEM.

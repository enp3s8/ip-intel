# ip-intel

CLI-утилита на Python, которая параллельно собирает информацию по IP-адресу (или домену) из 4 источников:

1. **Shodan** — при наличии `SHODAN_API_KEY` использует полный Shodan Host API (баннеры, сервисы, ISP, ОС, порты, CVE); без ключа автоматически работает через бесплатный **Shodan InternetDB** (порты, hostnames, CPE, теги, CVE).
2. **ipinfo.io** — геолокация, PTR, ASN/организация, часовой пояс, Anycast (поддерживает опциональный `IPINFO_TOKEN`).
3. **2ip** — данные `api.2ip.io` (гео, ASN, флаг хостинга) + RIPE-провайдер и подсеть с `api.2ip.me/provider.json` (с фолбэком на `api.2ip.me/geo.json`).
4. **MaxMind** — поддерживает и **Web Services API** (`geolite.info` / `geoip.maxmind.com`), и локальные базы **`.mmdb`** (`GeoLite2-City.mmdb`, `GeoLite2-Country.mmdb`, `GeoLite2-ASN.mmdb`) через встроенный pure-Python парсер MMDB v2 (без установки `geoip2` / `maxminddb`).

## Установка

```bash
git clone https://github.com/enp3s8/ip-intel.git
cd ip-intel
pip install -r requirements.txt
```

## Использование

```bash
# Интерактивный ввод IP или домена
python3 ip_intel.py

# Передать один или несколько IP / доменов аргументом
python3 ip_intel.py 1.1.1.1
python3 ip_intel.py 8.8.8.8 2606:4700:4700::1111 cloudflare.com

# Вывод в JSON / сохранение отчёта в файл
python3 ip_intel.py 1.1.1.1 --json
python3 ip_intel.py 1.1.1.1 --save report.json

# Чтение из stdin
echo "9.9.9.9" | python3 ip_intel.py --json

# Явно указать локальные .mmdb базы для MaxMind
python3 ip_intel.py 1.1.1.1 --mmdb /path/to/GeoLite2-City.mmdb --mmdb /path/to/GeoLite2-ASN.mmdb
```

## Настройка API-ключей (опционально)

Скрипт работает сразу без ключей. Для расширенных данных и лимитов создайте `.env`:

```bash
cp .env.example .env
```

Доступные переменные:
- `SHODAN_API_KEY` — ключ Shodan Host API
- `IPINFO_TOKEN` — токен ipinfo.io
- `TWOIP_TOKEN` — токен 2ip.io
- `MAXMIND_ACCOUNT_ID`, `MAXMIND_LICENSE_KEY`, `MAXMIND_ENDPOINT` (`geolite` или `paid`) — MaxMind Web Services
- `MAXMIND_MMDB_PATHS` — пути к локальным `.mmdb` файлам через `:`

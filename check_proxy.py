#!/usr/bin/env python3
"""Check MTProto DNS A records independently using the supplied API."""
import argparse
import csv
import getpass
import ipaddress
import json
import os
from pathlib import Path
import re
import socket
import sys
import time
import warnings
from datetime import datetime, timezone
from urllib.parse import parse_qs, urlsplit, urlencode
from urllib.request import Request, build_opener, HTTPRedirectHandler
from urllib.error import HTTPError, URLError

BASE = 'https://api.yazaebalsyadelatproxy.cc'
CONFIG = Path(os.environ.get('LOCALAPPDATA', str(Path.home() / '.config'))) / 'dinamic_ip' / 'api_key'
SUSPECT = {'RKN_BLOCK', 'DATA_CUT'}
STATUSES = {'OK', 'RKN_BLOCK', 'DATA_CUT', 'MT_DEAD', 'DOWN', 'UNKNOWN'}

class NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None

class ApiError(Exception):
    def __init__(self, code, msg):
        super().__init__(msg)
        self.code = code

class API:
    def __init__(self, key):
        self.key = key
        self.last = 0.0
        self.opener = build_opener(NoRedirect())

    def call(self, path, payload=None):
        for attempt in range(3):
            time.sleep(max(0, 2.2 - (time.monotonic() - self.last)))
            self.last = time.monotonic()
            req = Request(BASE + path, data=None if payload is None else json.dumps(payload).encode(),
                          headers={'X-API-Key': self.key, 'Content-Type': 'application/json', 'Accept': 'application/json'})
            try:
                with self.opener.open(req, timeout=75) as response:
                    result = json.load(response)
                if not isinstance(result, dict):
                    raise ApiError(0, 'API вернул неожиданный формат')
                return result
            except HTTPError as e:
                code = e.code
                delay = e.headers.get('Retry-After', '60')
                e.close()
                if code == 429 and attempt < 2:
                    try:
                        delay = float(delay)
                    except ValueError:
                        delay = 60
                    print('Лимит API: ожидание перед повтором.', flush=True)
                    time.sleep(max(2.2, delay))
                    continue
                messages = {401:'Ключ не принят. Используй --reset-key.', 403:'Ключ отозван или заблокирован.',
                            429:'Лимит API исчерпан.', 503:'API временно отключён.', 400:'Некорректный запрос.',
                            422:'Некорректные параметры прокси.', 502:'Ошибка проверки на стороне API.'}
                raise ApiError(code, messages.get(code, f'HTTP {code}')) from None
            except (URLError, TimeoutError, OSError, ValueError):
                raise ApiError(0, 'Сетевая ошибка или некорректный JSON API.') from None

    def check(self, ip, port, secret, timeout):
        result = self.call('/v1/check?' + urlencode({'mode':'sync', 'timeout':timeout}),
                           {'server':ip, 'port':port, 'secret':secret})
        if result.get('status') not in STATUSES:
            raise ApiError(0, 'Неизвестный формат статуса API.')
        if str(result.get('server', '')) != ip:
            raise ApiError(0, 'API не подтвердил проверяемый IP.')
        return result

def hidden_input(prompt):
    with warnings.catch_warnings():
        warnings.simplefilter('error', getpass.GetPassWarning)
        try:
            return getpass.getpass(prompt)
        except getpass.GetPassWarning:
            raise ValueError('Скрытый ввод недоступен. Запусти в обычном терминале (Windows: PowerShell или CMD).') from None

def get_key(reset=False):
    if not reset and CONFIG.is_file():
        return CONFIG.read_text(encoding='utf-8').strip()
    key = hidden_input('API-ключ (ввод скрыт): ').strip()
    if not re.fullmatch(r'rf_[A-Za-z0-9_-]+', key):
        raise ValueError('Некорректный формат API-ключа.')
    API(key).call('/v1/me')
    CONFIG.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    tmp = CONFIG.with_name('api_key.new')
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        with os.fdopen(fd, 'w', encoding='utf-8') as f:
            f.write(key + '\n')
        os.replace(tmp, CONFIG)
    finally:
        if tmp.exists():
            tmp.unlink()
    print('Ключ проверен и сохранён локально.')
    return key

def parse_link(link):
    u = urlsplit(link.strip())
    valid = (u.scheme == 'tg' and u.netloc.lower() == 'proxy') or (
        u.scheme == 'https' and u.hostname in ('t.me', 'telegram.me') and u.path.rstrip('/') == '/proxy')
    if not valid:
        raise ValueError('Нужна ссылка tg://proxy?... или https://t.me/proxy?...')
    q = parse_qs(u.query, strict_parsing=True)
    try:
        if any(len(q[k]) != 1 for k in ('server','port','secret')):
            raise ValueError
        host, port, secret = q['server'][0].rstrip('.'), int(q['port'][0]), q['secret'][0]
        if not host or not secret or not 1 <= port <= 65535:
            raise ValueError
        return host.encode('idna').decode('ascii'), port, secret
    except (KeyError, ValueError):
        raise ValueError('В ссылке нужны server, port и secret.') from None

def sort_ips(ips):
    return sorted(set(ips), key=ipaddress.IPv4Address)

def resolve_ips(host):
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        pass
    else:
        if ip.version != 4:
            raise ValueError('Поддерживаются только IPv4.')
        return [str(ip)], 'Прямой IP'
    # Prefer authoritative answers from each NS for the DNS zone.
    try:
        import dns.resolver
        import dns.query
        import dns.message
        import dns.flags
        import dns.rcode
        import dns.rdatatype
    except ImportError:
        print('Внимание: dnspython не установлен; используется системный DNS (может вернуть не все A-записи).')
    else:
        try:
            r = dns.resolver.Resolver()
            r.lifetime = 5
            zone = dns.resolver.zone_for_name(host, resolver=r, lifetime=8)
            nameservers = r.resolve(zone, 'NS')
            answers = []
            missing = 0
            for ns in nameservers:
                try:
                    servers = r.resolve(ns.target, 'A')
                    for address in servers:
                        query = dns.message.make_query(host, 'A')
                        query.flags &= ~dns.flags.RD
                        try:
                            response = dns.query.udp(query, address.address, timeout=3)
                            if response.flags & dns.flags.TC:
                                response = dns.query.tcp(query, address.address, timeout=5)
                            if response.rcode() != dns.rcode.NOERROR or not response.flags & dns.flags.AA:
                                continue
                            ips = {item.address for rr in response.answer if rr.rdtype == dns.rdatatype.A
                                   for item in rr}
                            if ips:
                                answers.append(ips)
                                break
                        except Exception:
                            continue
                    else:
                        missing += 1
                except Exception:
                    missing += 1
            if answers:
                if missing or any(a != answers[0] for a in answers):
                    print('Внимание: NS ответили не все или дали разные наборы IP; используется объединение ответов.')
                return sort_ips(set.union(*answers)), f'Авторитетный DNS ({len(answers)} NS)'
            print('Авторитетные A-записи недоступны; используется системный DNS.')
        except Exception:
            print('Не удалось опросить авторитетный DNS; используется системный DNS.')
    try:
        ips = {x[4][0] for x in socket.getaddrinfo(host, None, socket.AF_INET, socket.SOCK_STREAM)}
    except socket.gaierror:
        raise ValueError('Не удалось получить A-записи домена.') from None
    if not ips:
        raise ValueError('A-записи не найдены.')
    return sort_ips(ips), 'Системный DNS (полнота не гарантирована)'

def safe_result(api, ip, port, secret, timeout):
    try:
        return api.check(ip, port, secret, timeout)
    except ApiError as exc:
        if exc.code in (401,403,429,503,400,422):
            raise
        print(f'  Ошибка для {ip}: {exc}', flush=True)
        return {'status':'API_ERROR'}

def field(result, side, key):
    v = result.get(side)
    return v.get(key) if isinstance(v, dict) else None

def fmt(v):
    return '-' if v is None else ('yes' if v else 'no') if isinstance(v,bool) else str(v)

def check_all(api, ips, port, secret, timeout, recheck):
    rows = []
    for index, ip in enumerate(ips, 1):
        print(f'[{index}/{len(ips)}] {ip}:{port} ...', flush=True)
        first = safe_result(api, ip, port, secret, timeout)
        second = None
        if recheck and first['status'] in SUSPECT:
            print('  Повторная проверка подозрительного результата...', flush=True)
            second = safe_result(api, ip, port, secret, timeout)
        status = first['status']
        last = second or first
        confirmed = second is not None and status in SUSPECT and second['status'] in SUSPECT
        action = ('REVIEW_DNS' if confirmed else 'RECHECK' if status in SUSPECT else
                  'KEEP' if status == 'OK' else 'CHECK_VPS' if status in ('DOWN','MT_DEAD') else 'RECHECK')
        row = {'ip':ip, 'port':port, 'status':status, 'recheck':second['status'] if second else '',
               'action':action, 'checked_at':last.get('checked_at','')}
        for side in ('local','remote'):
            for key in ('tcp','handshake','data','ssh','ping_ms','latency_ms','duration_ms'):
                row[f'{side}_{key}'] = field(last, side, key)
        rows.append(row)
        print(f"  {status}" + (f" -> {second['status']}" if second else '') +
              f" | RU data={fmt(row['local_data'])} latency={fmt(row['local_latency_ms'])} ms"
              f" | EXT data={fmt(row['remote_data'])} latency={fmt(row['remote_latency_ms'])} ms", flush=True)
    return rows

def main():
    p = argparse.ArgumentParser(description='MTProto: проверка каждого IPv4 из DNS')
    p.add_argument('--reset-key', action='store_true', help='ввести и сохранить новый API-ключ')
    p.add_argument('--key-only', action='store_true', help='проверить ключ и выйти')
    p.add_argument('--timeout', type=int, default=10, choices=range(1,16), metavar='1..15')
    p.add_argument('--no-recheck', action='store_true', help='не перепроверять подозрительные IP')
    p.add_argument('--output', type=Path, help='путь к CSV-отчёту')
    args = p.parse_args()
    try:
        key = get_key(args.reset_key)
        api = API(key)
        if args.key_only:
            api.call('/v1/me')
            print('API-ключ действителен.')
            return 0
        host, port, secret = parse_link(hidden_input('MTProto-ссылка (ввод скрыт): '))
        ips, source = resolve_ips(host)
        print(f'\nДомен: {host} | Порт: {port} | IP: {len(ips)} | DNS: {source}')
        print('\n'.join(ips))
        rows = check_all(api, ips, port, secret, args.timeout, not args.no_recheck)
        print('\n' + f"{'IPv4':15} {'STATUS':12} {'RECHECK':12} ACTION")
        for row in rows:
            print(f"{row['ip']:15} {row['status']:12} {row['recheck'] or '-':12} {row['action']}")
        candidates = [r['ip'] for r in rows if r['action'] == 'REVIEW_DNS']
        print('\nКандидаты на исключение из DNS (после ручной проверки):')
        print('\n'.join(candidates) if candidates else 'Нет подтверждённых повтором кандидатов.')
        print('RU — только точка наблюдения API, не вся Россия. DNS не изменялся.')
        output = args.output or Path.cwd() / ('proxy-check-' + datetime.now(timezone.utc).strftime('%Y%m%d-%H%M%S-%f') + '.csv')
        with output.open('w', encoding='utf-8-sig', newline='') as f:
            writer = csv.DictWriter(f, fieldnames=list(rows[0]))
            writer.writeheader()
            writer.writerows(rows)
        print(f'CSV: {output.resolve()}')
        return 0
    except (ValueError, ApiError, OSError) as exc:
        print(f'Ошибка: {exc}', file=sys.stderr)
        return 1
    except (KeyboardInterrupt, EOFError):
        print('\nПроверка отменена.', file=sys.stderr)
        return 130

if __name__ == '__main__':
    sys.exit(main())

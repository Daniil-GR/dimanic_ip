"""Persist explicit per-host monitoring exclusions independently of reports."""
import ipaddress
import json


def read(path):
    try:
        value=json.loads(path.read_text(encoding='utf-8'))
    except FileNotFoundError:
        return {}
    except (OSError, ValueError):
        raise ValueError('Не удалось прочитать настройки паузы IPv4. Проверка и автоудаление остановлены.') from None
    try:
        if not isinstance(value,dict):
            raise ValueError
        for host,ips in value.items():
            if not isinstance(host,str) or not host or not isinstance(ips,list):
                raise ValueError
            if any(not isinstance(ip,str) or str(ipaddress.IPv4Address(ip))!=ip for ip in ips):
                raise ValueError
    except (ValueError,TypeError):
        raise ValueError('Некорректные настройки паузы IPv4. Проверка и автоудаление остановлены.') from None
    return value


def paused(path,host):
    return set(read(path).get(host.lower().rstrip('.'),[]))


def update(path,host,ip,enabled,write):
    data=read(path)
    host=host.lower().rstrip('.')
    if not host or str(ipaddress.IPv4Address(ip))!=ip or type(enabled) is not bool:
        raise ValueError('Некорректные параметры паузы.')
    ips=set(data.get(host,[]))
    if enabled:
        ips.add(ip)
    else:
        ips.discard(ip)
    if ips:
        data[host]=sorted(ips)
    else:
        data.pop(host,None)
    write(path,data)
    return ips


def active_pool(ips,rows,excluded):
    return ([ip for ip in ips if ip not in excluded],
            [r for r in rows if r['ip'] not in excluded and r['ip'] in ips])

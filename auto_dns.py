"""Conservative auto-clean policy and persistent provisioning protection."""
import ipaddress
import json


def read_protected(path):
    if not path.exists():
        return {}
    try:
        data = json.loads(path.read_text(encoding='utf-8'))
        if not isinstance(data, dict):
            raise ValueError
        for host, ips in data.items():
            if not isinstance(ips, list) or any(not isinstance(ip, str) or str(ipaddress.IPv4Address(ip)) != ip for ip in ips):
                raise ValueError
        return data
    except (OSError, ValueError, TypeError):
        raise ValueError('Не удалось прочитать список защищённых новых IP. Автоудаление запрещено.') from None


def protect(path, host, ips, write):
    data = read_protected(path)
    data[host] = sorted(set(data.get(host, [])) | set(ips))
    write(path, data)


def release_healthy(path, host, rows, write):
    data = read_protected(path)
    previous = set(data.get(host, []))
    current = previous - {r['ip'] for r in rows if r.get('local_data') is True}
    if current != previous:
        if current:
            data[host] = sorted(current)
        else:
            data.pop(host, None)
        write(path, data)
    return current


def release_protection(path, host, ip, write):
    data = read_protected(path)
    current = set(data.get(host, []))
    if ip in current:
        current.remove(ip)
        if current:
            data[host] = sorted(current)
        else:
            data.pop(host, None)
        write(path, data)
    return current


def plan(ips, rows, protected, allow_empty=False):
    expected = set(ips)
    indexed = {r['ip']: r for r in rows}
    if not expected or set(indexed) != expected or len(indexed) != len(rows):
        return [], 'Неполная проверка пула.'
    if not allow_empty and not any(r.get('local_data') is True for r in rows):
        return [], 'Нет ни одного доступного из РФ IP; возможен общий сбой.'
    if any(r.get('local_data') is None or r.get('first_ru_data') is None for r in rows):
        return [], 'Есть неопределённые результаты API; автоудаление отменено.'
    selected = [ip for ip in ips if ip not in protected and
                indexed[ip].get('first_ru_data') is False and
                indexed[ip].get('local_data') is False and
                indexed[ip].get('first_api_status',indexed[ip].get('recheck')) in ('RKN_BLOCK','DATA_CUT','MT_DEAD','DOWN','UNKNOWN') and
                indexed[ip].get('recheck') in ('RKN_BLOCK','DATA_CUT','MT_DEAD','DOWN','UNKNOWN')]
    if selected:
        return selected, ''
    blocked = [ip for ip in ips if ip in protected and
               indexed[ip].get('first_ru_data') is False and
               indexed[ip].get('local_data') is False]
    if blocked:
        return [], 'Дважды недоступные IP защищены как новые VPS: '+', '.join(blocked)+'. Снимите защиту в таблице, когда настройка завершена.'
    return [], 'Нет подтверждённых недоступных IP без защиты.'

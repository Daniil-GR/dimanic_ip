"""Private, report-bound MTProto target storage. Never include secrets in reports."""
import json
import os
import secrets

def save_target(path, report, target):
    host, port, secret = target
    scan_id = report.get('scan_id')
    if not scan_id or (host, port) != (report.get('host'), report.get('port')):
        raise ValueError('Сохранённая ссылка не соответствует отчёту.')
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    tmp = path.with_name(path.name + '.' + secrets.token_hex(8) + '.tmp')
    try:
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, 'w', encoding='utf-8') as f:
            json.dump({'scan_id':scan_id,'host':host,'port':port,'secret':secret}, f)
        os.replace(tmp, path)
    finally:
        if tmp.exists():
            tmp.unlink()

def restore_target(path, report):
    try:
        data = json.loads(path.read_text(encoding='utf-8'))
        if not isinstance(data, dict):
            return None
        scan_id = report.get('scan_id')
        host, port, secret = data.get('host'), data.get('port'), data.get('secret')
        if (not isinstance(scan_id,str) or not scan_id or data.get('scan_id') != scan_id
                or not isinstance(host,str) or not host or type(port) is not int
                or not 1 <= port <= 65535 or not isinstance(secret,str) or not secret
                or (host,port) != (report.get('host'),report.get('port'))):
            return None
        return host,port,secret
    except (OSError,ValueError):
        return None

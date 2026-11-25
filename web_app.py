"""Local browser dashboard. Start with python web_app.py."""
import argparse
import dynadot_dns as dynadot
import dynadot_add as dns_add
import auto_dns
from monitor_cycle import Monitor, INTERVAL
import copy
import csv
import io
import json
import os
from pathlib import Path
import re
import secrets
import threading
import time
import webbrowser
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from check_proxy import API, ApiError, CONFIG, parse_link, resolve_ips, field, safe_result
from target_store import save_target, restore_target

ROOT = Path(__file__).resolve().parent
REPORTS = CONFIG.parent / 'reports'
LAST_PROXY = CONFIG.parent / 'last_proxy.json'
PROTECTED = CONFIG.parent / 'protected_ipv4.json'
TOKEN = secrets.token_urlsafe(32)
LOCK = threading.Lock()
MONITOR = Monitor()
ACTIVE_PHASES = ('dns','checking','saving','key')
STATE = {'phase':'idle','rows':[], 'ips':[], 'host':'', 'port':None, 'source':'',
         'current':'', 'done':0, 'total':0, 'error':'', 'started_at':'', 'finished_at':'', 'scan_id':'', 'auto_result':None}
LAST = None
CLIENT = None
DNS_PREVIEW = None
ADD_PREVIEW = None
FIELDS = ('tcp','handshake','data','ssh','ping_ms','latency_ms','duration_ms')

def now():
    return datetime.now(timezone.utc).isoformat()

def client():
    global CLIENT
    key = CONFIG.read_text(encoding='utf-8').strip() if CONFIG.is_file() else ''
    if not key:
        raise ValueError('Сначала сохраните API-ключ.')
    if CLIENT is None or CLIENT.key != key:
        CLIENT = API(key)
    return CLIENT

def save_key(key):
    global CLIENT
    if not isinstance(key,str) or not re.fullmatch(r'rf_[A-Za-z0-9_-]+',key):
        raise ValueError('Некорректный формат API-ключа.')
    api = API(key)
    api.call('/v1/me')
    CONFIG.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    tmp = CONFIG.with_name('key-' + secrets.token_hex(8))
    try:
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd,'w',encoding='utf-8') as f:
            f.write(key+'\n')
        os.replace(tmp,CONFIG)
    finally:
        if tmp.exists():
            tmp.unlink()
    CLIENT = api

def change(**values):
    with LOCK:
        STATE.update(values)

def row_for(ip, port, first, second):
    last = second if second is not None else first
    ru = field(last,'local','data')
    ext = field(last,'remote','data')
    previous = field(first,'local','data')
    if ru is True:
        status = 'RU_OK' if ext is True else 'RU_OK_EXT_FAIL' if ext is False else 'RU_OK_EXT_UNKNOWN'
        action = 'KEEP'
    elif ru is False:
        status = 'RU_UNAVAILABLE' if ext is True else 'UNAVAILABLE' if ext is False else 'NEEDS_CHECK'
        action = 'REVIEW_DNS' if second is not None and previous is False else 'RECHECK'
    else:
        status,action = 'NEEDS_CHECK','RECHECK'
    row = {'ip':ip,'port':port,'status':status,'api_status':last['status'],
           'first_api_status':first['status'],'first_ru_data':previous,
           'first_ext_data':field(first,'remote','data'),
           'recheck':second['status'] if second else '', 'action':action,
           'checked_at':last.get('checked_at','')}
    for side in ('local','remote'):
        for key in FIELDS:
            row[side+'_'+key] = field(last,side,key)
    return row

def csv_bytes(rows):
    f = io.StringIO(newline='')
    if rows:
        writer = csv.DictWriter(f,fieldnames=list(rows[0]))
        writer.writeheader()
        writer.writerows(rows)
    return f.getvalue().encode('utf-8-sig')

def snapshot():
    with LOCK:
        return copy.deepcopy(STATE)

def save_report():
    report = snapshot()
    report['phase'] = 'done'
    REPORTS.mkdir(parents=True,exist_ok=True,mode=0o700)
    stamp = datetime.now(timezone.utc).strftime('%Y%m%d-%H%M%S-%f')
    for name,data in [('proxy-check-'+stamp+'.json',json.dumps(report,ensure_ascii=False,indent=2).encode()),
                      ('proxy-check-'+stamp+'.csv',csv_bytes(report['rows']))]:
        (REPORTS/name).write_bytes(data)
    tmp = REPORTS/'latest.tmp'
    tmp.write_text(json.dumps(report,ensure_ascii=False,indent=2),encoding='utf-8')
    if LAST is not None:
        save_target(LAST_PROXY,report,LAST)
    os.replace(tmp,REPORTS/'latest.json')

def apply_auto_cleanup(c,sub,zone,host,ips,rows,protected,generation=None,target=None):
    selected,reason=auto_dns.plan(ips,rows,protected)
    result={'status':'skipped','message':reason,'removed':[],'protected':sorted(protected & set(ips))}
    if not selected:
        return result
    try:
        # Recheck account ownership and exact initial DNS snapshot inside remove.
        if dynadot.config()!={k:c[k] for k in ('mode','key','secret','request_id_mode')}:
            raise ValueError('Настройки Dynadot изменились.')
        if dynadot.select_zone(host,dynadot.list_domains(c))!=c['zone']:
            raise ValueError('DNS-зона изменилась.')
        result.update(status='checking',message='Удаление подтверждённых недоступных IPv4…')
        change(auto_result=dict(result))
        if generation is not None:
            with LOCK:
                if not MONITOR.matches(generation,target):
                    return dict(result,status='skipped',message='Мониторинг остановлен до удаления.')
                MONITOR.committing=True
        try:
            deleted=dynadot.remove(c,sub,zone,selected)
        finally:
            if generation is not None:
                with LOCK:
                    MONITOR.committing=False
        result.update(status='removed',message='Удаление подтверждено Dynadot.',
                      removed=deleted['removed'],backup=deleted['backup'],
                      measurements=[r for r in rows if r['ip'] in selected])
        remaining=deleted['remaining']
        change(rows=[r for r in rows if r['ip'] in remaining],ips=remaining,
               done=len(remaining),total=len(remaining),
               source='Dynadot API (после автоудаления; DNS-кэш может отличаться)')
    except Exception as e:
        if generation is not None:
            with LOCK:
                if MONITOR.matches(generation,target):
                    MONITOR.stop('Мониторинг остановлен: результат удаления не подтверждён.')
        result.update(status='error',message='Автоудаление не подтверждено: '+str(e)+
                      ' Обновите DNS-список вручную. Автоматического повтора нет.')
    return result

def run_scan(target, timeout, repeat, chosen=None, auto=False, generation=None):
    host,port,secret = target
    try:
        api = client()
        if auto:
            c=dynadot.config()
            if c['mode']!='production':
                raise ValueError('Автоудаление доступно только для Production.')
            c=dict(c,zone=dynadot.select_zone(host,dynadot.list_domains(c)))
            sub=dynadot.subhost(host,c)
            zone=dynadot.get_zone(c)
            ips=sorted(dynadot.matching(zone,sub))
            if not ips:
                raise ValueError('В Dynadot нет A-записей текущего поддомена.')
            change(ips=ips,source='Dynadot API (текущий пул A-записей)',total=len(ips),phase='checking')
        elif chosen is None:
            ips,source = resolve_ips(host)
            change(ips=ips,source=source,total=len(ips),phase='checking')
        else:
            ips = chosen
            change(total=len(ips),phase='checking')
        for i,ip in enumerate(ips,1):
            if generation is not None:
                with LOCK:
                    if not MONITOR.matches(generation,target):
                        STATE.update(phase='error',error='Мониторинг остановлен. Проверка прервана без автоудаления.',current='',finished_at=now())
                        return
            change(current=ip)
            first = safe_result(api,ip,port,secret,timeout)
            second = None
            if (repeat or auto) and field(first,'local','data') is not True:
                change(current=ip+' · повтор')
                if auto:
                    time.sleep(5)
                second = safe_result(api,ip,port,secret,timeout)
            row = row_for(ip,port,first,second)
            with LOCK:
                STATE['rows'] = [r for r in STATE['rows'] if r['ip'] != ip] + [row]
                order = {v:j for j,v in enumerate(STATE['ips'])}
                STATE['rows'].sort(key=lambda r:order.get(r['ip'],0))
                STATE['done'] = i
        try:
            rows=snapshot()['rows']
            # Only measurements made in this run may release provisioning protection.
            protected=auto_dns.release_healthy(PROTECTED,host,[r for r in rows if r['ip'] in ips],dynadot.private_write)
            if auto:
                change(current='Проверка условий автоудаления')
                change(auto_result=apply_auto_cleanup(c,sub,zone,host,ips,rows,protected,generation,target))
        except (ValueError,OSError) as exc:
            if auto:
                change(auto_result={'status':'skipped','message':str(exc),'removed':[]})
        change(phase='saving',current='',finished_at=now())
        # Persist a finished snapshot while preventing concurrent scans until write completes.
        report = snapshot()
        report['phase'] = 'done'
        REPORTS.mkdir(parents=True,exist_ok=True,mode=0o700)
        stamp = datetime.now(timezone.utc).strftime('%Y%m%d-%H%M%S-%f')
        raw = json.dumps(report,ensure_ascii=False,indent=2).encode()
        (REPORTS/('proxy-check-'+stamp+'.json')).write_bytes(raw)
        (REPORTS/('proxy-check-'+stamp+'.csv')).write_bytes(csv_bytes(report['rows']))
        tmp = REPORTS/'latest.tmp'
        tmp.write_bytes(raw)
        # Write credentials separately, bound to this exact report. If interrupted,
        # mismatching scan IDs prevent accidentally repeating with another secret.
        save_target(LAST_PROXY,report,target)
        os.replace(tmp,REPORTS/'latest.json')
        change(phase='done')
    except (ValueError,ApiError,OSError) as e:
        change(phase='error',error=str(e),current='',finished_at=now())
    except Exception:
        change(phase='error',error='Внутренняя ошибка проверки. Частичные результаты сохранены в памяти.',current='',finished_at=now())

def start_scan(body,generation=None):
    global DNS_PREVIEW, ADD_PREVIEW, LAST
    link = body.get('link','')
    if not isinstance(link,str) or len(link)>8192:
        raise ValueError('Некорректная ссылка.')
    timeout = body.get('timeout',10)
    if type(timeout) is not int or not 1 <= timeout <= 15:
        raise ValueError('Таймаут должен быть от 1 до 15 секунд.')
    repeat = body.get('repeat',True) is True
    mode = body.get('mode','all')
    auto = body.get('auto_cleanup') is True
    if auto and mode!='all':
        raise ValueError('Автоудаление разрешено только при полной проверке.')
    if auto and dynadot.config()['mode']!='production':
        raise ValueError('Автоудаление доступно только для Production.')
    with LOCK:
        if MONITOR.enabled and generation is None:
            raise ValueError('Остановите мониторинг перед ручной проверкой.')
        if generation is not None and not MONITOR.matches(generation,LAST):
            raise ValueError('Мониторинг остановлен или прокси изменился.')
        if STATE['phase'] in ACTIVE_PHASES:
            raise ValueError('Дождитесь завершения текущей операции.')
        if not CONFIG.is_file():
            raise ValueError('Сначала сохраните API-ключ.')
        try:
            target = parse_link(link) if link else LAST
        except ValueError:
            raise ValueError('Некорректная MTProto-ссылка.') from None
        if target is None:
            raise ValueError('Вставьте MTProto-ссылку.')
        if mode == 'all':
            # Migrate new, untested addresses from the previous version before resetting the report.
            if STATE['host']==target[0]:
                pending=[r['ip'] for r in STATE['rows'] if r.get('api_status')=='NOT_TESTED']
                if pending:
                    try:
                        auto_dns.protect(PROTECTED,target[0],pending,dynadot.private_write)
                    except (ValueError,OSError):
                        if auto:
                            raise ValueError('Не удалось сохранить защиту новых IP. Автоудаление запрещено.') from None
            if auto:
                auto_dns.read_protected(PROTECTED)
            chosen = None
            STATE.update(host=target[0],port=target[1],rows=[],ips=[],source='',total=0,phase='dns',scan_id=secrets.token_hex(16))
            LAST = target
        elif mode in ('one','failed'):
            if LAST is None or target != LAST or (target[0],target[1]) != (STATE['host'],STATE['port']):
                raise ValueError('Для повтора используйте последний проверенный прокси.')
            chosen = ([body.get('ip')] if mode == 'one' else
                      [r['ip'] for r in STATE['rows'] if r['local_data'] is not True])
            if not chosen or any(ip not in STATE['ips'] for ip in chosen):
                raise ValueError('Нет подходящих IP для повтора.')
            STATE.update(phase='checking',total=len(chosen))
        else:
            raise ValueError('Неизвестный режим.')
        STATE.update(done=0,current='',error='',started_at=now(),finished_at='',auto_result=None)
        DNS_PREVIEW = None
        ADD_PREVIEW = None
        if generation is not None:
            MONITOR.started(time.monotonic())
    threading.Thread(target=run_scan,args=(target,timeout,repeat,chosen,auto,generation),daemon=True).start()

def monitor_operation(path,body):
    with LOCK:
        if path=='/api/monitor/stop':
            committing=MONITOR.committing
            MONITOR.stop('Мониторинг остановлен. Уже начатая DNS-операция завершится.' if committing else 'Мониторинг остановлен. Новые удаления не запускаются.')
            return MONITOR.public(time.monotonic())
        if STATE['phase'] in ACTIVE_PHASES:
            raise ValueError('Дождитесь завершения текущей операции.')
        if LAST is None or LAST[:2]!=(STATE['host'],STATE['port']):
            raise ValueError('Сначала выполните проверку нужного прокси.')
        if body.get('host')!=LAST[0] or body.get('port')!=LAST[1]:
            raise ValueError('Текущий прокси изменился. Обновите страницу.')
        if not CONFIG.is_file() or dynadot.config()['mode']!='production':
            raise ValueError('Нужны действующие API-ключи проверки и Production Dynadot.')
        timeout=body.get('timeout',10)
        if type(timeout) is not int or not 1<=timeout<=15:
            raise ValueError('Некорректный таймаут.')
        auto_dns.read_protected(PROTECTED)
        MONITOR.start(LAST,timeout,time.monotonic())
        return MONITOR.public(time.monotonic())

def monitor_loop():
    while True:
        time.sleep(0.5)
        with LOCK:
            if not MONITOR.due(time.monotonic(),STATE['phase'] in ACTIVE_PHASES):
                continue
            generation=MONITOR.generation
            timeout=MONITOR.timeout
        try:
            start_scan({'mode':'all','link':'','timeout':timeout,'repeat':True,'auto_cleanup':True},generation)
        except (ValueError,OSError) as exc:
            with LOCK:
                if MONITOR.enabled and MONITOR.generation==generation and STATE['phase'] not in ACTIVE_PHASES:
                    MONITOR.next_due=time.monotonic()+INTERVAL
                    MONITOR.message=str(exc)

def dns_operation(path,body):
    global DNS_PREVIEW, ADD_PREVIEW
    with LOCK:
        if STATE['phase'] in ('dns','checking','saving','key'):
            raise ValueError('Дождитесь завершения текущей операции.')
        old=STATE['phase']
        state=copy.deepcopy(STATE)
        STATE['phase']='key'
    try:
        if path=='/api/dynadot/config':
            with LOCK:
                if MONITOR.enabled:
                    raise ValueError('Остановите мониторинг перед сменой ключей Dynadot.')
            DNS_PREVIEW=None
            ADD_PREVIEW=None
            return dynadot.save_config(body)
        if old!='done' or not state['host'] or not state['rows']:
            raise ValueError('Сначала завершите проверку прокси.')
        if path=='/api/dynadot/preview':
            c,sub,g,records=dynadot.preview(state)
            token=secrets.token_urlsafe(24)
            DNS_PREVIEW=(token,time.monotonic(),state['host'],c,sub,g,records)
            return {'token':token,'host':state['host'],'zone':c['zone'],'mode':c['mode'],
                    'records':records}
        if path=='/api/dynadot/delete':
            ADD_PREVIEW=None
            p=DNS_PREVIEW
            DNS_PREVIEW=None
            if not p or body.get('token')!=p[0] or time.monotonic()-p[1]>300 or p[2]!=state['host']:
                raise ValueError('Предпросмотр устарел. Обновите список Dynadot.')
            if body.get('confirm')!=state['host']:
                raise ValueError('Подтвердите точное имя поддомена.')
            selected=body.get('ips')
            allowed={r['ip'] for r in p[6] if r['eligible']}
            if not isinstance(selected,list) or not selected or any(not isinstance(x,str) or x not in allowed for x in selected):
                raise ValueError('Можно удалить только выбранные проверенные IP с RU data=false.')
            if dynadot.config()!={k:p[3][k] for k in ('mode','key','secret','request_id_mode')}:
                raise ValueError('Настройки Dynadot изменились.')
            if dynadot.select_zone(state['host'],dynadot.list_domains(p[3]))!=p[3]['zone']:
                raise ValueError('Домен в Dynadot изменился. Обновите список.')
            result=dynadot.remove(p[3],p[4],p[5],selected)
            # Keep the original measurements, but invalidate the current preview.
            return result
        if path=='/api/dynadot/add-preview':
            ADD_PREVIEW=None
            ips=dns_add.parse_ips(body.get('ips'))
            c,sub,g,_=dynadot.preview(state)
            new,duplicates=dns_add.prepare(g,sub,ips)
            # DNS provisioning precedes proxy installation. No MTProto API call.
            token=secrets.token_urlsafe(24)
            ADD_PREVIEW=(token,time.monotonic(),state['scan_id'],(state['host'],state['port']),c,sub,g,new)
            return {'token':token,'host':state['host'],'zone':c['zone'],'mode':c['mode'],
                    'ttl':dns_add.current_ttl(g),'duplicates':duplicates,'ips':new}
        if path=='/api/dynadot/add':
            p=ADD_PREVIEW
            ADD_PREVIEW=None
            DNS_PREVIEW=None
            if not p or body.get('token')!=p[0] or time.monotonic()-p[1]>300 or p[2]!=state['scan_id'] or p[3]!=(state['host'],state['port']):
                raise ValueError('Предпросмотр устарел. Подготовьте добавление заново.')
            if body.get('confirm')!=state['host']:
                raise ValueError('Подтвердите точное имя поддомена.')
            selected=body.get('ips')
            allowed=set(p[7])
            if (not isinstance(selected,list) or not selected or any(not isinstance(x,str) or x not in allowed for x in selected)
                    or len(set(selected))!=len(selected)):
                raise ValueError('Можно добавлять только выбранные уникальные IPv4 из предпросмотра.')
            if dynadot.config()!={k:p[4][k] for k in ('mode','key','secret','request_id_mode')}:
                raise ValueError('Настройки Dynadot изменились.')
            if dynadot.select_zone(state['host'],dynadot.list_domains(p[4]))!=p[4]['zone']:
                raise ValueError('Домен в Dynadot изменился. Повторите проверку.')
            if p[4]['mode']=='production':
                # Persist protection BEFORE POST, including ambiguous network failures.
                auto_dns.protect(PROTECTED,state['host'],selected,dynadot.private_write)
            result=dns_add.append_records(p[4],p[5],p[6],selected)
            # Sandbox records must never be represented as live public DNS.
            if result['mode']=='production':
                rows={r['ip']:r for r in state['rows']}
                rows.update({ip:row_for(ip,state['port'],{'status':'NOT_TESTED'},None) for ip in selected})
                remaining=result['remaining']
                rows=[rows[ip] for ip in remaining if ip in rows]
                change(rows=rows,ips=remaining,done=sum(r['api_status']!='NOT_TESTED' for r in rows),total=len(remaining),
                       source='Dynadot API (настроенные A-записи; DNS-кэш может отличаться)',finished_at=now())
                try:
                    save_report()
                except (OSError,ValueError):
                    result['warning']='DNS добавлен и подтверждён, но локальный отчёт не удалось сохранить.'
            return result
        raise ValueError('Неизвестная операция.')
    finally:
        change(phase=old,current='')

class Handler(BaseHTTPRequestHandler):
    def log_message(self,*args):
        pass

    def allowed(self):
        return self.headers.get('Host') == '127.0.0.1:'+str(self.server.server_port)

    def send(self, code, data, kind='application/json; charset=utf-8', filename=None):
        self.send_response(code)
        self.send_header('Content-Type',kind)
        self.send_header('Content-Length',str(len(data)))
        self.send_header('Cache-Control','no-store')
        self.send_header('X-Content-Type-Options','nosniff')
        self.send_header('X-Frame-Options','DENY')
        self.send_header('Referrer-Policy','no-referrer')
        self.send_header('Content-Security-Policy',"default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; base-uri 'none'; frame-ancestors 'none'; form-action 'none'")
        if filename:
            self.send_header('Content-Disposition','attachment; filename="'+filename+'"')
        self.end_headers()
        self.wfile.write(data)

    def out(self, obj, code=200):
        self.send(code,json.dumps(obj,ensure_ascii=False).encode())

    def do_GET(self):
        if not self.allowed():
            return self.out({'error':'Invalid host'},403)
        if self.path == '/':
            self.send(200,(ROOT/'web'/'index.html').read_text(encoding='utf-8').replace('__TOKEN__',TOKEN).encode(),'text/html; charset=utf-8')
        elif self.path in ('/style.css','/app.js'):
            self.send(200,(ROOT/'web'/self.path[1:]).read_bytes(),'text/css; charset=utf-8' if self.path.endswith('.css') else 'text/javascript; charset=utf-8')
        elif self.path == '/api/state':
            data = snapshot()
            data['has_key'] = CONFIG.is_file()
            data['dynadot'] = dynadot.public_config()
            with LOCK:
                data['monitor'] = MONITOR.public(time.monotonic())
                data['can_repeat'] = LAST is not None and (LAST[0],LAST[1]) == (STATE['host'],STATE['port'])
            self.out(data)
        elif self.path == '/export.json':
            self.send(200,json.dumps(snapshot(),ensure_ascii=False,indent=2).encode(),'application/json; charset=utf-8','proxy-check.json')
        elif self.path == '/export.csv':
            self.send(200,csv_bytes(snapshot()['rows']),'text/csv; charset=utf-8','proxy-check.csv')
        else:
            self.out({'error':'Not found'},404)

    def do_POST(self):
        origin = 'http://127.0.0.1:'+str(self.server.server_port)
        if not self.allowed() or self.headers.get('Origin') != origin or self.headers.get('X-Local-Token') != TOKEN:
            return self.out({'error':'Forbidden'},403)
        try:
            n = int(self.headers.get('Content-Length','0'))
            if not 0 < n <= 16384 or self.headers.get_content_type() != 'application/json':
                raise ValueError('Некорректный запрос.')
            body = json.loads(self.rfile.read(n))
            if not isinstance(body,dict):
                raise ValueError('Некорректный запрос.')
            if self.path in ('/api/dynadot/config','/api/dynadot/preview','/api/dynadot/delete','/api/dynadot/add-preview','/api/dynadot/add'):
                self.out(dns_operation(self.path,body))
            elif self.path in ('/api/monitor/start','/api/monitor/stop'):
                self.out(monitor_operation(self.path,body))
            elif self.path == '/api/check':
                start_scan(body)
                self.out({'ok':True},202)
            elif self.path == '/api/key':
                with LOCK:
                    if MONITOR.enabled:
                        raise ValueError('Остановите мониторинг перед сменой API-ключа.')
                    if STATE['phase'] in ACTIVE_PHASES:
                        raise ValueError('Дождитесь завершения текущей операции.')
                    old = STATE['phase']
                    STATE['phase'] = 'key'
                try:
                    save_key(body.get('key'))
                finally:
                    change(phase=old)
                self.out({'ok':True})
            else:
                self.out({'error':'Not found'},404)
        except (ValueError,ApiError,OSError) as e:
            self.out({'error':str(e)},400)

def main():
    global LAST
    p = argparse.ArgumentParser(description='Локальный MTProto dashboard')
    p.add_argument('--port',type=int,default=8765)
    p.add_argument('--no-browser',action='store_true')
    args = p.parse_args()
    if not 1 <= args.port <= 65535:
        p.error('Некорректный порт')
    latest = REPORTS/'latest.json'
    if latest.is_file():
        try:
            old = json.loads(latest.read_text(encoding='utf-8'))
            if isinstance(old,dict) and isinstance(old.get('rows'),list):
                STATE.update({k:old[k] for k in STATE if k in old})
                STATE.update(phase='done',current='',error='')
                LAST = restore_target(LAST_PROXY,STATE)
        except (OSError,ValueError):
            pass
    try:
        server = ThreadingHTTPServer(('127.0.0.1',args.port),Handler)
    except OSError:
        print('Порт занят. Закройте предыдущий запуск или укажите --port 8766.')
        return 1
    url = 'http://127.0.0.1:'+str(server.server_port)
    print('Локальный dashboard: '+url+'\nДля остановки нажмите Ctrl+C.')
    threading.Thread(target=monitor_loop,daemon=True).start()
    if not args.no_browser:
        threading.Thread(target=webbrowser.open,args=(url,),daemon=True).start()
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        with LOCK:
            MONITOR.stop()
        server.server_close()
    return 0

if __name__ == '__main__':
    from workspace_server import main as workspace_main
    raise SystemExit(workspace_main())

"""Independent dashboard workspaces with shared API and DNS coordination."""
import argparse
import functools
import importlib.util
import json
import re
import secrets
import threading
import time
import webbrowser
from http.server import ThreadingHTTPServer

import web_app as base

ROOT = base.ROOT
WORKSPACES = base.CONFIG.parent / 'workspaces'
LIMIT = 12
CONTROL = threading.RLock()
DNS_LOCK = threading.RLock()
PROTECTION_LOCK = threading.RLock()
API_LOCK = threading.Lock()
API_LAST = 0.0
PAGES = {}
ID_PATTERN = re.compile(r'[a-f0-9]{12}')


class SharedAPI(base.API):
    """One request at a time across all pages, including API-key validation."""
    def call(self, path, payload=None):
        global API_LAST
        with API_LOCK:
            self.last = max(self.last, API_LAST)
            try:
                return super().call(path, payload)
            finally:
                API_LAST = max(API_LAST, self.last)


def serialized(fn, lock):
    @functools.wraps(fn)
    def wrapped(*args, **kwargs):
        with lock:
            return fn(*args, **kwargs)
    return wrapped


def install_shared_locks():
    # The original functions are shared by each imported workspace module.
    base.dynadot.request = serialized(base.dynadot.request, DNS_LOCK)
    base.dynadot.remove = serialized(base.dynadot.remove, DNS_LOCK)
    base.dns_add.append_records = serialized(base.dns_add.append_records, DNS_LOCK)
    base.auto_dns.protect = serialized(base.auto_dns.protect, PROTECTION_LOCK)
    base.auto_dns.release_healthy = serialized(base.auto_dns.release_healthy, PROTECTION_LOCK)
    base.auto_dns.release_protection = serialized(base.auto_dns.release_protection, PROTECTION_LOCK)


def restore(module):
    module.load_monitor_settings()
    latest = module.REPORTS / 'latest.json'
    try:
        data = json.loads(latest.read_text(encoding='utf-8'))
        if isinstance(data, dict) and isinstance(data.get('rows'), list):
            module.STATE.update({k:data[k] for k in module.STATE if k in data})
            module.STATE.update(phase='done', current='', error='')
            module.LAST = module.restore_target(module.LAST_PROXY, module.STATE)
    except (OSError, ValueError):
        pass


def owner_of(host, except_id):
    """Caller holds CONTROL. Match exact DNS name, independent of port."""
    normalized = host.lower().rstrip('.')
    for page_id, module in PAGES.items():
        if page_id == except_id:
            continue
        with module.LOCK:
            current = module.STATE.get('host') or ''
        if current.lower().rstrip('.') == normalized:
            return page_id
    return None


def require_unique(host, page_id):
    if host and owner_of(host, page_id):
        raise ValueError('Этот домен уже открыт на другой странице. Используйте её, чтобы избежать конфликтов DNS.')


def shared_settings_busy():
    for module in PAGES.values():
        with module.LOCK:
            if module.MONITOR.enabled or module.STATE['phase'] in module.ACTIVE_PHASES:
                return True
    return False


def wire(module, page_id):
    module.API = SharedAPI
    module.TOKEN = base.TOKEN
    original_scan = module.start_scan
    original_monitor = module.monitor_operation
    original_cleanup = module.apply_auto_cleanup

    def start_scan(body, generation=None):
        with CONTROL:
            link = body.get('link','')
            try:
                target = module.parse_link(link) if isinstance(link,str) and link else module.LAST
            except ValueError:
                raise ValueError('Некорректная MTProto-ссылка.') from None
            if target:
                require_unique(target[0], page_id)
            return original_scan(body, generation)

    def monitor_operation(path, body):
        with CONTROL:
            if path.endswith('/start') and module.LAST:
                require_unique(module.LAST[0], page_id)
            return original_monitor(path, body)

    def cleanup(c, sub, zone, host, ips, rows, protected, generation=None, target=None, pause_rev=None):
        # Serialize DNS mutations, including the initial fresh-read and verification.
        # Another page may have changed a different subdomain in this same zone.
        # A changed zone is a skipped cycle, not a reason to stop monitoring.
        with DNS_LOCK:
            selected, reason = module.auto_dns.plan(ips, rows, protected)
            if selected:
                try:
                    fresh = module.dynadot.get_zone(c)
                    if module.dynadot.canonical(fresh) != module.dynadot.canonical(zone):
                        return {'status':'skipped','message':'DNS-зона изменилась во время проверки. Повтор в следующем цикле.',
                                'removed':[],'protected':sorted(protected & set(ips))}
                except (ValueError, OSError) as exc:
                    return {'status':'skipped','message':'Не удалось перепроверить DNS: '+str(exc),'removed':[]}
            return original_cleanup(c,sub,zone,host,ips,rows,protected,generation,target,pause_rev)

    module.start_scan = start_scan
    module.monitor_operation = monitor_operation
    module.apply_auto_cleanup = cleanup


def load_page(page_id):
    """Caller holds CONTROL. Each page owns an independent module namespace."""
    if page_id == 'main':
        module = base
    else:
        if not ID_PATTERN.fullmatch(page_id):
            raise ValueError('Некорректный идентификатор страницы.')
        spec = importlib.util.spec_from_file_location('workspace_'+page_id, ROOT/'web_app.py')
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        directory = WORKSPACES/page_id
        module.REPORTS = directory/'reports'
        module.LAST_PROXY = directory/'last_proxy.json'
    wire(module,page_id)
    restore(module)
    PAGES[page_id] = module
    return module


def start_worker(module):
    threading.Thread(target=module.monitor_loop, daemon=True).start()


def create_page():
    with CONTROL:
        if len(PAGES)>=LIMIT:
            raise ValueError('Достигнут лимит 12 рабочих страниц.')
        WORKSPACES.mkdir(parents=True,exist_ok=True,mode=0o700)
        while True:
            page_id=secrets.token_hex(6)
            try:
                (WORKSPACES/page_id).mkdir(mode=0o700)
                break
            except FileExistsError:
                continue
        module=load_page(page_id)
        start_worker(module)
        return page_id


def page_list(current):
    with CONTROL:
        pages=[]
        for page_id,module in PAGES.items():
            with module.LOCK:
                pages.append({'id':page_id,'host':module.STATE.get('host',''),
                              'port':module.STATE.get('port'),'phase':module.STATE['phase'],
                              'monitoring':module.MONITOR.enabled})
        return {'current':current,'pages':pages,'limit':LIMIT}


class Router(base.Handler):
    def route(self):
        if not self.allowed():
            self.out({'error':'Invalid host'},403)
            return None
        if self.path=='/':
            self.send_response(302)
            self.send_header('Location','/w/main/')
            self.send_header('Content-Length','0')
            self.end_headers()
            return None
        match=re.fullmatch(r'/w/(main|[a-f0-9]{12})(/[^?]*)',self.path)
        if match is None:
            self.out({'error':'Not found'},404)
            return None
        page_id,path=match.groups()
        with CONTROL:
            module=PAGES.get(page_id)
        if module is None:
            self.out({'error':'Страница не найдена.'},404)
            return None
        self.path=path
        return page_id,module

    def do_GET(self):
        result=self.route()
        if result is None:
            return
        page_id,module=result
        if self.path=='/api/workspaces':
            self.out(page_list(page_id))
        else:
            module.Handler.do_GET(self)

    def do_POST(self):
        result=self.route()
        if result is None:
            return
        page_id,module=result
        origin='http://127.0.0.1:'+str(self.server.server_port)
        if self.headers.get('Origin')!=origin or self.headers.get('X-Local-Token')!=base.TOKEN:
            return self.out({'error':'Forbidden'},403)
        try:
            if self.path=='/api/workspaces':
                n=int(self.headers.get('Content-Length','0'))
                if not 0<n<=1024 or self.headers.get_content_type()!='application/json':
                    raise ValueError('Некорректный запрос.')
                body=json.loads(self.rfile.read(n))
                if body!={}:
                    raise ValueError('Некорректный запрос.')
                return self.out({'id':create_page()},201)
            if self.path in ('/api/key','/api/dynadot/config'):
                with CONTROL:
                    if shared_settings_busy():
                        raise ValueError('API-ключи общие. Перед заменой остановите мониторинги и проверки на всех страницах.')
                    return module.Handler.do_POST(self)
            if self.path.startswith('/api/dynadot/'):
                with CONTROL:
                    with module.LOCK:
                        host=module.STATE.get('host','')
                    require_unique(host,page_id)
                # A different workspace may run its MTProto check concurrently.
                # DNS transactions are shared and serialized; the existing
                # snapshot validation also rejects stale manual previews.
                with DNS_LOCK:
                    return module.Handler.do_POST(self)
            return module.Handler.do_POST(self)
        except (ValueError,OSError) as exc:
            self.out({'error':str(exc)},400)


def main():
    p=argparse.ArgumentParser(description='Локальный MTProto dashboard: рабочие страницы')
    p.add_argument('--port',type=int,default=8765)
    p.add_argument('--no-browser',action='store_true')
    args=p.parse_args()
    if not 1<=args.port<=65535:
        p.error('Некорректный порт')
    try:
        server=ThreadingHTTPServer(('127.0.0.1',args.port),Router)
    except OSError:
        print('Порт занят. Закройте предыдущий запуск или укажите --port 8766.')
        return 1
    try:
        install_shared_locks()
        with CONTROL:
            load_page('main')
            if WORKSPACES.is_dir():
                for directory in sorted(WORKSPACES.iterdir()):
                    if directory.is_dir() and ID_PATTERN.fullmatch(directory.name):
                        if len(PAGES)>=LIMIT:
                            break
                        load_page(directory.name)
            for module in PAGES.values():
                start_worker(module)
        url='http://127.0.0.1:'+str(server.server_port)+'/w/main/'
        print('Локальный dashboard: '+url+'\nДля остановки нажмите Ctrl+C.')
        if not args.no_browser:
            threading.Thread(target=webbrowser.open,args=(url,),daemon=True).start()
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        with CONTROL:
            for module in PAGES.values():
                with module.LOCK:
                    module.MONITOR.stop()
        server.server_close()
    return 0

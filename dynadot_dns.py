"""Dynadot REST v2: exact A-record selection and explicit deletion."""
import base64
import hashlib
import hmac
import ipaddress
import json
import os
from pathlib import Path
import re
import secrets
import time
import uuid
from datetime import datetime, timezone
from urllib.request import Request, build_opener
from urllib.error import HTTPError, URLError
from urllib.parse import urlencode
from check_proxy import CONFIG, NoRedirect

FILE = CONFIG.parent / 'dynadot.json'
BACKUPS = CONFIG.parent / 'dns-backups'
BASE = {'production':'https://api.dynadot.com','sandbox':'https://api-sandbox.dynadot.com'}

def domain(value):
    if not isinstance(value,str):
        raise ValueError('Некорректный домен.')
    value=value.strip().lower().rstrip('.')
    if len(value)>253 or not re.fullmatch(r'[a-z0-9-]+(?:\.[a-z0-9-]+)+',value):
        raise ValueError('Введите домен в ASCII (например vetka.rest).')
    if any(len(x)>63 or x.startswith('-') or x.endswith('-') for x in value.split('.')):
        raise ValueError('Некорректный домен.')
    try:
        ipaddress.ip_address(value)
    except ValueError:
        return value
    raise ValueError('Для Dynadot требуется доменное имя.')

def config():
    if not FILE.is_file():
        raise ValueError('Сначала настройте Dynadot.')
    try:
        cfg=json.loads(FILE.read_text(encoding='utf-8'))
        if cfg['mode'] not in BASE or not cfg['key'] or not cfg['secret']:
            raise ValueError
        result={k:cfg[k] for k in ('mode','key','secret')}
        result['request_id_mode']=cfg.get('request_id_mode','uuid')
        if result['request_id_mode'] not in ('none','uuid'):
            raise ValueError
        return result
    except (OSError,ValueError,KeyError,TypeError):
        raise ValueError('Некорректные локальные настройки Dynadot.') from None

def public_config():
    try:
        c=config()
        return {'configured':True,'mode':c['mode'],'request_id_mode':c['request_id_mode']}
    except ValueError:
        return {'configured':False,'mode':'production'}

def private_write(path, obj):
    path.parent.mkdir(parents=True,exist_ok=True,mode=0o700)
    temp=path.with_name(path.name+'.'+secrets.token_hex(8)+'.tmp')
    try:
        fd=os.open(temp,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600)
        with os.fdopen(fd,'w',encoding='utf-8') as f:
            json.dump(obj,f,ensure_ascii=False,indent=2)
        os.replace(temp,path)
    finally:
        if temp.exists():
            temp.unlink()

def save_config(body):
    c={'mode':body.get('mode','production')}
    if c['mode'] not in BASE:
        raise ValueError('Некорректный режим API.')
    for k in ('key','secret'):
        v=body.get(k)
        if not isinstance(v,str) or not v.strip() or len(v)>2048 or any(ord(x)<33 or ord(x)>126 for x in v.strip()):
            raise ValueError('Введите API Key и Secret Key.')
        c[k]=v.strip()
    # The documented X-Request-ID header is optional. Negotiate only via
    # read-only requests; never retry a DNS mutation with another signature.
    c['request_id_mode']='none'
    try:
        domains=list_domains(c)
    except DynadotError as first:
        if not signature_rejected(first):
            raise
        c['request_id_mode']='uuid'
        try:
            domains=list_domains(c)
        except DynadotError as second:
            raise ValueError(
                f'Без X-Request-ID: {first}. С X-Request-ID: {second}. '
                'Оба документированных варианта отклонены. Проверьте соответствие Production API Key и Secret Key; '
                'если ключи верны, передайте Dynadot идентификаторы запросов, но не сами ключи.'
            ) from None
    private_write(FILE,c)
    return dict(public_config(),domain_count=len(domains))

def signature_rejected(error):
    return str(error.code) in ('400','401','403') and 'signature' in error.detail.lower()

def signed_headers(c,path,body,request_id):
    message='\n'.join((c['key'],path,request_id,body)).encode('utf-8')
    signature=base64.b64encode(hmac.new(c['secret'].encode('utf-8'),message,hashlib.sha256).digest()).decode('ascii')
    headers={'Authorization':'Bearer '+c['key'],'X-Signature':signature,'Accept':'application/json'}
    if request_id:
        headers['X-Request-ID']=request_id
    return headers,signature

_last=0.0
def request(c,method,payload=None,path=None):
    global _last
    if path is None:
        path='/restful/v2/domains/'+domain(c['zone'])+'/records'
    body='' if payload is None else json.dumps(payload,ensure_ascii=True,separators=(',',':'))
    request_id=str(uuid.uuid4()) if c.get('request_id_mode','uuid')=='uuid' else ''
    headers,signature=signed_headers(c,path,body,request_id)
    if payload is not None:
        headers['Content-Type']='application/json'
    req=Request(BASE[c['mode']]+path,data=body.encode() if payload is not None else None,method=method,headers=headers)
    time.sleep(max(0,1.1-(time.monotonic()-_last)))
    _last=time.monotonic()
    try:
        with build_opener(NoRedirect()).open(req,timeout=30) as r:
            raw=json.loads(r.read(4*1024*1024))
    except HTTPError as e:
        code=e.code
        try:
            error=json.loads(e.read(65536))
        except (ValueError,OSError):
            error={}
        finally:
            e.close()
        detail=error_message(error,c,signature)
        raise DynadotError(code,detail,method,path,request_id) from None
    except (URLError,OSError,ValueError):
        raise ValueError('Dynadot: ошибка сети или ответа. Не повторяйте изменение вслепую; обновите DNS-список.') from None
    if not isinstance(raw,dict) or str(raw.get('code')) not in ('0','200'):
        raise DynadotError(raw.get('code','?') if isinstance(raw,dict) else '?',error_message(raw,c,signature),method,path,request_id)
    data=raw.get('data')
    if method=='POST' and payload is not None and path.endswith('/records') and data is None:
        return {}
    if not isinstance(data,dict):
        raise ValueError('Dynadot: неизвестная структура ответа.')
    return data

class DynadotError(ValueError):
    def __init__(self,code,detail,method='',path='',request_id=''):
        self.code=code
        self.detail=detail
        context=f' [{method} {path}; request ID {request_id or "не отправлен"}]' if path else ''
        super().__init__(f'Dynadot HTTP/API {code}: {detail}{context}')

def error_message(raw,c,signature):
    if not isinstance(raw,dict):
        return 'Неизвестный формат ошибки API.'
    messages=[]
    def collect(obj,depth=0):
        if depth>3:
            return
        if isinstance(obj,dict):
            for k,v in obj.items():
                if k.lower() in ('message','error','error_message','detail','description','reason','errors','data'):
                    if isinstance(v,str) and k.lower()!='data':
                        messages.append(v)
                    elif isinstance(v,(dict,list)):
                        collect(v,depth+1)
        elif isinstance(obj,list):
            for item in obj[:10]:
                collect(item,depth+1)
    collect(raw)
    v='; '.join(dict.fromkeys(messages))
    if not v:
        return 'Dynadot не предоставил подробности ошибки.'
    for secret in (c['key'],c['secret'],signature):
        if secret:
            v=v.replace(secret,'[скрыто]')
    return ' '.join(v.split())[:500]

def pagination_int(value):
    if type(value) is int and value>=0:
        return value
    if isinstance(value,str) and re.fullmatch(r'[0-9]{1,12}',value):
        return int(value)
    return None

def pagination_bool(value):
    if type(value) is bool:
        return value
    if type(value) is int and value in (0,1):
        return bool(value)
    if isinstance(value,str):
        v=value.strip().lower()
        if v in ('true','1','yes'):
            return True
        if v in ('false','0','no'):
            return False
    return None

def domain_page(data):
    rows=data.get('domain_info_list')
    if not isinstance(rows,list):
        raise ValueError('Dynadot: неизвестная структура списка доменов.')
    names={domain(r['domain_name']) for r in rows if isinstance(r,dict) and isinstance(r.get('domain_name'),str)}
    if len(names)!=len(rows):
        raise ValueError('Dynadot: неполный или повторяющийся список доменов.')
    return names

def pagination_shape(data):
    # Only names of known schema fields and their types, never actual domain or account data.
    p=data.get('pagination_result')
    if isinstance(p,dict):
        return ', '.join(k+':'+type(p[k]).__name__ for k in ('page','page_size','total','has_next_page') if k in p) or 'пустой объект'
    return type(p).__name__

def list_domains(c):
    endpoint='/restful/v2/domains'
    first=request(c,'GET',path=endpoint)
    first_names=domain_page(first)
    pagination=first.get('pagination_result')
    # A default request may omit metadata or return string values. If the
    # response does not establish the last page, restart with explicit paging.
    explicit=not isinstance(pagination,dict) or (
        pagination_bool(pagination.get('has_next_page')) is None
        and pagination_int(pagination.get('total')) is None)
    found=set()
    size=100
    for page in range(1,501):
        if explicit:
            path=endpoint+'?'+urlencode({'page':page,'page_size':size})
            data=request(c,'GET',path=path)
        elif page==1:
            data=first
        else:
            path=endpoint+'?'+urlencode({'page':page})
            data=request(c,'GET',path=path)
        names=domain_page(data)
        if names & found:
            raise ValueError('Dynadot: повтор страниц списка доменов. Изменение DNS запрещено.')
        found.update(names)
        p=data.get('pagination_result')
        p=p if isinstance(p,dict) else {}
        number=pagination_int(p.get('page'))
        total=pagination_int(p.get('total'))
        more=pagination_bool(p.get('has_next_page'))
        page_size=pagination_int(p.get('page_size'))
        if number is not None and number!=page:
            raise ValueError('Dynadot: неожиданный номер страницы.')
        if total is not None:
            if len(found)>total or (more is False and len(found)!=total) or (more is True and len(found)>=total):
                raise ValueError('Dynadot: противоречивые сведения о пагинации.')
            if more is None:
                more=len(found)<total
        if more is None and explicit:
            effective=page_size or size
            if not 1<=effective<=size or len(names)>effective:
                raise ValueError('Dynadot: неожиданный размер страницы.')
            # Without metadata, do not assume a short page is final: request
            # another page and require an empty response or explicit end.
            if not names:
                more=False
            else:
                more=True
        if more is False:
            if not first_names<=found:
                raise ValueError('Dynadot: список доменов изменился между запросами. Повторите подключение.')
            return sorted(found)
        if more is None or not names:
            raise ValueError('Dynadot: неизвестная пагинация ('+pagination_shape(data)+'). Изменение DNS запрещено.')
    raise ValueError('Слишком много страниц Dynadot. Изменение DNS запрещено.')

def select_zone(host,domains):
    h=domain(host)
    matches=[z for z in domains if h==z or h.endswith('.'+z)]
    if not matches:
        raise ValueError('Домен прокси не найден среди активных доменов аккаунта Dynadot.')
    z=max(matches,key=len)
    if h==z:
        raise ValueError('Прокси использует корневой домен. Разрешено удалять только A-записи поддоменов.')
    return z

def dns_shape(obj):
    # Only recognised schema field names and their types; never print records,
    # values, account information or authentication headers.
    if not isinstance(obj,dict):
        return type(obj).__name__
    keys=('glue_info','glue_type','domain_info','dns_main_list','dns_sub_list',
          'main_list','sub_list','ttl','nameserver_list')
    return ', '.join(k+':'+type(obj[k]).__name__ for k in keys if k in obj) or 'нет ожидаемых полей'

def parse_zone(data,zone):
    prefix=f'Dynadot GET_DNS ({zone}): '
    g=data.get('glue_info')
    if not isinstance(g,dict):
        if 'glue_type' in data and ('dns_main_list' in data or 'dns_sub_list' in data):
            g=data
        else:
            raise ValueError(prefix+'неизвестная структура ответа. data: '+dns_shape(data)+
                             '; glue_info: '+dns_shape(g)+'. Изменение DNS запрещено.')
    mode=g.get('glue_type')
    if not isinstance(mode,str) or mode.strip().lower()!='dns':
        known={'none','registrar_parking','name_servers','registrar_forwarding',
               'registrar_stealth_forwarding','registrar_email_hosting',
               'registrar_dynamic_website','registrar_advanced_hosting','registrar_free_hosting',
               'registrar_site_builder','for_sale_landing_page','storefront','parkbot','geo_forward'}
        value=mode.strip().lower() if isinstance(mode,str) else ''
        if value in known:
            raise ValueError(prefix+'тип DNS: '+value+'. Зона не использует Dynadot DNS. Изменение запрещено.')
        raise ValueError(prefix+'неизвестное поле glue_type ('+type(mode).__name__+
                         '); data: '+dns_shape(data)+'; glue_info: '+dns_shape(g)+
                         '. Изменение DNS запрещено.')
    for key in ('dns_main_list','dns_sub_list'):
        rows=g.get(key)
        # Dynadot can omit the apex list. It is not the target of REMOVE_DNS.
        # Preserve absence/null as unknown rather than inventing an empty list.
        if key=='dns_main_list' and rows is None:
            continue
        if not isinstance(rows,list) or any(not isinstance(r,dict) for r in rows):
            raise ValueError(prefix+'неполный список DNS-записей: '+key+' ('+
                             type(rows).__name__+'). '+dns_shape(g)+'. Изменение запрещено.')
        for r in rows:
            if not isinstance(r.get('record_type'),str) or not isinstance(r.get('record_value1'),str):
                raise ValueError(prefix+'неизвестный формат DNS-записи. Изменение запрещено.')
            if key=='dns_sub_list' and not isinstance(r.get('sub_host'),str):
                raise ValueError(prefix+'неизвестный формат поддомена. Изменение запрещено.')
    return g

def get_zone(c):
    zone=domain(c['zone'])
    return parse_zone(request(c,'GET'),zone)

def subhost(host,c):
    h=domain(host)
    zone=domain(c['zone'])
    suffix='.'+zone
    if not h.endswith(suffix):
        raise ValueError('Текущий отчёт не относится к поддомену настроенного домена.')
    return h[:-len(suffix)]

def matching(g,sub):
    found={}
    for r in g['dns_sub_list']:
        if r['sub_host'].lower().rstrip('.')==sub and r['record_type'].lower()=='a':
            try:
                ip=str(ipaddress.IPv4Address(r['record_value1']))
            except ValueError:
                raise ValueError('Некорректная A-запись в Dynadot.') from None
            if ip in found:
                raise ValueError('Обнаружены дубликаты A-записей; изменение запрещено.')
            found[ip]=r
    return found

def canonical(g):
    def records(key):
        rows=g.get(key)
        if key=='dns_main_list' and rows is None:
            return None
        return sorted(json.dumps(r,sort_keys=True,ensure_ascii=True) for r in rows)
    return (records('dns_main_list'),records('dns_sub_list'),g.get('ttl'))

def preview(state):
    c=config()
    c=dict(c,zone=select_zone(state['host'],list_domains(c)))
    sub=subhost(state['host'],c)
    g=get_zone(c)
    found=matching(g,sub)
    checked={r['ip']:r for r in state['rows']}
    records=[]
    for ip in sorted(found,key=ipaddress.IPv4Address):
        row=checked.get(ip,{})
        records.append({'ip':ip,'ru':row.get('local_data'),'ext':row.get('remote_data'),
                        'status':row.get('api_status','NOT_TESTED'),
                        'eligible':row.get('local_data') is False})
    return c,sub,g,records

def remove(c,sub,g,selected):
    if not selected or len(set(selected))!=len(selected):
        raise ValueError('Выберите уникальные IPv4.')
    found=matching(g,sub)
    if not set(selected)<=set(found) or len(found)<=len(selected):
        raise ValueError('DNS изменился или выбрана последняя A-запись. Удаление запрещено.')
    fresh=get_zone(c)
    if canonical(fresh)!=canonical(g):
        raise ValueError('DNS изменился после предварительного просмотра. Обновите список.')
    stamp=datetime.now(timezone.utc).strftime('%Y%m%d-%H%M%S-%f')
    path=BACKUPS/(c['mode']+'-'+stamp+'.json')
    audit={'zone':c['zone'],'subhost':sub,'selected':selected,'mode':c['mode'],
           'before':fresh,'outcome':'pending'}
    private_write(path,audit)
    # Exact record tuples only; never send an empty or wildcard filter.
    payload={'dns_sub_list':[{'sub_host':found[ip]['sub_host'],'record_type':'a',
                             'record_value1':found[ip]['record_value1']} for ip in selected]}
    try:
        result=request(c,'DELETE',payload)
        after=get_zone(c)
        audit['after']=after
        audit['result']=result
        expected=dict(fresh)
        expected['dns_sub_list']=[r for r in fresh['dns_sub_list'] if r not in [found[ip] for ip in selected]]
        if (str(result.get('sub_record_removed_count'))!=str(len(selected))
                or str(result.get('main_record_removed_count','0' if fresh.get('dns_main_list') is not None else '?'))!='0'
                or canonical(after)!=canonical(expected)):
            raise ValueError('Ответ или DNS после удаления не совпал с ожидаемым. Проверьте Dynadot вручную; не повторяйте запрос.')
        audit['outcome']='verified'
        private_write(path,audit)
        return {'removed':selected,'remaining':sorted(matching(after,sub),key=ipaddress.IPv4Address),
                'backup':path.name,'mode':c['mode']}
    except Exception:
        audit['outcome']='unverified'
        private_write(path,audit)
        raise

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
        domain(cfg['zone'])
        return cfg
    except (OSError,ValueError,KeyError,TypeError):
        raise ValueError('Некорректные локальные настройки Dynadot.') from None

def public_config():
    try:
        c=config()
        return {'configured':True,'zone':c['zone'],'mode':c['mode']}
    except ValueError:
        return {'configured':False,'zone':'','mode':'production'}

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
    c={'zone':domain(body.get('zone')),'mode':body.get('mode','production')}
    if c['mode'] not in BASE:
        raise ValueError('Некорректный режим API.')
    for k in ('key','secret'):
        v=body.get(k)
        if not isinstance(v,str) or not v.strip() or len(v)>2048 or any(ord(x)<33 or ord(x)>126 for x in v.strip()):
            raise ValueError('Введите API Key и Secret Key.')
        c[k]=v.strip()
    get_zone(c)
    private_write(FILE,c)
    return public_config()

_last=0.0
def request(c,method,payload=None):
    global _last
    path='/restful/v2/domains/'+domain(c['zone'])+'/records'
    body='' if payload is None else json.dumps(payload,ensure_ascii=True,separators=(',',':'))
    request_id=str(uuid.uuid4())
    message='\n'.join((c['key'],path,request_id,body)).encode()
    signature=base64.b64encode(hmac.new(c['secret'].encode(),message,hashlib.sha256).digest()).decode()
    req=Request(BASE[c['mode']]+path,data=body.encode() if payload is not None else None,method=method,
                headers={'Authorization':'Bearer '+c['key'],'X-Request-ID':request_id,
                         'X-Signature':signature,'Content-Type':'application/json','Accept':'application/json'})
    time.sleep(max(0,1.1-(time.monotonic()-_last)))
    _last=time.monotonic()
    try:
        with build_opener(NoRedirect()).open(req,timeout=30) as r:
            raw=json.loads(r.read(4*1024*1024))
    except HTTPError as e:
        code=e.code
        e.close()
        raise ValueError(f'Dynadot HTTP {code}. Проверьте ключи, разрешённый внешний IP, домен и лимиты.') from None
    except (URLError,OSError,ValueError):
        raise ValueError('Dynadot: ошибка сети или ответа. Не повторяйте удаление вслепую; обновите DNS-список.') from None
    if not isinstance(raw,dict) or str(raw.get('code')) not in ('0','200'):
        raise ValueError('Dynadot отклонил запрос или вернул неизвестный формат.')
    data=raw.get('data')
    if not isinstance(data,dict):
        raise ValueError('Dynadot: неизвестная структура ответа.')
    return data

def get_zone(c):
    data=request(c,'GET')
    g=data.get('glue_info')
    if not isinstance(g,dict) or g.get('glue_type')!='dns':
        raise ValueError('Домен не использует Dynadot DNS или формат ответа изменился.')
    for key in ('dns_main_list','dns_sub_list'):
        rows=g.get(key)
        if not isinstance(rows,list) or any(not isinstance(r,dict) for r in rows):
            raise ValueError('Неполный список DNS-записей. Изменение запрещено.')
        for r in rows:
            if not isinstance(r.get('record_type'),str) or not isinstance(r.get('record_value1'),str):
                raise ValueError('Неизвестный формат DNS-записи.')
            if key=='dns_sub_list' and not isinstance(r.get('sub_host'),str):
                raise ValueError('Неизвестный формат поддомена.')
    return g

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
        return sorted(json.dumps(r,sort_keys=True,ensure_ascii=True) for r in g[key])
    return (records('dns_main_list'),records('dns_sub_list'),g.get('ttl'))

def preview(state):
    c=config()
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
                or str(result.get('main_record_removed_count','0'))!='0'
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

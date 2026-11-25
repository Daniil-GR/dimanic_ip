"""Append-only Dynadot A-record operations. No API call without explicit confirmation."""
from collections import Counter
from datetime import datetime, timezone
import ipaddress
import json
import re
import dynadot_dns as d

def parse_ips(text):
    if not isinstance(text,str) or len(text)>4096:
        raise ValueError('Введите IPv4 по одному на строку, максимум 20 за проверку.')
    tokens=[x for x in re.split(r'[\s,;]+',text.strip()) if x]
    if not tokens or len(tokens)>20:
        raise ValueError('Введите от 1 до 20 IPv4 за проверку.')
    ips=[]
    for token in tokens:
        try:
            addr=ipaddress.IPv4Address(token)
        except ValueError:
            raise ValueError('Некорректный IPv4 в списке.') from None
        if not addr.is_global or addr.is_multicast or addr.is_reserved:
            raise ValueError('Разрешены только публичные unicast IPv4.')
        if str(addr) not in ips:
            ips.append(str(addr))
    return ips

def current_ttl(zone):
    ttl=d.pagination_int(zone.get('ttl'))
    if ttl is None or not 1 <= ttl <= 2147483647:
        raise ValueError('Не удалось определить текущий TTL в секундах. Добавление запрещено.')
    return ttl

def prepare(zone,sub,ips):
    existing=d.matching(zone,sub)
    new=[ip for ip in ips if ip not in existing]
    duplicates=[ip for ip in ips if ip in existing]
    current_ttl(zone)
    # Refuse types incompatible with A records or delegated DNS.
    for r in zone['dns_sub_list']:
        name=r['sub_host'].lower().rstrip('.')
        kind=r['record_type'].lower()
        if (name==sub and kind in ('cname','forward','stealth','ns','aname')) or (
            kind=='ns' and sub.endswith('.'+name)):
            raise ValueError('На поддомене или его родительской ветке есть конфликтующая DNS-запись.')
    if len(zone['dns_sub_list'])+len(new)>100:
        raise ValueError('Добавление превысит лимит 100 записей поддоменов Dynadot.')
    return new,duplicates

def payload_for(zone,sub,ips):
    new,duplicates=prepare(zone,sub,ips)
    if not new or duplicates or len(set(ips))!=len(ips):
        raise ValueError('Список новых адресов пуст или содержит дубликаты.')
    return {'dns_sub_list':[{'sub_host':sub,'record_type':'a','record_value1':ip} for ip in new],
            'ttl':current_ttl(zone),'add_dns_to_current_setting':True}

def _record_counter(rows):
    return Counter(json.dumps(r,sort_keys=True,ensure_ascii=True) for r in rows)

def verify(before,after,sub,ips):
    if current_ttl(before)!=current_ttl(after):
        return False
    if d.canonical(before)[0]!=d.canonical(after)[0]:
        return False
    remaining=[]
    added=Counter()
    wanted=set(ips)
    for r in after['dns_sub_list']:
        if (r['sub_host'].lower().rstrip('.')==sub and r['record_type'].lower()=='a'
                and r['record_value1'] in wanted):
            added[r['record_value1']]+=1
        else:
            remaining.append(r)
    return (added==Counter(ips) and
            _record_counter(remaining)==_record_counter(before['dns_sub_list']))

def append_records(c,sub,preview,ips):
    # Re-read immediately before mutation. Do not send POST on a changed zone.
    fresh=d.get_zone(c)
    if d.canonical(fresh)!=d.canonical(preview):
        raise ValueError('DNS изменился после проверки. Проверьте новые IP ещё раз.')
    payload=payload_for(fresh,sub,ips)
    stamp=datetime.now(timezone.utc).strftime('%Y%m%d-%H%M%S-%f')
    path=d.BACKUPS/(c['mode']+'-add-'+stamp+'.json')
    audit={'zone':c['zone'],'subhost':sub,'mode':c['mode'],'operation':'append',
           'selected':ips,'before':fresh,'outcome':'pending'}
    d.private_write(path,audit)
    try:
        # SET_DNS returns a success envelope which may not contain data.
        # Never automatically retry POST, including on an ambiguous timeout.
        d.request(c,'POST',payload)
        after=d.get_zone(c)
        audit['after']=after
        if not verify(fresh,after,sub,ips):
            raise ValueError('DNS после добавления не совпал с ожидаемым. Проверьте Dynadot вручную.')
        audit['outcome']='verified'
        d.private_write(path,audit)
        return {'added':ips,'remaining':sorted(d.matching(after,sub),key=ipaddress.IPv4Address),
                'backup':path.name,'mode':c['mode']}
    except Exception as exc:
        audit['outcome']='unverified'
        try:
            d.private_write(path,audit)
        except OSError:
            pass
        raise ValueError('Добавление не подтверждено: '+str(exc)+
                         ' Не повторяйте автоматически; обновите список DNS. Резервная копия: '+path.name) from None

"""Local, shared history of MTProto observations; no credentials are stored."""
import ipaddress
import json
import sqlite3
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone

FAIL = {'RKN_BLOCK','DATA_CUT','MT_DEAD','DOWN','UNKNOWN'}


def stamp(value):
    try:
        d=datetime.fromisoformat(value.replace('Z','+00:00'))
        if d.tzinfo is None:
            return None
        return d.astimezone(timezone.utc).isoformat(timespec='microseconds')
    except (AttributeError, TypeError, ValueError):
        return None


@contextmanager
def database(path):
    path.parent.mkdir(parents=True,exist_ok=True,mode=0o700)
    con=sqlite3.connect(path,timeout=15)
    con.row_factory=sqlite3.Row
    try:
        with con:
            con.execute('''CREATE TABLE IF NOT EXISTS events (
                ip TEXT NOT NULL, host TEXT NOT NULL, port INTEGER NOT NULL,
                at TEXT NOT NULL, kind TEXT NOT NULL, status TEXT NOT NULL,
                ext INTEGER, PRIMARY KEY(ip,host,port,at,kind,status))''')
            con.execute('CREATE INDEX IF NOT EXISTS events_target ON events(ip,host,port,kind,at)')
            con.execute('CREATE TABLE IF NOT EXISTS imports (path TEXT PRIMARY KEY)')
            yield con
    finally:
        con.close()


def target(host,port,ip):
    try:
        if not isinstance(host,str) or not host or type(port) is not int or not 1<=port<=65535:
            return None
        return str(ipaddress.IPv4Address(ip)),host.lower().rstrip('.'),port
    except (ValueError, TypeError):
        return None


def insert(con,key,at,kind,status,ext=None):
    if key and at:
        con.execute('INSERT OR IGNORE INTO events VALUES (?,?,?,?,?,?,?)',(*key,at,kind,status,ext))


def observe(con,host,port,rows,fallback=None):
    for row in rows:
        key=target(host,port,row.get('ip'))
        at=stamp(row.get('checked_at')) or stamp(fallback)
        if not key or not at:
            continue
        status=row.get('api_status')
        ext=row.get('remote_data')
        if row.get('local_data') is True and status not in ('API_ERROR','PAUSED','WAITING','NOT_TESTED'):
            # Store actual successful observations so imports and recovery remain chronological.
            insert(con,key,at,'success',str(status or 'RU_OK'),ext if type(ext) is bool else None)
        elif (row.get('first_ru_data') is False and row.get('local_data') is False
              and row.get('recheck') in FAIL and row.get('first_api_status') in FAIL):
            insert(con,key,at,'failure',row['recheck'],ext if type(ext) is bool else None)


def record(path,host,port,rows,fallback=None):
    with database(path) as con:
        observe(con,host,port,rows,fallback)


def removed(path,host,port,ips,at,mode):
    if mode!='production':
        return
    with database(path) as con:
        for ip in ips:
            insert(con,target(host,port,ip),stamp(at),'removed','DNS_REMOVED')


def import_reports(path,folder):
    """Idempotent import of previous saved scan reports, without guessing missing times."""
    if not folder.is_dir():
        return
    with database(path) as con:
        known={r[0] for r in con.execute('SELECT path FROM imports')}
    for file in sorted(folder.glob('proxy-check-*.json')):
        name=str(file.resolve())
        if name in known:
            continue
        try:
            if file.stat().st_size>16*1024*1024:
                continue
            report=json.loads(file.read_text(encoding='utf-8'))
            if not isinstance(report,dict) or not isinstance(report.get('rows'),list):
                continue
            host,port=report.get('host'),report.get('port')
            rows=[r for r in report['rows'] if isinstance(r,dict)]
            auto=report.get('auto_result') or {}
            if not isinstance(auto,dict):
                auto={}
            measurements=auto.get('measurements') or []
            rows += [r for r in measurements if isinstance(r,dict)]
            with database(path) as con:
                observe(con,host,port,rows)
                if auto.get('status')=='removed':
                    for ip in auto.get('removed',[]):
                        insert(con,target(host,port,ip),stamp(auto.get('removed_at') or report.get('finished_at')),'removed','DNS_REMOVED')
                con.execute('INSERT OR IGNORE INTO imports VALUES (?)',(name,))
        except (OSError, ValueError, TypeError):
            continue


def entries(path):
    with database(path) as con:
        rows=con.execute('''WITH groups AS (
            SELECT ip,host,port,MIN(CASE WHEN kind='failure' THEN at END) first_failure,
                MAX(CASE WHEN kind='failure' THEN at END) last_failure,
                SUM(kind='failure') failures, MAX(CASE WHEN kind='success' THEN at END) last_success,
                MAX(CASE WHEN kind='removed' THEN at END) removed_at
            FROM events GROUP BY ip,host,port HAVING failures>0 OR removed_at IS NOT NULL
        ) SELECT g.*,(SELECT status FROM events e WHERE e.ip=g.ip AND e.host=g.host AND e.port=g.port
                     AND e.kind='failure' ORDER BY at DESC,status DESC LIMIT 1) status,
                     (SELECT ext FROM events e WHERE e.ip=g.ip AND e.host=g.host AND e.port=g.port
                     AND e.kind='failure' ORDER BY at DESC,status DESC LIMIT 1) ext
          FROM groups g ORDER BY COALESCE(last_failure,removed_at) DESC,ip,host,port''').fetchall()
    result=[]
    for row in rows:
        r=dict(row)
        r['recovered']=bool(r['last_success'] and r['last_failure'] and r['last_success']>r['last_failure'])
        r['suspected_block']=r['status'] in ('RKN_BLOCK','DATA_CUT') and r['ext']==1
        r['review_from']=r['review_to']=None
        if r['suspected_block'] and not r['recovered']:
            date=datetime.fromisoformat(r['last_failure'])
            r['review_from']=(date+timedelta(days=60)).isoformat()
            r['review_to']=(date+timedelta(days=90)).isoformat()
        result.append(r)
    return result


def events(path):
    with database(path) as con:
        return [dict(r) for r in con.execute('''SELECT * FROM events e WHERE EXISTS
            (SELECT 1 FROM events f WHERE f.ip=e.ip AND f.host=e.host AND f.port=e.port
             AND f.kind IN ('failure','removed')) ORDER BY e.at DESC''')]

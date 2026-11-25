'use strict';
const $=id=>document.getElementById(id), token=document.querySelector('meta[name=local-token]').content;
let state={rows:[],ips:[]}, busy=false, lastRender='', lastKey=null, pauseBusy=false;
let monitorIntervalSeen=null,monitorIntervalDirty=false,monitorBusy=false;
const intervalValue=()=>{const v=Number($('monitorInterval').value);return Number.isInteger(v)&&v>=1&&v<=1440?v*60:null;};
const isPaused=ip=>(state.paused||[]).includes(ip);
const isProtected=ip=>(state.protected||[]).includes(ip);
const pauseLocked=()=>pauseBusy||!!state.pause_error||!!state.pause_committing||['key','saving'].includes(state.phase);
const esc=v=>String(v??'—').replace(/[&<>"']/g,x=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[x]));
const color=v=>v===true?'ok':v===false?'bad':'neutral';
const label=v=>v===true?'Доступен':v===false?'Нет данных DC':'Не определено';
const tone=r=>r.local_data===true?'ok':r.local_data===false?'bad':'warn';
const action={KEEP:'Оставить',REVIEW_DNS:'Проверить DNS/VPS',RECHECK:'Перепроверить'};
const fmt=v=>v===true?'Да':v===false?'Нет':v??'—';
const message=(s)=>{$('message').textContent=s;};
async function post(path,data){
  const r=await fetch(path.replace(/^\//,''),{method:'POST',headers:{'Content-Type':'application/json','X-Local-Token':token},body:JSON.stringify(data)});
  const j=await r.json();if(!r.ok)throw Error(j.error||'Ошибка запроса');return j;
}
async function run(mode='all',ip=null){
  if(busy)return;
  const auto=mode==='all'&&$('autoCleanup').checked;
  busy=true;buttons();message('');
  try{
    await post('/api/check',{link:mode==='all'?$('link').value:'',timeout:Number($('timeout').value),repeat:$('repeat').checked,mode,ip,auto_cleanup:auto});
    if(auto)$('autoCleanup').checked=false;
    $('link').value='';$('link').type='password';$('showLink').textContent='Показать';await poll();
  }catch(e){message(e.message);}finally{busy=false;buttons();}
}
function active(){return ['dns','checking','saving','key'].includes(state.phase);}
function buttons(){
  dnsButtons();
  const monitoring=!!state.monitor?.enabled;
  const lock=busy||active()||monitoring;
  const dnsReady=!!state.dynadot?.configured&&state.dynadot.mode==='production';
  $('monitorCleanup').disabled=lock||monitorBusy||!dnsReady;
  if(monitoring)$('monitorCleanup').checked=state.monitor.auto_cleanup===true;
  else if(!dnsReady)$('monitorCleanup').checked=false;
  const cleanup=$('monitorCleanup').checked;
  $('monitorStart').textContent=cleanup?'Запустить мониторинг с автоудалением':'Запустить мониторинг';
  $('monitorStart').disabled=lock||monitorBusy||!state.has_key||!state.can_repeat||!intervalValue()||!!state.monitor?.committing||(cleanup&&!dnsReady);
  $('monitorStop').disabled=!monitoring||monitorBusy;
  $('monitorSaveInterval').disabled=monitorBusy||!intervalValue()||intervalValue()===state.monitor?.interval;
  $('monitorInterval').disabled=monitorBusy;
  $('monitorModeHint').textContent=cleanup?'Автоудаление: два подтверждённых отказа RU независимо от NL. Паузы, защита новых VPS и защита от общего сбоя сохраняются.':dnsReady?'Обычный мониторинг: только проверка, DNS не изменяется.':'Обычный мониторинг доступен без Dynadot. Для автоудаления подключите Production Dynadot.';
  $('start').disabled=lock||!state.has_key;
  $('autoCleanup').disabled=lock||!state.dynadot?.configured||state.dynadot.mode!=='production';
  if(!state.dynadot?.configured||state.dynadot.mode!=='production')$('autoCleanup').checked=false;
  $('failed').disabled=lock||!state.has_key||!state.can_repeat||!state.rows.some(r=>r.local_data!==true&&!isPaused(r.ip));
  $('keyForm').querySelector('button').disabled=lock;
  document.querySelectorAll('[data-repeat]').forEach(b=>b.disabled=lock||!state.has_key||!state.can_repeat||isPaused(b.dataset.repeat));
  document.querySelectorAll('[data-pause-ip]').forEach(b=>b.disabled=pauseLocked());
  document.querySelectorAll('[data-release-ip]').forEach(b=>b.disabled=pauseLocked()||!!state.protection_error||isPaused(b.dataset.releaseIp));
  $('copyCandidates').disabled=!state.rows.some(r=>r.action==='REVIEW_DNS'&&!isPaused(r.ip)&&!isProtected(r.ip));
}
$('scanForm').addEventListener('submit',e=>{e.preventDefault();run();});
$('failed').onclick=()=>run('failed');
$('keyToggle').onclick=()=>{$('keyPanel').hidden=!$('keyPanel').hidden;};
$('showLink').onclick=()=>{const v=$('link');v.type=v.type==='password'?'text':'password';$('showLink').textContent=v.type==='password'?'Показать':'Скрыть';};
$('keyForm').addEventListener('submit',async e=>{
  e.preventDefault();if(busy||active())return;busy=true;buttons();
  try{await post('/api/key',{key:$('key').value.trim()});$('key').value='';$('keyPanel').hidden=true;message('Ключ проверен и сохранён.');await poll();}
  catch(e){message(e.message);}finally{busy=false;buttons();}
});
$('copyCandidates').onclick=async()=>{try{await navigator.clipboard.writeText(state.rows.filter(r=>r.action==='REVIEW_DNS'&&!isPaused(r.ip)&&!isProtected(r.ip)).map(r=>r.ip).join('\n'));message('IP скопированы.');}catch(e){message('Не удалось скопировать. Выделите IP в блоке выше.');}};
for(const id of ['search','filter','sort'])$(id).addEventListener('input',renderTable);
$('closeDetail').onclick=()=>$('detail').close();
function metrics(r,side){return '<span class="'+color(r[side+'_data'])+'">'+esc(label(r[side+'_data']))+'</span><small>Handshake '+esc(fmt(r[side+'_handshake']))+' · '+esc(r[side+'_latency_ms']??'—')+' ms</small>';}
function renderTable(){
  const existing=new Map(state.rows.map(r=>[r.ip,r]));
  let rows=state.ips.map(ip=>existing.get(ip)||{ip,port:state.port,api_status:'WAITING',action:'RECHECK'});
  rows=rows.filter(r=>r.ip.includes($('search').value.trim()));
  const f=$('filter').value;
  if(f!=='all')rows=rows.filter(r=>f==='paused'?isPaused(r.ip):!isPaused(r.ip)&&(f==='ok'?r.local_data===true:f==='bad'?r.local_data===false:r.local_data==null));
  if($('sort').value==='latency')rows.sort((a,b)=>(a.local_latency_ms??Infinity)-(b.local_latency_ms??Infinity));
  $('rows').innerHTML=rows.map(r=>{
    const paused=isPaused(r.ip), pending=!existing.has(r.ip)||['WAITING','PAUSED','NOT_TESTED'].includes(r.api_status);
    const status=paused?'На паузе':pending?'Ожидает проверки':r.api_status;
    const protectedIp=isProtected(r.ip);
    const release=protectedIp?'<button class="secondary pause-action" data-release-ip="'+esc(r.ip)+'">Снять защиту</button>':'';
    return '<tr><td>'+esc(r.ip)+'<small>:'+esc(r.port)+'</small></td><td>'+(paused?'<span class="neutral">—</span>':metrics(r,'local'))+'</td><td>'+(paused?'<span class="neutral">—</span>':metrics(r,'remote'))+'</td><td>'+esc(status)+'<small>'+esc(paused?'Проверки отключены':pending?'Нет измерений':r.recheck?'Повтор: '+r.recheck:'Первичная проверка')+'</small></td><td class="'+(paused?'paused-tone':tone(r))+'">'+esc(paused?'Сохранить в DNS':protectedIp?'Защищён · новый VPS':pending?'Ожидает проверки':action[r.action]||r.action)+'</td><td>'+(pending||paused?'':'<button class="secondary" data-detail="'+esc(r.ip)+'">Детали</button> ')+'<button class="secondary" data-repeat="'+esc(r.ip)+'">Повтор</button> <button class="secondary pause-action" data-pause-ip="'+esc(r.ip)+'" data-pause-value="'+String(!paused)+'">'+(paused?'Возобновить':'Пауза')+'</button> '+release+'</td></tr>';
  }).join('');
  $('empty').hidden=rows.length>0;buttons();
}
async function togglePause(ip,enabled){
  if(pauseLocked())return;
  pauseBusy=true;buttons();
  const host=state.host;
  try{
    const result=await post('/api/ipv4/pause',{host,ip,paused:enabled});
    if(state.host===result.host){
      state.paused=result.paused;
      if(!enabled)state.rows=state.rows.map(r=>r.ip===ip?{ip:r.ip,port:r.port,api_status:'WAITING',action:'RECHECK'}:r);
      render();
    }
    dns=null;$('dnsPreview').hidden=true;
    $('pauseMessage').textContent=ip+(enabled?' — на паузе. DNS сохранён.':' — проверки возобновлены со следующего цикла.');
    await poll();
  }catch(e){$('pauseMessage').textContent=e.message;}
  finally{pauseBusy=false;buttons();}
}
async function releaseProtection(ip){
  if(pauseLocked()||state.protection_error||isPaused(ip)||!isProtected(ip))return;
  if(!window.confirm('Снять защиту нового VPS '+ip+'? Если следующие две проверки RU завершатся неудачно, активное автоудаление сможет удалить его A-запись.'))return;
  pauseBusy=true;buttons();
  try{
    const result=await post('/api/ipv4/release-protection',{host:state.host,ip,confirm:true});
    if(state.host===result.host){
      state.protected=result.protected;
      state.rows=state.rows.map(r=>r.ip===ip?{ip:r.ip,port:r.port,api_status:'WAITING',action:'RECHECK'}:r);
      render();
    }
    $('pauseMessage').textContent=ip+' — защита снята. Нужна новая проверка.';
    await poll();
  }catch(e){$('pauseMessage').textContent=e.message;}
  finally{pauseBusy=false;buttons();}
}
function detail(ip){
  const r=state.rows.find(x=>x.ip===ip);if(!r)return;
  $('detailTitle').textContent=ip+':'+r.port;
  const fields=[['TCP','tcp'],['Handshake','handshake'],['Данные DC','data'],['SSH','ssh'],['Ping, ms','ping_ms'],['Latency, ms','latency_ms'],['Duration, ms','duration_ms']];
  $('detailBody').innerHTML='<p>'+esc(r.status)+' · API '+esc(r.api_status)+'</p><table><thead><tr><th>Метрика</th><th>RU</th><th>EXT</th></tr></thead><tbody>'+fields.map(([l,k])=>'<tr><td>'+esc(l)+'</td><td>'+esc(fmt(r['local_'+k]))+'</td><td>'+esc(fmt(r['remote_'+k]))+'</td></tr>').join('')+'</tbody></table><p>Первый результат: '+esc(r.first_api_status)+' · RU '+esc(fmt(r.first_ru_data))+' · EXT '+esc(fmt(r.first_ext_data))+'</p><p>Время: '+esc(r.checked_at)+'</p>';
  if(!$('detail').open)$('detail').showModal();
}
document.addEventListener('click',e=>{
  const d=e.target.closest('[data-detail]'),r=e.target.closest('[data-repeat]');
  const release=e.target.closest('[data-release-ip]');
  if(release)releaseProtection(release.dataset.releaseIp);
  const p=e.target.closest('[data-pause-ip]');
  if(p)togglePause(p.dataset.pauseIp,p.dataset.pauseValue==='true');
  if(d)detail(d.dataset.detail);if(r)run('one',r.dataset.repeat);
});
function render(){
  dnsRender();
  const p=state.phase;
  const m=state.monitor||{};
  $('monitorTarget').textContent='Прокси: '+(m.enabled?m.host+':'+m.port:state.host?state.host+':'+state.port:'—');
  if(Number.isInteger(m.interval)&&monitorIntervalSeen!==m.interval){
    monitorIntervalSeen=m.interval;
    if(!monitorIntervalDirty)$('monitorInterval').value=String(m.interval/60);
  }
  $('monitorStatus').textContent=m.enabled?(m.auto_cleanup?'Активен · автоудаление':'Активен · только проверка'):'Остановлен';
  $('monitorNext').textContent=m.enabled?(active()?'Проверка выполняется':'Следующая проверка через '+Math.floor((m.seconds||0)/60)+':'+String((m.seconds||0)%60).padStart(2,'0')):'';
  $('monitorMessage').textContent=m.message||'';
  const ar=state.auto_result;
  $('autoResult').textContent=ar?'Автоудаление: '+ar.message+(ar.removed?.length?' Удалены: '+ar.removed.join(', '):'')+(ar.protected?.length?' Защищены: '+ar.protected.join(', '):'')+(ar.backup?' Резервная копия: '+ar.backup:''):'';
  $('savedLinkHint').textContent=state.can_repeat?'Сохранённый прокси: '+state.host+':'+state.port+'. Оставьте поле пустым для повторной проверки или вставьте новую ссылку.':state.rows.length?'Для старого отчёта ссылка не сохранена. Введите её и запустите проверку один раз.':'Ссылка сохраняется локально после завершённой проверки.';
  $('link').placeholder=state.can_repeat?'Использовать сохранённый прокси или вставить новую ссылку':'tg://proxy?server=…&port=443&secret=…';
  if(lastKey!==state.has_key){lastKey=state.has_key;$('keyPanel').hidden=state.has_key;}
  $('keyState').textContent=state.has_key?'Ключ сохранён':'Нужен ключ';
  $('keyHint').textContent=state.has_key?'Введите новый ключ для замены.':'Введите ключ из Telegram-бота.';
  $('phase').textContent=({idle:'Готов к проверке',dns:'Получение A-записей…',checking:'Проверка: '+state.current,saving:'Сохранение отчёта…',done:'Проверка завершена',error:'Проверка прервана',key:'Проверка ключа…'})[p]||p;
  $('count').textContent=state.done+' / '+state.total;
  $('progress').max=Math.max(1,state.total);$('progress').value=state.done;
  $('meta').textContent=(state.source||'DNS ещё не проверен')+(state.finished_at?' · '+new Date(state.finished_at).toLocaleString('ru-RU'):'');
  if(state.error)message(state.error);
  $('domain').textContent=state.host?state.host+':'+state.port:'—';
  $('topologyRoot').textContent=state.host?state.host+':'+state.port:'Нет активного отчёта';
  if(state.pause_error||state.protection_error)$('pauseMessage').textContent=state.pause_error||state.protection_error;
  const signature=JSON.stringify([state.ips,state.rows,state.host,state.port,state.can_repeat,state.paused,state.protected]);
  if(signature!==lastRender){
    lastRender=signature;
    const ok=state.rows.filter(r=>r.local_data===true&&!isPaused(r.ip)).length,bad=state.rows.filter(r=>r.local_data===false&&!isPaused(r.ip)).length,pausedCount=state.ips.filter(isPaused).length;
    $('stats').innerHTML=[['IPv4 в DNS',state.ips.length,''],['Доступны из РФ',ok,'ok'],['Недоступны из РФ',bad,'bad'],['Нет данных / ожидают',Math.max(0,state.ips.length-ok-bad-pausedCount),'warn'],['На паузе',pausedCount,'paused-tone']].map(([l,n,c])=>'<div class="stat"><span>'+l+'</span><strong class="'+c+'">'+n+'</strong></div>').join('');
    $('candidates').textContent=state.rows.filter(r=>r.action==='REVIEW_DNS'&&!isPaused(r.ip)&&!isProtected(r.ip)).map(r=>r.ip).join(' · ')||'Нет подтверждённых повтором кандидатов.';
    renderTable();
    $('nodes').innerHTML=state.ips.map(ip=>{
      const r=state.rows.find(x=>x.ip===ip);
      if(isPaused(ip))return '<button class="node paused-tone" data-pause-ip="'+esc(ip)+'" data-pause-value="false"><strong>'+esc(ip)+'</strong><div class="node-status paused-tone">На паузе</div><small>DNS сохранён · возобновить</small></button>';
      return '<button class="node '+(r?tone(r):'neutral')+'" '+(r?'data-detail="'+esc(ip)+'"':'disabled')+'><strong>'+esc(ip)+'</strong><div class="branches"><span class="'+color(r?.local_data)+'">RU '+esc(fmt(r?.local_data))+'</span><span class="'+color(r?.remote_data)+'">EXT '+esc(fmt(r?.remote_data))+'</span></div><div class="node-status '+(r?tone(r):'neutral')+'">'+esc(['NOT_TESTED','WAITING','PAUSED'].includes(r?.api_status)?'Ожидает проверки':r?.status||'Ожидает проверки')+'</div><small>API: '+esc(r?.api_status||'—')+' · '+esc(r?.local_latency_ms??'—')+' ms</small></button>';
    }).join('');
  }
  buttons();
}
let polling=false;
async function poll(){
  if(polling)return;
  polling=true;try{const r=await fetch('api/state',{cache:'no-store'});if(!r.ok)throw Error();state=await r.json();render();}
  catch(e){message('Нет связи с локальным сервером. Проверьте окно терминала.');}finally{polling=false;}
}
let dns=null,dnsBusy=false,dnsFingerprint='',dnsSelection=[],addition=null,addSelection=[];
const dnsMsg=v=>{$('dnsMessage').textContent=v;};
function dnsButtons(){
  const lock=busy||dnsBusy||active()||!!state.monitor?.enabled;
  $('dnsLoad').disabled=lock||!state.dynadot?.configured||state.phase!=='done';
  $('dnsConfig').querySelector('button').disabled=lock;
  $('start').disabled=lock||!state.has_key;
  $('dnsSelect').disabled=lock||!dns;
  const n=document.querySelectorAll('[data-dns-ip]:checked').length;
  $('dnsDelete').disabled=lock||!dns||n===0||n>=dns.records.length;
  addButtons(lock);
  $('dnsDelete').textContent=n?'Удалить A-записи ('+n+')':'Удалить выбранные A-записи';
}
function dnsRender(){
  const c=state.dynadot||{};
  $('dnsState').textContent=c.configured?'Подключён · '+c.mode:'Не настроен';
  $('dnsHost').textContent=state.host||'Нет отчёта';
  const fp=JSON.stringify([state.host,state.started_at,state.finished_at,c.mode,c.configured]);
  if(dnsFingerprint!==fp){dnsFingerprint=fp;dns=null;$('dnsPreview').hidden=true;clearAddition();}
  $('addHost').textContent=state.host||'Нет отчёта';
  if(c.configured&&!$('dnsSettings').open){$('dnsMode').value=c.mode;}
}
async function dnsCall(fn){
  if(dnsBusy||busy||active())return;
  dnsBusy=true;busy=true;buttons();dnsMsg('');
  try{await fn();}catch(e){dnsMsg(e.message);}finally{dnsBusy=false;busy=false;await poll();buttons();}
}
$('dnsConfig').addEventListener('submit',e=>{
  e.preventDefault();dnsCall(async()=>{
    const result=await post('/api/dynadot/config',{mode:$('dnsMode').value,key:$('dnsKey').value,secret:$('dnsSecret').value});
    $('dnsKey').value='';$('dnsSecret').value='';$('dnsSettings').open=false;clearAddition();dns=null;$('dnsPreview').hidden=true;
    dnsMsg('Подключение проверено. Активных доменов: '+result.domain_count+'. Настройки сохранены локально.');
  });
});
async function loadDns(){
  dns=null;$('dnsPreview').hidden=true;
  dns=await post('/api/dynadot/preview',{});
  $('dnsRows').innerHTML=dns.records.map(r=>'<tr><td><input type="checkbox" data-dns-ip="'+esc(r.ip)+'" '+(!r.eligible?'disabled':'')+' aria-label="Выбрать '+esc(r.ip)+'"></td><td>'+esc(r.ip)+'</td><td class="'+color(r.ru)+'">'+esc(fmt(r.ru))+'</td><td class="'+color(r.ext)+'">'+esc(fmt(r.ext))+'</td><td>'+esc(r.status)+'</td></tr>').join('');
  $('dnsPreview').hidden=false;
  dnsMsg(dns.records.length?'Найдено записей: '+dns.records.length+' · '+dns.host+' (зона '+dns.zone+')':'У этого поддомена нет точных A-записей в Dynadot.');
}
$('dnsLoad').onclick=()=>dnsCall(loadDns);
$('dnsRows').addEventListener('change',dnsButtons);
$('dnsSelect').onclick=()=>{
  const boxes=[...document.querySelectorAll('[data-dns-ip]:not(:disabled)')];
  boxes.forEach(b=>b.checked=true);if(dns&&boxes.length>=dns.records.length&&boxes.length)boxes[boxes.length-1].checked=false;
  dnsButtons();
};
$('dnsDelete').onclick=()=>{
  if(!dns)return;
  dnsSelection=[...document.querySelectorAll('[data-dns-ip]:checked')].map(b=>b.dataset.dnsIp);
  $('dnsConfirmText').textContent='Удалить '+dnsSelection.length+' A-записей у '+dns.host+' ('+dns.mode+')?';
  $('dnsConfirmIPs').textContent=dnsSelection.join('\n');
  $('dnsConfirmHost').value='';$('dnsApply').disabled=true;$('dnsConfirm').showModal();
};
$('dnsConfirmHost').oninput=()=>{$('dnsApply').disabled=!dns||$('dnsConfirmHost').value!==dns.host;};
$('dnsCancel').onclick=()=>$('dnsConfirm').close();
$('dnsApply').onclick=()=>{
  if(!dns||$('dnsConfirmHost').value!==dns.host)return;
  const payload={token:dns.token,ips:dnsSelection,confirm:$('dnsConfirmHost').value};
  $('dnsConfirm').close();
  clearAddition();
  dnsCall(async()=>{
    dns=null;$('dnsPreview').hidden=true;
    const result=await post('/api/dynadot/delete',payload);
    dnsMsg('Удалено и проверено через Dynadot: '+result.removed.join(', ')+'. Осталось: '+result.remaining.length+'. Резервная копия: '+result.backup+'. Запустите новую проверку после обновления DNS.');
  });
};
function clearAddition(){addition=null;$('addPreview').hidden=true;}
const addMsg=v=>{$('addMessage').textContent=v;};
function addButtons(lock=busy||dnsBusy||active()||!!state.monitor?.enabled){
  const ready=!!state.dynadot?.configured&&state.phase==='done'&&!!state.host;
  $('addCheck').disabled=lock||!ready||!$('addIps').value.trim();
  $('addIps').disabled=lock;
  const n=document.querySelectorAll('[data-add-ip]:checked').length;
  $('addCommit').disabled=lock||!ready||!addition||!n;
  $('addCommit').textContent=n?'Добавить A-записи ('+n+')':'Добавить выбранные A-записи';
}
$('addIps').addEventListener('input',()=>{clearAddition();addButtons();});
$('addRows').addEventListener('change',()=>addButtons());
$('addCheck').onclick=()=>{
  clearAddition();addMsg('Проверка формата IPv4 и существующих DNS-записей…');
  dnsCall(async()=>{
    try{
      addition=await post('/api/dynadot/add-preview',{ips:$('addIps').value});
      $('addRows').innerHTML=addition.ips.map(ip=>'<tr><td><input type="checkbox" data-add-ip="'+esc(ip)+'" checked aria-label="Выбрать '+esc(ip)+'"></td><td>'+esc(ip)+'</td><td class="neutral">Новая A-запись · MTProto не проверен</td></tr>').join('');
      $('addPreview').hidden=!addition.ips.length;
      addMsg('Готово к добавлению: '+addition.ips.length+' · TTL '+addition.ttl+' сек. '+(addition.duplicates.length?'Уже в DNS: '+addition.duplicates.join(', '):''));
    }catch(e){clearAddition();addMsg(e.message);}
  });
};
$('addCommit').onclick=()=>{
  if(!addition)return;
  addSelection=[...document.querySelectorAll('[data-add-ip]:checked')].map(b=>b.dataset.addIp);
  $('addConfirmText').textContent='Добавить '+addSelection.length+' A-записей к '+addition.host+' ('+addition.mode+')? TTL: '+addition.ttl+' сек.';
  $('addConfirmIPs').textContent=addSelection.join('\n');
  $('addConfirmHost').value='';$('addApply').disabled=true;$('addConfirm').showModal();
};
$('addConfirmHost').oninput=()=>{$('addApply').disabled=!addition||$('addConfirmHost').value!==addition.host;};
$('addCancel').onclick=()=>$('addConfirm').close();
$('addApply').onclick=()=>{
  if(!addition||$('addConfirmHost').value!==addition.host)return;
  const payload={token:addition.token,ips:addSelection,confirm:$('addConfirmHost').value};
  $('addConfirm').close();clearAddition();
  dnsCall(async()=>{
    dns=null;$('dnsPreview').hidden=true;
    addMsg('Добавление и сверка DNS…');
    try{
      const r=await post('/api/dynadot/add',payload);
      $('addIps').value='';
      addMsg('Добавлено и подтверждено: '+r.added.join(', ')+'. Всего A-записей: '+r.remaining.length+'. Резервная копия: '+r.backup+'. '+(r.warning||'Теперь настройте прокси на VPS и запустите проверку. DNS-кэш обновится с учётом TTL.'));
      await poll();
      try{await loadDns();}catch(e){dnsMsg('Записи добавлены, но обновление таблицы не удалось: '+e.message);}
    }catch(e){addMsg(e.message);}
  });
};
$('monitorInterval').addEventListener('input',()=>{monitorIntervalDirty=true;buttons();});
$('monitorCleanup').addEventListener('change',buttons);
async function monitorAction(path,payload){
  if(monitorBusy)return;
  monitorBusy=true;buttons();
  try{
    const result=await post(path,payload);
    state.monitor=result;
    if(path!=='/api/monitor/stop'){
      monitorIntervalDirty=false;
      monitorIntervalSeen=result.interval;
      $('monitorInterval').value=String(result.interval/60);
    }
    if(path==='/api/monitor/stop')$('monitorCleanup').checked=false;
    render();
    await poll();
  }catch(e){message(e.message);}
  finally{monitorBusy=false;buttons();}
}
$('monitorSaveInterval').onclick=()=>{
  const interval=intervalValue();
  if(interval)monitorAction('/api/monitor/interval',{interval});
};
$('monitorStart').onclick=()=>{
  if($('link').value.trim()){message('Сначала проверьте новую ссылку, затем запустите мониторинг.');return;}
  const interval=intervalValue(),auto=$('monitorCleanup').checked;
  if(!interval)return;
  if(auto&&!window.confirm('Запустить мониторинг '+state.host+':'+state.port+' с автоудалением дважды недоступных из РФ A-записей? Интервал: '+interval/60+' мин.'))return;
  monitorAction('/api/monitor/start',{host:state.host,port:state.port,timeout:Number($('timeout').value),interval,auto_cleanup:auto});
};
$('monitorStop').onclick=()=>monitorAction('/api/monitor/stop',{});
let workspaceListSignature='',workspaceCreating=false,workspacePolling=false;
async function refreshWorkspaces(){
  if(workspacePolling)return;
  workspacePolling=true;
  try{
    const response=await fetch('api/workspaces',{cache:'no-store'});
    if(!response.ok)throw Error('Не удалось загрузить страницы.');
    const data=await response.json();
    $('workspaceNew').disabled=workspaceCreating||data.pages.length>=data.limit;
    const signature=JSON.stringify(data);
    if(signature===workspaceListSignature)return;
    workspaceListSignature=signature;
    $('workspaceTabs').replaceChildren();
    data.pages.forEach((page,index)=>{
      const a=document.createElement('a');
      a.className='workspace-tab'+(page.id===data.current?' current':'');
      a.href='/w/'+encodeURIComponent(page.id)+'/';
      if(page.id===data.current)a.setAttribute('aria-current','page');
      const label=document.createElement('strong');
      label.textContent=page.host?page.host+(page.port?':'+page.port:''):'Прокси '+(index+1);
      const status=document.createElement('small');
      status.className=page.monitoring?'ok':'muted';
      status.textContent=page.monitoring?'● Мониторинг активен':['dns','checking','saving','key'].includes(page.phase)?'Выполняется проверка':page.phase==='error'?'Ошибка проверки':page.host?'Готов к проверке':'Новая страница';
      a.append(label,status);$('workspaceTabs').append(a);
    });
  }catch(e){$('workspaceMessage').textContent=e.message;}finally{workspacePolling=false;}
}
$('workspaceNew').onclick=async()=>{
  if(workspaceCreating)return;
  workspaceCreating=true;$('workspaceNew').disabled=true;
  try{
    const result=await post('/api/workspaces',{});
    window.location.assign('/w/'+encodeURIComponent(result.id)+'/');
  }catch(e){
    $('workspaceMessage').textContent=e.message;workspaceCreating=false;
    await refreshWorkspaces();
  }
};
refreshWorkspaces();setInterval(refreshWorkspaces,2000);
poll();setInterval(poll,1000);

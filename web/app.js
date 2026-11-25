'use strict';
const $=id=>document.getElementById(id), token=document.querySelector('meta[name=local-token]').content;
let state={rows:[],ips:[]}, busy=false, lastRender='', lastKey=null;
const esc=v=>String(v??'—').replace(/[&<>"']/g,x=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[x]));
const color=v=>v===true?'ok':v===false?'bad':'neutral';
const label=v=>v===true?'Доступен':v===false?'Нет данных DC':'Не определено';
const tone=r=>r.local_data===true?'ok':r.local_data===false?'bad':'warn';
const action={KEEP:'Оставить',REVIEW_DNS:'Проверить DNS/VPS',RECHECK:'Перепроверить'};
const fmt=v=>v===true?'Да':v===false?'Нет':v??'—';
const message=(s)=>{$('message').textContent=s;};
async function post(path,data){
  const r=await fetch(path,{method:'POST',headers:{'Content-Type':'application/json','X-Local-Token':token},body:JSON.stringify(data)});
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
  const lock=busy||active();
  $('start').disabled=lock||!state.has_key;
  $('autoCleanup').disabled=lock||!state.dynadot?.configured||state.dynadot.mode!=='production';
  if(!state.dynadot?.configured||state.dynadot.mode!=='production')$('autoCleanup').checked=false;
  $('failed').disabled=lock||!state.has_key||!state.can_repeat||!state.rows.some(r=>r.local_data!==true);
  $('keyForm').querySelector('button').disabled=lock;
  document.querySelectorAll('[data-repeat]').forEach(b=>b.disabled=lock||!state.has_key||!state.can_repeat);
  $('copyCandidates').disabled=!state.rows.some(r=>r.action==='REVIEW_DNS');
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
$('copyCandidates').onclick=async()=>{try{await navigator.clipboard.writeText(state.rows.filter(r=>r.action==='REVIEW_DNS').map(r=>r.ip).join('\n'));message('IP скопированы.');}catch(e){message('Не удалось скопировать. Выделите IP в блоке выше.');}};
for(const id of ['search','filter','sort'])$(id).addEventListener('input',renderTable);
$('closeDetail').onclick=()=>$('detail').close();
function metrics(r,side){return '<span class="'+color(r[side+'_data'])+'">'+esc(label(r[side+'_data']))+'</span><small>Handshake '+esc(fmt(r[side+'_handshake']))+' · '+esc(r[side+'_latency_ms']??'—')+' ms</small>';}
function renderTable(){
  let rows=state.rows.filter(r=>r.ip.includes($('search').value.trim()));
  const f=$('filter').value;if(f!=='all')rows=rows.filter(r=>f==='ok'?r.local_data===true:f==='bad'?r.local_data===false:r.local_data==null);
  if($('sort').value==='latency')rows.sort((a,b)=>(a.local_latency_ms??Infinity)-(b.local_latency_ms??Infinity));
  $('rows').innerHTML=rows.map(r=>'<tr><td>'+esc(r.ip)+'<small>:'+esc(r.port)+'</small></td><td>'+metrics(r,'local')+'</td><td>'+metrics(r,'remote')+'</td><td>'+esc(r.api_status)+'<small>'+esc(r.recheck?'Повтор: '+r.recheck:r.api_status==='NOT_TESTED'?'Ожидает проверки':'Первичная проверка')+'</small></td><td class="'+tone(r)+'">'+esc(action[r.action]||r.action)+'</td><td><button class="secondary" data-detail="'+esc(r.ip)+'">Детали</button> <button class="secondary" data-repeat="'+esc(r.ip)+'">Повтор</button></td></tr>').join('');
  $('empty').hidden=rows.length>0;buttons();
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
  if(d)detail(d.dataset.detail);if(r)run('one',r.dataset.repeat);
});
function render(){
  dnsRender();
  const p=state.phase;
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
  const signature=JSON.stringify([state.ips,state.rows,state.host,state.port,state.can_repeat]);
  if(signature!==lastRender){
    lastRender=signature;
    const ok=state.rows.filter(r=>r.local_data===true).length,bad=state.rows.filter(r=>r.local_data===false).length;
    $('stats').innerHTML=[['IPv4 в DNS',state.ips.length,''],['Доступны из РФ',ok,'ok'],['Недоступны из РФ',bad,'bad'],['Нет данных / ожидают',Math.max(0,state.ips.length-ok-bad),'warn']].map(([l,n,c])=>'<div class="stat"><span>'+l+'</span><strong class="'+c+'">'+n+'</strong></div>').join('');
    $('candidates').textContent=state.rows.filter(r=>r.action==='REVIEW_DNS').map(r=>r.ip).join(' · ')||'Нет подтверждённых повтором кандидатов.';
    renderTable();
    $('nodes').innerHTML=state.ips.map(ip=>{
      const r=state.rows.find(x=>x.ip===ip);
      return '<button class="node '+(r?tone(r):'neutral')+'" '+(r?'data-detail="'+esc(ip)+'"':'disabled')+'><strong>'+esc(ip)+'</strong><div class="branches"><span class="'+color(r?.local_data)+'">RU '+esc(fmt(r?.local_data))+'</span><span class="'+color(r?.remote_data)+'">EXT '+esc(fmt(r?.remote_data))+'</span></div><div class="node-status '+(r?tone(r):'neutral')+'">'+esc(r?.api_status==='NOT_TESTED'?'Ожидает проверки':r?.status||'Ожидает проверки')+'</div><small>API: '+esc(r?.api_status||'—')+' · '+esc(r?.local_latency_ms??'—')+' ms</small></button>';
    }).join('');
  }
  buttons();
}
let polling=false;
async function poll(){
  if(polling)return;
  polling=true;try{const r=await fetch('/api/state',{cache:'no-store'});if(!r.ok)throw Error();state=await r.json();render();}
  catch(e){message('Нет связи с локальным сервером. Проверьте окно терминала.');}finally{polling=false;}
}
let dns=null,dnsBusy=false,dnsFingerprint='',dnsSelection=[],addition=null,addSelection=[];
const dnsMsg=v=>{$('dnsMessage').textContent=v;};
function dnsButtons(){
  const lock=busy||dnsBusy||active();
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
function addButtons(lock=busy||dnsBusy||active()){
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
poll();setInterval(poll,1000);

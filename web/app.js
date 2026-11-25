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
  busy=true;buttons();message('');
  try{
    await post('/api/check',{link:mode==='all'?$('link').value:'',timeout:Number($('timeout').value),repeat:$('repeat').checked,mode,ip});
    $('link').value='';$('link').type='password';$('showLink').textContent='Показать';await poll();
  }catch(e){message(e.message);}finally{busy=false;buttons();}
}
function active(){return ['dns','checking','saving','key'].includes(state.phase);}
function buttons(){
  const lock=busy||active();
  $('start').disabled=lock||!state.has_key;
  $('failed').disabled=lock||!state.can_repeat||!state.rows.some(r=>r.local_data!==true);
  $('keyForm').querySelector('button').disabled=lock;
  document.querySelectorAll('[data-repeat]').forEach(b=>b.disabled=lock||!state.can_repeat);
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
  $('rows').innerHTML=rows.map(r=>'<tr><td>'+esc(r.ip)+'<small>:'+esc(r.port)+'</small></td><td>'+metrics(r,'local')+'</td><td>'+metrics(r,'remote')+'</td><td>'+esc(r.api_status)+'<small>'+esc(r.recheck?'Повтор: '+r.recheck:'Первичная проверка')+'</small></td><td class="'+tone(r)+'">'+esc(action[r.action]||r.action)+'</td><td><button class="secondary" data-detail="'+esc(r.ip)+'">Детали</button> <button class="secondary" data-repeat="'+esc(r.ip)+'">Повтор</button></td></tr>').join('');
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
  const p=state.phase;
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
      return '<button class="node '+(r?tone(r):'neutral')+'" '+(r?'data-detail="'+esc(ip)+'"':'disabled')+'><strong>'+esc(ip)+'</strong><div class="branches"><span class="'+color(r?.local_data)+'">RU '+esc(fmt(r?.local_data))+'</span><span class="'+color(r?.remote_data)+'">EXT '+esc(fmt(r?.remote_data))+'</span></div><div class="node-status '+(r?tone(r):'neutral')+'">'+esc(r?.status||'Ожидает проверки')+'</div><small>API: '+esc(r?.api_status||'—')+' · '+esc(r?.local_latency_ms??'—')+' ms</small></button>';
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
poll();setInterval(poll,1000);

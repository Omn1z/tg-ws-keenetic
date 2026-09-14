'use strict';
const $=id=>document.getElementById(id), form=$('settings');
let csrf='',loaded=false,busy=false,timer,refreshing=null;
const STATS_INTERVAL_MS=2000;
let updateInfo=null,updateTimer,updateCall=false,updateActive=false,updateDeadline=0,updateTarget='',updateChecked=false,reloading=false;
const numbers=['port','max_connections','buffer_size','pool_size','connect_timeout_secs','idle_timeout_secs'];
const booleans=['cfproxy','domain_refresh','sni_fronting','force_test_dc','proxy_protocol'];
const strings=['link_host','fake_tls_domain','web_user'];
const lists=['cfproxy_user_domains','cfproxy_worker_domains'];
const field=name=>form.elements.namedItem(name);
function notice(text,error=false){$('notice').textContent=text;$('notice').classList.toggle('error',error);}
function bytes(n){let i=0;for(;n>=1024&&i<4;i++)n/=1024;return `${n.toFixed(i?1:0)} ${['Б','КиБ','МиБ','ГиБ','ТиБ'][i]}`;}
function elapsed(n){if(n<60)return `${n} с`;if(n<3600)return `${Math.floor(n/60)} мин`;if(n<86400)return `${Math.floor(n/3600)} ч`;return `${Math.floor(n/86400)} д`;}
async function request(path,body,timeout=0){const controller=new AbortController(),deadline=timeout?setTimeout(()=>controller.abort(),timeout):null;try{const res=await fetch(path,{method:body===undefined?'GET':'POST',headers:body===undefined?{}:{'Content-Type':'application/json','X-CSRF-Token':csrf},body:body===undefined?undefined:JSON.stringify(body),cache:'no-store',signal:controller.signal});const text=await res.text();let data;try{data=JSON.parse(text);}catch{throw Error(text||`HTTP ${res.status}`);}if(!res.ok){const error=Error(data.error||`HTTP ${res.status}`);error.status=res.status;throw error;}return data;}finally{clearTimeout(deadline);}}
const version=value=>`v${String(value).replace(/^v/,'')}`;
const sameVersion=(a,b)=>a&&b&&version(a)===version(b);
function updateMessage(text,error=false){$('update-status').textContent=text;$('update-status').hidden=!text;$('update-status').classList.toggle('error',error);}
function updateControls(){const installing=updateActive||!!updateInfo?.running,active=updateCall||installing||updateInfo?.checking;$('check-update').disabled=!csrf||active||busy;$('install-update').hidden=!updateInfo?.available&&updateInfo?.supported!==false;$('install-update').disabled=!csrf||active||busy||!updateInfo?.available||!updateInfo?.supported;$('restart').disabled=busy||installing;$('fields').disabled=!loaded||busy||installing;}
function finishUpdate(current){if(updateActive&&sameVersion(current,updateTarget)&&!reloading){reloading=true;clearTimeout(updateTimer);updateMessage('Обновлено. Перезагрузка панели…');location.reload();return true;}return false;}
function renderUpdate(info){
  updateInfo=info;if(info.current)$('version').textContent=version(info.current);
  $('available').textContent=info.available&&info.latest?`→ ${version(info.latest)}`:'';$('available').hidden=!$('available').textContent;
  if(finishUpdate(info.current))return;
  if(info.running&&!updateActive&&!sameVersion(info.current,info.latest)){updateActive=true;updateTarget=info.latest||'';if(!updateDeadline)updateDeadline=Date.now()+360000;}
  if(info.error||info.stage==='error'){updateActive=false;updateDeadline=0;updateMessage(info.error||'Не удалось обновить. Повторите попытку.',true);}
  else if(updateActive){const stages={downloading:'Загрузка обновления…',installing:'Установка обновления…',restarting:'Перезапуск. Ожидаем подключение…',complete:'Ожидаем новую версию…'};updateMessage(stages[info.stage]||'Подготовка обновления…');}
  else if(info.checking)updateMessage('Проверка обновлений…');
  else if(!info.supported)updateMessage('Для обновления используйте SSH.');
  else if(info.available)updateMessage('');
  else if(info.checked_at&&info.latest)updateMessage('Обновлений нет.');
  else updateMessage('');
  updateControls();scheduleUpdate();
}
function scheduleUpdate(){clearTimeout(updateTimer);if(reloading||document.hidden||(!updateActive&&!updateInfo?.checking&&!updateInfo?.running))return;if(updateActive&&Date.now()>=updateDeadline){updateActive=false;updateMessage('Роутер не подтвердил обновление. Проверьте связь и обновите страницу.',true);updateControls();return;}updateTimer=setTimeout(pollUpdate,1500);}
async function pollUpdate(){if(updateCall)return scheduleUpdate();updateCall=true;try{renderUpdate(await request('/api/update/status',undefined,10000));}catch(error){updateMessage(updateActive?'Ожидаем подключение к роутеру…':'Не удалось проверить обновления. Нажмите «Проверить».',!updateActive);if(!updateActive&&updateInfo)updateInfo.checking=false;}finally{updateCall=false;updateControls();scheduleUpdate();}}
async function checkUpdate(force=false){if(updateCall||updateActive||updateInfo?.running)return;updateChecked=true;updateCall=true;updateDeadline=0;updateMessage('Проверка обновлений…');updateControls();try{renderUpdate(await request('/api/update/check',force?{}:undefined,10000));}catch(error){if(updateInfo)updateInfo.checking=false;updateMessage('Не удалось проверить обновления. Нажмите «Проверить».',true);}finally{updateCall=false;updateControls();scheduleUpdate();}}
async function installUpdate(){if(updateCall||updateActive||busy||!updateInfo?.available||!updateInfo?.supported)return;updateTarget=updateInfo.latest;updateActive=true;updateDeadline=Date.now()+360000;updateCall=true;updateMessage('Подготовка обновления…');updateControls();try{renderUpdate(await request('/api/update',{},10000));}catch(error){if(error.status){updateActive=false;updateDeadline=0;updateMessage(error.message,true);}else updateMessage('Ожидаем ответ роутера…');}finally{updateCall=false;updateControls();scheduleUpdate();}}
function populate(cfg,passwordSet){
  for(const name of [...numbers,...strings])field(name).value=cfg[name];
  if(field('buffer_size').value===''){const option=new Option(`${cfg.buffer_size} Б · текущий`,cfg.buffer_size);field('buffer_size').add(option);field('buffer_size').value=cfg.buffer_size;}
  for(const name of booleans)field(name).checked=cfg[name];
  for(const name of lists)field(name).value=cfg[name].join('\n');
  field('dc_redirects').value=Object.entries(cfg.dc_redirects).map(([dc,ip])=>`${dc}:${ip}`).join('\n');
  field('web_password').value='';$('clear-password').checked=false;
  $('auth-note').textContent=passwordSet?'Пароль установлен. Пустое поле сохраняет текущий пароль.':'Пароль не установлен. Панель доступна устройствам локальной сети.';
  $('fields').disabled=false;
}
function refresh(reset=false){if(refreshing)return reset?refreshing.then(()=>refresh(true)):refreshing;refreshing=refreshState(reset).finally(()=>{refreshing=null;});return refreshing;}
async function refreshState(reset=false){
  try{const data=await request('/api/state',undefined,5000);csrf=data.csrf;const s=data.stats;
    document.title=`↑ ${bytes(s.bytes_up)} · ↓ ${bytes(s.bytes_down)}`;
    $('status').textContent='Работает';$('led').className='on';$('version').textContent=version(data.version);
    $('link').textContent=data.link;$('open').href=data.link;$('open').setAttribute('aria-disabled','false');
    $('active').textContent=s.connections_active;$('total').textContent=`Всего ${s.connections_total}`;
    $('up').textContent=bytes(s.bytes_up);$('down').textContent=bytes(s.bytes_down);$('uptime').textContent=elapsed(Math.floor(s.uptime_secs));
    $('routes').textContent=`WS ${s.connections_ws} · CF ${s.connections_cfproxy} · TCP ${s.connections_tcp_fallback}`;
    if(!loaded||reset){populate(data.config,data.password_set);loaded=true;}
    if(finishUpdate(data.version))return;if(data.update)renderUpdate(data.update);else updateControls();if(!updateChecked)checkUpdate();
  }catch(error){document.title='↑ — · ↓ — · нет связи';$('status').textContent='Нет связи';$('led').className='off';if(!loaded)notice(error.message,true);}
}
function payload(){const cfg={};for(const n of numbers)cfg[n]=Number(field(n).value);for(const n of strings)cfg[n]=field(n).value.trim();for(const n of booleans)cfg[n]=field(n).checked;for(const n of lists)cfg[n]=field(n).value.split(/[\s,;]+/).filter(Boolean);cfg.dc_redirects={};for(const line of field('dc_redirects').value.split('\n').map(s=>s.trim()).filter(Boolean)){const match=line.match(/^(\d+)\s*:\s*(.+)$/);if(!match)throw Error(`Неверная запись DC: ${line}`);cfg.dc_redirects[match[1]]=match[2];}if($('clear-password').checked)cfg.web_password='';else if(field('web_password').value)cfg.web_password=field('web_password').value;return cfg;}
async function change(path,body){if(busy||updateActive||updateInfo?.running)return;busy=true;$('fields').disabled=true;updateControls();notice('Применение…');try{await request(path,body);await refresh(true);notice('Готово. Настройки применены.');}catch(error){notice(error.message,true);}finally{busy=false;$('fields').disabled=!loaded;updateControls();}}
form.addEventListener('submit',event=>{event.preventDefault();try{change('/api/config',payload());}catch(error){notice(error.message,true);}});
$('restart').addEventListener('click',()=>change('/api/restart',{}));
$('check-update').addEventListener('click',()=>checkUpdate(true));
$('install-update').addEventListener('click',installUpdate);
$('new-secret').addEventListener('click',()=>{if(confirm('Создать новый секрет? Старую ссылку потребуется заменить на всех устройствах.'))change('/api/secret',{});});
$('copy').addEventListener('click',async()=>{const link=$('link').textContent;if(!loaded)return;try{await navigator.clipboard.writeText(link);notice('Ссылка скопирована.');}catch{const input=document.createElement('textarea');input.value=link;input.setAttribute('readonly','');document.body.append(input);input.select();const copied=document.execCommand('copy');input.remove();notice(copied?'Ссылка скопирована.':'Выделите и скопируйте ссылку вручную.',!copied);}});
// Keep the tab counters live in the background; the browser may throttle timers.
function schedule(){clearTimeout(timer);timer=setTimeout(async()=>{if(!busy)await refresh();schedule();},STATS_INTERVAL_MS);}
document.addEventListener('visibilitychange',()=>{if(!document.hidden&&!busy)refresh();schedule();scheduleUpdate();});
refresh().then(schedule);

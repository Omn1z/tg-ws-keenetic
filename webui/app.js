'use strict';
const $=id=>document.getElementById(id), form=$('settings');
let csrf='',loaded=false,busy=false,timer;
const numbers=['port','max_connections','buffer_size','pool_size','connect_timeout_secs','idle_timeout_secs'];
const booleans=['cfproxy','domain_refresh','sni_fronting','force_test_dc','proxy_protocol'];
const strings=['link_host','fake_tls_domain','web_user'];
const lists=['cfproxy_user_domains','cfproxy_worker_domains'];
const field=name=>form.elements.namedItem(name);
function notice(text,error=false){$('notice').textContent=text;$('notice').classList.toggle('error',error);}
function bytes(n){let i=0;for(;n>=1024&&i<4;i++)n/=1024;return `${n.toFixed(i?1:0)} ${['Б','КиБ','МиБ','ГиБ','ТиБ'][i]}`;}
function elapsed(n){if(n<60)return `${n} с`;if(n<3600)return `${Math.floor(n/60)} мин`;if(n<86400)return `${Math.floor(n/3600)} ч`;return `${Math.floor(n/86400)} д`;}
async function request(path,body){const res=await fetch(path,{method:body===undefined?'GET':'POST',headers:body===undefined?{}:{'Content-Type':'application/json','X-CSRF-Token':csrf},body:body===undefined?undefined:JSON.stringify(body),cache:'no-store'});const text=await res.text();let data;try{data=JSON.parse(text);}catch{throw Error(text||`HTTP ${res.status}`);}if(!res.ok)throw Error(data.error||`HTTP ${res.status}`);return data;}
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
async function refresh(reset=false){
  try{const data=await request('/api/state');csrf=data.csrf;const s=data.stats;
    $('status').textContent='Работает';$('led').className='on';$('version').textContent=`v${data.version}`;
    $('link').textContent=data.link;$('open').href=data.link;$('open').setAttribute('aria-disabled','false');
    $('active').textContent=s.connections_active;$('total').textContent=`Всего ${s.connections_total}`;
    $('up').textContent=bytes(s.bytes_up);$('down').textContent=bytes(s.bytes_down);$('uptime').textContent=elapsed(Math.floor(s.uptime_secs));
    $('routes').textContent=`WS ${s.connections_ws} · CF ${s.connections_cfproxy} · TCP ${s.connections_tcp_fallback}`;
    $('upstream').textContent=`Flowseal ${data.upstream}`;
    if(!loaded||reset){populate(data.config,data.password_set);loaded=true;}
  }catch(error){$('status').textContent='Нет связи';$('led').className='off';if(!loaded)notice(error.message,true);}
}
function payload(){const cfg={};for(const n of numbers)cfg[n]=Number(field(n).value);for(const n of strings)cfg[n]=field(n).value.trim();for(const n of booleans)cfg[n]=field(n).checked;for(const n of lists)cfg[n]=field(n).value.split(/[\s,;]+/).filter(Boolean);cfg.dc_redirects={};for(const line of field('dc_redirects').value.split('\n').map(s=>s.trim()).filter(Boolean)){const match=line.match(/^(\d+)\s*:\s*(.+)$/);if(!match)throw Error(`Неверная запись DC: ${line}`);cfg.dc_redirects[match[1]]=match[2];}if($('clear-password').checked)cfg.web_password='';else if(field('web_password').value)cfg.web_password=field('web_password').value;return cfg;}
async function change(path,body){if(busy)return;busy=true;$('fields').disabled=true;$('restart').disabled=true;notice('Применение…');try{await request(path,body);await refresh(true);notice('Готово. Настройки применены.');}catch(error){notice(error.message,true);}finally{busy=false;$('fields').disabled=!loaded;$('restart').disabled=false;}}
form.addEventListener('submit',event=>{event.preventDefault();try{change('/api/config',payload());}catch(error){notice(error.message,true);}});
$('restart').addEventListener('click',()=>change('/api/restart',{}));
$('new-secret').addEventListener('click',()=>{if(confirm('Создать новый секрет? Старую ссылку потребуется заменить на всех устройствах.'))change('/api/secret',{});});
$('copy').addEventListener('click',async()=>{const link=$('link').textContent;if(!loaded)return;try{await navigator.clipboard.writeText(link);notice('Ссылка скопирована.');}catch{const input=document.createElement('textarea');input.value=link;input.setAttribute('readonly','');document.body.append(input);input.select();const copied=document.execCommand('copy');input.remove();notice(copied?'Ссылка скопирована.':'Выделите и скопируйте ссылку вручную.',!copied);}});
function schedule(){clearTimeout(timer);if(document.hidden)return;timer=setTimeout(async()=>{if(!busy)await refresh();schedule();},5000);}
document.addEventListener('visibilitychange',()=>{if(!document.hidden&&!busy)refresh();schedule();});
refresh().then(schedule);

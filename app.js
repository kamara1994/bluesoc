/* BLUE SOC standalone: authenticated telemetry and explicit demonstration mode. */
'use strict';

const $ = (id) => document.getElementById(id);
const apiPath = './api/soc';
const STEPS = [
  { icon:'⏰', name:'WORKFLOW SCHEDULE', detail:'Only when n8n schedule is enabled' },
  { icon:'📡', name:'QUERY SPLUNK', detail:'Search authorized alert indexes' },
  { icon:'{}', name:'NORMALIZE SIGNAL', detail:'Parse source IP and detection details' },
  { icon:'?', name:'VALIDATE THREAT', detail:'Check scope, allowlist and confidence' },
  { icon:'🤖', name:'AI ANALYSIS', detail:'Assessment, never automatic authority' },
  { icon:'🛡', name:'PALO ALTO RESPONSE', detail:'Policy-controlled containment only' },
  { icon:'📱', name:'NOTIFY OPERATOR', detail:'Review details and rollback ability' },
  { icon:'📊', name:'PUBLISH TELEMETRY', detail:'Update read-only dashboard view' },
];
const demoEventTime = (minutes) => new Date(Date.now() - minutes * 60000).toISOString();
const state = {
  token: '',
  connection:'demo',
  features:{scan_enabled:false,chat_enabled:false},
  mode:'dashboard',
  events:[],
  blocks:[],
  runs:0,
  lastAnalysis:null,
  scanning:false,
  requestInFlight:false,
  lastSnapshot:'',
};
let typingElement = null;

function node(tag, className, value) {
  const el = document.createElement(tag);
  if (className) el.className = className;
  if (value !== undefined && value !== null) el.textContent = String(value);
  return el;
}
function put(id, value) {
  const target = $(id);
  if (target) target.textContent = String(value);
}
function formatTime(input) {
  const date = new Date(input);
  return Number.isFinite(date.getTime()) ? date.toLocaleTimeString() : 'UNKNOWN';
}
function toSafeSeverity(raw) {
  const severity = String(raw || '').toLowerCase();
  return ['critical','high','medium','low','info'].includes(severity) ? severity : 'info';
}
function setPill(id, label, working) {
  const el = $(id);
  if (!el) return;
  el.className = working ? 'holo-pill green' : 'holo-pill';
  el.replaceChildren(node('div','pill-dot'), document.createTextNode(label));
}
function setConnection(mode, detail) {
  state.connection = mode;
  const connected = mode === 'connected';
  setPill('n8n-status', 'N8N UNVERIFIED', false);
  setPill('splunk-status', connected ? 'JSONBIN CONNECTED' : 'SPLUNK UNVERIFIED', connected);
  setPill('ai-status', connected && state.features.chat_enabled ? 'AI CHAT CONFIGURED' : 'AI UNVERIFIED', false);
  setPill('poll-badge', mode === 'demo' ? 'DEMO DATA' : connected ? 'DATA SYNC' : 'OFFLINE', connected);
  put('feed-status', mode === 'demo' ? '● EXAMPLE EVENTS' : connected ? '● READ-ONLY SYNC' : '● NOT CONNECTED');
  put('connection-note', detail ||
    (mode === 'demo' ? 'DEMO MODE · Synthetic events only. No firewall actions, live Splunk data or AI calls.' :
     connected ? 'Authenticated telemetry read. Firewall outcomes are reported by upstream data, not independently verified.' :
     'Telemetry unavailable. Use CONFIG to reconnect.'));
  $('trig-btn').disabled = !connected || !state.features.scan_enabled || state.scanning;
  $('send-btn').disabled = !connected || !state.features.chat_enabled;
  $('chat-in').disabled = !connected || !state.features.chat_enabled;
}
function clearChildren(id) {
  $(id).replaceChildren();
}
function renderSteps(done = 0, running = -1) {
  const parent = $('wf-steps');
  parent.replaceChildren();
  STEPS.forEach((step, i) => {
    const isDone = i < done, isCurrent = i === running;
    const wrapper = node('div','wf-step' + (isDone ? ' done' : isCurrent ? ' running' : ''));
    wrapper.appendChild(node('div','wf-icon' + (isDone ? ' done' : isCurrent ? ' running' : ''),step.icon));
    const details = node('div','wf-info');
    details.append(node('div','wf-name',step.name), node('div','wf-detail',step.detail));
    const status = node('div','wf-status ' + (isDone ? 'ss-done' : isCurrent ? 'ss-running' : 'ss-ready'),
      isDone ? '✓ REPORTED' : isCurrent ? '▶ REQUEST' : 'PENDING');
    wrapper.append(details,status);
    parent.appendChild(wrapper);
  });
}
function renderEvent(e) {
  const sev=toSafeSeverity(e.severity);
  const type=String(e.event_type||'event');
  const css=type.toLowerCase().includes('rigby')?'type-rigby'
      :type.toLowerCase().includes('pan')?'type-pan':'type-zeek';
  const card=node('article','event-card '+sev);
  const head=node('div','evt-top');
  head.append(node('div','evt-type '+css,type.slice(0,100)),node('div','evt-time',formatTime(e.timestamp)));
  card.append(head,node('div','evt-msg',String(e.message||'No description').slice(0,500)));
  if(e.source_ip) card.appendChild(node('div','evt-ips',
    String(e.source_ip).slice(0,64)+' → '+String(e.dest_ip||'unknown').slice(0,64)));
  return card;
}
function renderBlock(b) {
  const row=node('div','blocked-entry');
  row.append(node('div','blocked-ip',String(b.ip||'unknown').slice(0,64)),node('div','blocked-fw','REPORTED'));
  const middle=node('div','');
  middle.style.flex='1';
  middle.appendChild(node('div','blocked-reason',String(b.reason||'Upstream report').slice(0,200)));
  row.append(middle,node('div','blocked-time',b.time?formatTime(b.time):''));
  return row;
}
function renderSnapshot(data, demo) {
  state.events = Array.isArray(data.events) ? data.events.slice(-100) : [];
  state.blocks = Array.isArray(data.blocked_ips) ? data.blocked_ips.slice(-100) : [];
  state.runs = Number.isFinite(Number(data.runs)) ? Number(data.runs) : 0;
  const analysis=data.analysis||{};
  put('s-total',state.events.length);
  put('s-runs',state.runs);
  put('s-crit',state.events.filter(e=>['critical','high'].includes(toSafeSeverity(e.severity))).length);
  put('s-rigby',state.events.filter(e=>/rigby/i.test(String(e.event_type||'')+' '+String(e.message||''))).length);
  put('s-sources',new Set(state.events.map(e=>e.source_ip).filter(Boolean)).size);
  put('s-blocked',state.blocks.length);
  put('blocked-badge',state.blocks.length+(demo?' DEMO':' REPORTED'));
  put('last-run',data.last_run?formatTime(data.last_run):'NOT REPORTED');
  put('wf-status',demo?'DEMO':state.runs>0?'REPORTED':'WAITING');
  const feed=$('event-feed');
  feed.replaceChildren();
  if(state.events.length===0) feed.appendChild(node('p','empty-state','No events are reported by the connected source.'));
  else for(const event of [...state.events].reverse())feed.appendChild(renderEvent(event));
  const blocked=$('blocked-list');
  blocked.replaceChildren();
  if(state.blocks.length===0)blocked.appendChild(node('p','no-blocks','No blocks reported.'));
  else for(const item of [...state.blocks].reverse())blocked.appendChild(renderBlock(item));
  // Do not equate the AI assessment with a successful firewall policy change.
  const digest=JSON.stringify(analysis);
  if(digest && digest!==state.lastSnapshot && (analysis.activity||analysis.threat_level)){
    state.lastSnapshot=digest;
    addMsg('bot',[
      demo?'DEMO ANALYSIS (SAMPLE ONLY)':'Latest AI analysis reported by upstream',
      'Risk: '+String(analysis.threat_level||'unclassified'),
      'Source: '+String(analysis.offending_ip||'not supplied'),
      'Finding: '+String(analysis.activity||'not supplied'),
      'A firewall block requires independent policy verification.',
    ].join('\n'),'BLUE SOC ANALYSIS');
  }
  // A run count does not prove each workflow step succeeded; require separate verification.
  renderSteps();
}
function loadDemo() {
  state.token='';
  state.features={scan_enabled:false,chat_enabled:false};
  state.lastSnapshot='';
  const data={
    events:[
      {event_type:'zeek_http', severity:'info', timestamp:demoEventTime(6), message:'Example: authorized web request observed', source_ip:'198.51.100.23', dest_ip:'192.0.2.10'},
      {event_type:'rigby_url_alert', severity:'high', timestamp:demoEventTime(4), message:'Example: Rigby rule matched a lab URL', source_ip:'198.51.100.23', dest_ip:'192.0.2.10'},
      {event_type:'pan_traffic', severity:'medium', timestamp:demoEventTime(2), message:'Example: firewall policy evaluation', source_ip:'198.51.100.23', dest_ip:'192.0.2.10'},
    ],
    blocked_ips:[{ip:'198.51.100.23',reason:'DEMO ONLY: illustrative containment record',time:demoEventTime(1)}],
    runs:1,
    last_run:demoEventTime(1),
    analysis:{threat_level:'high',offending_ip:'198.51.100.23',activity:'Example only: detection triaged by workflow.'},
  };
  renderSnapshot(data,true);
  setConnection('demo');
  showToast('DEMO MODE · No live actions');
}
async function request(path, options) {
  const response=await fetch(path,{
    ...options,
    headers:{Authorization:'Bearer '+state.token, ...(options?.headers||{})},
    cache:'no-store',
    signal:AbortSignal.timeout(10000),
  });
  let json;
  try{json=await response.json();}catch{json={};}
  if(!response.ok){
    const error=new Error(String(json.error||'API HTTP '+response.status));
    error.status=response.status;
    throw error;
  }
  return json;
}
async function poll() {
  if(!state.token||state.requestInFlight)return;
  state.requestInFlight=true;
  try{
    const result=await request(apiPath,{method:'GET'});
    if(!result.ok||!result.data)throw new Error('No telemetry returned');
    state.features={scan_enabled:result.features?.scan_enabled===true,chat_enabled:result.features?.chat_enabled===true};
    renderSnapshot(result.data,false);
    setConnection('connected','Private telemetry retrieved at '+formatTime(result.data.fetched_at)+'. Firewall blocks are reported, not independently verified.');
  }catch(error){
    if(error.status===401)state.token='';
    state.features={scan_enabled:false,chat_enabled:false};
    setConnection('offline','Unable to retrieve telemetry: '+error.message+'. Check the admin token and server environment.');
  }finally{state.requestInFlight=false;}
}
async function triggerScan() {
  if(!state.token){openConfig();return;}
  if(!state.features.scan_enabled){showToast('Scan workflow is not enabled on the server',true);return;}
  if(state.scanning)return;
  if(!window.confirm('Trigger the authorized n8n workflow? It may request real firewall containment if enabled in your lab.'))return;
  state.scanning=true;
  $('trig-btn').disabled=true;
  $('trig-btn').textContent='⏳ REQUESTING...';
  put('wf-status','REQUESTING');
  try{
    const result=await request(apiPath,{
      method:'POST',headers:{'Content-Type':'application/json'},
      body:JSON.stringify({action:'scan'}),
    });
    if(result.ok){
      put('wf-status','ACCEPTED');
      showToast('Workflow requested. Check telemetry to verify its result.');
      // An HTTP acknowledgement does not prove that a firewall rule was changed.
    }
  }catch(e){
    put('wf-status','ERROR');
    showToast('Workflow unavailable: '+e.message,true);
  }finally{
    state.scanning=false;
    $('trig-btn').textContent='▶ REQUEST N8N WORKFLOW';
    $('trig-btn').disabled=state.connection!=='connected' || !state.features.scan_enabled;
  }
}
function addMsg(role,text,meta='BLUE SOC'){
  const box=$('chat-box'), bubble=node('div','msg-bub',text);
  const message=node('div','chat-msg '+(role==='user'?'user':'bot'));
  message.append(bubble,node('div','msg-meta',meta+' · '+new Date().toLocaleTimeString()));
  box.appendChild(message);
  if(box.childElementCount>65)box.firstElementChild?.remove();
  box.scrollTop=box.scrollHeight;
}
function showTyping(){
  hideTyping();
  typingElement=node('div','chat-msg bot');
  const dots=node('div','typing-ind');
  for(let i=0;i<3;i++)dots.appendChild(node('div','t-dot'));
  typingElement.appendChild(dots);
  $('chat-box').appendChild(typingElement);
}
function hideTyping(){typingElement?.remove();typingElement=null;}
function setTab(mode,btn){
  state.mode=mode==='telegram'?'telegram':'dashboard';
  document.querySelectorAll('.chat-tab').forEach(t=>t.classList.remove('active'));
  btn.classList.add('active');
  $('chat-in').placeholder=state.mode==='telegram'?'Message routed to the configured Telegram workflow':'Ask the authorized AI analyst...';
}
async function sendChat(){
  const input=$('chat-in');
  const message=input.value.trim().slice(0,2000);
  if(!message)return;
  if(!state.token){openConfig();return;}
  if(!state.features.chat_enabled){showToast('AI workflow is not configured on the server',true);return;}
  input.value='';
  $('send-btn').disabled=true;
  addMsg('user',message,'YOU');
  showTyping();
  try{
    const result=await request(apiPath,{
      method:'POST',headers:{'Content-Type':'application/json'},
      body:JSON.stringify({action:'chat',message,mode:state.mode}),
    });
    hideTyping();
    addMsg('bot',String(result.reply||'No answer received.'),'BLUE SOC AI');
  }catch(e){
    hideTyping();
    addMsg('bot','Chat unavailable: '+e.message,'SYSTEM STATUS');
  }finally{
    $('send-btn').disabled=state.connection!=='connected' || !state.features.chat_enabled;
    input.focus();
  }
}
function clearFeed(){
  state.events=[];
  $('event-feed').replaceChildren(node('p','empty-state','View cleared locally. Upstream records are unchanged; refresh to reload.'));
  showToast('Local view cleared; server records remain intact');
}
function openConfig(){
  $('cfg-key').value='';
  $('cfg-modal').classList.remove('hidden');
  $('cfg-key').focus();
}
function closeConfig(){$('cfg-modal').classList.add('hidden');}
async function saveConfig(){
  const token=$('cfg-key').value.trim();
  if(token.length<24){showToast('Enter your private dashboard token (24+ characters)',true);return;}
  state.token=token;
  $('cfg-key').value='';
  closeConfig();
  setConnection('offline','Connecting securely to the BLUE SOC backend...');
  await poll();
  if(state.connection==='connected')showToast('Authenticated telemetry connected');
}
function showToast(message,isError=false){
  document.querySelector('.toast')?.remove();
  const toast=node('div','toast'+(isError?' error':''),message);
  toast.setAttribute('role','status');
  document.body.appendChild(toast);
  window.setTimeout(()=>toast.remove(),4800);
}
function tick(){put('clock',new Date().toISOString().replace('T',' ').slice(0,19)+' UTC');}
function startParticles(){
  const canvas=$('particle-canvas');
  const ctx=canvas?.getContext('2d');
  if(!ctx)return;
  let width=0,height=0,raf=0;
  const pts=Array.from({length:55},()=>({
    x:Math.random()*window.innerWidth,y:Math.random()*window.innerHeight,
    vx:(Math.random()-.5)*.35,vy:(Math.random()-.5)*.35,
    r:Math.random()*1.2+.3,alpha:Math.random()*.5+.1,
  }));
  function resize(){width=canvas.width=window.innerWidth;height=canvas.height=window.innerHeight;}
  function animate(){
    ctx.clearRect(0,0,width,height);
    for(const p of pts){
      p.x+=p.vx;p.y+=p.vy;
      if(p.x<0||p.x>width)p.vx*=-1;
      if(p.y<0||p.y>height)p.vy*=-1;
      ctx.beginPath();ctx.arc(p.x,p.y,p.r,0,Math.PI*2);
      ctx.fillStyle='rgba(0,180,255,'+p.alpha+')';ctx.fill();
    }
    raf=window.requestAnimationFrame(animate);
  }
  window.addEventListener('resize',resize);
  resize();
  if(window.matchMedia('(prefers-reduced-motion: reduce)').matches)return;
  animate();
  document.addEventListener('visibilitychange',()=>{
    if(document.hidden)window.cancelAnimationFrame(raf);
    else animate();
  });
}
window.triggerScan=triggerScan;
window.sendChat=sendChat;
window.clearFeed=clearFeed;
window.setTab=setTab;
window.openConfig=openConfig;
window.closeConfig=closeConfig;
window.saveConfig=saveConfig;
window.loadDemo=loadDemo;
window.poll=poll;

tick();
setInterval(tick,1000);
renderSteps();
clearChildren('chat-box');
addMsg('bot','BLUE SOC is in DEMO MODE. Sign in with your private dashboard token to view real telemetry or use authorized workflows. Live status is never assumed.','SYSTEM');
loadDemo();
startParticles();
setInterval(()=>{if(state.token)poll();},15000);

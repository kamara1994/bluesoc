import { test } from 'node:test';
import assert from 'node:assert/strict';
import handler from '../api/soc.js';

const originalEnv = {
  BLUE_SOC_ADMIN_TOKEN:process.env.BLUE_SOC_ADMIN_TOKEN,
  BLUE_SOC_JSONBIN_ID:process.env.BLUE_SOC_JSONBIN_ID,
  BLUE_SOC_JSONBIN_READ_KEY:process.env.BLUE_SOC_JSONBIN_READ_KEY,
  BLUE_SOC_ALLOW_SCAN:process.env.BLUE_SOC_ALLOW_SCAN,
  BLUE_SOC_SCAN_WEBHOOK:process.env.BLUE_SOC_SCAN_WEBHOOK,
  BLUE_SOC_CHAT_WEBHOOK:process.env.BLUE_SOC_CHAT_WEBHOOK,
};
const token = 'test-token-with-at-least-thirty-two-chars';
function setup() {
  process.env.BLUE_SOC_ADMIN_TOKEN = token;
  process.env.BLUE_SOC_JSONBIN_ID = 'abcdef1234567890abcdef12';
  process.env.BLUE_SOC_JSONBIN_READ_KEY = 'dummy-read-key';
  process.env.BLUE_SOC_ALLOW_SCAN = 'false';
}
function createRes() {
  return {
    statusCode:200,
    headers:{},
    setHeader(k,v){this.headers[k]=v;return this;},
    status(code){this.statusCode=code;return this;},
    json(data){this.body=data;return this;},
  };
}
async function call(method='GET', {auth=true,body,origin}={}) {
  const headers={host:'localhost:3000'};
  if(auth)headers.authorization='Bearer '+token;
  if(origin)headers.origin=origin;
  const res=createRes();
  await handler({method,headers,body},res);
  return res;
}
test('unauthenticated and bogus tokens cannot access telemetry', async () => {
  setup();
  const missing = await call('GET',{auth:false});
  assert.equal(missing.statusCode,401);
  assert.equal(missing.body.ok,false);
});
test('authorized GET returns a bounded, normalized record without raw HTML execution', async () => {
  setup();
  const previous=globalThis.fetch;
  try{
    globalThis.fetch=async()=>({
      ok:true,
      json:async()=>({record:{
        events:[{event_type:'<img src=x onerror=alert(1)>',severity:'HIGH',source_ip:'198.51.100.25',message:'<script>alert(1)</script>'}],
        blocked_ips:['198.51.100.25'],
        runs:3,
        last_run:'2026-11-06T19:00:00Z',
        analysis:{threat_level:'medium',activity:'Observed lab test'},
        debug_secret:'not-for-client',
      }}),
    });
    const response=await call('GET');
    assert.equal(response.statusCode,200);
    assert.equal(response.body.data.events[0].severity,'high');
    assert.equal(response.body.data.runs,3);
    assert.equal('debug_secret' in response.body.data,false);
    assert.ok(response.body.data.events[0].message.includes('<script>')); // frontend must display with textContent
    assert.equal(response.headers['Cache-Control'].includes('no-store'),true);
  }finally{globalThis.fetch=previous;}
});
test('scan requests stay disabled without explicit server approval', async () => {
  setup();
  process.env.BLUE_SOC_SCAN_WEBHOOK='https://example.com/webhook/scan';
  const response=await call('POST',{body:{action:'scan'}});
  assert.equal(response.statusCode,403);
});
test('cross-origin POSTs are refused', async()=>{
  setup();
  const response=await call('POST',{body:{action:'chat',message:'hello'},origin:'https://evil.example'});
  assert.equal(response.statusCode,403);
});
test('bad messages and wrong actions are rejected', async () => {
  setup();
  assert.equal((await call('POST',{body:{action:'chat',message:''}})).statusCode,400);
  assert.equal((await call('POST',{body:{action:'chat',message:'a'.repeat(2001)}})).statusCode,400);
  assert.equal((await call('POST',{body:{action:'unknown'}})).statusCode,400);
});
process.on('exit',()=>{for(const [key,value] of Object.entries(originalEnv))if(value===undefined)delete process.env[key];else process.env[key]=value;});

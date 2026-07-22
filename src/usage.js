// ENGR HUB worker — usage.js
// (worker.js에서 이동. 로직 변경 없음)

import { kstParts } from './jira.js';

export function usageKeys(now=new Date()){
  const p=kstParts(now);
  return { day:`${p.year}-${p.month}-${p.day}`, month:`${p.year}-${p.month}` };
}

export function createUsageBucket(){ return { today:0, month:0, successToday:0, successMonth:0, failToday:0, failMonth:0 }; }

export function createUsageStore(){ return { team:createUsageBucket(), users:{} }; }

export function ensureUserUsage(store,user){
  if(!user)return createUsageBucket();
  if(!store.users)store.users={};
  if(!store.users[user])store.users[user]=createUsageBucket();
  return store.users[user];
}

export function bumpUsageBucket(b,type,scope){
  if(type==='AI_REQUEST') b[scope==='day'?'today':'month']=(b[scope==='day'?'today':'month']||0)+1;
  if(type==='AI_SUCCESS') b[scope==='day'?'successToday':'successMonth']=(b[scope==='day'?'successToday':'successMonth']||0)+1;
  if(type==='AI_FAIL') b[scope==='day'?'failToday':'failMonth']=(b[scope==='day'?'failToday':'failMonth']||0)+1;
}

export async function updateAIUsage(env,user,outcome,model){
  if(!['success','fail','cached'].includes(outcome))return;
  try{
    const keys=usageKeys();
    const kvKey=`usage:v2:${keys.month}`;
    let store={days:{},team:createUsageBucket(),users:{}};
    try{const raw=await env.ENGR_KV.get(kvKey);if(raw)store=JSON.parse(raw);}catch(_){ }
    if(!store.days)store.days={};
    if(!store.days[keys.day])store.days[keys.day]={team:createUsageBucket(),users:{}};
    if(!store.team)store.team=createUsageBucket();
    if(!store.users)store.users={};
    const dayStore=store.days[keys.day];
    if(!dayStore.team)dayStore.team=createUsageBucket();
    if(!dayStore.users)dayStore.users={};
    const type=outcome==='fail'?'AI_FAIL':'AI_SUCCESS';
    bumpUsageBucket(dayStore.team,'AI_REQUEST','day');
    bumpUsageBucket(store.team,'AI_REQUEST','month');
    bumpUsageBucket(dayStore.team,type,'day');
    bumpUsageBucket(store.team,type,'month');
    // 모델(제공자)별 호출 카운트 — 실제 호출(성공/캐시)만
    if(outcome!=='fail'){
      const provider=String(model||'').includes('gemini')?'gemini':'llama';
      if(!dayStore.team.models)dayStore.team.models={};
      if(!store.team.models)store.team.models={};
      dayStore.team.models[provider]=(dayStore.team.models[provider]||0)+1;
      store.team.models[provider]=(store.team.models[provider]||0)+1;
    }
    if(user){
      bumpUsageBucket(ensureUserUsage(dayStore,user),'AI_REQUEST','day');
      bumpUsageBucket(ensureUserUsage(store,user),'AI_REQUEST','month');
      bumpUsageBucket(ensureUserUsage(dayStore,user),type,'day');
      bumpUsageBucket(ensureUserUsage(store,user),type,'month');
    }
    store.updatedAt=new Date().toISOString();
    await env.ENGR_KV.put(kvKey,JSON.stringify(store),{expirationTtl:60*60*24*400});
  }catch(_){ }
}

export async function readUsageCounter(env,user=''){
  const keys=usageKeys();
  try{
    const raw=await env.ENGR_KV.get(`usage:v2:${keys.month}`);
    if(raw){
      const store=JSON.parse(raw);
      const day=store.days?.[keys.day]||{};
      const u=(user||'').trim();
      const team={
        today:day.team?.today||0,
        month:store.team?.month||0,
        successToday:day.team?.successToday||0,
        successMonth:store.team?.successMonth||0,
        failToday:day.team?.failToday||0,
        failMonth:store.team?.failMonth||0,
        modelsToday:day.team?.models||{},
        modelsMonth:store.team?.models||{},
      };
      const du=u?(day.users?.[u]||{}):{};
      const mu=u?(store.users?.[u]||{}):{};
      const me={
        today:du.today||0,
        month:mu.month||0,
        successToday:du.successToday||0,
        successMonth:mu.successMonth||0,
        failToday:du.failToday||0,
        failMonth:mu.failMonth||0,
      };
      return {ok:true,timezone:'Asia/Seoul',asOf:new Date().toISOString(),source:'counter_v2',note: 'AI usage counter data.',me,team};
    }
  }catch(_){ }
  let daily=null, monthly=null;
  try{const raw=await env.ENGR_KV.get(`usage:daily:${keys.day}`);if(raw)daily=JSON.parse(raw);}catch(_){ }
  try{const raw=await env.ENGR_KV.get(`usage:monthly:${keys.month}`);if(raw)monthly=JSON.parse(raw);}catch(_){ }
  if(!daily&&!monthly)return null;
  const u=(user||'').trim();
  const team={
    today:daily?.team?.today||0,
    month:monthly?.team?.month||0,
    successToday:daily?.team?.successToday||0,
    successMonth:monthly?.team?.successMonth||0,
    failToday:daily?.team?.failToday||0,
    failMonth:monthly?.team?.failMonth||0,
  };
  const du=u?(daily?.users?.[u]||{}):{};
  const mu=u?(monthly?.users?.[u]||{}):{};
  const me={
    today:du.today||0,
    month:mu.month||0,
    successToday:du.successToday||0,
    successMonth:mu.successMonth||0,
    failToday:du.failToday||0,
    failMonth:mu.failMonth||0,
  };
  return {ok:true,timezone:'Asia/Seoul',asOf:new Date().toISOString(),source:'counter',note: 'AI usage counter data.',me,team};
}

export function emptyUsageStats(){
  return { today:0, month:0, successToday:0, successMonth:0, failToday:0, failMonth:0 };
}

export function addUsage(stats, field, isToday, isMonth){
  if (isToday) stats[field+'Today'] = (stats[field+'Today'] || 0) + 1;
  if (isMonth) stats[field+'Month'] = (stats[field+'Month'] || 0) + 1;
}

export async function getUsage(env, user='') {
  const cached = await readUsageCounter(env, user);
  if (cached) return cached;
  return {
    ok: true,
    timezone: 'Asia/Seoul',
    asOf: new Date().toISOString(),
    source: 'counter_empty',
    note: 'AI usage counter data.',
    me: emptyUsageStats(),
    team: emptyUsageStats(),
  };
}

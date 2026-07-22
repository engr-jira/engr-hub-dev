// ENGR HUB worker — push.js
// (worker.js에서 이동. 로직 변경 없음)

import { getUsers, normalizeUserId } from './auth.js';

export const PUSH_EVENTS = {
  link:      { label: '업무 링크 등록',    defTitle: '🔗 새 업무 링크',     defBody: "{user}님이 '{target}' 등록", page: 'links' },
  knowledge: { label: '팀 노하우 등록',    defTitle: '📚 새 팀 노하우',     defBody: "{user}님이 '{target}' 등록", page: 'knowledge' },
  eos:       { label: '라이선스 등록', defTitle: '⏳ 라이선스 등록', defBody: "{user}님이 '{target}' 등록", page: 'eos' },
};

export function u8ToB64url(u){ let s=''; for(let i=0;i<u.length;i++)s+=String.fromCharCode(u[i]); return btoa(s).replace(/\+/g,'-').replace(/\//g,'_').replace(/=+$/,''); }

export async function vapidAuthHeader(env, audience){
  const jwkRaw = env.VAPID_PRIVATE_JWK, pub = env.VAPID_PUBLIC_KEY, sub = env.VAPID_SUBJECT || 'mailto:admin@example.com';
  if(!jwkRaw || !pub) throw new Error('VAPID not configured');
  const jwk = typeof jwkRaw === 'string' ? JSON.parse(jwkRaw) : jwkRaw;
  const key = await crypto.subtle.importKey('jwk', { kty:'EC', crv:'P-256', d:jwk.d, x:jwk.x, y:jwk.y, ext:true }, { name:'ECDSA', namedCurve:'P-256' }, false, ['sign']);
  const enc = new TextEncoder();
  const header = u8ToB64url(enc.encode(JSON.stringify({ typ:'JWT', alg:'ES256' })));
  const payload = u8ToB64url(enc.encode(JSON.stringify({ aud:audience, exp:Math.floor(Date.now()/1000)+12*3600, sub })));
  const signingInput = `${header}.${payload}`;
  const sig = await crypto.subtle.sign({ name:'ECDSA', hash:'SHA-256' }, key, enc.encode(signingInput));
  return { Authorization:`vapid t=${signingInput}.${u8ToB64url(new Uint8Array(sig))}, k=${pub}` };
}

export async function sendWebPush(env, sub, ttl=86400){
  const u = new URL(sub.endpoint);
  const auth = await vapidAuthHeader(env, `${u.protocol}//${u.host}`);
  const res = await fetch(sub.endpoint, { method:'POST', headers:{ ...auth, TTL:String(ttl) } });
  return res.status; // 201=ok, 404/410=만료(구독 제거)
}

export async function getPushSubs(env){ try{ const r=await env.ENGR_KV.get('push:subs'); return r?JSON.parse(r):{}; }catch(_){ return {}; } }

export async function savePushSubs(env, s){ await env.ENGR_KV.put('push:subs', JSON.stringify(s)); }

export async function getPushSettings(env){
  let s={}; try{ const r=await env.ENGR_KV.get('push:settings'); if(r)s=JSON.parse(r); }catch(_){}
  const events={};
  for(const [k,def] of Object.entries(PUSH_EVENTS)){
    const e=(s.events&&s.events[k])||{};
    let title=(e.title||def.defTitle), body=(e.body||def.defBody);
    // 옛 'EOS/라이선스' 문구 자가 치환(저장된 멘트 마이그레이션)
    title=title.replace(/EOS\s*\/\s*라이선스/g,'라이선스'); body=body.replace(/EOS\s*\/\s*라이선스/g,'라이선스');
    events[k]={ enabled:e.enabled!==false, title, body, label:def.label };
  }
  return { events, include:Array.isArray(s.include)?s.include:[], exclude:Array.isArray(s.exclude)?s.exclude:[] };
}

export function fillTemplate(tpl, vars){ return String(tpl||'').replace(/\{(\w+)\}/g,(m,k)=> vars[k]!==undefined?vars[k]:m); }

export async function endpointHash(endpoint){ const b=await crypto.subtle.digest('SHA-256', new TextEncoder().encode(endpoint)); return u8ToB64url(new Uint8Array(b)).slice(0,40); }

export async function enqueuePending(env, endpoint, payload){
  const pk='push:pending:'+await endpointHash(endpoint);
  let pend=[]; try{ const r=await env.ENGR_KV.get(pk); if(r)pend=JSON.parse(r); }catch(_){}
  pend.push(payload); if(pend.length>30)pend=pend.slice(-30);
  await env.ENGR_KV.put(pk, JSON.stringify(pend), { expirationTtl:60*60*24*7 });
}

export async function pushNotify(env, eventKey, actorId, vars){
  try{
    const def=PUSH_EVENTS[eventKey]; if(!def)return;
    const settings=await getPushSettings(env);
    const ev=settings.events[eventKey];
    if(!ev || !ev.enabled) return;
    const subs=await getPushSubs(env);
    const actorNorm=normalizeUserId(actorId||'');
    const include=settings.include.map(normalizeUserId).filter(Boolean);
    const exclude=settings.exclude.map(normalizeUserId).filter(Boolean);
    let recipients=Object.keys(subs);
    if(include.length) recipients=recipients.filter(u=>include.includes(u));
    recipients=recipients.filter(u=> !exclude.includes(u) && u!==actorNorm);
    if(!recipients.length) return;
    let users={}; try{ users=await getUsers(env); }catch(_){}
    const actorName=(users[actorNorm]&&users[actorNorm].displayName)||actorId||'팀원';
    const fullVars={ user:actorName, event:def.label, ...vars };
    const payload={ title:fillTemplate(ev.title,fullVars), body:fillTemplate(ev.body,fullVars), page:def.page, ts:Date.now(), tag:eventKey };
    let changed=false;
    for(const uid of recipients){
      let pref={}; try{ const pr=await env.ENGR_KV.get('push:pref:'+uid); if(pr)pref=JSON.parse(pr); }catch(_){}
      if(pref.enabled===false) continue;
      const list=subs[uid]||[];
      for(const s of list){
        try{ await enqueuePending(env, s.endpoint, payload); }catch(_){}
        try{ const st=await sendWebPush(env, s); if(st===404||st===410){ subs[uid]=(subs[uid]||[]).filter(x=>x.endpoint!==s.endpoint); changed=true; } }catch(_){}
      }
      if(subs[uid] && !subs[uid].length){ delete subs[uid]; changed=true; }
    }
    if(changed) await savePushSubs(env, subs);
  }catch(_){}
}

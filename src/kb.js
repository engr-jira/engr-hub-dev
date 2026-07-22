// ENGR HUB worker — kb.js
// (worker.js에서 이동. 로직 변경 없음)

import { auditLog } from './audit.js';

export const KB_PRODUCT_SEED = [
  { product:'DLP', q:'Symantec Data Loss Prevention DLP', topics:['install upgrade','agent endpoint','policy detection','incident response','enforce server','database oracle','email prevent','network prevent','discover scan','troubleshooting logs'] },
  { product:'SEP', q:'Symantec Endpoint Protection SEP SEPM 14.3', topics:['install upgrade','client communication','definitions LiveUpdate','policy configuration','content update','database embedded','replication','EDR ATP integration','uninstall cleanwipe','troubleshooting logs'] },
  { product:'CASB', q:'CloudSOC CASB Gatelet Securlet', topics:['gatelet','securlet','SAML SSO','user sync','policy incident','data exposure','API connection','office 365','salesforce','troubleshooting'] },
  { product:'SWG', q:'Cloud SWG Secure Web Gateway', topics:['policy','access method','authentication','SAML','PAC file','traffic forwarding','SSL interception','reporting','agent','troubleshooting'] },
  { product:'WSS', q:'Web Security Service WSS Cloud SWG', topics:['WSS Agent','explicit proxy','IPSec','auth connector','portal policy','SSL inspection','bypass','roaming users','reporting','troubleshooting'] },
  { product:'LUA', q:'Symantec LiveUpdate Administrator LUA', topics:['install upgrade','download schedule','distribution center','SEP content','proxy setting','certificate','database','cleanup','performance','troubleshooting logs'] },
  { product:'ProxySG', q:'ProxySG SGOS Advanced Secure Gateway', topics:['SGOS upgrade','policy CPL','SSL proxy','authentication realm','ICAP','content filtering','access log','proxy forwarding','certificate','troubleshooting'] },
];

export function kbSeedItems(){
  return KB_PRODUCT_SEED.flatMap(seed=>seed.topics.map(topic=>({
    title:`KB recent 5 years - ${seed.product} - ${topic}`,
    category:'Broadcom KB',
    product:seed.product,
    q:`${seed.q} ${topic}`,
  })));
}

export function htmlDecode(s=''){
  return String(s)
    .replace(/&amp;/g,'&').replace(/&quot;/g,'"').replace(/&#39;|&apos;/g,"'")
    .replace(/&lt;/g,'<').replace(/&gt;/g,'>').replace(/\s+/g,' ').trim();
}

export function stripTags(s=''){return htmlDecode(String(s).replace(/<[^>]+>/g,' '));}

export function kbArticleTitleFromSlug(slug=''){
  return slug.replace(/-/g,' ').replace(/\s+/g,' ').trim().replace(/\b\w/g,m=>m.toUpperCase());
}

export function kbCursorEncode(cursor){
  try{return btoa(JSON.stringify(cursor)).replace(/\+/g,'-').replace(/\//g,'_').replace(/=+$/,'');}catch(_){return '';}
}

export function kbCursorDecode(raw){
  if(!raw)return { task:0, page:0 };
  try{
    const padded = String(raw).replace(/-/g,'+').replace(/_/g,'/');
    return { task:0, page:0, ...JSON.parse(atob(padded + '==='.slice((padded.length + 3) % 4))) };
  }catch(_){return { task:0, page:0 };}
}

export function normalizeKbArticleUrl(raw=''){
  try{
    const u = new URL(String(raw).trim());
    if(u.hostname !== 'knowledge.broadcom.com')return null;
    const m = u.pathname.match(/^\/external\/article\/(\d+)(?:\/([^/?#]+))?/i);
    if(!m)return null;
    const slug = (m[2] || '').replace(/\.html$/i,'');
    const path = slug ? `/external/article/${m[1]}/${slug}` : `/external/article/${m[1]}`;
    return { articleId:m[1], slug, url:`https://knowledge.broadcom.com${path}` };
  }catch(_){return null;}
}

export function extractKbDate(html=''){
  const text = stripTags(html).slice(0, 12000);
  const metaPatterns = [
    /(?:dateModified|article:modified_time|modified_time|lastmod)["'][^>]+content=["']([^"']+)["']/i,
    /(?:datePublished|article:published_time|published_time)["'][^>]+content=["']([^"']+)["']/i,
    /(?:Updated|Last Updated|Modified|Published)\s*:?\s*([A-Z][a-z]+ \d{1,2}, \d{4}|\d{4}-\d{2}-\d{2}|\d{1,2}\/\d{1,2}\/\d{4})/i
  ];
  for(const re of metaPatterns){
    const m = html.match(re) || text.match(re);
    if(m){
      const d = new Date(m[1]);
      if(!Number.isNaN(d.getTime()))return d.toISOString();
    }
  }
  return null;
}

export function extractKbTitle(html='', fallback=''){
  const candidates = [
    html.match(/<meta[^>]+property=["']og:title["'][^>]+content=["']([^"']+)["']/i)?.[1],
    html.match(/<title[^>]*>([\s\S]*?)<\/title>/i)?.[1],
    html.match(/<h1[^>]*>([\s\S]*?)<\/h1>/i)?.[1],
    fallback
  ];
  return stripTags(candidates.find(Boolean) || '').replace(/\s*\|\s*Broadcom\s*$/i,'') || fallback;
}

export function kbSearchTasks(){
  return kbSeedItems().map(seed=>({
    product: seed.product,
    q: `site:knowledge.broadcom.com/external/article ${seed.q}`,
    queryLabel: seed.q
  }));
}

export const KB_VERIFIED_SEED = [
  { product:'SEP', title:'Versions, system requirements, release dates - SEP/SES 14.3.x', url:'https://knowledge.broadcom.com/external/article/154575' },
  { product:'SEP', title:'Versions, system requirements, release dates - SEP/SES 16.x', url:'https://knowledge.broadcom.com/external/article/397614' },
  { product:'SEP', title:'New fixes and component versions in SEP 14.3 RU10', url:'https://knowledge.broadcom.com/external/article/386578' },
  { product:'SEP', title:'New fixes and component versions in SEP 14.4', url:'https://knowledge.broadcom.com/external/article/430629' },
  { product:'SEP', title:"What's new for all releases of Symantec Endpoint Protection 14.x", url:'https://knowledge.broadcom.com/external/article/185214' },
  { product:'SEP', title:'Windows compatibility with Symantec Endpoint Protection clients', url:'https://knowledge.broadcom.com/external/article/163625' },
  { product:'SEP', title:'Product guides for Symantec Endpoint Protection', url:'https://knowledge.broadcom.com/external/article/185213' },
  { product:'SEP', title:'Download the latest version of Endpoint Protection', url:'https://knowledge.broadcom.com/external/article/157395' },
  { product:'SEP', title:'SEP CVE/security advisory portal', url:'https://knowledge.broadcom.com/external/article/225891' },
  { product:'DLP', title:'DLP Endpoint Agent build numbers and latest hotfix information', url:'https://knowledge.broadcom.com/external/article/185118' },
  { product:'DLP', title:'Symantec Data Loss Prevention - Release types', url:'https://knowledge.broadcom.com/external/article/164993' },
  { product:'DLP', title:'DLP Quick Upgrade Guides', url:'https://knowledge.broadcom.com/external/article/270589' },
  { product:'DLP', title:'High Level Steps for Upgrading DLP', url:'https://knowledge.broadcom.com/external/article/247415' },
  { product:'DLP', title:'DLP Release Cadence', url:'https://knowledge.broadcom.com/external/article/211665' },
  { product:'DLP', title:'Recent DLP Product Advisories', url:'https://knowledge.broadcom.com/external/article/269358' },
  { product:'DLP', title:'DLP CVE-2025-22228 impact', url:'https://knowledge.broadcom.com/external/article/430578' },
  { product:'DLP', title:'DLP CVE-2025-41249 impact', url:'https://knowledge.broadcom.com/external/article/417005' },
  { product:'DLP', title:'DLP CVE-2025-21587 impact', url:'https://knowledge.broadcom.com/external/article/404445' },
  { product:'DLP', title:'DLP CVE-2025-22233 impact', url:'https://knowledge.broadcom.com/external/article/404795' },
  { product:'DLP', title:'DLP CVE-2025-48976 impact', url:'https://knowledge.broadcom.com/external/article/417030' },
  { product:'ProxySG', title:'End of life and lifecycle for Edge SWG/ProxySG/ASG', url:'https://knowledge.broadcom.com/external/article/151102' },
  { product:'ProxySG', title:'Edge SWG ProxySG - Network Web Prevent DLP integration', url:'https://knowledge.broadcom.com/external/article/230914' },
  { product:'ProxySG', title:'Secure ICAP between DLP detection server and ProxySG', url:'https://knowledge.broadcom.com/external/article/383826' },
  { product:'ProxySG', title:'ISG/MC/SGOS/Reporter CVE-2025-32728 impact', url:'https://knowledge.broadcom.com/external/article/400771' },
  { product:'Support', title:'Advanced search options on the Broadcom Support Portal', url:'https://knowledge.broadcom.com/external/article/200997' },
  { product:'Support', title:'Search personalization features on the Broadcom Support Portal', url:'https://knowledge.broadcom.com/external/article/201253' },
  { product:'Support', title:'Subscribe to a Broadcom knowledge article by article or product', url:'https://knowledge.broadcom.com/external/article/275360' },
  { product:'Support', title:'Accessing Broadcom knowledge base articles from a case', url:'https://knowledge.broadcom.com/external/article/252162' },
];

export function collectKbUrlsFromText(value, source='text'){
  const text = typeof value === 'string' ? value : JSON.stringify(value || '');
  const out = [];
  const full = /https?:\/\/knowledge\.broadcom\.com\/external\/article\/\d+(?:\/[A-Za-z0-9-]+)?/gi;
  const query = /https?:\/\/knowledge\.broadcom\.com\/external\/article\?articleId=(\d+)/gi;
  let m;
  while((m=full.exec(text)))out.push({ url:m[0], source });
  while((m=query.exec(text)))out.push({ url:`https://knowledge.broadcom.com/external/article/${m[1]}`, source });
  return out;
}

export async function discoverKbFromJira(env, limit=80){
  if(!env.JIRA_TOKEN)return [];
  const jiraAuth = 'Basic ' + btoa('mj.park@escare.co.kr:' + env.JIRA_TOKEN);
  const body = {
    jql:'project=ENGR AND text ~ "knowledge.broadcom.com/external/article" ORDER BY updated DESC',
    maxResults:Math.max(1, Math.min(100, limit)),
    fieldsByKeys:false,
    fields:['summary','description','comment','labels','updated']
  };
  try{
    const res = await fetch('https://escare-engr.atlassian.net/rest/api/3/search/jql', {
      method:'POST',
      headers:{ 'Authorization':jiraAuth, 'Content-Type':'application/json', 'Accept':'application/json' },
      body:JSON.stringify(body)
    });
    if(!res.ok)return [];
    const data = await res.json();
    return (data.issues || []).flatMap(issue=>collectKbUrlsFromText(issue, `jira:${issue.key || ''}`));
  }catch(_){ return []; }
}

export async function importFreeKbLinks(env, user, years=5, opts={}){
  const raw = await env.ENGR_KV.get('config:links') || await env.ENGR_KV.get('links');
  const links = raw ? JSON.parse(raw) : [];
  const cutoff = new Date(); cutoff.setUTCFullYear(cutoff.getUTCFullYear() - years);
  const limit = Math.max(1, Math.min(120, parseInt(opts.limit || '80', 10) || 80));
  const candidates = [
    ...KB_VERIFIED_SEED.map(x=>({ ...x, source:'curated_seed' })),
    ...links.flatMap(l=>collectKbUrlsFromText(l, 'existing_links')),
    ...(await discoverKbFromJira(env, limit))
  ];
  const existingArticleIds = new Set(links.map(l=>String(l.articleId || normalizeKbArticleUrl(l.url)?.articleId || '')).filter(Boolean));
  const existingUrls = new Set(links.map(l=>String(l.url || '').replace(/[?#].*$/,'')));
  const seen = new Set();
  let imported = 0, duplicated = 0, inaccessible = 0, scanned = 0, discovered = 0;
  for(const candidate of candidates){
    if(scanned >= limit)break;
    const normalized = normalizeKbArticleUrl(candidate.url);
    if(!normalized){ inaccessible++; continue; }
    if(seen.has(normalized.articleId)){ duplicated++; continue; }
    seen.add(normalized.articleId);
    scanned++; discovered++;
    if(existingArticleIds.has(normalized.articleId) || existingUrls.has(normalized.url)){ duplicated++; continue; }
    const article = await verifyKbArticle({ ...candidate, url:normalized.url, product:candidate.product || 'Broadcom', title:candidate.title || '' }, cutoff);
    if(!article.ok){ inaccessible++; continue; }
    const now = new Date().toISOString();
    links.unshift({
      id: crypto.randomUUID(),
      category:'Broadcom KB',
      product:article.product,
      articleId:article.articleId,
      source:'broadcom-kb-free-import',
      title:`[${article.product}] ${article.title}`,
      url:article.url,
      desc:`Free verified import from ${candidate.source || 'known source'}. ${article.dateUnknown ? 'Document date unknown' : 'Document date ' + article.updatedAt.slice(0,10)}. Verified ${now.slice(0,10)}`,
      updatedAt:article.updatedAt || null,
      dateUnknown:article.dateUnknown,
      verifiedAt:now,
      createdBy:user || 'system',
      createdAt:now
    });
    existingArticleIds.add(article.articleId);
    existingUrls.add(article.url);
    imported++;
  }
  if(imported > 0)await env.ENGR_KV.put('config:links', JSON.stringify(links));
  await auditLog(env, user || 'system', 'LINK_KB_IMPORT', { years, imported, duplicated, inaccessible, scanned, discovered, mode:'free_verified' });
  return { ok:true, imported, added:imported, duplicated, skipped:duplicated, inaccessible, scanned, discovered, years, total:links.length, attempts:0, errors:0, nextCursor:null, mode:'free_verified', cost:'free' };
}

export async function googleKbSearch(env, task, years, page){
  const key = env.GOOGLE_SEARCH_KEY;
  const cx = env.GOOGLE_SEARCH_CX;
  if(!key || !cx)throw new Error('GOOGLE_SEARCH_KEY and GOOGLE_SEARCH_CX are required for Broadcom KB import.');
  const api = new URL('https://www.googleapis.com/customsearch/v1');
  api.searchParams.set('key', key);
  api.searchParams.set('cx', cx);
  api.searchParams.set('q', task.q);
  api.searchParams.set('dateRestrict', `y${years}`);
  api.searchParams.set('num', '10');
  api.searchParams.set('start', String(page * 10 + 1));
  const res = await fetch(api.toString(), { headers:{ 'Accept':'application/json' } });
  if(!res.ok)throw new Error(`Google search failed: ${res.status}`);
  const data = await res.json();
  return (data.items || []).map(item=>({
    title: item.title || '',
    url: item.link || '',
    snippet: item.snippet || '',
    product: task.product,
    queryLabel: task.queryLabel
  }));
}

export async function verifyKbArticle(candidate, cutoff){
  const normalized = normalizeKbArticleUrl(candidate.url);
  if(!normalized)return { ok:false, reason:'not_article' };
  const res = await fetch(normalized.url, { headers:{ 'Accept':'text/html,application/xhtml+xml', 'User-Agent':'ENGR-HUB-KB-Importer/1.1' } });
  if(!res.ok)return { ok:false, reason:`http_${res.status}`, articleId:normalized.articleId, url:normalized.url };
  const html = await res.text();
  const updatedAt = extractKbDate(html);
  const dateUnknown = !updatedAt;
  if(updatedAt && new Date(updatedAt) < cutoff)return { ok:false, reason:'older_than_range', articleId:normalized.articleId, url:normalized.url };
  const title = extractKbTitle(html, candidate.title || kbArticleTitleFromSlug(normalized.slug) || `Broadcom KB ${normalized.articleId}`);
  return { ok:true, articleId:normalized.articleId, url:normalized.url, title, product:candidate.product, updatedAt, dateUnknown, queryLabel:candidate.queryLabel };
}

export async function importPaidKbLinks(env, user, years=5, opts={}){
  if(!env.GOOGLE_SEARCH_KEY || !env.GOOGLE_SEARCH_CX){
    return { ok:false, message:'GOOGLE_SEARCH_KEY and GOOGLE_SEARCH_CX Worker secrets are required for Broadcom KB import.', imported:0, duplicated:0, inaccessible:0, scanned:0, discovered:0, mode:'search_api_required' };
  }
  const raw = await env.ENGR_KV.get('config:links') || await env.ENGR_KV.get('links');
  const links = raw ? JSON.parse(raw) : [];
  let imported = 0, duplicated = 0, inaccessible = 0, scanned = 0, discovered = 0, attempts = 0, errors = 0;
  const cutoff = new Date(); cutoff.setUTCFullYear(cutoff.getUTCFullYear() - years);
  const limit = Math.max(1, Math.min(50, parseInt(opts.limit || '20', 10) || 20));
  const maxQueries = Math.max(1, Math.min(6, parseInt(opts.maxQueries || '3', 10) || 3));
  const maxPagesPerTask = Math.max(1, Math.min(10, parseInt(opts.maxPagesPerTask || '3', 10) || 3));
  const tasks = kbSearchTasks();
  const cursor = kbCursorDecode(opts.cursor || '');
  let taskIndex = Math.max(0, Math.min(tasks.length, parseInt(cursor.task || 0, 10) || 0));
  let page = Math.max(0, Math.min(maxPagesPerTask - 1, parseInt(cursor.page || 0, 10) || 0));
  const seenInRun = new Set();
  const existingArticleIds = new Set(links.map(l=>String(l.articleId || normalizeKbArticleUrl(l.url)?.articleId || '')).filter(Boolean));
  const existingUrls = new Set(links.map(l=>String(l.url || '').replace(/[?#].*$/,'')));
  while(taskIndex < tasks.length && attempts < maxQueries && scanned < limit){
    const task = tasks[taskIndex];
    try{
      attempts++;
      const results = await googleKbSearch(env, task, years, page);
      if(!results.length){
        page = maxPagesPerTask;
      }
      for(const result of results){
        if(scanned >= limit)break;
        scanned++;
        const normalized = normalizeKbArticleUrl(result.url);
        if(!normalized){ inaccessible++; continue; }
        if(seenInRun.has(normalized.articleId)){ duplicated++; continue; }
        seenInRun.add(normalized.articleId);
        discovered++;
        if(existingArticleIds.has(normalized.articleId) || existingUrls.has(normalized.url)){ duplicated++; continue; }
        const article = await verifyKbArticle({ ...result, url: normalized.url }, cutoff);
        if(!article.ok){ inaccessible++; continue; }
        const now = new Date().toISOString();
        const item = {
          id: crypto.randomUUID(),
          category: 'Broadcom KB',
          product: article.product,
          articleId: article.articleId,
          source: 'broadcom-kb-import',
          title: `[${article.product}] ${article.title}`,
          url: article.url,
          desc: `Broadcom KB Article ${article.articleId}. Imported from ${article.queryLabel}. ${article.dateUnknown ? 'Document date unknown' : 'Document date ' + article.updatedAt.slice(0,10)}. Verified ${now.slice(0,10)}`,
          updatedAt: article.updatedAt || null,
          dateUnknown: article.dateUnknown,
          verifiedAt: now,
          createdBy: user || 'system',
          createdAt: now
        };
        links.unshift(item);
        existingArticleIds.add(article.articleId);
        existingUrls.add(article.url);
        imported++;
      }
      page++;
      if(page >= maxPagesPerTask){ taskIndex++; page = 0; }
    }catch(e){
      errors++;
      page++;
      if(page >= maxPagesPerTask){ taskIndex++; page = 0; }
    }
  }
  if(imported > 0)await env.ENGR_KV.put('config:links', JSON.stringify(links));
  const nextCursor = taskIndex < tasks.length ? kbCursorEncode({ task:taskIndex, page }) : null;
  await auditLog(env, user || 'system', 'LINK_KB_IMPORT', { years, imported, duplicated, inaccessible, scanned, discovered, attempts, errors, nextCursor:!!nextCursor, mode:'articles' });
  return { ok:true, imported, added:imported, duplicated, skipped:duplicated, inaccessible, scanned, discovered, years, total:links.length, attempts, errors, nextCursor, mode:'articles' };
}

export async function importRecentKBLinks(env, user, years=5, opts={}){
  const provider = String(opts.provider || '').toLowerCase();
  const paidAllowed = env.KB_ALLOW_PAID_SEARCH === 'true' || provider === 'google';
  if(paidAllowed)return await importPaidKbLinks(env, user, years, opts);
  return await importFreeKbLinks(env, user, years, opts);
}

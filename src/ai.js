// ENGR HUB worker — ai.js
// (worker.js에서 이동. 로직 변경 없음)

import { sha256Hex } from './auth.js';

export function normalizeAIMode(mode = '') {
  const aliases = {
    analyze: 'technical_analysis',
    reply: 'reply_draft',
    similar: 'similar_issues',
  };
  return aliases[mode] || mode || 'technical_analysis';
}

export function redactSensitiveText(text = '') {
  return String(text)
    .replace(/(authorization\s*[:=]\s*)(bearer\s+)?[^\s"'<>]+/gi, '$1[REDACTED]')
    .replace(/(cookie\s*[:=]\s*)[^\n\r]+/gi, '$1[REDACTED]')
    .replace(/((api[_-]?key|token|secret|password|passwd|pin)\s*[:=]\s*)[^\s"'<>]+/gi, '$1[REDACTED]')
    .replace(/\b(?:\d{1,3}\.){3}\d{1,3}\b/g, '[IP_REDACTED]')
    .replace(/[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}/gi, '[EMAIL_REDACTED]');
}

export async function callAI(env, userPrompt, mode = 'technical_analysis') {
  mode = normalizeAIMode(mode);
  //
  let systemPrompt = '';
  try { systemPrompt = await env.ENGR_KV.get('config:ai_system') || ''; } catch (_) {}

  if (!systemPrompt.trim()) {
    systemPrompt = `You are a security engineering operations assistant for ENGR HUB.
Separate confirmed facts from assumptions. Do not invent Jira, log, KB, or customer data.
Mask or omit credentials, PINs, API keys, tokens, cookies, internal URLs, and personal data.
For log analysis, start with evidence from logs, then facts, possible causes, impact, checks, actions, and next questions.
Customer-facing drafts must be concise, polite, and limited to confirmed facts.
All outputs are review drafts for humans; never instruct automatic customer sending, Jira changes, policy changes, or data deletion.`.trim();
  }
  const promptLimit = mode === 'log' ? 18000 : 24000;
  const rawPrompt = redactSensitiveText(userPrompt || '');
  const clippedPrompt = rawPrompt.length > promptLimit
    ? rawPrompt.slice(0, promptLimit) + `\n\n[\uC785\uB825\uC774 \uB108\uBB34 \uAE38\uC5B4 ${promptLimit}\uC790\uB85C \uC904\uC600\uC2B5\uB2C8\uB2E4.]`
    : rawPrompt;

  //
  const fullText = `[SYSTEM]${systemPrompt}\n[USER]${clippedPrompt}`;
  const hash = await sha256Hex(mode + '|' + fullText);
  const cacheKey = `ai:v3:${mode}:${hash.slice(0, 40)}`;  // v3: 옛 워커가 text를 배열로 저장한 오염 캐시 무효화(callAI 비-string 방어와 함께)

  //
  try {
    const cached = await env.ENGR_KV.get(cacheKey);
    if (cached) {
      const data = JSON.parse(cached);
      data._cached = true;
      return data;
    }
  } catch (_) {}

  //
  let userText = clippedPrompt;

  //
  let text = '';
  let modelUsed = '';

  // 1\uC21C\uC704: Google Gemini (\uBB34\uB8CC \uB4F1\uAE09) \u2014 GEMINI_API_KEY \uB610\uB294 GEMINI_KEY \uC124\uC815 \uC2DC
  const geminiKey = env.GEMINI_API_KEY || env.GEMINI_KEY;
  if (geminiKey) {
    try {
      const gModel = env.GEMINI_MODEL || 'gemini-2.5-flash';
      const gRes = await fetch(`https://generativelanguage.googleapis.com/v1beta/models/${gModel}:generateContent?key=${geminiKey}`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          systemInstruction: { parts: [{ text: systemPrompt }] },
          contents: [{ role: 'user', parts: [{ text: userText }] }],
          // maxOutputTokens 상향 + thinking 비활성화(2.5-flash는 사고 토큰이 출력예산을 잠식해 답변이 잘림)
          generationConfig: { temperature: 0.4, maxOutputTokens: 8192, thinkingConfig: { thinkingBudget: 0 } },
        }),
      });
      if (gRes.ok) {
        const gData = await gRes.json();
        text = (gData?.candidates?.[0]?.content?.parts || []).map(p => p.text || '').join('') || '';
        if (text) modelUsed = gModel;
      }
    } catch (_) {}
  }

  // \uD3F4\uBC31: Cloudflare Workers AI (Llama) \u2014 Gemini \uBBF8\uC124\uC815/\uC2E4\uD328 \uC2DC (\uBB34\uBE44\uC6A9)
  if (!text) {
    const response = await env.AI.run('@cf/meta/llama-3.3-70b-instruct-fp8-fast', {
      messages: [
        { role: 'system', content: systemPrompt },
        { role: 'user', content: userText },
      ],
      max_tokens: 8192,
      temperature: 0.4,
    });
    text = response?.response || '';
    if (text) modelUsed = 'llama-3.3-70b';
  }

  if (!text) throw new Error('AI \uC751\uB2F5\uC774 \uBE44\uC5B4 \uC788\uC2B5\uB2C8\uB2E4.');

  //
  const result = {
    candidates: [{ content: { parts: [{ text }] } }],
    _model: modelUsed,
  };

  //
  try {
    await env.ENGR_KV.put(cacheKey, JSON.stringify(result), { expirationTtl: 60 * 60 * 24 * 7 });
  } catch (_) {}

  return result;
}

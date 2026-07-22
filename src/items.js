// ENGR HUB worker — items.js
// (worker.js에서 이동. 로직 변경 없음)

import { auditLog } from './audit.js';
import { isAdmin } from './auth.js';

export async function canModifyItem(env, user, item) {
  if (!user || !item) return false;
  if (await isAdmin(env, user)) return true;
  return item.createdBy === user;
}

export function cleanCommentText(text = '') {
  return String(text || '').trim().slice(0, 2000);
}

export async function addCollectionComment(env, key, id, user, text, auditType) {
  const body = cleanCommentText(text);
  if (!body) return { status: 400, body: { ok: false, message: '\uB313\uAE00 \uB0B4\uC6A9\uC744 \uC785\uB825\uD558\uC138\uC694.' } };
  const raw = await env.ENGR_KV.get(key);
  const items = raw ? JSON.parse(raw) : [];
  const target = items.find(item => item.id === id);
  if (!target) return { status: 404, body: { ok: false, message: '\uB300\uC0C1\uC744 \uCC3E\uC744 \uC218 \uC5C6\uC2B5\uB2C8\uB2E4.' } };
  const now = new Date().toISOString();
  const comment = {
    id: Date.now().toString(36) + Math.random().toString(36).slice(2, 6),
    text: body,
    createdBy: user,
    createdAt: now,
  };
  target.comments = Array.isArray(target.comments) ? target.comments : [];
  target.comments.push(comment);
  if (target.comments.length > 100) target.comments = target.comments.slice(-100);
  target.updatedAt = now;
  await env.ENGR_KV.put(key, JSON.stringify(items));
  await auditLog(env, user, auditType, { id, commentId: comment.id });
  return { status: 200, body: { ok: true, comment }, item: target };
}

export async function deleteCollectionComment(env, key, id, commentId, user, auditType) {
  const raw = await env.ENGR_KV.get(key);
  const items = raw ? JSON.parse(raw) : [];
  const target = items.find(item => item.id === id);
  if (!target) return { status: 404, body: { ok: false, message: '\uB300\uC0C1\uC744 \uCC3E\uC744 \uC218 \uC5C6\uC2B5\uB2C8\uB2E4.' } };
  const comments = Array.isArray(target.comments) ? target.comments : [];
  const comment = comments.find(c => c.id === commentId);
  if (!comment) return { status: 404, body: { ok: false, message: '\uB313\uAE00\uC744 \uCC3E\uC744 \uC218 \uC5C6\uC2B5\uB2C8\uB2E4.' } };
  if (!await isAdmin(env, user) && comment.createdBy !== user) {
    return { status: 403, body: { ok: false, message: '\uC791\uC131\uC790 \uB610\uB294 \uAD00\uB9AC\uC790\uB9CC \uC0AD\uC81C\uD560 \uC218 \uC788\uC2B5\uB2C8\uB2E4.' } };
  }
  target.comments = comments.filter(c => c.id !== commentId);
  target.updatedAt = new Date().toISOString();
  await env.ENGR_KV.put(key, JSON.stringify(items));
  await auditLog(env, user, auditType, { id, commentId });
  return { status: 200, body: { ok: true, deleted: 1 } };
}

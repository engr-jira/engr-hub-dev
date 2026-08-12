// ENGR HUB worker — items.js
// (worker.js에서 이동. 로직 변경 없음)

import { auditLog } from './audit.js';
import { isAdmin } from './auth.js';
import { KV_CONFLICT_RESPONSE, kvMutateArray } from './kv.js';

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
  const m = await kvMutateArray(env, key, (items) => {
    const target = items.find(item => item.id === id);
    if (!target) return { abort: { status: 404, body: { ok: false, message: '대상을 찾을 수 없습니다.' } } };
    const now = new Date().toISOString();
    const comment = {
      id: Date.now().toString(36) + Math.random().toString(36).slice(2, 6),
      text: body,
      createdBy: user,
      createdAt: now,
    };
    const merged = (Array.isArray(target.comments) ? target.comments : []).concat(comment);
    const next = { ...target, comments: merged.length > 100 ? merged.slice(-100) : merged, updatedAt: now };
    return { list: items.map(it => it.id === id ? next : it), value: { comment, item: next } };
  });
  if (m.abort) return m.abort;
  if (m.conflict) return { status: 409, body: KV_CONFLICT_RESPONSE };
  await auditLog(env, user, auditType, { id, commentId: m.value.comment.id });
  return { status: 200, body: { ok: true, comment: m.value.comment }, item: m.value.item };
}

export async function deleteCollectionComment(env, key, id, commentId, user, auditType) {
  const m = await kvMutateArray(env, key, async (items) => {
    const target = items.find(item => item.id === id);
    if (!target) return { abort: { status: 404, body: { ok: false, message: '대상을 찾을 수 없습니다.' } } };
    const comments = Array.isArray(target.comments) ? target.comments : [];
    const comment = comments.find(c => c.id === commentId);
    if (!comment) return { abort: { status: 404, body: { ok: false, message: '댓글을 찾을 수 없습니다.' } } };
    if (!await isAdmin(env, user) && comment.createdBy !== user) {
      return { abort: { status: 403, body: { ok: false, message: '작성자 또는 관리자만 삭제할 수 있습니다.' } } };
    }
    const next = { ...target, comments: comments.filter(c => c.id !== commentId), updatedAt: new Date().toISOString() };
    return { list: items.map(it => it.id === id ? next : it) };
  });
  if (m.abort) return m.abort;
  if (m.conflict) return { status: 409, body: KV_CONFLICT_RESPONSE };
  await auditLog(env, user, auditType, { id, commentId });
  return { status: 200, body: { ok: true, deleted: 1 } };
}

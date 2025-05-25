// 版权所有 (C) Fourth Master
// License: AGPL
// 作者: Fourth Master
// 博客: https://blog.soeg.cn
// 演示: https://883588.xyz
// 短链核心逻辑模块，负责生成、校验、跳转、统计等
// 依赖src/kv/kv.js进行数据读写
import { putShortLink, getShortLink, deleteShortLink, addToBlacklist, isBlacklisted, removeFromBlacklist } from '../kv/kv.js';

// 敏感词、广告、恶意、垃圾词列表（可扩展）
const SENSITIVE_WORDS = ['admin', 'sex', 'spam', 'ad', 'malware'];

/**
 * 校验短链code是否合法
 * @param {string} code
 * @returns {string|null} 不合法返回错误信息，合法返回null
 */
export function validateCode(code) {
  if (!/^[a-zA-Z0-9]{6,12}$/.test(code)) return '短链仅支持6-12位字母数字';
  for (const word of SENSITIVE_WORDS) {
    if (code.toLowerCase().includes(word)) return '短链包含敏感/广告/恶意/垃圾内容';
  }
  return null;
}

/**
 * 生成随机短链code
 * @returns {string}
 */
export function generateCode() {
  const chars = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789';
  let code = '';
  for (let i = 0; i < 8; i++) code += chars[Math.floor(Math.random() * chars.length)];
  return code;
}

/**
 * 创建短链
 * @param {string} longUrl
 * @param {string} customCode
 * @returns {object} { code, status, msg }
 */
export async function createShortLink(longUrl, customCode, expire, delay) {
  let code = customCode || generateCode();
  const err = validateCode(code);
  if (err) return { status: 0, msg: err };
  // 检查是否重复
  let exist;
  try {
    exist = await getShortLink(code);
  } catch(e) {
    return { status: 0, msg: 'KV异常: ' + (e.message || e.toString()) };
  }
  if (exist) return { status: 0, msg: '短链已存在，请更换' };
  // 检查黑名单
  try {
    const urlObj = new URL(longUrl);
    if (await isBlacklisted(urlObj.hostname)) return { status: 0, msg: '目标域名被列入黑名单' };
  } catch {
    return { status: 0, msg: '长链接格式不正确' };
  }
  // 有效期处理
  let expireValue = null;
  // 优先支持前端传递的expire为时间戳（毫秒）
  if (typeof expire === 'number' && expire > 1000000000000) {
    expireValue = expire;
  } else if (expire === 'permanent' || expire === 0) {
    expireValue = 0;
  } else if (typeof expire !== 'undefined') {
    let expireDays = parseInt(expire, 10);
    if (isNaN(expireDays) || expireDays < 1) expireDays = 30;
    if (expireDays > 365) expireDays = 365;
    expireValue = Date.now() + expireDays * 24 * 3600 * 1000;
  } else {
    expireValue = Date.now() + 30 * 24 * 3600 * 1000;
  }
  // 存储短链，delay字段始终为布尔值
  const data = { longUrl, created: Date.now(), count: 0, expire: expireValue, delay: !!delay };
  try {
    await putShortLink(code, data);
  } catch(e) {
    return { status: 0, msg: 'KV写入异常: ' + (e.message || e.toString()) };
  }
  const baseUrl = typeof ORIGIN !== 'undefined' ? ORIGIN : (typeof globalThis !== 'undefined' && globalThis.ORIGIN) ? globalThis.ORIGIN : '';
  const shortUrl = baseUrl ? baseUrl.replace(/\/$/, '') + '/' + code : '/' + code;
  return { status: 1, code, shortUrl, expire: expireValue, delay: !!delay, msg: '创建成功' };
}

/**
 * 跳转短链
 * @param {string} code
 * @returns {object} { longUrl, status, msg }
 */
export async function resolveShortLink(code) {
  const data = await getShortLink(code);
  if (!data) return { status: 0, msg: '短链不存在' };
  // 统计访问量、每日访问量、最后访问时间
  data.visits = (data.visits || 0) + 1;
  const now = new Date();
  const today = now.toISOString().slice(0, 10);
  data.dailyVisits = data.dailyVisits || {};
  data.dailyVisits[today] = (data.dailyVisits[today] || 0) + 1;
  data.lastVisit = now.toISOString();
  await putShortLink(code, data);
  // 返回delay字段，保证类型为布尔值
  return { status: 1, longUrl: data.longUrl, delay: !!data.delay };
}

// 统计、黑白名单等功能可继续扩展
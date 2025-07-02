// 版权所有 (C) Fourth Master
// License: AGPL
// 作者: Fourth Master
// 博客: https://blog.soeg.cn
// 演示: https://883588.xyz
// Cloudflare Worker 主入口
// 负责短链接生成、校验、存储、跳转等核心逻辑
import { createShortLink, resolveShortLink } from './core/shortlink.js';
import { initKV } from './kv/kv.js';
import ADMIN_HTML from './admin/admin.html' assert { type: 'text' }

addEventListener('fetch', event => {
  event.respondWith(handleRequest(event.request));
});
function decodeBase64(base64String) {
  try {
    const decodedData = atob(base64String);
    return decodeURIComponent(escape(decodedData));
  } catch (error) {
    console.error('解码失败:', error);
    return null;
  }
}

async function handleRequest(request, env) {
  // 【////域名跳转逻辑：如访问 www.883588.xyz 自动 301 跳转到 883588.xyz
  // API名称: 主域名跳转
  // 参数: 无（自动判断 Host）
  // 返回值: 301 跳转响应
  // 使用方法: 直接访问 www.883588.xyz 任意路径
  // 备注: 保证所有请求都统一到主域名，利于SEO和用户体验
  const urlt = new URL(request.url);
  if (urlt.hostname === 'www.883588.xyz') {
    urlt.hostname = '883588.xyz';
    return Response.redirect(urlt.toString(), 301);
  }
  ////////】中里可以删除
  // 初始化KV命名空间（需在wrangler.toml中配置绑定）
  if (!globalThis.KV) {
    // Cloudflare Worker环境自动注入KV
    initKV(LINKS);
    globalThis.KV = LINKS;
  }
  // 速率限制逻辑
  const url = new URL(request.url);
  // 静态资源统一处理：支持.png、.webp、.ico、.js、.css等静态文件
  const staticExts = ['.png', '.webp', '.ico', '.js', '.css', '.jpg', '.jpeg', '.gif', '.svg', '.woff', '.woff2', '.ttf', '.eot', '.map'];
  if (staticExts.some(ext => url.pathname.endsWith(ext))) {
    // API名称: 静态资源文件输出
    // 参数: 无（直接请求静态资源路径）
    // 返回值: 对应静态文件内容
    // 使用方法: 直接访问如 /logo.png、/main.js 等
    // 备注: 通过Cloudflare Worker的ASSETS绑定实现高性能静态资源分发
    return env.ASSETS.fetch(request);
  }
  const ip = request.headers.get('CF-Connecting-IP') || request.headers.get('x-forwarded-for') || '';
  // 只对API接口做速率限制
  const isApi = url.pathname.startsWith('/api/') || url.pathname.startsWith('/admin/api/');
  if (isApi) {
    const rateKey = `ratelimit:${ip}:${url.pathname}`;
    let rateInfo = await KV.get(rateKey, { type: 'json' });
    const now = Date.now();
    const windowMs = 60 * 1000; // 1分钟窗口
    const maxReq = url.pathname.startsWith('/admin/api/') ? 10 : 20; // 管理接口更严格
    if (!rateInfo || now - rateInfo.ts > windowMs) {
      rateInfo = { count: 1, ts: now };
    } else {
      rateInfo.count++;
    }
    if (rateInfo.count > maxReq) {
      return new Response(JSON.stringify({ status: 0, msg: '请求过于频繁，请稍后再试' }), { status: 429, headers: { 'Content-Type': 'application/json' } });
    }
    await KV.put(rateKey, JSON.stringify(rateInfo), { expirationTtl: 120 });
  }
  // 路由分发
  if (url.pathname === '/doc' || url.pathname === '/doc.html') {
    // 输出 API 文档页面
    const html = await import('./frontend/doc.html', { assert: { type: 'text' } });
    const list = await KV.list({ prefix: 'friendlink:' });
    let friendLinks = list.keys.map(k => {
      const val = k.name.replace('friendlink:', '');
      let info = { name: val, url: '' };
      if (k.metadata && k.metadata.url) info.url = k.metadata.url;
      return `<a href=\"${info.url}\" target=\"_blank\" rel=\"noopener\">${info.name}</a>`;
    }).join(' ');
    if (!friendLinks || friendLinks.length === 0) {friendLinks = decodeBase64('PGEgaHJlZj0iaHR0cHM6Ly9ibG9nLnNvZWcuY24iIHRhcmdldD0iX2JsYW5rIiByZWw9Im5vb3BlbmVyIj7lm5vniLfmiYvmiY48L2E+');}
    let copyright = await KV.get('setting:copyright');
    if (!copyright) {copyright = decodeBase64('IDIwMjUgPGEgaHJlZj0iaHR0cHM6Ly93d3cuODgzNTg4Lnh5ei8iIHRhcmdldD0iX2JsYW5rIj4zNeefremTvjwvYT4gQnnvvJrlm5vniLc=');}
    let redirectHtml = (html.default || html)
      .replace(/<span id="friend-links">.*<\/span>/, `<span id="friend-links">${friendLinks}</span>`);
    const injectScript = `<span id="copyright-info"> ${copyright}</span>`;
    redirectHtml = redirectHtml.replace(/<span id="copyright-info">[\s\S]*?<\/span>/, injectScript);
    return new Response(redirectHtml, { status: 200, headers: { 'Content-Type': 'text/html' } });
  } else if (url.pathname.startsWith('/api/create')) {
    if (request.method !== 'POST') {
      return new Response(JSON.stringify({ status: 0, msg: '仅支持POST' }), { status: 405, headers: { 'Content-Type': 'application/json' } });
    }
    let body = {};
    try { body = await request.json(); } catch {}
    const { longUrl, customCode, expireDays } = body;
    const delay = body.delay !== undefined ? body.delay : true; // 默认delay为true
    if (!longUrl) return new Response(JSON.stringify({ status: 0, msg: '缺少longUrl参数' }), { status: 400, headers: { 'Content-Type': 'application/json' } });
    const result = await createShortLink(longUrl, customCode, expireDays, delay);
    if (result.status === 1) {
      result.shortUrl = url.origin + '/s/' + result.code;
    }
    return new Response(JSON.stringify(result), { status: 200, headers: { 'Content-Type': 'application/json' } });
  // 新增：站点信息接口，返回友情链接和版权信息
  } else if (url.pathname.startsWith('/s/')) {
    const code = url.pathname.replace('/s/', '').replace(/\/$/, '');
    if (!code) return new Response('短链参数缺失', { status: 400 });
    const result = await resolveShortLink(code);

    if (result.status === 1) {
      // 新增：判断是否为微信/QQ内置浏览器，若是则直接输出fh.html页面
      const ua = request.headers.get('user-agent') || '';
      if (/MicroMessenger|QQ\//i.test(ua)) {
        // 输出特殊提示页面，避免内置浏览器跳转失败
        const fhHtml = await import('./frontend/fh.html', { assert: { type: 'text' } });
        return new Response(fhHtml.default || fhHtml, { status: 200, headers: { 'Content-Type': 'text/html' } });
      }
      // 跳转延时3秒（可根据白名单优化）
      // 判断目标域名是否在白名单，白名单内直接跳转
      const targetUrl = result.longUrl;
      let isWhite = false;
      let delay = false;
      try {
        const { isWhitelisted } = await import('./kv/kv.js');
        // 提取主域名（去除多级子域名，仅保留主域名和www.前缀）
        const extractMainDomain = (hostname) => {
          // 只保留最后两段或带www的三段
          const parts = hostname.split('.');
          if (parts.length >= 3 && parts[0] === 'www') {
            return parts.slice(-3).join('.');
          } else {
            return parts.slice(-2).join('.');
          }
        };
        const domain = (() => {
          try {
            return new URL(targetUrl).hostname;
          } catch { return ''; }
        })();
        let mainDomain = extractMainDomain(domain);
        // 允许www.前缀和主域名都可匹配
        let checkDomains = [mainDomain];
        if (mainDomain.startsWith('www.')) {
          checkDomains.push(mainDomain.replace(/^www\./, ''));
        } else {
          checkDomains.push('www.' + mainDomain);
        }
        for (let d of checkDomains) {
          if (await isWhitelisted(d)) {
            isWhite = true;
            break;
          }
        }
        delay = result.delay;
      } catch {}
      if (isWhite) {
        // 直跳白名单域名
        return Response.redirect(targetUrl, 302);
      }
      // 根据delay字段判断是否延时跳转
      if (delay) {
        // 返回延时跳转页面
        const html = await import('./frontend/redirect.html', { assert: { type: 'text' } });
        let redirectHtml = (html.default || html)
          .replace(/<title>.*<\/title>/, '<title>35短链接 - 跳转中...</title>')
          .replace('<body>', `<body>`);
        // 直接注入目标链接和倒计时变量，避免通过URL参数暴露
        const injectScript = `<script>\nvar targetUrl = ${JSON.stringify(result.longUrl)};\nvar sec = 3;\nwindow.addEventListener('DOMContentLoaded', function() {\n  var target = document.getElementById('target');\n  var count = document.getElementById('count');\n  var btn = document.getElementById('jumpBtn');\n  var copyBtn = document.getElementById('copyBtn');\n  var toast = document.getElementById('toast');\n  if (!targetUrl) {\n    target.style.display = 'none';\n    count.style.display = 'none';\n    return;\n  }\n  target.href = targetUrl;\n  target.textContent = targetUrl;\n  count.textContent = sec;\n  btn.onclick = function() { window.location.href = targetUrl; };\n  if (copyBtn) {\n    copyBtn.onclick = function() {\n      if (!targetUrl) return;\n      navigator.clipboard.writeText(targetUrl).then(function() {\n        if (toast) {\n          toast.textContent = '已复制到剪贴板';\n          toast.style.display = 'block';\n          setTimeout(function() { toast.style.display = 'none'; }, 1800);\n        }\n      }, function() {\n        if (toast) {\n          toast.textContent = '复制失败，请手动复制';\n          toast.style.display = 'block';\n          setTimeout(function() { toast.style.display = 'none'; }, 1800);\n        }\n      });\n    };\n  }\n  var timer = setInterval(function() {\n    sec--;\n    if (sec <= 0) {\n      clearInterval(timer);\n      window.location.href = targetUrl;\n    } else {\n      count.textContent = sec;\n    }\n  }, 1000);\n});<\/script>`;
        // 移除原有<script>标签，插入新脚本
        redirectHtml = redirectHtml.replace(/<script>[\s\S]*?<\/script>/, injectScript);
        return new Response(redirectHtml, { status: 200, headers: { 'Content-Type': 'text/html' } });
      } else {
        // delay为false时直接跳转目标链接
        return Response.redirect(targetUrl, 302);
      }
    } else {
      return new Response(result.msg, { status: 404 });
    }
  } else if (url.pathname === '/admin/login') {
    if (request.method === 'GET') {
      // 返回登录页面
      const html = await import('./admin/login.html', { assert: { type: 'text' } });
      return new Response(html.default || html, { status: 200, headers: { 'Content-Type': 'text/html' } });
    } else if (request.method === 'POST') {
      // Cloudflare Turnstile 人机验证校验
      let body = {};
      try { body = await request.json(); } catch {}
      const { username, password, turnstileToken } = body;
      if (!turnstileToken) {
        return new Response(JSON.stringify({ status: 0, msg: '请完成人机验证' }), { status: 400, headers: { 'Content-Type': 'application/json' } });
      }
      // 校验Turnstile token
      const verifyResp = await fetch('https://challenges.cloudflare.com/turnstile/v0/siteverify', {
        method: 'POST',
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        body: `secret=0x4AAAAAABjJ5IIUNGR02u2Acu4y7WDcI6c&response=${encodeURIComponent(turnstileToken)}`
      });
      const verifyData = await verifyResp.json();
      if (!verifyData.success) {
        return new Response(JSON.stringify({ status: 0, msg: '人机验证失败，请重试' }), { status: 400, headers: { 'Content-Type': 'application/json' } });
      }
      const envUser = globalThis.ADMIN_USER || 'admin';
      const envPass = globalThis.ADMIN_PASS || 'password';
      // 新增：登录错误次数与锁定机制
      const lockKey = `admin:login:lock:${username}`;
      const failKey = `admin:login:fail:${username}`;
      let lockInfo = null;
      let failInfo = null;
      try {
        lockInfo = await KV.get(lockKey);
        failInfo = await KV.get(failKey);
        lockInfo = lockInfo ? JSON.parse(lockInfo) : null;
        failInfo = failInfo ? JSON.parse(failInfo) : { count: 0, last: 0 };
      } catch {}
      const now = Date.now();
      // 检查是否被锁定
      if (lockInfo && lockInfo.unlock > now) {
        const left = lockInfo.unlock - now;
        let msg = `密码错误次数过多，已锁定。请${Math.ceil(left/60000)}分钟后再试。`;
        if (left > 3600000) msg = `密码错误次数过多，已锁定。请${Math.ceil(left/3600000)}小时后再试。`;
        if (left > 86400000) msg = `密码错误次数过多，已锁定。请24小时后再试。`;
        return new Response(JSON.stringify({ status: 0, msg }), { status: 403, headers: { 'Content-Type': 'application/json' } });
      }
      let logMsg = `[LOGIN] 输入账号:${username}, 输入密码:${password}, 系统账号:${envUser}, 系统密码:${envPass}`;
      let loginOk = username === envUser && password === envPass;
      if (loginOk) {
        // 登录成功，清除错误记录
        await KV.delete(lockKey);
        await KV.delete(failKey);
        console.log(logMsg + ' => 登录成功');
        const headers = new Headers();
        headers.set('Content-Type', 'application/json');
        // 可选：生成token等
        return new Response(JSON.stringify({ status: 1, msg: '登录成功', token: 'Bearer admin-token' }), { status: 200, headers });
      } else {
        // 登录失败，记录错误次数
        failInfo.count++;
        failInfo.last = now;
        let lockTime = 0;
        if (failInfo.count >= 10) lockTime = 3600000; // 1小时
        if (failInfo.count >= 20) lockTime = 86400000; // 24小时
        if (lockTime > 0) {
          await KV.put(lockKey, JSON.stringify({ unlock: now + lockTime }), { expirationTtl: Math.ceil(lockTime/1000) });
        }
        await KV.put(failKey, JSON.stringify(failInfo), { expirationTtl: 86400 });
        console.log(logMsg + ' => 登录失败');
        return new Response(JSON.stringify({ status: 0, msg: '账号或密码错误' }), { status: 401, headers: { 'Content-Type': 'application/json' } });
      }
    }
    // 校验验证码
    const ip = request.headers.get('CF-Connecting-IP') || request.headers.get('x-forwarded-for') || '';
    if (!captcha) {
      return new Response(JSON.stringify({ status: 0, msg: '请输入验证码' }), { status: 400, headers: { 'Content-Type': 'application/json' } });
    }
    let valid = false;
    if (ip) {
      const realCode = await KV.get(`admin:captcha:${ip}`);
      if (realCode && captcha.toUpperCase() === realCode.toUpperCase()) {
        valid = true;
        await KV.delete(`admin:captcha:${ip}`); // 用过即删
      }
    }
    if (!valid) {
      return new Response(JSON.stringify({ status: 0, msg: '验证码错误或已过期' }), { status: 400, headers: { 'Content-Type': 'application/json' } });
    }
    // 新增：登录错误次数与锁定机制
    const lockKey = `admin:login:lock:${username}`;
    const failKey = `admin:login:fail:${username}`;
    let lockInfo = null;
    let failInfo = null;
    try {
      lockInfo = await KV.get(lockKey);
      failInfo = await KV.get(failKey);
      lockInfo = lockInfo ? JSON.parse(lockInfo) : null;
      failInfo = failInfo ? JSON.parse(failInfo) : { count: 0, last: 0 };
    } catch {}
    const now = Date.now();
    // 检查是否被锁定
    if (lockInfo && lockInfo.unlock > now) {
      const left = lockInfo.unlock - now;
      let msg = `密码错误次数过多，已锁定。请${Math.ceil(left/60000)}分钟后再试。`;
      if (left > 3600000) msg = `密码错误次数过多，已锁定。请${Math.ceil(left/3600000)}小时后再试。`;
      if (left > 86400000) msg = `密码错误次数过多，已锁定。请24小时后再试。`;
      return new Response(JSON.stringify({ status: 0, msg }), { status: 403, headers: { 'Content-Type': 'application/json' } });
    }
    let logMsg = `[LOGIN] 输入账号:${username}, 输入密码:${password}, 系统账号:${envUser}, 系统密码:${envPass}`;
    let loginOk = username === envUser && password === envPass;
    if (loginOk) {
      // 登录成功，清除错误记录
      await KV.delete(lockKey);
      await KV.delete(failKey);
      console.log(logMsg + ' => 登录成功');
      const headers = new Headers();
      headers.set('Content-Type', 'application/json');
      headers.append('Set-Cookie', `user=${encodeURIComponent(username)}; Path=/admin; SameSite=Lax`);
      headers.append('Set-Cookie', `password=${encodeURIComponent(password)}; Path=/admin; SameSite=Lax`);
      return new Response(JSON.stringify({ status: 1, msg: '登录成功' }), { status: 200, headers });
    } else {
      // 登录失败，增加错误次数
      failInfo.count = (failInfo.count || 0) + 1;
      failInfo.last = now;
      let lockTime = 0;
      let msg = '账号或密码错误';
      if (failInfo.count >= 6) {
        lockTime = 24 * 3600 * 1000; // 24小时
        msg = '密码错误6次，账号已锁定24小时';
      } else if (failInfo.count >= 4) {
        lockTime = 30 * 60 * 1000; // 30分钟
        msg = '密码错误4次，账号已锁定30分钟';
      } else if (failInfo.count >= 3) {
        lockTime = 15 * 60 * 1000; // 15分钟
        msg = '密码错误3次，账号已锁定15分钟';
      }
      if (lockTime > 0) {
        await KV.put(lockKey, JSON.stringify({ unlock: now + lockTime }), { expirationTtl: Math.ceil(lockTime/1000) });
        failInfo.count = 0; // 重置错误次数
      }
      await KV.put(failKey, JSON.stringify(failInfo), { expirationTtl: 86400 });
      console.warn(logMsg + ' => 登录失败');
      return new Response(JSON.stringify({ status: 0, msg }), { status: 401, headers: { 'Content-Type': 'application/json' } });
    }
  } else if (url.pathname.startsWith('/admin/api/')) {
    // 管理后台API接口
    // 权限校验（单管理员token机制）
    const cookie = request.headers.get('Cookie') || '';
    function getCookie(name) {
      const match = cookie.match(new RegExp('(?:^|; )' + name.replace(/([.$?*|{}()\[\]\\/+^])/g, '\\$1') + '=([^;]*)'));
      return match ? decodeURIComponent(match[1]) : '';
    }
    // 新增：用 user 和 password 两个 cookie 校验身份
    const envUser = globalThis.ADMIN_USER || 'admin';
    const envPass = globalThis.ADMIN_PASS || 'password';
    const user = getCookie('user');
    const password = getCookie('password');
    if (user !== envUser || password !== envPass) {
      return new Response(JSON.stringify({ status: 0, msg: '未授权' }), { status: 401, headers: { 'Content-Type': 'application/json' } });
    }
    // 解析API路径
    const apiPath = url.pathname.replace('/admin/api/', '');
    try {
      if (apiPath === 'links' && request.method === 'GET') {// 获取短链列表
        // 获取短链列表（简单实现：KV.list）
        const list = await KV.list({ prefix: 'shortlink:' });
        const codes = list.keys.map(k => k.name.replace('shortlink:', ''));
        const data = [];
        const urlSearch = url.searchParams || new URLSearchParams(url.search);
        const kw = urlSearch.get('kw') || '';
        for (const code of codes) {
          const item = await KV.get('shortlink:' + code);
          if (item) {
            const parsed = { code, ...JSON.parse(item) };
            if (!kw || parsed.code.includes(kw) || (parsed.longUrl && parsed.longUrl.includes(kw))) {
              data.push(parsed);
            }
          }
        }
        return new Response(JSON.stringify({ status: 1, data }), { status: 200, headers: { 'Content-Type': 'application/json' } });
      } else if (apiPath === 'links' && request.method === 'POST') {// 新增短链
        const body = await request.json();
        // 新增参数：expire（到期时间戳，可选），delay（是否跳转延时3秒，布尔，可选）
        const { url, custom, expire, delay } = body;
        if (!url) return new Response(JSON.stringify({ status: 0, msg: '缺少url参数' }), { status: 400, headers: { 'Content-Type': 'application/json' } });
        // 创建短链时传递expire和delay参数
        const result = await createShortLink(url, custom, expire, delay);
        if (result.status === 1) {
          result.shortUrl = url.origin + '/s/' + result.code;
          await writeAdminLog('新增短链', `code:${result.code}, url:${url}, expire:${expire}, delay:${delay}`, user, ip);
        }
        return new Response(JSON.stringify(result), { status: 200, headers: { 'Content-Type': 'application/json' } });
      } else if (apiPath.startsWith('links/') && request.method === 'PUT') {// 修改短链
        /**
         * API名称: 修改短链
         * 参数: code（路径参数，原短链码），newCode（新短链码，可选），longUrl（目标URL，可选），expire（到期时间戳，可选），delay（是否跳转延时3秒，布尔，可选）
         * 返回值: { status, msg }
         * 使用方法: PUT /admin/api/links/{code}，body: { newCode, longUrl, expire, delay }
         * 备注: 支持同时修改短链的码、URL、到期时间和跳转延时属性，若更换短链码则迁移数据并删除原有短链
         */
        const code = apiPath.replace('links/', '');
        const body = await request.json();
        const { newCode, longUrl, expire, delay } = body;
        if (!newCode && !longUrl && !expire && typeof delay === 'undefined') {
          return new Response(JSON.stringify({ status: 0, msg: '缺少可修改参数' }), { status: 400, headers: { 'Content-Type': 'application/json' } });
        }
        const item = await KV.get('shortlink:' + code);
        if (!item) return new Response(JSON.stringify({ status: 0, msg: '短链不存在' }), { status: 404, headers: { 'Content-Type': 'application/json' } });
        let data = JSON.parse(item);
        // 检查是否需要更换短链码
        if (newCode && newCode !== code) {
          const exist = await KV.get('shortlink:' + newCode);
          if (exist) {
            return new Response(JSON.stringify({ status: 0, msg: '新短链码已存在' }), { status: 409, headers: { 'Content-Type': 'application/json' } });
          }
        }
        if (typeof longUrl !== 'undefined') data.longUrl = longUrl;
        if (typeof expire !== 'undefined') data.expire = expire;
        if (typeof delay !== 'undefined') data.delay = !!delay;
        let logMsg = `code:${code}, newCode:${newCode}, longUrl:${longUrl}, expire:${expire}, delay:${delay}`;
        if (newCode && newCode !== code) {
          await KV.put('shortlink:' + newCode, JSON.stringify(data));
          await KV.delete('shortlink:' + code);
          await writeAdminLog('修改短链（更换短链码）', logMsg, user, ip);
          return new Response(JSON.stringify({ status: 1, msg: '修改成功，短链码已更换' }), { status: 200, headers: { 'Content-Type': 'application/json' } });
        } else {
          await KV.put('shortlink:' + code, JSON.stringify(data));
          await writeAdminLog('修改短链', logMsg, user, ip);
          return new Response(JSON.stringify({ status: 1, msg: '修改成功' }), { status: 200, headers: { 'Content-Type': 'application/json' } });
        }
      } else if (apiPath.startsWith('links/') && request.method === 'DELETE') {
        // 删除短链
        const code = apiPath.replace('links/', '');
        await KV.delete('shortlink:' + code);
        await writeAdminLog('删除短链', `code:${code}`, user, ip);
        return new Response(JSON.stringify({ status: 1, msg: '删除成功' }), { status: 200, headers: { 'Content-Type': 'application/json' } });
      } else if (apiPath === 'stats' && request.method === 'GET') {
        // 统计信息（总数、今日访问、累计访问、各短链访问量）
        const list = await KV.list({ prefix: 'shortlink:' });
        const totalLinks = list.keys.length;
        let totalVisits = 0;
        let todayVisits = 0;
        const stats = [];
        const today = new Date().toISOString().slice(0, 10);
        for (const k of list.keys) {
          const code = k.name.replace('shortlink:', '');
          const item = await KV.get('shortlink:' + code);
          if (item) {
            const data = JSON.parse(item);
            const visits = data.visits || 0;
            const daily = data.dailyVisits || {};
            const lastVisit = data.lastVisit || '';
            totalVisits += visits;
            todayVisits += daily[today] || 0;
            stats.push({ code, visits, dailyVisits: daily, lastVisit });
          }
        }
        return new Response(JSON.stringify({ status: 1, totalLinks, todayVisits, totalVisits, stats }), { status: 200, headers: { 'Content-Type': 'application/json' } });
      } else if (apiPath === 'blacklist' && request.method === 'GET') {
        // 获取黑名单
        const list = await KV.list({ prefix: 'blacklist:' });
        const data = list.keys.map(k => k.name.replace('blacklist:', ''));
        return new Response(JSON.stringify({ status: 1, data }), { status: 200, headers: { 'Content-Type': 'application/json' } });
      } else if (apiPath === 'blacklist' && request.method === 'POST') {
        // 添加黑名单
        const body = await request.json();
        const item = (body.item || '').trim();
        if (!item) return new Response(JSON.stringify({ status: 0, msg: '参数缺失' }), { status: 400, headers: { 'Content-Type': 'application/json' } });
        await KV.put('blacklist:' + item, '1');
        await writeAdminLog('添加黑名单', `domain:${item}`, user, ip);
        return new Response(JSON.stringify({ status: 1, msg: '添加成功' }), { status: 200, headers: { 'Content-Type': 'application/json' } });
      } else if (apiPath.startsWith('blacklist/') && request.method === 'DELETE') {
        // 移除黑名单
        const item = decodeURIComponent(apiPath.replace('blacklist/', ''));
        await KV.delete('blacklist:' + item);
        await writeAdminLog('移除黑名单', `domain:${item}`, user, ip);
        return new Response(JSON.stringify({ status: 1, msg: '移除成功' }), { status: 200, headers: { 'Content-Type': 'application/json' } });
      } else if (apiPath === 'whitelist' && request.method === 'GET') {
        // 获取白名单
        /**
         * API名称：获取白名单列表
         * 路径：/admin/api/whitelist
         * 方法：GET
         * 参数：无
         * 返回值：{ status: 1, data: [{ value: 域名, created: 创建时间 }] }
         * 用法：后台管理获取白名单数据
         * 备注：无
         */
        const list = await KV.list({ prefix: 'whitelist:' });
        const data = list.keys.map(k => {
          const name = k.name.replace('whitelist:', '');
          const created = k.metadata && k.metadata.created ? k.metadata.created : (k.expiration ? k.expiration : undefined);
          return { value: name, created };
        });
        return new Response(JSON.stringify({ status: 1, data }), { status: 200, headers: { 'Content-Type': 'application/json' } });
      } else if (apiPath === 'whitelist' && request.method === 'POST') {
        // 添加白名单
        /**
         * API名称：添加白名单
         * 路径：/admin/api/whitelist
         * 方法：POST
         * 参数：{ item: 域名 }
         * 返回值：{ status: 1, msg: '添加成功' } 或 { status: 0, msg: '参数缺失' }
         * 用法：后台管理添加白名单
         * 备注：无
         */
        const body = await request.json();
        const item = (body.item || '').trim();
        if (!item) return new Response(JSON.stringify({ status: 0, msg: '参数缺失' }), { status: 400, headers: { 'Content-Type': 'application/json' } });
        await KV.put('whitelist:' + item, '1', { metadata: { created: Date.now() } });
        await writeAdminLog('添加白名单', `domain:${item}`, user, ip);
        return new Response(JSON.stringify({ status: 1, msg: '添加成功' }), { status: 200, headers: { 'Content-Type': 'application/json' } });
      } else if (apiPath.startsWith('whitelist/') && request.method === 'DELETE') {
        // 移除白名单
        /**
         * API名称：移除白名单
         * 路径：/admin/api/whitelist/{item}
         * 方法：DELETE
         * 参数：item（路径参数，域名）
         * 返回值：{ status: 1, msg: '移除成功' }
         * 用法：后台管理移除白名单
         * 备注：无
         */
        const item = decodeURIComponent(apiPath.replace('whitelist/', ''));
        await KV.delete('whitelist:' + item);
        await writeAdminLog('移除白名单', `domain:${item}`, user, ip);
        return new Response(JSON.stringify({ status: 1, msg: '移除成功' }), { status: 200, headers: { 'Content-Type': 'application/json' } });
      } else if (apiPath === 'friendlink' && request.method === 'GET') {
        // 获取友情链接列表
        /**
         * API名称：获取友情链接列表
         * 路径：/admin/api/friendlink
         * 方法：GET
         * 参数：无
         * 返回值：{ status: 1, data: [{ name: 名称, url: 链接, created: 创建时间 }] }
         * 用法：后台管理获取友情链接数据
         * 备注：无
         */
        const list = await KV.list({ prefix: 'friendlink:' });
        const data = list.keys.map(k => {
          const val = k.name.replace('friendlink:', '');
          let info = { name: val, url: '', created: undefined };
          if (k.metadata && k.metadata.url) info.url = k.metadata.url;
          if (k.metadata && k.metadata.created) info.created = k.metadata.created;
          return info;
        });
        return new Response(JSON.stringify({ status: 1, data }), { status: 200, headers: { 'Content-Type': 'application/json' } });
      } else if (apiPath === 'friendlink' && request.method === 'POST') {
        // 添加友情链接
        /**
         * API名称：添加友情链接
         * 路径：/admin/api/friendlink
         * 方法：POST
         * 参数：{ name: 名称, url: 链接 }
         * 返回值：{ status: 1, msg: '添加成功' } 或 { status: 0, msg: '参数缺失' }
         * 用法：后台管理添加友情链接
         * 备注：名称和链接均不能为空
         */
        const body = await request.json();
        const name = (body.name || '').trim();
        const url = (body.url || '').trim();
        if (!name || !url) return new Response(JSON.stringify({ status: 0, msg: '参数缺失' }), { status: 400, headers: { 'Content-Type': 'application/json' } });
        await KV.put('friendlink:' + name, '1', { metadata: { url, created: Date.now() } });
        await writeAdminLog('添加友情链接', `name:${name}, url:${url}`, user, ip);
        return new Response(JSON.stringify({ status: 1, msg: '添加成功' }), { status: 200, headers: { 'Content-Type': 'application/json' } });
        
      } else if (apiPath.startsWith('friendlink/') && request.method === 'DELETE') {
        // 删除友情链接
        /**
         * API名称：删除友情链接
         * 路径：/admin/api/friendlink/{name}
         * 方法：DELETE
         * 参数：name（路径参数，名称）
         * 返回值：{ status: 1, msg: '删除成功' }
         * 用法：后台管理删除友情链接
         * 备注：无
         */
        const name = decodeURIComponent(apiPath.replace('friendlink/', ''));
        await KV.delete('friendlink:' + name);
        await writeAdminLog('删除友情链接', `name:${name}`, user, ip);
        return new Response(JSON.stringify({ status: 1, msg: '删除成功' }), { status: 200, headers: { 'Content-Type': 'application/json' } });
      } else if (apiPath === 'setting/copyright' && request.method === 'GET') {
        // 获取系统设置-版权信息
        const copyright = await KV.get('setting:copyright');
        return new Response(JSON.stringify({ status: 1, data: copyright || '' }), { status: 200, headers: { 'Content-Type': 'application/json' } });
      } else if (apiPath === 'setting/copyright' && request.method === 'POST') {
        // 保存系统设置-版权信息
        const body = await request.json();
        const copyright = (body.copyright || '').trim();
        await KV.put('setting:copyright', copyright);
        await writeAdminLog('保存版权信息', copyright, user, ip);
        return new Response(JSON.stringify({ status: 1, msg: '保存成功' }), { status: 200, headers: { 'Content-Type': 'application/json' } });

      } else if (apiPath === 'logs' && request.method === 'GET') {
        /**
         * API名称：操作日志查询（支持日期范围）
         * 路径：/admin/api/logs
         * 方法：GET
         * 参数：date（可选，单日），startDate（可选，起始日期yyyy-mm-dd），endDate（可选，结束日期yyyy-mm-dd），page（页码，默认1），pageSize（每页数量，默认20）
         * 返回值：{ status: 1, data: 日志数组, total: 总条数 }
         * 用法：后台管理查询操作日志，支持按日期或日期范围筛选
         * 备注：date、startDate、endDate三者只需传一种，优先级：date > (startDate+endDate)
         */
        const urlSearch = url.searchParams || new URLSearchParams(url.search);
        const date = urlSearch.get('date');
        const startDate = urlSearch.get('startDate');
        const endDate = urlSearch.get('endDate');
        const page = parseInt(urlSearch.get('page') || '1');
        const pageSize = parseInt(urlSearch.get('pageSize') || '20');
        let logs = [];
        if (date) {
          // 单日查询
          const key = `adminlog:${date}`;
          const val = await KV.get(key);
          logs = val ? JSON.parse(val) : [];
        } else if (startDate && endDate) {
          // 日期范围查询
          // 生成日期数组
          function getDateArray(start, end) {
            const arr = [];
            let dt = new Date(start);
            const endDt = new Date(end);
            while (dt <= endDt) {
              arr.push(dt.toISOString().slice(0, 10));
              dt.setDate(dt.getDate() + 1);
            }
            return arr;
          }
          const dateArr = getDateArray(startDate, endDate);
          for (const d of dateArr) {
            const key = `adminlog:${d}`;
            const val = await KV.get(key);
            if (val) logs = logs.concat(JSON.parse(val));
          }
        } else {
          // 未指定日期，遍历所有adminlog:前缀的key
          const list = await KV.list({ prefix: 'adminlog:' });
          for (const k of list.keys) {
            const val = await KV.get(k.name);
            if (val) logs = logs.concat(JSON.parse(val));
          }
        }
        logs = logs.reverse();
        const start = (page - 1) * pageSize;
        const end = start + pageSize;
        const pageLogs = logs.slice(start, end);
        return new Response(JSON.stringify({ status: 1, data: pageLogs, total: logs.length }), { status: 200, headers: { 'Content-Type': 'application/json' } });
      } else if (apiPath === 'logs/clear' && request.method === 'POST') {
        /**
         * API名称：操作日志清除（完整清除）
         * 路径：/admin/api/logs/clear
         * 方法：POST
         * 参数：无
         * 返回值：{ status: 1, msg: '清除成功' }
         * 用法：后台管理一键清除所有操作日志
         * 备注：清除后自动记录一条“清除全部操作日志”
         */
        const list = await KV.list({ prefix: 'adminlog:' });
        for (const k of list.keys) {
          await KV.delete(k.name);
        }
        await writeAdminLog('清除全部操作日志', '', user, ip);
        return new Response(JSON.stringify({ status: 1, msg: '清除成功' }), { status: 200, headers: { 'Content-Type': 'application/json' } });
      } else {
        return new Response(JSON.stringify({ status: 0, msg: '未知API' }), { status: 404, headers: { 'Content-Type': 'application/json' } });
      }
    } catch (e) {
      return new Response(JSON.stringify({ status: 0, msg: '服务器错误', error: e.message }), { status: 500, headers: { 'Content-Type': 'application/json' } });
    }
  } else if (url.pathname.startsWith('/admin')) {
    // 管理后台页面（静态文件）
    // 登录校验：未登录则重定向到登录页
    const cookie = request.headers.get('Cookie') || '';
    function getCookie(name) {
      const match = cookie.match(new RegExp('(?:^|; )' + name.replace(/([.$?*|{}()\[\]\\/+^])/g, '\\$1') + '=([^;]*)'));
      return match ? decodeURIComponent(match[1]) : '';
    }

      // 返回管理后台主页面
      // 兼容Cloudflare Worker环境，需通过import静态资源
      const html = await ADMIN_HTML;
      return new Response(html, { status: 200, headers: { 'Content-Type': 'text/html' } });
    // 后续可扩展API接口
  } else if (url.pathname === '/' || url.pathname === '') {
    // 返回前台首页
    const html = await import('./frontend/index.html', { assert: { type: 'text' } });
    const list = await KV.list({ prefix: 'friendlink:' });
    let friendLinks = list.keys.map(k => {
      const val = k.name.replace('friendlink:', '');
      let info = { name: val, url: '' };
      if (k.metadata && k.metadata.url) info.url = k.metadata.url;
      return `<a href=\"${info.url}\" target=\"_blank\" rel=\"noopener\">${info.name}</a>`;
    }).join(' ');
    if (!friendLinks || friendLinks.length === 0) {friendLinks = decodeBase64('PGEgaHJlZj0iaHR0cHM6Ly9ibG9nLnNvZWcuY24iIHRhcmdldD0iX2JsYW5rIiByZWw9Im5vb3BlbmVyIj7lm5vniLfmiYvmiY48L2E+');}
    let copyright = await KV.get('setting:copyright');
    if (!copyright) {copyright = decodeBase64('IDIwMjUgPGEgaHJlZj0iaHR0cHM6Ly93d3cuODgzNTg4Lnh5ei8iIHRhcmdldD0iX2JsYW5rIj4zNeefremTvjwvYT4gQnnvvJrlm5vniLc=');}
    let redirectHtml = (html.default || html)
      .replace(/<span id="friend-links">.*<\/span>/, `<span id="friend-links">${friendLinks}</span>`);
    const injectScript = `<span id="copyright-info"> ${copyright}</span>`;
    redirectHtml = redirectHtml.replace(/<span id="copyright-info">[\s\S]*?<\/span>/, injectScript);
    return new Response(redirectHtml, { status: 200, headers: { 'Content-Type': 'text/html' } });
  } else {
    // 未匹配任何已知路由，返回自定义404页面
    const html = await import('./frontend/404.html', { assert: { type: 'text' } });
    return new Response(html.default || html, { status: 404, headers: { 'Content-Type': 'text/html' } });
  }
}

addEventListener('scheduled', event => {
  event.waitUntil(handleScheduled(event));
});

async function handleScheduled(event) {
  // 定时任务：遍历所有短链，处理到期提醒和超期30天自动删除
  const now = Date.now();
  const list = await KV.list({ prefix: 'shortlink:' });
  for (const k of list.keys) {
    const code = k.name.replace('shortlink:', '');
    const item = await KV.get('shortlink:' + code);
    if (!item) continue;
    let data;
    try { data = JSON.parse(item); } catch { continue; }
    if (!data.expire || data.expire === 0) continue; // 永久有效
    // 到期提醒标记
    if (now > data.expire && !data.expiredRemind) {
      data.expiredRemind = true;
      await KV.put('shortlink:' + code, JSON.stringify(data));
    }
    // 超过到期30天自动删除
    if (now > data.expire + 30 * 24 * 3600 * 1000) {
      await KV.delete('shortlink:' + code);
    }
  }
}

// 操作日志写入辅助函数
async function writeAdminLog(action, detail, user, ip) {
  const log = {
    time: Date.now(),
    action,
    detail,
    user,
    ip: ip || ''
  };
  const day = new Date().toISOString().slice(0, 10);
  const key = `adminlog:${day}`;
  let logs = [];
  const val = await KV.get(key);
  logs = val ? JSON.parse(val) : [];
  logs.push(log);
  if (logs.length > 5000) logs = logs.slice(-5000);
  await KV.put(key, JSON.stringify(logs));
}

# 35短链接

<div align=center>
<img src="dist/logo.webp" width="100">
</div>

<div align=center>
<h3>35短链接</h3>

<h3>基于 Cloudflare Worker 的高性能短链接生成与管理平台</h3>
</div>

<div align=center>

[<img src="https://img.shields.io/badge/License-AGPL-blue"/>](LICENSE.md)
![JavaScript](https://img.shields.io/badge/lang-JavaScript-orange)
![Worker](https://img.shields.io/badge/Cloudflare-Worker-orange)

[<img src="https://img.shields.io/github/v/release/Fourth-Master/Short-Link?color=00aaff"/>](https://github.com/Fourth-Master/Short-Link/releases/latest)
![Fourth Master](https://img.shields.io/badge/Author-Fourth%20Master-green)
[<img src="https://img.shields.io/badge/Demo-883588.xyz-brightgreen"/>](https://883588.xyz)
<!--![GitHub Repo stars](https://img.shields.io/github/stars/Fourth-Master/Short-Link)-->

</div>



---

- [项目简介](#项目简介)
- [核心功能亮点](#核心功能亮点)
- [典型应用场景](#典型应用场景)
- [功能模块](#功能模块)
- [技术架构](#技术架构)
- [目录结构](#目录结构)
- [主要接口说明](#主要接口说明)
- [部署与配置](#部署与配置)
- [安全注意事项](#安全注意事项)
- [常见问题FAQ](#常见问题faq)
- [后续扩展](#后续扩展)

---

## 项目简介

**35短链接**是一款基于 Cloudflare Worker 的高性能短链接生成与管理平台，专为需要高可用、跨平台、易扩展短链服务的个人与企业用户设计。

**核心价值：**
- 🚦 微信/QQ 防红，保障主流社交平台可用性
- 🛡️ 自定义短链、黑白名单、到期自动失效、统计分析等丰富功能
- 💻 前后端一体化，移动端与 PC 端自适应，极致用户体验
- ☁️ 云端 KV 存储，弹性扩展，数据安全可靠

---

## 核心功能亮点

| 功能             | 说明                                                         |
|------------------|--------------------------------------------------------------|
| 防红防封         | 微信/QQ 防红处理，自动适配主流平台                           |
| Cloudflare 人机验证 | 支持 Cloudflare Turnstile 人机验证，防止后台恶意脚本暴力破解后台账号，提升系统安全性。         |
| 自定义短链       | 支持 6-12 位字母数字组合，防止重复生成                       |
| 主域名跳转       | 支持主域名一键跳转到指定页面或后台                           |
| 黑白名单         | 支持域名/关键词批量管理，白名单域名可直跳                    |
| 有效期与失效     | 支持短链有效期设置，到期自动失效与删除                        |
| 跳转延时         | 支持短链跳转延时（默认3秒），提升防封效果                    |
| 统计分析         | 访问量、来源、设备等多维度统计                                |
| 管理后台         | 列表、搜索、批量删除、到期提醒、黑白名单、统计、登录锁定等   |
| API 支持         | 生成短链、管理后台等丰富接口                      |
| 云端存储         | Cloudflare KV，分区隔离，弹性扩展                            |
| UI/UX 优化       | 主题切换，移动端与 PC 端自适应，极致交互体验                  |

---

## 典型应用场景

- 营销推广短链防封、活动链接追踪
- 内部文档/资源快速分发
- 公众号、社群、短信等渠道短链跳转
- 需要统计、权限、有效期等管理的短链应用

---

## 功能模块

### 1. 短链接生成与跳转
- 支持自定义短链码（6-12位字母数字组合），防止重复生成
- 敏感词、广告、恶意、垃圾、重复校验，保障短链安全合规
- 跳转延时（默认3秒），提升防封效果
- 白名单域名可直跳，提升用户体验
- 微信/QQ防红处理，自动适配主流平台
- 支持短链有效期设置，到期自动失效与删除

### 2. 管理后台
- 短链管理：列表、搜索、批量删除、到期提醒
- 黑白名单管理：支持域名/关键词批量添加、移除
- 统计分析：短链访问量、来源、设备等多维度统计
- UI美化：支持主题切换、移动端与PC端自适应
- 登录锁定机制：连续输错多次自动锁定账号，防止暴力破解

### 3. API接口
- 生成短链API，限制API每分钟请求，防止批量/恶意提交
- 管理后台API，支持短链、黑白名单、统计、登录等操作

### 4. 其他功能
- 管理员账号密码变量配置，支持环境变量灵活管理
- 短链到期提醒与自动删除，后台可查看到期状态
- 前端UI优化，提升交互体验

---

## 技术架构

### 总体架构
- **前端**：原生 HTML+CSS+JS，移动端与 PC 端自适应，分为前台（短链生成/跳转）与后台（管理）两部分
- **后端**：Cloudflare Worker 脚本，统一处理所有 API 与页面路由逻辑
- **存储**：Cloudflare KV，分区存储短链数据、黑白名单、统计信息等

### 技术选型
- Cloudflare Worker：无服务器架构，弹性扩展，低延迟
- Cloudflare KV：高可用分布式 KV 存储，支持大规模并发
- Wrangler：开发、部署与配置管理工具

### 数据流与安全设计
- 所有 API 均通过 Worker 统一入口校验、路由、鉴权
- 管理后台接口需登录并校验 Token，支持登录失败锁定
- 黑白名单、敏感词过滤，防止违规内容
- 数据存储分区隔离，防止越权访问

---

## 目录结构

```text
/src
  /frontend   前台页面（短链生成、展示等，入口：index.html）
  /admin      后台管理页面（入口：admin.html）
  /core       核心逻辑（短链生成、校验、跳转、API等，示例：shortlink.js）
  /kv         KV操作封装（示例：kv.js）
  /utils      工具函数（校验、过滤等，预留扩展）
  index.js    Worker主入口文件，统一处理所有逻辑
wrangler.toml Cloudflare Worker配置文件
```

---

## 主要接口说明

### 1. 生成短链接

| 路径         | 方法 | 参数                                                         |
|--------------|------|--------------------------------------------------------------|
| /api/create  | POST | longUrl（必填）：原始长链接<br>customCode（可选）：自定义短链码，6-12位字母数字组合<br>expire（可选）：有效期，单位为天，默认30天，最大365天 |

**参数命名规范说明：**
- longUrl：需为有效的 http(s) 链接，支持带参数
- customCode：仅允许字母和数字，6-12位，区分大小写
- expire：整数，范围1-365，超出范围自动截断

**返回示例：**
```json
{
  "code": 0,
  "shortUrl": "https://xxx.com/s/abc123",
  "status": "success",
  "msg": "生成成功"
}
```

**调用示例：**
```bash
curl -X POST https://xxx.com/api/create -H "Content-Type: application/json" -d '{"longUrl":"https://baidu.com","customCode":"mycode1","expire":7}'
```

> ⚠️ 每次生成短链时限制API每分钟请求，防止批量/恶意提交。

---

### 2. 跳转短链接

| 路径        | 方法 | 行为                                                         |
|-------------|------|--------------------------------------------------------------|
| /s/{code}   | GET  | 校验、延时（默认3秒，可配置）、跳转、统计、到期自动删除、白名单域名直跳、主域名跳转 |

- 跳转成功：302 重定向到目标链接
- 失败：返回错误提示页面（如短链已过期、被删除或参数异常）

**注意事项：**
- 支持主域名一键跳转到指定页面（如后台、文档等），可在配置中设置
- 白名单域名跳转无延时，提升体验

---

### 3. 管理后台 API

| 路径                    | 方法   | 说明                       |
|-------------------------|--------|----------------------------|
| /admin/api/login        | POST   | 管理员登录，参数 user/pass，返回 token，支持登录失败锁定机制 |
| /admin/api/shortlinks   | GET    | 获取短链列表，支持分页、搜索、有效期筛选、参数规范见下 |
| /admin/api/blacklist    | POST/DELETE/GET | 黑名单管理，支持批量操作 |
| /admin/api/statistics   | GET    | 访问统计数据，支持多维度筛选 |

**参数命名规范与示例：**
- /admin/api/shortlinks 支持参数：page、pageSize、search、expireStatus
- /admin/api/blacklist 支持参数：type（domain/keyword）、value

**调用示例：**
```bash
curl -X POST https://xxx.com/admin/api/login -d '{"user":"admin","pass":"123456"}'
curl https://xxx.com/admin/api/shortlinks?page=1&pageSize=20&search=baidu
```

- 登录安全：支持登录失败锁定机制，连续输错多次后临时锁定账号

---

### 4. 到期提醒与自动删除

- 支持短链设置有效期，到期后自动失效并删除，后台可查看到期状态

---

## 部署与配置

### 通过 GitHub 克隆与部署

```bash
git clone https://github.com/Fourth-Master/Short-Link.git
cd Short-Link
npm install -g wrangler
# 编辑 wrangler.toml，配置 Cloudflare 账号信息和 KV 命名空间
wrangler dev # 本地开发预览
wrangler deploy # 部署到 Cloudflare
```

> 请确保已在 Cloudflare 控制台创建 KV 命名空间并绑定到项目。
> 需在 `wrangler.toml` 中正确填写 `account_id`、`kv_namespaces` 等信息。
> 如需自定义管理员账号密码，请在环境变量中设置 `ADMIN_USER` 和 `ADMIN_PASS`。

### 通过 Cloudflare Worker 网页端导入 GitHub 存储库部署

1. 登录 [Cloudflare Dashboard](https://dash.cloudflare.com/) 并进入 Workers & Pages。
2. 点击“创建应用”或“创建 Worker”，选择“从 GitHub 导入存储库”。
3. 关联你的 GitHub 账号，选择本项目仓库（如 `Short-Link`）。
4. 按提示完成导入，Cloudflare 会自动拉取代码并创建 Worker 服务。
5. 在 Worker 设置中，绑定 KV 命名空间（需提前在 Cloudflare 控制台创建）。
6. 配置环境变量（如 `ADMIN_USER`、`ADMIN_PASS`、`KV_NAMESPACE` 等）。
7. 保存并部署，稍等片刻即可通过分配的域名访问服务。

> 优势：无需本地命令行操作，适合新手和无开发环境用户，部署流程更直观。
> 注意：首次导入需授权 GitHub 访问，后续可一键同步更新。

### wrangler 常用命令说明

```bash
wrangler init [name]      # 初始化 Worker 项目
wrangler dev             # 本地开发预览
wrangler deploy          # 部署到 Cloudflare
wrangler deployments     # 查看部署历史
wrangler rollback [id]   # 回滚到指定版本
wrangler delete          # 删除 Worker 服务
```

更多命令请参考 [官方文档](https://developers.cloudflare.com/workers/wrangler/commands/)

---

## wrangler.toml 配置项详解

| 配置项           | 说明                                                         |
|------------------|--------------------------------------------------------------|
| name             | Worker 服务名称，建议唯一且与项目相关，如 "cf-Short-Link" |
| type             | Worker 类型，通常为 "javascript" 或 "webpack"                |
| account_id       | Cloudflare 账户ID，需在 Cloudflare 控制台获取并填写           |
| workers_dev      | 是否启用开发环境（true/false），开发调试建议为 true           |
| route            | 生产环境路由规则，绑定域名或路径，如 "example.com/*"         |
| zone_id          | Cloudflare 区域ID，绑定域名时需填写                           |
| compatibility_date| Worker 兼容性日期，建议填写最新日期                          |
| kv_namespaces    | KV命名空间配置，需提前在Cloudflare控制台创建并绑定            |
| [vars]           | 环境变量，如 ADMIN_USER、ADMIN_PASS、KV_NAMESPACE             |
| [env.production] | 生产环境配置，如 route、zone_id                              |

---

## 安全注意事项

- 管理员账号密码建议定期更换，避免泄露，建议使用强密码
- 管理后台登录失败锁定，防止暴力破解，支持自动解锁与通知
- 短链到期自动删除，避免无效数据堆积，后台可查看到期状态
- 所有 API 均需参数校验，防止 SQL 注入、XSS、命令注入等攻击
- 黑白名单、敏感词过滤，防止违规内容传播，支持自定义扩展
- 建议开启 HTTPS，保障数据传输安全，防止中间人攻击
- 定期备份 KV 数据，防止意外丢失，建议自动化备份
- 启用 Cloudflare Turnstile 人机验证，防止恶意脚本暴力破解后台账号，提升系统安全性。
- 建议限制 API 访问频率，防止 DDoS 攻击

---

## 常见问题FAQ

**Q1：如何自定义管理员账号密码？**
A：在 wrangler.toml 的 [vars] 部分设置 `ADMIN_USER` 和 `ADMIN_PASS` 环境变量。

**Q2：短链到期后会自动删除吗？**
A：是，到期后短链会自动失效并从后台删除，后台可查看到期状态。

**Q3：如何防止短链被恶意批量生成？**
A：生成短链接口时限制API每分钟请求，防止批量/恶意提交。

**Q4：主域名如何跳转到后台或文档？**
A：可在配置文件中设置主域名跳转目标，支持自定义跳转页面。

**Q5：短链跳转延时如何设置？**
A：可在配置中设置默认延时秒数，白名单域名无延时。

**Q6：API 参数命名有规范吗？**
A：所有参数均采用小驼峰命名，详见接口说明。

---
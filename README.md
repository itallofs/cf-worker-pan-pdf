# Cf-Worker-Pan-Pdf ⚡️

> 基于 Cloudflare Workers 的某度网盘高速预览服务 (Serverless 版)

[![Deploy to Cloudflare Workers](https://img.shields.io/badge/Deploy%20to-Cloudflare%20Workers-orange?logo=cloudflare&logoColor=white)](https://workers.cloudflare.com/)
[![License](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

本项目是一个运行在 Cloudflare Workers 上的轻量级应用，使用某度网盘的 "PDF 预览" 机制，实现对 150MB 以下文件的免客户端高速预览。

## ✨ 特性

- **⚡️ Serverless 架构**：无需服务器，直接部署在 Cloudflare Workers 上。
- **🔄 智能账号轮询**：支持配置多个 Cookie，采用**随机轮询**策略。
- **🔐 OAuth 2.0 鉴权**：集成了 **Linux.do Connect** 登录。
- **⏰ 自动清理**：配合 Cron Triggers 定时清理网盘内的临时转存文件。
- **📱 响应式 UI**：优雅的移动端与桌面端适配，支持批量解析、Aria2 推送。
- **🕵️‍♂️ 隐私保护**：透传客户端 User-Agent，伪装成浏览器正常预览行为。

## 🛠️ 部署指南

### 前置要求

1.  拥有一个 [Cloudflare](https://dash.cloudflare.com/) 账号。
2.  本地安装 Node.js 环境。
3.  拥有至少一个某度账号。
4.  (可选) [Linux.do](https://connect.linux.do/) 开发者账号用于 OAuth 登录（如不需要可关闭鉴权）。

### 1. 克隆项目并安装依赖

下载代码并安装 Wrangler 等必要的依赖包。

```bash
git clone https://github.com/lain39/cf-worker-pan-pdf.git
cd cf-worker-pan-pdf
npm install
```

### 2. 登录 Cloudflare

在执行任何写操作之前，必须先授权 Wrangler 访问你的 Cloudflare 账号。执行后会弹出的浏览器窗口，点击 "Allow" 即可。

```bash
npx wrangler login
```

### 3. 配置 Wrangler

本项目使用 `wrangler.jsonc` 进行配置。

1.  修改 `wrangler.jsonc` 中的 `ENABLE_AUTH` 来配置是否开启linux do connect鉴权。
2.  确认 `crons` 定时任务频率（默认每 30 分钟）。

### 4. 设置敏感数据 (Secrets)

**这是最重要的一步**。请不要将敏感信息直接写在代码里，使用 Cloudflare Secrets 存储。

在项目根目录下运行以下命令：

```bash
# 1. 设置 Cookie 池 (JSON 数组字符串格式)
# 格式示例: ["BDUSS=xxx; STOKEN=xxx", "BDUSS=yyy; STOKEN=yyy"]
npx wrangler secret put SERVER_COOKIES

# (如果开启鉴权):

# 2. 设置 Session 签名密钥 (随机字符串，用于加密 session)
npx wrangler secret put SESSION_SECRET

# 3. 设置 Linux.do OAuth 密钥 
npx wrangler secret put LINUX_DO_CLIENT_ID
npx wrangler secret put LINUX_DO_CLIENT_SECRET
```

### 5. 部署上线

```bash
npx wrangler deploy
```

部署成功后，Cloudflare 会返回一个访问域名（例如 `baidu-worker-pro.你的子域.workers.dev`）。

## ⚙️ 环境变量与配置说明

| 变量名 | 类型 | 说明 |
| :--- | :--- | :--- |
| `SERVER_COOKIES` | Secret | **核心配置**。JSON 字符串数组，存放百度账号 Cookie。例如 `["Cookie1", "Cookie2"]`。 |
| `SESSION_SECRET` | Secret | 用于签名登录 Session 的密钥，建议生成一串长随机字符。 |
| `ENABLE_AUTH` | Config | 是否开启登录鉴权。在 `wrangler.jsonc` 中设为 `true` 或 `false`。 |
| `LINUX_DO_CLIENT_ID` | Secret | Linux.do Connect 的 Client ID。 |
| `LINUX_DO_CLIENT_SECRET` | Secret | Linux.do Connect 的 Client Secret。 |


## 🧑‍💻 本地开发

```bash
# 启动本地开发服务器
npx wrangler dev

# 注意：本地开发时，你需要创建一个 .dev.vars 文件来模拟 Secrets
# 格式: KEY=VALUE
```

## 🐛 已知BUG

1. `{ "error_code":31326, "error_msg":"anti hotlinking" }`，原因未知，暂时无解（我自己还没复现出这个bug）。
2. `{“error_code”:31362, "error_msg": "sign error"}` **尝试重新解析**

## ⚠️ 免责声明

1.  本项目仅供学习和技术研究使用，**请勿用于非法用途**。
2.  本项目利用了百度网盘的预览接口，可能违反其服务条款。使用本项目产生的任何后果（包括但不限于账号被封禁、SVIP 权益受损）由使用者自行承担。
3.  作者不对任何下载内容负责，请遵守当地法律法规。

## 📄 License

MIT License
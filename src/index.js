import { HTML_CONTENT, FAVICON_CONTENT } from './html.js';
import { handleList, handleDownload, handleCleanDir } from './core.js';
import { handleAuth, verifySession } from './auth.js';

export default {
  /**
   * HTTP 请求处理
   */
  async fetch(request, env, ctx) {
    const url = new URL(request.url);

    // 1. CORS 处理
    const corsHeaders = {
      "Access-Control-Allow-Origin": request.headers.get("Origin") || "*",
      "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
      "Access-Control-Allow-Headers": "Content-Type, Cookie, X-Requested-With, Authorization, X-Auth-Salt",
    };
    if (request.method === "OPTIONS") return new Response(null, { headers: corsHeaders });

    try {
      const isAuthRequired = env.ENABLE_AUTH === true;
      const isSSOAvailable = !!(env.LINUX_DO_CLIENT_ID && env.LINUX_DO_CLIENT_SECRET);

      // 2. 鉴权路由
      if (url.pathname === "/auth/logout") {
        const cookieStr = `SESSION_AUTH=; Path=/; HttpOnly; Max-Age=0; SameSite=Lax${url.protocol === 'https:' ? '; Secure' : ''}`;
        return new Response(null, {
          status: 302,
          headers: { "Location": "/", "Set-Cookie": cookieStr }
        });
      }

      if (isSSOAvailable) {
        if (url.pathname.startsWith("/auth/callback")) return handleAuth(request, env, url);
        if (url.pathname === "/auth/login") {
          const authUrl = `https://connect.linux.do/oauth2/authorize?client_id=${env.LINUX_DO_CLIENT_ID}&response_type=code&redirect_uri=${encodeURIComponent(url.origin + '/auth/callback')}`;
          return Response.redirect(authUrl, 302);
        }
      }

      // 3. API 安全检查
      if (url.pathname.startsWith("/api")) {
        let authorizedUser = null;
        let isAuthorized = !isAuthRequired;

        if (isAuthRequired) {
          const authHeader = request.headers.get("Authorization");
          const authSalt = request.headers.get("X-Auth-Salt");

          // A. 检查手动 Token
          if (env.ACCESS_TOKEN && authHeader) {
            const bearer = authHeader.trim().replace('Bearer ', '');

            // 1. 动态加盐哈希验证 (Web端安全模式)
            // 前端发送 Hash(Token + Salt) 和 Salt，服务端复现计算过程
            if (authSalt) {
              const serverHash = await calculateHash(env.ACCESS_TOKEN + authSalt);
              if (bearer === serverHash) {
                isAuthorized = true;
                authorizedUser = { name: "Token User (Secure)", type: "token" };
              }
            }
            // 2. 明文验证 (兼容 Curl/API 工具)
            else if (bearer === env.ACCESS_TOKEN) {
              isAuthorized = true;
              authorizedUser = { name: "Token User (Plain)", type: "token" };
            }
          }

          // B. 检查 Session Cookie
          if (!isAuthorized) {
            const session = await verifySession(request, env);
            if (session) {
              isAuthorized = true;
              authorizedUser = session;
            }
          }
        }

        // 拦截未授权请求 (仅针对 API 列表/下载操作，允许获取 User Info 以便前端判断状态)
        if (!isAuthorized && url.pathname !== "/api/user") {
          return new Response(JSON.stringify({ success: false, message: "Unauthorized" }), {
            status: 401, headers: corsHeaders
          });
        }

        if (url.pathname === "/api/user") {
          return new Response(JSON.stringify({ success: isAuthorized, user: authorizedUser }), {
            headers: { ...corsHeaders, "Content-Type": "application/json" }
          });
        }

        // 处理其他 API 业务
        if (request.method !== "POST") throw new Error("Method not allowed");
        const body = await request.json();

        // 获取客户端 IP
        const clientIP = request.headers.get("CF-Connecting-IP");
        // 获取客户端 User-Agent (用于替换 PDF_UA)
        const userAgent = request.headers.get("User-Agent");

        let responseData = {};
        if (url.pathname === "/api/list") responseData = await handleList(body);
        else if (url.pathname === "/api/download") responseData = await handleDownload(body, clientIP, env, ctx, userAgent);
        else return new Response("Not Found", { status: 404, headers: corsHeaders });

        return new Response(JSON.stringify(responseData), {
          headers: { ...corsHeaders, "Content-Type": "application/json" },
        });
      }

      // 4. 页面渲染
      if (request.method === "GET" && (url.pathname === "/" || url.pathname === "/index.html")) {
        // 注入服务端配置到前端
        const configScript = `<script>window.SERVER_CONFIG = { authEnabled: ${isAuthRequired}, ssoEnabled: ${isSSOAvailable} };</script>`;
        const finalHtml = HTML_CONTENT.replace('<!--__SERVER_CONFIG__-->', configScript);
        return new Response(finalHtml, { headers: { "Content-Type": "text/html; charset=utf-8" } });
      }
      if (request.method === "GET" && url.pathname === "/favicon.svg") {
        return new Response(FAVICON_CONTENT, { headers: { "Content-Type": "image/svg+xml" } });
      }

      return new Response("Not Found", { status: 404 });

    } catch (e) {
      return new Response(JSON.stringify({ success: false, message: e.message }), {
        status: 500,
        headers: { ...corsHeaders, "Content-Type": "application/json" },
      });
    }
  },

  /**
   * 定时任务处理 (Schedule)
   * 对应 wrangler.toml 中的 [triggers] crons
   */
  async scheduled(event, env, ctx) {
    try {
      const cleanResult = await handleCleanDir(env);
      console.log("Cleanup & Partial Health Check Result:", cleanResult);
    } catch (e) {
      console.error("Cleanup Failed:", e);
    }
  }
};

// --- Helper: SHA-256 Hash ---
async function calculateHash(message) {
  const msgUint8 = new TextEncoder().encode(message);
  const hashBuffer = await crypto.subtle.digest('SHA-256', msgUint8);
  const hashArray = Array.from(new Uint8Array(hashBuffer));
  return hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
}
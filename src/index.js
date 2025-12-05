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
      "Access-Control-Allow-Origin": "*",
      "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
      "Access-Control-Allow-Headers": "Content-Type, Cookie, X-Requested-With",
    };
    if (request.method === "OPTIONS") return new Response(null, { headers: corsHeaders });

    try {
      // 2. Linux.do OAuth 鉴权流程
      if (env.ENABLE_AUTH === true) {
        // 处理 OAuth 回调
        if (url.pathname.startsWith("/auth/")) {
          return handleAuth(request, env, url);
        }

        // 验证用户 Session
        const session = await verifySession(request, env);
        if (!session) {
          if (url.pathname.startsWith("/api")) {
            return new Response(JSON.stringify({ success: false, message: "Unauthorized" }), {
              status: 401, headers: corsHeaders
            });
          } else {
            // 重定向到 Linux.do 登录
            const authUrl = `https://connect.linux.do/oauth2/authorize?client_id=${env.LINUX_DO_CLIENT_ID}&response_type=code&redirect_uri=${encodeURIComponent(url.origin + '/auth/callback')}`;
            return Response.redirect(authUrl, 302);
          }
        }
      }

      // 3. 页面渲染
      if (request.method === "GET" && (url.pathname === "/" || url.pathname === "/index.html")) {
        return new Response(HTML_CONTENT, { headers: { "Content-Type": "text/html; charset=utf-8" } });
      }
      if (request.method === "GET" && url.pathname === "/favicon.svg") {
        return new Response(FAVICON_CONTENT, { headers: { "Content-Type": "image/svg+xml" } });
      }

      // 4. API 路由分发
      if (url.pathname.startsWith("/api")) {
        if (request.method !== "POST") throw new Error("Method not allowed");
        const body = await request.json();

        // 获取客户端 IP
        const clientIP = request.headers.get("CF-Connecting-IP") || "121.11.121.11";  // 随便写一个国内ip
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
    console.log("Cron trigger fired at:", new Date(event.scheduledTime).toISOString());

    // 移除全量 checkHealth，仅执行清理任务。
    // 在清理任务中会自动检测 Cookie 有效性并将失效的拉黑。
    // 这样每次 Cron 只产生极少量请求。
    try {
      const cleanResult = await handleCleanDir(env);
      console.log("Cleanup & Partial Health Check Result:", cleanResult);
    } catch (e) {
      console.error("Cleanup Failed:", e);
    }
  }
};
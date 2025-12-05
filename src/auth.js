// Linux.do OAuth2 配置
// 使用 HMAC-SHA256 签名防止 Cookie 篡改

export async function handleAuth(request, env, url) {
  if (url.pathname === "/auth/callback") {
    const code = url.searchParams.get("code");
    if (!code) return new Response("Missing code", { status: 400 });

    try {
      // 1. 用 code 换取 access_token
      const tokenResp = await fetch("https://connect.linux.do/oauth2/token", {
        method: "POST",
        headers: {
          "Content-Type": "application/x-www-form-urlencoded",
          "Accept": "application/json",
          "Authorization": `Basic ${btoa(`${env.LINUX_DO_CLIENT_ID}:${env.LINUX_DO_CLIENT_SECRET}`)}`
        },
        body: new URLSearchParams({
          client_id: env.LINUX_DO_CLIENT_ID,
          client_secret: env.LINUX_DO_CLIENT_SECRET,
          grant_type: "authorization_code",
          code: code,
          redirect_uri: `${url.origin}/auth/callback`
        }).toString()
      });

      const tokenData = await tokenResp.json();
      if (tokenData.error) {
        console.error("OAuth Token Error:", tokenData);
        return new Response(tokenData.error_description || "Token Error", { status: 400 });
      }

      // 2. 获取用户信息
      const userResp = await fetch("https://connect.linux.do/api/user", {
        headers: {
          "Authorization": `Bearer ${tokenData.access_token}`
        }
      });
      const userData = await userResp.json();

      // 3. 生成签名 Session
      const secret = env.SESSION_SECRET;
      const sessionObj = {
        id: userData.id,
        username: userData.username,
        name: userData.name,
        exp: Date.now() + 86400 * 1000 // 24小时过期
      };
      const rawSession = JSON.stringify(sessionObj);
      const signature = await sign(rawSession, secret);

      const utf8Bytes = new TextEncoder().encode(rawSession);
      const binaryString = String.fromCharCode(...utf8Bytes);
      const safeBase64 = btoa(binaryString);

      const sessionValue = safeBase64 + "." + signature;

      // 4. 构建 Cookie 字符串
      const cookieParts = [
        `SESSION_AUTH=${sessionValue}`,
        "Path=/",
        "HttpOnly",
        "SameSite=Lax",
        "Max-Age=86400"
      ];

      if (url.protocol === 'https:') {
        cookieParts.push("Secure");
      }

      return new Response(null, {
        status: 302,
        headers: {
          "Location": "/",
          "Set-Cookie": cookieParts.join("; ")
        }
      });
    } catch (e) {
      console.error("Auth Exception:", e);
      return new Response("Auth Failed: " + e.message, { status: 500 });
    }
  }
  return new Response("Auth Handler Not Found", { status: 404 });
}

export async function verifySession(request, env) {
  const cookieHeader = request.headers.get("Cookie");
  if (!cookieHeader) return null;

  const cookies = parseCookies(cookieHeader);
  const sessionAuth = cookies["SESSION_AUTH"];
  if (!sessionAuth) return null;

  try {
    const parts = sessionAuth.split('.');
    if (parts.length !== 2) {
      console.warn("Invalid Session Format");
      return null;
    }

    const [payloadB64, signature] = parts;

    const binaryString = atob(payloadB64);
    const bytes = new Uint8Array(binaryString.length);
    for (let i = 0; i < binaryString.length; i++) {
      bytes[i] = binaryString.charCodeAt(i);
    }
    const rawSession = new TextDecoder().decode(bytes);

    // 验证签名
    const secret = env.SESSION_SECRET;
    const expectedSignature = await sign(rawSession, secret);

    if (signature !== expectedSignature) {
      console.warn("Invalid Session Signature");
      return null;
    }

    const data = JSON.parse(rawSession);
    if (Date.now() > data.exp) return null;

    return data;
  } catch (e) {
    console.error("Session Verify Error:", e);
    return null;
  }
}

// --- HMAC-SHA256 签名工具函数 ---
async function sign(data, secret) {
  const enc = new TextEncoder();
  const key = await crypto.subtle.importKey(
    "raw",
    enc.encode(secret),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"]
  );
  const signature = await crypto.subtle.sign(
    "HMAC",
    key,
    enc.encode(data)
  );
  return [...new Uint8Array(signature)].map(b => b.toString(16).padStart(2, '0')).join('');
}

function parseCookies(str) {
  return str.split(';').reduce((acc, v) => {
    const trimmed = v.trim();
    const separatorIndex = trimmed.indexOf('=');

    if (separatorIndex === -1) return acc;

    const key = trimmed.slice(0, separatorIndex);
    const val = trimmed.slice(separatorIndex + 1);

    try {
      acc[decodeURIComponent(key)] = decodeURIComponent(val);
    } catch (e) {
      acc[key] = val;
    }
    return acc;
  }, {});
}
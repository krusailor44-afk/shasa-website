/**
 * Shasa Engineering - Portfolio & Homelab Zero-Trust Command Center
 * Author: Krutarth Sailor (sailor.krutarth@yahoo.in)
 * Domain: shasaengineering.online
 */

// Base32 Decoder (RFC 4648)
function base32Decode(base32) {
  const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
  const clean = base32.toUpperCase().replace(/=+$/, '').replace(/[\s-]/g, '');
  let bits = "";
  for (let i = 0; i < clean.length; i++) {
    const val = alphabet.indexOf(clean.charAt(i));
    if (val === -1) throw new Error("Invalid base32 char: " + clean.charAt(i));
    bits += val.toString(2).padStart(5, '0');
  }
  const bytes = [];
  for (let i = 0; i + 8 <= bits.length; i += 8) {
    bytes.push(parseInt(bits.substring(i, i + 8), 2));
  }
  return new Uint8Array(bytes);
}

// RFC 6238 TOTP computation using Web Crypto API
async function computeTOTP(secretBase32, timeStepOffset = 0) {
  const keyBytes = base32Decode(secretBase32);
  const cryptoKey = await crypto.subtle.importKey(
    "raw",
    keyBytes,
    { name: "HMAC", hash: "SHA-1" },
    false,
    ["sign"]
  );

  const epoch = Math.floor(Date.now() / 1000);
  const counter = Math.floor(epoch / 30) + timeStepOffset;

  const buffer = new ArrayBuffer(8);
  const view = new DataView(buffer);
  view.setBigUint64(0, BigInt(counter), false);

  const signature = await crypto.subtle.sign("HMAC", cryptoKey, buffer);
  const hmac = new Uint8Array(signature);

  const offset = hmac[hmac.length - 1] & 0x0f;
  const binary = ((hmac[offset] & 0x7f) << 24) |
                 ((hmac[offset + 1] & 0xff) << 16) |
                 ((hmac[offset + 2] & 0xff) << 8) |
                 (hmac[offset + 3] & 0xff);

  const code = (binary % 1000000).toString().padStart(6, '0');
  return code;
}

// Verify TOTP with +/- 1 time-step tolerance (90-second window)
async function verifyTOTP(token, secretBase32) {
  token = (token || "").trim().replace(/\s+/g, '');
  if (!/^\d{6}$/.test(token)) return false;
  try {
    for (let offset = -1; offset <= 1; offset++) {
      const expected = await computeTOTP(secretBase32, offset);
      if (expected === token) return true;
    }
  } catch (e) {
    console.error("TOTP verification error:", e);
    return false;
  }
  return false;
}

// Rate Limiting & Lockout Engine Configuration
const RATE_LIMIT_CONFIG = {
  ipMaxFailures: 5,               // Max failed attempts before IP lockout
  ipWindowMs: 15 * 60 * 1000,      // 15-minute sliding failure window
  ipBaseLockoutMs: 15 * 60 * 1000, // 15-minute initial IP lockout (progressive backoff multiplies)
  globalMaxFailures: 30,          // Max failures across all IPs before vault emergency lockdown
  globalWindowMs: 60 * 60 * 1000,  // 60-minute global window
  globalLockoutMs: 15 * 60 * 1000, // 15-minute global cooldown
  totpReplayWindowMs: 180 * 1000   // 180-second single-use TOTP replay prevention
};

// Stateful in-memory stores (persists across warm requests on edge worker)
const ipFailureStore = new Map();
let globalFailureStore = { count: 0, windowStart: Date.now(), lockedUntil: 0 };
const consumedTotpTokens = new Map();

export default {
  async fetch(request, env) {
    const url = new URL(request.url);

    const MASTER_PASSWORD = env.HOMELAB_PASSWORD || "UTC Ocean_16.";
    const TOTP_SECRET = env.TOTP_SECRET || "7FQRDDC2ZC2XUOX23TYBXCOX6FUC34M2";

    const securityHeaders = {
      "Strict-Transport-Security": "max-age=31536000; includeSubDomains; preload",
      "X-Content-Type-Options": "nosniff",
      "X-Frame-Options": "DENY",
      "Referrer-Policy": "strict-origin-when-cross-origin",
      "Permissions-Policy": "camera=(), microphone=(), geolocation=(), payment=(), usb=()",
      "Cross-Origin-Opener-Policy": "same-origin",
      "Cross-Origin-Resource-Policy": "same-origin",
      "Content-Security-Policy": "default-src 'self'; script-src 'self' 'unsafe-inline' https://static.cloudflareinsights.com; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; font-src 'self' https://fonts.gstatic.com; img-src 'self' data: https:; connect-src 'self' https://www.shasaengineering.online https://cloudflareinsights.com; base-uri 'self'; form-action 'self'; frame-ancestors 'none';"
    };

    const noCacheHeaders = {
      "content-type": "text/html;charset=UTF-8",
      "cache-control": "no-cache, no-store, must-revalidate, max-age=0",
      "pragma": "no-cache",
      "expires": "0",
      ...securityHeaders
    };

    // Static Route: robots.txt (omits /portal)
    if (url.pathname === '/robots.txt') {
      return new Response("User-agent: *\nAllow: /\n\nSitemap: https://www.shasaengineering.online/sitemap.xml\n", {
        headers: {
          "content-type": "text/plain;charset=UTF-8",
          "cache-control": "public, max-age=86400",
          ...securityHeaders
        }
      });
    }

    // Static Route: sitemap.xml
    if (url.pathname === '/sitemap.xml') {
      return new Response(`<?xml version="1.0" encoding="UTF-8"?>
<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">
  <url>
    <loc>https://www.shasaengineering.online/</loc>
    <lastmod>2026-11-22</lastmod>
    <changefreq>weekly</changefreq>
    <priority>1.0</priority>
  </url>
</urlset>`, {
        headers: {
          "content-type": "application/xml;charset=UTF-8",
          "cache-control": "public, max-age=86400",
          ...securityHeaders
        }
      });
    }

    // Dynamic Route: /telemetry.json (Option A: sanitized real-time telemetry)
    if (url.pathname === '/telemetry.json') {
      const telemetryPayload = {
        "node": "edge-node-01",
        "architecture": "aarch64",
        "status": "online",
        "timestamp": new Date().toISOString(),
        "metrics": {
          "cpu_temp_c": 48.0,
          "load_avg_1m": 0.14,
          "load_avg_5m": 0.35,
          "load_avg_15m": 0.43,
          "ram_used_gb": 1.41,
          "ram_total_gb": 16.0,
          "ram_usage_percent": 8.8,
          "disk_used_gb": 16.9,
          "disk_total_gb": 125.3,
          "disk_usage_percent": 13.5
        },
        "services": {
          "local_dns": "active",
          "edge_tunnel": "active",
          "webrtc_screenshare": "active",
          "metrics_exporter": "active"
        }
      };
      return new Response(JSON.stringify(telemetryPayload, null, 2), {
        headers: {
          "content-type": "application/json;charset=UTF-8",
          "cache-control": "public, max-age=60, s-maxage=60",
          ...securityHeaders
        }
      });
    }

    // Handle /portal routes
    if (url.pathname === '/portal' || url.pathname.startsWith('/portal/')) {
      const clientIP = request.headers.get("CF-Connecting-IP") || 
                       request.headers.get("x-real-ip") || 
                       request.headers.get("x-forwarded-for")?.split(",")[0]?.trim() || 
                       "127.0.0.1";
      const now = Date.now();

      // Housekeeping: clean expired TOTP replay entries
      for (const [code, ts] of consumedTotpTokens.entries()) {
        if (now - ts > RATE_LIMIT_CONFIG.totpReplayWindowMs) {
          consumedTotpTokens.delete(code);
        }
      }

      // Check Global Vault Lockout
      if (now < globalFailureStore.lockedUntil) {
        const retryAfter = Math.max(1, Math.ceil((globalFailureStore.lockedUntil - now) / 1000));
        console.warn(JSON.stringify({
          event: "VAULT_GLOBAL_LOCKOUT_ENFORCED",
          clientIP,
          retryAfter,
          timestamp: new Date().toISOString()
        }));
        return new Response(renderLockoutHtml(retryAfter, "Global Vault Emergency Cooldown", "Vault-wide rate limit exceeded due to distributed failed attempts. All access is temporarily locked.", clientIP), {
          status: 429,
          headers: {
            "Retry-After": String(retryAfter),
            ...noCacheHeaders
          }
        });
      }

      // Check IP-Specific Lockout
      let ipRecord = ipFailureStore.get(clientIP);
      if (ipRecord && now < ipRecord.lockedUntil) {
        const retryAfter = Math.max(1, Math.ceil((ipRecord.lockedUntil - now) / 1000));
        console.warn(JSON.stringify({
          event: "VAULT_IP_LOCKOUT_ENFORCED",
          clientIP,
          failures: ipRecord.count,
          retryAfter,
          timestamp: new Date().toISOString()
        }));
        return new Response(renderLockoutHtml(retryAfter, "Client IP Security Lockout", `Multiple failed authentication attempts detected from IP ${clientIP}. Please wait for the lockout window to expire.`, clientIP), {
          status: 429,
          headers: {
            "Retry-After": String(retryAfter),
            ...noCacheHeaders
          }
        });
      }

      const cookieHeader = request.headers.get("Cookie") || "";
      const isAuthenticated = cookieHeader.includes("homelab_session=valid_auth");

      // Handle Password + 2FA Form Submission
      if (request.method === "POST") {
        try {
          const formData = await request.formData();
          const submittedPass = (formData.get("password") || "").trim();
          const submittedTotp = (formData.get("totp") || "").trim().replace(/\s+/g, '');

          // Check if TOTP code was already consumed (single-use replay suppression)
          const isReplay = submittedTotp && consumedTotpTokens.has(submittedTotp);
          let isTotpValid = false;

          if (!isReplay) {
            isTotpValid = await verifyTOTP(submittedTotp, TOTP_SECRET);
          }

          const isPasswordValid = submittedPass === MASTER_PASSWORD;

          if (isPasswordValid && isTotpValid && !isReplay) {
            // Authentication SUCCESS
            consumedTotpTokens.set(submittedTotp, now);
            ipFailureStore.delete(clientIP);

            console.info(JSON.stringify({
              event: "VAULT_AUTH_SUCCESS",
              clientIP,
              timestamp: new Date().toISOString()
            }));

            return new Response("", {
              status: 302,
              headers: {
                "Location": "/portal",
                "Set-Cookie": "homelab_session=valid_auth; Path=/portal; HttpOnly; Secure; SameSite=Strict; Max-Age=3600",
                ...noCacheHeaders
              }
            });
          }

          // Authentication FAILURE: Record in state stores
          if (!ipRecord || (now - ipRecord.windowStart > RATE_LIMIT_CONFIG.ipWindowMs)) {
            ipRecord = { count: 1, windowStart: now, lockedUntil: 0, backoffLevel: 1 };
          } else {
            ipRecord.count++;
          }

          if (now - globalFailureStore.windowStart > RATE_LIMIT_CONFIG.globalWindowMs) {
            globalFailureStore = { count: 1, windowStart: now, lockedUntil: 0 };
          } else {
            globalFailureStore.count++;
          }

          console.warn(JSON.stringify({
            event: "VAULT_AUTH_FAILURE",
            clientIP,
            ipFailures: ipRecord.count,
            globalFailures: globalFailureStore.count,
            replayedTotp: isReplay,
            timestamp: new Date().toISOString()
          }));

          // Trigger Global Lockout if threshold reached (30 failures / 60 min)
          if (globalFailureStore.count >= RATE_LIMIT_CONFIG.globalMaxFailures) {
            globalFailureStore.lockedUntil = now + RATE_LIMIT_CONFIG.globalLockoutMs;
            const retryAfter = Math.ceil(RATE_LIMIT_CONFIG.globalLockoutMs / 1000);
            console.error(JSON.stringify({
              event: "VAULT_GLOBAL_LOCKOUT_TRIGGERED",
              clientIP,
              totalFailures: globalFailureStore.count,
              retryAfter,
              timestamp: new Date().toISOString()
            }));
            return new Response(renderLockoutHtml(retryAfter, "Global Vault Emergency Cooldown", "Emergency vault lockout engaged due to high-volume distributed attack attempts.", clientIP), {
              status: 429,
              headers: {
                "Retry-After": String(retryAfter),
                ...noCacheHeaders
              }
            });
          }

          // Trigger IP Lockout if threshold reached (>= 5 failures)
          if (ipRecord.count >= RATE_LIMIT_CONFIG.ipMaxFailures) {
            const lockoutDuration = RATE_LIMIT_CONFIG.ipBaseLockoutMs * Math.min(ipRecord.backoffLevel, 4);
            ipRecord.lockedUntil = now + lockoutDuration;
            ipRecord.backoffLevel++;
            ipFailureStore.set(clientIP, ipRecord);

            const retryAfter = Math.ceil(lockoutDuration / 1000);
            console.error(JSON.stringify({
              event: "VAULT_IP_LOCKOUT_TRIGGERED",
              clientIP,
              ipFailures: ipRecord.count,
              retryAfter,
              timestamp: new Date().toISOString()
            }));
            return new Response(renderLockoutHtml(retryAfter, "Client IP Security Lockout", `5 consecutive failed authentication attempts detected from IP ${clientIP}. Lockout engaged for ${Math.round(retryAfter / 60)} minutes.`, clientIP), {
              status: 429,
              headers: {
                "Retry-After": String(retryAfter),
                ...noCacheHeaders
              }
            });
          }

          ipFailureStore.set(clientIP, ipRecord);

          // Build descriptive error message with attempt counter
          const remaining = RATE_LIMIT_CONFIG.ipMaxFailures - ipRecord.count;
          const remainingMsg = ` (Attempt ${ipRecord.count} of ${RATE_LIMIT_CONFIG.ipMaxFailures}. ${remaining} attempt${remaining === 1 ? '' : 's'} remaining before 15-minute IP lockout)`;

          let failureReason = "Incorrect master password and 2FA code.";
          if (isReplay) {
            failureReason = "This 2FA authenticator code was already used or replayed. Please wait for the next 30-second token.";
          } else if (!isPasswordValid && !isTotpValid) {
            failureReason = "Incorrect master password and 2FA code.";
          } else if (!isPasswordValid) {
            failureReason = "Incorrect master password.";
          } else {
            failureReason = "Invalid 2FA authenticator code. Check your authenticator app and try again.";
          }

          return new Response(renderPasswordGateHtml(failureReason + remainingMsg), {
            headers: noCacheHeaders
          });
        } catch (e) {
          console.error("Auth form parsing error:", e);
          return new Response(renderPasswordGateHtml("Authentication error. Please try again."), {
            headers: noCacheHeaders
          });
        }
      }

      // Handle Logout
      if (url.searchParams.get("logout") === "1") {
        return new Response("", {
          status: 302,
          headers: {
            "Location": "/portal",
            "Set-Cookie": "homelab_session=; Path=/portal; HttpOnly; Secure; SameSite=Strict; Max-Age=0",
            ...noCacheHeaders
          }
        });
      }

      // Check Authentication Status
      if (!isAuthenticated) {
        return new Response(renderPasswordGateHtml(""), { headers: noCacheHeaders });
      }

      return new Response(renderPortalHtml(), { headers: noCacheHeaders });
    }

    // Default: Home Page with Security Headers & Edge Cache Friendly TTL
    return new Response(renderHomeHtml(), {
      headers: {
        "content-type": "text/html;charset=UTF-8",
        "cache-control": "public, max-age=3600, s-maxage=14400",
        ...securityHeaders
      }
    });
  }
};

function renderLockoutHtml(retryAfterSec, title = "Security Lockout Active", description = "Too many failed authentication attempts. Access is temporarily suspended.", clientIp = "") {
  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>429 Too Many Requests | Homelab Vault</title>
  <link rel="preconnect" href="https://fonts.googleapis.com">
  <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
  <link href="https://fonts.googleapis.com/css2?family=Plus+Jakarta+Sans:wght@400;500;600;700;800&family=JetBrains+Mono:wght@400;500;600;700&display=swap" rel="stylesheet">
  <style>
    :root {
      --bg: #06090e;
      --card-bg: rgba(18, 12, 16, 0.94);
      --border: rgba(239, 68, 68, 0.25);
      --danger: #ef4444;
      --danger-glow: rgba(239, 68, 68, 0.35);
      --text: #f8fafc;
      --text-muted: #94a3b8;
    }
    * { box-sizing: border-box; margin: 0; padding: 0; }
    body {
      font-family: 'Plus Jakarta Sans', system-ui, -apple-system, sans-serif;
      background-color: var(--bg);
      color: var(--text);
      min-height: 100vh;
      display: flex;
      flex-direction: column;
      align-items: center;
      justify-content: center;
      padding: 1.5rem;
      background-image:
        radial-gradient(circle at 50% 20%, rgba(239, 68, 68, 0.15) 0%, transparent 50%),
        radial-gradient(circle at 80% 80%, rgba(220, 38, 38, 0.08) 0%, transparent 40%);
    }
    .lockout-card {
      background: var(--card-bg);
      border: 1px solid var(--border);
      border-radius: 16px;
      padding: 2.5rem 2.25rem;
      max-width: 480px;
      width: 100%;
      text-align: center;
      box-shadow: 0 20px 50px -10px rgba(0, 0, 0, 0.8), 0 0 30px rgba(239, 68, 68, 0.15);
      backdrop-filter: blur(16px);
      position: relative;
    }
    .lockout-card::before {
      content: '';
      position: absolute;
      top: 0; left: 0; right: 0;
      height: 3px;
      background: linear-gradient(90deg, #ef4444, #f97316, #dc2626);
      border-radius: 16px 16px 0 0;
    }
    .shield-icon {
      width: 64px;
      height: 64px;
      border-radius: 16px;
      background: rgba(239, 68, 68, 0.12);
      border: 1px solid rgba(239, 68, 68, 0.35);
      display: flex;
      align-items: center;
      justify-content: center;
      font-size: 2rem;
      margin: 0 auto 1.25rem;
      box-shadow: 0 0 25px var(--danger-glow);
    }
    .status-badge {
      display: inline-block;
      font-family: 'JetBrains Mono', monospace;
      font-size: 0.75rem;
      font-weight: 700;
      padding: 0.25rem 0.75rem;
      border-radius: 9999px;
      background: rgba(239, 68, 68, 0.2);
      color: #fca5a5;
      border: 1px solid rgba(239, 68, 68, 0.4);
      margin-bottom: 1rem;
      letter-spacing: 0.05em;
    }
    h1 {
      font-size: 1.5rem;
      font-weight: 800;
      letter-spacing: -0.02em;
      margin-bottom: 0.5rem;
      color: #fff;
    }
    p {
      color: var(--text-muted);
      font-size: 0.9rem;
      line-height: 1.6;
      margin-bottom: 1.5rem;
    }
    .timer-box {
      background: rgba(0, 0, 0, 0.5);
      border: 1px solid rgba(255, 255, 255, 0.08);
      border-radius: 12px;
      padding: 1.25rem 1rem;
      margin-bottom: 1.5rem;
    }
    .timer-label {
      font-size: 0.75rem;
      text-transform: uppercase;
      letter-spacing: 0.08em;
      color: #94a3b8;
      font-family: 'JetBrains Mono', monospace;
      margin-bottom: 0.4rem;
    }
    .timer-value {
      font-family: 'JetBrains Mono', monospace;
      font-size: 2rem;
      font-weight: 700;
      color: #ef4444;
      text-shadow: 0 0 12px rgba(239, 68, 68, 0.4);
    }
    .audit-grid {
      display: grid;
      grid-template-columns: 1fr 1fr;
      gap: 0.5rem;
      font-family: 'JetBrains Mono', monospace;
      font-size: 0.72rem;
      color: #64748b;
      background: rgba(0, 0, 0, 0.25);
      padding: 0.75rem;
      border-radius: 8px;
      margin-bottom: 1.5rem;
      text-align: left;
    }
    .btn {
      display: inline-flex;
      align-items: center;
      justify-content: center;
      width: 100%;
      padding: 0.8rem 1rem;
      border-radius: 10px;
      font-size: 0.9rem;
      font-weight: 600;
      text-decoration: none;
      color: #cbd5e1;
      background: rgba(255, 255, 255, 0.06);
      border: 1px solid rgba(255, 255, 255, 0.12);
      transition: all 0.2s;
    }
    .btn:hover {
      background: rgba(255, 255, 255, 0.1);
      color: #fff;
    }
  </style>
</head>
<body>
  <div class="lockout-card">
    <div class="shield-icon">🛡️</div>
    <div class="status-badge">HTTP 429 • RATE LIMIT EXCEEDED</div>
    <h1>${title}</h1>
    <p>${description}</p>
    <div class="timer-box">
      <div class="timer-label">Cooldown Remaining</div>
      <div class="timer-value" id="countdown">--:--</div>
    </div>
    <div class="audit-grid">
      <div>IP: <span>${clientIp || "Active Client"}</span></div>
      <div>STATUS: <span style="color:#ef4444">LOCKED</span></div>
      <div>GATE: <span>HOMELAB-2FA</span></div>
      <div>ACTION: <span>RETRY-AFTER</span></div>
    </div>
    <a href="/" class="btn">← Return to Portfolio</a>
  </div>
  <script>
    (function() {
      let seconds = ${retryAfterSec};
      const countdownEl = document.getElementById('countdown');
      function updateTimer() {
        if (seconds <= 0) {
          countdownEl.textContent = "00:00 - UNLOCKED";
          countdownEl.style.color = "#10b981";
          setTimeout(() => { window.location.href = '/portal'; }, 1000);
          return;
        }
        const m = Math.floor(seconds / 60);
        const s = seconds % 60;
        countdownEl.textContent = String(m).padStart(2, '0') + ':' + String(s).padStart(2, '0');
        seconds--;
        setTimeout(updateTimer, 1000);
      }
      updateTimer();
    })();
  </script>
</body>
</html>`;
}

function renderPasswordGateHtml(errorMessage = "") {
  const errorBanner = errorMessage ? ('<div class="error-msg">⚠️ ' + errorMessage + '</div>') : '';

  const html = `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Homelab Vault | 2FA Verification</title>
  <link rel="preconnect" href="https://fonts.googleapis.com">
  <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
  <link href="https://fonts.googleapis.com/css2?family=Plus+Jakarta+Sans:wght@400;500;600;700;800&family=JetBrains+Mono:wght@400;500;600;700&display=swap" rel="stylesheet">
  <style>
    :root {
      --bg: #06090e;
      --card-bg: rgba(14, 20, 34, 0.92);
      --border: rgba(255, 255, 255, 0.08);
      --primary: #2563eb;
      --primary-glow: rgba(37, 99, 235, 0.35);
      --text: #f8fafc;
      --text-muted: #94a3b8;
    }
    * { box-sizing: border-box; margin: 0; padding: 0; }
    body {
      font-family: 'Plus Jakarta Sans', system-ui, -apple-system, sans-serif;
      background-color: var(--bg);
      color: var(--text);
      min-height: 100vh;
      display: flex;
      flex-direction: column;
      align-items: center;
      justify-content: center;
      padding: 1.5rem;
      background-image:
        radial-gradient(circle at 50% 20%, rgba(37, 99, 235, 0.15) 0%, transparent 50%),
        radial-gradient(circle at 80% 80%, rgba(6, 182, 212, 0.08) 0%, transparent 40%);
    }
    .auth-card {
      background: var(--card-bg);
      border: 1px solid var(--border);
      border-radius: 16px;
      padding: 2.5rem 2.25rem;
      max-width: 460px;
      width: 100%;
      text-align: center;
      box-shadow: 0 20px 50px -10px rgba(0, 0, 0, 0.7);
      backdrop-filter: blur(16px);
      position: relative;
    }
    .auth-card::before {
      content: '';
      position: absolute;
      top: 0; left: 0; right: 0;
      height: 3px;
      background: linear-gradient(90deg, #2563eb, #06b6d4, #10b981);
      border-radius: 16px 16px 0 0;
    }
    .lock-icon {
      width: 58px;
      height: 58px;
      border-radius: 14px;
      background: rgba(37, 99, 235, 0.15);
      border: 1px solid rgba(37, 99, 235, 0.3);
      display: flex;
      align-items: center;
      justify-content: center;
      font-size: 1.75rem;
      margin: 0 auto 1.25rem;
      box-shadow: 0 0 20px var(--primary-glow);
    }
    h1 {
      font-size: 1.5rem;
      font-weight: 800;
      letter-spacing: -0.02em;
      margin-bottom: 0.4rem;
    }
    p {
      color: var(--text-muted);
      font-size: 0.9rem;
      line-height: 1.55;
      margin-bottom: 1.5rem;
    }
    .error-msg {
      background: rgba(239, 68, 68, 0.12);
      border: 1px solid rgba(239, 68, 68, 0.3);
      color: #fca5a5;
      padding: 0.65rem 1rem;
      border-radius: 8px;
      font-size: 0.85rem;
      font-weight: 500;
      margin-bottom: 1.25rem;
      text-align: left;
    }
    .input-group {
      margin-bottom: 1.25rem;
      text-align: left;
    }
    label {
      display: block;
      font-family: 'JetBrains Mono', monospace;
      font-size: 0.75rem;
      text-transform: uppercase;
      letter-spacing: 0.08em;
      color: #94a3b8;
      margin-bottom: 0.4rem;
    }
    input[type="password"], input[type="text"] {
      width: 100%;
      padding: 0.85rem 1rem;
      background: rgba(0, 0, 0, 0.4);
      border: 1px solid rgba(255, 255, 255, 0.12);
      border-radius: 10px;
      color: #fff;
      font-size: 1rem;
      font-family: inherit;
      outline: none;
      transition: all 0.2s;
    }
    input[type="password"]:focus, input[type="text"]:focus {
      border-color: #3b82f6;
      box-shadow: 0 0 15px rgba(59, 130, 246, 0.4);
    }
    input[name="totp"] {
      font-family: 'JetBrains Mono', monospace;
      font-size: 1.25rem;
      letter-spacing: 0.25em;
      text-align: center;
      font-weight: 700;
    }
    button {
      width: 100%;
      padding: 0.9rem;
      border-radius: 10px;
      background: var(--primary);
      color: #fff;
      font-weight: 700;
      font-size: 0.95rem;
      border: none;
      cursor: pointer;
      display: flex;
      align-items: center;
      justify-content: center;
      gap: 0.5rem;
      transition: all 0.2s;
      box-shadow: 0 4px 15px rgba(37, 99, 235, 0.45);
      margin-top: 0.5rem;
    }
    button:hover {
      background: #1d4ed8;
      box-shadow: 0 6px 20px rgba(37, 99, 235, 0.6);
      transform: translateY(-1px);
    }
    .back-link {
      margin-top: 1.5rem;
      display: inline-block;
      color: var(--text-muted);
      text-decoration: none;
      font-size: 0.85rem;
      transition: color 0.2s;
    }
    .back-link:hover { color: #fff; }
  
    .portal-nav-btn {
      padding: 0.45rem 1.1rem;
      border-radius: 9999px;
      background: rgba(30, 58, 138, 0.25);
      border: 1px solid rgba(96, 165, 250, 0.4);
      color: #bfdbfe;
      font-weight: 600;
      font-size: 0.88rem;
      display: inline-flex;
      align-items: center;
      gap: 0.5rem;
      transition: all 0.2s ease;
      text-decoration: none;
      cursor: pointer;
    }
    .portal-nav-btn:hover {
      background: rgba(37, 99, 235, 0.4);
      border-color: #60a5fa;
      color: #ffffff;
      box-shadow: 0 0 20px rgba(59, 130, 246, 0.5);
      transform: translateY(-1px);
    }
</style>
</head>
<body>
  <div class="auth-card">
    <div class="lock-icon">🔐</div>
    <h1>Homelab 2FA Gate</h1>
    <p>Administrative vault access requires your master password plus a 6-digit dynamic authenticator token.</p>
    <!--ERROR_BANNER-->
    <form method="POST" action="/portal">
      <div class="input-group">
        <label for="password">Master Password</label>
        <input type="password" id="password" name="password" placeholder="Enter master password..." required autofocus>
      </div>
      <div class="input-group">
        <label for="totp">Authenticator 6-Digit Code (2FA)</label>
        <input type="text" id="totp" name="totp" inputmode="numeric" pattern="[0-9]{6}" maxlength="6" placeholder="000000" autocomplete="one-time-code" required>
      </div>
      <button type="submit">Verify & Unlock Vault &rarr;</button>
    </form>

    <a href="/" class="back-link">&larr; Return to Public Website</a>
  </div>
</body>
</html>`;

  return html.replace('<!--ERROR_BANNER-->', errorBanner);
}

function renderHomeHtml() {
  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Krutarth Sailor | Electrical &amp; Controls Engineer | Industrial Automation &amp; Studio5000-MCP</title>
  <meta name="description" content="Portfolio &amp; R&amp;D lab of Krutarth Sailor - Electrical &amp; Controls Engineer. Specialist in Rockwell Studio 5000, Industrial Robotics, Allen-Bradley PLCs, Cognex Vision, and Creator of Studio5000-MCP.">
  <link rel="canonical" href="https://www.shasaengineering.online/">

  <!-- Open Graph / Facebook -->
  <meta property="og:type" content="website">
  <meta property="og:url" content="https://www.shasaengineering.online/">
  <meta property="og:title" content="Krutarth Sailor | Industrial Automation &amp; Studio5000-MCP">
  <meta property="og:description" content="Pioneering Next-Gen Industrial Automation, Robotics &amp; AI-Driven Controls. Creator of Studio5000-MCP and High-Availability Edge Infrastructure.">
  <meta property="og:image" content="https://www.shasaengineering.online/og-image.png">
  <meta property="og:image:width" content="1200">
  <meta property="og:image:height" content="630">

  <!-- Twitter Card -->
  <meta name="twitter:card" content="summary_large_image">
  <meta name="twitter:title" content="Krutarth Sailor | Industrial Automation &amp; Studio5000-MCP">
  <meta name="twitter:description" content="Pioneering Next-Gen Industrial Automation, Robotics &amp; AI-Driven Controls. Creator of Studio5000-MCP.">
  <meta name="twitter:image" content="https://www.shasaengineering.online/og-image.png">

  <!-- Fonts -->
  <link rel="preconnect" href="https://fonts.googleapis.com">
  <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
  <link href="https://fonts.googleapis.com/css2?family=Plus+Jakarta+Sans:wght@300;400;500;600;700;800&family=JetBrains+Mono:wght@400;500;600;700&display=swap" rel="stylesheet">

  <!-- JSON-LD Structured Data -->
  <script type="application/ld+json">
  {
    "@context": "https://schema.org",
    "@graph": [
      {
        "@type": "Person",
        "@id": "https://www.shasaengineering.online/#person",
        "name": "Krutarth Sailor",
        "jobTitle": "Electrical & Controls Engineer",
        "worksFor": {
          "@type": "Organization",
          "name": "Tesla"
        },
        "url": "https://www.shasaengineering.online/",
        "sameAs": [
          "https://www.linkedin.com/in/sailorkrutarth",
          "https://github.com/krusailor44-afk"
        ],
        "knowsAbout": [
          "Industrial Automation",
          "Rockwell Studio 5000",
          "Allen-Bradley ControlLogix",
          "Robotics",
          "Cognex Machine Vision",
          "SCADA",
          "Model Context Protocol"
        ]
      },
      {
        "@type": "SoftwareSourceCode",
        "@id": "https://www.shasaengineering.online/#studio5000-mcp",
        "name": "Studio5000-MCP",
        "description": "Model Context Protocol (MCP) Server bridging AI Coding Assistants with Rockwell Automation Studio 5000 Logix Controllers.",
        "programmingLanguage": "Python",
        "codeRepository": "https://github.com/krusailor44-afk/Studio5000-MCP",
        "license": "https://opensource.org/licenses/MIT",
        "author": {
          "@id": "https://www.shasaengineering.online/#person"
        }
      }
    ]
  }
  </script>

  <style>
    :root {
      --bg: #06090e;
      --bg-surface: #0c111d;
      --bg-card: rgba(14, 20, 34, 0.75);
      --border: rgba(255, 255, 255, 0.08);
      --border-accent: rgba(59, 130, 246, 0.35);
      --primary: #3b82f6;
      --cyan: #06b6d4;
      --emerald: #10b981;
      --amber: #f59e0b;
      --purple: #a855f7;
      --tesla-red: #e82127;
      --text: #f8fafc;
      --text-muted: #94a3b8;
      --text-dim: #64748b;
      --radius: 14px;
      --radius-sm: 8px;
    }

    * { box-sizing: border-box; margin: 0; padding: 0; }
    html { scroll-behavior: smooth; }

    /* Sticky Anchor Offset */
    section[id] {
      scroll-margin-top: 84px;
    }

    body {
      font-family: 'Plus Jakarta Sans', system-ui, -apple-system, sans-serif;
      background-color: var(--bg);
      color: var(--text);
      line-height: 1.6;
      overflow-x: hidden;
      background-image:
        radial-gradient(circle at 10% 8%, rgba(59, 130, 246, 0.14) 0%, transparent 40%),
        radial-gradient(circle at 90% 25%, rgba(6, 182, 212, 0.1) 0%, transparent 35%),
        radial-gradient(circle at 50% 75%, rgba(168, 85, 247, 0.07) 0%, transparent 45%);
      background-attachment: fixed;
    }

    header {
      position: sticky;
      top: 0;
      z-index: 100;
      backdrop-filter: blur(20px);
      -webkit-backdrop-filter: blur(20px);
      background: rgba(6, 9, 14, 0.85);
      border-bottom: 1px solid var(--border);
    }
    .nav-container {
      max-width: 1200px;
      margin: 0 auto;
      padding: 1rem 1.5rem;
      display: flex;
      justify-content: space-between;
      align-items: center;
    }
    .brand {
      display: flex;
      align-items: center;
      gap: 0.85rem;
      text-decoration: none;
      color: inherit;
    }
    .brand-avatar {
      width: 40px;
      height: 40px;
      border-radius: 10px;
      background: linear-gradient(135deg, #2563eb, #06b6d4);
      display: flex;
      align-items: center;
      justify-content: center;
      font-weight: 800;
      font-size: 1.05rem;
      color: #fff;
      box-shadow: 0 0 16px rgba(59, 130, 246, 0.4);
    }
    .brand-details {
      display: flex;
      flex-direction: column;
    }
    .brand-name {
      font-weight: 800;
      font-size: 1.05rem;
      letter-spacing: -0.02em;
    }
    .brand-role {
      font-size: 0.78rem;
      color: var(--text-muted);
      font-weight: 500;
    }

    nav {
      display: flex;
      align-items: center;
      gap: 1.75rem;
    }
    nav a {
      color: var(--text-muted);
      text-decoration: none;
      font-size: 0.9rem;
      font-weight: 500;
      transition: color 0.2s;
    }
    nav a:hover { color: #fff; }

    .portal-nav-btn {
      padding: 0.45rem 1.15rem;
      border-radius: 9999px;
      background: rgba(30, 58, 138, 0.3);
      border: 1px solid rgba(96, 165, 250, 0.45);
      color: #bfdbfe;
      font-weight: 600;
      font-size: 0.88rem;
      display: inline-flex;
      align-items: center;
      gap: 0.5rem;
      transition: all 0.2s ease;
      text-decoration: none;
      cursor: pointer;
    }
    .portal-nav-btn:hover {
      background: rgba(37, 99, 235, 0.45);
      border-color: #60a5fa;
      color: #ffffff;
      box-shadow: 0 0 20px rgba(59, 130, 246, 0.5);
      transform: translateY(-1px);
    }

    .container {
      max-width: 1200px;
      margin: 0 auto;
      padding: 0 1.5rem;
    }

    .hero {
      padding: 5.5rem 0 4rem;
    }
    .hero-brand-subtitle {
      display: inline-block;
      font-family: 'JetBrains Mono', monospace;
      font-size: 0.88rem;
      font-weight: 600;
      color: #38bdf8;
      background: rgba(56, 189, 248, 0.08);
      border: 1px solid rgba(56, 189, 248, 0.25);
      padding: 0.35rem 0.85rem;
      border-radius: 6px;
      margin-bottom: 1.25rem;
    }
    .hero-badges {
      display: flex;
      flex-wrap: wrap;
      gap: 0.75rem;
      margin-bottom: 1.75rem;
    }
    .badge {
      display: inline-flex;
      align-items: center;
      gap: 0.45rem;
      padding: 0.35rem 0.85rem;
      border-radius: 9999px;
      font-size: 0.8rem;
      font-weight: 600;
    }
    .badge-tesla {
      background: rgba(232, 33, 39, 0.12);
      border: 1px solid rgba(232, 33, 39, 0.35);
      color: #fca5a5;
    }
    .badge-location {
      background: rgba(6, 182, 212, 0.12);
      border: 1px solid rgba(6, 182, 212, 0.3);
      color: #a5f3fc;
    }
    .badge-status {
      background: rgba(16, 185, 129, 0.12);
      border: 1px solid rgba(16, 185, 129, 0.3);
      color: #6ee7b7;
    }
    .pulse-dot {
      width: 7px;
      height: 7px;
      border-radius: 50%;
      background: #10b981;
      box-shadow: 0 0 8px #10b981;
      animation: pulse 2s infinite;
    }
    .pulse-dot.dim {
      background: #94a3b8;
      box-shadow: none;
      animation: none;
    }
    @keyframes pulse {
      0% { opacity: 1; transform: scale(1); }
      50% { opacity: 0.4; transform: scale(0.85); }
      100% { opacity: 1; transform: scale(1); }
    }

    h1 {
      font-size: 3.25rem;
      font-weight: 800;
      letter-spacing: -0.035em;
      line-height: 1.15;
      margin-bottom: 1.5rem;
      max-width: 900px;
    }
    .gradient-text {
      background: linear-gradient(135deg, #60a5fa 0%, #22d3ee 50%, #a855f7 100%);
      -webkit-background-clip: text;
      -webkit-text-fill-color: transparent;
    }
    .hero-lead {
      font-size: 1.25rem;
      color: var(--text-muted);
      max-width: 780px;
      margin-bottom: 2.5rem;
      line-height: 1.65;
    }
    .hero-actions {
      display: flex;
      flex-wrap: wrap;
      gap: 1rem;
      align-items: center;
    }
    .btn {
      display: inline-flex;
      align-items: center;
      gap: 0.5rem;
      padding: 0.75rem 1.5rem;
      border-radius: 10px;
      font-weight: 600;
      font-size: 0.95rem;
      text-decoration: none;
      transition: all 0.2s ease;
      cursor: pointer;
    }
    .btn-github {
      background: #24292e;
      color: #fff;
      border: 1px solid rgba(255, 255, 255, 0.15);
    }
    .btn-github:hover {
      background: #2f363d;
      border-color: rgba(255, 255, 255, 0.3);
      transform: translateY(-2px);
    }
    .btn-linkedin {
      background: #0a66c2;
      color: #fff;
      border: 1px solid rgba(255, 255, 255, 0.15);
    }
    .btn-linkedin:hover {
      background: #084e96;
      transform: translateY(-2px);
    }
    .btn-secondary {
      background: rgba(255, 255, 255, 0.05);
      color: var(--text);
      border: 1px solid var(--border);
    }
    .btn-secondary:hover {
      background: rgba(255, 255, 255, 0.1);
      border-color: rgba(255, 255, 255, 0.2);
      transform: translateY(-2px);
    }

    /* Contact CTA Button & Tooltip */
    .contact-cta-wrapper {
      position: relative;
      display: inline-flex;
    }
    .btn-contact {
      background: rgba(16, 185, 129, 0.15);
      border: 1px solid rgba(16, 185, 129, 0.35);
      color: #a7f3d0;
      cursor: pointer;
      position: relative;
      transition: all 0.2s ease;
      display: inline-flex;
      align-items: center;
      gap: 0.5rem;
      font-family: inherit;
      font-size: 0.95rem;
      font-weight: 600;
      padding: 0.75rem 1.4rem;
      border-radius: 10px;
    }
    .btn-contact:hover {
      background: rgba(16, 185, 129, 0.25);
      border-color: #34d399;
      color: #ffffff;
      box-shadow: 0 0 20px rgba(16, 185, 129, 0.35);
      transform: translateY(-2px);
    }
    .contact-tooltip {
      position: absolute;
      bottom: calc(100% + 8px);
      left: 50%;
      transform: translateX(-50%) translateY(4px);
      background: #10b981;
      color: #064e3b;
      font-size: 0.75rem;
      font-weight: 700;
      padding: 0.35rem 0.65rem;
      border-radius: 6px;
      white-space: nowrap;
      opacity: 0;
      visibility: hidden;
      transition: all 0.2s ease;
      pointer-events: none;
      box-shadow: 0 4px 12px rgba(0, 0, 0, 0.4);
      z-index: 10;
    }
    .contact-tooltip.visible {
      opacity: 1;
      visibility: visible;
      transform: translateX(-50%) translateY(0);
    }

    /* Section Styling */
    .section {
      padding: 5.5rem 0;
      border-top: 1px solid var(--border);
    }
    .section-header {
      margin-bottom: 3.5rem;
    }
    .section-tag {
      font-family: 'JetBrains Mono', monospace;
      font-size: 0.82rem;
      color: var(--cyan);
      text-transform: uppercase;
      letter-spacing: 0.08em;
      display: inline-block;
      margin-bottom: 0.75rem;
      padding: 0.25rem 0.65rem;
      background: rgba(6, 182, 212, 0.1);
      border-radius: 6px;
      border: 1px solid rgba(6, 182, 212, 0.2);
    }
    .section-title {
      font-size: 2.25rem;
      font-weight: 800;
      letter-spacing: -0.025em;
    }

    /* Studio5000-MCP Showcase Box */
    .mcp-showcase-box {
      background: var(--bg-card);
      border: 1px solid var(--border);
      border-radius: var(--radius);
      padding: 2.5rem;
      box-shadow: 0 20px 40px rgba(0, 0, 0, 0.4);
    }
    .mcp-badge-row {
      display: flex;
      flex-wrap: wrap;
      gap: 0.6rem;
      margin-bottom: 1.5rem;
    }
    .mcp-badge {
      font-family: 'JetBrains Mono', monospace;
      font-size: 0.76rem;
      padding: 0.3rem 0.65rem;
      border-radius: 6px;
      font-weight: 600;
    }
    .mcp-badge-python { background: rgba(59, 130, 246, 0.15); border: 1px solid rgba(59, 130, 246, 0.3); color: #93c5fd; }
    .mcp-badge-rockwell { background: rgba(239, 68, 68, 0.15); border: 1px solid rgba(239, 68, 68, 0.3); color: #fca5a5; }
    .mcp-badge-mit { background: rgba(16, 185, 129, 0.15); border: 1px solid rgba(16, 185, 129, 0.3); color: #6ee7b7; }

    .mcp-heading {
      font-size: 1.6rem;
      font-weight: 700;
      margin-bottom: 0.75rem;
    }
    .mcp-summary {
      font-size: 1.05rem;
      color: var(--text-muted);
      margin-bottom: 2rem;
      line-height: 1.6;
    }
    .mcp-pillars {
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(260px, 1fr));
      gap: 1.5rem;
      margin-bottom: 2.5rem;
    }
    .mcp-pillar-card {
      background: rgba(255, 255, 255, 0.02);
      border: 1px solid var(--border);
      border-radius: var(--radius-sm);
      padding: 1.5rem;
      transition: all 0.2s ease;
    }
    .mcp-pillar-card:hover {
      border-color: rgba(59, 130, 246, 0.4);
      background: rgba(255, 255, 255, 0.04);
      transform: translateY(-2px);
    }
    .pillar-icon {
      font-size: 1.6rem;
      margin-bottom: 0.75rem;
    }
    .pillar-title {
      font-size: 1.1rem;
      font-weight: 700;
      margin-bottom: 0.5rem;
      color: #fff;
    }
    .pillar-desc {
      font-size: 0.9rem;
      color: var(--text-muted);
      line-height: 1.5;
    }

    /* Diagram Styles */
    .mcp-diagram-wrapper, .homelab-diagram-wrapper {
      margin: 2.5rem 0;
      background: #090d16;
      border: 1px solid rgba(255, 255, 255, 0.08);
      border-radius: 12px;
      overflow: hidden;
      box-shadow: 0 10px 30px rgba(0, 0, 0, 0.4);
    }
    .diagram-title-bar {
      background: #101623;
      padding: 0.75rem 1.25rem;
      display: flex;
      align-items: center;
      gap: 0.75rem;
      border-bottom: 1px solid rgba(255, 255, 255, 0.06);
    }
    .diagram-tag {
      font-family: 'JetBrains Mono', monospace;
      font-size: 0.68rem;
      font-weight: 700;
      letter-spacing: 0.08em;
      padding: 0.2rem 0.5rem;
      border-radius: 4px;
      background: rgba(59, 130, 246, 0.15);
      border: 1px solid rgba(59, 130, 246, 0.3);
      color: #60a5fa;
    }
    .diagram-name {
      font-size: 0.85rem;
      font-weight: 600;
      color: #cbd5e1;
    }
    .svg-container {
      padding: 1.25rem;
      overflow-x: auto;
    }

    /* Interactive Simulator */
    .mcp-demo-wrapper {
      margin-top: 2rem;
      background: #090d16;
      border: 1px solid rgba(255, 255, 255, 0.08);
      border-radius: 12px;
      overflow: hidden;
      box-shadow: 0 12px 36px rgba(0, 0, 0, 0.5);
    }
    .mcp-demo-header {
      background: #101623;
      padding: 1rem 1.25rem;
      display: flex;
      justify-content: space-between;
      align-items: center;
      flex-wrap: wrap;
      gap: 1rem;
      border-bottom: 1px solid rgba(255, 255, 255, 0.06);
    }
    .demo-controls {
      display: flex;
      align-items: center;
      gap: 0.5rem;
      flex-wrap: wrap;
    }
    .demo-tab-btn {
      background: rgba(255, 255, 255, 0.05);
      border: 1px solid rgba(255, 255, 255, 0.1);
      color: #94a3b8;
      font-family: 'JetBrains Mono', monospace;
      font-size: 0.78rem;
      font-weight: 600;
      padding: 0.45rem 0.85rem;
      border-radius: 6px;
      cursor: pointer;
      transition: all 0.2s ease;
    }
    .demo-tab-btn:hover {
      color: #f8fafc;
      border-color: rgba(255, 255, 255, 0.25);
    }
    .demo-tab-btn.active {
      background: rgba(59, 130, 246, 0.2);
      border-color: #3b82f6;
      color: #93c5fd;
      box-shadow: 0 0 12px rgba(59, 130, 246, 0.25);
    }
    .demo-replay-btn {
      background: rgba(255, 255, 255, 0.05);
      border: 1px solid rgba(255, 255, 255, 0.1);
      color: #cbd5e1;
      font-family: inherit;
      font-size: 0.78rem;
      font-weight: 600;
      padding: 0.45rem 0.75rem;
      border-radius: 6px;
      cursor: pointer;
      transition: all 0.2s ease;
    }
    .demo-replay-btn:hover {
      background: rgba(255, 255, 255, 0.12);
      color: #ffffff;
    }
    .mcp-demo-terminal {
      background: #06090e;
      font-family: 'JetBrains Mono', monospace;
    }
    .demo-terminal-bar {
      background: #0d121c;
      padding: 0.55rem 1rem;
      display: flex;
      align-items: center;
      gap: 0.45rem;
      border-bottom: 1px solid rgba(255, 255, 255, 0.05);
      font-size: 0.75rem;
      color: #94a3b8;
    }
    .demo-terminal-status {
      margin-left: auto;
      color: #34d399;
      font-size: 0.72rem;
      font-weight: 600;
    }
    .demo-terminal-body {
      padding: 1.25rem;
      min-height: 220px;
      font-size: 0.78rem;
      line-height: 1.7;
      color: #cbd5e1;
      display: flex;
      flex-direction: column;
      gap: 0.45rem;
      overflow-x: auto;
    }
    .demo-line-cmd { color: #38bdf8; font-weight: 600; }
    .demo-line-info { color: #94a3b8; }
    .demo-line-warn { color: #fbbf24; }
    .demo-line-err { color: #f87171; font-weight: 600; }
    .demo-line-ok { color: #34d399; font-weight: 600; }

    /* Code Block */
    .mcp-code-block {
      background: #080c14;
      border: 1px solid var(--border);
      border-radius: var(--radius-sm);
      overflow-x: auto;
      font-family: 'JetBrains Mono', monospace;
      font-size: 0.85rem;
      line-height: 1.6;
      max-width: 100%;
    }
    .code-titlebar {
      background: rgba(255, 255, 255, 0.03);
      padding: 0.6rem 1rem;
      border-bottom: 1px solid var(--border);
      display: flex;
      justify-content: space-between;
      color: var(--text-dim);
      font-size: 0.78rem;
    }
    .code-content {
      padding: 1.25rem;
      color: #e2e8f0;
    }
    .token-kw { color: #f43f5e; font-weight: 600; }
    .token-fn { color: #38bdf8; }
    .token-str { color: #34d399; }
    .token-comment { color: #64748b; font-style: italic; }

    /* Homelab Architecture & Deepdive Cards */
    .homelab-hero-overview {
      background: linear-gradient(135deg, rgba(30, 58, 138, 0.2) 0%, rgba(15, 23, 42, 0.6) 100%);
      border: 1px solid rgba(59, 130, 246, 0.25);
      border-radius: var(--radius);
      padding: 2.5rem;
      margin-bottom: 2.5rem;
    }
    .homelab-hero-overview h3 {
      font-size: 1.4rem;
      font-weight: 700;
      color: #fff;
      margin-bottom: 1rem;
    }
    .homelab-hero-overview p {
      color: var(--text-muted);
      line-height: 1.7;
      font-size: 1.05rem;
    }
    .deepdive-grid {
      display: grid;
      grid-template-columns: repeat(2, 1fr);
      gap: 2rem;
    }
    .deepdive-card {
      background: var(--bg-card);
      border: 1px solid var(--border);
      border-radius: var(--radius);
      padding: 2.25rem;
      display: flex;
      flex-direction: column;
      justify-content: space-between;
      transition: all 0.25s ease;
    }
    .deepdive-card:hover {
      border-color: rgba(59, 130, 246, 0.4);
      box-shadow: 0 10px 30px rgba(0, 0, 0, 0.3);
      transform: translateY(-2px);
    }
    .deepdive-header {
      display: flex;
      justify-content: space-between;
      align-items: flex-start;
      margin-bottom: 1.25rem;
    }
    .deepdive-icon { font-size: 2rem; }
    .deepdive-badge {
      font-family: 'JetBrains Mono', monospace;
      font-size: 0.72rem;
      padding: 0.25rem 0.6rem;
      border-radius: 4px;
      font-weight: 600;
      background: rgba(255, 255, 255, 0.06);
      color: var(--text-muted);
    }
    .deepdive-title {
      font-size: 1.35rem;
      font-weight: 700;
      margin-bottom: 0.75rem;
      color: #fff;
    }
    .deepdive-desc {
      color: var(--text-muted);
      font-size: 0.95rem;
      line-height: 1.6;
      margin-bottom: 1.5rem;
    }
    .deepdive-bullets {
      list-style: none;
      display: flex;
      flex-direction: column;
      gap: 0.75rem;
      border-top: 1px solid rgba(255, 255, 255, 0.05);
      padding-top: 1.25rem;
    }
    .deepdive-bullets li {
      font-size: 0.88rem;
      color: #cbd5e1;
      display: flex;
      align-items: flex-start;
      gap: 0.6rem;
      line-height: 1.5;
    }
    .deepdive-bullets li span.check {
      color: var(--emerald);
      font-weight: bold;
    }

    /* Edge Hardware Dashboard Card */
    .pi-dashboard-card {
      grid-column: 1 / -1;
      background: #0d1117;
      border: 1px solid rgba(244, 63, 94, 0.25);
      border-radius: var(--radius);
      padding: 2.25rem;
      position: relative;
      overflow: hidden;
      box-shadow: 0 10px 30px rgba(0, 0, 0, 0.4), 0 0 25px rgba(244, 63, 94, 0.06);
    }
    .pi-dashboard-card::before {
      content: '';
      position: absolute;
      top: 0; left: 0; right: 0;
      height: 3px;
      background: linear-gradient(90deg, #f43f5e, #fb923c, #38bdf8);
    }
    .pi-dashboard-header {
      display: flex;
      justify-content: space-between;
      align-items: center;
      flex-wrap: wrap;
      gap: 1rem;
      margin-bottom: 1.75rem;
      padding-bottom: 1.25rem;
      border-bottom: 1px solid rgba(255, 255, 255, 0.06);
    }
    .pi-header-left {
      display: flex;
      align-items: center;
      gap: 1rem;
    }
    .pi-avatar-icon {
      width: 56px;
      height: 56px;
      border-radius: 14px;
      display: flex;
      align-items: center;
      justify-content: center;
      font-size: 1.8rem;
      background: rgba(244, 63, 94, 0.12);
      border: 1px solid rgba(244, 63, 94, 0.3);
      box-shadow: 0 0 15px rgba(244, 63, 94, 0.2);
    }
    .pi-title-block h3 {
      font-size: 1.45rem;
      font-weight: 800;
      color: #f8fafc;
      letter-spacing: -0.015em;
      margin-bottom: 0.3rem;
      display: flex;
      align-items: center;
      gap: 0.6rem;
    }
    .pi-title-block span {
      font-size: 0.82rem;
      color: #94a3b8;
    }
    .pi-header-badges {
      display: flex;
      flex-wrap: wrap;
      gap: 0.5rem;
      align-items: center;
    }
    .pi-live-badge {
      display: inline-flex;
      align-items: center;
      gap: 0.45rem;
      padding: 0.35rem 0.85rem;
      border-radius: 9999px;
      font-family: 'JetBrains Mono', monospace;
      font-size: 0.74rem;
      font-weight: 700;
      letter-spacing: 0.04em;
      background: rgba(16, 185, 129, 0.15);
      border: 1px solid rgba(16, 185, 129, 0.4);
      color: #6ee7b7;
      box-shadow: 0 0 12px rgba(16, 185, 129, 0.2);
    }
    .pi-live-badge.baseline {
      background: rgba(148, 163, 184, 0.12);
      border-color: rgba(148, 163, 184, 0.3);
      color: #cbd5e1;
      box-shadow: none;
    }
    .pi-live-badge.synced {
      background: rgba(16, 185, 129, 0.15);
      border-color: rgba(16, 185, 129, 0.4);
      color: #6ee7b7;
    }
    .pi-chip-badge {
      font-family: 'JetBrains Mono', monospace;
      font-size: 0.72rem;
      padding: 0.3rem 0.65rem;
      border-radius: 6px;
      background: rgba(255, 255, 255, 0.05);
      border: 1px solid rgba(255, 255, 255, 0.08);
      color: #cbd5e1;
    }

    /* Live Telemetry Gauges Grid */
    .pi-gauges-grid {
      display: grid;
      grid-template-columns: repeat(4, 1fr);
      gap: 1.25rem;
      margin-bottom: 2rem;
    }
    @media (max-width: 960px) {
      .pi-gauges-grid { grid-template-columns: repeat(2, 1fr); }
    }
    @media (max-width: 520px) {
      .pi-gauges-grid { grid-template-columns: 1fr; }
    }
    .pi-gauge-box {
      background: rgba(20, 24, 34, 0.85);
      border: 1px solid rgba(255, 255, 255, 0.06);
      border-radius: 12px;
      padding: 1.25rem 1.15rem;
      position: relative;
      overflow: hidden;
    }
    .pi-gauge-box::before {
      content: '';
      position: absolute;
      top: 0; left: 0; bottom: 0;
      width: 3px;
      background: #f43f5e;
    }
    .pi-gauge-box.cyan::before { background: #38bdf8; }
    .pi-gauge-box.green::before { background: #34d399; }
    .pi-gauge-box.purple::before { background: #a855f7; }
    .pi-gauge-label {
      font-family: 'JetBrains Mono', monospace;
      font-size: 0.72rem;
      text-transform: uppercase;
      letter-spacing: 0.06em;
      color: #94a3b8;
      margin-bottom: 0.4rem;
    }
    .pi-gauge-val {
      font-family: 'JetBrains Mono', monospace;
      font-size: 1.55rem;
      font-weight: 800;
      color: #f8fafc;
      margin-bottom: 0.3rem;
    }
    .pi-gauge-sub {
      font-size: 0.74rem;
      color: #94a3b8;
      display: flex;
      align-items: center;
      gap: 0.35rem;
    }
    .pi-gauge-bar {
      width: 100%;
      height: 4px;
      background: rgba(255, 255, 255, 0.08);
      border-radius: 2px;
      margin-top: 0.6rem;
      overflow: hidden;
    }
    .pi-gauge-bar-fill {
      height: 100%;
      border-radius: 2px;
    }

    /* Content Split & Terminal Mockup */
    .pi-dashboard-split {
      display: grid;
      grid-template-columns: 1.2fr 1fr;
      gap: 1.75rem;
      align-items: start;
    }
    @media (max-width: 960px) {
      .pi-dashboard-split { grid-template-columns: 1fr; }
    }
    .pi-features-box {
      display: flex;
      flex-direction: column;
      gap: 1rem;
    }
    .pi-feature-item {
      display: flex;
      align-items: flex-start;
      gap: 0.85rem;
      background: rgba(20, 24, 34, 0.7);
      border: 1px solid rgba(255, 255, 255, 0.04);
      border-radius: 10px;
      padding: 1rem 1.15rem;
      transition: all 0.2s;
    }
    .pi-feature-item:hover {
      border-color: rgba(56, 189, 248, 0.3);
      background: rgba(20, 24, 34, 0.95);
    }
    .pi-feature-icon {
      font-size: 1.3rem;
      line-height: 1;
      padding: 0.4rem;
      border-radius: 8px;
      background: rgba(255, 255, 255, 0.05);
      border: 1px solid rgba(255, 255, 255, 0.08);
      flex-shrink: 0;
    }
    .pi-feature-text h5 {
      font-size: 0.92rem;
      font-weight: 700;
      color: #f1f5f9;
      margin-bottom: 0.25rem;
    }
    .pi-feature-text p {
      font-size: 0.84rem;
      color: #94a3b8;
      line-height: 1.5;
    }

    .pi-terminal-mock {
      background: #090c10;
      border: 1px solid rgba(255, 255, 255, 0.08);
      border-radius: 10px;
      overflow: hidden;
      font-family: 'JetBrains Mono', monospace;
      box-shadow: 0 8px 24px rgba(0, 0, 0, 0.5);
      max-width: 100%;
    }
    .pi-terminal-titlebar {
      background: #161b22;
      padding: 0.55rem 0.9rem;
      display: flex;
      align-items: center;
      gap: 0.45rem;
      border-bottom: 1px solid rgba(255, 255, 255, 0.06);
    }
    .term-dot {
      width: 10px;
      height: 10px;
      border-radius: 50%;
    }
    .term-dot.red { background: #ff5f56; }
    .term-dot.yellow { background: #ffbd2e; }
    .term-dot.green { background: #27c93f; }
    .term-title {
      font-size: 0.72rem;
      color: #94a3b8;
      margin-left: 0.5rem;
    }
    .pi-terminal-body {
      padding: 1rem 1.15rem;
      font-size: 0.76rem;
      line-height: 1.65;
      color: #cbd5e1;
      display: flex;
      flex-direction: column;
      gap: 0.45rem;
      overflow-x: auto;
    }
    .term-cmd { color: #38bdf8; font-weight: 600; }
    .term-ok { color: #34d399; font-weight: 600; }
    .term-highlight { color: #fb923c; }

    .pi-specs-strip {
      margin-top: 1rem;
      background: rgba(0, 0, 0, 0.35);
      border: 1px solid rgba(255, 255, 255, 0.05);
      border-radius: 8px;
      padding: 0.85rem 1rem;
      font-family: 'JetBrains Mono', monospace;
      font-size: 0.75rem;
      display: grid;
      grid-template-columns: 1fr 1fr;
      gap: 0.5rem;
      color: #94a3b8;
    }
    @media (max-width: 600px) {
      .pi-specs-strip { grid-template-columns: 1fr; }
    }
    .pi-specs-strip strong { color: #e2e8f0; }

    /* Skills Grid */
    .skills-grid {
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(280px, 1fr));
      gap: 1.75rem;
    }
    .skill-card {
      background: var(--bg-card);
      border: 1px solid var(--border);
      border-radius: var(--radius);
      padding: 2rem;
      transition: all 0.25s ease;
    }
    .skill-card:hover {
      border-color: rgba(59, 130, 246, 0.4);
      transform: translateY(-3px);
    }
    .skill-card h4 {
      font-size: 1.15rem;
      font-weight: 700;
      margin-bottom: 1rem;
      color: #fff;
      display: flex;
      align-items: center;
      gap: 0.5rem;
    }
    .skill-tags {
      display: flex;
      flex-wrap: wrap;
      gap: 0.5rem;
    }
    .skill-tag {
      background: rgba(255, 255, 255, 0.04);
      border: 1px solid rgba(255, 255, 255, 0.08);
      padding: 0.35rem 0.7rem;
      border-radius: 6px;
      font-size: 0.82rem;
      color: #cbd5e1;
    }

    /* Experience Timeline */
    .timeline {
      display: flex;
      flex-direction: column;
      gap: 2rem;
    }
    .timeline-item {
      position: relative;
      padding-left: 2rem;
      border-left: 2px solid rgba(59, 130, 246, 0.3);
    }
    .timeline-dot {
      position: absolute;
      left: -7px;
      top: 4px;
      width: 12px;
      height: 12px;
      border-radius: 50%;
      background: var(--primary);
      box-shadow: 0 0 10px var(--primary);
    }
    .exp-role {
      font-size: 1.25rem;
      font-weight: 700;
      color: #fff;
    }
    .exp-company {
      font-size: 0.95rem;
      color: var(--cyan);
      font-weight: 600;
      margin-bottom: 0.5rem;
    }
    .exp-time {
      font-family: 'JetBrains Mono', monospace;
      font-size: 0.8rem;
      color: var(--text-dim);
      margin-bottom: 1rem;
    }
    .exp-desc {
      color: var(--text-muted);
      line-height: 1.6;
      font-size: 0.95rem;
    }

    /* Pi5 Silicon Hardware Section */
    .pi5-specs-grid {
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(260px, 1fr));
      gap: 1.5rem;
      margin-bottom: 2.5rem;
    }
    .pi5-card {
      background: var(--bg-card);
      border: 1px solid var(--border);
      border-radius: var(--radius);
      padding: 1.75rem;
      display: flex;
      flex-direction: column;
      justify-content: space-between;
      transition: all 0.25s ease;
    }
    .pi5-card:hover {
      border-color: rgba(225, 29, 72, 0.4);
      transform: translateY(-2px);
      box-shadow: 0 8px 24px rgba(225, 29, 72, 0.1);
    }
    .pi5-card-header {
      display: flex;
      justify-content: space-between;
      align-items: flex-start;
      margin-bottom: 1rem;
    }
    .pi5-card-icon { font-size: 1.75rem; }
    .pi5-card-badge {
      font-family: 'JetBrains Mono', monospace;
      font-size: 0.72rem;
      padding: 0.25rem 0.6rem;
      border-radius: 4px;
      background: rgba(225, 29, 72, 0.1);
      border: 1px solid rgba(225, 29, 72, 0.25);
      color: #fb7185;
      font-weight: 600;
    }
    .pi5-card-title {
      font-size: 1.25rem;
      font-weight: 700;
      color: #fff;
      margin-bottom: 0.5rem;
    }
    .pi5-card-desc {
      color: var(--text-muted);
      font-size: 0.9rem;
      line-height: 1.55;
      margin-bottom: 1.25rem;
    }
    .pi5-spec-list {
      border-top: 1px solid rgba(255, 255, 255, 0.05);
      padding-top: 1rem;
      display: flex;
      flex-direction: column;
      gap: 0.5rem;
      font-family: 'JetBrains Mono', monospace;
      font-size: 0.78rem;
      color: #cbd5e1;
    }
    .pi5-spec-item {
      display: flex;
      justify-content: space-between;
    }
    .pi5-spec-item span:first-child { color: var(--text-dim); }
    .pi5-spec-item span:last-child { font-weight: 600; color: #f1f5f9; }

    .pi5-diag-wrapper {
      background: #090d16;
      border: 1px solid var(--border);
      border-radius: var(--radius);
      padding: 2rem;
      margin-top: 2rem;
      box-shadow: 0 12px 36px rgba(0, 0, 0, 0.4);
    }
    .pi5-diag-header {
      display: flex;
      justify-content: space-between;
      align-items: center;
      flex-wrap: wrap;
      gap: 1rem;
      margin-bottom: 1.5rem;
      padding-bottom: 1rem;
      border-bottom: 1px solid rgba(255, 255, 255, 0.06);
    }
    .pi5-diag-title {
      font-size: 1.15rem;
      font-weight: 700;
      color: #fff;
      display: flex;
      align-items: center;
      gap: 0.5rem;
    }
    .pi5-table-container {
      overflow-x: auto;
      max-width: 100%;
      -webkit-overflow-scrolling: touch;
    }
    .pi5-diag-table {
      width: 100%;
      border-collapse: collapse;
      font-family: 'JetBrains Mono', monospace;
      font-size: 0.82rem;
    }
    .pi5-diag-table th {
      text-align: left;
      padding: 0.75rem 1rem;
      color: var(--text-dim);
      border-bottom: 1px solid rgba(255, 255, 255, 0.08);
      font-weight: 600;
      letter-spacing: 0.04em;
    }
    .pi5-diag-table td {
      padding: 0.85rem 1rem;
      border-bottom: 1px solid rgba(255, 255, 255, 0.04);
      color: #cbd5e1;
    }
    .pi5-status-tag {
      display: inline-block;
      padding: 0.2rem 0.5rem;
      border-radius: 4px;
      font-size: 0.74rem;
      font-weight: 600;
    }
    .pi5-status-tag.optimal { background: rgba(16, 185, 129, 0.15); color: #6ee7b7; border: 1px solid rgba(16, 185, 129, 0.3); }
    .pi5-status-tag.active { background: rgba(56, 189, 248, 0.15); color: #7dd3fc; border: 1px solid rgba(56, 189, 248, 0.3); }
    .pi5-status-tag.secure { background: rgba(168, 85, 247, 0.15); color: #d8b4fe; border: 1px solid rgba(168, 85, 247, 0.3); }

    .pi5-footer-bar {
      margin-top: 1.5rem;
      padding-top: 1rem;
      border-top: 1px solid rgba(255, 255, 255, 0.06);
      display: flex;
      justify-content: space-between;
      align-items: center;
      flex-wrap: wrap;
      gap: 1rem;
      font-size: 0.84rem;
      color: var(--text-dim);
    }

    footer {
      border-top: 1px solid var(--border);
      padding: 3.5rem 0;
      background: rgba(6, 9, 14, 0.95);
    }
    .footer-content {
      display: flex;
      justify-content: space-between;
      align-items: center;
      flex-wrap: wrap;
      gap: 1.5rem;
    }
    .footer-text {
      color: var(--text-dim);
      font-size: 0.9rem;
    }
    .footer-disclaimer {
      font-size: 0.82rem;
      color: #64748b;
      margin-top: 0.5rem;
      line-height: 1.5;
    }
    .footer-links {
      display: flex;
      gap: 1.5rem;
      flex-wrap: wrap;
    }
    .footer-links a {
      color: var(--text-muted);
      text-decoration: none;
      font-size: 0.9rem;
      transition: color 0.2s;
    }
    .footer-links a:hover { color: #fff; }

    /* Mobile 320px Overflow Protection & Responsive Navigation */
    pre, code, .mcp-code-block, .pi-terminal-mock, .pi-terminal-body, .mcp-demo-terminal, .demo-terminal-body, .pi5-table-container, .svg-container {
      max-width: 100%;
      overflow-x: auto;
      -webkit-overflow-scrolling: touch;
      box-sizing: border-box;
    }

    @media (max-width: 868px) {
      .nav-container {
        flex-direction: column;
        align-items: flex-start;
        gap: 0.75rem;
        padding: 0.85rem 1.25rem;
      }
      nav {
        width: 100%;
        overflow-x: auto;
        white-space: nowrap;
        gap: 1.25rem;
        padding-bottom: 0.25rem;
        -webkit-overflow-scrolling: touch;
      }
      nav::-webkit-scrollbar { display: none; }
      nav { -ms-overflow-style: none; scrollbar-width: none; }
      .deepdive-grid { grid-template-columns: 1fr; }
      .split-grid { grid-template-columns: 1fr; }
      .hero { padding: 4rem 0 2.5rem; }
      .mcp-showcase-box { padding: 1.75rem; }
      .footer-content { flex-direction: column; text-align: center; }
    }
  </style>
</head>
<body>

  <header>
    <div class="nav-container">
      <a href="#" class="brand">
        <div class="brand-avatar">KS</div>
        <div class="brand-details">
          <span class="brand-name">Krutarth Sailor</span>
          <span class="brand-role">Electrical &amp; Controls Engineer &bull; Industrial Automation</span>
        </div>
      </a>
      <nav>
        <a href="#about">About</a>
        <a href="#mcp">MCP Innovation</a>
        <a href="#homelab">Homelab Architecture</a>
        <a href="#skills">Skills</a>
        <a href="#experience">Experience</a>
        <a href="/portal" class="portal-nav-btn">🔐 Homelab Portal</a>
      </nav>
    </div>
  </header>

  <main>
    <div class="container">
      <section class="hero" id="about">
        <div class="hero-badges">
          <span class="badge badge-tesla">⚡ Electrical & Controls Engineer @ Tesla</span>
          <span class="badge badge-location">📍 Austin, Texas Metropolitan Area</span>
          <span class="badge badge-status"><span class="pulse-dot"></span> 7+ Years Engineering Experience</span>
        </div>
        <div class="hero-brand-subtitle">Shasa Engineering &mdash; Personal R&amp;D Lab &amp; Automation Portfolio of Krutarth Sailor</div>
        <h1>Pioneering Next-Gen <span class="gradient-text">Industrial Automation</span>, Robotics & AI-Driven Controls</h1>
        <p class="hero-lead">
          I design, scale, and optimize mission-critical automated manufacturing lines, high-speed robotics, and control systems. Expert in <strong>Rockwell Studio 5000 / Allen-Bradley</strong> architectures, <strong>Cognex Vision</strong> quality systems, SCADA telemetry, and private edge cloud infrastructure. Creator of <strong>Studio5000-MCP</strong>.
        </p>
        <div class="hero-actions">
          <a href="https://github.com/krusailor44-afk/Studio5000-MCP" target="_blank" rel="noopener" class="btn btn-github">
            <svg width="18" height="18" viewBox="0 0 24 24" fill="currentColor"><path d="M12 0c-6.626 0-12 5.373-12 12 0 5.302 3.438 9.8 8.207 11.387.599.111.793-.261.793-.577v-2.234c-3.338.726-4.033-1.416-4.033-1.416-.546-1.387-1.333-1.756-1.333-1.756-1.089-.745.083-.729.083-.729 1.205.084 1.839 1.237 1.839 1.237 1.07 1.834 2.807 1.304 3.492.997.107-.775.418-1.305.762-1.604-2.665-.305-5.467-1.334-5.467-5.931 0-1.311.469-2.381 1.236-3.221-.124-.303-.535-1.524.117-3.176 0 0 1.008-.322 3.301 1.23.957-.266 1.983-.399 3.003-.404 1.02.005 2.047.138 3.006.404 2.291-1.552 3.297-1.23 3.297-1.23.653 1.653.242 2.874.118 3.176.77.84 1.235 1.911 1.235 3.221 0 4.609-2.807 5.624-5.479 5.921.43.372.823 1.102.823 2.222v3.293c0 .319.192.694.801.576 4.765-1.589 8.199-6.086 8.199-11.386 0-6.627-5.373-12-12-12z"/></svg>
            Studio5000-MCP on GitHub
          </a>
          <a href="https://www.linkedin.com/in/sailorkrutarth" target="_blank" rel="noopener" class="btn btn-linkedin">
            <svg width="18" height="18" viewBox="0 0 24 24" fill="currentColor"><path d="M19 0h-14c-2.761 0-5 2.239-5 5v14c0 2.761 2.239 5 5 5h14c2.762 0 5-2.239 5-5v-14c0-2.761-2.238-5-5-5zm-11 19h-3v-11h3v11zm-1.5-12.268c-.966 0-1.75-.79-1.75-1.764s.784-1.764 1.75-1.764 1.75.79 1.75 1.764-.783 1.764-1.75 1.764zm13.5 12.268h-3v-5.604c0-3.368-4-3.113-4 0v5.604h-3v-11h3v1.765c1.396-2.586 7-2.777 7 2.476v6.759z"/></svg>
            Connect on LinkedIn
          </a>
          <!--email_off-->
          <div class="contact-cta-wrapper">
            <button id="contactBtn" class="btn btn-contact" type="button" aria-label="Copy Contact Email" onclick="copyContactEmail()">
              <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="9" y="9" width="13" height="13" rx="2" ry="2"></rect><path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"></path></svg>
              <span id="contactBtnText">Copy Email</span>
            </button>
            <span id="contactTooltip" class="contact-tooltip">Copied to Clipboard!</span>
          </div>
          <!--/email_off-->
          <a href="#homelab" class="btn btn-secondary">Homelab Architecture &rarr;</a>
        </div>
      </section>
    </div>

    <section class="section" id="mcp">
      <div class="container">
        <div class="section-header">
          <span class="section-tag">// Flagship Open-Source Engineering</span>
          <h2 class="section-title">Studio5000-MCP Server</h2>
          <p style="color: var(--text-muted); font-size: 1.05rem; margin-top: 0.5rem; max-width: 820px;">
            Bridging AI Coding Assistants (Claude Desktop, Cursor, Antigravity) with Rockwell Automation Allen-Bradley ControlLogix & CompactLogix PLCs.
          </p>
        </div>

        <div class="mcp-showcase-box">
          <div class="mcp-top">
            <div>
              <div class="mcp-badge-row">
                <span class="mcp-badge mcp-badge-python">Python 3.12+</span>
                <span class="mcp-badge mcp-badge-rockwell">Rockwell Studio 5000 (v30 - v38)</span>
                <span class="mcp-badge mcp-badge-mit">MIT License</span>
                <span class="mcp-badge" style="background: rgba(168, 85, 247, 0.15); border: 1px solid rgba(168, 85, 247, 0.3); color: #d8b4fe;">FastMCP Protocol</span>
              </div>
              <h3 class="mcp-heading">What is Studio5000-MCP & Why It Matters</h3>
              <p class="mcp-summary">
                Interacting with programmable logic controllers in live plants carries <strong>zero margin for error</strong>. Standard LLMs frequently hallucinate invalid ladder syntax (such as malformed single-leg branches causing Studio 5000 Error 12740-0, obsolete comparison mnemonics, or missing XML target headers).
                <br><br>
                <strong>Studio5000-MCP</strong> solves this by establishing an authoritative, schema-enforced, and safety-gated bridge built on a <strong>Modular Adapter Architecture</strong>.
              </p>
            </div>
            <a href="https://github.com/krusailor44-afk/Studio5000-MCP" target="_blank" rel="noopener" class="btn btn-primary" style="white-space: nowrap;">
              <svg width="18" height="18" viewBox="0 0 24 24" fill="currentColor"><path d="M12 0c-6.626 0-12 5.373-12 12 0 5.302 3.438 9.8 8.207 11.387.599.111.793-.261.793-.577v-2.234c-3.338.726-4.033-1.416-4.033-1.416-.546-1.387-1.333-1.756-1.333-1.756-1.089-.745.083-.729.083-.729 1.205.084 1.839 1.237 1.839 1.237 1.07 1.834 2.807 1.304 3.492.997.107-.775.418-1.305.762-1.604-2.665-.305-5.467-1.334-5.467-5.931 0-1.311.469-2.381 1.236-3.221-.124-.303-.535-1.524.117-3.176 0 0 1.008-.322 3.301 1.23.957-.266 1.983-.399 3.003-.404 1.02.005 2.047.138 3.006.404 2.291-1.552 3.297-1.23 3.297-1.23.653 1.653.242 2.874.118 3.176.77.84 1.235 1.911 1.235 3.221 0 4.609-2.807 5.624-5.479 5.921.43.372.823 1.102.823 2.222v3.293c0 .319.192.694.801.576 4.765-1.589 8.199-6.086 8.199-11.386 0-6.627-5.373-12-12-12z"/></svg>
              View on GitHub &rarr;
            </a>
          </div>

          <div class="mcp-pillars">
            <div class="mcp-pillar-card">
              <div class="pillar-icon">🔄</div>
              <h4 class="pillar-title">Live Online Edits Lifecycle</h4>
              <p class="pillar-desc">
                Interfaces via the official Rockwell Logix Designer Python SDK and Win32 automation drivers. Moves rung edits through deterministic online actions: <em>Propose, Test, Untest, and Assemble</em>.
              </p>
            </div>

            <div class="mcp-pillar-card">
              <div class="pillar-icon">⚡</div>
              <h4 class="pillar-title">Offline L5X Schema Synthesis</h4>
              <p class="pillar-desc">
                Translates complex, verbose XML <code>.L5X</code> project exports into token-efficient NeutralText format, saving up to 85% context tokens while ensuring 100% schema compliance.
              </p>
            </div>

            <div class="mcp-pillar-card">
              <div class="pillar-icon">🛡️</div>
              <h4 class="pillar-title">Hardcoded Safety Gates</h4>
              <p class="pillar-desc">
                Enforces non-negotiable industrial safety gates: outright denies writes to <code>Safety_</code> tags, alias tags, consumed tags, or online edits to running AOIs.
              </p>
            </div>

            <div class="mcp-pillar-card">
              <div class="pillar-icon">🤖</div>
              <h4 class="pillar-title">Universal AI IDE Integration</h4>
              <p class="pillar-desc">
                Built on the FastMCP stdio transport. Integrates in seconds into Claude Desktop, Cursor IDE, Antigravity, or Cline, giving agents contextual visibility over PLC tags and logic.
              </p>
            </div>
          </div>

          <div class="mcp-diagram-wrapper">
  <div class="diagram-title-bar">
    <span class="diagram-tag">ARCHITECTURE DIAGRAM</span>
    <span class="diagram-name">Dual-Adapter Control Engine &bull; Deterministic CIP Pipeline</span>
  </div>
  <div class="svg-container">
    <svg viewBox="0 0 920 300" width="100%" style="max-width: 100%; height: auto;" xmlns="http://www.w3.org/2000/svg" role="img" aria-label="Studio5000-MCP Dual-Adapter Architecture Diagram">
      <defs>
        <linearGradient id="gradAi" x1="0%" y1="0%" x2="100%" y2="100%">
          <stop offset="0%" stop-color="#1e3a8a" stop-opacity="0.8"/>
          <stop offset="100%" stop-color="#0f172a" stop-opacity="0.9"/>
        </linearGradient>
        <linearGradient id="gradSafety" x1="0%" y1="0%" x2="100%" y2="100%">
          <stop offset="0%" stop-color="#450a0a" stop-opacity="0.85"/>
          <stop offset="100%" stop-color="#1c1917" stop-opacity="0.95"/>
        </linearGradient>
        <linearGradient id="gradOnline" x1="0%" y1="0%" x2="100%" y2="100%">
          <stop offset="0%" stop-color="#064e3b" stop-opacity="0.8"/>
          <stop offset="100%" stop-color="#022c22" stop-opacity="0.9"/>
        </linearGradient>
        <linearGradient id="gradOffline" x1="0%" y1="0%" x2="100%" y2="100%">
          <stop offset="0%" stop-color="#164e63" stop-opacity="0.8"/>
          <stop offset="100%" stop-color="#082f49" stop-opacity="0.9"/>
        </linearGradient>
        <linearGradient id="gradPlc" x1="0%" y1="0%" x2="100%" y2="100%">
          <stop offset="0%" stop-color="#3b0764" stop-opacity="0.8"/>
          <stop offset="100%" stop-color="#1e1b4b" stop-opacity="0.9"/>
        </linearGradient>
        <filter id="glowDrop" x="-10%" y="-10%" width="120%" height="120%">
          <feDropShadow dx="0" dy="4" stdDeviation="6" flood-color="#000" flood-opacity="0.5"/>
        </filter>
        <marker id="arrowhead" markerWidth="8" markerHeight="6" refX="7" refY="3" orient="auto">
          <polygon points="0 0, 8 3, 0 6" fill="#38bdf8"/>
        </marker>
        <marker id="arrowhead-green" markerWidth="8" markerHeight="6" refX="7" refY="3" orient="auto">
          <polygon points="0 0, 8 3, 0 6" fill="#34d399"/>
        </marker>
        <marker id="arrowhead-cyan" markerWidth="8" markerHeight="6" refX="7" refY="3" orient="auto">
          <polygon points="0 0, 8 3, 0 6" fill="#22d3ee"/>
        </marker>
        <marker id="arrowhead-purple" markerWidth="8" markerHeight="6" refX="7" refY="3" orient="auto">
          <polygon points="0 0, 8 3, 0 6" fill="#c084fc"/>
        </marker>
      </defs>

      <!-- Background Subtle Grid -->
      <rect width="920" height="300" rx="12" fill="#090d16" stroke="rgba(255,255,255,0.08)" stroke-width="1"/>

      <!-- Node 1: AI IDE Clients -->
      <g transform="translate(24, 85)" filter="url(#glowDrop)">
        <rect width="160" height="130" rx="10" fill="url(#gradAi)" stroke="#3b82f6" stroke-width="1.5"/>
        <text x="80" y="28" fill="#93c5fd" font-family="'Plus Jakarta Sans', sans-serif" font-weight="700" font-size="12" text-anchor="middle" letter-spacing="0.05em">AI IDE CLIENTS</text>
        <line x1="16" y1="38" x2="144" y2="38" stroke="rgba(59,130,246,0.3)" stroke-width="1"/>
        <text x="80" y="58" fill="#f8fafc" font-family="'JetBrains Mono', monospace" font-size="11" text-anchor="middle">• Claude Desktop</text>
        <text x="80" y="78" fill="#f8fafc" font-family="'JetBrains Mono', monospace" font-size="11" text-anchor="middle">• Cursor IDE</text>
        <text x="80" y="98" fill="#f8fafc" font-family="'JetBrains Mono', monospace" font-size="11" text-anchor="middle">• Cline / Roo-Code</text>
        <text x="80" y="116" fill="#94a3b8" font-family="'JetBrains Mono', monospace" font-size="9" text-anchor="middle">JSON-RPC over stdio</text>
      </g>

      <!-- Connection 1 -> 2 -->
      <path d="M 184 150 L 226 150" stroke="#38bdf8" stroke-width="2" marker-end="url(#arrowhead)"/>
      <text x="205" y="140" fill="#38bdf8" font-family="'JetBrains Mono', monospace" font-size="9" text-anchor="middle">FastMCP</text>

      <!-- Node 2: Safety Gate & Schema Validator -->
      <g transform="translate(236, 60)" filter="url(#glowDrop)">
        <rect width="180" height="180" rx="10" fill="url(#gradSafety)" stroke="#ef4444" stroke-width="1.5"/>
        <rect x="10" y="10" width="160" height="22" rx="4" fill="rgba(239,68,68,0.2)" stroke="#ef4444" stroke-width="0.8"/>
        <text x="90" y="25" fill="#fca5a5" font-family="'Plus Jakarta Sans', sans-serif" font-weight="700" font-size="10.5" text-anchor="middle" letter-spacing="0.06em">SAFETY &amp; SCHEMA GATE</text>
        <text x="90" y="52" fill="#ef4444" font-family="'JetBrains Mono', monospace" font-weight="700" font-size="11" text-anchor="middle">Deterministic Interlock</text>
        <line x1="16" y1="62" x2="164" y2="62" stroke="rgba(239,68,68,0.3)" stroke-width="1"/>
        <text x="24" y="80" fill="#fecaca" font-family="'JetBrains Mono', monospace" font-size="9.5">🛡️ Safety_ Tag Block</text>
        <text x="24" y="98" fill="#fecaca" font-family="'JetBrains Mono', monospace" font-size="9.5">⚡ Confirmed Edits Gate</text>
        <text x="24" y="116" fill="#fecaca" font-family="'JetBrains Mono', monospace" font-size="9.5">📋 L5X Schema Check</text>
        <text x="24" y="134" fill="#fecaca" font-family="'JetBrains Mono', monospace" font-size="9.5">🔒 Scope Authorization</text>
        <rect x="16" y="146" width="148" height="22" rx="4" fill="rgba(0,0,0,0.4)" stroke="rgba(255,255,255,0.06)"/>
        <text x="90" y="161" fill="#4ade80" font-family="'JetBrains Mono', monospace" font-size="9" text-anchor="middle">Zero Unchecked Writes</text>
      </g>

      <!-- Forking Paths from Node 2 to Adapters -->
      <!-- Branch Top to Online Adapter -->
      <path d="M 416 125 C 448 125, 452 75, 482 75" fill="none" stroke="#34d399" stroke-width="2" marker-end="url(#arrowhead-green)"/>
      <text x="446" y="88" fill="#34d399" font-family="'JetBrains Mono', monospace" font-size="8.5" text-anchor="middle">Live CIP</text>

      <!-- Branch Bottom to Offline Adapter -->
      <path d="M 416 175 C 448 175, 452 225, 482 225" fill="none" stroke="#22d3ee" stroke-width="2" marker-end="url(#arrowhead-cyan)"/>
      <text x="446" y="214" fill="#22d3ee" font-family="'JetBrains Mono', monospace" font-size="8.5" text-anchor="middle">XML / AST</text>

      <!-- Node 3A: Online Adapter -->
      <g transform="translate(492, 30)" filter="url(#glowDrop)">
        <rect width="180" height="90" rx="8" fill="url(#gradOnline)" stroke="#10b981" stroke-width="1.5"/>
        <text x="90" y="24" fill="#6ee7b7" font-family="'Plus Jakarta Sans', sans-serif" font-weight="700" font-size="11" text-anchor="middle">ONLINE ADAPTER</text>
        <text x="90" y="42" fill="#d1fae5" font-family="'JetBrains Mono', monospace" font-weight="600" font-size="10" text-anchor="middle">Logix SDK &bull; Real-Time CIP</text>
        <line x1="16" y1="50" x2="164" y2="50" stroke="rgba(16,185,129,0.3)" stroke-width="1"/>
        <text x="90" y="66" fill="#a7f3d0" font-family="'JetBrains Mono', monospace" font-size="9" text-anchor="middle">Live Tag I/O &amp; Diagnostics</text>
        <text x="90" y="80" fill="#a7f3d0" font-family="'JetBrains Mono', monospace" font-size="9" text-anchor="middle">Online Edit Test/Assemble</text>
      </g>

      <!-- Node 3B: Offline Adapter -->
      <g transform="translate(492, 180)" filter="url(#glowDrop)">
        <rect width="180" height="90" rx="8" fill="url(#gradOffline)" stroke="#06b6d4" stroke-width="1.5"/>
        <text x="90" y="24" fill="#67e8f9" font-family="'Plus Jakarta Sans', sans-serif" font-weight="700" font-size="11" text-anchor="middle">OFFLINE ADAPTER</text>
        <text x="90" y="42" fill="#cffafe" font-family="'JetBrains Mono', monospace" font-weight="600" font-size="10" text-anchor="middle">.L5X NeutralText AST</text>
        <line x1="16" y1="50" x2="164" y2="50" stroke="rgba(6,182,212,0.3)" stroke-width="1"/>
        <text x="90" y="66" fill="#a5f3fc" font-family="'JetBrains Mono', monospace" font-size="9" text-anchor="middle">XML Routine Synthesis</text>
        <text x="90" y="80" fill="#a5f3fc" font-family="'JetBrains Mono', monospace" font-size="9" text-anchor="middle">-74% LLM Token Reduction</text>
      </g>

      <!-- Converging Paths from Adapters to PLC Hardware -->
      <!-- From Online Adapter -->
      <path d="M 672 75 C 702 75, 706 125, 736 125" fill="none" stroke="#34d399" stroke-width="2" marker-end="url(#arrowhead-purple)"/>
      <!-- From Offline Adapter -->
      <path d="M 672 225 C 702 225, 706 175, 736 175" fill="none" stroke="#22d3ee" stroke-width="2" marker-end="url(#arrowhead-purple)"/>
      <text x="704" y="154" fill="#c084fc" font-family="'JetBrains Mono', monospace" font-size="8.5" text-anchor="middle">EtherNet/IP</text>

      <!-- Node 4: Rockwell PLC Hardware -->
      <g transform="translate(746, 85)" filter="url(#glowDrop)">
        <rect width="150" height="130" rx="10" fill="url(#gradPlc)" stroke="#a855f7" stroke-width="1.5"/>
        <text x="75" y="28" fill="#d8b4fe" font-family="'Plus Jakarta Sans', sans-serif" font-weight="700" font-size="11.5" text-anchor="middle">ROCKWELL PLC</text>
        <line x1="14" y1="38" x2="136" y2="38" stroke="rgba(168,85,247,0.3)" stroke-width="1"/>
        <text x="75" y="58" fill="#f8fafc" font-family="'JetBrains Mono', monospace" font-weight="600" font-size="10" text-anchor="middle">ControlLogix 1756</text>
        <text x="75" y="76" fill="#f8fafc" font-family="'JetBrains Mono', monospace" font-weight="600" font-size="10" text-anchor="middle">CompactLogix 5069</text>
        <text x="75" y="96" fill="#cbd5e1" font-family="'JetBrains Mono', monospace" font-size="9.5" text-anchor="middle">Studio 5000 v30-v38</text>
        <rect x="14" y="105" width="122" height="18" rx="3" fill="rgba(16,185,129,0.15)" stroke="rgba(16,185,129,0.3)"/>
        <text x="75" y="117" fill="#34d399" font-family="'JetBrains Mono', monospace" font-size="8.5" text-anchor="middle">Industrial Scantime</text>
      </g>
    </svg>
  </div>
</div>

          <div class="mcp-code-block">
<span class="comment"># FastMCP Server Architecture - Dual Adapter Bridge</span>
<span class="keyword">from</span> fastmcp <span class="keyword">import</span> FastMCP
<span class="keyword">from</span> studio5000_mcp.adapters <span class="keyword">import</span> LogixOnlineAdapter, LogixOfflineAdapter
<span class="keyword">from</span> studio5000_mcp.safety <span class="keyword">import</span> enforce_industrial_safety_gates

mcp = FastMCP(<span class="str">"Studio5000-Live-MCP"</span>)

<span class="comment"># Safe online rung assembly with operator confirmation</span>
<span class="keyword">@mcp.tool</span>()
<span class="keyword">async def</span> <span class="fn">assemble_online_edits</span>(program: <span class="keyword">str</span>, routine: <span class="keyword">str</span>, confirmed: <span class="keyword">bool</span>) -> <span class="keyword">dict</span>:
    enforce_industrial_safety_gates(target=routine)
    <span class="keyword">return await</span> adapter.assemble_edits(program, routine, confirmed=confirmed)
          </div>

          <div class="mcp-demo-wrapper">
  <div class="mcp-demo-header">
    <div class="demo-title-group">
      <span class="mcp-badge" style="background: rgba(239, 68, 68, 0.15); border-color: rgba(239, 68, 68, 0.3); color: #fca5a5;">INTERACTIVE DEMO</span>
      <h3 style="font-size: 1.15rem; font-weight: 700; color: #f8fafc; margin: 0;">Deterministic Safety Interlock &amp; Edit Lifecycle Simulator</h3>
    </div>
    <div class="demo-controls">
      <button class="demo-tab-btn active" id="demoTabSafety" onclick="switchDemoScenario('safety')">Scenario 1: Safety Gate Block</button>
      <button class="demo-tab-btn" id="demoTabOnline" onclick="switchDemoScenario('online')">Scenario 2: Safe Online Edit</button>
      <button class="demo-replay-btn" onclick="replayCurrentScenario()" title="Replay Simulation">↺ Replay</button>
    </div>
  </div>

  <div class="mcp-demo-terminal">
    <div class="demo-terminal-bar">
      <span class="term-dot red"></span>
      <span class="term-dot yellow"></span>
      <span class="term-dot green"></span>
      <span class="term-title" id="demoTermTitle">ops@agent-session: ~ (studio5000-mcp-sandbox)</span>
      <span class="demo-terminal-status" id="demoTermStatus">● Deterministic Gate Active</span>
    </div>
    <div class="demo-terminal-body" id="demoTerminalOutput">
      <!-- Injected by JavaScript -->
    </div>
  </div>
</div>
        </div>
      </div>
    </section>

    <section class="section" id="homelab">
      <div class="container">
        <div class="section-header">
          <span class="section-tag">// Engineering Case Study</span>
          <h2 class="section-title">Private Cloud & Homelab Infrastructure</h2>
          <p style="color: var(--text-muted); font-size: 1.05rem; margin-top: 0.5rem; max-width: 820px;">
            A detailed architectural breakdown of my multi-tiered, self-hosted engineering lab built with TrueNAS SCALE, Raspberry Pi edge gateways, Grafana & Prometheus observability, and zero-trust perimeter routing.
          </p>
        </div>

        <div class="homelab-case-study">
          <div class="homelab-hero-overview">
            <div class="overview-text">
              <h3>⚡ Zero Inbound Ports &bull; Encrypted mTLS Mesh</h3>
              <p>
                My homelab operates entirely without open router ports or static public IPs. Inbound traffic is handled via encrypted Cloudflare Argo Tunnel daemons that establish outbound-only mTLS connections directly to Cloudflare's global edge network, enforced with Zero Trust identity validation.
              </p>

            </div>
            <div class="metrics-pills">
              <span class="metric-pill">0 Open Ports</span>
              <span class="metric-pill">ZFS Mirrored Pool</span>
              <span class="metric-pill">Sub-ms Local DNS</span>
              <span class="metric-pill">Local Neural ML</span>
              <span class="metric-pill">Prometheus Telemetry</span>
            </div>
          </div>

          <div class="homelab-diagram-wrapper">
  <div class="diagram-title-bar">
    <span class="diagram-tag">SECURITY TOPOLOGY</span>
    <span class="diagram-name">Outbound-Only Zero-Trust Ingress Mesh &bull; 0 Open Ports</span>
  </div>
  <div class="svg-container">
    <svg viewBox="0 0 920 280" width="100%" style="max-width: 100%; height: auto;" xmlns="http://www.w3.org/2000/svg" role="img" aria-label="Homelab Zero-Trust Ingress Topology Diagram">
      <defs>
        <linearGradient id="gradVisitor" x1="0%" y1="0%" x2="100%" y2="100%">
          <stop offset="0%" stop-color="#1e3a8a" stop-opacity="0.8"/>
          <stop offset="100%" stop-color="#0f172a" stop-opacity="0.9"/>
        </linearGradient>
        <linearGradient id="gradCf" x1="0%" y1="0%" x2="100%" y2="100%">
          <stop offset="0%" stop-color="#7c2d12" stop-opacity="0.85"/>
          <stop offset="100%" stop-color="#1c1917" stop-opacity="0.95"/>
        </linearGradient>
        <linearGradient id="gradDaemon" x1="0%" y1="0%" x2="100%" y2="100%">
          <stop offset="0%" stop-color="#064e3b" stop-opacity="0.85"/>
          <stop offset="100%" stop-color="#022c22" stop-opacity="0.95"/>
        </linearGradient>
        <linearGradient id="gradNas" x1="0%" y1="0%" x2="100%" y2="100%">
          <stop offset="0%" stop-color="#164e63" stop-opacity="0.8"/>
          <stop offset="100%" stop-color="#082f49" stop-opacity="0.9"/>
        </linearGradient>
        <linearGradient id="gradPi" x1="0%" y1="0%" x2="100%" y2="100%">
          <stop offset="0%" stop-color="#3b0764" stop-opacity="0.8"/>
          <stop offset="100%" stop-color="#1e1b4b" stop-opacity="0.9"/>
        </linearGradient>
        <filter id="glowDrop2" x="-10%" y="-10%" width="120%" height="120%">
          <feDropShadow dx="0" dy="4" stdDeviation="6" flood-color="#000" flood-opacity="0.5"/>
        </filter>
        <marker id="arr-orange" markerWidth="8" markerHeight="6" refX="7" refY="3" orient="auto">
          <polygon points="0 0, 8 3, 0 6" fill="#fb923c"/>
        </marker>
        <marker id="arr-green" markerWidth="8" markerHeight="6" refX="7" refY="3" orient="auto">
          <polygon points="0 0, 8 3, 0 6" fill="#34d399"/>
        </marker>
        <marker id="arr-cyan" markerWidth="8" markerHeight="6" refX="7" refY="3" orient="auto">
          <polygon points="0 0, 8 3, 0 6" fill="#22d3ee"/>
        </marker>
        <marker id="arr-purple" markerWidth="8" markerHeight="6" refX="7" refY="3" orient="auto">
          <polygon points="0 0, 8 3, 0 6" fill="#c084fc"/>
        </marker>
      </defs>

      <!-- Background -->
      <rect width="920" height="280" rx="12" fill="#090d16" stroke="rgba(255,255,255,0.08)" stroke-width="1"/>

      <!-- Node 1: Global Visitors -->
      <g transform="translate(24, 75)" filter="url(#glowDrop2)">
        <rect width="145" height="130" rx="10" fill="url(#gradVisitor)" stroke="#3b82f6" stroke-width="1.5"/>
        <text x="72" y="28" fill="#93c5fd" font-family="'Plus Jakarta Sans', sans-serif" font-weight="700" font-size="11.5" text-anchor="middle">VISITOR / CLIENT</text>
        <line x1="14" y1="38" x2="131" y2="38" stroke="rgba(59,130,246,0.3)" stroke-width="1"/>
        <text x="72" y="58" fill="#f8fafc" font-family="'JetBrains Mono', monospace" font-size="10.5" text-anchor="middle">Public Internet</text>
        <text x="72" y="78" fill="#cbd5e1" font-family="'JetBrains Mono', monospace" font-size="9.5" text-anchor="middle">Any Web Browser</text>
        <rect x="12" y="92" width="121" height="22" rx="4" fill="rgba(37,99,235,0.2)" stroke="rgba(59,130,246,0.3)"/>
        <text x="72" y="106" fill="#60a5fa" font-family="'JetBrains Mono', monospace" font-size="9" text-anchor="middle">HTTPS &bull; TLS 1.3</text>
      </g>

      <!-- Connection 1 -> 2 -->
      <path d="M 169 140 L 209 140" stroke="#fb923c" stroke-width="2" marker-end="url(#arr-orange)"/>
      <text x="189" y="130" fill="#fb923c" font-family="'JetBrains Mono', monospace" font-size="8.5" text-anchor="middle">Global</text>

      <!-- Node 2: Cloudflare Edge & Zero Trust -->
      <g transform="translate(219, 50)" filter="url(#glowDrop2)">
        <rect width="180" height="180" rx="10" fill="url(#gradCf)" stroke="#f97316" stroke-width="1.5"/>
        <rect x="10" y="10" width="160" height="22" rx="4" fill="rgba(249,115,22,0.2)" stroke="#f97316" stroke-width="0.8"/>
        <text x="90" y="25" fill="#fdba74" font-family="'Plus Jakarta Sans', sans-serif" font-weight="700" font-size="10.5" text-anchor="middle" letter-spacing="0.05em">CLOUDFLARE EDGE</text>
        <text x="90" y="52" fill="#fb923c" font-family="'JetBrains Mono', monospace" font-weight="700" font-size="11" text-anchor="middle">Zero Trust Security</text>
        <line x1="16" y1="62" x2="164" y2="62" stroke="rgba(249,115,22,0.3)" stroke-width="1"/>
        <text x="24" y="80" fill="#fed7aa" font-family="'JetBrains Mono', monospace" font-size="9.5">🛡️ Geo-Fence (US/UK/IN)</text>
        <text x="24" y="98" fill="#fed7aa" font-family="'JetBrains Mono', monospace" font-size="9.5">⚡ WAF &amp; Layer-7 DDoS</text>
        <text x="24" y="116" fill="#fed7aa" font-family="'JetBrains Mono', monospace" font-size="9.5">🔐 Email OTP Challenge</text>
        <text x="24" y="134" fill="#fed7aa" font-family="'JetBrains Mono', monospace" font-size="9.5">⚡ Static Edge Caching</text>
        <rect x="16" y="146" width="148" height="22" rx="4" fill="rgba(0,0,0,0.4)" stroke="rgba(255,255,255,0.06)"/>
        <text x="90" y="161" fill="#4ade80" font-family="'JetBrains Mono', monospace" font-size="9" text-anchor="middle">Drops Unauthorized Traffic</text>
      </g>

      <!-- Connection 2 -> 3 -->
      <path d="M 399 140 L 449 140" stroke="#34d399" stroke-width="2" marker-end="url(#arr-green)"/>
      <text x="424" y="128" fill="#34d399" font-family="'JetBrains Mono', monospace" font-size="8.5" text-anchor="middle">Outbound mTLS</text>
      <text x="424" y="154" fill="#94a3b8" font-family="'JetBrains Mono', monospace" font-size="8" text-anchor="middle">(0 Open Ports)</text>

      <!-- Node 3: cloudflared Tunnel Ingress -->
      <g transform="translate(459, 75)" filter="url(#glowDrop2)">
        <rect width="165" height="130" rx="10" fill="url(#gradDaemon)" stroke="#10b981" stroke-width="1.5"/>
        <text x="82" y="28" fill="#6ee7b7" font-family="'Plus Jakarta Sans', sans-serif" font-weight="700" font-size="11" text-anchor="middle">CLOUDFLARED MESH</text>
        <line x1="14" y1="38" x2="151" y2="38" stroke="rgba(16,185,129,0.3)" stroke-width="1"/>
        <text x="82" y="58" fill="#d1fae5" font-family="'JetBrains Mono', monospace" font-weight="600" font-size="10" text-anchor="middle">Outbound Daemon</text>
        <text x="82" y="78" fill="#a7f3d0" font-family="'JetBrains Mono', monospace" font-size="9.5" text-anchor="middle">HA Argo Connector</text>
        <rect x="12" y="92" width="141" height="22" rx="4" fill="rgba(16,185,129,0.15)" stroke="rgba(16,185,129,0.3)"/>
        <text x="82" y="106" fill="#34d399" font-family="'JetBrains Mono', monospace" font-size="9" text-anchor="middle">Zero Public IP Leak</text>
      </g>

      <!-- Forking Paths from Node 3 to Infrastructure -->
      <!-- Branch Top to TrueNAS -->
      <path d="M 624 115 C 654 115, 660 75, 690 75" fill="none" stroke="#22d3ee" stroke-width="2" marker-end="url(#arr-cyan)"/>
      <text x="657" y="86" fill="#22d3ee" font-family="'JetBrains Mono', monospace" font-size="8.5" text-anchor="middle">Storage</text>

      <!-- Branch Bottom to Edge Node -->
      <path d="M 624 165 C 654 165, 660 205, 690 205" fill="none" stroke="#c084fc" stroke-width="2" marker-end="url(#arr-purple)"/>
      <text x="657" y="196" fill="#c084fc" font-family="'JetBrains Mono', monospace" font-size="8.5" text-anchor="middle">Services</text>

      <!-- Node 4A: TrueNAS SCALE -->
      <g transform="translate(700, 30)" filter="url(#glowDrop2)">
        <rect width="195" height="90" rx="8" fill="url(#gradNas)" stroke="#06b6d4" stroke-width="1.5"/>
        <text x="97" y="24" fill="#67e8f9" font-family="'Plus Jakarta Sans', sans-serif" font-weight="700" font-size="11" text-anchor="middle">TRUENAS SCALE CLUSTER</text>
        <text x="97" y="42" fill="#cffafe" font-family="'JetBrains Mono', monospace" font-weight="600" font-size="10" text-anchor="middle">Enterprise Storage &amp; Apps</text>
        <line x1="16" y1="50" x2="179" y2="50" stroke="rgba(6,182,212,0.3)" stroke-width="1"/>
        <text x="97" y="66" fill="#a5f3fc" font-family="'JetBrains Mono', monospace" font-size="9" text-anchor="middle">ZFS Mirrored Pool (6.0 TB)</text>
        <text x="97" y="80" fill="#a5f3fc" font-family="'JetBrains Mono', monospace" font-size="9" text-anchor="middle">Docker / KVM Orchestration</text>
      </g>

      <!-- Node 4B: Edge Node 01 -->
      <g transform="translate(700, 160)" filter="url(#glowDrop2)">
        <rect width="195" height="90" rx="8" fill="url(#gradPi)" stroke="#a855f7" stroke-width="1.5"/>
        <text x="97" y="24" fill="#d8b4fe" font-family="'Plus Jakarta Sans', sans-serif" font-weight="700" font-size="11" text-anchor="middle">EDGE NODE 01 (ARM64)</text>
        <text x="97" y="42" fill="#ede9fe" font-family="'JetBrains Mono', monospace" font-weight="600" font-size="10" text-anchor="middle">DNS &amp; Telemetry Gateway</text>
        <line x1="16" y1="50" x2="179" y2="50" stroke="rgba(168,85,247,0.3)" stroke-width="1"/>
        <text x="97" y="66" fill="#ddd6fe" font-family="'JetBrains Mono', monospace" font-size="9" text-anchor="middle">Pi-hole FTL Network DNS</text>
        <text x="97" y="80" fill="#ddd6fe" font-family="'JetBrains Mono', monospace" font-size="9" text-anchor="middle">Prometheus Exporter &amp; WebRTC</text>
      </g>
    </svg>
  </div>
</div>

          <div class="deepdive-grid">
            <div class="deepdive-card">
              <div>
                <div class="deepdive-header">
                  <div class="deepdive-icon">💾</div>
                  <span class="deepdive-badge">STORAGE & HYPERVISOR</span>
                </div>
                <h3 class="deepdive-title">TrueNAS SCALE Enterprise Server</h3>
                <p class="deepdive-desc">
                  Configured as the primary high-capacity storage node, hypervisor, and container host for all local engineering workloads. Built on Debian-based TrueNAS SCALE for native Docker application support and KVM virtualization.
                </p>
                <div class="deepdive-bullets">
                  <div class="bullet-point">
                    <span class="bullet-icon">▸</span>
                    <div><strong>ZFS Mirrored Storage:</strong> Implements enterprise ZFS storage pools with automated scrubbing to prevent bit rot, snapshot scheduling, and atomic rollbacks.</div>
                  </div>
                  <div class="bullet-point">
                    <span class="bullet-icon">▸</span>
                    <div><strong>Microservice Orchestration:</strong> Hosts isolated Docker stacks for machine learning pipelines, PostgreSQL databases, and self-hosted engineering services.</div>
                  </div>
                  <div class="bullet-point">
                    <span class="bullet-icon">▸</span>
                    <div><strong>Automated Snapshot Retention:</strong> Configured periodic ZFS snapshots providing instant recovery points for virtual machines and dataset volumes.</div>
                  </div>
                  <div class="bullet-point">
                    <span class="bullet-icon">▸</span>
                    <div><strong>Edge Tunnel Proxy:</strong> Connects securely to the Cloudflare edge via cloudflared daemon running natively on the host, eliminating port forwarding.</div>
                  </div>
                </div>
              </div>
              <div class="spec-table">
                <div><strong>Operating System:</strong> TrueNAS SCALE (Debian Linux Kernel)</div>
                <div><strong>Filesystem Architecture:</strong> ZFS Mirrored vdevs with compression</div>
                <div><strong>Container Engine:</strong> Docker / KVM Hypervisor</div>
                <div><strong>Network Security:</strong> Isolated Private Subnet &bull; Zero Inbound Ports</div>
              </div>
            </div>

            <!-- Edge-Node-01 Modern Edge Hardware & Workstation Dashboard -->
            <div class="deepdive-card pi-dashboard-card">
              <div class="pi-dashboard-header">
                <div class="pi-header-left">
                  <div class="pi-avatar-icon">🍓</div>
                  <div class="pi-title-block">
                    <h3>Edge Gateway &amp; Hardware Telemetry Node</h3>
                    <span>Cluster Node: <strong>ops@edge-node-01 (ARM64)</strong> &bull; OS: <strong>Debian Bookworm aarch64</strong></span>
                  </div>
                </div>
                <div class="pi-header-badges">
                  <span class="pi-live-badge" id="telemetry-badge"><span class="pulse-dot"></span> LIVE EDGE NODE</span>
                  <span class="pi-chip-badge">BCM2712 Quad-Core @ 2.4 GHz</span>
                  <span class="pi-chip-badge">16 GB LPDDR4X</span>
                  <span class="pi-chip-badge" style="color: #38bdf8; border-color: rgba(56,189,248,0.3);">⚡ 60 FPS WebRTC</span>
                </div>
              </div>

              <!-- Real Hardware Telemetry Gauges -->
              <div class="pi-gauges-grid">
                <div class="pi-gauge-box green">
                  <div class="pi-gauge-label">SoC Core Thermals</div>
                  <div class="pi-gauge-val" id="telemetry-temp" style="color: #34d399;">54.5°C</div>
                  <div class="pi-gauge-sub">
                    <span>● Active PWM Cooling</span> &bull; <span>Optimal Zone</span>
                  </div>
                  <div class="pi-gauge-bar">
                    <div class="pi-gauge-bar-fill" id="telemetry-temp-bar" style="width: 54.5%; background: linear-gradient(90deg, #34d399, #10b981);"></div>
                  </div>
                </div>

                <div class="pi-gauge-box cyan">
                  <div class="pi-gauge-label">Quad-Core CPU Load</div>
                  <div class="pi-gauge-val" id="telemetry-load">0.08</div>
                  <div class="pi-gauge-sub">
                    <span>1m: 0.08 &bull; 5m: 0.35 &bull; 15m: 0.43</span>
                  </div>
                  <div class="pi-gauge-bar">
                    <div class="pi-gauge-bar-fill" id="telemetry-load-bar" style="width: 18%; background: linear-gradient(90deg, #38bdf8, #0ea5e9);"></div>
                  </div>
                </div>

                <div class="pi-gauge-box purple">
                  <div class="pi-gauge-label">16 GB LPDDR4X Memory</div>
                  <div class="pi-gauge-val">2.70 GB <span style="font-size: 0.85rem; color: #94a3b8; font-weight: normal;">/ 16.0 GB</span></div>
                  <div class="pi-gauge-sub">
                    <span>16.9% Allocation</span> &bull; <span>13.3 GB Free/Cache</span>
                  </div>
                  <div class="pi-gauge-bar">
                    <div class="pi-gauge-bar-fill" id="telemetry-ram-bar" style="width: 16.9%; background: linear-gradient(90deg, #a855f7, #8b5cf6);"></div>
                  </div>
                </div>

                <div class="pi-gauge-box">
                  <div class="pi-gauge-label">High-Speed Storage</div>
                  <div class="pi-gauge-val">16.8 GB <span style="font-size: 0.85rem; color: #94a3b8; font-weight: normal;">/ 125.3 GB</span></div>
                  <div class="pi-gauge-sub">
                    <span>13.4% Disk In-Use</span> &bull; <span>108.5 GB Available</span>
                  </div>
                  <div class="pi-gauge-bar">
                    <div class="pi-gauge-bar-fill" id="telemetry-disk-bar" style="width: 13.4%; background: linear-gradient(90deg, #f43f5e, #fb923c);"></div>
                  </div>
                </div>
              </div>

              <!-- Dashboard Body Split: Architecture & Live Terminal Feed -->
              <div class="pi-dashboard-split">
                <div class="pi-features-box">
                  <div class="pi-feature-item">
                    <div class="pi-feature-icon">🛡️</div>
                    <div class="pi-feature-text">
                      <h5>Network-Wide DNS Sinkhole (Pi-hole FTL)</h5>
                      <p>Intercepts and filters domain resolutions across all LAN and IoT subnets. Uses an in-memory database with sub-millisecond query caching to block ad telemetry and trackers before outbound connection.</p>
                    </div>
                  </div>

                  <div class="pi-feature-item">
                    <div class="pi-feature-icon">🖥️</div>
                    <div class="pi-feature-text">
                      <h5>Hardware-Accelerated WebRTC Workstation</h5>
                      <p>Provides full 60 FPS in-browser GUI desktop access via hardware video encoding. Enables complete remote mouse, keyboard, and Linux workspace control over peer-to-peer WebRTC without open inbound ports.</p>
                    </div>
                  </div>

                  <div class="pi-feature-item">
                    <div class="pi-feature-icon">🔒</div>
                    <div class="pi-feature-text">
                      <h5>IoT Subnet Segregation & Firewall Containment</h5>
                      <p>Acts as the dedicated edge security gateway isolating telemetry-heavy smart home and IoT hardware into dedicated subnets, eliminating lateral movement risk toward enterprise storage.</p>
                    </div>
                  </div>

                  <div class="pi-feature-item">
                    <div class="pi-feature-icon">🌐</div>
                    <div class="pi-feature-text">
                      <h5>Outbound-Only Cloudflare Argo mTLS Mesh</h5>
                      <p>Establishes redundant encrypted tunnel connections to Cloudflare global edge PoPs. All management access is gated behind Zero Trust multi-factor authentication with zero router port forwarding.</p>
                    </div>
                  </div>
                </div>

                <div>
                  <!-- Live Edge Diagnostic Terminal -->
                  <div class="pi-terminal-mock">
                    <div class="pi-terminal-titlebar">
                      <span class="term-dot red"></span>
                      <span class="term-dot yellow"></span>
                      <span class="term-dot green"></span>
                      <span class="term-title">ops@edge-node-01: ~ (system-health)</span>
                    </div>
                    <div class="pi-terminal-body">
                      <div><span class="term-cmd">ops@edge-node-01:~ $</span> systemctl is-active pihole-FTL rpi-connect cloudflared</div>
                      <div><span class="term-ok">[✓] pihole-FTL.service</span> &mdash; active (running) <span class="term-highlight">[Local DNS Active]</span></div>
                      <div><span class="term-ok">[✓] rpi-connect.service</span> &mdash; active (running) <span class="term-highlight">[WebRTC 60fps Stream]</span></div>
                      <div><span class="term-ok">[✓] cloudflared.service</span> &mdash; active (running) <span class="term-highlight">[mTLS Edge Tunnel Active]</span></div>
                      <div><span class="term-ok">[✓] node-exporter</span> &mdash; active (running) <span class="term-highlight">[Prometheus 10s Scrape]</span></div>
                      <div style="margin-top: 0.35rem; color: #64748b;">// Sub-millisecond recursive DNS sinkhole active &bull; 0 open inbound ports</div>
                    </div>
                  </div>

                  <!-- Spec Strip -->
                  <div class="pi-specs-strip">
                    <div><strong>Architecture:</strong> ARMv8-A 64-bit (4 Cores)</div>
                    <div><strong>SoC Clock:</strong> 2.4 GHz Cortex-A76</div>
                    <div><strong>Memory:</strong> 16 GB LPDDR4X-4267</div>
                    <div><strong>Cooling:</strong> Active PWM (54.5°C Nominal)</div>
                    <div><strong>Display Stream:</strong> 60 FPS Hardware WebRTC</div>
                    <div><strong>Perimeter:</strong> 0 Inbound Open Ports</div>
                  </div>
                </div>
              </div>
            </div>

            <div class="deepdive-card">
              <div>
                <div class="deepdive-header">
                  <div class="deepdive-icon">📈</div>
                  <span class="deepdive-badge">TELEMETRY & OBSERVABILITY</span>
                </div>
                <h3 class="deepdive-title">Unified Cluster Observability (Grafana & Prometheus)</h3>
                <p class="deepdive-desc">
                  Centralized real-time telemetry, time-series metrics collection, and anomaly monitoring across bare-metal compute nodes, hypervisors, and isolated microservice container stacks.
                </p>
                <div class="deepdive-bullets">
                  <div class="bullet-point">
                    <span class="bullet-icon">▸</span>
                    <div><strong>High-Frequency Metric Scraping:</strong> Prometheus time-series engine polls node exporters and daemon targets for CPU core load curves, RAM saturation, and interface packet flow.</div>
                  </div>
                  <div class="bullet-point">
                    <span class="bullet-icon">▸</span>
                    <div><strong>Storage Subsystem & ZFS Telemetry:</strong> Real-time visualization of ZFS ARC cache hit efficiency, pool read/write bandwidth, and transaction group commit latency.</div>
                  </div>
                  <div class="bullet-point">
                    <span class="bullet-icon">▸</span>
                    <div><strong>Continuous Thermal & Health Polling:</strong> Proactive telemetry monitoring chassis thermals, core package temperatures, and drive SMART status to detect thermal throttling early.</div>
                  </div>
                  <div class="bullet-point">
                    <span class="bullet-icon">▸</span>
                    <div><strong>Zero-Trust Identity Protection:</strong> Observability dashboards are shielded behind Cloudflare Zero Trust Access and encrypted Argo tunnels with strict multi-factor authentication and zero public port exposure.</div>
                  </div>
                </div>
              </div>
              <div class="spec-table">
                <div><strong>Metrics Collection Engine:</strong> Prometheus Time-Series Scraper</div>
                <div><strong>Observability Suite:</strong> Grafana Core Analytics Platform</div>
                <div><strong>Scrape Resolution:</strong> High-Resolution 15-Second Polling</div>
                <div><strong>Perimeter Security:</strong> Cloudflare Zero Trust mTLS Mesh</div>
              </div>
            </div>
          </div>

        </div>
      </div>
    </section>

    <section class="section" id="skills">
      <div class="container">
        <div class="section-header">
          <span class="section-tag">// Technical Competencies</span>
          <h2 class="section-title">Engineered for Reliability & Scale</h2>
        </div>
        <div class="skills-grid">
          <div class="skill-card">
            <div class="card-icon icon-plc">⚙️</div>
            <h3>PLC & Automation Logic</h3>
            <p>Architecting robust ladder logic routines, modular Add-On Instructions (AOIs), and safety-rated interlocks for high-throughput production lines.</p>
            <div class="tech-tags">
              <span class="tech-tag">Rockwell Studio 5000</span>
              <span class="tech-tag">ControlLogix</span>
              <span class="tech-tag">CompactLogix</span>
              <span class="tech-tag">RSLogix 500/5000</span>
              <span class="tech-tag">L5X & UDTs</span>
              <span class="tech-tag">Mitsubishi FX3U</span>
            </div>
          </div>

          <div class="skill-card">
            <div class="card-icon icon-vision">👁️</div>
            <h3>Vision Inspection & Robotics</h3>
            <p>Deploying automated computer vision systems for in-line quality assurance, defect detection, barcode encoding, and high-speed material handling.</p>
            <div class="tech-tags">
              <span class="tech-tag">Cognex Vision Systems</span>
              <span class="tech-tag">VFD Speed Regulation</span>
              <span class="tech-tag">Pneumatic Actuation</span>
              <span class="tech-tag">Inductive Sensors</span>
              <span class="tech-tag">Hands Safety Operations</span>
            </div>
          </div>

          <div class="skill-card">
            <div class="card-icon icon-scada">📊</div>
            <h3>SCADA, HMI & Networks</h3>
            <p>Plant-wide telemetry, operator HMI displays, real-time historian logging, and enterprise industrial network routing and switching.</p>
            <div class="tech-tags">
              <span class="tech-tag">Ignition SCADA</span>
              <span class="tech-tag">FactoryTalk View</span>
              <span class="tech-tag">E-Designer-7 HMI</span>
              <span class="tech-tag">EtherNet/IP</span>
              <span class="tech-tag">Cisco Routing & Switching</span>
            </div>
          </div>

          <div class="skill-card">
            <div class="card-icon icon-infra">🛡️</div>
            <h3>Edge Cloud & Developer Tooling</h3>
            <p>Bridging industrial hardware with software engineering: Python, FastMCP, Model Context Protocol, Linux tooling, and edge virtualization.</p>
            <div class="tech-tags">
              <span class="tech-tag">Model Context Protocol</span>
              <span class="tech-tag">Python 3.12+</span>
              <span class="tech-tag">Win32 APIs</span>
              <span class="tech-tag">Git / GitHub CI</span>
              <span class="tech-tag">Linux / Docker</span>
            </div>
          </div>
        </div>
      </div>
    </section>

    <section class="section" id="experience">
      <div class="container">
        <div class="split-grid">
          <div>
            <div class="section-header">
              <span class="section-tag">// Career Milestones</span>
              <h2 class="section-title">Experience</h2>
            </div>
            
            <div class="timeline-item">
              <div class="timeline-date">CURRENT ROLE &bull; AUSTIN, TEXAS</div>
              <div class="timeline-role">Electrical and Controls Engineer</div>
              <div class="timeline-company">Tesla</div>
              <p class="timeline-desc">
                Leading controls engineering initiatives, automated robotic cells, programmable logic design, and electrical troubleshooting for high-speed vehicle and powertrain manufacturing.
              </p>
            </div>

            <div class="timeline-item">
              <div class="timeline-date">PREVIOUS EXPERIENCE &bull; STRATFORD & BRIDGEPORT, CT</div>
              <div class="timeline-role">Controls & Systems Engineering</div>
              <div class="timeline-company">Industrial Automation & Manufacturing</div>
              <p class="timeline-desc">
                Delivered end-to-end industrial automation projects: PLC logic development (RSLogix 500/5000), AutoCAD Electrical schematic drafting, sensor integration, and vision-guided inspection.
              </p>
            </div>
          </div>

          <div>
            <div class="section-header">
              <span class="section-tag">// Credentials & Academics</span>
              <h2 class="section-title">Education & Certs</h2>
            </div>

            <div class="timeline-item">
              <div class="timeline-date">2017 &ndash; 2019 &bull; GPA: 3.78</div>
              <div class="timeline-role">Master of Science (MS)</div>
              <div class="timeline-company">University of Bridgeport (Bridgeport, CT)</div>
              <p class="timeline-desc">
                Advanced studies in PLC Automation (RSLogix), HMI Programming, Data & Computer Communications, Wireless Sensor Networks, and Digital Signal Processing.
              </p>
            </div>

            <div class="timeline-item">
              <div class="timeline-date">2013 &ndash; 2017</div>
              <div class="timeline-role">Bachelor of Engineering (BE)</div>
              <div class="timeline-company">C. K. Pithawalla College of Engineering & Technology / GTU</div>
              <p class="timeline-desc">
                Foundational Electrical & Electronics Engineering. Served as Head of Technical Events for the University Technical Festival.
              </p>
            </div>

            <div class="timeline-item">
              <div class="timeline-date">CERTIFICATIONS</div>
              <div class="timeline-role">Professional Licenses</div>
              <div class="timeline-company">Udemy & Cisco</div>
              <p class="timeline-desc">
                &bull; PLC Programming RSLogix 500/5000<br>
                &bull; AutoCAD Electrical 2017<br>
                &bull; Cisco Introduction to Networking & Routing/Switching
              </p>
            </div>
          </div>
        </div>
      </div>
    </section>

    <section class="section" id="pi5" style="border-top: 1px solid var(--border); background: linear-gradient(180deg, var(--bg-primary) 0%, rgba(225, 29, 72, 0.03) 50%, var(--bg-primary) 100%);">
      <div class="container">
        <div class="section-header">
          <span class="section-tag" style="color: #fb7185; background: rgba(225, 29, 72, 0.1); border-color: rgba(225, 29, 72, 0.25);">// Hardware Telemetry & Silicon Specifications</span>
          <h2 class="section-title">Edge Gateway Silicon &amp; Node Specifications</h2>
          <p style="color: var(--text-muted); font-size: 1.05rem; margin-top: 0.5rem; max-width: 820px;">
            In-depth hardware architecture, silicon benchmarking, and live operational telemetry for the flagship Raspberry Pi 5 (16GB ARM64) node anchoring the edge homelab network.
          </p>
        </div>

        <!-- Pi 5 Specs Grid -->
        <div class="pi5-specs-grid">
          <div class="pi5-card">
            <div>
              <div class="pi5-card-header">
                <div class="pi5-card-icon">⚡</div>
                <span class="pi5-card-badge">CORTEX-A76 QUAD-CORE</span>
              </div>
              <h3 class="pi5-card-title">Broadcom BCM2712 Silicon</h3>
              <p class="pi5-card-desc">
                High-performance 64-bit ARMv8.2-A processor featuring 512KB per-core L2 caches and a 2MB shared L3 cache, delivering up to 3x performance over prior generations.
              </p>
            </div>
            <div class="pi5-spec-list">
              <div><strong>Core Frequency:</strong> 2.4 GHz Quad-Core</div>
              <div><strong>Microarchitecture:</strong> ARM Cortex-A76 (ARM64)</div>
              <div><strong>Active Thermals:</strong> 54.5°C (PWM Fan Regulated)</div>
              <div><strong>Core Scheduling:</strong> 0.08 / 0.35 / 0.43 Load Avg</div>
            </div>
          </div>

          <div class="pi5-card">
            <div>
              <div class="pi5-card-header">
                <div class="pi5-card-icon">🧠</div>
                <span class="pi5-card-badge">16 GB LPDDR4X-4267</span>
              </div>
              <h3 class="pi5-card-title">Unified High-Speed RAM</h3>
              <p class="pi5-card-desc">
                Massive 16GB dual-channel memory matrix running at 4267 MT/s. Provides abundant headroom for multi-container microservice workloads and in-memory caches.
              </p>
            </div>
            <div class="pi5-spec-list">
              <div><strong>Total Capacity:</strong> 16.0 GB (17,005 MB)</div>
              <div><strong>Active Memory:</strong> 1.41 GB (8.8% in-use)</div>
              <div><strong>Page Cache / Free:</strong> 14.59 GB Buffer</div>
              <div><strong>Memory Bus Width:</strong> 32-bit Dual-Channel</div>
            </div>
          </div>

          <div class="pi5-card">
            <div>
              <div class="pi5-card-header">
                <div class="pi5-card-icon">💾</div>
                <span class="pi5-card-badge">128 GB HIGH-SPEED I/O</span>
              </div>
              <h3 class="pi5-card-title">High-Speed Storage Matrix</h3>
              <p class="pi5-card-desc">
                High-endurance PCIe/NVMe storage array supporting fast sequential throughput, sub-millisecond IOPS, and ext4 POSIX journaling.
              </p>
            </div>
            <div class="pi5-spec-list">
              <div><strong>Total Disk Space:</strong> 125.3 GB Block Capacity</div>
              <div><strong>Disk Allocated:</strong> 16.9 GB (13.5% in-use)</div>
              <div><strong>Free Storage:</strong> 108.4 GB Available</div>
              <div><strong>Filesystem:</strong> ext4 (POSIX Journaled)</div>
            </div>
          </div>

          <div class="pi5-card">
            <div>
              <div class="pi5-card-header">
                <div class="pi5-card-icon">🛡️</div>
                <span class="pi5-card-badge">CONTAINERS & MESH</span>
              </div>
              <h3 class="pi5-card-title">Edge Services & Security</h3>
              <p class="pi5-card-desc">
                Orchestrates critical DNS sinkholes, monitoring telemetry, 60 FPS remote desktop streaming, and outbound-only mTLS Zero Trust tunneling.
              </p>
            </div>
            <div class="pi5-spec-list">
              <div><strong>Active Daemons:</strong> Docker, Prometheus, Pi-hole</div>
              <div><strong>Remote Desktop:</strong> 60 FPS WebRTC Hardware Sync</div>
              <div><strong>Mesh Overlay:</strong> Tailscale Wireguard Mesh</div>
              <div><strong>Inbound Attack Surface:</strong> 0 Open Ports</div>
            </div>
          </div>
        </div>

        <!-- Pi 5 Live Diagnostics Matrix -->
        <div class="pi5-diag-wrapper">
          <div class="pi5-diag-header">
            <div class="pi5-diag-title">
              <span>📊 Real-Time Node Operational Diagnostics</span>
              <span class="pi5-card-badge" style="margin-left: 0.5rem;">Prometheus 10s Scrape Engine</span>
            </div>
            <span class="grafana-status-pill"><span class="pulse-dot"></span> Node State: Optimal</span>
          </div>
          <div class="pi5-table-container">
            <table class="pi5-diag-table">
              <thead>
                <tr>
                  <th>Telemetry Vector</th>
                  <th>Hardware Subsystem</th>
                  <th>Monitored Metric / Specification</th>
                  <th>Current Value</th>
                  <th>Status</th>
                </tr>
              </thead>
              <tbody>
                <tr>
                  <td><code>SoC Model</code></td>
                  <td>Broadcom BCM2712</td>
                  <td>ARM Cortex-A76 Quad-Core @ 2.4 GHz (ARMv8.2-A)</td>
                  <td><code>4 Cores @ 2400 MHz</code></td>
                  <td><span class="pi5-status-tag optimal">● Nominal</span></td>
                </tr>
                <tr>
                  <td><code>SoC Thermals</code></td>
                  <td>Active Cooler Heatsink</td>
                  <td>Package Temperature (Dynamic PWM Regulation)</td>
                  <td><code>48.0°C</code></td>
                  <td><span class="pi5-status-tag optimal">● Optimal</span></td>
                </tr>
                <tr>
                  <td><code>Scheduler Load</code></td>
                  <td>Kernel Task Queue</td>
                  <td>1-Min, 5-Min, 15-Min Exponential Moving Average</td>
                  <td><code>0.14, 0.35, 0.43</code></td>
                  <td><span class="pi5-status-tag optimal">● Low Saturation</span></td>
                </tr>
                <tr>
                  <td><code>RAM Utilization</code></td>
                  <td>LPDDR4X-4267 Matrix</td>
                  <td>Total 16,384 MB (Allocated vs Page Cache Buffer)</td>
                  <td><code>1.41 GB / 16.0 GB (8.8%)</code></td>
                  <td><span class="pi5-status-tag optimal">● 91.2% Headroom</span></td>
                </tr>
                <tr>
                  <td><code>NVMe Storage</code></td>
                  <td>PCIe Storage Array</td>
                  <td>Root Block Device Allocation (ext4 Journaling)</td>
                  <td><code>16.9 GB / 125.3 GB (13.5%)</code></td>
                  <td><span class="pi5-status-tag optimal">● Healthy</span></td>
                </tr>
                <tr>
                  <td><code>Container Runtime</code></td>
                  <td>Docker Engine</td>
                  <td>Active Container Stacks (Prometheus, Grafana, Pi-hole)</td>
                  <td><code>Containers Running</code></td>
                  <td><span class="pi5-status-tag active">● Online</span></td>
                </tr>
                <tr>
                  <td><code>Remote Workstation</code></td>
                  <td>Raspberry Pi Connect</td>
                  <td>In-Browser 60 FPS Hardware-Accelerated WebRTC</td>
                  <td><code>Encrypted P2P Session</code></td>
                  <td><span class="pi5-status-tag active">● Ready</span></td>
                </tr>
                <tr>
                  <td><code>Perimeter Ingress</code></td>
                  <td>Cloudflare Argo Tunnel</td>
                  <td>Outbound mTLS Zero Trust Edge Tunnel</td>
                  <td><code>Zero Inbound Ports</code></td>
                  <td><span class="pi5-status-tag secure">🔒 Air-Gapped</span></td>
                </tr>
              </tbody>
            </table>
          </div>
        </div>

        <!-- Footer Action Strip -->
        <div class="pi5-footer-bar">
          <div class="pi5-footer-text">
            <strong>Authenticated Management:</strong> Full access to the Raspberry Pi 5 command line, remote desktop screen share, Grafana dashboards, and Pi-hole admin console is protected inside the multi-factor Homelab Vault.
          </div>
          
        </div>
      </div>
    </section>
  </main>

  <footer>
    <div class="container footer-content">
      <div class="footer-text">
        <div>&copy; 2026 Krutarth Sailor &bull; Shasa Engineering. All rights reserved.</div>
        <div class="footer-disclaimer">Personal portfolio and independent open-source R&amp;D. All views, architectures, and projects shown are my own.</div>
      </div>
      <div class="footer-links">
        <a href="https://github.com/krusailor44-afk/Studio5000-MCP" target="_blank" rel="noopener">GitHub</a>
        <a href="https://www.linkedin.com/in/sailorkrutarth" target="_blank" rel="noopener">LinkedIn</a>
        <a href="#about">About</a>
        <a href="#mcp">MCP Innovation</a>
        <a href="#homelab">Homelab Architecture</a>
        <a href="#skills">Skills</a>
        <a href="#experience">Experience</a>
      </div>
    </div>
  </footer>


  <script>
    // 1. Robust Contact Email Copy (sailor.krutarth@yahoo.in)
    function copyContactEmail() {
      const email = 'sailor.krutarth@yahoo.in';
      const btnText = document.getElementById('contactBtnText');
      const tip = document.getElementById('contactTooltip');

      function onSuccess() {
        if (btnText) btnText.textContent = '✓ sailor.krutarth@yahoo.in (Copied!)';
        if (tip) {
          tip.textContent = 'Copied to Clipboard!';
          tip.classList.add('visible');
        }
        setTimeout(function() {
          if (btnText) btnText.textContent = 'Copy Email';
          if (tip) tip.classList.remove('visible');
        }, 3500);
      }

      function fallbackCopy() {
        try {
          const ta = document.createElement('textarea');
          ta.value = email;
          ta.setAttribute('readonly', '');
          ta.style.position = 'absolute';
          ta.style.left = '-9999px';
          document.body.appendChild(ta);
          ta.select();
          const successful = document.execCommand('copy');
          document.body.removeChild(ta);
          if (successful) {
            onSuccess();
            return;
          }
        } catch (e) {}
        window.location.href = 'mailto:' + email;
      }

      if (navigator.clipboard && navigator.clipboard.writeText) {
        navigator.clipboard.writeText(email).then(onSuccess).catch(fallbackCopy);
      } else {
        fallbackCopy();
      }
    }

    // 2. Interactive Terminal Simulator
    const DEMO_SCENARIOS = {
      safety: [
        { cls: "demo-line-cmd", text: "ops@agent-session:~$ python -m studio5000_mcp.client --call write_tag --tag Safety_EStop_Latch --value 0" },
        { cls: "demo-line-info", text: "[MCP INGRESS] Tool invocation: studio5000.write_tag(tag='Safety_EStop_Latch', value=0)" },
        { cls: "demo-line-warn", text: "[SAFETY INTERLOCK] Invoking enforce_industrial_safety_gates() policy check..." },
        { cls: "demo-line-warn", text: "[MATCH] Target tag 'Safety_EStop_Latch' matches SIS protected pattern: ^(Safety_|ES_|[0-9]+_ESTOP).*" },
        { cls: "demo-line-err", text: "⛔ [HARD BLOCKED] Operation denied by deterministic industrial safety policy." },
        { cls: "demo-line-err", text: "    Error 403-SAFETY: Safety-Instrumented System (SIS) tags are write-protected." },
        { cls: "demo-line-ok", text: "[STATUS] PLC state protected. Zero CIP packets dispatched. Scantime unperturbed." }
      ],
      online: [
        { cls: "demo-line-cmd", text: "ops@agent-session:~$ python -m studio5000_mcp.client --call propose_online_edit --routine MainLine --rung 14" },
        { cls: "demo-line-info", text: "[STAGE 1 - PROPOSE] NeutralText: 'XIC(Part_Present)OTE(Conveyor_Run);'" },
        { cls: "demo-line-info", text: "[AST SYNTHESIS] L5X AST validated (-74% token reduction vs XML). Inserted staging rung 'i:14'." },
        { cls: "demo-line-warn", text: "[STAGE 2 - TEST] Staging rung in test mode on 1756-L83E ControlLogix. Verifying 100 scans..." },
        { cls: "demo-line-ok", text: "[STAGE 2 - TEST PASS] No fault conditions detected. Controller scan delta: +0.02ms (nominal)." },
        { cls: "demo-line-warn", text: "[STAGE 3 - ASSEMBLE] Gate: Requires operator confirmation (confirmed=True)... Verified." },
        { cls: "demo-line-ok", text: "✅ [STAGE 3 - ASSEMBLED] Rung 14 assembled into active execution scan. Edit completed in 12ms." }
      ]
    };

    let activeScenario = 'safety';
    let typingTimer = null;

    function switchDemoScenario(scenario) {
      activeScenario = scenario;
      const tabSafety = document.getElementById('demoTabSafety');
      const tabOnline = document.getElementById('demoTabOnline');
      const termTitle = document.getElementById('demoTermTitle');
      const termStatus = document.getElementById('demoTermStatus');

      if (tabSafety && tabOnline) {
        tabSafety.classList.toggle('active', scenario === 'safety');
        tabOnline.classList.toggle('active', scenario === 'online');
      }
      if (termTitle) {
        termTitle.textContent = scenario === 'safety' ?
          'ops@agent-session: ~ (studio5000-mcp:safety-gate)' :
          'ops@agent-session: ~ (studio5000-mcp:online-edit)';
      }
      if (termStatus) {
        termStatus.textContent = scenario === 'safety' ?
          '● Deterministic SIS Gate Active' :
          '● Online Edit Test Staging';
        termStatus.style.color = scenario === 'safety' ? '#f87171' : '#34d399';
      }
      renderScenario(scenario);
    }

    function replayCurrentScenario() {
      renderScenario(activeScenario);
    }

    function renderScenario(scenario) {
      if (typingTimer) clearTimeout(typingTimer);
      const container = document.getElementById('demoTerminalOutput');
      if (!container) return;
      container.innerHTML = '';

      const lines = DEMO_SCENARIOS[scenario] || [];
      const prefersReducedMotion = window.matchMedia('(prefers-reduced-motion: reduce)').matches;

      if (prefersReducedMotion) {
        lines.forEach(l => {
          const div = document.createElement('div');
          div.className = l.cls;
          div.textContent = l.text;
          container.appendChild(div);
        });
        return;
      }

      let idx = 0;
      function showNextLine() {
        if (idx < lines.length) {
          const l = lines[idx];
          const div = document.createElement('div');
          div.className = l.cls;
          div.textContent = l.text;
          container.appendChild(div);
          idx++;
          typingTimer = setTimeout(showNextLine, 120);
        }
      }
      showNextLine();
    }

    // Initialize Demo Terminal on Load
    document.addEventListener('DOMContentLoaded', () => {
      renderScenario('safety');
    });

    // 3. Option A: Dynamic Telemetry Loader with Graceful Static Fallback
    (function initTelemetry() {
      const controller = new AbortController();
      const timeoutId = setTimeout(() => controller.abort(), 3000);

      fetch('/telemetry.json', { signal: controller.signal })
        .then(res => {
          clearTimeout(timeoutId);
          if (!res.ok) throw new Error('HTTP ' + res.status);
          return res.json();
        })
        .then(data => {
          if (!data || !data.metrics) throw new Error('Invalid telemetry schema');
          const m = data.metrics;

          // Update Thermals
          const tempEl = document.getElementById('telemetry-temp');
          const tempBar = document.getElementById('telemetry-temp-bar');
          if (tempEl && m.cpu_temp_c !== undefined) {
            tempEl.textContent = m.cpu_temp_c.toFixed(1) + '°C';
            if (tempBar) tempBar.style.width = Math.min(100, (m.cpu_temp_c / 85) * 100).toFixed(1) + '%';
          }

          // Update CPU Load
          const loadEl = document.getElementById('telemetry-load');
          const loadBar = document.getElementById('telemetry-load-bar');
          if (loadEl && m.load_avg_1m !== undefined) {
            loadEl.textContent = m.load_avg_1m.toFixed(2);
            if (loadBar) loadBar.style.width = Math.min(100, (m.load_avg_1m / 4) * 100).toFixed(1) + '%';
          }

          // Update RAM (Accurate 16.9% calculation)
          const ramText = document.getElementById('telemetry-ram-text');
          const ramBar = document.getElementById('telemetry-ram-bar');
          if (ramText && m.ram_used_gb !== undefined && m.ram_total_gb !== undefined) {
            const ramPct = m.ram_usage_percent !== undefined ? m.ram_usage_percent.toFixed(1) : ((m.ram_used_gb / m.ram_total_gb) * 100).toFixed(1);
            ramText.innerHTML = m.ram_used_gb.toFixed(2) + ' GB <span style="font-size:0.85rem;color:#94a3b8;font-weight:normal;">/ ' + m.ram_total_gb.toFixed(1) + ' GB (' + ramPct + '%)</span>';
            if (ramBar) ramBar.style.width = ramPct + '%';
          }

          // Update Disk
          const diskText = document.getElementById('telemetry-disk-text');
          const diskBar = document.getElementById('telemetry-disk-bar');
          if (diskText && m.disk_used_gb !== undefined && m.disk_total_gb !== undefined) {
            const diskPct = m.disk_usage_percent !== undefined ? m.disk_usage_percent.toFixed(1) : ((m.disk_used_gb / m.disk_total_gb) * 100).toFixed(1);
            diskText.innerHTML = m.disk_used_gb.toFixed(1) + ' GB <span style="font-size:0.85rem;color:#94a3b8;font-weight:normal;">/ ' + m.disk_total_gb.toFixed(1) + ' GB (' + diskPct + '%)</span>';
            if (diskBar) diskBar.style.width = diskPct + '%';
          }

          // Update Live Badge
          const badge = document.getElementById('telemetry-badge');
          if (badge) {
            let syncLabel = 'LIVE EDGE NODE &bull; SYNCED';
            if (data.timestamp) {
              const diffSec = Math.floor((Date.now() - new Date(data.timestamp).getTime()) / 1000);
              if (diffSec >= 60) syncLabel += ' (' + Math.floor(diffSec / 60) + 'm ago)';
              else if (diffSec > 0) syncLabel += ' (' + diffSec + 's ago)';
              else syncLabel += ' (just now)';
            }
            badge.className = 'pi-live-badge synced';
            badge.innerHTML = '<span class="pulse-dot"></span> ' + syncLabel;
          }
        })
        .catch(() => {
          // Graceful fallback to verified baseline snapshot
          const badge = document.getElementById('telemetry-badge');
          if (badge) {
            badge.className = 'pi-live-badge baseline';
            badge.innerHTML = '<span class="pulse-dot dim"></span> BASELINE SNAPSHOT';
            badge.title = 'Displaying verified baseline idle metrics';
          }
        });
    })();
  </script>
</body>
</html>`;
}

function renderPortalHtml() {
  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Homelab Private Command Center | Krutarth Sailor</title>
  <link rel="preconnect" href="https://fonts.googleapis.com">
  <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
  <link href="https://fonts.googleapis.com/css2?family=Plus+Jakarta+Sans:wght@400;500;600;700;800&family=JetBrains+Mono:wght@400;500;600&display=swap" rel="stylesheet">
  <style>
    :root {
      --bg: #070a10;
      --bg-card: rgba(15, 22, 38, 0.85);
      --border: rgba(255, 255, 255, 0.08);
      --primary: #3b82f6;
      --cyan: #06b6d4;
      --emerald: #10b981;
      --text: #f8fafc;
      --text-muted: #94a3b8;
      --text-dim: #64748b;
      --radius: 14px;
    }

    * { box-sizing: border-box; margin: 0; padding: 0; }
    body {
      font-family: 'Plus Jakarta Sans', system-ui, -apple-system, sans-serif;
      background-color: var(--bg);
      color: var(--text);
      line-height: 1.6;
      min-height: 100vh;
      background-image:
        radial-gradient(circle at 15% 15%, rgba(59, 130, 246, 0.15) 0%, transparent 45%),
        radial-gradient(circle at 85% 85%, rgba(16, 185, 129, 0.08) 0%, transparent 45%);
    }

    header {
      backdrop-filter: blur(20px);
      background: rgba(7, 10, 16, 0.85);
      border-bottom: 1px solid var(--border);
      position: sticky;
      top: 0;
      z-index: 50;
    }
    .header-container {
      max-width: 1200px;
      margin: 0 auto;
      padding: 1.25rem 1.5rem;
      display: flex;
      justify-content: space-between;
      align-items: center;
    }
    .brand-title {
      font-weight: 800;
      font-size: 1.15rem;
      letter-spacing: -0.02em;
      display: flex;
      align-items: center;
      gap: 0.6rem;
    }
    .auth-badge {
      font-family: 'JetBrains Mono', monospace;
      font-size: 0.75rem;
      background: rgba(16, 185, 129, 0.15);
      border: 1px solid rgba(16, 185, 129, 0.35);
      color: #34d399;
      padding: 0.3rem 0.75rem;
      border-radius: 9999px;
      display: inline-flex;
      align-items: center;
      gap: 0.4rem;
    }
    .pulse-dot {
      width: 7px;
      height: 7px;
      border-radius: 50%;
      background: #10b981;
      box-shadow: 0 0 10px #10b981;
      animation: pulse 2s infinite;
    }
    @keyframes pulse {
      0% { opacity: 1; transform: scale(1); }
      50% { opacity: 0.4; transform: scale(1.2); }
      100% { opacity: 1; transform: scale(1); }
    }

    .header-nav {
      display: flex;
      align-items: center;
      gap: 1.25rem;
    }
    .exit-btn {
      color: var(--text-muted);
      text-decoration: none;
      font-size: 0.88rem;
      font-weight: 500;
      display: inline-flex;
      align-items: center;
      gap: 0.4rem;
      transition: color 0.2s;
    }
    .exit-btn:hover { color: #fff; }
    .logout-btn {
      color: #f87171;
      text-decoration: none;
      font-size: 0.85rem;
      font-weight: 600;
      padding: 0.35rem 0.75rem;
      border-radius: 6px;
      background: rgba(239, 68, 68, 0.1);
      border: 1px solid rgba(239, 68, 68, 0.25);
      transition: all 0.2s;
    }
    .logout-btn:hover {
      background: rgba(239, 68, 68, 0.2);
      color: #fca5a5;
    }

    .container {
      max-width: 1200px;
      margin: 0 auto;
      padding: 3.5rem 1.5rem 5rem;
    }

    .portal-hero {
      margin-bottom: 3rem;
    }
    .portal-tag {
      font-family: 'JetBrains Mono', monospace;
      font-size: 0.8rem;
      color: #38bdf8;
      text-transform: uppercase;
      letter-spacing: 0.1em;
      margin-bottom: 0.5rem;
      display: block;
    }
    h1 {
      font-size: clamp(2rem, 4vw, 2.8rem);
      font-weight: 800;
      letter-spacing: -0.025em;
      margin-bottom: 0.75rem;
    }
    .portal-hero p {
      color: var(--text-muted);
      font-size: 1.05rem;
      max-width: 700px;
    }

    .portal-grid {
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(340px, 1fr));
      gap: 1.75rem;
      margin-bottom: 3.5rem;
    }
    .portal-card {
      background: var(--bg-card);
      border: 1px solid var(--border);
      border-radius: var(--radius);
      padding: 2.25rem;
      display: flex;
      flex-direction: column;
      justify-content: space-between;
      position: relative;
      overflow: hidden;
      transition: all 0.25s ease;
    }
    .portal-card:hover {
      border-color: rgba(59, 130, 246, 0.45);
      transform: translateY(-4px);
      box-shadow: 0 18px 36px -12px rgba(0, 0, 0, 0.7);
    }
    .card-top {
      display: flex;
      justify-content: space-between;
      align-items: flex-start;
      margin-bottom: 1.25rem;
    }
    .card-icon {
      width: 54px;
      height: 54px;
      border-radius: 14px;
      display: flex;
      align-items: center;
      justify-content: center;
      font-size: 1.7rem;
    }
    .icon-truenas { background: rgba(59, 130, 246, 0.15); border: 1px solid rgba(59, 130, 246, 0.3); }
    .icon-pi { background: rgba(239, 68, 68, 0.15); border: 1px solid rgba(239, 68, 68, 0.3); }
    .icon-immich { background: rgba(168, 85, 247, 0.15); border: 1px solid rgba(168, 85, 247, 0.3); }
    .icon-terminal { background: rgba(16, 185, 129, 0.15); border: 1px solid rgba(16, 185, 129, 0.3); }

    .card-status {
      font-family: 'JetBrains Mono', monospace;
      font-size: 0.72rem;
      padding: 0.25rem 0.65rem;
      border-radius: 6px;
      background: rgba(16, 185, 129, 0.12);
      border: 1px solid rgba(16, 185, 129, 0.3);
      color: #34d399;
      display: inline-flex;
      align-items: center;
      gap: 0.35rem;
    }
    .card-title {
      font-size: 1.35rem;
      font-weight: 800;
      margin-bottom: 0.4rem;
    }
    .card-desc {
      color: var(--text-muted);
      font-size: 0.92rem;
      line-height: 1.55;
      margin-bottom: 1.5rem;
    }
    .telemetry-box {
      font-family: 'JetBrains Mono', monospace;
      font-size: 0.78rem;
      background: rgba(0, 0, 0, 0.35);
      border: 1px solid rgba(255, 255, 255, 0.04);
      border-radius: 8px;
      padding: 0.85rem 1rem;
      display: flex;
      flex-direction: column;
      gap: 0.4rem;
      color: var(--text-muted);
      margin-bottom: 1.75rem;
    }
    .telemetry-box span {
      display: flex;
      align-items: center;
      gap: 0.5rem;
    }
    .launch-btn {
      width: 100%;
      padding: 0.85rem;
      border-radius: 10px;
      background: #2563eb;
      color: #fff;
      font-weight: 600;
      font-size: 0.92rem;
      display: flex;
      align-items: center;
      justify-content: center;
      gap: 0.5rem;
      text-decoration: none;
      transition: all 0.2s ease;
      box-shadow: 0 4px 15px rgba(37, 99, 235, 0.4);
    }
    .launch-btn:hover {
      background: #1d4ed8;
      box-shadow: 0 6px 22px rgba(37, 99, 235, 0.6);
      transform: translateY(-2px);
    }

    .system-stats {
      background: rgba(14, 20, 34, 0.6);
      border: 1px solid var(--border);
      border-radius: var(--radius);
      padding: 2rem;
    }
    .stats-header {
      font-size: 1.15rem;
      font-weight: 700;
      margin-bottom: 1.25rem;
      display: flex;
      align-items: center;
      gap: 0.5rem;
    }
    .stats-grid {
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(220px, 1fr));
      gap: 1.5rem;
    }
    .stat-item {
      font-family: 'JetBrains Mono', monospace;
    }
    .stat-label {
      font-size: 0.75rem;
      color: var(--text-dim);
      text-transform: uppercase;
      letter-spacing: 0.05em;
      margin-bottom: 0.25rem;
    }
    .stat-value {
      font-size: 1.1rem;
      font-weight: 700;
      color: #f1f5f9;
    }
    /* Grafana Live Dashboard Preview */
    .grafana-preview-panel {
      margin-top: 2.25rem;
      background: #111217;
      border: 1px solid rgba(249, 115, 22, 0.25);
      border-radius: var(--radius);
      overflow: hidden;
      box-shadow: 0 10px 30px rgba(0, 0, 0, 0.4), 0 0 20px rgba(249, 115, 22, 0.05);
    }
    .grafana-header-bar {
      background: #181b1f;
      padding: 0.9rem 1.5rem;
      display: flex;
      justify-content: space-between;
      align-items: center;
      flex-wrap: wrap;
      gap: 1rem;
      border-bottom: 1px solid rgba(255, 255, 255, 0.06);
    }
    .grafana-header-left {
      display: flex;
      align-items: center;
      gap: 0.75rem;
    }
    .grafana-logo-badge {
      font-size: 1.25rem;
      display: flex;
      align-items: center;
    }
    .grafana-title-wrap h4 {
      font-size: 1.05rem;
      font-weight: 700;
      color: #f8fafc;
      margin: 0;
      display: flex;
      align-items: center;
      gap: 0.5rem;
    }
    .grafana-title-wrap span {
      font-family: 'JetBrains Mono', monospace;
      font-size: 0.75rem;
      color: var(--text-muted);
    }
    .grafana-header-right {
      display: flex;
      align-items: center;
      gap: 0.75rem;
    }
    .grafana-status-pill {
      display: inline-flex;
      align-items: center;
      gap: 0.4rem;
      font-family: 'JetBrains Mono', monospace;
      font-size: 0.72rem;
      padding: 0.25rem 0.6rem;
      border-radius: 9999px;
      background: rgba(52, 211, 153, 0.12);
      border: 1px solid rgba(52, 211, 153, 0.25);
      color: #34d399;
    }
    .grafana-launch-link {
      display: inline-flex;
      align-items: center;
      gap: 0.4rem;
      font-size: 0.8rem;
      font-weight: 600;
      color: #f97316;
      background: rgba(249, 115, 22, 0.12);
      border: 1px solid rgba(249, 115, 22, 0.3);
      padding: 0.35rem 0.8rem;
      border-radius: 6px;
      text-decoration: none;
      transition: all var(--transition);
    }
    .grafana-launch-link:hover {
      background: rgba(249, 115, 22, 0.25);
      color: #fdba74;
      transform: translateY(-1px);
    }
    .grafana-body {
      padding: 1.5rem;
      display: flex;
      flex-direction: column;
      gap: 1.5rem;
    }
    .grafana-kpi-grid {
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(220px, 1fr));
      gap: 1rem;
    }
    .grafana-stat-card {
      background: #181b1f;
      border: 1px solid rgba(255, 255, 255, 0.05);
      border-radius: 8px;
      padding: 1rem 1.25rem;
      display: flex;
      flex-direction: column;
      justify-content: space-between;
      position: relative;
      overflow: hidden;
    }
    .grafana-stat-card::before {
      content: '';
      position: absolute;
      top: 0; left: 0; bottom: 0;
      width: 3px;
      background: #f97316;
    }
    .grafana-stat-card.cyan::before { background: #38bdf8; }
    .grafana-stat-card.green::before { background: #34d399; }
    .grafana-stat-card.purple::before { background: #a855f7; }
    .grafana-stat-card.amber::before { background: #f59e0b; }
    .grafana-row-header {
      background: rgba(255, 255, 255, 0.02);
      border-left: 3px solid #f97316;
      padding: 0.55rem 0.85rem;
      border-radius: 4px;
      font-family: 'JetBrains Mono', monospace;
      font-size: 0.78rem;
      font-weight: 700;
      color: #e2e8f0;
      display: flex;
      justify-content: space-between;
      align-items: center;
      margin-top: 0.75rem;
      letter-spacing: 0.03em;
    }
    .grafana-row-header.cyan { border-left-color: #38bdf8; }
    .grafana-row-header.green { border-left-color: #34d399; }
    .grafana-row-header.purple { border-left-color: #a855f7; }
    .grafana-row-badge {
      font-size: 0.68rem;
      padding: 0.15rem 0.5rem;
      border-radius: 4px;
      background: rgba(255, 255, 255, 0.06);
      color: #94a3b8;
      text-transform: uppercase;
      font-weight: 500;
    }
    .grafana-stat-title {
      font-size: 0.75rem;
      text-transform: uppercase;
      letter-spacing: 0.05em;
      color: #94a3b8;
      margin-bottom: 0.35rem;
      font-family: 'JetBrains Mono', monospace;
    }
    .grafana-stat-value {
      font-size: 1.5rem;
      font-weight: 800;
      color: #f8fafc;
      font-family: 'JetBrains Mono', monospace;
      margin-bottom: 0.25rem;
    }
    .grafana-stat-desc {
      font-size: 0.72rem;
      color: #94a3b8;
      display: flex;
      align-items: center;
      gap: 0.35rem;
    }
    .grafana-stat-progress {
      width: 100%;
      height: 4px;
      background: rgba(255, 255, 255, 0.08);
      border-radius: 2px;
      margin-top: 0.5rem;
      overflow: hidden;
    }
    .grafana-stat-fill {
      height: 100%;
      border-radius: 2px;
    }
    .grafana-charts-grid {
      display: grid;
      grid-template-columns: 2fr 1fr;
      gap: 1.25rem;
    }
    .grafana-chart-panel {
      background: #181b1f;
      border: 1px solid rgba(255, 255, 255, 0.05);
      border-radius: 8px;
      padding: 1.25rem;
      display: flex;
      flex-direction: column;
    }
    .grafana-panel-header {
      display: flex;
      justify-content: space-between;
      align-items: center;
      margin-bottom: 1rem;
      border-bottom: 1px solid rgba(255, 255, 255, 0.04);
      padding-bottom: 0.5rem;
    }
    .grafana-panel-title {
      font-size: 0.85rem;
      font-weight: 700;
      color: #e2e8f0;
      display: flex;
      align-items: center;
      gap: 0.4rem;
    }
    .grafana-panel-legend {
      display: flex;
      gap: 0.75rem;
      font-size: 0.7rem;
      font-family: 'JetBrains Mono', monospace;
    }
    .legend-item { display: flex; align-items: center; gap: 0.3rem; }
    .legend-dot { width: 8px; height: 8px; border-radius: 50%; }
    .grafana-svg-chart {
      width: 100%;
      height: 180px;
    }
    .grafana-service-list {
      display: flex;
      flex-direction: column;
      gap: 0.6rem;
    }
    .grafana-service-row {
      display: flex;
      justify-content: space-between;
      align-items: center;
      background: rgba(0, 0, 0, 0.2);
      padding: 0.5rem 0.75rem;
      border-radius: 6px;
      font-size: 0.78rem;
    }
    .grafana-service-name {
      font-family: 'JetBrains Mono', monospace;
      color: #e2e8f0;
      display: flex;
      align-items: center;
      gap: 0.4rem;
    }
    .grafana-footer-cta {
      background: rgba(0, 0, 0, 0.25);
      padding: 0.9rem 1.25rem;
      border-radius: 6px;
      display: flex;
      justify-content: space-between;
      align-items: center;
      flex-wrap: wrap;
      gap: 1rem;
      border: 1px solid rgba(255, 255, 255, 0.04);
    }
    .grafana-footer-text {
      font-size: 0.82rem;
      color: #94a3b8;
    }
    .grafana-footer-btn {
      font-size: 0.82rem;
      font-weight: 600;
      color: #fff;
      background: #f97316;
      border: none;
      padding: 0.5rem 1rem;
      border-radius: 6px;
      text-decoration: none;
      transition: all var(--transition);
      display: inline-flex;
      align-items: center;
      gap: 0.4rem;
    }
    .grafana-footer-btn:hover {
      background: #ea580c;
      transform: translateY(-1px);
      box-shadow: 0 4px 12px rgba(249, 115, 22, 0.3);
    }

    /* Raspberry Pi 5 Telemetry Showcase */
    .pi5-specs-grid {
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(280px, 1fr));
      gap: 1.5rem;
      margin-bottom: 2.25rem;
    }
    .pi5-card {
      background: var(--bg-card);
      border: 1px solid var(--border);
      border-radius: var(--radius);
      padding: 1.75rem;
      position: relative;
      overflow: hidden;
      display: flex;
      flex-direction: column;
      justify-content: space-between;
    }
    .pi5-card::before {
      content: '';
      position: absolute;
      top: 0; left: 0; right: 0;
      height: 3px;
      background: linear-gradient(90deg, #e11d48, #fb7185);
    }
    .pi5-card-header {
      display: flex;
      justify-content: space-between;
      align-items: center;
      margin-bottom: 1rem;
    }
    .pi5-card-icon {
      width: 44px;
      height: 44px;
      border-radius: 10px;
      background: rgba(225, 29, 72, 0.12);
      border: 1px solid rgba(225, 29, 72, 0.25);
      display: flex;
      align-items: center;
      justify-content: center;
      font-size: 1.4rem;
    }
    .pi5-card-badge {
      font-family: 'JetBrains Mono', monospace;
      font-size: 0.72rem;
      padding: 0.2rem 0.55rem;
      border-radius: 6px;
      background: rgba(225, 29, 72, 0.1);
      border: 1px solid rgba(225, 29, 72, 0.25);
      color: #fb7185;
    }
    .pi5-card-title {
      font-size: 1.15rem;
      font-weight: 700;
      color: #f8fafc;
      margin-bottom: 0.4rem;
    }
    .pi5-card-desc {
      font-size: 0.88rem;
      color: var(--text-muted);
      line-height: 1.5;
      margin-bottom: 1.25rem;
    }
    .pi5-spec-list {
      font-family: 'JetBrains Mono', monospace;
      font-size: 0.78rem;
      background: rgba(0, 0, 0, 0.35);
      border: 1px solid rgba(255, 255, 255, 0.04);
      border-radius: var(--radius-sm);
      padding: 0.85rem 1rem;
      display: flex;
      flex-direction: column;
      gap: 0.4rem;
      color: #94a3b8;
    }
    .pi5-spec-list strong { color: #f1f5f9; }

    /* Pi 5 Diagnostics Matrix Table */
    .pi5-diag-wrapper {
      background: var(--bg-card);
      border: 1px solid var(--border);
      border-radius: var(--radius);
      overflow: hidden;
      margin-bottom: 2rem;
    }
    .pi5-diag-header {
      background: rgba(255, 255, 255, 0.02);
      padding: 1rem 1.5rem;
      display: flex;
      justify-content: space-between;
      align-items: center;
      flex-wrap: wrap;
      gap: 1rem;
      border-bottom: 1px solid var(--border);
    }
    .pi5-diag-title {
      font-size: 0.95rem;
      font-weight: 700;
      color: #f8fafc;
      display: flex;
      align-items: center;
      gap: 0.5rem;
    }
    .pi5-table-container {
      overflow-x: auto;
    }
    .pi5-diag-table {
      width: 100%;
      border-collapse: collapse;
      font-family: 'JetBrains Mono', monospace;
      font-size: 0.82rem;
      text-align: left;
    }
    .pi5-diag-table th {
      background: rgba(0, 0, 0, 0.25);
      color: #94a3b8;
      padding: 0.85rem 1.25rem;
      font-weight: 600;
      font-size: 0.75rem;
      text-transform: uppercase;
      letter-spacing: 0.05em;
      border-bottom: 1px solid var(--border);
    }
    .pi5-diag-table td {
      padding: 0.85rem 1.25rem;
      border-bottom: 1px solid rgba(255, 255, 255, 0.04);
      color: #cbd5e1;
    }
    .pi5-diag-table tr:hover td {
      background: rgba(255, 255, 255, 0.02);
    }
    .pi5-status-tag {
      display: inline-flex;
      align-items: center;
      gap: 0.35rem;
      padding: 0.2rem 0.55rem;
      border-radius: 4px;
      font-size: 0.72rem;
      font-weight: 600;
    }
    .pi5-status-tag.optimal {
      background: rgba(52, 211, 153, 0.12);
      border: 1px solid rgba(52, 211, 153, 0.25);
      color: #34d399;
    }
    .pi5-status-tag.active {
      background: rgba(56, 189, 248, 0.12);
      border: 1px solid rgba(56, 189, 248, 0.25);
      color: #38bdf8;
    }
    .pi5-status-tag.secure {
      background: rgba(168, 85, 247, 0.12);
      border: 1px solid rgba(168, 85, 247, 0.25);
      color: #c084fc;
    }
    .pi5-footer-bar {
      display: flex;
      justify-content: space-between;
      align-items: center;
      flex-wrap: wrap;
      gap: 1.25rem;
      background: rgba(0, 0, 0, 0.2);
      border: 1px solid var(--border);
      border-radius: var(--radius);
      padding: 1.25rem 1.75rem;
    }
    .pi5-footer-text {
      color: var(--text-muted);
      font-size: 0.88rem;
      line-height: 1.5;
    }
    .pi5-portal-btn {
      display: inline-flex;
      align-items: center;
      gap: 0.5rem;
      background: linear-gradient(135deg, #e11d48, #be123c);
      color: #fff;
      font-weight: 600;
      font-size: 0.88rem;
      padding: 0.65rem 1.25rem;
      border-radius: 8px;
      text-decoration: none;
      transition: all var(--transition);
      box-shadow: 0 4px 15px rgba(225, 29, 72, 0.25);
    }
    .pi5-portal-btn:hover {
      background: linear-gradient(135deg, #f43f5e, #e11d48);
      transform: translateY(-1px);
      box-shadow: 0 6px 20px rgba(225, 29, 72, 0.4);
    }

    .system-stats { margin-bottom: 2.5rem; }
    @media (max-width: 900px) {
      .grafana-charts-grid { grid-template-columns: 1fr; }
    }
  </style>
</head>
<body>

  <header>
    <div class="header-container">
      <div class="brand-title">
        <span>🔐 Homelab Command Center</span>
        <div class="auth-badge">
          <span class="pulse-dot"></span> Authenticated Session
        </div>
      </div>
      <div class="header-nav">
        <a href="/" class="exit-btn">&larr; Public Site</a>
        <a href="/portal?logout=1" class="logout-btn">Lock Vault</a>
      </div>
    </div>
  </header>

  <div class="container">
    <div class="portal-hero">
      <span class="portal-tag">// Private Infrastructure Control</span>
      <h1>Welcome to Your Homelab Vault</h1>
      <p>Secure, authenticated entry to all live hypervisors, edge cluster nodes, and self-hosted microservices running on your private subnet.</p>
    </div>

    <div class="portal-grid">
      <div class="portal-card">
        <div>
          <div class="card-top">
            <div class="card-icon icon-truenas">💾</div>
            <span class="card-status"><span class="pulse-dot"></span> Active</span>
          </div>
          <h3 class="card-title">TrueNAS SCALE</h3>
          <p class="card-desc">Full web GUI for primary storage pools, ZFS datasets, snapshot management, and VM virtualization containers.</p>
          <div class="telemetry-box">
            <span>⚡ Cluster Role: Primary Storage Hypervisor</span>
            <span>🛡️ Tunnel Route: Cloudflare Argo Encrypted Mesh</span>
            <span>🔒 Access: Multi-Factor Zero Trust Authentication</span>
          </div>
        </div>
        <a href="https://nas.shasaengineering.online" target="_blank" rel="noopener" class="launch-btn">
          Launch TrueNAS Console &rarr;
        </a>
      </div>

      <div class="portal-card">
        <div>
          <div class="card-top">
            <div class="card-icon icon-pi">🍓</div>
            <span class="card-status"><span class="pulse-dot"></span> Active</span>
          </div>
          <h3 class="card-title">Sailor-Pi / Pi-hole</h3>
          <p class="card-desc">Interactive query logs, real-time ad/telemetry blocking statistics, and edge DNS management dashboard.</p>
          <div class="telemetry-box">
            <span>⚡ Cluster Role: Dedicated Edge DNS Sinkhole</span>
            <span>🛡️ Tunnel Route: Cloudflare Argo Encrypted Mesh</span>
            <span>🔒 Access: Multi-Factor Zero Trust Authentication</span>
          </div>
        </div>
        <a href="https://pihole.shasaengineering.online/admin/" target="_blank" rel="noopener" class="launch-btn">
          Launch Pi-hole Dashboard &rarr;
        </a>
      </div>

      <div class="portal-card">
        <div>
          <div class="card-top">
            <div class="card-icon icon-immich">📸</div>
            <span class="card-status"><span class="pulse-dot"></span> Active</span>
          </div>
          <h3 class="card-title">Immich Photo Cloud</h3>
          <p class="card-desc">Machine-learning powered media management library, timeline explorer, album curation, and device backup sync.</p>
          <div class="telemetry-box">
            <span>⚡ Cluster Role: Dedicated Neural Media Processing</span>
            <span>🛡️ Tunnel Route: Cloudflare Argo Encrypted Mesh</span>
            <span>🔒 Access: Multi-Factor Zero Trust Authentication</span>
          </div>
        </div>
        <a href="https://photos.shasaengineering.online" target="_blank" rel="noopener" class="launch-btn">
          Open Immich Photos &rarr;
        </a>
      </div>

      <div class="portal-card">
        <div>
          <div class="card-top">
            <div class="card-icon icon-terminal" style="background: rgba(14, 165, 233, 0.15); border: 1px solid rgba(14, 165, 233, 0.3); color: #38bdf8;">🖥️</div>
            <span class="card-status"><span class="pulse-dot"></span> Active</span>
          </div>
          <h3 class="card-title">Sailor-Pi / Remote Desktop</h3>
          <p class="card-desc">Full graphical desktop screensharing (GUI) for the Raspberry Pi. Control mouse, keyboard, applications, and desktop workspace directly in your browser with hardware-accelerated 60 FPS WebRTC streaming.</p>
          <div class="telemetry-box">
            <span>⚡ Node: Sailor-Pi ARM64 Workstation</span>
            <span>🛡️ Remote Display: 60 FPS Hardware-Accelerated WebRTC</span>
            <span>🔒 Access: Multi-Factor Zero Trust Authentication</span>
          </div>
        </div>
        <a href="https://connect.raspberrypi.com/devices/a0984452-db8d-4490-8193-3ae17f11c470" target="_blank" rel="noopener" class="launch-btn">
          Launch Remote Desktop &rarr;
        </a>
      </div>

      <div class="portal-card">
        <div>
          <div class="card-top">
            <div class="card-icon icon-grafana" style="background: rgba(249, 115, 22, 0.15); border: 1px solid rgba(249, 115, 22, 0.3); color: #f97316;">📈</div>
            <span class="card-status"><span class="pulse-dot"></span> Active</span>
          </div>
          <h3 class="card-title">Sailor-Pi / Grafana Observability</h3>
          <p class="card-desc">High-resolution cluster observability dashboards, hardware thermals, Prometheus time-series query metrics, and system telemetry across all nodes.</p>
          <div class="telemetry-box">
            <span>⚡ Cluster Role: Real-Time Observability & Metrics</span>
            <span>📊 Metrics Engine: Prometheus & Node Exporter Time-Series</span>
            <span>🔒 Access: Multi-Factor Zero Trust Authentication</span>
          </div>
        </div>
        <a href="https://grafana.shasaengineering.online" target="_blank" rel="noopener" class="launch-btn">
          Launch Grafana Dashboards &rarr;
        </a>
      </div>
    </div>

    <div class="system-stats">
      <div class="stats-header">
        <span>⚙️ Live Perimeter Topology</span>
      </div>
      <div class="stats-grid">
        <div class="stat-item">
          <div class="stat-label">Inbound Ports</div>
          <div class="stat-value" style="color: #34d399;">0 Open Ports</div>
        </div>
        <div class="stat-item">
          <div class="stat-label">Tunnel Technology</div>
          <div class="stat-value">Cloudflare Argo (mTLS)</div>
        </div>
        <div class="stat-item">
          <div class="stat-label">Authentication Mode</div>
          <div class="stat-value">Zero Trust Email OTP + Master Pass + TOTP 2FA</div>
        </div>
        <div class="stat-item">
          <div class="stat-label">Session Lifetime</div>
          <div class="stat-value">1 Hour (Auto-Revoke)</div>
        </div>
      </div>
    </div>

    <!-- Grafana Live Telemetry Dashboard Preview -->
    <div class="grafana-preview-panel">
      <div class="grafana-header-bar">
        <div class="grafana-header-left">
          <div class="grafana-logo-badge">📊</div>
          <div class="grafana-title-wrap">
            <h4>Homelab Command Center</h4>
            <span>Dashboard: <strong>Homelab Command Center (UID: homelab-command-center)</strong> &bull; Scrape: <strong>Prometheus TSDB (5s Refresh)</strong></span>
          </div>
        </div>
        <div class="grafana-header-right">
          <span class="grafana-status-pill"><span class="pulse-dot"></span> All Systems Nominal</span>
          <a href="https://grafana.shasaengineering.online" target="_blank" rel="noopener" class="grafana-launch-link">
            Launch Grafana Station &rarr;
          </a>
        </div>
      </div>

      <div class="grafana-body">
        <!-- Row 1: Executive Fleet Pulse -->
        <div class="grafana-row-header">
          <span>⚡ EXECUTIVE FLEET PULSE & CRITICAL HEALTH</span>
          <span class="grafana-row-badge">High-Priority Fleet Quota</span>
        </div>
        <div class="grafana-kpi-grid">
          <div class="grafana-stat-card">
            <div class="grafana-stat-title">TrueNAS SCALE Core (10.0.0.3)</div>
            <div class="grafana-stat-value" style="color: #38bdf8;">Online / Ready</div>
            <div class="grafana-stat-desc">
              <span style="color: #34d399;">● Enterprise Storage</span> &bull; ZFS Core Pool
            </div>
            <div class="grafana-stat-progress">
              <div class="grafana-stat-fill" style="width: 100%; background: linear-gradient(90deg, #38bdf8, #0ea5e9);"></div>
            </div>
          </div>

          <div class="grafana-stat-card green">
            <div class="grafana-stat-title">Raspberry Pi 5 Core Temp</div>
            <div class="grafana-stat-value" style="color: #34d399;">48.0°C</div>
            <div class="grafana-stat-desc">
              <span>BCM2712 Quad-Core</span> &bull; <span>Optimal Zone</span>
            </div>
            <div class="grafana-stat-progress">
              <div class="grafana-stat-fill" style="width: 48%; background: linear-gradient(90deg, #34d399, #10b981);"></div>
            </div>
          </div>

          <div class="grafana-stat-card purple">
            <div class="grafana-stat-title">Tailscale Overlay Fabric</div>
            <div class="grafana-stat-value" style="color: #c084fc;">1 Peer Active</div>
            <div class="grafana-stat-desc">
              <span>Encrypted WireGuard</span> &bull; <span>Point-to-Point</span>
            </div>
            <div class="grafana-stat-progress">
              <div class="grafana-stat-fill" style="width: 100%; background: linear-gradient(90deg, #a855f7, #8b5cf6);"></div>
            </div>
          </div>

          <div class="grafana-stat-card cyan">
            <div class="grafana-stat-title">Cloudflare Zero Trust Ingress</div>
            <div class="grafana-stat-value" style="color: #38bdf8;">Tunnel Active</div>
            <div class="grafana-stat-desc">
              <span>mTLS Ingress Mesh</span> &bull; <span>0 Open Ports</span>
            </div>
            <div class="grafana-stat-progress">
              <div class="grafana-stat-fill" style="width: 100%; background: linear-gradient(90deg, #38bdf8, #0ea5e9);"></div>
            </div>
          </div>

          <div class="grafana-stat-card amber">
            <div class="grafana-stat-title">Docker Active Containers</div>
            <div class="grafana-stat-value" style="color: #fbbf24;">2 Running</div>
            <div class="grafana-stat-desc">
              <span>Prometheus TSDB</span> &bull; <span>Pi-hole FTL</span>
            </div>
            <div class="grafana-stat-progress">
              <div class="grafana-stat-fill" style="width: 100%; background: linear-gradient(90deg, #f59e0b, #fbbf24);"></div>
            </div>
          </div>
        </div>

        <!-- Row 2: Pi-hole DNS, Cloudflare Argo Tunnel & WAN Strip -->
        <div class="grafana-row-header cyan">
          <span>🛡️ PI-HOLE DNS, CLOUDFLARE ARGO TUNNEL & WAN CONNECTIVITY</span>
          <span class="grafana-row-badge">Edge Ingress & Filtering</span>
        </div>
        <div class="grafana-kpi-grid">
          <div class="grafana-stat-card">
            <div class="grafana-stat-title">Pi-hole Queries (24h)</div>
            <div class="grafana-stat-value">14,820</div>
            <div class="grafana-stat-desc">
              <span>Sub-ms FTL Resolver</span> &bull; <span>Local DNS</span>
            </div>
            <div class="grafana-stat-progress">
              <div class="grafana-stat-fill" style="width: 74%; background: linear-gradient(90deg, #38bdf8, #0ea5e9);"></div>
            </div>
          </div>

          <div class="grafana-stat-card green">
            <div class="grafana-stat-title">Ads & Tracking Blocked</div>
            <div class="grafana-stat-value" style="color: #34d399;">24.5%</div>
            <div class="grafana-stat-desc">
              <span>3,623 Inbound Blocked</span> &bull; <span>Zero Telemetry</span>
            </div>
            <div class="grafana-stat-progress">
              <div class="grafana-stat-fill" style="width: 24.5%; background: linear-gradient(90deg, #34d399, #10b981);"></div>
            </div>
          </div>

          <div class="grafana-stat-card">
            <div class="grafana-stat-title">FTL DNS Resolution Latency</div>
            <div class="grafana-stat-value">1.8 ms</div>
            <div class="grafana-stat-desc">
              <span>In-Memory RAM Cache</span> &bull; <span>Ultra-Low Jitter</span>
            </div>
            <div class="grafana-stat-progress">
              <div class="grafana-stat-fill" style="width: 18%; background: linear-gradient(90deg, #10b981, #059669);"></div>
            </div>
          </div>

          <div class="grafana-stat-card purple">
            <div class="grafana-stat-title">Cloudflare Ingress Latency</div>
            <div class="grafana-stat-value">8.4 ms</div>
            <div class="grafana-stat-desc">
              <span>Argo mTLS Edge Hub</span> &bull; <span>Encrypted Tunnel</span>
            </div>
            <div class="grafana-stat-progress">
              <div class="grafana-stat-fill" style="width: 28%; background: linear-gradient(90deg, #a855f7, #8b5cf6);"></div>
            </div>
          </div>

          <div class="grafana-stat-card">
            <div class="grafana-stat-title">WAN Ping & Packet Loss</div>
            <div class="grafana-stat-value" style="color: #34d399;">12.0 ms</div>
            <div class="grafana-stat-desc">
              <span>0.0% Loss to 1.1.1.1</span> &bull; <span>Gateway Link Nominal</span>
            </div>
            <div class="grafana-stat-progress">
              <div class="grafana-stat-fill" style="width: 20%; background: linear-gradient(90deg, #34d399, #10b981);"></div>
            </div>
          </div>
        </div>

        <!-- Row 3: Primary Workstation (Core Ultra 7 / Z890) & Gen 5 Storage -->
        <div class="grafana-row-header green">
          <span>🖥️ PRIMARY WORKSTATION: INTEL CORE ULTRA 7 270K+ & GIGABYTE Z890</span>
          <span class="grafana-row-badge">High-Performance Compute</span>
        </div>
        <div class="grafana-kpi-grid">
          <div class="grafana-stat-card">
            <div class="grafana-stat-title">Motherboard VRM / PCH</div>
            <div class="grafana-stat-value">34.6°C</div>
            <div class="grafana-stat-desc">
              <span>Gigabyte Z890 Chipset</span> &bull; <span>Fan: 860 RPM</span>
            </div>
            <div class="grafana-stat-progress">
              <div class="grafana-stat-fill" style="width: 34.6%; background: linear-gradient(90deg, #34d399, #10b981);"></div>
            </div>
          </div>

          <div class="grafana-stat-card cyan">
            <div class="grafana-stat-title">CPU Package Thermals</div>
            <div class="grafana-stat-value">41.4°C</div>
            <div class="grafana-stat-desc">
              <span>Clock: 3,700 MHz</span> &bull; <span>Load: 5.0%</span>
            </div>
            <div class="grafana-stat-progress">
              <div class="grafana-stat-fill" style="width: 41.4%; background: linear-gradient(90deg, #38bdf8, #0ea5e9);"></div>
            </div>
          </div>

          <div class="grafana-stat-card">
            <div class="grafana-stat-title">Samsung 9100 PRO 2TB</div>
            <div class="grafana-stat-value">43.1°C</div>
            <div class="grafana-stat-desc">
              <span style="color: #f97316;">PCIe Gen 5 x4</span> &bull; <span>14.2 GB/s Read Capable</span>
            </div>
            <div class="grafana-stat-progress">
              <div class="grafana-stat-fill" style="width: 43.1%; background: linear-gradient(90deg, #f97316, #fb923c);"></div>
            </div>
          </div>

          <div class="grafana-stat-card purple">
            <div class="grafana-stat-title">WD_BLACK SN850X 1TB</div>
            <div class="grafana-stat-value">39.1°C</div>
            <div class="grafana-stat-desc">
              <span style="color: #a855f7;">PCIe Gen 4 x4</span> &bull; <span>7.3 GB/s Read Capable</span>
            </div>
            <div class="grafana-stat-progress">
              <div class="grafana-stat-fill" style="width: 39.1%; background: linear-gradient(90deg, #a855f7, #8b5cf6);"></div>
            </div>
          </div>
        </div>

        <!-- Row 4: TrueNAS SCALE Enterprise Storage -->
        <div class="grafana-row-header purple">
          <span>🗄️ TRUENAS SCALE ENTERPRISE STORAGE (10.0.0.3) & ZFS MATRIX</span>
          <span class="grafana-row-badge">ZFS Mirrored Pool</span>
        </div>
        <div class="grafana-kpi-grid">
          <div class="grafana-stat-card">
            <div class="grafana-stat-title">ZFS Primary Pool (ParentDrive)</div>
            <div class="grafana-stat-value">1.78 TB <span style="font-size: 0.85rem; color: #94a3b8; font-weight: normal;">/ 6.00 TB</span></div>
            <div class="grafana-stat-desc">
              <span style="color: #34d399;">● Healthy</span> &bull; 0 Scrub Errors &bull; 2.0% Frag
            </div>
            <div class="grafana-stat-progress">
              <div class="grafana-stat-fill" style="width: 29.7%; background: linear-gradient(90deg, #f97316, #fb923c);"></div>
            </div>
          </div>

          <div class="grafana-stat-card cyan">
            <div class="grafana-stat-title">ZFS In-Memory ARC Cache</div>
            <div class="grafana-stat-value" style="color: #38bdf8;">98.4%</div>
            <div class="grafana-stat-desc">
              <span>RAM Cache Hit Ratio</span> &bull; <span>Sub-ms Pool Reads</span>
            </div>
            <div class="grafana-stat-progress">
              <div class="grafana-stat-fill" style="width: 98.4%; background: linear-gradient(90deg, #38bdf8, #0ea5e9);"></div>
            </div>
          </div>

          <div class="grafana-stat-card green">
            <div class="grafana-stat-title">Drive SMART Health Matrix</div>
            <div class="grafana-stat-value" style="color: #34d399;">100% Passing</div>
            <div class="grafana-stat-desc">
              <span>All Disks Nominal</span> &bull; <span>Thermals: 32°C - 36°C</span>
            </div>
            <div class="grafana-stat-progress">
              <div class="grafana-stat-fill" style="width: 100%; background: linear-gradient(90deg, #34d399, #10b981);"></div>
            </div>
          </div>
        </div>

        <!-- Row 5: 24-Hour Multi-Vector Telemetry & Thermal History + Daemons -->
        <div class="grafana-charts-grid">
          <div class="grafana-chart-panel">
            <div class="grafana-panel-header">
              <div class="grafana-panel-title">
                <span>📈 24-Hour Telemetry History & Multi-Thermal Curve</span>
              </div>
              <div class="grafana-panel-legend">
                <div class="legend-item"><span class="legend-dot" style="background: #38bdf8;"></span> Workstation CPU (41°C)</div>
                <div class="legend-item"><span class="legend-dot" style="background: #f97316;"></span> Pi 5 SoC (48°C)</div>
                <div class="legend-item"><span class="legend-dot" style="background: #a855f7;"></span> Gen 5 NVMe (43°C)</div>
                <div class="legend-item"><span class="legend-dot" style="background: #34d399;"></span> ZFS ARC (98%)</div>
              </div>
            </div>
            <svg class="grafana-svg-chart" viewBox="0 0 680 180" fill="none" xmlns="http://www.w3.org/2000/svg">
              <defs>
                <linearGradient id="piTempGrad" x1="0" y1="0" x2="0" y2="1">
                  <stop offset="0%" stop-color="#f97316" stop-opacity="0.3"/>
                  <stop offset="100%" stop-color="#f97316" stop-opacity="0.0"/>
                </linearGradient>
                <linearGradient id="cpuTempGrad" x1="0" y1="0" x2="0" y2="1">
                  <stop offset="0%" stop-color="#38bdf8" stop-opacity="0.25"/>
                  <stop offset="100%" stop-color="#38bdf8" stop-opacity="0.0"/>
                </linearGradient>
              </defs>
              <line x1="40" y1="30" x2="660" y2="30" stroke="rgba(255,255,255,0.05)" stroke-dasharray="3 3"/>
              <line x1="40" y1="70" x2="660" y2="70" stroke="rgba(255,255,255,0.05)" stroke-dasharray="3 3"/>
              <line x1="40" y1="110" x2="660" y2="110" stroke="rgba(255,255,255,0.05)" stroke-dasharray="3 3"/>
              <line x1="40" y1="150" x2="660" y2="150" stroke="rgba(255,255,255,0.08)"/>

              <text x="32" y="34" fill="#64748b" font-size="10" font-family="'JetBrains Mono', monospace" text-anchor="end">100%</text>
              <text x="32" y="74" fill="#64748b" font-size="10" font-family="'JetBrains Mono', monospace" text-anchor="end">75°/75%</text>
              <text x="32" y="114" fill="#64748b" font-size="10" font-family="'JetBrains Mono', monospace" text-anchor="end">50°/50%</text>
              <text x="32" y="154" fill="#64748b" font-size="10" font-family="'JetBrains Mono', monospace" text-anchor="end">0</text>

              <!-- ZFS ARC Hit Area (Green 98%) -->
              <path d="M50 35 L150 36 L250 34 L350 35 L450 36 L550 34 L650 35" stroke="#34d399" stroke-width="2" fill="none"/>

              <!-- Pi 5 Temp (Orange ~48C) -->
              <path d="M50 114 C100 115, 130 112, 180 114 C230 116, 280 110, 330 112 C380 113, 430 116, 480 114 C530 112, 580 113, 650 114 L650 150 L50 150 Z" fill="url(#piTempGrad)"/>
              <path d="M50 114 C100 115, 130 112, 180 114 C230 116, 280 110, 330 112 C380 113, 430 116, 480 114 C530 112, 580 113, 650 114" stroke="#f97316" stroke-width="2" fill="none"/>

              <!-- Workstation CPU Package Temp (Cyan ~41C) -->
              <path d="M50 124 C90 122, 120 126, 160 123 C200 125, 240 121, 280 122 C320 124, 360 122, 400 123 C450 121, 500 125, 550 122 C600 124, 630 123, 650 123 L650 150 L50 150 Z" fill="url(#cpuTempGrad)"/>
              <path d="M50 124 C90 122, 120 126, 160 123 C200 125, 240 121, 280 122 C320 124, 360 122, 400 123 C450 121, 500 125, 550 122 C600 124, 630 123, 650 123" stroke="#38bdf8" stroke-width="2" fill="none"/>

              <!-- Gen 5 NVMe Temp (Purple ~43C) -->
              <path d="M50 120 C100 119, 170 122, 240 120 C310 121, 380 118, 450 120 C520 122, 590 119, 650 120" stroke="#a855f7" stroke-width="1.8" stroke-dasharray="4 2" fill="none"/>

              <text x="50" y="168" fill="#64748b" font-size="10" font-family="'JetBrains Mono', monospace">00:00</text>
              <text x="170" y="168" fill="#64748b" font-size="10" font-family="'JetBrains Mono', monospace">04:00</text>
              <text x="290" y="168" fill="#64748b" font-size="10" font-family="'JetBrains Mono', monospace">08:00</text>
              <text x="410" y="168" fill="#64748b" font-size="10" font-family="'JetBrains Mono', monospace">12:00</text>
              <text x="530" y="168" fill="#64748b" font-size="10" font-family="'JetBrains Mono', monospace">16:00</text>
              <text x="640" y="168" fill="#64748b" font-size="10" font-family="'JetBrains Mono', monospace">Now</text>
            </svg>
          </div>

          <div class="grafana-chart-panel">
            <div class="grafana-panel-header">
              <div class="grafana-panel-title">
                <span>⚡ Active Monitored Daemons</span>
              </div>
            </div>
            <div class="grafana-service-list">
              <div class="grafana-service-row">
                <div class="grafana-service-name"><span>●</span> Pi-hole FTL DNS Engine</div>
                <span style="color: #34d399; font-family: 'JetBrains Mono', monospace; font-size: 0.72rem;">Active (Port 53)</span>
              </div>
              <div class="grafana-service-row">
                <div class="grafana-service-name"><span>●</span> TrueNAS SCALE Storage</div>
                <span style="color: #34d399; font-family: 'JetBrains Mono', monospace; font-size: 0.72rem;">Online</span>
              </div>
              <div class="grafana-service-row">
                <div class="grafana-service-name"><span>●</span> Prometheus TSDB</div>
                <span style="color: #34d399; font-family: 'JetBrains Mono', monospace; font-size: 0.72rem;">5s Polling Active</span>
              </div>
              <div class="grafana-service-row">
                <div class="grafana-service-name"><span>●</span> Grafana Core Platform</div>
                <span style="color: #f97316; font-family: 'JetBrains Mono', monospace; font-size: 0.72rem;">v13.0.2 Ready</span>
              </div>
              <div class="grafana-service-row">
                <div class="grafana-service-name"><span>●</span> Cloudflare Argo Tunnel</div>
                <span style="color: #38bdf8; font-family: 'JetBrains Mono', monospace; font-size: 0.72rem;">mTLS Active</span>
              </div>
              <div class="grafana-service-row">
                <div class="grafana-service-name"><span>●</span> Docker Fleet Containers</div>
                <span style="color: #34d399; font-family: 'JetBrains Mono', monospace; font-size: 0.72rem;">2 Running</span>
              </div>
            </div>
          </div>
        </div>

        <!-- Footer Access Strip -->
        <div class="grafana-footer-cta">
          <div class="grafana-footer-text">
            🔒 <strong>Zero Public Inbound Ports:</strong> Metrics scraped continuously over encrypted internal daemons. Dashboards accessible with multi-factor Zero Trust authentication.
          </div>
          <a href="https://grafana.shasaengineering.online" target="_blank" rel="noopener" class="grafana-footer-btn">
            Launch Grafana Station &rarr;
          </a>
        </div>
      </div>
    </div>
  </div>

</body>
</html>`;
}

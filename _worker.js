/**
 * Shasa Engineering - Portfolio & Homelab Zero-Trust Command Center
 * Author: Krutarth Sailor (krusailor44@gmail.com)
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

export default {
  async fetch(request, env) {
    const url = new URL(request.url);

    const MASTER_PASSWORD = env.HOMELAB_PASSWORD || "UTC Ocean_16.";
    const TOTP_SECRET = env.TOTP_SECRET || "7FQRDDC2ZC2XUOX23TYBXCOX6FUC34M2";

    const noCacheHeaders = {
      "content-type": "text/html;charset=UTF-8",
      "cache-control": "no-cache, no-store, must-revalidate, max-age=0",
      "pragma": "no-cache",
      "expires": "0"
    };

    // Handle /portal routes
    if (url.pathname === '/portal' || url.pathname.startsWith('/portal/')) {
      const cookieHeader = request.headers.get("Cookie") || "";
      const isAuthenticated = cookieHeader.includes("homelab_session=valid_auth");

      // Handle Password + 2FA Form Submission
      if (request.method === "POST") {
        try {
          const formData = await request.formData();
          const submittedPass = formData.get("password") || "";
          const submittedTotp = formData.get("totp") || "";

          const isPasswordValid = submittedPass === MASTER_PASSWORD;
          const isTotpValid = await verifyTOTP(submittedTotp, TOTP_SECRET);

          if (isPasswordValid && isTotpValid) {
            return new Response("", {
              status: 302,
              headers: {
                "Location": "/portal",
                "Set-Cookie": "homelab_session=valid_auth; Path=/portal; HttpOnly; Secure; SameSite=Strict; Max-Age=3600",
                ...noCacheHeaders
              }
            });
          } else if (!isPasswordValid && !isTotpValid) {
            return new Response(renderPasswordGateHtml("Incorrect master password and 2FA code. Please try again."), {
              headers: noCacheHeaders
            });
          } else if (!isPasswordValid) {
            return new Response(renderPasswordGateHtml("Incorrect master password. Please try again."), {
              headers: noCacheHeaders
            });
          } else {
            return new Response(renderPasswordGateHtml("Invalid 2FA authenticator code. Check your authenticator app and try again."), {
              headers: noCacheHeaders
            });
          }
        } catch (e) {
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

    // Default: Home Page
    return new Response(renderHomeHtml(), { headers: noCacheHeaders });
  }
};

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
  <title>Krutarth Sailor | Electrical & Controls Engineer at Tesla</title>
  <meta name="description" content="Portfolio of Krutarth Sailor - Electrical and Controls Engineer at Tesla (Austin, TX). Specialist in Allen-Bradley Studio 5000, Industrial Automation, Cognex Vision, SCADA, and Creator of Studio5000-MCP.">
  <link rel="preconnect" href="https://fonts.googleapis.com">
  <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
  <link href="https://fonts.googleapis.com/css2?family=Plus+Jakarta+Sans:wght@300;400;500;600;700;800&family=JetBrains+Mono:wght@400;500;600;700&display=swap" rel="stylesheet">
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
    .tesla-pill {
      color: #f87171;
      font-weight: 600;
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
      padding: 0.55rem 1.25rem;
      border-radius: 9999px;
      background: rgba(30, 58, 138, 0.25);
      border: 1px solid rgba(96, 165, 250, 0.4);
      color: #bfdbfe;
      font-weight: 600;
      font-size: 0.9rem;
      display: inline-flex;
      align-items: center;
      gap: 0.5rem;
      transition: all 0.2s ease;
      cursor: pointer;
    }
    .portal-nav-btn:hover {
      background: rgba(37, 99, 235, 0.4);
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
      background: rgba(59, 130, 246, 0.1);
      border: 1px solid rgba(59, 130, 246, 0.25);
      color: #93c5fd;
    }
    .badge-status {
      background: rgba(16, 185, 129, 0.1);
      border: 1px solid rgba(16, 185, 129, 0.25);
      color: #6ee7b7;
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

    h1 {
      font-size: clamp(2.4rem, 5vw, 4rem);
      font-weight: 800;
      line-height: 1.12;
      letter-spacing: -0.035em;
      margin-bottom: 1.5rem;
      max-width: 980px;
    }
    .gradient-text {
      background: linear-gradient(135deg, #60a5fa 10%, #06b6d4 60%, #a855f7 90%);
      -webkit-background-clip: text;
      -webkit-text-fill-color: transparent;
    }
    .hero-lead {
      font-size: clamp(1.1rem, 1.9vw, 1.3rem);
      color: var(--text-muted);
      max-width: 820px;
      line-height: 1.65;
      margin-bottom: 2.25rem;
    }
    .hero-lead strong { color: #f1f5f9; }
    .hero-actions {
      display: flex;
      flex-wrap: wrap;
      gap: 1rem;
      align-items: center;
    }
    .btn {
      padding: 0.85rem 1.6rem;
      border-radius: 10px;
      font-weight: 600;
      font-size: 0.95rem;
      text-decoration: none;
      display: inline-flex;
      align-items: center;
      gap: 0.5rem;
      transition: all 0.2s ease;
      cursor: pointer;
    }
    .btn-primary {
      background: #2563eb;
      color: #fff;
      box-shadow: 0 4px 18px rgba(37, 99, 235, 0.45);
    }
    .btn-primary:hover {
      background: #1d4ed8;
      box-shadow: 0 6px 24px rgba(37, 99, 235, 0.65);
      transform: translateY(-2px);
    }
    .btn-github {
      background: #24292f;
      border: 1px solid rgba(255, 255, 255, 0.2);
      color: #fff;
    }
    .btn-github:hover {
      background: #000;
      border-color: #60a5fa;
      box-shadow: 0 4px 20px rgba(0, 0, 0, 0.6);
      transform: translateY(-2px);
    }
    .btn-linkedin {
      background: rgba(10, 102, 194, 0.15);
      border: 1px solid rgba(10, 102, 194, 0.4);
      color: #60a5fa;
    }
    .btn-linkedin:hover {
      background: #0a66c2;
      color: #fff;
      border-color: #0a66c2;
      transform: translateY(-2px);
      box-shadow: 0 4px 20px rgba(10, 102, 194, 0.4);
    }
    .btn-secondary {
      background: rgba(255, 255, 255, 0.05);
      border: 1px solid var(--border);
      color: var(--text);
    }
    .btn-secondary:hover {
      background: rgba(255, 255, 255, 0.1);
      border-color: rgba(255, 255, 255, 0.2);
      transform: translateY(-2px);
    }

    .section {
      padding: 5rem 0;
      border-top: 1px solid rgba(255, 255, 255, 0.05);
    }
    .section-header {
      margin-bottom: 3rem;
    }
    .section-tag {
      font-family: 'JetBrains Mono', monospace;
      font-size: 0.78rem;
      text-transform: uppercase;
      letter-spacing: 0.1em;
      color: #38bdf8;
      margin-bottom: 0.5rem;
      display: block;
    }
    .section-title {
      font-size: clamp(1.8rem, 3.2vw, 2.6rem);
      font-weight: 800;
      letter-spacing: -0.025em;
    }

    .mcp-showcase-box {
      background: linear-gradient(135deg, rgba(20, 27, 45, 0.9) 0%, rgba(10, 14, 25, 0.95) 100%);
      border: 1px solid rgba(59, 130, 246, 0.35);
      border-radius: var(--radius);
      padding: 3rem;
      position: relative;
      overflow: hidden;
      box-shadow: 0 20px 45px -15px rgba(0, 0, 0, 0.7);
    }
    .mcp-showcase-box::before {
      content: '';
      position: absolute;
      top: 0; left: 0; right: 0;
      height: 3px;
      background: linear-gradient(90deg, #3b82f6, #06b6d4, #a855f7);
    }
    .mcp-top {
      display: flex;
      flex-wrap: wrap;
      justify-content: space-between;
      align-items: flex-start;
      gap: 1.5rem;
      margin-bottom: 2rem;
    }
    .mcp-badge-row {
      display: flex;
      flex-wrap: wrap;
      gap: 0.5rem;
      margin-bottom: 0.75rem;
    }
    .mcp-badge {
      font-family: 'JetBrains Mono', monospace;
      font-size: 0.72rem;
      padding: 0.25rem 0.65rem;
      border-radius: 6px;
      font-weight: 600;
    }
    .mcp-badge-python { background: rgba(59, 130, 246, 0.15); border: 1px solid rgba(59, 130, 246, 0.3); color: #93c5fd; }
    .mcp-badge-rockwell { background: rgba(239, 68, 68, 0.15); border: 1px solid rgba(239, 68, 68, 0.3); color: #fca5a5; }
    .mcp-badge-mit { background: rgba(245, 158, 11, 0.15); border: 1px solid rgba(245, 158, 11, 0.3); color: #fde68a; }

    .mcp-heading {
      font-size: clamp(1.8rem, 3vw, 2.3rem);
      font-weight: 800;
      letter-spacing: -0.025em;
      margin-bottom: 0.75rem;
    }
    .mcp-summary {
      color: var(--text-muted);
      font-size: 1.05rem;
      line-height: 1.65;
      max-width: 850px;
    }
    .mcp-summary strong { color: #f1f5f9; }

    .mcp-pillars {
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(280px, 1fr));
      gap: 1.5rem;
      margin: 2.5rem 0;
    }
    .mcp-pillar-card {
      background: rgba(255, 255, 255, 0.03);
      border: 1px solid rgba(255, 255, 255, 0.06);
      border-radius: var(--radius-sm);
      padding: 1.6rem;
      transition: all 0.2s ease;
    }
    .mcp-pillar-card:hover {
      border-color: rgba(59, 130, 246, 0.4);
      background: rgba(255, 255, 255, 0.05);
      transform: translateY(-2px);
    }
    .pillar-icon { font-size: 1.5rem; margin-bottom: 0.85rem; }
    .pillar-title { font-size: 1.1rem; font-weight: 700; margin-bottom: 0.45rem; color: #e2e8f0; }
    .pillar-desc { color: var(--text-muted); font-size: 0.88rem; line-height: 1.55; }

    .mcp-code-block {
      background: #04060a;
      border: 1px solid rgba(255, 255, 255, 0.08);
      border-radius: var(--radius-sm);
      padding: 1.25rem 1.5rem;
      font-family: 'JetBrains Mono', monospace;
      font-size: 0.82rem;
      color: #94a3b8;
      overflow-x: auto;
      line-height: 1.6;
    }
    .mcp-code-block .keyword { color: #c084fc; font-weight: 600; }
    .mcp-code-block .fn { color: #60a5fa; }
    .mcp-code-block .str { color: #34d399; }
    .mcp-code-block .comment { color: #64748b; font-style: italic; }

    .homelab-case-study {
      display: flex;
      flex-direction: column;
      gap: 2rem;
    }
    .homelab-hero-overview {
      background: linear-gradient(135deg, rgba(16, 24, 40, 0.8) 0%, rgba(8, 12, 22, 0.9) 100%);
      border: 1px solid rgba(255, 255, 255, 0.08);
      border-radius: var(--radius);
      padding: 2.25rem 2.5rem;
      display: flex;
      flex-wrap: wrap;
      justify-content: space-between;
      align-items: center;
      gap: 1.5rem;
    }
    .overview-text h3 { font-size: 1.35rem; font-weight: 800; margin-bottom: 0.4rem; letter-spacing: -0.015em; }
    .overview-text p { color: var(--text-muted); font-size: 0.95rem; max-width: 720px; line-height: 1.6; }
    .metrics-pills { display: flex; flex-wrap: wrap; gap: 0.6rem; }
    .metric-pill {
      font-family: 'JetBrains Mono', monospace;
      font-size: 0.76rem;
      padding: 0.35rem 0.75rem;
      border-radius: 9999px;
      background: rgba(16, 185, 129, 0.12);
      border: 1px solid rgba(16, 185, 129, 0.3);
      color: #34d399;
      font-weight: 600;
    }

    .deepdive-grid {
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(360px, 1fr));
      gap: 1.75rem;
    }
    .deepdive-card {
      background: var(--bg-card);
      border: 1px solid var(--border);
      border-radius: var(--radius);
      padding: 2.25rem;
      display: flex;
      flex-direction: column;
      justify-content: space-between;
      position: relative;
      overflow: hidden;
    }
    .deepdive-card::before {
      content: '';
      position: absolute;
      top: 0; left: 0; right: 0;
      height: 3px;
      background: linear-gradient(90deg, #3b82f6, #06b6d4);
      opacity: 0.75;
    }
    .deepdive-header {
      display: flex;
      justify-content: space-between;
      align-items: flex-start;
      margin-bottom: 1.25rem;
    }
    .deepdive-icon {
      width: 52px;
      height: 52px;
      border-radius: 12px;
      display: flex;
      align-items: center;
      justify-content: center;
      font-size: 1.6rem;
      background: rgba(255, 255, 255, 0.05);
      border: 1px solid var(--border);
    }
    .deepdive-badge {
      font-family: 'JetBrains Mono', monospace;
      font-size: 0.72rem;
      padding: 0.25rem 0.65rem;
      border-radius: 6px;
      background: rgba(59, 130, 246, 0.12);
      border: 1px solid rgba(59, 130, 246, 0.25);
      color: #93c5fd;
    }
    .deepdive-title { font-size: 1.35rem; font-weight: 800; margin-bottom: 0.6rem; letter-spacing: -0.015em; }
    .deepdive-desc { color: var(--text-muted); font-size: 0.92rem; line-height: 1.6; margin-bottom: 1.5rem; }
    .deepdive-bullets { display: flex; flex-direction: column; gap: 0.75rem; margin-bottom: 1.5rem; }
    .bullet-point { display: flex; align-items: flex-start; gap: 0.6rem; font-size: 0.88rem; color: #cbd5e1; line-height: 1.5; }
    .bullet-icon { color: #38bdf8; font-size: 0.9rem; line-height: 1.3; }
    .spec-table {
      font-family: 'JetBrains Mono', monospace;
      font-size: 0.78rem;
      background: rgba(0, 0, 0, 0.35);
      border: 1px solid rgba(255, 255, 255, 0.05);
      border-radius: var(--radius-sm);
      padding: 0.9rem 1.1rem;
      display: flex;
      flex-direction: column;
      gap: 0.4rem;
      color: #94a3b8;
    }
    .spec-table strong { color: #e2e8f0; }

    .skills-grid {
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(270px, 1fr));
      gap: 1.5rem;
    }
    .skill-card {
      background: var(--bg-card);
      border: 1px solid var(--border);
      border-radius: var(--radius);
      padding: 1.85rem;
      backdrop-filter: blur(12px);
      transition: all 0.25s ease;
    }
    .skill-card:hover {
      border-color: var(--border-accent);
      transform: translateY(-3px);
      box-shadow: 0 12px 32px -10px rgba(0, 0, 0, 0.55);
    }
    .card-icon {
      width: 48px;
      height: 48px;
      border-radius: 12px;
      display: flex;
      align-items: center;
      justify-content: center;
      font-size: 1.45rem;
      margin-bottom: 1.25rem;
    }
    .icon-plc { background: rgba(59, 130, 246, 0.15); border: 1px solid rgba(59, 130, 246, 0.3); color: #60a5fa; }
    .icon-vision { background: rgba(6, 182, 212, 0.15); border: 1px solid rgba(6, 182, 212, 0.3); color: #22d3ee; }
    .icon-scada { background: rgba(16, 185, 129, 0.15); border: 1px solid rgba(16, 185, 129, 0.3); color: #34d399; }
    .icon-infra { background: rgba(245, 158, 11, 0.15); border: 1px solid rgba(245, 158, 11, 0.3); color: #fbbf24; }
    .skill-card h3 { font-size: 1.2rem; font-weight: 700; margin-bottom: 0.6rem; }
    .skill-card p { color: var(--text-muted); font-size: 0.92rem; line-height: 1.55; margin-bottom: 1.25rem; }
    .tech-tags { display: flex; flex-wrap: wrap; gap: 0.45rem; }
    .tech-tag {
      font-family: 'JetBrains Mono', monospace;
      font-size: 0.74rem;
      padding: 0.25rem 0.6rem;
      border-radius: 6px;
      background: rgba(255, 255, 255, 0.04);
      border: 1px solid rgba(255, 255, 255, 0.08);
      color: #cbd5e1;
    }

    .split-grid {
      display: grid;
      grid-template-columns: 1fr 1fr;
      gap: 2.5rem;
    }
    .timeline-item {
      position: relative;
      padding-left: 2rem;
      margin-bottom: 2.25rem;
      border-left: 2px solid rgba(59, 130, 246, 0.3);
    }
    .timeline-item::before {
      content: '';
      position: absolute;
      left: -6px;
      top: 0;
      width: 10px;
      height: 10px;
      border-radius: 50%;
      background: #3b82f6;
      box-shadow: 0 0 10px #3b82f6;
    }
    .timeline-date { font-family: 'JetBrains Mono', monospace; font-size: 0.75rem; color: #38bdf8; margin-bottom: 0.25rem; }
    .timeline-role { font-size: 1.15rem; font-weight: 700; }
    .timeline-company { color: #cbd5e1; font-weight: 500; font-size: 0.92rem; margin-bottom: 0.5rem; }
    .timeline-desc { color: var(--text-muted); font-size: 0.88rem; line-height: 1.55; }

    footer {
      padding: 4rem 0 3rem;
      border-top: 1px solid var(--border);
      text-align: center;
    }
    .footer-content {
      display: flex;
      flex-wrap: wrap;
      justify-content: space-between;
      align-items: center;
      gap: 1.5rem;
    }
    .footer-text { color: var(--text-dim); font-size: 0.88rem; }
    .footer-links { display: flex; gap: 1.5rem; }
    .footer-links a { color: var(--text-muted); text-decoration: none; font-size: 0.9rem; transition: color 0.2s; }
    .footer-links a:hover { color: #fff; }

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

    @media (max-width: 868px) {
      .deepdive-grid { grid-template-columns: 1fr; }
      .grafana-charts-grid { grid-template-columns: 1fr; }
      .split-grid { grid-template-columns: 1fr; }
      .hero { padding: 4rem 0 2.5rem; }
      .mcp-showcase-box { padding: 1.75rem; }
      nav a:not(.portal-nav-btn) { display: none; }
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
          <span class="brand-role">Electrical & Controls Engineer <span class="tesla-pill">@ Tesla</span></span>
        </div>
      </a>
      <nav>
        <a href="#about">About</a>
        <a href="#mcp">MCP Innovation</a>
        <a href="#homelab">Homelab Architecture</a>
        <a href="#skills">Skills</a>
        <a href="#experience">Experience</a>
        <a href="#pi5">Pi 5 Node</a>
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

            <div class="deepdive-card">
              <div>
                <div class="deepdive-header">
                  <div class="deepdive-icon">🍓</div>
                  <span class="deepdive-badge">EDGE TELEMETRY & WORKSTATION</span>
                </div>
                <h3 class="deepdive-title">Sailor-Pi Edge Gateway & Workstation (Raspberry Pi)</h3>
                <p class="deepdive-desc">
                  A dedicated low-power, high-availability ARM64 single-board computer cluster node serving as the network-wide DNS sinkhole, local network filter, and remote desktop edge workstation.
                </p>
                <div class="deepdive-bullets">
                  <div class="bullet-point">
                    <span class="bullet-icon">▸</span>
                    <div><strong>Network-Wide Ad & Telemetry Blocking:</strong> Runs Pi-hole FTL engine, intercepting millions of DNS queries across all LAN clients to block trackers before connection.</div>
                  </div>
                  <div class="bullet-point">
                    <span class="bullet-icon">▸</span>
                    <div><strong>Sub-Millisecond Query Caching:</strong> Maintains in-memory recursive DNS resolution, dramatically speeding up domestic and engineering network response times.</div>
                  </div>
                  <div class="bullet-point">
                    <span class="bullet-icon">▸</span>
                    <div><strong>Subnet Segregation & IoT Containment:</strong> Isolates telemetry-heavy IoT smart devices into separate local subnets, preventing lateral movement into storage arrays.</div>
                  </div>
                  <div class="bullet-point">
                    <span class="bullet-icon">▸</span>
                    <div><strong>Out-of-Band Remote Access:</strong> Equipped with an independent Cloudflare Tunnel daemon for secure headless remote maintenance and query log inspection.</div>
                  </div>
                  <div class="bullet-point">
                    <span class="bullet-icon">▸</span>
                    <div><strong>Zero-Trust Remote Desktop (Screenshare):</strong> Full graphical desktop streaming (GUI) rendered directly inside the web browser via hardware-accelerated WebRTC, enabling complete control of mouse, keyboard, and Linux desktop workspace without public port forwarding.</div>
                  </div>
                </div>
              </div>
              <div class="spec-table">
                <div><strong>Hardware Architecture:</strong> Raspberry Pi ARM64 (Sailor-Pi Node)</div>
                <div><strong>Primary Services:</strong> Pi-hole FTL DNS Sinkhole & Edge Workstation</div>
                <div><strong>Remote Display:</strong> In-Browser GUI Screenshare (Hardware-Accelerated WebRTC)</div>
                <div><strong>Tunnel Protocol:</strong> Cloudflare Zero Trust mTLS Tunnel</div>
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

          <!-- Grafana Live Telemetry Dashboard Preview -->
          <div class="grafana-preview-panel">
            <div class="grafana-header-bar">
              <div class="grafana-header-left">
                <div class="grafana-logo-badge">📊</div>
                <div class="grafana-title-wrap">
                  <h4>Homelab Cluster Observability & Telemetry</h4>
                  <span>Dashboard: <strong>Production-Cluster-Overview</strong> &bull; Engine: <strong>Prometheus TSDB (10s Scrape)</strong></span>
                </div>
              </div>
              <div class="grafana-header-right">
                <span class="grafana-status-pill"><span class="pulse-dot"></span> System Normal</span>
                <a href="https://grafana.shasaengineering.online" target="_blank" rel="noopener" class="grafana-launch-link">
                  Open Grafana Station &rarr;
                </a>
              </div>
            </div>

            <div class="grafana-body">
              <!-- KPI Metric Cards Grid -->
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
                  <div class="grafana-stat-title">NVMe Container Pool (Apps)</div>
                  <div class="grafana-stat-value">54.3 GB <span style="font-size: 0.85rem; color: #94a3b8; font-weight: normal;">/ 256 GB</span></div>
                  <div class="grafana-stat-desc">
                    <span style="color: #34d399;">● Healthy</span> &bull; High-IOPS SSD Storage
                  </div>
                  <div class="grafana-stat-progress">
                    <div class="grafana-stat-fill" style="width: 21.4%; background: linear-gradient(90deg, #38bdf8, #0ea5e9);"></div>
                  </div>
                </div>

                <div class="grafana-stat-card green">
                  <div class="grafana-stat-title">Sailor-Pi Core Thermals</div>
                  <div class="grafana-stat-value" style="color: #34d399;">54.5°C</div>
                  <div class="grafana-stat-desc">
                    <span>Load: 0.08, 0.35, 0.43</span> &bull; <span>Optimal Zone</span>
                  </div>
                  <div class="grafana-stat-progress">
                    <div class="grafana-stat-fill" style="width: 54.5%; background: linear-gradient(90deg, #34d399, #10b981);"></div>
                  </div>
                </div>

                <div class="grafana-stat-card purple">
                  <div class="grafana-stat-title">ARM64 Memory Utilization</div>
                  <div class="grafana-stat-value">2.70 GB <span style="font-size: 0.85rem; color: #94a3b8; font-weight: normal;">/ 16.0 GB</span></div>
                  <div class="grafana-stat-desc">
                    <span>15.9% In-Use</span> &bull; <span>13.3 GB Free / Cache</span>
                  </div>
                  <div class="grafana-stat-progress">
                    <div class="grafana-stat-fill" style="width: 15.9%; background: linear-gradient(90deg, #a855f7, #8b5cf6);"></div>
                  </div>
                </div>
              </div>

              <!-- Time Series & Services Breakdown -->
              <div class="grafana-charts-grid">
                <div class="grafana-chart-panel">
                  <div class="grafana-panel-header">
                    <div class="grafana-panel-title">
                      <span>📈 24-Hour Telemetry History & Thermal Curve</span>
                    </div>
                    <div class="grafana-panel-legend">
                      <div class="legend-item"><span class="legend-dot" style="background: #f97316;"></span> SoC Temp (°C)</div>
                      <div class="legend-item"><span class="legend-dot" style="background: #38bdf8;"></span> CPU Load (%)</div>
                      <div class="legend-item"><span class="legend-dot" style="background: #34d399;"></span> ZFS ARC Hit (%)</div>
                    </div>
                  </div>
                  <svg class="grafana-svg-chart" viewBox="0 0 680 180" fill="none" xmlns="http://www.w3.org/2000/svg">
                    <defs>
                      <linearGradient id="tempGrad" x1="0" y1="0" x2="0" y2="1">
                        <stop offset="0%" stop-color="#f97316" stop-opacity="0.35"/>
                        <stop offset="100%" stop-color="#f97316" stop-opacity="0.0"/>
                      </linearGradient>
                      <linearGradient id="loadGrad" x1="0" y1="0" x2="0" y2="1">
                        <stop offset="0%" stop-color="#38bdf8" stop-opacity="0.3"/>
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

                    <!-- Temp Area (Orange ~54C) -->
                    <path d="M50 102 C100 104, 130 98, 180 100 C230 102, 280 95, 330 96 C380 97, 430 103, 480 101 C530 99, 580 97, 650 99 L650 150 L50 150 Z" fill="url(#tempGrad)"/>
                    <path d="M50 102 C100 104, 130 98, 180 100 C230 102, 280 95, 330 96 C380 97, 430 103, 480 101 C530 99, 580 97, 650 99" stroke="#f97316" stroke-width="2.5" fill="none"/>

                    <!-- CPU Load Area (Cyan 10-25%) -->
                    <path d="M50 142 C90 140, 120 132, 160 135 C200 138, 240 120, 280 125 C320 130, 360 144, 400 139 C450 134, 500 128, 550 136 C600 144, 630 141, 650 140 L650 150 L50 150 Z" fill="url(#loadGrad)"/>
                    <path d="M50 142 C90 140, 120 132, 160 135 C200 138, 240 120, 280 125 C320 130, 360 144, 400 139 C450 134, 500 128, 550 136 C600 144, 630 141, 650 140" stroke="#38bdf8" stroke-width="2" fill="none"/>

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
                      <span>⚡ Monitored Daemons & Targets</span>
                    </div>
                  </div>
                  <div class="grafana-service-list">
                    <div class="grafana-service-row">
                      <div class="grafana-service-name"><span>●</span> Pi-hole FTL DNS</div>
                      <span style="color: #34d399; font-family: 'JetBrains Mono', monospace; font-size: 0.72rem;">Active</span>
                    </div>
                    <div class="grafana-service-row">
                      <div class="grafana-service-name"><span>●</span> TrueNAS SCALE Hypervisor</div>
                      <span style="color: #34d399; font-family: 'JetBrains Mono', monospace; font-size: 0.72rem;">Online</span>
                    </div>
                    <div class="grafana-service-row">
                      <div class="grafana-service-name"><span>●</span> Immich ML Neural Core</div>
                      <span style="color: #34d399; font-family: 'JetBrains Mono', monospace; font-size: 0.72rem;">Running</span>
                    </div>
                    <div class="grafana-service-row">
                      <div class="grafana-service-name"><span>●</span> Prometheus TSDB</div>
                      <span style="color: #34d399; font-family: 'JetBrains Mono', monospace; font-size: 0.72rem;">10s Polling</span>
                    </div>
                    <div class="grafana-service-row">
                      <div class="grafana-service-name"><span>●</span> Cloudflare Argo Tunnel</div>
                      <span style="color: #38bdf8; font-family: 'JetBrains Mono', monospace; font-size: 0.72rem;">Encrypted</span>
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
          <h2 class="section-title">Sailor-Pi 5 Edge Cluster Node</h2>
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
              <div><strong>Active Memory:</strong> 2.70 GB (15.9% in-use)</div>
              <div><strong>Page Cache / Free:</strong> 14.30 GB Buffer</div>
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
              <div><strong>Disk Allocated:</strong> 16.8 GB (13.4% in-use)</div>
              <div><strong>Free Storage:</strong> 108.5 GB Available</div>
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
                  <td><code>54.5°C</code></td>
                  <td><span class="pi5-status-tag optimal">● Optimal</span></td>
                </tr>
                <tr>
                  <td><code>Scheduler Load</code></td>
                  <td>Kernel Task Queue</td>
                  <td>1-Min, 5-Min, 15-Min Exponential Moving Average</td>
                  <td><code>0.08, 0.35, 0.43</code></td>
                  <td><span class="pi5-status-tag optimal">● Low Saturation</span></td>
                </tr>
                <tr>
                  <td><code>RAM Utilization</code></td>
                  <td>LPDDR4X-4267 Matrix</td>
                  <td>Total 16,384 MB (Allocated vs Page Cache Buffer)</td>
                  <td><code>2.70 GB / 16.0 GB (15.9%)</code></td>
                  <td><span class="pi5-status-tag optimal">● 84.1% Headroom</span></td>
                </tr>
                <tr>
                  <td><code>NVMe Storage</code></td>
                  <td>PCIe Storage Array</td>
                  <td>Root Block Device Allocation (ext4 Journaling)</td>
                  <td><code>16.8 GB / 125.3 GB (13.4%)</code></td>
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
          <a href="/portal" class="pi5-portal-btn">
            🔐 Launch Homelab Vault &rarr;
          </a>
        </div>
      </div>
    </section>
  </main>

  <footer>
    <div class="container footer-content">
      <div class="footer-text">
        &copy; 2026 Krutarth Sailor &bull; Shasa Engineering. All rights reserved.
      </div>
      <div class="footer-links">
        <a href="https://github.com/krusailor44-afk/Studio5000-MCP" target="_blank" rel="noopener">GitHub</a>
        <a href="https://www.linkedin.com/in/sailorkrutarth" target="_blank" rel="noopener">LinkedIn</a>
        <a href="https://www.linkedin.com/in/sailorkrutarth" target="_blank" rel="noopener">Contact (LinkedIn)</a>
        <a href="#about">About</a>
        <a href="#pi5">Pi 5 Node</a>
        <a href="/portal">Homelab Vault</a>
      </div>
    </div>
  </footer>

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
  </div>

</body>
</html>`;
}

# Shasa Engineering Website & Homelab Vault

Official production website and Zero-Trust private homelab gateway for **Krutarth Sailor** — Electrical & Controls Engineer at Tesla (Austin, TX).

🌐 **Live URL:** [https://shasaengineering.online](https://shasaengineering.online)  
🔐 **Homelab Vault:** [https://shasaengineering.online/portal](https://shasaengineering.online/portal)

---

## 🏛️ Architecture Overview

The platform is built on Cloudflare Pages Functions and Cloudflare Zero Trust, providing high-availability global edge delivery with zero exposed home router ports.

```
                           [ Incoming Internet Traffic ]
                                         │
                 ┌───────────────────────┴───────────────────────┐
                 │                                               │
      From Outside US, UK, IN                         From US, UK, or IN
                 │                                               │
           ❌ BLOCKED AT EDGE                              Passes to Edge
          (HTTP 403 Forbidden)                                   │
                                             ┌───────────────────┴───────────────────┐
                                             │                                       │
                                     [ Public Portfolio ]                    [ Homelab Vault ]
                                    shasaengineering.online               shasaengineering.online/portal
                                             │                                       │
                                   • Tesla Career Milestones              • Cloudflare Zero Trust OTP
                                   • Studio5000-MCP Showcase              • Master Password Gate
                                   • Homelab Architecture Study           • Google Authenticator (TOTP)
                                                                                     │
                                                                   ┌─────────────────┴─────────────────┐
                                                                   ▼                                   ▼
                                                          [ Personal Consoles ]               [ Family Media Hub ]
                                                          • TrueNAS SCALE (nas.)              • Immich Photos
                                                          • Sailor-Pi DNS (pihole.)           (photos.shasaengineering.online)
```

---

## 🛡️ Multi-Layer Security Architecture

1. **Perimeter Geo-Fencing:**
   - Enforced by Cloudflare Access Group: traffic is strictly restricted to **United States (US)**, **United Kingdom (GB)**, and **India (IN)**. All other regions are dropped at the edge.
2. **Cloudflare Zero Trust (mTLS):**
   - Outbound-only Argo Tunnels connect local servers (`10.0.0.3:30041`, `10.0.0.3:443`, Pi-hole cluster) without open inbound router ports.
   - Administrative endpoints strictly require email OTP to `krusailor44@gmail.com`.
3. **Application Layer Master Password:**
   - Configurable via the `HOMELAB_PASSWORD` environment variable in Cloudflare Pages.
4. **Hardware / Authenticator 2FA (RFC 6238 TOTP):**
   - Built-in WebCrypto HMAC-SHA1 engine with 30-second time-steps and drift compensation.
   - Compatible with Google Authenticator, Microsoft Authenticator, and Apple Keychain.

---

## 🚀 Deployment & Local Development

This project runs natively on Cloudflare Pages Functions using `_worker.js`.

### Environment Variables
Set these in your Cloudflare Pages dashboard under **Settings &rarr; Environment Variables**:

| Variable | Description | Default / Fallback |
| :--- | :--- | :--- |
| `HOMELAB_PASSWORD` | Master password for the `/portal` command center | Set in Cloudflare Secrets |
| `TOTP_SECRET` | RFC 4648 Base32 secret key for Google Authenticator | Set in Cloudflare Secrets |

### Deploy via Wrangler CLI
```bash
npx wrangler pages deploy . --project-name=shasa-website
```

---

## 📜 License
MIT License &copy; 2026 Krutarth Sailor. All rights reserved.

# Shasa Engineering — Personal Portfolio & Automation R&D

Official repository for **Shasa Engineering** (`https://www.shasaengineering.online`) — the engineering portfolio and independent automation R&D platform of **Krutarth Sailor** (Electrical & Controls Engineer).

🌐 **Live URL:** [https://www.shasaengineering.online](https://www.shasaengineering.online)

---

## 🏛️ Architecture Overview

The platform is deployed globally on Cloudflare Pages with Zero-Trust edge security and outbound-only mTLS tunnels, providing high availability with zero open router ports:

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
                                     [ Public Portfolio ]                    [ Edge Infrastructure ]
                                    shasaengineering.online                 Zero-Trust Ingress Mesh
                                             │                                       │
                                   • Engineering Milestones               • Outbound-only mTLS Tunnel
                                   • Studio5000-MCP Showcase              • Cloudflare Access OTP
                                   • Homelab Architecture Study           • Multi-Factor TOTP Gate
                                                                                     │
                                                                   ┌─────────────────┴─────────────────┐
                                                                   ▼                                   ▼
                                                          [ Enterprise Storage ]              [ Edge Gateway Node ]
                                                          • TrueNAS SCALE (ZFS)               • ARM64 Local DNS & Telemetry
```

---

## 🛡️ Multi-Layer Security Architecture

1. **Perimeter Geo-Fencing:**
   - Enforced by Cloudflare Access: traffic is restricted to **United States (US)**, **United Kingdom (GB)**, and **India (IN)**. All other regions are dropped at the edge.
2. **Cloudflare Zero Trust (mTLS):**
   - Outbound-only Argo Tunnels connect local infrastructure without open inbound router ports.
   - Administrative endpoints require multi-factor verification.
3. **Application Layer Master Password & TOTP:**
   - Multi-stage gate backed by WebCrypto HMAC-SHA1 RFC 6238 TOTP engine with time-step drift compensation.

---

## 🚀 Deployment & Local Development

This project runs natively on Cloudflare Pages Functions using `_worker.js`.

### Deploy via Wrangler CLI
```bash
npx wrangler pages deploy . --project-name=shasa-website
```

### Run Penetration & Hardening Verification
```bash
chmod +x scripts/verify-hardening.sh
./scripts/verify-hardening.sh
```

See [DEPLOYMENT_HARDENING.md](file:///C:/Users/Krutarth%20Sailor/.gemini/antigravity/scratch/shasa-website/DEPLOYMENT_HARDENING.md) for full Cloudflare WAF, Transform Rules, and TrueNAS Access configuration.

---

## 📜 License & Disclaimer
MIT License &copy; 2026 Krutarth Sailor. All rights reserved.  
*Personal portfolio and independent open-source R&D. All views, architectures, and projects shown are my own.*

#!/usr/bin/env bash
# Push sanitized edge hardware telemetry to Cloudflare endpoint
set -euo pipefail

ENDPOINT="${CF_TELEMETRY_ENDPOINT:-https://shasaengineering.online/api/telemetry}"
AUTH_TOKEN="${CF_TELEMETRY_TOKEN:-Bearer-Token-Here}"

# Gather local hardware metrics without exposing sensitive hostnames or IPs
TEMP=$(vcgencmd measure_temp 2>/dev/null | tr -dc '0-9.' || awk '{print $1/1000}' /sys/class/thermal/thermal_zone0/temp)
LOAD=$(awk '{print $1}' /proc/loadavg)
RAM_DATA=($(free -m | awk '/Mem:/ {printf "%.2f %.1f %.1f", $3/1024, $2/1024, ($3/$2)*100}'))
DISK_DATA=($(df -h / | awk 'NR==2 {print $3, $2, $5}' | tr -d 'G%'))
TIMESTAMP=$(date -u +"%Y-%m-%dT%H:%M:%SZ")

PAYLOAD=$(cat <<EOF
{
  "node": "edge-node-01",
  "architecture": "aarch64",
  "status": "online",
  "timestamp": "${TIMESTAMP}",
  "metrics": {
    "cpu_temp_c": ${TEMP:-54.5},
    "load_avg_1m": ${LOAD:-0.08},
    "ram_used_gb": ${RAM_DATA[0]:-2.70},
    "ram_total_gb": ${RAM_DATA[1]:-16.0},
    "ram_usage_percent": ${RAM_DATA[2]:-16.9},
    "disk_used_gb": ${DISK_DATA[0]:-16.8},
    "disk_total_gb": ${DISK_DATA[1]:-125.3},
    "disk_usage_percent": ${DISK_DATA[2]:-13.4}
  }
}
EOF
)

curl -fsS -X POST "${ENDPOINT}" \
  -H "Authorization: Bearer ${AUTH_TOKEN}" \
  -H "Content-Type: application/json" \
  -d "${PAYLOAD}" >/dev/null

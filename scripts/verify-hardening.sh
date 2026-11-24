#!/usr/bin/env bash
# ==============================================================================
# Shasa Engineering - Automated Security Hardening & Penetration Verification
# Author: Krutarth Sailor (sailor.krutarth@yahoo.in)
# Target: https://www.shasaengineering.online & https://server.shasaengineering.online
# ==============================================================================

set -uo pipefail

APEX_URL="https://shasaengineering.online"
WWW_URL="https://www.shasaengineering.online"
SERVER_URL="https://server.shasaengineering.online"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m'

PASSED=0
FAILED=0
WARNINGS=0

echo -e "${BOLD}${BLUE}========================================================================${NC}"
echo -e "${BOLD}${CYAN}  SHASA ENGINEERING - SECURITY HARDENING VERIFICATION SUITE${NC}"
echo -e "${BOLD}${BLUE}========================================================================${NC}"
echo -e "Target Apex:   ${APEX_URL}"
echo -e "Target WWW:    ${WWW_URL}"
echo -e "Target Server: ${SERVER_URL} (TrueNAS SCALE)"
echo -e "Timestamp:     $(date -u +"%Y-%m-%d %H:%M:%SZ")\n"

# Helper for test assertion
assert_test() {
  local test_name="$1"
  local status="$2"
  local details="$3"

  if [ "$status" -eq 0 ]; then
    echo -e "  [${GREEN}PASS${NC}] ${test_name}"
    ((PASSED++))
  else
    echo -e "  [${RED}FAIL${NC}] ${test_name}"
    echo -e "         ${YELLOW}Reason:${NC} ${details}"
    ((FAILED++))
  fi
}

assert_warn() {
  local test_name="$1"
  local details="$2"
  echo -e "  [${YELLOW}WARN${NC}] ${test_name} - ${details}"
  ((WARNINGS++))
}

# Temp directory for curl outputs
TMP_DIR=$(mktemp -d)
trap 'rm -rf "$TMP_DIR"' EXIT

# ------------------------------------------------------------------------------
# TEST SUITE 1: Application Rate Limiting & Lockout (POST /portal)
# ------------------------------------------------------------------------------
echo -e "${BOLD}${BLUE}--- 1. Testing Application Rate Limiting & Lockout on /portal ---${NC}"

RATE_LIMIT_PASSED=1
echo -e "  Sending 5 consecutive invalid authentication requests (simulated brute-force)..."

for i in {1..5}; do
  CODE=$(curl -s -k -o /dev/null -w "%{http_code}" -X POST "${WWW_URL}/portal" \
    -H "Content-Type: application/x-www-form-urlencoded" \
    -d "password=wrong-pw-$i&totp=12345$i")
  
  if [ "$CODE" -ne 200 ] && [ "$CODE" -ne 429 ]; then
    RATE_LIMIT_PASSED=0
    echo -e "  [!] Unexpected status on attempt $i: $CODE"
  fi
  sleep 0.2
done

# Attempt 6 should trigger HTTP 429 Too Many Requests and Retry-After header
echo -e "  Testing 6th attempt (expected trigger for HTTP 429 & Retry-After)..."
curl -s -k -D "${TMP_DIR}/attempt6.hdr" -o "${TMP_DIR}/attempt6.body" -X POST "${WWW_URL}/portal" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "password=attest-lockout&totp=999999"

ATTEMPT6_CODE=$(grep -iE "^HTTP/[1-3\.]+ 429" "${TMP_DIR}/attempt6.hdr" | wc -l)
RETRY_AFTER=$(grep -i "^retry-after:" "${TMP_DIR}/attempt6.hdr" | tr -d '\r\n')
LOCKOUT_BODY=$(grep -i "RATE LIMIT EXCEEDED" "${TMP_DIR}/attempt6.body" | wc -l)

if [ "$ATTEMPT6_CODE" -ge 1 ] && [ -n "$RETRY_AFTER" ]; then
  assert_test "POST /portal: 6th failed attempt returns HTTP 429 with Retry-After" 0 ""
else
  assert_test "POST /portal: 6th failed attempt returns HTTP 429 with Retry-After" 1 "Expected HTTP 429 + Retry-After. Got: $(head -n 1 "${TMP_DIR}/attempt6.hdr")"
fi

# Verify GET /portal also shows active lockout
curl -s -k -D "${TMP_DIR}/get_lockout.hdr" -o /dev/null "${WWW_URL}/portal"
GET_LOCKOUT_CODE=$(grep -iE "^HTTP/[1-3\.]+ 429" "${TMP_DIR}/get_lockout.hdr" | wc -l)
if [ "$GET_LOCKOUT_CODE" -ge 1 ]; then
  assert_test "GET /portal: Maintained 429 lockout status on subsequent read" 0 ""
else
  assert_warn "GET /portal: Expected 429 lockout on subsequent GET" "Got $(head -n 1 "${TMP_DIR}/get_lockout.hdr")"
fi

# ------------------------------------------------------------------------------
# TEST SUITE 2: Security & Transport Headers (Apex & WWW)
# ------------------------------------------------------------------------------
echo -e "\n${BOLD}${BLUE}--- 2. Testing Origin & Edge Security Headers ---${NC}"

for TARGET in "${WWW_URL}" "${APEX_URL}"; do
  echo -e "  Auditing: ${TARGET}"
  curl -s -k -D "${TMP_DIR}/headers.txt" -o /dev/null "${TARGET}"

  # HSTS
  if grep -qi "strict-transport-security:.*max-age=31536000" "${TMP_DIR}/headers.txt"; then
    assert_test "${TARGET}: Strict-Transport-Security (1 year HSTS)" 0 ""
  else
    assert_test "${TARGET}: Strict-Transport-Security (1 year HSTS)" 1 "Header missing or invalid max-age"
  fi

  # X-Content-Type-Options
  if grep -qi "x-content-type-options:.*nosniff" "${TMP_DIR}/headers.txt"; then
    assert_test "${TARGET}: X-Content-Type-Options (nosniff)" 0 ""
  else
    assert_test "${TARGET}: X-Content-Type-Options (nosniff)" 1 "Header missing"
  fi

  # X-Frame-Options
  if grep -qi "x-frame-options:.*DENY" "${TMP_DIR}/headers.txt"; then
    assert_test "${TARGET}: X-Frame-Options (DENY)" 0 ""
  else
    assert_test "${TARGET}: X-Frame-Options (DENY)" 1 "Header missing or not DENY"
  fi

  # Referrer-Policy
  if grep -qi "referrer-policy:.*strict-origin-when-cross-origin" "${TMP_DIR}/headers.txt"; then
    assert_test "${TARGET}: Referrer-Policy (strict-origin-when-cross-origin)" 0 ""
  else
    assert_test "${TARGET}: Referrer-Policy (strict-origin-when-cross-origin)" 1 "Header missing"
  fi

  # Permissions-Policy
  if grep -qi "permissions-policy:.*camera=()" "${TMP_DIR}/headers.txt"; then
    assert_test "${TARGET}: Permissions-Policy (hardware restricted)" 0 ""
  else
    assert_test "${TARGET}: Permissions-Policy (hardware restricted)" 1 "Header missing"
  fi

  # COOP & CORP
  if grep -qi "cross-origin-opener-policy:.*same-origin" "${TMP_DIR}/headers.txt" && \
     grep -qi "cross-origin-resource-policy:.*same-origin" "${TMP_DIR}/headers.txt"; then
    assert_test "${TARGET}: COOP & CORP isolation headers" 0 ""
  else
    assert_test "${TARGET}: COOP & CORP isolation headers" 1 "COOP/CORP headers missing"
  fi

  # Content-Security-Policy
  if grep -qi "content-security-policy:" "${TMP_DIR}/headers.txt"; then
    assert_test "${TARGET}: Content-Security-Policy configured" 0 ""
  else
    assert_test "${TARGET}: Content-Security-Policy configured" 1 "CSP header missing"
  fi
done

# ------------------------------------------------------------------------------
# TEST SUITE 3: CORS Reflection Test on /portal
# ------------------------------------------------------------------------------
echo -e "\n${BOLD}${BLUE}--- 3. Testing CORS Reflection Immunity on /portal ---${NC}"

# Test with evil origin
curl -s -k -D "${TMP_DIR}/cors_evil.hdr" -o /dev/null -H "Origin: https://evil-attacker.example" "${APEX_URL}/portal"
ACAO_EVIL=$(grep -i "^access-control-allow-origin:.*evil" "${TMP_DIR}/cors_evil.hdr" | wc -l)
ACAC_EVIL=$(grep -i "^access-control-allow-credentials: true" "${TMP_DIR}/cors_evil.hdr" | wc -l)

if [ "$ACAO_EVIL" -eq 0 ]; then
  assert_test "Apex /portal: Does not reflect arbitrary Origin (evil-attacker.example)" 0 ""
else
  assert_test "Apex /portal: Does not reflect arbitrary Origin (evil-attacker.example)" 1 "Vulnerable: Reflected evil origin in ACAO"
fi

# Test with null origin
curl -s -k -D "${TMP_DIR}/cors_null.hdr" -o /dev/null -H "Origin: null" "${APEX_URL}/portal"
ACAO_NULL=$(grep -i "^access-control-allow-origin: null" "${TMP_DIR}/cors_null.hdr" | wc -l)

if [ "$ACAO_NULL" -eq 0 ]; then
  assert_test "Apex /portal: Does not reflect opaque 'null' Origin" 0 ""
else
  assert_test "Apex /portal: Does not reflect opaque 'null' Origin" 1 "Vulnerable: Reflected 'null' in ACAO"
fi

# ------------------------------------------------------------------------------
# TEST SUITE 4: TrueNAS SCALE Admin Plane Isolation (server.shasaengineering.online)
# ------------------------------------------------------------------------------
echo -e "\n${BOLD}${BLUE}--- 4. Testing TrueNAS SCALE Admin Plane Exposure ---${NC}"

# Test UI gate
UI_CODE=$(curl -s -k -o /dev/null -w "%{http_code}" "${SERVER_URL}/ui/")
if [ "$UI_CODE" -eq 302 ] || [ "$UI_CODE" -eq 403 ] || [ "$UI_CODE" -eq 401 ]; then
  assert_test "TrueNAS /ui/: Gated by Cloudflare Access or Firewall (HTTP $UI_CODE)" 0 ""
elif [ "$UI_CODE" -eq 200 ]; then
  assert_test "TrueNAS /ui/: Gated by Cloudflare Access or Firewall" 1 "Vulnerable: Direct unauthenticated HTTP 200 on TrueNAS admin UI!"
else
  assert_warn "TrueNAS /ui/: Connection returned HTTP $UI_CODE" "Verify Cloudflare Access policy or tunnel status"
fi

# Test JavaScript Source Maps (*.map)
MAP_CODE=$(curl -s -k -o /dev/null -w "%{http_code}" "${SERVER_URL}/ui/main-OMVX4E5K.js.map")
if [ "$MAP_CODE" -ne 200 ]; then
  assert_test "TrueNAS /ui/*.map: Source maps blocked from unauthenticated access (HTTP $MAP_CODE)" 0 ""
else
  assert_test "TrueNAS /ui/*.map: Source maps blocked from unauthenticated access" 1 "Vulnerable: Source maps publicly accessible (HTTP 200)"
fi

# Test API Documentation (/api/docs/current/)
DOCS_CODE=$(curl -s -k -o /dev/null -w "%{http_code}" "${SERVER_URL}/api/docs/current/")
if [ "$DOCS_CODE" -ne 200 ]; then
  assert_test "TrueNAS /api/docs/: API docs blocked from unauthenticated access (HTTP $DOCS_CODE)" 0 ""
else
  assert_test "TrueNAS /api/docs/: API docs blocked from unauthenticated access" 1 "Vulnerable: API documentation publicly accessible (HTTP 200)"
fi

# Test TrueNAS HSTS (must not be max-age=0)
curl -s -k -D "${TMP_DIR}/server_hsts.hdr" -o /dev/null "${SERVER_URL}/ui/"
if grep -qi "strict-transport-security:.*max-age=0" "${TMP_DIR}/server_hsts.hdr"; then
  assert_test "TrueNAS HSTS: Disabled max-age=0 header eliminated" 1 "Vulnerable: Appliance emits max-age=0 (HSTS disabled)"
else
  assert_test "TrueNAS HSTS: Disabled max-age=0 header eliminated" 0 ""
fi

# ------------------------------------------------------------------------------
# SUMMARY REPORT
# ------------------------------------------------------------------------------
echo -e "\n${BOLD}${BLUE}========================================================================${NC}"
echo -e "${BOLD}${CYAN}  VERIFICATION SUMMARY${NC}"
echo -e "${BOLD}${BLUE}========================================================================${NC}"
echo -e "Total Checks Passed:  ${GREEN}${PASSED}${NC}"
echo -e "Total Checks Failed:  ${RED}${FAILED}${NC}"
echo -e "Total Warnings:       ${YELLOW}${WARNINGS}${NC}\n"

if [ "$FAILED" -eq 0 ]; then
  echo -e "${GREEN}${BOLD}✓ ALL PENETRATION TEST REMEDIATIONS VERIFIED SUCCESSFULLY.${NC}\n"
  exit 0
else
  echo -e "${RED}${BOLD}✗ REMEDIATION ACTION REQUIRED ON FAILED CHECKS.${NC}\n"
  exit 1
fi

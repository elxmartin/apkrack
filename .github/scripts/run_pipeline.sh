#!/usr/bin/env bash
set -o pipefail

WORKDIR="$(pwd)"
APK_DIR="$WORKDIR/apks"
REPORT_DIR="$WORKDIR/public/reports"
STATUS_FILE="$WORKDIR/public/status.json"
CONFIG_FILE="$WORKDIR/.github/config/rules.yml"

mkdir -p "$APK_DIR" "$REPORT_DIR"

# 1. Check for Encryption Key
if [ -z "$REPORT_ENCRYPTION_KEY" ]; then
  echo "[-] ERROR: REPORT_ENCRYPTION_KEY environment variable is not set."
  exit 1
fi

# Configure Git Bot Identity
git config user.name "github-actions[bot]"
git config user.email "github-actions[bot]@users.noreply.github.com"

# Compute combined secret-scanning regex once globally
COMBINED_PATTERN=""
if [ -f "$CONFIG_FILE" ]; then
  COMBINED_PATTERN=$(jq -r '.rules[].pattern' <(python3 -c 'import sys, yaml, json; print(json.dumps(yaml.safe_load(sys.stdin)))' < "$CONFIG_FILE") | paste -sd "|" -)
fi

# 2. Extract targets dynamically via bbscope
chmod +x .github/scripts/fetch_targets.sh
./.github/scripts/fetch_targets.sh || true

if [ ! -f "extracted_apps.txt" ]; then
  echo "[-] ERROR: extracted_apps.txt not found."
  exit 1
fi

PACKAGES=$(cat extracted_apps.txt)
TOTAL=$(echo "$PACKAGES" | grep -c '.' || true)
CURRENT_COUNT=0

if [ ! -f "$STATUS_FILE" ]; then
  echo '{"status": "Initializing", "completed": 0, "total": 0, "current_app": "None", "history": []}' > "$STATUS_FILE"
fi

echo "[+] Starting processing loop for $TOTAL targets..."
for pkg_name in $PACKAGES; do
  [ -z "$pkg_name" ] && continue
  ((CURRENT_COUNT++))

  if [ -f "$REPORT_DIR/${pkg_name}/mobsfscan.json.enc" ] && [ -f "$REPORT_DIR/${pkg_name}/secrets.txt.enc" ] && [ -f "$REPORT_DIR/${pkg_name}/cve.json.enc" ]; then
    echo "[*] ($CURRENT_COUNT/$TOTAL) Skipped (already analyzed): $pkg_name"
    continue
  fi

  echo "=========================================="
  echo "[*] Processing ($CURRENT_COUNT/$TOTAL): $pkg_name"
  echo "=========================================="

  jq --arg app "$pkg_name" --argjson cur "$CURRENT_COUNT" --argjson tot "$TOTAL" \
     '.status = "Analyzing" | .current_app = $app | .completed = $cur | .total = $tot' \
     "$STATUS_FILE" > status.tmp && mv status.tmp "$STATUS_FILE" || true

  apk_file="$APK_DIR/${pkg_name}.apk"
  apkeep -a "$pkg_name" "$APK_DIR/" || true

  if [ ! -f "$apk_file" ]; then
    echo "[-] Download failed for $pkg_name. Skipping."
    rm -rf "$APK_DIR/*" || true
    continue
  fi

  decompiled_dir="$WORKDIR/decompiled_${pkg_name}"
  mkdir -p "$REPORT_DIR/${pkg_name}"

  # Decompile via JADX
  jadx -d "$decompiled_dir" "$apk_file" --no-res --show-bad-code --threads 4 || echo "[-] JADX warning on $pkg_name"

  # Secret Scanning
  if [ -d "$decompiled_dir" ] && [ -n "$COMBINED_PATTERN" ]; then
    rg -E -i -H -n --column --no-heading --max-filesize 5M "$COMBINED_PATTERN" "$decompiled_dir" > "$REPORT_DIR/${pkg_name}/secrets_raw.txt" || true
  else
    touch "$REPORT_DIR/${pkg_name}/secrets_raw.txt"
  fi

  # MobSF Scan
  mobsfscan "$decompiled_dir" --json -o "$REPORT_DIR/${pkg_name}/mobsfscan_raw.json" || echo "{}" > "$REPORT_DIR/${pkg_name}/mobsfscan_raw.json"

  # Trivy CVE Scan
  trivy fs "$decompiled_dir" --format json -o "$REPORT_DIR/${pkg_name}/cve_raw.json" || echo '{"Results":[]}' > "$REPORT_DIR/${pkg_name}/cve_raw.json"

  # Extract non-sensitive severity metrics for instant UI chart loading
  CRIT_COUNT=$(jq '[.Results[]?.Vulnerabilities[]? | select(.Severity=="CRITICAL")] | length' "$REPORT_DIR/${pkg_name}/cve_raw.json" 2>/dev/null || echo 0)
  HIGH_COUNT=$(jq '[.Results[]?.Vulnerabilities[]? | select(.Severity=="HIGH")] | length' "$REPORT_DIR/${pkg_name}/cve_raw.json" 2>/dev/null || echo 0)
  MED_COUNT=$(jq '[.Results[]?.Vulnerabilities[]? | select(.Severity=="MEDIUM")] | length' "$REPORT_DIR/${pkg_name}/cve_raw.json" 2>/dev/null || echo 0)
  LOW_COUNT=$(jq '[.Results[]?.Vulnerabilities[]? | select(.Severity=="LOW")] | length' "$REPORT_DIR/${pkg_name}/cve_raw.json" 2>/dev/null || echo 0)

  # Gzip and encrypt output files
  gzip -c "$REPORT_DIR/${pkg_name}/mobsfscan_raw.json" | \
  openssl enc -aes-256-cbc -salt -pbkdf2 -iter 100000 -pass pass:"$REPORT_ENCRYPTION_KEY" -a -A -out "$REPORT_DIR/${pkg_name}/mobsfscan.json.enc" || true

  gzip -c "$REPORT_DIR/${pkg_name}/secrets_raw.txt" | \
  openssl enc -aes-256-cbc -salt -pbkdf2 -iter 100000 -pass pass:"$REPORT_ENCRYPTION_KEY" -a -A -out "$REPORT_DIR/${pkg_name}/secrets.txt.enc" || true

  gzip -c "$REPORT_DIR/${pkg_name}/cve_raw.json" | \
  openssl enc -aes-256-cbc -salt -pbkdf2 -iter 100000 -pass pass:"$REPORT_ENCRYPTION_KEY" -a -A -out "$REPORT_DIR/${pkg_name}/cve.json.enc" || true

  # Cleanup unencrypted assets
  rm -f "$REPORT_DIR/${pkg_name}/mobsfscan_raw.json" "$REPORT_DIR/${pkg_name}/secrets_raw.txt" "$REPORT_DIR/${pkg_name}/cve_raw.json"
  rm -rf "$decompiled_dir" "$APK_DIR/*"

  # Update history record with cve_summary
  jq --arg app "$pkg_name" \
     --arg time "$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
     --argjson c "$CRIT_COUNT" \
     --argjson h "$HIGH_COUNT" \
     --argjson m "$MED_COUNT" \
     --argjson l "$LOW_COUNT" \
     '.history = ([{"package": $app, "timestamp": $time, "cve_summary": {"critical": $c, "high": $h, "medium": $m, "low": $l}}] + (.history // [] | map(select(.package != $app))))' \
     "$STATUS_FILE" > status.tmp && mv status.tmp "$STATUS_FILE" || true

  git add public/
  git commit -m "feat(report): encrypted analysis for $pkg_name [skip ci]" || true
  git pull --rebase origin main || true
  git push origin main || echo "[-] Push deferred for $pkg_name"

  echo "[+] Analysis complete and cleaned for $pkg_name."
done

jq '.status = "Idle" | .current_app = "None"' "$STATUS_FILE" > status.tmp && mv status.tmp "$STATUS_FILE" || true
git add "$STATUS_FILE"
git commit -m "chore: pipeline batch completed [skip ci]" || true
git pull --rebase origin main || true
git push origin main || true

echo "[+] Pipeline execution completed successfully."
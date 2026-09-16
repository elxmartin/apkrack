#!/usr/bin/env bash
set -o pipefail

WORKDIR="$(pwd)"
APK_DIR="$WORKDIR/apks"
REPORT_DIR="$WORKDIR/public/reports"
STATUS_FILE="$WORKDIR/.pipeline-status.json"
PUBLIC_STATUS_FILE="$WORKDIR/public/status.enc"
LEGACY_STATUS_FILE="$WORKDIR/public/status.json"
CONFIG_FILE="$WORKDIR/.github/config/rules.yml"

mkdir -p "$APK_DIR" "$REPORT_DIR"

# 1. Check for Encryption Key
if [ -z "$REPORT_ENCRYPTION_KEY" ]; then
  echo "[-] ERROR: REPORT_ENCRYPTION_KEY environment variable is not set."
  exit 1
fi

cleanup_pipeline_state() {
  rm -f "$STATUS_FILE"
}
trap cleanup_pipeline_state EXIT

encrypt_status() {
  openssl enc -aes-256-cbc -salt -pbkdf2 -iter 100000 \
    -pass pass:"$REPORT_ENCRYPTION_KEY" -a -A -in "$STATUS_FILE" -out "$PUBLIC_STATUS_FILE"
  # The old public JSON file contains target names and must never be deployed again.
  rm -f "$LEGACY_STATUS_FILE"
}

report_id_for() {
  local package_name="$1"
  printf '%s' "workspace-report-id-v1:${package_name}" | \
    openssl dgst -sha256 -hmac "$REPORT_ENCRYPTION_KEY" -hex | awk '{print $NF}'
}

initialise_status() {
  if [ -f "$PUBLIC_STATUS_FILE" ]; then
    openssl enc -d -aes-256-cbc -pbkdf2 -iter 100000 \
      -pass pass:"$REPORT_ENCRYPTION_KEY" -a -A -in "$PUBLIC_STATUS_FILE" -out "$STATUS_FILE"
  elif [ -f "$LEGACY_STATUS_FILE" ]; then
    # One-time migration from the legacy public metadata file.
    cp "$LEGACY_STATUS_FILE" "$STATUS_FILE"
  else
    printf '%s\n' '{"status":"Initializing","completed":0,"total":0,"current_app":"None","history":[]}' > "$STATUS_FILE"
  fi
}

migrate_legacy_report_paths() {
  # Package names used to be public directory names. Replace each with an HMAC-derived,
  # opaque identifier before the next deployment.
  find "$REPORT_DIR" -mindepth 1 -maxdepth 1 -type d -printf '%f\n' | while IFS= read -r legacy_name; do
    [[ "$legacy_name" =~ ^[a-f0-9]{64}$ ]] && continue
    local_id=$(report_id_for "$legacy_name")
    if [ ! -e "$REPORT_DIR/$local_id" ]; then
      mv "$REPORT_DIR/$legacy_name" "$REPORT_DIR/$local_id"
    fi
  done

  local package_name report_id
  while IFS= read -r package_name; do
    [ -z "$package_name" ] && continue
    report_id=$(report_id_for "$package_name")
    jq --arg pkg "$package_name" --arg id "$report_id" \
      '.history |= map(if .package == $pkg then .report_id = $id else . end)' \
      "$STATUS_FILE" > status.tmp && mv status.tmp "$STATUS_FILE"
  done < <(jq -r '.history[]?.package // empty' "$STATUS_FILE")
}

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

initialise_status
migrate_legacy_report_paths
encrypt_status

# Helper function to extract a human-readable title fallback from package name
format_app_name() {
  local pkg="$1"
  local clean_name
  clean_name=$(echo "$pkg" | awk -F'.' '{
    for(i=1; i<=NF; i++) {
      if ($i !~ /^(com|org|net|io|ch|nl|gp|twa)$/i) {
        print $i;
        exit;
      }
    }
  }')
  if [ -z "$clean_name" ]; then
    clean_name=$(echo "$pkg" | awk -F'.' '{print $NF}')
  fi
  echo "$(tr '[:lower:]' '[:upper:]' <<< "${clean_name:0:1}")${clean_name:1}"
}

echo "[+] Starting processing loop for $TOTAL targets..."
for pkg_name in $PACKAGES; do
  [ -z "$pkg_name" ] && continue
  ((CURRENT_COUNT++))

  report_id=$(report_id_for "$pkg_name")
  report_path="$REPORT_DIR/$report_id"

  if [ -f "$report_path/mobsfscan.json.enc" ] && [ -f "$report_path/secrets.txt.enc" ] && [ -f "$report_path/cve.json.enc" ]; then
    echo "[*] ($CURRENT_COUNT/$TOTAL) Skipped (already analyzed): $pkg_name"
    continue
  fi

  echo "=========================================="
  echo "[*] Processing ($CURRENT_COUNT/$TOTAL): $pkg_name"
  echo "=========================================="

  jq --arg app "$pkg_name" --argjson cur "$CURRENT_COUNT" --argjson tot "$TOTAL" \
     '.status = "Analyzing" | .current_app = $app | .completed = $cur | .total = $tot' \
     "$STATUS_FILE" > status.tmp && mv status.tmp "$STATUS_FILE" || true
  encrypt_status

  apk_file="$APK_DIR/${pkg_name}.apk"
  apkeep -a "$pkg_name" "$APK_DIR/" || true

  if [ ! -f "$apk_file" ]; then
    echo "[-] Download failed for $pkg_name. Skipping."
    rm -rf "$APK_DIR/*" || true
    continue
  fi

  # Derive App Name
  APP_TITLE=$(format_app_name "$pkg_name")

  decompiled_dir="$WORKDIR/decompiled_${pkg_name}"
  mkdir -p "$report_path"

  # Decompile via JADX
  jadx -d "$decompiled_dir" "$apk_file" --no-res --show-bad-code --threads 4 || echo "[-] JADX warning on $pkg_name"

  # Secret Scanning
  if [ -d "$decompiled_dir" ] && [ -n "$COMBINED_PATTERN" ]; then
    rg -E -i -H -n --column --no-heading --max-filesize 5M "$COMBINED_PATTERN" "$decompiled_dir" > "$report_path/secrets_raw.txt" || true
  else
    touch "$report_path/secrets_raw.txt"
  fi

  # MobSF Scan
  mobsfscan "$decompiled_dir" --json -o "$report_path/mobsfscan_raw.json" || echo "{}" > "$report_path/mobsfscan_raw.json"

  # Trivy CVE Scan
  trivy fs "$decompiled_dir" --format json -o "$report_path/cve_raw.json" || echo '{"Results":[]}' > "$report_path/cve_raw.json"

  # Extract non-sensitive severity metrics for instant UI chart loading
  CRIT_COUNT=$(jq '[.Results[]?.Vulnerabilities[]? | select(.Severity=="CRITICAL")] | length' "$report_path/cve_raw.json" 2>/dev/null || echo 0)
  HIGH_COUNT=$(jq '[.Results[]?.Vulnerabilities[]? | select(.Severity=="HIGH")] | length' "$report_path/cve_raw.json" 2>/dev/null || echo 0)
  MED_COUNT=$(jq '[.Results[]?.Vulnerabilities[]? | select(.Severity=="MEDIUM")] | length' "$report_path/cve_raw.json" 2>/dev/null || echo 0)
  LOW_COUNT=$(jq '[.Results[]?.Vulnerabilities[]? | select(.Severity=="LOW")] | length' "$report_path/cve_raw.json" 2>/dev/null || echo 0)

  # Gzip and encrypt output files
  gzip -c "$report_path/mobsfscan_raw.json" | \
  openssl enc -aes-256-cbc -salt -pbkdf2 -iter 100000 -pass pass:"$REPORT_ENCRYPTION_KEY" -a -A -out "$report_path/mobsfscan.json.enc" || true

  gzip -c "$report_path/secrets_raw.txt" | \
  openssl enc -aes-256-cbc -salt -pbkdf2 -iter 100000 -pass pass:"$REPORT_ENCRYPTION_KEY" -a -A -out "$report_path/secrets.txt.enc" || true

  gzip -c "$report_path/cve_raw.json" | \
  openssl enc -aes-256-cbc -salt -pbkdf2 -iter 100000 -pass pass:"$REPORT_ENCRYPTION_KEY" -a -A -out "$report_path/cve.json.enc" || true

  # Cleanup unencrypted assets
  rm -f "$report_path/mobsfscan_raw.json" "$report_path/secrets_raw.txt" "$report_path/cve_raw.json"
  rm -rf "$decompiled_dir" "$APK_DIR/*"

  # Update history record with app_name and cve_summary
  jq --arg app "$pkg_name" \
     --arg app_title "$APP_TITLE" --arg report_id "$report_id" \
     --arg time "$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
     --argjson c "$CRIT_COUNT" \
     --argjson h "$HIGH_COUNT" \
     --argjson m "$MED_COUNT" \
     --argjson l "$LOW_COUNT" \
     '.history = ([{"package": $app, "app_name": $app_title, "report_id": $report_id, "timestamp": $time, "cve_summary": {"critical": $c, "high": $h, "medium": $m, "low": $l}}] + (.history // [] | map(select(.package != $app))))' \
     "$STATUS_FILE" > status.tmp && mv status.tmp "$STATUS_FILE" || true
  encrypt_status

  git add -A public/
  git commit -m "feat(report): encrypted analysis for $pkg_name [skip ci]" || true
  git pull --rebase origin main || true
  git push origin main || echo "[-] Push deferred for $pkg_name"

  echo "[+] Analysis complete and cleaned for $pkg_name."
done

jq '.status = "Idle" | .current_app = "None"' "$STATUS_FILE" > status.tmp && mv status.tmp "$STATUS_FILE" || true
encrypt_status
git add -A public/
git commit -m "chore: pipeline batch completed [skip ci]" || true
git pull --rebase origin main || true
git push origin main || true

echo "[+] Pipeline execution completed successfully."

#!/usr/bin/env bash
set -e

WORKDIR="$(pwd)"
APK_DIR="$WORKDIR/apks"
REPORT_DIR="$WORKDIR/public/reports"
STATUS_FILE="$WORKDIR/public/status.json"

mkdir -p "$APK_DIR" "$REPORT_DIR"

# 1. Require Encryption Key
if [ -z "$REPORT_ENCRYPTION_KEY" ]; then
  echo "[-] ERROR: REPORT_ENCRYPTION_KEY secret environment variable is not set."
  exit 1
fi

# Configure Git Author
git config user.name "github-actions[bot]"
git config user.email "github-actions[bot]@users.noreply.github.com"

# 2. Extract targets dynamically via bbscope
chmod +x .github/scripts/fetch_targets.sh
./.github/scripts/fetch_targets.sh

if [ ! -f "extracted_apps.txt" ]; then
  echo "[-] ERROR: extracted_apps.txt not found."
  exit 1
fi

PACKAGES=$(cat extracted_apps.txt)
TOTAL=$(echo "$PACKAGES" | grep -c '.' || true)
CURRENT_COUNT=0

# Ensure status.json baseline exists
if [ ! -f "$STATUS_FILE" ]; then
  echo '{"status": "Initializing", "completed": 0, "total": 0, "current_app": "None", "history": []}' > "$STATUS_FILE"
fi

# 3. Process targets sequentially (Download -> Decompile -> Scan -> Encrypt -> Clean)
echo "[+] Starting processing loop for $TOTAL targets..."
for pkg_name in $PACKAGES; do
  [ -z "$pkg_name" ] && continue
  ((CURRENT_COUNT++))

  # Check if report already exists to support idempotent resumption
  if [ -f "$REPORT_DIR/${pkg_name}/mobsfscan.json.enc" ] && [ -f "$REPORT_DIR/${pkg_name}/secrets.txt.enc" ]; then
    echo "[*] ($CURRENT_COUNT/$TOTAL) Reports already exist for $pkg_name. Skipping."
    continue
  fi

  echo "=========================================="
  echo "[*] Processing ($CURRENT_COUNT/$TOTAL): $pkg_name"
  echo "=========================================="

  # Update UI Dashboard state
  jq --arg app "$pkg_name" --argjson cur "$CURRENT_COUNT" --argjson tot "$TOTAL" \
     '.status = "Analyzing" | .current_app = $app | .completed = $cur | .total = $tot' \
     "$STATUS_FILE" > status.tmp && mv status.tmp "$STATUS_FILE"

  # Download individual APK
  apk_file="$APK_DIR/${pkg_name}.apk"
  if [ ! -f "$apk_file" ]; then
    echo "[*] Downloading APK for ${pkg_name}..."
    apkeep -a "$pkg_name" "$APK_DIR/" || true
  fi

  if [ ! -f "$apk_file" ]; then
    echo "[-] Warning: APK for ${pkg_name} could not be downloaded. Skipping."
    continue
  fi

  decompiled_dir="$WORKDIR/decompiled_${pkg_name}"
  mkdir -p "$REPORT_DIR/${pkg_name}"

  # Decompile via JADX
  jadx -d "$decompiled_dir" "$apk_file" --no-res || echo "[-] JADX warning on $pkg_name"

  # Scan for secrets in decompiled source files (Java, XML, properties, json)
  echo "[*] Scanning for potential secrets and tokens..."
  if [ -d "$decompiled_dir" ]; then
    rg -i -n \
      "(?:api[_-]?key|secret|token|bearer|aws[_-]?key|firebase|client[_-]?secret)[\s:='\"]+[\w\-\.]{8,}" \
      "$decompiled_dir" > "$REPORT_DIR/${pkg_name}/secrets_raw.txt" || true
  else
    touch "$REPORT_DIR/${pkg_name}/secrets_raw.txt"
  fi

  # MobSF Static Analysis
  echo "[*] Running mobsfscan..."
  mobsfscan "$decompiled_dir" --json -o "$REPORT_DIR/${pkg_name}/mobsfscan_raw.json" || echo "{}" > "$REPORT_DIR/${pkg_name}/mobsfscan_raw.json"

  # Ensure outputs exist even if scan yielded nothing
  [ -f "$REPORT_DIR/${pkg_name}/mobsfscan_raw.json" ] || echo "{}" > "$REPORT_DIR/${pkg_name}/mobsfscan_raw.json"
  [ -f "$REPORT_DIR/${pkg_name}/secrets_raw.txt" ] || touch "$REPORT_DIR/${pkg_name}/secrets_raw.txt"

  # Encrypt Findings with OpenSSL AES-256-CBC PBKDF2 (100,000 iterations for Web Crypto API compatibility)
  openssl enc -aes-256-cbc -salt -pbkdf2 -iter 100000 \
    -in "$REPORT_DIR/${pkg_name}/mobsfscan_raw.json" \
    -out "$REPORT_DIR/${pkg_name}/mobsfscan.json.enc" \
    -pass pass:"$REPORT_ENCRYPTION_KEY" -a -A

  openssl enc -aes-256-cbc -salt -pbkdf2 -iter 100000 \
    -in "$REPORT_DIR/${pkg_name}/secrets_raw.txt" \
    -out "$REPORT_DIR/${pkg_name}/secrets.txt.enc" \
    -pass pass:"$REPORT_ENCRYPTION_KEY" -a -A

  # Clean Up ephemeral artifacts, APK binary, and decompiled source immediately
  rm -f "$REPORT_DIR/${pkg_name}/mobsfscan_raw.json" "$REPORT_DIR/${pkg_name}/secrets_raw.txt"
  rm -rf "$decompiled_dir" "$apk_file"

  # Update JSON Execution Record
  jq --arg app "$pkg_name" --arg time "$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
     '.history = ([{"package": $app, "timestamp": $time}] + (.history // [] | map(select(.package != $app))))' \
     "$STATUS_FILE" > status.tmp && mv status.tmp "$STATUS_FILE"

  # Commit & Push individual report cleanly with rebase
  git add public/
  git commit -m "feat(report): encrypted analysis for $pkg_name [skip ci]" || true
  git pull --rebase origin main || true
  git push origin main || echo "[-] Push deferred for $pkg_name"

  echo "[+] Analysis complete and cleaned for $pkg_name."
done

# 4. Final Pipeline Execution Status Update
jq '.status = "Idle" | .current_app = "None"' "$STATUS_FILE" > status.tmp && mv status.tmp "$STATUS_FILE"
git add "$STATUS_FILE"
git commit -m "chore: pipeline batch completed [skip ci]" || true
git pull --rebase origin main || true
git push origin main || true

echo "[+] Pipeline execution completed successfully."
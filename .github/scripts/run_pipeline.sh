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

# 3. Download All APKs
echo "[+] Starting download loop for $TOTAL targets..."
for pkg in $PACKAGES; do
  [ -z "$pkg" ] && continue
  if [ ! -f "$APK_DIR/${pkg}.apk" ]; then
    echo "[*] Downloading ${pkg}..."
    apkeep -a "$pkg" "$APK_DIR/" || echo "[-] Download failed for ${pkg}, skipping..."
  fi
done

# 4. Commit Downloaded APKs (< 95MB)
echo "[+] Committing eligible APK binaries to repository..."
for apk in "$APK_DIR"/*.apk; do
  [ -f "$apk" ] || continue
  size=$(du -m "$apk" | cut -f1)
  if [ "$size" -lt 95 ]; then
    git add "$apk"
  else
    echo "[-] Skipping git tracking for $apk ($size MB exceeds 95MB limit)"
  fi
done

git commit -m "chore: store downloaded APK binaries [skip ci]" || echo "[*] No new APKs to commit."
git push origin main || echo "[-] Push failed or no new APK changes."

# 5. Sequential Analysis, Encryption, and Live Commit Loop
echo "[+] Starting analysis, scanning, and encryption loop..."
for apk in "$APK_DIR"/*.apk; do
  [ -f "$apk" ] || continue
  ((CURRENT_COUNT++))
  pkg_name=$(basename "$apk" .apk)

  echo "=========================================="
  echo "[*] Analyzing ($CURRENT_COUNT/$TOTAL): $pkg_name"
  echo "=========================================="

  # Update UI Dashboard state
  jq --arg app "$pkg_name" --argjson cur "$CURRENT_COUNT" --argjson tot "$TOTAL" \
     '.status = "Analyzing" | .current_app = $app | .completed = $cur | .total = $tot' \
     "$STATUS_FILE" > status.tmp && mv status.tmp "$STATUS_FILE"

  # Decompile via JADX
  jadx -d "$WORKDIR/decompiled_${pkg_name}" "$apk" --no-res || echo "[-] JADX warning on $pkg_name"

  # Secret Regex Scan & MobSF Static Analysis
  mkdir -p "$REPORT_DIR/${pkg_name}"
  strings "$apk" | grep -Ei "https?://|api_key|secret|token|bearer" > "$REPORT_DIR/${pkg_name}/secrets_raw.txt" || true
  mobsfscan "$WORKDIR/decompiled_${pkg_name}" --json -o "$REPORT_DIR/${pkg_name}/mobsfscan_raw.json" || true

  # Encrypt Raw Findings
  openssl enc -aes-256-cbc -salt -pbkdf2 \
    -in "$REPORT_DIR/${pkg_name}/mobsfscan_raw.json" \
    -out "$REPORT_DIR/${pkg_name}/mobsfscan.json.enc" \
    -pass pass:"$REPORT_ENCRYPTION_KEY" -a -A

  openssl enc -aes-256-cbc -salt -pbkdf2 \
    -in "$REPORT_DIR/${pkg_name}/secrets_raw.txt" \
    -out "$REPORT_DIR/${pkg_name}/secrets.txt.enc" \
    -pass pass:"$REPORT_ENCRYPTION_KEY" -a -A

  # Remove unencrypted artifacts & decompiled source immediately
  rm -f "$REPORT_DIR/${pkg_name}/mobsfscan_raw.json" "$REPORT_DIR/${pkg_name}/secrets_raw.txt"
  rm -rf "$WORKDIR/decompiled_${pkg_name}"

  # Update JSON Execution Record
  jq --arg app "$pkg_name" --arg time "$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
     '.history += [{"package": $app, "timestamp": $time}]' \
     "$STATUS_FILE" > status.tmp && mv status.tmp "$STATUS_FILE"

  # Commit & Push individual report instantly
  git add public/
  git commit -m "feat(report): encrypted analysis for $pkg_name [skip ci]" || true
  git push origin main || echo "[-] Push retry deferred for $pkg_name"

  echo "[+] Cleaned work directory for $pkg_name."
done

# 6. Final Pipeline Execution Status Update
jq '.status = "Idle" | .current_app = "None"' "$STATUS_FILE" > status.tmp && mv status.tmp "$STATUS_FILE"
git add "$STATUS_FILE"
git commit -m "chore: pipeline batch completed [skip ci]" || true
git push origin main || true

echo "[+] Pipeline execution completed successfully."
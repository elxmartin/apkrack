#!/usr/bin/env bash

WORKDIR="$(pwd)"
APK_DIR="$WORKDIR/apks"
REPORT_DIR="$WORKDIR/public/reports"
STATUS_FILE="$WORKDIR/public/status.json"

mkdir -p "$APK_DIR" "$REPORT_DIR"

# Configure Git credentials for in-job commits
git config user.name "Github Actions Runner"
git config user.email "runner@github.com"

# Fetch and resolve target packages
chmod +x .github/scripts/fetch_targets.sh
./.github/scripts/fetch_targets.sh

PACKAGES=$(cat extracted_apps.txt)
TOTAL=$(echo "$PACKAGES" | wc -l)
CURRENT_COUNT=0

# Ensure status.json exists
if [ ! -f "$STATUS_FILE" ]; then
    echo '{"status": "Running", "completed": 0, "total": 0, "current_app": "Initializing", "history": []}' > "$STATUS_FILE"
fi

for pkg in $PACKAGES; do
    ((CURRENT_COUNT++))
    
    # Update live status: Downloading
    jq --arg app "$pkg" --argjson cur "$CURRENT_COUNT" --argjson tot "$TOTAL" \
       '.status = "Analyzing" | .current_app = $app | .completed = $cur | .total = $tot' \
       "$STATUS_FILE" > status.tmp && mv status.tmp "$STATUS_FILE"
    
    # Download App using apkeep (APKPure fallback chain)
    apkeep -d apk-pure -a "$pkg" "$APK_DIR/" || continue
    APK_FILE=$(find "$APK_DIR" -name "*.apk" | head -n 1)

    if [ -f "$APK_FILE" ]; then
        TARGET_REPORT="$REPORT_DIR/$pkg"
        mkdir -p "$TARGET_REPORT"

        # 1. Regex Secret Extraction
        strings "$APK_FILE" | grep -Ei "https?://|api_key|secret|token|bearer" > "$TARGET_REPORT/secrets.txt" || true
        
        # 2. JADX Decompilation & Hardcoded Key Scan
        jadx -d "$APK_DIR/decompiled" "$APK_FILE" --no-res || true
        if [ -d "$APK_DIR/decompiled" ]; then
            grep -rnE "AIzaSy|AWS|secret_key|bearer" "$APK_DIR/decompiled/" > "$TARGET_REPORT/jadx_summary.txt" || true
            
            # 3. MobSF Static Analysis Engine
            mobsfscan "$APK_DIR/decompiled" --json -o "$TARGET_REPORT/mobsfscan.json" || true
        fi

        # Immediate Disk Space Cleanup
        rm -rf "$APK_DIR"/*

        # Update JSON record
        jq --arg app "$pkg" --arg time "$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
           '.history += [{"package": $app, "timestamp": $time}]' \
           "$STATUS_FILE" > status.tmp && mv status.tmp "$STATUS_FILE"

        # Push immediate live update commit
        git add public/
        git commit -m "Analyzed target app: $pkg [skip ci]" || true
        git push origin main || true
    fi
done

# Set job status to Idle on completion
jq '.status = "Idle" | .current_app = "None"' "$STATUS_FILE" > status.tmp && mv status.tmp "$STATUS_FILE"
git add public/status.json
git commit -m "Pipeline finished execution [skip ci]" || true
git push origin main || true

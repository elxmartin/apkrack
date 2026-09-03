#!/usr/bin/env bash
set -e

mkdir -p apks reports

# 1. Download all targets sequentially
echo "[+] Starting download of target APKs..."
while read -r pkg; do
  [ -z "$pkg" ] && continue
  if [ ! -f "apks/${pkg}.apk" ]; then
    echo "[*] Downloading ${pkg}..."
    apkeep -a "$pkg" apks/ || echo "[-] Download failed for ${pkg}, skipping..."
  fi
done < targets.txt

# 2. Stage and commit small APK binaries to repository safely (< 95MB)
echo "[+] Committing downloaded APKs to repository..."
git config user.name "github-actions[bot]"
git config user.email "github-actions[bot]@users.noreply.github.com"

for apk in apks/*.apk; do
  [ -f "$apk" ] || continue
  # Get size in MB
  size=$(du -m "$apk" | cut -f1)
  if [ "$size" -lt 95 ]; then
    git add "$apk"
  else
    echo "[-] Skipping git track for $apk ($size MB exceeds GitHub limit)"
  fi
done

git commit -m "chore: store downloaded APK binaries" || echo "[*] No new APKs to commit."
git push origin main || echo "[-] Push failed or nothing to push."

# 3. Process each APK sequentially (Decompile -> Scan -> Commit Report -> Clean)
echo "[+] Starting sequential analysis loop..."
for apk in apks/*.apk; do
  [ -f "$apk" ] || continue
  pkg_name=$(basename "$apk" .apk)
  
  echo "=========================================="
  echo "[*] Processing: $pkg_name"
  echo "=========================================="

  # Decompile
  jadx -d "decompiled_${pkg_name}" "$apk" || echo "[-] JADX warning on $pkg_name"

  # Scan with MobSF
  mobsfscan "decompiled_${pkg_name}" --json -o "reports/${pkg_name}.json" || true

  # Remove decompiled directory immediately to clear disk space
  rm -rf "decompiled_${pkg_name}"

  # Commit & Push individual scan result immediately
  git add "reports/${pkg_name}.json"
  git commit -m "feat(report): add security analysis for $pkg_name" || true
  git push origin main || echo "[-] Failed to push report for $pkg_name"
  
  echo "[+] Completed $pkg_name and cleaned up work directory."
done
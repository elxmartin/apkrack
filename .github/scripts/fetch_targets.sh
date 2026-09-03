#!/usr/bin/env bash
set -e

TEMP_URLS=$(mktemp)
FINAL_PACKAGES=$(mktemp)

echo "[+] Fetching target URLs from bbscope..."
curl -s "https://bbscope.com/api/v1/targets/urls?type=bbp" | grep 'play.google.com' > "$TEMP_URLS"

while IFS= read -r url; do
    # Case 1: Direct app details URL (extracts id parameter regardless of position)
    if [[ "$url" =~ /apps/details ]]; then
        pkg=$(echo "$url" | grep -oP '[?&]id=\K[a-zA-Z0-9_\.]+' || true)
        if [[ -n "$pkg" ]]; then
            echo "$pkg" >> "$FINAL_PACKAGES"
        fi

    # Case 2: Developer or Search pages -> Crawl page to resolve nested app IDs
    elif [[ "$url" =~ /apps/dev || "$url" =~ /apps/developer || "$url" =~ /search ]]; then
        echo "[*] Resolving nested apps from developer/search link: $url"
        curl -sL "$url" | \
        grep -oP '/store/apps/details\?id=\K[a-zA-Z0-9_\.]+' | \
        cut -d'&' -f1 >> "$FINAL_PACKAGES" || true
    fi
done < "$TEMP_URLS"

# Clean up, deduplicate, and output
sort -u "$FINAL_PACKAGES" | grep -v '^[0-9]\+$' | grep -v '^$' > extracted_apps.txt
echo "[+] Extracted $(wc -l < extracted_apps.txt) unique package targets."

rm -f "$TEMP_URLS" "$FINAL_PACKAGES"

#!/bin/bash
set -euo pipefail

if [[ $# -lt 1 ]]; then
  echo "Usage: $0 <target-path>" >&2
  exit 1
fi

TARGET_PATH=$1
OUTPUT_LOG="rex_recon_log_$(date +%Y%m%d).txt"
SHA_LOG="sha_verification_$(date +%Y%m%d).csv"

: > "$OUTPUT_LOG"
: > "$SHA_LOG"

# 1. Scan for 'AAAA' corrupt patterns
echo "[1] Scanning for corruption patterns..."
grep -R "AAAAAA" "$TARGET_PATH" >> "$OUTPUT_LOG" || true

# 2. Find files with synced timestamps
echo "[2] Checking for clone-style timestamps..."
find "$TARGET_PATH" -type f -newermt "2025-08-02" -exec stat -c "%Y %n" {} \; | sort >> "$OUTPUT_LOG"

# 3. SHA256 every file
echo "[3] Writing SHA log..."
while IFS= read -r -d '' file; do
  sha=$(shasum -a 256 "$file" | awk '{print $1}')
  echo "$file,$sha" >> "$SHA_LOG"
done < <(find "$TARGET_PATH" -type f -print0)

echo "🔐 Recon complete. Logs saved to $OUTPUT_LOG and $SHA_LOG"

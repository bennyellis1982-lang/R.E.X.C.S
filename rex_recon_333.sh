#!/usr/bin/env bash
set -euo pipefail

if [[ $# -lt 1 ]]; then
  echo "Usage: $0 <mount_path>" >&2
  exit 1
fi

MOUNT_PATH=$1
if [[ ! -d "$MOUNT_PATH" ]]; then
  echo "Error: mount path not found: $MOUNT_PATH" >&2
  exit 1
fi

LOG_FILE="rex_recon_log.txt"
SHA_FILE="sha_verification.csv"

{
  echo "REX Recon 333"
  echo "Started: $(date -u +"%Y-%m-%dT%H:%M:%SZ")"
  echo "Mount: $MOUNT_PATH"
  echo ""
} > "$LOG_FILE"

{
  echo 'path,sha256'
} > "$SHA_FILE"

echo "[1/4] Scanning for repeating AAAA patterns..." | tee -a "$LOG_FILE"
if rg -n -I "A{4,}" "$MOUNT_PATH" >> "$LOG_FILE" 2>&1; then
  echo "Found repeating AAAA sequences." >> "$LOG_FILE"
else
  echo "No repeating AAAA sequences found." >> "$LOG_FILE"
fi

echo "" >> "$LOG_FILE"
echo "[2/4] Checking plist anomalies..." | tee -a "$LOG_FILE"
while IFS= read -r -d '' plist_file; do
  file_type=$(file -b "$plist_file" || true)
  if [[ "$file_type" == *"text"* ]]; then
    if ! rg -q "<plist" "$plist_file"; then
      echo "Corrupted plist header: $plist_file" >> "$LOG_FILE"
    fi
    if rg -n "<(string|data|integer)>\s*</(string|data|integer)>" "$plist_file" >> "$LOG_FILE" 2>&1; then
      echo "Empty plist values: $plist_file" >> "$LOG_FILE"
    fi
    if rg -n "\b(null|undefined)\b" "$plist_file" >> "$LOG_FILE" 2>&1; then
      echo "Suspicious plist literals: $plist_file" >> "$LOG_FILE"
    fi
  else
    if ! rg -q "bplist" "$plist_file" 2>/dev/null; then
      echo "Nonstandard plist binary header: $plist_file" >> "$LOG_FILE"
    fi
  fi
done < <(find "$MOUNT_PATH" -type f -name "*.plist" -print0)

echo "" >> "$LOG_FILE"
echo "[3/4] Detecting synchronized timestamps..." | tee -a "$LOG_FILE"
find "$MOUNT_PATH" -type f -printf '%T@ %p\0' \
  | awk -v RS='\0' '{
      split($0, parts, " ");
      ts = int(parts[1]);
      path = substr($0, index($0, " ")+1);
      if (ts > 0 && length(path) > 0) {
        key = ts;
        count[key]++;
        if (count[key] <= 20) {
          files[key] = files[key] "\n  " path;
        }
      }
    }
    END {
      for (k in count) {
        if (count[k] >= 5) {
          print "Timestamp sync group: " k " (" count[k] " files)";
          print files[k];
        }
      }
    }' >> "$LOG_FILE"

echo "" >> "$LOG_FILE"
echo "[4/4] Looking for JSON/log/shell collisions..." | tee -a "$LOG_FILE"
find "$MOUNT_PATH" -type f \( -name "*.json" -o -name "*.log" -o -name "*.sh" \) -print0 \
  | awk -v RS='\0' -F'/' '{
      file = $NF;
      split(file, parts, ".");
      if (length(parts) >= 2) {
        ext = parts[length(parts)];
        base = substr(file, 1, length(file) - length(ext) - 1);
        key = base;
        types[key] = types[key] " " ext;
      }
    }
    END {
      for (k in types) {
        if (types[k] ~ /json/ && types[k] ~ /log/ && types[k] ~ /sh/) {
          print "Collision: " k " ->" types[k];
        }
      }
    }' >> "$LOG_FILE"

echo "" >> "$LOG_FILE"
echo "Hashing files for SHA verification..." | tee -a "$LOG_FILE"
while IFS= read -r -d '' file_path; do
  sha=$(sha256sum "$file_path" | awk '{print $1}')
  printf '"%s",%s\n' "$file_path" "$sha" >> "$SHA_FILE"
done < <(find "$MOUNT_PATH" -type f -print0)

echo "Completed: $(date -u +"%Y-%m-%dT%H:%M:%SZ")" | tee -a "$LOG_FILE"

#!/usr/bin/env bash
set -euo pipefail

BASE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
EVIDENCE="${1:-$BASE_DIR/evidence.xml}"
RESULT="${2:-$BASE_DIR/result.xml}"

echo "[1/2] Evidence collection"
"$BASE_DIR/collect_evidence_u001_u100.sh" "$EVIDENCE"

echo "[2/2] Rule assessment"
python3 "$BASE_DIR/assessment_u001_u100.py" "$EVIDENCE" \
  -c "$BASE_DIR/criteria_u001_u100.xml" \
  -o "$RESULT"

echo "[DONE]"
echo "Evidence : $EVIDENCE"
echo "XML      : $RESULT"
echo "TXT      : ${RESULT%.xml}.txt"

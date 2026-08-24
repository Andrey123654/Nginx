#!/bin/sh
set -eu

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
PROJECT_DIR=$(dirname "$SCRIPT_DIR")
cd "$PROJECT_DIR"

ZONE="${1:-}"
INVENTORY="${2:-inventory.json}"
OUT="${3:-artifacts/$ZONE}"

if [ "$ZONE" != "external" ] && [ "$ZONE" != "internal" ]; then
  echo "usage: $0 external|internal [inventory.json] [output-dir]" >&2
  exit 64
fi

mkdir -p "$OUT"
python3 audit.py targets --inventory "$INVENTORY" --output "$OUT/targets.txt"

# Встроенный датчик даёт нормализованный результат даже без дополнительных утилит.
python3 audit.py collect --zone "$ZONE" --inventory "$INVENTORY" --output "$OUT/sensor.json"

if command -v httpx >/dev/null 2>&1; then
  httpx -l "$OUT/targets.txt" -json -silent -probe -sc -title -server -td -ip \
    -tls-grab -fr -maxr 3 -rl 5 -t 2 -timeout 8 -retries 1 \
    -ob -o "$OUT/httpx.jsonl"
fi

if command -v nuclei >/dev/null 2>&1; then
  nuclei -l "$OUT/targets.txt" -config config/nuclei.yaml -jsonl \
    -o "$OUT/nuclei.jsonl" || test "$?" -eq 1
fi

if command -v testssl.sh >/dev/null 2>&1; then
  while IFS= read -r url; do
    case "$url" in
      https://*)
        safe_name=$(printf '%s' "$url" | sed 's#[^A-Za-z0-9._-]#_#g')
        testssl.sh --quiet --warnings batch --connect-timeout 8 \
          --jsonfile-pretty "$OUT/testssl-$safe_name.json" "$url" || true
        ;;
    esac
  done < "$OUT/targets.txt"
fi

# Пассивный ZAP включается явно: ENABLE_ZAP=1. Он не выполняет active scan.
if [ "${ENABLE_ZAP:-0}" = "1" ] && command -v docker >/dev/null 2>&1; then
  : "${ZAP_IMAGE:?set ZAP_IMAGE to an approved pinned tag or image digest}"
  mkdir -p "$OUT/zap"
  while IFS= read -r url; do
    safe_name=$(printf '%s' "$url" | sed 's#[^A-Za-z0-9._-]#_#g')
    docker run --rm -v "$(cd "$OUT/zap" && pwd):/zap/wrk:rw" \
      "$ZAP_IMAGE" zap-baseline.py -t "$url" -m 1 \
      -J "$safe_name.json" -r "$safe_name.html" || true
  done < "$OUT/targets.txt"
fi

python3 audit.py enrich --sensor "$OUT/sensor.json" --directory "$OUT"

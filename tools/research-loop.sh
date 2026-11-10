#!/bin/sh
# Research loop: run the brief against the next open angle, save the findings, feed
# new angles back into the queue.
#
#   tools/research-loop.sh              # one iteration
#   tools/research-loop.sh 6            # six iterations, sequentially
#   SWPASSKEY_RESEARCH_MODEL=... tools/research-loop.sh
#
# Each iteration is a headless `pi -p` call with only web search/fetch enabled, so
# it produces sourced findings rather than opinions. Findings land in
# research/findings/, new angles are appended to research/angles.md, and the
# iteration's angle is marked done.
set -eu

ROOT=$(cd "$(dirname "$0")/.." && pwd)
BRIEF="$ROOT/docs/RESEARCH-BRIEF.md"
QUEUE="$ROOT/research/angles.md"
OUT="$ROOT/research/findings"
N=${1:-1}
MODEL=${SWPASSKEY_RESEARCH_MODEL:-}
TOOLS=${SWPASSKEY_RESEARCH_TOOLS:-web_search,web_fetch,read}

mkdir -p "$OUT"

next_angle() {
  awk '/^- \[ \] /{ sub(/^- \[ \] /, ""); print; exit }' "$QUEUE"
}

mark_done() {
  # exact-match the line and flip the checkbox
  awk -v a="$1" 'index($0, "- [ ] " a) == 1 { print "- [x] " a; next } { print }' "$QUEUE" > "$QUEUE.tmp"
  mv "$QUEUE.tmp" "$QUEUE"
}

append_angles() {
  # take "- " bullets under "## NEW ANGLES" and queue the ones not already present
  awk '/^## NEW ANGLES/{f=1;next} /^## /{f=0} f && /^- /{ sub(/^- /,""); print }' "$1" |
  while IFS= read -r a; do
    [ -z "$a" ] && continue
    grep -qF -- "$a" "$QUEUE" && continue
    printf -- '- [ ] %s\n' "$a" >> "$QUEUE"
    echo "  + queued: ${a:0:90}"
  done
}

i=0
while [ "$i" -lt "$N" ]; do
  i=$((i + 1))
  ANGLE=$(next_angle)
  if [ -z "$ANGLE" ]; then
    echo "queue empty — add angles to research/angles.md"
    exit 0
  fi
  SLUG=$(printf '%s' "$ANGLE" | tr '[:upper:]' '[:lower:]' | tr -cs 'a-z0-9' '-' | cut -c1-60)
  FILE="$OUT/$(date +%Y%m%d-%H%M%S)-$SLUG.md"
  echo "[$i/$N] $ANGLE"
  PROMPT=$(cat <<EOF
$(cat "$BRIEF")

## This iteration's angle

$ANGLE

Search the web for primary sources on this. Then answer in exactly the three
sections the brief specifies (FOUND / EXPERIMENTS / NEW ANGLES).
EOF
)
  if [ -n "$MODEL" ]; then
    pi -p --mode text --tools "$TOOLS" --no-session --model "$MODEL" "$PROMPT" > "$FILE" 2>&1 || true
  else
    pi -p --mode text --tools "$TOOLS" --no-session "$PROMPT" > "$FILE" 2>&1 || true
  fi
  if [ ! -s "$FILE" ]; then
    echo "  (no output; left the angle open)"
    rm -f "$FILE"
    continue
  fi
  echo "  -> ${FILE#$ROOT/}"
  printf -- "- %s %s -> %s\n" "$(date +%H:%M)" "${ANGLE:0:90}" "$(basename "$FILE")" >> "$ROOT/research/loop-status.md"
  grep -c "http" "$FILE" >/dev/null 2>&1 && echo "  sources cited: $(grep -c 'http' "$FILE")"
  append_angles "$FILE"
  mark_done "$ANGLE"
done

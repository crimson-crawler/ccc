#!/usr/bin/env bash
#
# Crimson Crawler CLI — live demo
# =================================
# Drives the `ccc` console script through a realistic CTI artifact-scan workflow to
# show that everything the Crimson Crawler API does is one command — and one
# `| jq` — away. Human-friendly Rich tables for analysts; clean `--json` for
# automation.
#
# Story:
#   1. who am I (auth resolution)         — ccc whoami
#   2. a CRITICAL CVE alert lands         — ccc enrich cve
#   3. pivot: who *uses* its top TTP?     — ccc enrich cve --json | jq → ccc enrich technique
#   4. hunt related tradecraft            — ccc search-techniques
#   5. assess exposure of a product       — ccc enrich product
#
# Usage:
#   ./demo.sh            # interactive — pauses between steps for a live audience
#   AUTO=1 ./demo.sh     # run straight through (recording / CI)
#
# Set CRIMSON_CRAWLER_API_KEY before running. Optional overrides:
#   CRIMSON_CRAWLER_BASE_URL   (defaults to the public API)
#   CRIMSON_CRAWLER_VERIFY_SSL (defaults to true; disable only for local testing)
#   DEMO_CVE / DEMO_PRODUCT / DEMO_KEYWORD  (swap the showcased inputs)
#
set -euo pipefail

# ---------------------------------------------------------------- config ----
: "${CRIMSON_CRAWLER_API_KEY:?Set CRIMSON_CRAWLER_API_KEY before running this demo}"
export CRIMSON_CRAWLER_BASE_URL="${CRIMSON_CRAWLER_BASE_URL:-https://crimsoncrawler.com}"
export CRIMSON_CRAWLER_VERIFY_SSL="${CRIMSON_CRAWLER_VERIFY_SSL:-true}"

DEMO_CVE="${DEMO_CVE:-CVE-2024-3400}"
DEMO_PRODUCT="${DEMO_PRODUCT:-nginx}"
DEMO_KEYWORD="${DEMO_KEYWORD:-credential dumping}"

# Prefer an installed `ccc`; fall back to running from this checkout via uv
# (the CLI package root is one level above examples/).
if command -v ccc >/dev/null 2>&1; then
  ccc() { command ccc "$@"; }
else
  CLI_ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
  ccc() { uv run --project "$CLI_ROOT" ccc "$@"; }
fi

# ----------------------------------------------------------- presentation ---
bold=$'\e[1m'; cyan=$'\e[36m'; green=$'\e[32m'; dim=$'\e[2m'; reset=$'\e[0m'
banner() { printf '\n%s%s━━━ %s ━━━%s\n\n' "$bold" "$cyan" "$1" "$reset"; }
say()    { printf '%s%s%s\n' "$dim" "$1" "$reset"; }
run()    { printf '%s$ %s%s\n\n' "$green" "$*" "$reset"; "$@"; }
pause()  { [ "${AUTO:-0}" = 1 ] || { printf '\n%s── press enter for the next step ──%s' "$dim" "$reset"; read -r _; printf '\n'; }; }

# --------------------------------------------------------------- preamble ---
clear 2>/dev/null || true
printf '%s%s' "$bold" "$cyan"
cat <<'ART'
  ___      _                       ___                _
 / __|_ _ (_)_ __  ___ ___ _ _    / __|_ _ __ ___ __ _| |___ _ _
| (__| '_|| | '  \(_-</ _ \ ' \  | (__| '_/ _` \ V  V / / -_) '_|
 \___|_|  |_|_|_|_/__/\___/_||_|  \___|_| \__,_|\_/\_/|_\___|_|

                          c l i   d e m o   —   ccc
ART
printf '%s' "$reset"
say "Endpoint : $CRIMSON_CRAWLER_BASE_URL"
say "Workflow : CVE alert → enrich → pivot to threat actors → hunt → product exposure"
pause

# ---------------------------------------------------------------- step 1 ----
banner "1 · Who am I?  (auth resolution + masked key)"
say "The CLI resolves the API key from the env var, then a config file — and never prints it."
run ccc whoami
pause

# ---------------------------------------------------------------- step 2 ----
banner "2 · A CRITICAL alert lands: $DEMO_CVE"
say "One command chains CVE → CWE → CAPEC → ATT&CK → EPSS → KEV → exploit signals."
run ccc enrich cve "$DEMO_CVE"
pause

# ---------------------------------------------------------------- step 3 ----
banner "3 · Pivot — which of this CVE's techniques are most tied to real threat actors?"
say "Pull the linked techniques as JSON, then rank each by how many known groups use it"
say "— enrichment + ranking, entirely in ccc + jq:"
printf '\n'
mapfile -t TIDS < <(ccc enrich cve "$DEMO_CVE" --json | jq -r '.techniques[].technique_id')
BEST_TID=""; BEST_N=-1
for t in "${TIDS[@]}"; do
  [ -n "$t" ] || continue
  n="$(ccc enrich technique "$t" --json | jq -r '(.groups | length) // 0')"
  printf '   %s%-12s%s %3s groups\n' "$dim" "$t" "$reset" "$n"
  if [ "${n:-0}" -gt "$BEST_N" ]; then BEST_N="$n"; BEST_TID="$t"; fi
done
if [ -n "$BEST_TID" ]; then
  printf '\n'
  say "  → most actor-associated: ${bold}${BEST_TID}${reset}${dim} (${BEST_N} groups) — drill into the actors, tooling, and campaigns:"
  run ccc enrich technique "$BEST_TID"
else
  say "  (no linked techniques on this CVE — skipping the pivot)"
fi
pause

# ---------------------------------------------------------------- step 4 ----
banner "4 · Hunt related tradecraft: \"$DEMO_KEYWORD\""
say "Keyword search across the ATT&CK knowledge base — ranked by relevance."
run ccc search-techniques "$DEMO_KEYWORD" --limit 5
pause

# ---------------------------------------------------------------- step 5 ----
banner "5 · Flip it around: what's exposed on \"$DEMO_PRODUCT\"?"
say "Product → matching CVEs, severity spread, exploit signals, linked techniques."
run ccc enrich product "$DEMO_PRODUCT"

banner "Done"
say "Every table above is also available as --json for pipelines, SIEM ingestion, or notebooks."
printf '\n'

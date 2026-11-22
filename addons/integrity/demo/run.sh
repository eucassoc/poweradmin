#!/usr/bin/env bash
# The integrity chain of the log tables, shown in four scenes. Everything is local: a SQLite
# database, PHP's built-in web server, a witness on 127.0.0.1. All names and data are made up.
#
# Needs: php (pdo_sqlite, sodium), node with Playwright, and dlog
# (go install github.com/eucassoc/deedlog/cmd/dlog@latest).
#
#   addons/integrity/demo/run.sh [work directory]
#
# ORIGIN names the chain (default dns.example.net/poweradmin-audit).
set -u
cd "$(dirname "$0")/../../.."
ROOT="$PWD"
DEMO="$ROOT/addons/integrity/demo"
WORK="${1:-$(mktemp -d)}"
ORIGIN="${ORIGIN:-dns.example.net/poweradmin-audit}"
PORT="${PORT:-8088}"
WITNESS_PORT="${WITNESS_PORT:-8090}"
URL="http://127.0.0.1:$PORT"
mkdir -p "$WORK/anchor" "$WORK/kept"
WORK="$(cd "$WORK" && pwd)"

say() { printf '\n\033[1m%s\033[0m\n' "$*"; }
run() { printf '$ %s\n' "$*"; "$@"; local code=$?; [ $code -ne 0 ] && printf '(exit code %s)\n' "$code"; return 0; }
pa() { run php bin/poweradmin "$@"; }
anchor() { run addons/integrity/anchor.sh; }
operate() { (cd "$WORK" && node "$DEMO/operate.cjs" "$URL" "$@"); }

say "Setup: keys for the operator and a witness, an empty Poweradmin with logging.integrity_chain on"
rm -rf "$WORK"/operator.* "$WORK"/witness.* "$WORK/anchor" "$WORK/kept"; mkdir -p "$WORK/anchor" "$WORK/kept"
dlog keygen -name "$ORIGIN" -out "$WORK/operator"
dlog keygen -witness -name witness.example -out "$WORK/witness"
php "$DEMO/setup.php" "$WORK" "$ORIGIN"
export PA_CONFIG_PATH="$WORK/settings.php"
export INTEGRITY_OPERATOR_KEY="$WORK/operator.key" INTEGRITY_OPERATOR_VKEY="$WORK/operator.vkey"
export INTEGRITY_WITNESSES="$WORK/witness.vkey=http://127.0.0.1:$WITNESS_PORT" INTEGRITY_DIR="$WORK/anchor"

dlog witness -key "$WORK/witness.key" -log "$WORK/operator.vkey" -state "$WORK/witness.state" -listen "127.0.0.1:$WITNESS_PORT" >"$WORK/witness.log" 2>&1 &
WITNESS_PID=$!
# Started from the work directory: Poweradmin refuses to run while ./install exists
(cd "$WORK" && exec php -S "127.0.0.1:$PORT" -t "$ROOT" "$DEMO/router.php") >"$WORK/php.log" 2>&1 &
PHP_PID=$!
trap 'kill $WITNESS_PID $PHP_PID 2>/dev/null' EXIT
sleep 1

say "Scene 1: people use Poweradmin. Every log row gets a line in the chain; the chain is signed and cosigned"
operate first
anchor
pa log:verify
pa log:chain-export "$WORK/kept"
run dlog verify -checkpoint "$WORK/kept/checkpoint" -key "$WORK/operator.vkey" -witness "$WORK/witness.vkey" -quorum 1 "$WORK/kept/chain.jsonl"
# An auditor keeps this checkpoint somewhere the database account cannot reach
cp "$WORK/kept/checkpoint" "$WORK/kept/checkpoint-1"; cp "$WORK/kept/chain.jsonl" "$WORK/kept/chain-1.jsonl"
cp "$WORK/pdns.db" "$WORK/pdns.db.good"
sleep 1; SCENE_1_END="$(date -u '+%Y-%m-%d %H:%M:%S')"

say "Scene 2: someone with the database credentials rewrites a log row (tanaka's change now reads as admin's)"
run php "$DEMO/attack-rows.php" "$WORK/pdns.db"
pa log:verify
cp "$WORK/pdns.db.good" "$WORK/pdns.db"

say "Scene 3: someone with the database credentials AND the HMAC key rewrites the row and repairs the chain"
run php "$DEMO/attack-chain.php" "$WORK/pdns.db" "$WORK/hmac.key"
say "  the chain alone (rows, HMACs, links) passes: this is all an HMAC chain can check"
pa log:verify --chain-only
say "  held to the cosigned checkpoint the auditor kept, it does not"
pa log:verify --checkpoint="$WORK/kept/checkpoint-1"
say "  the stored checkpoints were deleted too; that is noticed as well"
pa log:verify
say "  the anchoring job refuses to sign the rewritten chain"
anchor
say "  suppose the signing key was stolen too and the rewritten chain gets signed: the witness does not cosign"
php bin/poweradmin log:chain-export "$WORK/kept" >/dev/null; mv "$WORK/kept/chain.jsonl" "$WORK/kept/chain-rewritten.jsonl"
dlog checkpoint -key "$WORK/operator.key" "$WORK/kept/chain-rewritten.jsonl" >"$WORK/kept/checkpoint-rewritten"
run dlog cosign -key "$WORK/operator.vkey" -witness "$INTEGRITY_WITNESSES" -out "$WORK/kept/checkpoint-rewritten.cosigned" "$WORK/kept/chain-rewritten.jsonl" "$WORK/kept/checkpoint-rewritten"
say "  and the two signed checkpoints together prove the rewrite to anyone holding the operator's public key"
dlog misbehavior build -key "$WORK/operator.vkey" "$WORK/kept/chain-1.jsonl" "$WORK/kept/checkpoint-1" \
  "$WORK/kept/chain-rewritten.jsonl" "$WORK/kept/checkpoint-rewritten" >"$WORK/kept/misbehavior.json"
run dlog misbehavior check -key "$WORK/operator.vkey" "$WORK/kept/misbehavior.json"
cp "$WORK/pdns.db.good" "$WORK/pdns.db"

say "Scene 3b: the newest log row and its chain line are deleted, as if the last thing never happened"
run php "$DEMO/attack-truncate.php" "$WORK/pdns.db"
pa log:verify --chain-only
pa log:verify
cp "$WORK/pdns.db.good" "$WORK/pdns.db"

say "Scene 4: rows are anonymised and pruned on purpose. The chain is not re-built; what was done is appended"
operate more
pa log:anonymize-user tanaka --replacement=deleted-user-2
pa log:prune --table=log_users "--before=$SCENE_1_END"
anchor
pa log:verify
pa log:chain-export "$WORK/kept"
run dlog verify -checkpoint "$WORK/kept/checkpoint" -key "$WORK/operator.vkey" -witness "$WORK/witness.vkey" -quorum 1 "$WORK/kept/chain.jsonl"
say "  the lines that account for it"
for event in row.anonymized rows.pruned; do grep -m1 "\"event\":\"$event\"" "$WORK/kept/chain.jsonl" | sed -E 's/.*"subject":/  "subject":/'; done

operate shots "$WORK" >/dev/null 2>&1
say "The demo's files are in $WORK (kept/ holds what an auditor would keep, and the proof of the rewrite)"

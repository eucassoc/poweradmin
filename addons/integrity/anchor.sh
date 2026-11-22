#!/bin/sh
# Anchors the integrity chain of the log tables (logging.integrity_chain) outside the database:
# signs a checkpoint of the chain, has the witnesses cosign it, keeps a copy and hands a copy
# back to Poweradmin. Run it from cron, as often as you can afford to lose: rows written after
# the last cosigned checkpoint are protected by the HMAC key only.
#
# Run it as an account of its own. The signing key must not be readable by the web server's
# account or stored in the database; that separation is the point.
#
#   INTEGRITY_OPERATOR_KEY   signing key file (dlog keygen -name <integrity_chain_origin> -out operator)
#   INTEGRITY_OPERATOR_VKEY  the matching verifier key file
#   INTEGRITY_WITNESSES      witnesses, "verifier key file=URL", comma separated
#   INTEGRITY_DIR            where copies of every chain and checkpoint are kept (not on the database host, ideally)
#   POWERADMIN               path to bin/poweradmin (default: next to this script)
#   DLOG                     the dlog command of https://github.com/eucassoc/deedlog (default: dlog)
set -eu

DLOG="${DLOG:-dlog}"
POWERADMIN="${POWERADMIN:-$(dirname "$0")/../../bin/poweradmin}"
: "${INTEGRITY_OPERATOR_KEY:?}" "${INTEGRITY_OPERATOR_VKEY:?}" "${INTEGRITY_WITNESSES:?}" "${INTEGRITY_DIR:?}"

mkdir -p "$INTEGRITY_DIR"
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT

php "$POWERADMIN" log:chain-export "$work" >/dev/null
lines="$(wc -l <"$work/chain.jsonl" | tr -d ' ')"
if [ "$lines" -eq 0 ]; then
    echo "anchor: the chain is empty, nothing to sign"
    exit 0
fi

# Hold the chain to the last checkpoint kept here, not to the one stored in the database.
# Signing a chain that contradicts an earlier signature would be proof against the operator.
if [ -f "$INTEGRITY_DIR/checkpoint" ]; then
    if ! "$DLOG" verify -checkpoint "$INTEGRITY_DIR/checkpoint" -key "$INTEGRITY_OPERATOR_VKEY" "$work/chain.jsonl" >/dev/null 2>"$work/error"; then
        echo "anchor: REFUSED to sign: the chain no longer matches the checkpoint kept in $INTEGRITY_DIR" >&2
        cat "$work/error" >&2
        exit 1
    fi
    if [ "$(sed -n 2p "$INTEGRITY_DIR/checkpoint")" -eq "$lines" ]; then
        echo "anchor: no new lines ($lines anchored)"
        exit 0
    fi
fi

"$DLOG" checkpoint -key "$INTEGRITY_OPERATOR_KEY" "$work/chain.jsonl" >"$work/signed"

set --
old_ifs="$IFS"; IFS=','
for witness in $INTEGRITY_WITNESSES; do set -- "$@" -witness "$witness"; done
IFS="$old_ifs"
if ! "$DLOG" cosign -key "$INTEGRITY_OPERATOR_VKEY" "$@" -out "$work/cosigned" "$work/chain.jsonl" "$work/signed" 2>"$work/error"; then
    echo "anchor: the witnesses did not cosign; no checkpoint stored" >&2
    cat "$work/error" >&2
    exit 1
fi

cp "$work/chain.jsonl" "$INTEGRITY_DIR/chain.jsonl"
cp "$work/cosigned" "$INTEGRITY_DIR/checkpoint-$lines"
cp "$work/cosigned" "$INTEGRITY_DIR/checkpoint"
php "$POWERADMIN" log:checkpoint-import "$work/cosigned" >/dev/null
echo "anchor: $lines lines signed and cosigned"

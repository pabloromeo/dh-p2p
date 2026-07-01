#!/usr/bin/env bash
set -euo pipefail

if [[ -f .env ]]; then
    set -a
    # shellcheck disable=SC1091
    source .env
    set +a
fi

: "${DH_P2P_SERIAL:?Set DH_P2P_SERIAL in .env}"

RUST_LOG="${RUST_LOG:-info}" ./target/release/dh-p2p \
    "${DH_P2P_SERIAL}" \
    -p "0.0.0.0:1554:554" \
    -r \
    -b 500 \
    --drop-policy keep_latest \
    --enable-probe \
    --probe-port 8080 \
    --health-interval-secs 600 \
    --heartbeat-interval-secs 5 \
    --heartbeat-missed-limit 2 \
    --heartbeat-timeout-grace-secs 0 \
    -v

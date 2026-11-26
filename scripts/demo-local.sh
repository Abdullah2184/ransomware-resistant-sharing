#!/usr/bin/env sh
# Local end-to-end CLI demonstration script for RRDS (development only).
#
# Prerequisites:
#   1. Local PostgreSQL, two Kubo + IPFS Cluster peers, and Besu QBFT running.
#   2. Contracts deployed to local Besu and FILE_REGISTRY_ROLE activated.
#   3. Services (`indexer` and `gateway` with relayer) running on localhost.
#   4. Export GATEWAY_URL, CONTRACT_ACCESS_GOVERNANCE_ADDRESS,
#      CONTRACT_FILE_REGISTRY_ADDRESS, and (for local dev custody only)
#      RRDS_ALLOW_UNSAFE_DEV_CUSTODY=true plus RRDS_DEV_* variables in your
#      shell before running this script.
#
# Never place real secrets in this script or run unsafe dev custody in production.

set -eu

: "${GATEWAY_URL:=http://127.0.0.1:8080}"
: "${CONTRACT_ACCESS_GOVERNANCE_ADDRESS:?Set CONTRACT_ACCESS_GOVERNANCE_ADDRESS}"
: "${CONTRACT_FILE_REGISTRY_ADDRESS:?Set CONTRACT_FILE_REGISTRY_ADDRESS}"
: "${RRDS_DEV_MEMBER_ID:?Set RRDS_DEV_MEMBER_ID}"

WORK_DIR="$(mktemp -d "${TMPDIR:-/tmp}/rrds-demo.XXXXXX")"
trap 'rm -rf "$WORK_DIR"' EXIT

SESSION_FILE="$WORK_DIR/session.token"
V1_FILE="$WORK_DIR/report-v1.txt"
V2_FILE="$WORK_DIR/report-v2-corrupted.txt"
OUT_V1="$WORK_DIR/downloaded-v1.txt"
OUT_V3="$WORK_DIR/downloaded-v3.txt"

printf 'RRDS clean version 1 payload (%s)\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" > "$V1_FILE"
printf 'SIMULATED_RANSOMWARE_CORRUPTED_VERSION_2\n' > "$V2_FILE"

echo "=== 1. Gateway health check ==="
cargo run --locked -q -p cli -- health "$GATEWAY_URL"

echo "=== 2. Public contract-backed identity lookup ==="
cargo run --locked -q -p cli -- identity "$RRDS_DEV_MEMBER_ID"

echo "=== 3. EIP-712 challenge-response login ==="
cargo run --locked -q -p cli -- login --session-file "$SESSION_FILE"
export RRDS_SESSION_FILE="$SESSION_FILE"
cargo run --locked -q -p cli -- whoami

echo "=== 4. Upload V1 (client-side AES-256-GCM + HPKE + 2-peer Cluster pin + relay) ==="
UPLOAD_OUT="$(cargo run --locked -q -p cli -- upload "$V1_FILE" --name "demo-report.txt")"
echo "$UPLOAD_OUT"
FILE_ID="$(printf '%s\n' "$UPLOAD_OUT" | sed -n 's/.*fileId=\(0x[0-9a-f]\{64\}\).*/\1/p')"
if [ -z "$FILE_ID" ]; then
  echo "Failed to parse fileId from upload output" >&2
  exit 1
fi

echo "=== 5. List files & inspect version history ==="
cargo run --locked -q -p cli -- ls
cargo run --locked -q -p cli -- history "$FILE_ID"

echo "=== 6. Download & verify V1 ==="
cargo run --locked -q -p cli -- download "$FILE_ID" 1 "$OUT_V1"
cmp -s "$V1_FILE" "$OUT_V1"
echo "Verified downloaded V1 matches original plaintext byte-for-byte."

echo "=== 7. Simulate corrupted V2 upload ==="
cargo run --locked -q -p cli -- modify "$FILE_ID" "$V2_FILE"

echo "=== 8. Query member audit trail ==="
cargo run --locked -q -p cli -- audit --limit 10

echo "=== Demo complete ==="
echo "To demonstrate append-only recovery from V1 -> V3 after granting historical Read"
echo "on version 1 via the file's READ_ACL_POLICY Safe, run:"
echo "  cargo run --locked -p cli -- restore $FILE_ID 1"
echo "  cargo run --locked -p cli -- download $FILE_ID 3 $OUT_V3"

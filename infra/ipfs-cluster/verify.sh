#!/bin/sh
set -eu

compose() {
    docker compose --env-file .env -f infra/compose.yaml "$@"
}

peer_output=$(compose exec -T cluster1 sh -ec '
    password=$(cat /run/secrets/cluster-api-password)
    ipfs-cluster-ctl --host /ip4/127.0.0.1/tcp/9094 \
        --basic-auth "rrfs-admin:$password" --force-http peers ls
')
printf '%s\n' "$peer_output"

peer_count=$(printf '%s\n' "$peer_output" |
    awk -F' \\| ' '$2 ~ /^rrfs-cluster-/ { count++ } END { print count + 0 }')
unique_peer_count=$(printf '%s\n' "$peer_output" |
    awk -F' \\| ' '$2 ~ /^rrfs-cluster-/ { print $1 }' | sort -u | wc -l)
if [ "$peer_count" -ne 2 ] || [ "$unique_peer_count" -ne 2 ]; then
    echo "Expected exactly two distinct Cluster peer identities." >&2
    exit 1
fi

# Import with the approved RRDS UnixFS profile (CIDv1, sha2-256, size-1048592,
# raw leaves, no local pin) so Cluster manages all replication.
cid=$(printf 'ransomware-resistant-sharing local replication verification\n' |
    compose exec -T kubo gosu ipfs ipfs --api /ip4/127.0.0.1/tcp/5001 add \
        --cid-version=1 --hash=sha2-256 --chunker=size-1048592 \
        --raw-leaves=true --pin=false -Q)

compose exec -T cluster1 sh -ec '
    password=$(cat /run/secrets/cluster-api-password)
    export CLUSTER_CREDENTIALS="rrfs-admin:$password"
    ipfs-cluster-ctl --host /ip4/127.0.0.1/tcp/9094 --force-http \
        pin add --replication 2 "$1"
' sh "$cid"

compose exec -T cluster1 sh -ec '
    password=$(cat /run/secrets/cluster-api-password)
    attempt=0
    while [ "$attempt" -lt 60 ]; do
        status=$(ipfs-cluster-ctl --host /ip4/127.0.0.1/tcp/9094 \
            --basic-auth "rrfs-admin:$password" --force-http status "$1")
        pinned_count=$(printf "%s\n" "$status" |
            grep -F " : PINNED |" | wc -l)
        if [ "$pinned_count" -eq 2 ]; then
            printf "%s\n" "$status"
            exit 0
        fi
        attempt=$((attempt + 1))
        sleep 2
    done
    printf "%s\n" "$status" >&2
    echo "CID did not reach PINNED status on both Cluster peers." >&2
    exit 1
' sh "$cid"

# Confirm the replicated block is retrievable from BOTH kubo and kubo2.
for node in kubo kubo2; do
    retrieved=$(compose exec -T "$node" gosu ipfs ipfs --api /ip4/127.0.0.1/tcp/5001 cat "$cid")
    if [ "$retrieved" != "ransomware-resistant-sharing local replication verification" ]; then
        echo "Retrieved payload mismatch on $node for CID $cid" >&2
        exit 1
    fi
done
printf 'verified CID %s retrievable from both kubo and kubo2\n' "$cid"

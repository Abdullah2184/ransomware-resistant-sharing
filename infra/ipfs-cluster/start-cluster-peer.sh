#!/bin/sh
set -eu

if [ ! -r /run/secrets/cluster-secret ] || [ ! -r /run/secrets/cluster-api-password ]; then
    echo "Missing required IPFS Cluster credentials." >&2
    exit 1
fi

CLUSTER_SECRET=$(cat /run/secrets/cluster-secret)
CLUSTER_API_PASSWORD=$(cat /run/secrets/cluster-api-password)
export CLUSTER_SECRET
export CLUSTER_CREDENTIALS="rrfs-admin:$CLUSTER_API_PASSWORD"
export CLUSTER_RESTAPI_BASICAUTHCREDENTIALS="rrfs-admin:$CLUSTER_API_PASSWORD"

if [ -n "${CLUSTER_BOOTSTRAP_FROM:-}" ]; then
    bootstrap_host="/dns4/$CLUSTER_BOOTSTRAP_FROM/tcp/9094"
    bootstrap_peer_id=$(
        ipfs-cluster-ctl --host "$bootstrap_host" \
            --basic-auth "$CLUSTER_CREDENTIALS" --force-http \
            --encoding=json id |
            sed -n 's/^[[:space:]]*"id": "\([^"]*\)",$/\1/p'
    )
    if [ -z "$bootstrap_peer_id" ]; then
        echo "Unable to retrieve the bootstrap Cluster peer identity." >&2
        exit 1
    fi
    set -- "$@" --bootstrap \
        "/dns4/$CLUSTER_BOOTSTRAP_FROM/tcp/9096/p2p/$bootstrap_peer_id"
fi

exec /usr/local/bin/entrypoint.sh "$@"

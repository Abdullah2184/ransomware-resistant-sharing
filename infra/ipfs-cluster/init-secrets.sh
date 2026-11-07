#!/bin/sh
set -eu

script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
secret_dir="$script_dir/secrets"

mkdir -p "$secret_dir"
chmod 700 "$secret_dir"
umask 077

create_hex_secret() {
    path=$1
    if [ ! -s "$path" ]; then
        openssl rand -hex 32 > "$path"
        chmod 600 "$path"
    fi
}

create_hex_secret "$secret_dir/cluster-secret"
create_hex_secret "$secret_dir/cluster-api-password"

if [ ! -s "$secret_dir/swarm-key" ]; then
    {
        printf '/key/swarm/psk/1.0.0/\n/base16/\n'
        openssl rand -hex 32
    } > "$secret_dir/swarm-key"
    chmod 600 "$secret_dir/swarm-key"
fi

printf '%s\n' "Local IPFS private-network and Cluster credentials are ready in the ignored secrets directory."

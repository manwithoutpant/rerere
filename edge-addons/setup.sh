#!/usr/bin/env bash
# Isolated add-on installer; existing services/settings are outside its ownership.
set -Eeuo pipefail
if [[ "$EUID" -ne 0 ]]; then
    printf '%s\n' 'Run this script as root or with sudo bash.'
    exit 1
fi
role=''
if [[ $# -gt 0 ]]; then role="$1"; fi
if [[ "$role" != foreign && "$role" != iran ]]; then
    printf '%s\n' 'Usage: sudo bash setup.sh foreign|iran [installer options]'
    exit 2
fi
shift
for dependency in curl python3 openssl ip ss systemctl systemd-run; do
    command -v "$dependency" >/dev/null || {
        printf 'Missing prerequisite: %s\n' "$dependency"
        exit 1
    }
done
edge_work=$(mktemp -d)
trap 'rm -rf -- "$edge_work"' EXIT
edge_base='https://raw.githubusercontent.com/manwithoutpant/rerere/71bd0456f49b03a5ca14286169634e50e2cfa475/edge-addons'
curl -fL --retry 3 --connect-timeout 15 --max-time 180 "$edge_base/edge_addons.py" -o "$edge_work/edge_addons.py"
curl -fL --retry 3 --connect-timeout 15 --max-time 180 "$edge_base/test_native.py" -o "$edge_work/test_native.py"
printf '%s  %s\n' 'f22a64cdcb759ba5f8b797ec2eec6152ded8cd0117635212fbc4e8a757be0f61' "$edge_work/edge_addons.py" '70034e80eaf085a43f94209bdd685fea409299e81fef7b82dbf5049a123070e2' "$edge_work/test_native.py" | sha256sum -c -
if [[ "$role" == foreign ]]; then
    python3 -u "$edge_work/edge_addons.py" install \
      --role foreign --domain edge-us.devwork12.ir \
      --bind-ip 89.117.67.71 --ipv6 2a09:e683:6:13::a "$@"
else
    python3 -u "$edge_work/edge_addons.py" install \
      --role iran --domain edge-ir.devwork12.ir \
      --bind-ip 5.160.131.169 --ipv6 2a00:15c9:0:4::a8 \
      --peer-file /root/edge-peer.json "$@"
fi

# shellcheck shell=sh
# shellcheck disable=SC2034

AUTHOR="DCx7C5 <dcxdevelopment@protonmail.com>"
VERSION=$(curl -s https://api.github.com/repos/dcx7c5/dcrypto | jq -r '.latest // empty' || echo "0.1")
PKGVER="${VERSION:+"$(echo "${VERSION}" | awk -F'-' '{print $1}')"}"
PKGREL="${VERSION:+${VERSION##*-}}"

DYSTOPIAN_USER="$(whoami || echo "root")"
DYSTOPIAN_CLEANUP_FILES="$DC_DIR/**/*.tmp"
DYSTOPIAN_PERM_FILES="$DC_DB"
DYSTOPIAN_EXIT_STATE=""



# SSL / GnuPG
DC_DIR=/etc/dystopian-crypto
DC_CA="$DC_DIR/ca"
DC_CERT="$DC_DIR/cert"
DC_KEY="$DC_CERT/private"
DC_CRL="$DC_DIR/crl"
DC_CAKEY="$DC_CA/private"
DC_OLD="$DC_DIR/old"
DC_DB="$DC_DIR/crypto-db.json"
DC_GNUPG="$DC_DIR/gnupg"
DC_FAKE_GNUPG="/tmp/dystopian-crypto-$RAND"

# SECUREBOOT
SECUREBOOT_ENABLED=0
DS_DIR=/etc/dystopian-secboot
DS_DB="$DS_DIR/secboot-db.json"
DC_MS_DIR="$DS_DIR/ms"
PK_GUID="8be4df61-93ca-11d2-aa0d-00e098032b8c"
KEK_GUID="d719b2cb-3d3a-4596-a3bc-dad00e67656f"
DB_GUID="d719b2cb-3d3a-4596-a3bc-dad00e67656f"
DBX_GUID="d719b2cb-3d3a-4596-a3bc-dad00e67656f"

# HOSTS
DH_DIR=/etc/dystopian-hosts
DH_DB=$DH_DIR/hosts-db.json

# AURTOOLS
DA_DIR=/etc/dystopian-aurtool
DA_DB=$DA_DIR/aurtool-db.json

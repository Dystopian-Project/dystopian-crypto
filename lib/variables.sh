# shellcheck shell=sh
# shellcheck disable=SC2034

AUTHOR="DCx7C5 <dcxdevelopment@protonmail.com>"
VERSION="0.1"
VERBOSE=0
DEBUG=0
QUIET=0
RAND="$(od -An -N2 -i /dev/urandom | tr -d ' ' | head -c 4)"
DC_USER="$(whoami || echo "root")"
DC_DIR=/etc/dcrypto
DC_CLEANUP_FILES="$DC_DIR/**/*.tmp"
DC_PERM_FILES="$DC_DB"
DC_EXIT_STATE=""

# SSL
DC_CA="$DC_DIR/ca"
DC_CERT="$DC_DIR/cert"
DC_KEY="$DC_CERT/private"
DC_CRL="$DC_DIR/crl"
DC_DB="$DC_DIR/db.json"
DC_CAKEY="$DC_CA/private"
DC_OLD="$DC_DIR/old"
SSL_CMD="openssl"

# GPG
DC_GNUPG="$DC_DIR/gnupg"
DC_FAKE_GNUPG="/tmp/dcrypto$RAND"
GPG_CMD="gpg"

# SECUREBOOT
SECUREBOOT_ENABLED=0
DC_SECBOOT_DIR="$DC_DIR/secureboot"
DC_SECBOOT_MS_DIR="$DC_SECBOOT_DIR/ms"
PK_GUID="8be4df61-93ca-11d2-aa0d-00e098032b8c"
KEK_GUID="d719b2cb-3d3a-4596-a3bc-dad00e67656f"
DB_GUID="d719b2cb-3d3a-4596-a3bc-dad00e67656f"
DBX_GUID="d719b2cb-3d3a-4596-a3bc-dad00e67656f"

MICROSOFT_GUID="77fa9abd-0359-4d32-bd60-28f4e78f784b"
MICROSOFT_PK_URL="https://github.com/microsoft/secureboot_objects/raw/refs/heads/main/PreSignedObjects/PK/Certificate/WindowsOEMDevicesPK.der"

MICROSOFT_KEK_CA2023_URL="https://github.com/microsoft/secureboot_objects/raw/refs/heads/main/PreSignedObjects/KEK/Certificates/microsoft%20corporation%20kek%202k%20ca%202023.der"

DC_SSL_DEPENDENCIES=(openssl)

DC_GPG_DEPENDENCIES=(gpg)

DC_SECUREBOOT_ARCH_DEPENDENCIES=(
    bootctl
    wget
    openssl
    efitools
)

SECUREBOOT_DEFAULT_PATHS=(
    /etc/secureboot


)
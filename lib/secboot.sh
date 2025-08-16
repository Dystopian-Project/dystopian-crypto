# shellcheck shell=sh
# shellcheck disable=SC2001
# shellcheck disable=SC2154
# shellcheck disable=SC2181

_cert_to_esl() {
    cert_path="${1:+$(absolutepath "$1")}"
    cert_path="${1:-})"
    esl_out="$2"
    cert_file="${cert_path:+$(filename "$cert_path")}"
    cert_dir="${cert_path:+$(dirpath "$cert_path")}"

}

_secureboot_create_keypair() {
    key_out="${1:-"$DC_SECUREBOOT/"}"
    cert_out="${2:-}"
    compatibility="${3:-true}"
    tpm="${4:-false}"


    if [ "$compatibility" = "true" ]; then
        key_type="rsa:4096"
    else
        key_type=""
    fi



}


_secureboot_create() {
    compatibility="${1:-false}"
    platform_key=""

    # Create own UUID
    uuid=$(dd if=/dev/urandom bs=16 count=1 2>/dev/null | od -An -tx4 | tr -d ' \n')
    uuid=$(echo "${uuid:0:8}-${uuid:9:4}-${uuid:12:4}-${uuid:16:4}-${uuid:20}")

    jq -e --arg uuid "$uuid" '.sb.UUID = $uuid'

}


_secureboot_load() {
    platform_key=""
}


secureboot_init() {
    bla=""


}

secureboot_enroll() {
    bla=""
}

secureboot_status() {
    bla=""
}
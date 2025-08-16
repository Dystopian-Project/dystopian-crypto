# shellcheck shell=sh
# shellcheck disable=SC2001


secboot_save_key() {
    if ! jq -e --arg type "$1" --arg val "$2" '.sb[$type] = $val' "$DC_DB"; then
        echoe "Failed adding Secure Boot $1: $2 to database"
        return 1
    fi
    return 0
}

secboot_save_vendor() {
    if ! jq -e --arg type "$1" --arg val "$2" '.sb.VENDOR[$type] = $val' "$DC_DB"; then
        echoe "Failed adding Secure Boot Vendor $1: $2 to database"
        return 1
    fi
    return 0
}

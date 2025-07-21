# shellcheck shell=sh
# shellcheck disable=SC2001

get_value_from_index() {
    jq -r \
        --arg idx "$1" \
        --arg value "$2" \
        '.ssl.ca.root[$idx][$value]
        // .ssl.ca.intermediate[$idx][$value]
        // .ssl.keys[$idx][$value]
        // empty' "$DC_DB"
}

get_value_from_ca_index() {
    jq -r \
        --arg idx "$1" \
        --arg value "$2" \
        '.ssl.ca.root[$idx][$value] // .ssl.ca.intermediate[$idx][$value] // empty' "$DC_DB"
}

get_value_from_keys_index() {
    jq -r \
        --arg idx "$1" \
        --arg value "$2" \
        '.ssl.keys[$idx][$value] // empty' "$DC_DB"
}

get_value_from_caroot_index() {
    jq -r \
        --arg idx "$1" \
        --arg value "$2" \
        '.ssl.ca.root[$idx][$value] // empty' "$DC_DB"
}

get_value_from_caint_index() {
    jq -r \
        --arg idx "$1" \
        --arg value "$2" \
        '.ssl.ca.intermediate[$idx][$value] // empty' "$DC_DB"
}

get_defaultCA_key() {
    index=$(jq -r '.ssl.defaultCA // empty' "$DC_DB")
    if [ -z "$index" ]; then
        echoe "Couldn't load defaultCA index name from database"
        return 1
    fi
    get_value_from_ca_index "$index" "key"
}

get_defaultCA_cert() {
    index=$(jq -r '.ssl.defaultCA // empty' "$DC_DB")
    if [ -z "$index" ]; then
        echoe "Couldn't load defaultCA index name from database"
        return 1
    fi
    get_value_from_ca_index "$index" "cert"
}


reset_ssl_index() {
    # Reset SSL section to default state
    if jq '.ssl = {
        defaultCA: "",
        keys: {},
        ca: {
            root: {},
            intermediate: {}
        }
    }' "$DC_DB" > "${DC_DB}.tmp"; then
        mv "${DC_DB}.tmp" "$DC_DB" || {
            echoe "Failed to reset SSL index"
            rm -f "${DC_DB}.tmp" >/dev/null
            return 1
        }
    fi
    echosv "SSL index reset to default state"
}

reset_gpg_index() {
    # Reset GPG section to default state
    if jq '.gpg = {
        defaultHome: "",
        defaultKey: "",
        keys: {}
    }' "$DC_DB" > "${DC_DB}.tmp"; then
        mv "${DC_DB}.tmp" "$DC_DB" || {
            echoe "Failed to reset GPG index"
            rm -f "${DC_DB}.tmp" >/dev/null
            return 1
        }
    fi
    echosv "GPG index reset to default state"
}

delete_key_from_keys_index() {
    index="$1"
    key="$2"
    file_delete="${3:-true}"

    if [ "$file_delete" = "true" ]; then
        file="$(jq -r --arg idx "$index" --arg key "$key" '.ssl.keys[$idx][$key] // empty' "$DC_DB")"
        rm -f "$file"
    fi

    jq -r --arg idx "$index" --arg key "$key" 'del(.ssl.keys[$idx][$key])' "$DC_DB" > "${DC_DB}.tmp" || {
        echoe "Failed calling jq --arg idx $index --arg key $key 'del(.ssl.ca[idx][key])' $DC_DB > ${DC_DB}.tmp"
        rm -f "$DC_DB.tmp"
        return 1
    }

    mv "${DC_DB}.tmp" "$DC_DB" || {
        echoe "Failed moving $DC_DB"
        rm -f "$DC_DB.tmp"
        return 1
    }

    rm -f "${DC_DB}.tmp" || {
        echoe "Removing $DC_DB.tmp failed"
        rm -f "$DC_DB.tmp"
        return 1
    }

    return 0
}

delete_key_from_ca_index() {
    index="$1"
    key="$2"
    file_delete="${3:-true}"

    if [ "$file_delete" = "true" ]; then
        file="$(jq -r --arg idx "$index" --arg key "$key" '.ssl.ca.intermediate[$idx][$key] // .ssl.ca.root[$idx][$key] // empty' "$DC_DB")"
        rm -f "$file"
    fi

    jq -r --arg idx "$index" --arg key "$key" 'del(.ssl.ca.root[$idx][$key]) // del(.ssl.ca.intermediate[$idx][$key])' "$DC_DB" > "${DC_DB}.tmp" || {
        echoe "Failed calling jq --arg idx $index --arg key $key 'del(.ssl.ca[idx][key])' $DC_DB > ${DC_DB}.tmp"
        rm -f "$DC_DB.tmp"
        return 1
    }

    mv "${DC_DB}.tmp" "$DC_DB" || {
        echoe "Failed moving $DC_DB"
        rm -f "$DC_DB.tmp"
        return 1
    }

    rm -f "${DC_DB}.tmp" || {
        echoe "Removing $DC_DB.tmp failed"
        rm -f "$DC_DB.tmp"
        return 1
    }

    return 0
}

cleanup_index() {
    index="$1"
    jq --arg idx "$index" 'del(.ssl.keys[$idx])' "$DC_DB" > "${DC_DB}.tmp" || {
        echoe "Failed deleting contents of ssl: keys: $index"
        rm -f "${DC_DB}.tmp"
        return 1
    }

    mv "${DC_DB}.tmp" "$DC_DB" || {
        echoe "Failed to move temporary database file to $DC_DB"
        rm -f "${DC_DB}.tmp"
        return 1
    }

    return 0
}


backup_and_rename() {
    file_type="$1"
    index="$2"
    outfile="$3"

    # Count existing backup entries for this index and import_file type
    n=$(jq -r \
           --arg idx "$index" \
           --arg type "${file_type}bkp" \
            '.ssl.keys[$idx] | to_entries | map(select(.key | startswith($type))) | length' "$DC_DB")

    # Increment for new backup
    n=$((n + 1))

    # Create backup filename
    backup_file="${outfile%.*}.${n}.${outfile##*.}"

    # Move the existing import_file to backup location
    mv "$outfile" "$backup_file" || {
        echoe "Failed to backup $file_type import_file to $backup_file"
        return 1
    }

    # Update index: move current entry to backup entry, remove original entry
    backup_key="${file_type}bkp${n}"
    if ! jq --arg idx "$index" \
      --arg backup_path "$(get_realpath_from_file "$backup_file")" \
      --arg backup_key "$backup_key" \
      --arg file_type "$file_type" \
      '.ssl.keys[$idx][$backup_key] = .ssl.keys[$idx][$file_type] |
       del(.ssl.keys[$idx][$file_type])' \
      "$DC_DB" > "${DC_DB}.tmp"; then
        echoe "Failed to update index with backup entry"
        rm -f "${DC_DB}.tmp"
        return 1
    fi

    mv "${DC_DB}.tmp" "$DC_DB" || {
        echoe "Failed to move temporary database file to $DC_DB"
        rm -f "${DC_DB}.tmp"
        return 1
    }

    # Update the backup entry with the actual backup import_file path
    if ! jq --arg idx "$index" \
      --arg backup_path "$(get_realpath_from_file "$backup_file")" \
      --arg backup_key "$backup_key" \
      '.ssl.keys[$idx][$backup_key] = $backup_path' \
      "$DC_DB" > "${DC_DB}.tmp"; then
        echoe "Failed to update backup path in index"
        rm -f "${DC_DB}.tmp"
        return 1
    fi

    mv "${DC_DB}.tmp" "$DC_DB" || {
        echoe "Failed to move temporary database file to $DC_DB"
        rm -f "${DC_DB}.tmp"
        return 1
    }
    return 0
}


default_ca_exists() {
    if jq -e '.ssl.defaultCA // empty' "$DC_DB" >/dev/null; then
        return 0
    fi
    return 1
}


index_exists() {
    if jq -e \
        --arg idx "$1" \
        '.ssl.ca.root[$idx]
        // .ssl.ca.intermediate[$idx]
        // .ssl.keys[$idx]
        // empty' "$DC_DB" >/dev/null; then
        return 0
    fi
    return 1
}


root_ca_index_exists() {
    if jq -e \
        --arg idx "$1" \
        '.ssl.ca.root[$idx]
        // empty' "$DC_DB" >/dev/null; then
        return 0
    fi
    return 1
}


int_ca_index_exists() {
    if jq -e \
        --arg idx "$1" \
        '.ssl.ca.intermediate[$idx]
        // empty' "$DC_DB" >/dev/null; then
      return 0
    fi
    return 1
}


keys_index_exists() {
    if jq -e \
        --arg idx "$1" \
        '.ssl.keys[$idx]
        // empty' "$DC_DB" >/dev/null; then
      return 0
    fi
    return 1
}


add_to_ssl_keys_database() {
    index="$1"
    key="$2"
    value="$3"

    if [ -z "$index" ] || [ -z "$key" ] || [ -z "$value" ]; then
        echoe "Index, key, and value are required"
        return 1
    fi

    # Convert value to realpath if it's a import_file that exists
    if [ -f "$value" ]; then
        value="$(absolutepath "$value")"
    fi

    if ! jq --arg idx "$index" \
      --arg key "$key" \
      --arg value "$value" \
      '.ssl.keys[$idx][$key] = $value' \
      "$DC_DB" > "${DC_DB}.tmp"; then
        echoe "Failed to add $key to index"
        rm -f "${DC_DB}.tmp"
        return 1
    fi

    mv "${DC_DB}.tmp" "$DC_DB" || {
        echoe "Failed to move temporary database file to $DC_DB"
        rm -f "${DC_DB}.tmp"
        return 1
    }
    echod "Successfully updated ssl keys database for ssl: keys: $index: $key"
    return 0
}

add_to_ca_database() {
    storage_type="$1"
    index="$2"
    key="$3"
    value="$4"
    echod "Adding to CA database: type=$storage_type, index=$index, key=$key, value=$value"
    if ! jq --arg type "$storage_type" \
            --arg idx "$index" \
            --arg key "$key" \
            --arg val "$value" \
            '.ssl.ca[$type][$idx][$key] = $val' \
            "$DC_DB" > "${DC_DB}.tmp"; then
        echoe "Failed to update CA database for ssl: $storage_type: $index: $key"
        rm -f "${DC_DB}.tmp"
        return 1
    fi

    mv "${DC_DB}.tmp" "$DC_DB" || {
        echoe "Failed to move temporary database file to $DC_DB"
        rm -f "${DC_DB}.tmp"
        return 1
    }
    echod "Successfully updated ssl CA database for ssl: $storage_type: $index: $key"
    return 0
}

find_index_by_key_value() {
    search_key="$1"
    search_value="$2"
    jq -r \
        --arg key "$search_key" \
        --arg value "$search_value" \
        '.ssl.keys | to_entries[] | select(.value[$key] == $value) | .key
        // .ssl.ca.root | to_entries[] | select(.value[$key] == $value) | .key
        // .ssl.ca.intermediate | to_entries[] | select(.value[$key] == $value) | .key
        // empty' "$DC_DB"
}

find_keys_index_by_key_value() {
    search_key="$1"
    search_value="$2"

    jq -r \
        --arg key "$search_key" \
        --arg value "$search_value" \
        '.ssl.keys | to_entries[] | select(.value[$key] == $value) | .key
        // empty' "$DC_DB"
}

find_ca_index_by_key_value() {
    key="$1"
    value="$2"
    jq -r \
        --arg key "$key" \
        --arg val "$value" \
        '.ssl.ca.root | to_entries[] | select(.value[$key] == $val) | "root:\(.key)"
        // .ssl.ca.intermediate | to_entries[] | select(.value[$key] == $val) | "intermediate:\(.key)"
        // empty' "$DC_DB"
}

cleanup_ca_index() {
    ca_type="$1"
    ca_index="$2"

    if [ -z "$ca_type" ] || [ -z "$ca_index" ]; then
        echoe "Error: CA type and index are required"
        return 1
    fi

    if ! jq -e --arg type "$ca_type" \
            --arg idx "$ca_index" \
            'del(.ssl.ca[$type][$idx])' \
            "$DC_DB" > "${DC_DB}.tmp"; then
        echoe "Failed to cleanup .ssl.ca.$ca_type.$ca_index"
        rm -f "${DC_DB}.tmp"
        return 1
    fi

    mv "${DC_DB}.tmp" "$DC_DB" || {
        echoe "Failed to move temporary database file to $DC_DB"
        rm -f "${DC_DB}.tmp"
        return 1
    }

    echosv "Cleaned up CA Index $ca_type:$ca_index"
    return 0
}


add_to_serial_file() {
    index="$1"
    serial="$2"
    printf "%s" "$2" >> "$DC_CA"
}
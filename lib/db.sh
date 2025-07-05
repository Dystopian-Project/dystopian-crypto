get_ssl_keys_key_value() {
    index="$1"
    key="$2"

    if [ -z "$index" ] || [ -z "$key" ]; then
        echoe "Index and key are required"
        return 1
    fi

    jq -r --arg idx "$index" --arg key "$key" \
        '.ssl.keys[$idx][$key] // empty' \
        "$DC_DB"
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
        chmod 600 "$DC_DB" && chown root:"$DC_USER" "$DC_DB"
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
        chmod 600 "$DC_DB" && chown root:"$DC_USER" "$DC_DB"
    fi
    echosv "GPG index reset to default state"
}

get_storage() {
    cat="$1"
    key="$2"
    jq --arg cat "$cat" --arg key "$key" -r '.[$cat][$key]' "${DC_DB}"
}


delete_storage() {
  if [ "$1" = "default" ]; then
    echoe "The default CA storage can't be deleted"
    exit 1
  fi
  jq "del(.storages.$1)" \
  "$DC_DB" > "${DC_DB}.tmp" \
    && mv "${DC_DB}.tmp" "DC_DB"
  chmod 600 "$DC_DB" && chown root:"$DC_USER" "$DC_DB"
  echosv "Deleted CA storage ${1}"
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
        value="$(realpath "$value")"
    fi

    if jq --arg idx "$index" \
       --arg key "$key" \
       --arg value "$value" \
       '.ssl.keys[$idx][$key] = $value' \
       "$DC_DB" > "${DC_DB}.tmp" \
       && mv "${DC_DB}.tmp" "$DC_DB" \
       && chmod 600 "$DC_DB" && chown root:"$DC_USER" "$DC_DB"; then
        :  # Success - do nothing
    else
        echoe "Failed to add $key to index"
        rm -f "${DC_DB}.tmp"  # Clean up temp import_file on failure
        return 1
    fi
}


cleanup_after_signing() {
    index="$1"
    dictkey="$2"
    path="$3"
    keep="${4:-"false"}"

    if [ "$keep" = "false" ] && [ -f "$path" ]; then
        rm -f "$path"

        jq --arg idx "$index" --arg dictkey "$dictkey" \
           'del(.ssl.keys[$idx][$dictkey])' \
           "$DC_DB" > "${DC_DB}.tmp" \
           && mv "${DC_DB}.tmp" "$DC_DB"
        chmod 600 "$DC_DB" && chown root:"$DC_USER" "$DC_DB"
        echos "Cleaned up $index: $dictkey: $path"
    fi
}

cleanup_index() {
    index="$1"
        jq --arg idx "$index" \
        'del(.ssl.keys[$idx])' \
        "$DC_DB" > "${DC_DB}.tmp" \
        && mv "${DC_DB}.tmp" "$DC_DB"
        chmod 600 "$DC_DB" && chown root:"$DC_USER" "$DC_DB"
        echos "Cleaned up Index $index"
}

find_index_by_key_value() {
    search_key="$1"
    search_value="$2"

    jq -r --arg key "$search_key" --arg value "$search_value" \
        '.ssl.keys | to_entries[] | select(.value[$key] == $value) | .key' \
        "$DC_DB"
}

backup_and_rename() {
    file_type="$1"  # "csr" or "cfg"
    index="$2"
    outfile="$3"

    if [ -z "$file_type" ] || [ -z "$index" ] || [ -z "$outfile" ]; then
        echoe "File type, index, and output import_file are required"
        return 1
    fi

    if [ "$file_type" != "csr" ] && [ "$file_type" != "cfg" ]; then
        echoe "File type must be 'csr' or 'cfg'"
        return 1
    fi

    if [ ! -f "$outfile" ]; then
        echoe "$file_type import_file $outfile does not exist"
        return 1
    fi

    # Count existing backup entries for this index and import_file type
    n=$(jq -r --arg idx "$index" --arg type "${file_type}bkp" \
        '.ssl.keys[$idx] | to_entries | map(select(.key | startswith($type))) | length' \
        "$DC_DB")

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
    if jq --arg idx "$index" \
       --arg backup_path "$(realpath "$backup_file")" \
       --arg backup_key "$backup_key" \
       --arg file_type "$file_type" \
       '.ssl.keys[$idx][$backup_key] = .ssl.keys[$idx][$file_type] |
        del(.ssl.keys[$idx][$file_type])' \
       "$DC_DB" > "${DC_DB}.tmp" \
       && mv "${DC_DB}.tmp" "$DC_DB" \
       && chmod 600 "$DC_DB" && chown root:"$DC_USER" "$DC_DB"; then
        :  # Success - do nothing
    else
        echoe "Failed to update index with backup entry"
        rm -f "${DC_DB}.tmp"  # Clean up temp import_file on failure
        return 1
    fi


    # Update the backup entry with the actual backup import_file path
    if jq --arg idx "$index" \
       --arg backup_path "$(realpath "$backup_file")" \
       --arg backup_key "$backup_key" \
       '.ssl.keys[$idx][$backup_key] = $backup_path' \
       "$DC_DB" > "${DC_DB}.tmp" \
       && mv "${DC_DB}.tmp" "$DC_DB" \
       && chmod 600 "$DC_DB" && chown root:"$DC_USER" "$DC_DB"; then
        :  # Success - do nothing
    else
        echoe "Failed to update backup path in index"
        rm -f "${DC_DB}.tmp" >/dev/null
        return 1
    fi


    echov "$file_type import_file backed up: $backup_file"
    echov "Index updated with ${backup_key} entry"

    return 0
}

# CA-specific index functions
get_ca_value() {
    ca_type="$1"  # "root" or "intermediate"
    ca_index="$2"
    key="$3"

    if [ -z "$ca_type" ] || [ -z "$ca_index" ] || [ -z "$key" ]; then
        echoe "CA type, index and key are required"
        return 1
    fi

    jq -r --arg type "$ca_type" --arg idx "$ca_index" --arg key "$key" \
        '.ssl.ca[$type][$idx][$key] // empty' "$DC_DB"
}


add_to_ca_database() {
    ca_type="$1"
    ca_index="$2"
    key="$3"
    value="$4"
    if [ -z "$ca_type" ] || [ -z "$ca_index" ] || [ -z "$key" ] || [ -z "$value" ]; then
        echoe "CA type, index, key, and value are required"
        return 1
    fi

    # Convert value to realpath if it's a import_file that exists
    if [ -f "$value" ]; then
        value="$(realpath "$value")"
    fi

    if jq --arg type "$ca_type" \
       --arg idx "$ca_index" \
       --arg key "$key" \
       --arg value "$value" \
       '.ssl.ca[$type][$idx][$key] = $value' \
       "$DC_DB" > "${DC_DB}.tmp" \
       && mv "${DC_DB}.tmp" "$DC_DB" \
       && chmod 600 "$DC_DB" && chown root:"$DC_USER" "$DC_DB"; then
        :  # Success - do nothing
    else
        echoe "Failed to add $key to CA index"
        rm -f "${DC_DB}.tmp" >/dev/null
        return 1
    fi
}

find_ca_by_key_value() {
    ca_type="$1"  # "root" or "intermediate"
    search_key="$2"
    search_value="$3"

    if [ -z "$ca_type" ] || [ -z "$search_key" ] || [ -z "$search_value" ]; then
        echoe "CA type, search key, and search value are required"
        return 1
    fi

    jq -r --arg type "$ca_type" --arg key "$search_key" --arg value "$search_value" \
        '.ssl.ca[$type] | to_entries[] | select(.value[$key] == $value) | .key' \
        "$DC_DB"
}



find_ca_by_key_value_any() {
    search_key="$1"
    search_value="$2"

    if [ -z "$search_key" ] || [ -z "$search_value" ]; then
        echoe "Search key and search value are required"
        return 1
    fi

    # Try root first, then intermediate
    result=$(find_ca_by_key_value "root" "$search_key" "$search_value")
    if [ -n "$result" ]; then
        return 0
    fi

    result=$(find_ca_by_key_value "intermediate" "$search_key" "$search_value")
    if [ -n "$result" ]; then
        return 0
    fi

    return 1
}

ca_with_name_exists() {
    name="$1"
      # Check if <name> exists in root or intermediate
    if jq -e ".ssl.ca.root.\"$name\" // .ssl.ca.intermediate.\"$name\" // null" "$DC_DB" >/dev/null; then
        echod "CA name '$name' exists"
        return 0
    else
        echowv "CA name '$name' does not exist"
        return 1
    fi
}

cleanup_ca_index() {
    ca_type="$1"
    ca_index="$2"

    if [ -z "$ca_type" ] || [ -z "$ca_index" ]; then
        echoe "Error: CA type and index are required"
        return 1
    fi

    jq --arg type "$ca_type" --arg idx "$ca_index" \
        'del(.ssl.ca[$type][$idx])' \
        "$DC_DB" > "${DC_DB}.tmp" \
        && mv "${DC_DB}.tmp" "$DC_DB"
    chmod 600 "$DC_DB" && chown root:"$DC_USER" "$DC_DB"
    echos "Cleaned up CA Index $ca_type:$ca_index"
}

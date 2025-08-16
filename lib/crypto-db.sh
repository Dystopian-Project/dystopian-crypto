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
        encrypted: [],
        keys: {},
        ca: {
            root: {},
            intermediate: {}
        }
    }' "$DC_DB" > "${DC_DB}.tmp"; then
        mv -- "${DC_DB}.tmp" "$DC_DB" || {
            echoe "Failed to reset SSL index"
            rm -f -- "${DC_DB}.tmp" >/dev/null
            return 1
        }
    fi
    echosv "SSL index reset to default state"
}

reset_gpg_index() {
    # Reset GPG section to default state
    if jq '.gpg = {
        defaultKey: "",
        defaultSign: "",
        defaultAuth: "",
        defaultEncrypt: "",
        keys: {}
    }' "$DC_DB" > "${DC_DB}.tmp"; then
        mv -- "${DC_DB}.tmp" "$DC_DB" || {
            echoe "Failed to reset GPG index"
            rm -f -- "${DC_DB}.tmp" >/dev/null
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
        rm -f -- "$file"
    fi

    jq -r --arg idx "$index" --arg key "$key" 'del(.ssl.keys[$idx][$key])' "$DC_DB" > "${DC_DB}.tmp" || {
        echoe "Failed calling jq --arg idx $index --arg key $key 'del(.ssl.ca[idx][key])' $DC_DB > ${DC_DB}.tmp"
        rm -f -- "$DC_DB.tmp"
        return 1
    }

    mv -- "${DC_DB}.tmp" "$DC_DB" || {
        echoe "Failed moving $DC_DB"
        rm -f -- "$DC_DB.tmp"
        return 1
    }

    rm -f -- "${DC_DB}.tmp" || {
        echoe "Removing $DC_DB.tmp failed"
        rm -f -- "$DC_DB.tmp"
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
        rm -f -- "$file"
    fi

    jq -r --arg idx "$index" --arg key "$key" 'del(.ssl.ca.root[$idx][$key]) // del(.ssl.ca.intermediate[$idx][$key])' "$DC_DB" > "${DC_DB}.tmp" || {
        echoe "Failed calling jq --arg idx $index --arg key $key 'del(.ssl.ca[idx][key])' $DC_DB > ${DC_DB}.tmp"
        rm -f -- "$DC_DB.tmp"
        return 1
    }

    mv -- "${DC_DB}.tmp" "$DC_DB" || {
        echoe "Failed moving $DC_DB"
        rm -f -- "$DC_DB.tmp"
        return 1
    }

    return 0
}

cleanup_index() {
    index="$1"
    jq --arg idx "$index" 'del(.ssl.keys[$idx])' "$DC_DB" > "${DC_DB}.tmp" || {
        echoe "Failed deleting contents of ssl: keys: $index"
        rm -f -- "${DC_DB}.tmp"
        return 1
    }

    mv -- "${DC_DB}.tmp" "$DC_DB" || {
        echoe "Failed to move temporary database file to $DC_DB"
        rm -f -- "${DC_DB}.tmp"
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
    mv -- "$outfile" "$backup_file" || {
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
        rm -f -- "${DC_DB}.tmp"
        return 1
    fi

    mv -- "${DC_DB}.tmp" "$DC_DB" || {
        echoe "Failed to move temporary database file to $DC_DB"
        rm -f -- "${DC_DB}.tmp"
        return 1
    }

    # Update the backup entry with the actual backup import_file path
    if ! jq --arg idx "$index" \
      --arg backup_path "$(get_realpath_from_file "$backup_file")" \
      --arg backup_key "$backup_key" \
      '.ssl.keys[$idx][$backup_key] = $backup_path' \
      "$DC_DB" > "${DC_DB}.tmp"; then
        echoe "Failed to update backup path in index"
        rm -f -- "${DC_DB}.tmp"
        return 1
    fi

    mv -- "${DC_DB}.tmp" "$DC_DB" || {
        echoe "Failed to move temporary database file to $DC_DB"
        rm -f -- "${DC_DB}.tmp"
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
        // empty' "$DC_DB" >/dev/null 2>&1; then
        return 0
    fi
    return 1
}


gpg_index_exists() {
    if jq -e \
          --arg idx "$1" \
          '.gpg.keys[$idx] //
           .gpg.keys[].subkeys[$idx] //
            empty' "$DC_DB" >/dev/null 2>&1; then
        return 0
    fi
    return 1
}


root_ca_index_exists() {
    if jq -e \
        --arg idx "$1" \
        '.ssl.ca.root[$idx]
        // empty' "$DC_DB" >/dev/null 2>&1; then
        return 0
    fi
    return 1
}


int_ca_index_exists() {
    if jq -e \
        --arg idx "$1" \
        '.ssl.ca.intermediate[$idx]
        // empty' "$DC_DB" >/dev/null 2>&1; then
      return 0
    fi
    return 1
}


keys_index_exists() {
    if jq -e \
        --arg idx "$1" \
        '.ssl.keys[$idx]
        // empty' "$DC_DB" >/dev/null 2>&1; then
      return 0
    fi
    return 1
}


add_to_ssl_keys_database() {
    index="$1"
    key="$2"
    value="$3"
    if ! jq --arg idx "$1" \
      --arg key "$2" \
      --arg value "$3" \
      '.ssl.keys[$idx][$key] = $value' \
      "$DC_DB" > "${DC_DB}.tmp"; then
        echoe "Failed to add $2 to index"
        rm -f -- "${DC_DB}.tmp"
        return 1
    fi

    mv -- "${DC_DB}.tmp" "$DC_DB" || {
        echoe "Failed to move temporary database file to $DC_DB"
        rm -f -- "${DC_DB}.tmp"
        return 1
    }
    echod "Updating ssl keys database successful for ssl: keys: $1: $2 = $3"
    return 0
}


add_to_ca_database() {
    storage_type="$1"
    index="$2"
    key="$3"
    value="$4"
    if ! jq --arg type "$storage_type" \
            --arg idx "$index" \
            --arg key "$key" \
            --arg val "$value" \
            '.ssl.ca[$type][$idx][$key] = $val' \
            "$DC_DB" > "${DC_DB}.tmp"; then
        echoe "Failed to update CA database for ssl: $storage_type: $index: $key"
        rm -f -- "${DC_DB}.tmp"
        return 1
    fi

    mv -- "${DC_DB}.tmp" "$DC_DB" || {
        echoe "Failed to move temporary database file to $DC_DB"
        rm -f -- "${DC_DB}.tmp"
        return 1
    }
    echod "Updating ssl CA database successful for ssl: $storage_type: $index: $key = $value"
    return 0
}

add_gpg_key() {
    if ! jq --arg idx "$1" \
        '.gpg.keys[$idx] = {}' \
        "$DC_DB" > "${DC_DB}.tmp"; then
            echoe "Failed to update GPG database for gpg: $1: $2 : $3"
            rm -f -- "${DC_DB}.tmp"
            return 1
    fi

    mv -- "${DC_DB}.tmp" "$DC_DB" || {
        echoe "Failed to move temporary database file to $DC_DB"
        rm -f -- "${DC_DB}.tmp"
        return 1
    }
    echod "Updating GPG database successful for gpg: keys: $1 = {}"
    return 0
}

add_gpg_sub() {
    if ! jq --arg idx "$1" \
            --arg sub "$2" \
            '.gpg.keys[$idx].subkeys[$sub] = {}' \
            "$DC_DB" > "${DC_DB}.tmp"; then
        echoe "Failed to update GPG database for gpg: $1: $2 : $3"
        rm -f -- "${DC_DB}.tmp"
        return 1
    fi

    mv -- "${DC_DB}.tmp" "$DC_DB" || {
        echoe "Failed to move temporary database file to $DC_DB"
        rm -f -- "${DC_DB}.tmp"
        return 1
    }
    echod "Updating GPG database successful for gpg: keys: $1: subkeys: $2 = {}"
    return 0
}


add_to_gpg_key() {
    if [ $# -eq 4 ]; then
        if ! jq -r \
                --arg idx "$1" \
                --arg sidx "$2" \
                --arg key "$3" \
                --arg val "$4" \
                '.gpg.keys[$idx].subkeys[$sidx][$key] = $val' \
                "$DC_DB" > "${DC_DB}.tmp"; then
            echoe "Something went wrong while adding subkeys"
            rm -f -- "${DC_DB}.tmp"
            return 1
        fi
    elif [ $# -eq 3 ]; then
        if ! jq -r --arg idx "$1" \
                    --arg key "$2" \
                    --arg val "$3" \
                    '.gpg.keys[$idx][$key] = $val' \
                    "$DC_DB" > "${DC_DB}.tmp"; then
                echoe "Failed to update GPG database for gpg: $1: $2 : $3"
                rm -f -- "${DC_DB}.tmp"
                return 1
        fi
    fi

    mv -- "${DC_DB}.tmp" "$DC_DB" || {
        echoe "Failed to move temporary database file to $DC_DB"
        rm -f -- "${DC_DB}.tmp"
        return 1
    }
    if [ $# -eq 3 ]; then
        echod "Updating GPG database successful for gpg: keys: $1: $2 = $3"
    elif [ $# -eq 4 ]; then
        echod "Updating GPG database successful for gpg: keys: $1: subkeys: $2: $3 = $4"
    fi
    return 0
}



find_index_by_key_value() {
    if ! jq -r \
            --arg key "$1" \
            --arg value "$2" \
            '.ssl.keys | to_entries[] | select(.value[$key] == $value) | .key
            // .ssl.ca.root | to_entries[] | select(.value[$key] == $value) | .key
            // .ssl.ca.intermediate | to_entries[] | select(.value[$key] == $value) | .key
            // empty' "$DC_DB"; then
        return 1
    fi
    return 0
}


find_gpg_index_by_key_value() {
    if ! jq -r \
            --arg key "$1" \
            --arg value "$2" \
            '.gpg.keys | to_entries[] | select(.value[$key] == $value) | .key //
             empty' "$DC_DB"; then
        return 1
    fi
    return 0
}


find_keys_index_by_key_value() {
    if ! jq -r \
            --arg key "$1" \
            --arg value "$2" \
            '.ssl.keys | to_entries[] | select(.value[$key] == $value) | .key //
             empty' "$DC_DB"; then
        return 1
    fi
    return 0
}


find_ca_index_by_key_value() {
    if ! jq -r \
            --arg key "$1" \
            --arg val "$2" \
            '.ssl.ca.root | to_entries[] | select(.value[$key] == $val) | "root:\(.key)"
            // .ssl.ca.intermediate | to_entries[] | select(.value[$key] == $val) | "intermediate:\(.key)"
            // empty' "$DC_DB"; then
        return 1
    fi
    return 0
}


cleanup_ca_index() {
    ca_type="$1"
    ca_index="$2"

    if ! jq -e --arg type "$ca_type" \
            --arg idx "$ca_index" \
            'del(.ssl.ca[$type][$idx])' \
            "$DC_DB" > "${DC_DB}.tmp"; then
        echoe "Failed to cleanup .ssl.ca.$ca_type.$ca_index"
        rm -f -- "${DC_DB}.tmp"
        return 1
    fi

    mv -- "${DC_DB}.tmp" "$DC_DB" || {
        echoe "Failed to move temporary database file to $DC_DB"
        rm -f -- "${DC_DB}.tmp"
        return 1
    }

    echosv "Cleaned up CA Index $ca_type:$ca_index"
    return 0
}

cleanup_gpg_index() {
    if ! jq -e --arg idx "$1" 'del(.gpg.keys[$idx])' "$DC_DB" > "${DC_DB}.tmp"; then
        echoe "Failed to cleanup .gpg.keys.$1"
        rm -f -- "${DC_DB}.tmp"
        return 1
    fi

    mv -- "${DC_DB}.tmp" "$DC_DB" || {
        echoe "Failed to move temporary database file to $DC_DB"
        rm -f -- "${DC_DB}.tmp"
        return 1
    }
    return 0
}

add_to_encrypted_db() {
    if ! jq -e --arg path "$1" --arg salt "$2" \
         '.ssl.encrypted += [{"path": $path, "salt": $salt}]' "$DC_DB" > "${DC_DB}.tmp"; then
        echoe "Something went wrong"
        return 1
    fi

    mv -- "${DC_DB}.tmp" "$DC_DB" || {
        echoe "Not able to save temporary db as database file."
        return 1
    }
    return 0
}


remove_from_encrypted_db_by_path() {
    if ! jq -e --arg path "$1" \
         '.ssl.encrypted = [.ssl.encrypted[] | select(.path != $path)]' "$DC_DB" > "${DC_DB}.tmp"; then
        echoe "Something went wrong"
        return 1
    fi

    mv -- "${DC_DB}.tmp" "$DC_DB" || {
        echoe "Not able to save temporary db as database file."
        return 1
    }
    return 0
}


add_to_gpg_subkeys() {
    if ! jq -e \
            --arg idx "$1" \
            --arg subidx "$2" \
            --arg key "$3" \
            --arg value "$4" \
        '.gpg.keys[$idx].subkeys[$subidx][$key] = $value' "$DC_DB" > "${DC_DB}.tmp"; then
        echoe "Something went wrong while adding subkeys"
    fi
    mv -- "${DC_DB}.tmp" "$DC_DB" || {
        echoe "Not able to save temporary db as database file."
        return 1
    }
    echod "Updating GPG database successful for gpg: keys: $1: subkeys: $2: $3 = $4"
    return 0
}


get_value_from_sub() {
    if ! jq -r \
            --arg idx "$1" \
            --arg val "$2" \
            '.gpg.keys[].subkeys |
             .[$idx][$val] // empty' "$DC_DB"; then
        echoe "Failed getting value: $2 from subkey index: $1"
        return 1
    fi
    return 0
}


get_value_from_primary() {
    if ! jq -r \
            --arg idx "$1" \
            --arg val "$2" \
            '.gpg.keys[$idx][$val] // empty' \
            "$DC_DB"; then
        echoe "Failed getting value: $2 from primary key index: $1"
        return 1
    fi
    return 0
}


get_gpg_value() {
    value=$(get_value_from_sub "$1" "$2")

    if [ -z "$value" ]; then
        value=$(get_value_from_primary "$1" "$2")
    fi

    # shellcheck disable=SC2181
    if [ "$?" -ne 0 ] || [ -z "$value" ]; then
        echoe "Failed fetching from json file"
        return 1
    fi
    echo "$value"
    return 0
}

delete_gpg_key_and_value_from_sub() {
    index="$1"
    key="$2"

    if ! jq -r --arg idx "$1" \
               --arg key "$2" \
               '.gpg.keys[].subkeys' "$DC_DB"; then
        echoe
    fi


}


delete_gpg_key_and_value_from_primary() {
    index="$1"
    key="$2"
}


delete_gpg_key_and_value() {
    index="$1"
    key="$2"
}

get_value_by_key_match_from_sub() {
    if ! jq -r --arg val "$1" \
               --arg matchkey "$2" \
               --arg matchval "$3" \
               '.gpg.keys[].subkeys[] |
                select(.[$matchkey] == $matchval) |
                .[$val] // empty' "$DC_DB"; then
        echoe "Failed getting value: $1 by key $2 matching $3 from subkey"
        return 1
    fi
    return 0
}


get_value_by_key_match_from_primary() {
    if ! jq -r --arg val "$1" \
               --arg matchkey "$2" \
               --arg matchval "$3" \
               '.gpg.keys[].subkeys[] |
                select(.[$matchkey] == $matchval) |
                .[$val] // empty' "$DC_DB"; then
        echoe "Failed getting value: $1 by key $2 matching $3 from primary"
        return 1
    fi
    return 0
}


get_value_by_key_match() {
    value=$(get_value_by_key_match_from_sub "$1" "$2" "$3")

    if [ -z "$value" ]; then
        value=$(get_value_by_key_match_from_primary "$1" "$2" "$3")
    fi

    # shellcheck disable=SC2181
    if [ "$?" -ne 0 ] || [ -z "$val" ]; then
        echoe "Failed fetching from json file"
        return 1
    fi

    echo "$value"
    return 0
}

get_index_by_key_match_from_sub() {
    if ! jq -r \
            --arg mkey "$1" \
            --arg mval "$2" \
            '.gpg.keys[].subkeys | to_entries[] |
             select(.value[$mkey] == $mval) | .key // empty' "$DC_DB"; then
        echoe "Failed getting index where sub key: $1 has value: $2"
        return 1
    fi
    return 0
}

get_index_by_key_match_from_primary() {
    if ! jq -r \
            --arg mkey "$1" \
            --arg mval "$2" \
            '.gpg.keys | to_entries[] |
             select(.value[$mkey] == $mval) |
             .key // empty' "$DC_DB"; then
        echoe "Failed getting index where primary key: $1 has value: $2"
        return 1
    fi
    return 0
}


get_index_by_key_match() {
    index=$(get_index_by_key_match_from_sub "$1" "$2")

    if [ -z "$index" ]; then
        index=$(get_index_by_key_match_from_primary "$1" "$2")
    fi

    # shellcheck disable=SC2181
    if [ "$?" -ne 0 ] || [ -z "$index" ]; then
        echoe "Failed fetching from json file"
        return 1
    fi

    echo "$index"
    return 0
}

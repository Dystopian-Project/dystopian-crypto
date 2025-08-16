# shellcheck shell=sh
# shellcheck disable=SC2001
# shellcheck disable=SC2034
# shellcheck disable=SC2181

askyesno() {
    default="$2"
    case "$default" in
        y|Y|yes|Yes|YES)
            question=$(printf "%s [Y/n]: " "$1")
            default_return=0
            ;;
        n|N|no|No|NO)
            question=$(printf "%s [y/N]: " "$1")
            default_return=1
            ;;
        *)
            question=$(printf "%s [y/N]: " "$1")
            default_return=1
            ;;
    esac
    while true; do
        printf "\033[1m\033[1;33m>\033[0m\033[1m %s\033[0m" "$question"
        read -r yesno
        case "$yesno" in
            y|Y|j|J|yes|Yes|YES) return 0;;
            n|N|no|NO|No) return 1;;
            "") return $default_return;;
            * ) ;;
        esac
    done
}

echoi() {
    if [ "$QUIET" -ne 1 ]; then
        if [ "$DEBUG" -eq 1 ]; then istr="   INFO:"; else istr=""; fi
        printf "\033[1m\033[1;36m>%s\033[0m\033[1;37m\033[1m %s\033[0m\n" "$istr" "$1"
    fi
}

echov() {
    if [ "$VERBOSE" -eq 1 ]; then
        if [ "$DEBUG" -eq 1 ]; then istr="   INFO:"; else istr=""; fi
        printf "\033[1m\033[1;36m>%s\033[0m\033[1;37m\033[1m %s\033[0m\n" "$istr" "$1"
    fi
}

echod() {
    if [ "$DEBUG" -eq 1 ]; then
        printf "\033[1m\033[1;37m>  DEBUG:\033[0m %s\n" "$1"
    fi
}

echow() {
    if [ "$QUIET" -ne 1 ]; then
      printf "\033[1m\033[1;33m> WARNING:\033[0m\033[1;37m\033[1m %s\033[0m\n" "$1" >&2
    fi
}

echowv() {
    if [ "$VERBOSE" -eq 1 ]; then
        echow "$1"
    fi
}

echoe() {
    printf "\033[1m\033[1;31m>  ERROR:\033[0m\033[1;37m\033[1m %s\033[0m\n" "$1" >&2
}

echos() {
    if [ "$QUIET" -ne 1 ]; then
        printf "\033[1m\033[1;32m>>>\033[0m\033[1;37m\033[1m %s\033[0m\n" "$1"
    fi
}

echosv() {
  if [ "$VERBOSE" -eq 1 ]; then
      if [ "$DEBUG" -eq 1 ]; then istr="   INFO:"; else istr=""; fi
      printf "\033[1m\033[1;32m>%s\033[0m\033[1;37m\033[1m %s\033[0m\n" "$istr" "$1"
  fi
}

is_ip() {
    ip="$1"
    if echo "$ip" | grep -E '^((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$' >/dev/null 2>&1; then
        return 0
    elif echo "$ip" | grep -E '^([0-9a-fA-F]{1,4}:){0,7}[0-9a-fA-F]{1,4}(:[0-9a-fA-F]{1,4}){0,7}$|^::1$' >/dev/null 2>&1; then
        return 0
    fi
    return 1
}

shorthelp() {
  echo ""
  help | sed -n "/^  $1/,/^$/p"
}

reset_dcrypto() {
    ssl="${1:-false}"
    gpg="${2:-false}"
    if askyesno "Are you sure you want to reset the config and keys?" "n";then
        if askyesno "Do you want to backup the directory first?" "y"; then
            cp -rf "$DC_DIR" "${DC_DIR}.bkp" 2>/dev/null || {
                echoe "Problem backing up keys and config"
                exit 1
            }
            echos "Backup successful @ /etc/dystopian-crypto.bkp"
        fi
        if [ -n "$ssl" ] && [ "$ssl" = "true" ]; then
            rm -rf -- "${DC_CA}" "{$DC_CERT}" "${DC_CRL}" 2>/dev/null || {
                echoe "Problem resetting dystopian-crypto ssl"
                exit 1
            }
            mkdir -p "$DC_CAKEY" "$DC_KEY" "$DC_CRL" || {
                echoe "Problem creating ssl directories"
                exit 1
            }
            set_permissions_and_owner "$DC_DIR" 750
            set_permissions_and_owner "$DC_KEY" 700
            set_permissions_and_owner "$DC_CAKEY" 700
            reset_ssl_index
            echos "Reset of dystopian-crypto SSL successful"
        fi
        if [ -n "$gpg" ] && [ "$gpg" = "true" ]; then
            rm -rf -- "${DC_GNUPG}" 2>/dev/null || {
              echoe "Problem resetting dystopian-crypto gpg"
              exit 1
            }
            mkdir -p "$DC_GNUPG" || {
                echoe "Failed creating new gpg home directory"
                exit 1
            }
            set_permissions_and_owner "$DC_GNUPG" 700
            reset_gpg_index
            echos "Reset of dystopian-crypto GPG successful"
        fi
    else
      echoi "Exiting dystopian-crypto. No harm was done."
      exit 0
    fi
}

# Maintenance and utility functions
show_index() {
    show_keys="${1:-false}"
    show_ca="${2:-false}"
    show_json="${3:-false}"

    if [ "$show_json" = "true" ]; then
        jq '.' "$DC_DB"
        return 0
    fi

    echoi "dystopian-crypto Index Summary"
    echo "  ===================="
    echo ""

    # Show default CA
    default_ca=$(jq -r '.ssl.defaultCA // "none"' "$DC_DB")
    echoi "Default CA: $default_ca"
    echo ""

    if [ "$show_ca" = "true" ] || [ "$show_keys" = "false" ]; then
        echoi "Certificate Authorities:"
        echo "  ------------------------"
        # Show root CAs
        echoi "Root CAs:"
        jq -r '.ssl.ca.root | to_entries[] | "  - " + .key' "$DC_DB" 2>/dev/null || echo "  None"

        # Show intermediate CAs
        echoi "Intermediate CAs:"
        jq -r '.ssl.ca.intermediate | to_entries[] | "  - " + .key' "$DC_DB" 2>/dev/null || echo "  None"
        echo ""
    fi

    if [ "$show_keys" = "true" ] || [ "$show_ca" = "false" ]; then
        echoi "Keys and Certificates:"
        echo "  ----------------------"
        key_count=$(jq -r '.ssl.keys | length' "$DC_DB")

        if [ "$VERBOSE" -eq 1 ]; then
            jq -r '.ssl.keys | to_entries[] | "  - " + .key + ": " + (.value | to_entries | map(.key + "=" + .value) | join(", "))' "$DC_DB" 2>/dev/null
        fi
        echo ""
        echos "Total key entries: $key_count"
    fi
}


cleanup_dcrypto_files() {
    cleanup_index="$1"
    cleanup_orphaned="${2:-false}"
    cleanup_backups="${3:-false}"
    cleanup_non_ca_keys="${4:-false}"
    cleanup_dry_run="${5:-false}"
    keep_backups="${6:-2}"  # Number of recent backup CSRs to keep

    echod "Starting cleanup_dcrypto_files with parameters:"
    echod "        cleanup_index: $cleanup_index"
    echod "     cleanup_orphaned: $cleanup_orphaned"
    echod "      cleanup_backups: $cleanup_backups"
    echod "  cleanup_non_ca_keys: $cleanup_non_ca_keys"
    echod "      cleanup_dry_run: $cleanup_dry_run"
    echod "         keep_backups: $keep_backups"
    echod "               DC_DIR: $DC_DIR"
    echod "                DC_DB: $DC_DB"

    echoi "dystopian-crypto Cleanup${cleanup_dry_run:+$([ "$cleanup_dry_run" = "true" ] && echo "DRY RUN")}"
    echoi "=============="

    # Clean specific index
    if [ -n "$cleanup_index" ]; then
        echoi "Cleaning up specific index: $cleanup_index"
        if ! jq -e ".ssl.keys.\"$cleanup_index\"" "$DC_DB" >/dev/null 2>&1; then
            echoe "Index $cleanup_index does not exist in $DC_DB"
            return 1
        fi
        if [ "$cleanup_dry_run" != "true" ]; then
            _cleanup_index "$cleanup_index" || {
                echoe "Failed to clean index $cleanup_index"
                return 1
            }
            echos "Index $cleanup_index cleaned successfully"
        else
            echov "Dry run: Would clean index $cleanup_index"
        fi
        return 0
    fi

    # Clean orphaned files
    if [ "$cleanup_orphaned" = "true" ]; then
        echoi "Finding orphaned files..."
        tmpfile_orphaned=$(mktemp) || { echoe "Failed to create temporary import_file for orphaned files"; return 1; }
        find "$DC_DIR" -type f \( -name "*.pem" -o -name "*.csr" -o -name "*.conf" -o -name "*.salt" \) > "$tmpfile_orphaned"
        found_orphaned=false
        while IFS= read -r import_file < "$tmpfile_orphaned"; do
            file_path="$(realpath "$import_file")"
            echod "Checking if import_file is orphaned: $file_path"
            # Strip quotes from index.json paths
            if ! jq -r '.ssl.keys | to_entries[] | .value | to_entries[] | .value' "$DC_DB" | sed 's/^"\(.*\)"$/\1/' | grep -Fx "$file_path" >/dev/null 2>&1 && \
               ! jq -r '.ssl.ca | to_entries[] | .value | to_entries[] | .value' "$DC_DB" | sed 's/^"\(.*\)"$/\1/' | grep -Fx "$file_path" >/dev/null 2>&1; then
                found_orphaned=true
                echoi "Orphaned import_file: $file_path"
                if [ "$cleanup_dry_run" != "true" ]; then
                    rm -f -- "$file_path" 2>/dev/null || {
                        echoe "Failed to remove orphaned import_file: $file_path"
                        continue
                    }
                    echos "Removed orphaned import_file: $file_path"
                else
                    echov "Dry run: Would remove orphaned import_file: $file_path"
                fi
            else
                echod "File $file_path is referenced in index, skipping"
            fi
        done
        rm -f -- "$tmpfile_orphaned"
        if [ "$found_orphaned" = "false" ]; then
            echoi "No orphaned files found"
        fi
        echos "Orphaned import_file cleanup completed"
    fi

    # Clean backup files
    if [ "$cleanup_backups" = "true" ]; then
        echoi "Cleaning up backup files..."
        tmpfile_backups=$(mktemp) || { echoe "Failed to create temporary import_file for backup files"; return 1; }
        find "$DC_DIR" -type f \( -name "*bkp*" -o -name "cert.[0-9]*.csr" \) > "$tmpfile_backups"
        found_backups=false
        while IFS= read -r backup_file < "$tmpfile_backups"; do
            found_backups=true
            backup_file_path="$(realpath "$backup_file")"
            # Check if import_file is a csrbkp in index.json
            index=$(jq -r --arg path "$backup_file_path" '.ssl.keys | to_entries[] | select(.value | to_entries[] | select(.key | test("^csrbkp") and .value == $path)) | .key' "$DC_DB")
            if [ -n "$index" ]; then
                # Sort csrbkp entries by number and keep only the most recent $keep_backups
                backup_files=$(jq -r --arg idx "$index" '.ssl.keys[$idx] | to_entries[] | select(.key | test("^csrbkp")) | .value' "$DC_DB" | sort -V)
                total_backups=$(echo "$backup_files" | wc -l)
                if [ "$total_backups" -gt "$keep_backups" ]; then
                    delete_count=$((total_backups - keep_backups))
                    echo "$backup_files" | head -n "$delete_count" | while IFS= read -r old_backup; do
                        echoi "Backup import_file (index $index): $old_backup"
                        if [ "$cleanup_dry_run" != "true" ]; then
                            rm -f -- "$old_backup" 2>/dev/null || {
                                echoe "Failed to remove backup import_file: $old_backup"
                                continue
                            }
                            # Remove from index.json
                            bkp_key=$(jq -r --arg idx "$index" --arg path "$old_backup" '.ssl.keys[$idx] | to_entries[] | select(.value == $path) | .key' "$DC_DB")
                            if jq -e "del(.ssl.keys.\"$index\".\"$bkp_key\")" "$DC_DB" > "$DC_DB.tmp"; then
                                mv -- "$DC_DB.tmp" "$DC_DB" 2>/dev/null
                                set_permissions_and_owner "$DC_DB" 600
                            else
                                echoe "Failed to update index.json for backup import_file: $old_backup"
                                continue
                            fi
                            echos "Removed backup import_file: $old_backup"
                        else
                            echov "Dry run: Would remove backup import_file: $old_backup"
                        fi
                    done
                else
                    echod "Keeping backup import_file (within limit $keep_backups): $backup_file_path"
                fi
            else
                echoi "Backup import_file (no index): $backup_file_path"
                if [ "$cleanup_dry_run" != "true" ]; then
                    rm -f -- "$backup_file_path" 2>/dev/null || {
                        echoe "Failed to remove backup import_file: $backup_file_path"
                        continue
                    }
                    echos "Removed backup import_file: $backup_file_path"
                else
                    echov "Dry run: Would remove backup import_file: $backup_file_path"
                fi
            fi
        done
        rm -f -- "$tmpfile_backups" >/dev/null
        if [ "$found_backups" = "false" ]; then
            echoi "No backup files found"
        fi
        echos "Backup import_file cleanup completed"
    fi

    # Clean non-CA keys
    if [ "$cleanup_non_ca_keys" = "true" ]; then
        echoi "Cleaning up non-CA key files..."
        tmpfile_keys=$(mktemp) || { echoe "Failed to create temporary import_file for non-CA keys"; return 1; }
        jq -r '.ssl.keys | to_entries[] | .key + " " + .value.key' "$DC_DB" > "$tmpfile_keys"
        found_keys=false
        while IFS= read -r line < "$tmpfile_keys"; do
            found_keys=true
            index=$(echo "$line" | cut -d' ' -f1)
            key_file=$(echo "$line" | cut -d' ' -f2- | sed 's/^"\(.*\)"$/\1/')
            echod "Checking key import_file: $key_file (index $index)"
            # Get CA keys from index.json
            ca_keys=$(jq -r '.ssl.ca | to_entries[] | .value | to_entries[] | .value | select(.key == "key") | .value' "$DC_DB" | sed 's/^"\(.*\)"$/\1/')
            # Skip if key is a CA key
            if echo "$ca_keys" | grep -Fx "$key_file" >/dev/null 2>&1; then
                echod "Key $key_file is a CA key, skipping"
                continue
            fi
            echoi "Non-CA key import_file: $key_file (index $index)"
            if [ "$cleanup_dry_run" != "true" ]; then
                rm -f -- "$key_file" 2>/dev/null || {
                    echoe "Failed to remove non-CA key import_file: $key_file"
                    continue
                }
                # Remove the entire index entry
                if jq -e "del(.ssl.keys.\"$index\")" "$DC_DB" > "$DC_DB.tmp"; then
                    mv -- "$DC_DB.tmp" "$DC_DB" 2>/dev/null
                    set_permissions_and_owner "$DC_DB" 600
                else
                    echoe "Failed to update index.json for non-CA key: $key_file"
                    continue
                fi
                echos "Removed non-CA key import_file: $key_file"
            else
                echov "Dry run: Would remove non-CA key import_file: $key_file"
            fi
        done
        rm -f -- "$tmpfile_keys" >/dev/null
        if [ "$found_keys" = "false" ]; then
            echoi "No non-CA key files found"
        fi
        echos "Non-CA key cleanup completed"
    fi

    # Display cleanup completion message
    if [ "$cleanup_dry_run" = "true" ]; then
        echos "dystopian-crypto cleanup completed successfully (DRY RUN)"
    else
        echos "dystopian-crypto cleanup completed successfully"
    fi
    return 0
}

list_certificate_authorities() {
    ca_list_type="${1:-all}"

    echoi "Certificate Authorities"
    echoi "======================"

    if [ "$ca_list_type" = "all" ] || [ "$ca_list_type" = "root" ]; then
        echoi ""
        echoi "Root CAs:"
        echoi "---------"
        jq -r '.ssl.ca.root | to_entries[] | .key + " | " + (.value.name // "Unnamed") + " | " + (.value.created // "Unknown date")' "$DC_DB" 2>/dev/null | \
        while IFS='|' read -r index name created; do
            printf "  %-12s %-30s %s\n" "$index" "$name" "$created"
            if [ "$VERBOSE" -eq 1 ]; then
                cert_file=$(_get_ca_value "root" "$(echo "$index" | tr -d ' ')" "cert")
                if [ -f "$cert_file" ]; then
                    echoi "    Certificate: $cert_file"
                    echoi "    Subject: $(openssl x509 -in "$cert_file" -noout -subject | sed 's/subject=//')"
                fi
            fi
        done
    fi

    if [ "$ca_list_type" = "all" ] || [ "$ca_list_type" = "intermediate" ]; then
        echoi ""
        echoi "Intermediate CAs:"
        echoi "-----------------"
        jq -r '.ssl.ca.intermediate | to_entries[] | .key + " | " + (.value.name // "Unnamed") + " | " + (.value.created // "Unknown date")' "$DC_DB" 2>/dev/null | \
        while IFS='|' read -r index name created; do
            printf "  %-12s %-30s %s\n" "$index" "$name" "$created"
            if [ "$VERBOSE" -eq 1 ]; then
                cert_file=$(_get_ca_value "intermediate" "$(echo "$index" | tr -d ' ')" "cert")
                if [ -f "$cert_file" ]; then
                    echoi "    Certificate: $cert_file"
                    echoi "    Subject: $(openssl x509 -in "$cert_file" -noout -subject | sed 's/subject=//')"
                fi
            fi
        done
    fi
}


install_docker_cert() {
    client="${1:-false}"
    server="${2:-false}"
    import_dir="${3:-}"
    domains_ips_server="${4:-"localhost,127.0.0.1,172.17.0.1,host.docker.internal"}"

    echod "Starting create_private_key with parameters:"
    echod "      client: $client"
    echod "      server: $server"
    echod "  import_dir: $import_dir"
    echod "        user: $DC_USER"

    if [ -d "$import_dir" ]; then
        pems=$(find "$import_dir" -type f -name "*.pem")
        for fp in $pems; do
            if basename "$fp" | grep -qE "^int"; then
                type="intermediate"
            else
                type="root"
            fi

            if grep -qE 'PRIVATE KEY' "$fp"; then
                keyorcert="key"
            elif grep -qE "CERTIFICATE" "$fp"; then
                keyorcert="cert"
            else
                echoe "Problem during import_file import: $fp"
                return 1
            fi

            index="$(basename "$fp" | awk -F. '{print $(NF-1)}')"
            add_to_ca_database "$type" "$index" "$keyorcert" "$fp"
        done
        echod "Found import files: $import_dir"

    fi

    if ! ca_with_name_exists "docker"; then
        echoi "Creating Docker Certificate Authority"
        create_certificate_authority "" "" "Docker"
    fi

    echov "Docker Certificate Authority found in database"
    ca_cert_file="$(jq -r '.ssl.ca.root.docker.cert // .ssl.ca.intermediate.docker.cert' "$DC_DB")"
    echod "Found CA certificate import_file: $ca_cert_file"
    ca_key_file="$(jq -r '.ssl.ca.root.docker.key // .ssl.ca.intermediate.docker.key' "$DC_DB")"
    echod "Found CA private key import_file: $ca_key_file"

    #daemon_json="/etc/docker/daemon.json"

    if [ "$server" = "true" ]; then
        echov "Installing Docker client certificate"
        server_dir="/etc/docker/tls"
        if [ ! -d "$server_dir" ]; then
            mkdir -p "$server_dir"
        fi
        server_cert_out="$server_dir/server-cert.pem"
        server_key_out="$server_dir/server-key.pem"
        server_csr_out="$server_dir/server-cert.csr"

        create_private_key "$server_key_out" "" ""
        create_certificate_signing_request "$server_key_out" "$server_csr_out" "$domains_ips_server" "$server"
        sign_certificate_request "$server_csr_out" "$ca_cert_file" "$ca_key_file" "$server_cert_out"

        set_permissions_and_owner "$server_key_out" 400
        set_permissions_and_owner "$server_cert_out" 444

    fi

    if [ "$client" = "true" ]; then
        echov "Installing Docker server certificate"
        #home_dir="$(eval echo "~${DC_USER}")"
        user_dir="$homedir/.docker"

        if [ ! -d "$user_dir" ]; then
            mkdir -p "$user_dir"
        fi
        client_key_out="$user_dir/key.pem"
        client_csr_out="$user_dir/cert.csr"
        client_cert_out="$user_dir/cert.pem"

        create_private_key "$client_key_out" "" ""
        create_certificate_signing_request "$client_key_out" "$client_csr_out" "localhost,127.0.0.1" "$client"
        sign_certificate_request "$client_csr_out" "$ca_cert_file" "$ca_key_file" "$client_cert_out"

        set_permissions_and_owner "$client_key_out" 400
        set_permissions_and_owner "$client_cert_out" 444
    fi

}


key_belongs_to_cert() {
    key_file="$1"
    cert_file="$2"
    keypub=$(openssl ec -in "$key_file" -pubout 2>/dev/null || \
             openssl rsa -in "$key_file" -pubout 2>/dev/null)
    if [ -z "$keypub" ]; then
        echod "Couldn't determine publickey in keyfile: $key_file"
        return 1
    fi
    keypub=$(echo "$keypub" | tail -n +2 | head -n -1)
    certpub=$(openssl x509 -in "$cert_file" -noout -pubkey | tail -n +2 | head -n -1)
    if [ "$keypub" = "$certpub" ]; then
        echod "Publickey of $key_file and $cert_file are identical"
        return 0
    fi
    return 1
}


get_file_type() {
    file="$(realpath "$1")"
    filename="$(basename "$file")"
    ext=${filename##*.}
    type=""

    if [ "$ext" = "conf" ] || [ "$ext" = "cfg" ]; then
        type="cfg"
    elif [ "$ext" = "pem" ] || [ "$ext" = "cert" ] || [ "$ext" = "crt" ] || [ "$ext" = "cer" ]; then
        if grep -qE "PRIVATE KEY" "$file"; then
            type="key"

        elif grep -qE "BEGIN CERTIFICATE" "$file"; then
            if grep -qE "CA:TRUE" "$file" && grep -qE "pathlen:" "$file"; then
                type="intermediate"
            elif grep -qE "CA:TRUE"; then
                type="root"
            else
                type="normal"
            fi
        fi
    fi
    if [ -n "$type" ]; then
        echo "$type"
        return 0
    fi
    return 1
}


check_ssl_database() {
    echoi "Checking database integrity"
    files=$(find "$DC_CA" -type f -maxdepth 1)
    for f in $files; do
        f="$(realpath "$f")"
        ca_name="$(basename "$f" | awk -F. '{print $(NF-1)}')"
        if ! jq -e --arg idx "$ca_name" '.ssl.ca.root // .ssl.ca.intermediate | to_entries[] | select(.key == $idx)' "$DC_DB"; then
            echow "File is missing in database: $f"
        fi
    done
}

set_permissions_and_owner() {
    perm="$2"
    if [ "$DB_USER" = "root" ] && [ "$perm" -eq 440 ]; then
        perm=400
    fi
    if ! chmod "$perm" "$1" 2>/dev/null; then
        echoe "Failed to set permissions $perm on $1"
        return 1
    fi
    if ! chown "root:${DC_USER}" "$1" 2>/dev/null; then
        echoe "Failed to set owner root:${DC_USER} on $1"
        return 1
    fi
    if [ "$1" != "$DC_DB" ]; then
        echov "Successfully set perm ($perm) and owner 'root:$DC_USER' on $1"
    else
        echod "Successfully set perm ($perm) and owner 'root:$DC_USER' on $1"
    fi
    return 0
}


get_dir_from_index() {
    jq -r \
        --arg idx "$1" \
        '.ssl.keys[idx] | .dir //
         .ssl.ca.root[$idx] | .dir //
         .ssl.ca.intermediate[$idx] | .dir //
         empty' -- "$DC_DB"
}

rename_file_if_exists() {
    # Get file components
    dir="$(dirpath "$1")"
    basename="${1##*/}"
    ext="${basename##*.}"
    base="${basename%*".$ext"}"

    # If file doesn't exist, return original file
    if [ ! -f "$dir/$base.$ext" ]; then
        echo "$1"
        return 0
    fi
    # Rename with counter
    c=1
    if [ -n "$2" ] && echo "$base" | grep -qE "^[a-zA-Z]*\.$2$"; then
        # Handle <base>.<name>.<counter>.<ext> (e.g., key.test.1.pem)
        while [ -f "$dir/$base.$c.$ext" ]; do
            c=$(("$c" + 1))
        done
        echo "$dir/$base.$c.$ext"
    else
        # Handle <base>.<counter>.<ext> (e.g., key.1.pem or custom.1.pem)
        while [ -f "$dir/$base.$c.$ext" ]; do
            c=$(("$c" + 1))
        done
        echo "$dir/$base.$c.$ext"
    fi
}

absolutepath() {
    if which realpath >/dev/null 2>&1; then
        realpath -- "$1"
    else
        dir="$(dirpath "$1")"
        basename="${1##*/}"
        echo "$dir/$basename"
    fi
    return 0
}

absolutepathidx() {
    dir="$(dirpath "$1")"
    basename="${1##*/}"
    ext="${basename##*.}"
    base="${basename%*".$ext"}"

    if [ ! -f "$dir/$base.$2.$ext" ]; then
        echo "$dir/$base.$2.$ext"
        return 0
    fi

    c=1
    while [ -f "$dir/$base.$2.$c.$ext" ]; do
        c=$(("$c" + 1))
    done
    echo "$dir/$base.$2.$c.$ext"
}

dirpath() {
    path="$1"
    resolved_path=""

    case "$path" in
        /*)
            work_path="$path"
            ;;
        *)
            # The check ensures we don't add a trailing slash if pwd is just "/"
            current_dir=$(pwd)
            if [ "$current_dir" = "/" ]; then
                work_path="/$path"
            else
                work_path="$current_dir/$path"
            fi
            ;;
    esac

    set -f # Temporarily disable globbing to handle components like '*'.
    IFS='/' # Set the Internal Field Separator to '/' to split the path.
    for component in $work_path; do
        case "$component" in
            "" | ".")
                continue
                ;;
            ..)
                resolved_path=$(echo "$resolved_path" | sed 's|/[^/]*$||')
                ;;
            *)
                resolved_path="$resolved_path/$component"
                ;;
        esac
    done
    unset IFS
    set +f

    if [ -z "$resolved_path" ]; then
        echo "/"
    else
        echo "$resolved_path"
    fi
    return 0
}

filename() {
    if which basename >/dev/null 2>&1; then
        basename -- "$1"
        return 0
    fi
    echo "$1" | awk -F'/' '{print $NF}'
}

get_index_from_filename() {
    basename="${1##*/}"
    ext="${basename##*.}"
    base="${basename%*".$ext"}"
    if echo "$base" | grep -qE '\.'; then
        echo "$base" | awk -F. '{print $NF}'
        return 0
    fi
    return 1
}


_cleanup() {
    echod "Cleaning up generated files..."
    for file in $DC_CLEANUP_FILES; do
        rm -rf -- "$file"
    done
    echod "done."
}


set_perms_trap() {
    echod "Setting permissions and ownership..."
    for file in $DC_PERM_FILES; do
        set_permissions_and_owner "$file" 440
    done
    echod "done."
}


on_exit() {
    set_perms_trap
    _cleanup
}


#
## GPG FUNCTIONS
#


get_index_from_gpg() {
    if ! gpg --homedir "$DC_GNUPG" --list-keys --keyid-format long "$1" | \
         grep uid | \
         awk -F'[][]' '{print $(NF-0)}' | \
         awk -F' <' '{print $1}' | \
         sed -e 's/\-/\_/g' -e 's/\ /\_/g' | \
         tr "[:upper:]" "[:lower:]"; then
        echoe "Failed getting index from gpg name"
        return 1
    fi
    return 0
}


get_name_from_gpg() {
    if ! gpg --homedir "$DC_GNUPG" --list-keys --keyid-format long "$1" | \
         grep uid | \
         awk -F'[][]' '{print $(NF-0)}' | \
         awk -F' <' '{print $1}'; then
        echoe "Failed getting Name from $1"
        return 1
    fi
    return 0
}


get_email_from_gpg() {
    if ! gpg --homedir "$DC_GNUPG" --list-keys --keyid-format long "$1" | \
         grep uid | \
         awk -F'<' '{print $2}' | \
         awk -F'>' '{print $1}'; then
        echoe "Error getting email address from $1"
        return 1
    fi
    return 0
}


get_fingerprint_from_gpg() {
    if ! gpg --homedir "$DC_GNUPG" --fingerprint --keyid-format long "$1" | \
         grep -i finger | \
         awk -F'= ' '{print $2}'; then
        echoe "Failed getting fingerprint from $1"
        return 1
    fi
    return 0
}


get_subkey_ids_from_gpg() {
    if ! gpg --homedir "$DC_GNUPG" --list-keys --keyid-format long "$1" | \
         grep sub | \
         awk -F'/' '{print $2}' | \
         awk -F' ' '{print $1}'; then
        echoe "Failed getting subkeys from $1"
        return 1
    fi
    return 0
}


create_gpg_filename() {
    index="$1"
    usage="$2"
    armor="${3:-false}"
    typestr="${4:-}"

    if [ "$armor" = "false" ] && { [ "$typestr" = "public" ] || [ "$typestr" = "sub" ]; }; then
        ext="gpg"
    elif [ "$armor" = "false" ] && { [ "$typestr" = "secret" ] || [ "$typestr" = "ssb" ]; }; then
        ext="key"
    elif [ "$armor" = "true" ]; then
        ext="asc"
    fi

    if [ "$usage" = "S" ]; then
        usage="signing"
    elif [ "$usage" = "E" ]; then
        usage="encrypt"
    elif [ "$usage" = "A" ]; then
        usage="auth"
    fi

    echo "$index-$(date "+%Y%m%d_%H%M")-$usage-$typestr.$ext"
}


get_name_real_from_uid() {
    if ! echo "$1" | grep -qE "\(|\)"; then
        echo "$1" | awk -F' <' '{print $1}'
    else
        echo "$1" | awk -F' \\(' '{print $1}'
    fi
}


get_name_email_from_uid() {
    echo "$1" | awk -F' <' '{print $2}' | awk -F'>' '{print $1}'
}


get_name_comment_from_uid() {
    echo "$1" | awk -F' \\(' '{print $2}' | awk -F'\\)' '{print $1}'
}


gpg_build_cmd() {
    { [ "$2" = "add" ] || [ "$2" = "gen" ] || [ "$2" = "adduid" ]; } && [ -n "$5" ] && GPG_CMD="$GPG_CMD --batch"
    [ "$2" = "imp" ] && [ -z "$5" ] && gpg_cmd="$GPG_CMD --batch"
    [ -n "$1" ] && GPG_CMD="$GPG_CMD --homedir ${1}"
    [ "$4" = "false" ] && GPG_CMD="$GPG_CMD --armor"
    [ -s "$5" ] && GPG_CMD="$GPG_CMD --pinentry-mode loopback --passphrase-file ${5}"
    { { [ -n "$5" ] && [ ! -f "$5" ]; } || [ -z "$5" ]; } && { [ "$2" != "exp" ] && [ "$2" != "imp" ]; } && GPG_CMD="$GPG_CMD --pinentry-mode loopback --passphrase-fd 0"
    [ "$2" = "exp" ] && GPG_CMD="$GPG_CMD --export"
    [ "$2" = "imp" ] && GPG_CMD="$GPG_CMD --import"
    [ "$2" = "expsec" ] && GPG_CMD="$GPG_CMD --export-secret-keys"
    [ "$2" = "expsecsub" ] && GPG_CMD="$GPG_CMD --export-secret-subkeys"
    [ "$3" = "true" ] && GPG_CMD="$GPG_CMD -a"
    [ "$2" = "gen" ] && GPG_CMD="$GPG_CMD --quick-gen-key"
    [ "$2" = "add" ] && GPG_CMD="$GPG_CMD --quick-add-key"
    [ "$2" = "adduid" ] && GPG_CMD="$GPG_CMD --quick-add-uid"
}


ssl_build_cmd() {
    use="$1"
    in="$2"
    out="$3"
    passphrase="$4"
    no_argon="${5:-false}"
    tpm="${6:-false}"

    SSL_CMD="openssl"
    # Usage scenarios
    [ "$use" = "key" ] && SSL_CMD="$SSL_CMD genpkey"
    [ "$use" = "req" ] && SSL_CMD="$SSL_CMD req"
    [ "$use" = "crt" ] && SSL_CMD="$SSL_CMD x509"
    { [ "$use" = "enc" ] || [ "$use" = "dec" ]; } && SSL_CMD="$SSL_CMD aes-256-cbc"
    [ "$use" = "dec" ] && SSL_CMD="$SSL_CMD -d"
    [ "$use" = "enc" ] && SSL_CMD="$SSL_CMD -e"

    # Check tpm
    { [ "$tpm" = "true" ] && [ "$use" = "crt" ]; } && SSL_CMD="$SSL_CMD -provider tpm2"

    # No argon
    { [ -n "$passphrase" ] && [ "$no_argon" = "true" ]; } && SSL_CMD="$SSL_CMD -pbkdf2"

    # Passphrase
    if [ "$passphrase" != "cli" ] && [ "$passphrase" != "CLI" ]; then
        [ -s "$passphrase" ] && SSL_CMD="$SSL_CMD -pass file:$1"
        { [ -n "$passphrase" ] && [ ! -f "$passphrase" ]; } && SSL_CMD="$SSL_CMD -pass pass:$1"
    fi

    { [ -n "$in" ] && [ "$in" != "stdin" ] && [ "$in" != "-" ]; } && SSL_CMD="$SSL_CMD -in $in"
    { [ -n "$out" ] && [ "$out" != "stdout" ] && [ "$out" != "-" ]; } && SSL_CMD="$SSL_CMD -out $out"

}


check_gpg_key_integrity() {
    mkdir -p -- "$DC_FAKE_GNUPG" || {
        echoe "Not able to create directory for key integrity check."
        return 1
    }

    touch -- "$DC_FAKE_GNUPG/pubring.kbx" || {
        echoe "Not able to create pubring.kbx for key integrity check."
        return 1
    }

    if grep -qE "BEGIN PGP (PUBLIC|PRIVATE) KEY BLOCK" -- "$1"; then
        gpg --batch --homedir "$DC_FAKE_GNUPG" --import -- "$1"
    elif file -- "$1" | grep -q "openssl enc"; then
        ssl_build_cmd "$2" "$1"
        $SSL_CMD | gpg --batch --homedir "$DC_FAKE_GNUPG" --import -- "$1"
    else
        echoe "Key is not a GPG key"
    fi

    if [ "$?" -ne 0 ]; then
        echoe "Key integrity check failed"
        rm -rf -- "$DC_FAKE_GNUPG"
        return 1
    fi

    rm -rf -- "$DC_FAKE_GNUPG"
    return 0
}

encrypt_gpg_key() {
    salt=$(openssl rand -hex 16)
    iv=$(openssl rand -hex 16)

    {
        echo "Salted__"
        echo "$iv"
        echo "$3" | openssl aes-256-cbc -e \
                                 -K "$(_create_argon2id_derived_key_pw "$2" "$salt")" \
                                 -iv "$iv"
    } > "${1}.enc"

    if [ ! -s "${1}.enc" ]; then
        echoe "Failed creating file with encrypted gpg key."
        return 1
    fi

    set_permissions_and_owner "${1}.enc" 440
    return 0
}

decrypt_gpg_key() {
    path="${1:+$(basename -- "$1")}"
    index="${2:-$(basename -- "${path%%.*}")}"
    passphrase="$3"
    salt="$(get_gpg_value "$index" "salt")"
    iv=$(sed -n '2p' "$path")
    passphrasedbg="${3:+$()}"
    saltdbg="${salt}"

    echod "Starting decrypt_gpg_key with parameters:"
    echod "      path: $path"
    echod "     index: $index"
    echod "      salt: $salt"
    echod "        iv: $iv"

    echoi "Decrypting gpg key..."

    echod "Decrypt Key: tail -n +3 \"$path\" | openssl aes-256-cbc -d -iv \"$iv\" -K \"\$(_create_argon2id_derived_key_pw "" "")\""

    tail -n +3 "$path" | openssl aes-256-cbc -d \
            -iv "$iv" \
            -K "$(_create_argon2id_derived_key_pw "$3" "$salt")"

    # jq -r --arg idx "$index" 'del(.gpg.keys[$idx].salt)' "$DC_DB"

}

install_package() {
    package="$1"

    if [ -f /etc/os-release ]; then
        while read -r line; do
            case "$line" in
                ID=*)
                    distro=$(printf "%s\n" "$line" | sed 's/ID_LIKE=//')
                    if [ -z "$distro" ]; then
                        distro=$(printf "%s\n" "$line" | sed 's/ID=//')
                    fi
                    ;;
            esac
        done < /etc/os-release
    else
        echoe "Cannot detect distribution. /etc/os-release not found."
        return 1
    fi

    case "$distro" in
        ubuntu | debian)
            echov "Detected $distro. Using apt to install $package..."
            # Update package lists
            apt update
            # Install the package
            if apt install -y "$package"; then
                echoi "$package installed successfully"
            else
                echoe "Failed to install $package"
                return 1
            fi
            ;;
        arch)
            echov "Detected Arch Linux. Using pacman to install $package..."
            # Sync and install the package
            if pacman -S --noconfirm "$package"; then
                echoi "$package installed successfully."
            else
                echoe "Failed to install $package"
                return 1
            fi
            ;;
        *)
            echoe "Unsupported distribution: $distro"
            return 1
            ;;
    esac
    return 0
}

check_dependencies_secureboot() {
bla
}

remount_efivars_rw() {
    echod "Remounting efivars to read/write"
    mount -o rw,remount /sys/firmware/efi/efivars || {
        echoe "Failed remounting efivars to read/write"
        return 1
    }
    echod "$(mount | grep efivars)"
    return 0
}

remount_efivars_ro() {
    echod "Remounting efivars to read only"
    mount -o ro,remount /sys/firmware/efi/efivars || {
        echoe "Failed remounting efivars to read only"
        return 1
    }
    echod "$(mount | grep efivars)"
    return 0
}


ssl_convert_der_to_pem() {
    echod "Converting DER to PEM:"
    openssl x509 -inform der -outform pem -in "$1" -out "${1%.*}.pem"
    echod "Converted $1 to ${1%.*}.pem"
}

ssl_convert_pem_to_der() {
    echod "Converting PEM to DER:"
    openssl x509 -inform pem -outform der -in "$1" -out "${1%.*}.der"
    echod "Converted $1 to ${1%.*}.pem"
}

download_ms_kek_certs() {
    echoi "Downloading Microsoft Corporation KEK CA 2011 certificate and  Microsoft Corporation KEK 2K CA 2023..."
    pk=$(wget -qO - "")

}

detect_distro() {
    # Detect the distribution
    if [ -f /etc/os-release ]; then
        while read -r line; do
            case "$line" in
                ID=*|ID_LIKE=*)
                    distro=$(printf "%s\n" "$line" | sed 's/ID_LIKE=//')
                    [ -z "$distro" ] && distro=$(printf "%s\n" "$line" | sed 's/ID=//')
                    ;;
            esac
        done < /etc/os-release
    else
        echoe "Cannot detect distribution. /etc/os-release not found."
        return 1
    fi

    echod "Detected distribution: $distro"
}

check_secureboot_status() {
    SECUREBOOT_ENABLED=$(od --address-radix=n \
                            --format=u1 "/sys/firmware/efi/efivars/SecureBoot-8be4df61-93ca-11d2-aa0d-00e098032b8c" | \
                            awk -F' ' '{print $NF}')
    if [ "$?" -ne 0 ]; then
        echoe "Failed checking secureboot status"
        return 1
    fi

    return 0
}

_setup_dcrypto_directory() {
    echoi "Setting up dcrypto..."
    mkdir -p "$DC_CAKEY" "$DC_KEY" "$DC_CRL" "$DC_GPGHOME"
    chmod 750 -R "$DC_DIR"
    chmod 700 "$DC_KEY" "$DC_CAKEY"
    jq -n '{
        ssl: {
          defaultCA: "",
          keys: {},
          ca: {
            root: {},
            intermediate: {}
        }
        },
          gpg: {
            defaultHome: "",
            defaultKey: "",
            keys: {}
          }
        }' > "$DC_DB"
    chmod 600 "$DC_DB" && chown root:"$DC_USER" "$DC_DB"
    echos "...setup successful"
    return 0
}


_askyesno() {
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
        -h|--help|help|*)
            question=$(printf "%s [y/N]: " "$1")
            default_return=1
            ;;
    esac
    while true; do
        printf "%s" "$question"
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
    printf "\033[1m\033[1;36m>\033[0m\033[1;37m\033[1m %s\033[0m\n" "$1"
}

echov() {
  if [ "$VERBOSE" -eq 1 ]; then
      echoi "$1"
  fi
}
echod() {
  if [ "$DEBUG" -eq 1 ]; then
      printf "\033[1m\033[1;37m> DEBUG:\033[0m %s\n" "$1"
  fi
}
echow() {
    printf "\033[1m\033[1;33m> WARNING:\033[0m\033[1;37m\033[1m %s\033[0m\n" "$1"
}

echowv() {
    if [ "$VERBOSE" -eq 1 ]; then
        echow "$1"
    fi
}

echoe() {
    printf "\033[1m\033[1;31m>>> ERROR:\033[0m\033[1;37m\033[1m %s\033[0m\n" "$1" >&2
}

echos() {
    printf "\033[1m\033[1;32m>>>\033[0m\033[1;37m\033[1m %s\033[0m\n" "$1"
}

echosv() {
  if [ "$VERBOSE" -eq 1 ]; then
      printf "\033[1m\033[1;32m>\033[0m\033[1;37m\033[1m %s\033[0m\n" "$1"
  fi
}

_is_ip() {
    ip="$1"
    if echo "$ip" | grep -E '^((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$' >/dev/null 2>&1; then
        return 0
    elif echo "$ip" | grep -E '^([0-9a-fA-F]{1,4}:){0,7}[0-9a-fA-F]{1,4}(:[0-9a-fA-F]{1,4}){0,7}$|^::1$' >/dev/null 2>&1; then
        return 0
    fi
    return 1
}


_shorthelp() {
  echo ""
  help | sed -n "/  $1/,/^$/p"
}


_reset_dcrypto() {
    ssl="${1:-false}"
    gpg="${2:-false}"
    if _askyesno "Are you sure you want to reset the config and keys?" "n";then
        if _askyesno "Do you want to backup the directory first?" "y"; then
            cp -rf "$DC_DIR" "${DC_DIR}.bkp" 2>/dev/null || {
              echoe "Problem backing up keys and config"
              exit 1
            }
            echos "Backup successful @ /etc/dcrypto.bkp"
        fi
        if [ -n "$ssl" ] && [ "$ssl" = "true" ]; then
            rm -rf "${DC_CA}" "{$DC_CERT}" "${DC_CRL}" 2>/dev/null || {
              echoe "Problem resetting dcrypto ssl"
              exit 1
            }
            mkdir -p "$DC_CAKEY" "$DC_KEY" "$DC_CRL" || {
                echoe "Problem creating ssl directories"
                exit 1
            }
            chmod 750 -R "$DC_DIR"
            chmod 700 "$DC_KEY" "$DC_CAKEY"
            _reset_ssl_index
            echos "Reset of dcrypto SSL successful"
        fi
        if [ -n "$gpg" ] && [ "$gpg" = "true" ]; then
            rm -rf "${DC_GPGHOME}" 2>/dev/null || {
              echoe "Problem resetting dcrypto gpg"
              exit 1
            }
            mkdir -p "$DC_GPGHOME"
            _reset_gpg_index
            echos "Reset of dcrypto GPG successful"
        fi
    else
      echoi "Exiting dcrypto. No harm was done."
      exit 0
    fi
}

# Parses domains & ips from comma separated string
_process_domains() {
    domains_ips="$1"
    orig_args="$*"
    : "${dnsc:=1}"
    : "${ipc:=1}"
    domains_ips=$(printf "%s" "$domains_ips" | sed 's/,/ /g')
    domcount=$(printf "%s" "$domains_ips" | wc -w | tr -d ' ')
    ips=""
    dns=""
    for domain in $domains_ips; do
        if _is_ip "$domain"; then
            ips="${ips}\nIP.$ipc = $domain"
            ipc=$(("$ipc" + 1))
        else
            dns="${dns}\nDNS.$dnsc = $domain"
            dnsc=$(("$dnsc" + 1))
        fi
    done
    set -- "$orig_args"
}

# Creates SSL configuration file
_create_sslconfig() {
    cfg_type="$1"
    domains_ips="$2"
    email="${3:-}"
    country="${4:-}"
    state="${5:-}"
    locality="${6:-}"
    organization="${7:-}"
    orgunit="${8:-}"
    common_name="${9:-}"
    crldistpoints="${10:-}"

    _process_domains "$domains_ips"
    if [ "$cfg_type" = "server" ]; then
        common_name="${domains_ips%% *}"
    elif [ "$cfg_type" = "client" ]; then
        if [ -z "$common_name" ]; then
            common_name="$domains_ips"
        fi
    fi

    DC_SSLCFG=$(cat <<EOF
[ ca ]
default_ca = CA_default

[ CA_default ]
default_md = sha384
default_crl_days = 30
policy = policy_loose

[ policy_loose ]
countryName = optional
stateOrProvinceName = optional
localityName = optional
organizationName = optional
organizationalUnitName = optional
commonName = supplied
emailAddress = optional

[ req ]
default_md = sha384
prompt = no
distinguished_name = req_distinguished_name
EOF
)
    if [ "$cfg_type" = "intca" ] || [ "$cfg_type" = "rootca" ]; then
        DC_SSLCFG="${DC_SSLCFG}\nx509_extensions = v3_ca\n\n"
    elif [ "$cfg_type" = "server" ] || [ "$cfg_type" = "client" ]; then
        DC_SSLCFG="${DC_SSLCFG}\nreq_extensions = req_ext\n\n"
    fi
    DC_SSLCFG="${DC_SSLCFG}[ req_distinguished_name ]\n"

    if [ -n "$country" ]; then
        DC_SSLCFG="${DC_SSLCFG}C = ${country}\n"
    fi
    if [ -n "$state" ]; then
        DC_SSLCFG="${DC_SSLCFG}ST = ${state}\n"
    fi
    if [ -n "$locality" ]; then
        DC_SSLCFG="${DC_SSLCFG}L = ${locality}\n"
    fi
    if [ -n "$organization" ]; then
        DC_SSLCFG="${DC_SSLCFG}O = ${organization}\n"
    fi
    if [ "$cfg_type" = "rootca" ]; then
        if [ -z "$orgunit" ]; then
            DC_SSLCFG="${DC_SSLCFG}OU = Certificate Authority\n"
        else
            DC_SSLCFG="${DC_SSLCFG}OU = ${orgunit}\n"
        fi
        if [ -z "$common_name" ]; then
            DC_SSLCFG="${DC_SSLCFG}CN = $common_name CA\n"
        else
            DC_SSLCFG="${DC_SSLCFG}CN = ${common_name}\n"
        fi

    elif [ "$cfg_type" = "intca" ]; then
        if [ -z "$orgunit" ]; then
            DC_SSLCFG="${DC_SSLCFG}OU = Intermediate Certificate Authority\n"
        else
            DC_SSLCFG="${DC_SSLCFG}OU = ${orgunit}\n"
        fi
        if [ -z "$common_name" ]; then
            DC_SSLCFG="${DC_SSLCFG}CN = $common_name Intermediate CA\n"
        else
            DC_SSLCFG="${DC_SSLCFG}CN = ${common_name}\n"
        fi
    elif [ "$cfg_type" = "server" ] || [ "$cfg_type" = "client" ]; then
        DC_SSLCFG="${DC_SSLCFG}CN = $common_name\n"
    fi
    if [ -n "$email" ]; then
        DC_SSLCFG="${DC_SSLCFG}emailAddress = $email\n"
    fi
    DC_SSLCFG="${DC_SSLCFG}\n"
    if [ "$cfg_type" = "server" ] || [ "$cfg_type" = "client" ]; then
        DC_SSLCFG="${DC_SSLCFG}[ req_ext ]\n"
        DC_SSLCFG="${DC_SSLCFG}subjectKeyIdentifier = hash\n"
        DC_SSLCFG="${DC_SSLCFG}basicConstraints = CA:FALSE\n"
        if [ "$cfg_type" = "server" ]; then
            DC_SSLCFG="${DC_SSLCFG}keyUsage = critical, digitalSignature, keyEncipherment\n"
            DC_SSLCFG="${DC_SSLCFG}extendedKeyUsage = serverAuth\n"
        elif [ "$cfg_type" = "client" ]; then
            DC_SSLCFG="${DC_SSLCFG}keyUsage = critical, digitalSignature\n"
            DC_SSLCFG="${DC_SSLCFG}extendedKeyUsage = clientAuth\n"
        fi
    fi

    if [ "$domcount" -gt 1 ]; then
        DC_SSLCFG="${DC_SSLCFG}subjectAltName = @alt_names\n\n"
        DC_SSLCFG="${DC_SSLCFG}[ alt_names ]$ips$dns\n"
    fi
    if [ "$cfg_type" = "intca" ] || [ "$cfg_type" = "rootca" ]; then
        DC_SSLCFG="${DC_SSLCFG}[ v3_ca ]\n"
        DC_SSLCFG="${DC_SSLCFG}subjectKeyIdentifier = hash\n"
        DC_SSLCFG="${DC_SSLCFG}authorityKeyIdentifier = keyid:always,issuer\n"
        if [ "$cfg_type" = "intca" ]; then
            DC_SSLCFG="${DC_SSLCFG}basicConstraints = critical, CA:TRUE, pathlen:0\n"
        elif [ "$cfg_type" = "rootca" ]; then
            DC_SSLCFG="${DC_SSLCFG}basicConstraints = critical, CA:TRUE\n"
        fi
        DC_SSLCFG="${DC_SSLCFG}keyUsage = critical, digitalSignature, cRLSign, keyCertSign\n"
    fi
    if [ -n "$crldistpoints" ]; then
        DC_SSLCFG="${DC_SSLCFG}\n\ncrlDistributionPoints = URI:$crldistpoints"
    fi
    DC_SSLCFG=$(printf "%b" "$DC_SSLCFG")
}


# Maintenance and utility functions
show_ssl_index() {
    show_keys="${1:-false}"
    show_ca="${2:-false}"
    show_json="${3:-false}"

    if [ "$show_json" = "true" ]; then
        jq '.' "$DC_DB"
        return 0
    fi

    echoi "DCrypto Index Summary"
    echoi "===================="

    # Show default CA
    default_ca=$(jq -r '.ssl.defaultCA // "none"' "$DC_DB")
    echoi "Default CA: $default_ca"
    echoi ""

    if [ "$show_ca" = "true" ] || [ "$show_keys" = "false" ]; then
        echoi "Certificate Authorities:"
        echoi "------------------------"

        # Show root CAs
        echoi "Root CAs:"
        jq -r '.ssl.ca.root | to_entries[] | "  " + .key + ": " + (.value.name // "Unnamed")' "$DC_DB" 2>/dev/null || echo "  None"

        # Show intermediate CAs
        echoi "Intermediate CAs:"
        jq -r '.ssl.ca.intermediate | to_entries[] | "  " + .key + ": " + (.value.name // "Unnamed")' "$DC_DB" 2>/dev/null || echo "  None"
        echoi ""
    fi

    if [ "$show_keys" = "true" ] || [ "$show_ca" = "false" ]; then
        echoi "Keys and Certificates:"
        echoi "----------------------"
        key_count=$(jq -r '.ssl.keys | length' "$DC_DB")
        echoi "Total key entries: $key_count"

        if [ "$VERBOSE" -eq 1 ]; then
            jq -r '.ssl.keys | to_entries[] | "  " + .key + ": " + (.value | to_entries | map(.key + "=" + .value) | join(", "))' "$DC_DB" 2>/dev/null
        fi
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
    echod "     cleanup_index: $cleanup_index"
    echod "  cleanup_orphaned: $cleanup_orphaned"
    echod "   cleanup_backups: $cleanup_backups"
    echod "cleanup_non_ca_keys: $cleanup_non_ca_keys"
    echod "    cleanup_dry_run: $cleanup_dry_run"
    echod "      keep_backups: $keep_backups"
    echod "            DC_DIR: $DC_DIR"
    echod "             DC_DB: $DC_DB"

    echoi "DCrypto Cleanup${cleanup_dry_run:+ (DRY RUN)}"
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
                    rm -f "$file_path" 2>/dev/null || {
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
        rm -f "$tmpfile_orphaned"
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
                            rm -f "$old_backup" 2>/dev/null || {
                                echoe "Failed to remove backup import_file: $old_backup"
                                continue
                            }
                            # Remove from index.json
                            bkp_key=$(jq -r --arg idx "$index" --arg path "$old_backup" '.ssl.keys[$idx] | to_entries[] | select(.value == $path) | .key' "$DC_DB")
                            jq -r "del(.ssl.keys.\"$index\".\"$bkp_key\")" "$DC_DB" > "$DC_DB.tmp" && mv "$DC_DB.tmp" "$DC_DB" 2>/dev/null || {
                                echoe "Failed to update index.json for backup import_file: $old_backup"
                                continue
                            }
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
                    rm -f "$backup_file_path" 2>/dev/null || {
                        echoe "Failed to remove backup import_file: $backup_file_path"
                        continue
                    }
                    echos "Removed backup import_file: $backup_file_path"
                else
                    echov "Dry run: Would remove backup import_file: $backup_file_path"
                fi
            fi
        done
        rm -f "$tmpfile_backups"
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
                rm -f "$key_file" 2>/dev/null || {
                    echoe "Failed to remove non-CA key import_file: $key_file"
                    continue
                }
                # Remove the entire index entry
                jq -r "del(.ssl.keys.\"$index\")" "$DC_DB" > "$DC_DB.tmp" && mv "$DC_DB.tmp" "$DC_DB" 2>/dev/null || {
                    echoe "Failed to update index.json for non-CA key: $key_file"
                    continue
                }
                echos "Removed non-CA key import_file: $key_file"
            else
                echov "Dry run: Would remove non-CA key import_file: $key_file"
            fi
        done
        rm -f "$tmpfile_keys"
        if [ "$found_keys" = "false" ]; then
            echoi "No non-CA key files found"
        fi
        echos "Non-CA key cleanup completed"
    fi

    # Display cleanup completion message
    if [ "$cleanup_dry_run" = "true" ]; then
        echos "DCrypto cleanup completed successfully (DRY RUN)"
    else
        echos "DCrypto cleanup completed successfully"
    fi
    return 0
}


set_default_ca() {
    ca_index="$1"
    ca_type="${2:-root}"

    if [ -z "$ca_index" ]; then
        echoe "CA index is required"
        return 1
    fi

    # Verify CA exists
    ca_cert=$(_get_ca_value "$ca_type" "$ca_index" "cert")
    if [ -z "$ca_cert" ] || [ ! -f "$ca_cert" ]; then
        echoe "CA $ca_type:$ca_index does not exist or cert import_file not found"
        return 1
    fi

    # Set as default
    if jq --arg ca_index "$ca_index" '.ssl.defaultCA = $ca_index' \
        "$DC_DB" > "${DC_DB}.tmp" \
        && mv "${DC_DB}.tmp" "$DC_DB" \
        && chmod 600 "$DC_DB" \
        && chown root:"$DC_USER" "$DC_DB"; then
        :  # Success - do nothing
    else
        echoe "Failed to set default CA"
        return 1
    fi

    echos "Set default CA to: $ca_type:$ca_index"
}


list_certificate_authorities() {
    ca_list_type="${1:-all}"
    verbose="${2:-false}"

    if [ "$verbose" = "false" ] || [ "$VERBOSE" -eq 1 ]; then
        verbose="true"
    fi

    echoi "Certificate Authorities"
    echoi "======================"

    if [ "$ca_list_type" = "all" ] || [ "$ca_list_type" = "root" ]; then
        echoi ""
        echoi "Root CAs:"
        echoi "---------"
        jq -r '.ssl.ca.root | to_entries[] | .key + " | " + (.value.name // "Unnamed") + " | " + (.value.created // "Unknown date")' "$DC_DB" 2>/dev/null | \
        while IFS='|' read -r index name created; do
            printf "  %-12s %-30s %s\n" "$index" "$name" "$created"
            if [ "$verbose" = "true" ]; then
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
            if [ "$verbose" = "true" ]; then
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
            _add_to_ca_database "$type" "$index" "$keyorcert" "$fp"
        done
        echod "Found import files: $import_dir"

    fi

    if ! _ca_with_name_exists "docker"; then
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

        chmod 400 "$server_key_out"
        chmod 444 "$server_cert_out"
    fi



    if [ "$client" = "true" ]; then
        echov "Installing Docker server certificate"
        home_dir="$(eval echo "~${DC_USER}")"
        user_dir="$home_dir/.docker"

        if [ ! -d "$user_dir" ]; then
            mkdir -p "$user_dir"
        fi
        client_key_out="$user_dir/key.pem"
        client_csr_out="$user_dir/cert.csr"
        client_cert_out="$user_dir/cert.pem"

        create_private_key "$client_key_out" "" ""
        create_certificate_signing_request "$client_key_out" "$client_csr_out" "localhost,127.0.0.1" "$client"
        sign_certificate_request "$client_csr_out" "$ca_cert_file" "$ca_key_file" "$client_cert_out"

        chmod 400 "$client_key_out"
        chmod 444 "$client_cert_out"

    fi

}


_key_belongs_to_cert() {
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


_get_file_type() {
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
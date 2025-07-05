# Env vars
RAND="$(od -An -N2 -i /dev/urandom | tr -d ' ' | head -c 4)"


# Creates Password using argon2id kdf
_create_argon2id_derived_key_pw() {
    password="$1"
    salt="$2"

    if [ -f "$salt" ]; then
        salt="$(cat "$salt")"
    elif [ -z "$salt" ]; then
        echoe "Salt or salt import_file not specified"
        return 1
    fi

    if [ -f "$password" ]; then
        password="$(cat "$password")"
    elif [ -z "$password" ]; then
        echoe "Password or password import_file not specified"
        return 1
    fi

    # Check the exit status of the pipeline
    if openssl kdf \
        -keylen 32 \
        -kdfopt password:"$password" \
        -kdfopt salt:"$salt" \
        -kdfopt memcost:"131072" \
        -kdfopt early_clean:1 \
        -kdfopt lanes:"$(nproc)" ARGON2ID 2>/dev/null | \
        tr -d ':\n '; then
        return 0
    else
        echoe "Failed to generate Argon2id key"
        return 1
    fi
}


create_private_key() {
    out_file="$1"
    password="$2"
    salt_out="$3"
    import_dir="$(realpath "$out_file" | awk -F/ '{NF--; print}' OFS=/)"
    no_argon="$4"
    nodb=0

    echod "Starting create_private_key with parameters:"
    echod "  out_file: $out_file"
    echod "  password: $([ -n "$password" ] && echo "[SET]" || echo "[EMPTY]")"
    echod "  import_dir: $import_dir"
    echod "  user: $DC_USER"

    # Check if password is import_file
    if [ -f "$password" ]; then
        echov "Reading password from import_file: $password"
        password="$(cat "$password")"
        if [ "$no_argon" = "false" ]; then
            salt_out="${3:-"$import_dir/${out_file%*.*}.salt"}"
            echod "Salt output path: $salt_out"
        fi
    elif [ -n "$password" ] ; then
        echov "Using provided password for encryption"
        if [ "$no_argon" = "false" ]; then
            salt_out="${3:-"$import_dir/${out_file%*.*}.salt"}"
            echod "Salt output path: $salt_out"
        fi
    else
        echov "Creating unencrypted private key"
    fi

    # Check if out or salt import_file already exist
    if [ -f "$out_file" ]; then
        echod "Output import_file already exists, generating new name"
        echov "Key or salt on out path already exist. Changing name to... "
        out_file="${out_file%.pem}-${RAND}.${out_file##*.}"
        echod "New output import_file: $out_file"
        if [ -n "$password" ] && [ "$no_argon" = "false" ]; then
            salt_out="${out_file%.salt}.${salt_out##*.}"
            if [ -f "$salt_out" ]; then
                salt_out="${salt_out%.salt}-${RAND}.${salt_out##*.}"
                echov "Salt import_file renamed to: $(basename "$salt_out")"
            fi
        fi
    fi

    if echo "$out_file" | grep -qE "ca-key"; then
        nodb=1
    fi

    # Generate key without and with encryption
    if [ -z "$password" ]; then
        echov "Generating secp384r1 private key..."
        (
            openssl ecparam -genkey -name secp384r1 -out "$out_file" -outform PEM 2>/dev/null || {
                echoe "Failed to generate private key"
                return 1
            }
            echod "Private key generated successfully"

            chmod 400 "$out_file" 2>/dev/null || {
                echoe "Failed to set permissions on $out_file"
                return 1
            }
            echov "Set permissions (400) on key import_file"

            chown root:"${DC_USER}" "$out_file" 2>/dev/null || {
                echoe "Failed to set owner on $out_file"
                return 1
            }
            echov "Set owner (root:${DC_USER}) on key import_file"
            if [ "$nodb" -eq 0 ]; then
                echod "Adding key to SSL index with RAND: $RAND"
                _add_to_ssl_keys_database "$RAND" "key" "$out_file"
            fi
         )
    else
        echov "Generating encrypted secp384r1 private key..."
        (

            if [ -z "$no_argon" ]; then
                # Generate salt and save it
                echov "Generating cryptographic salt..."
                salt_value="$(openssl rand -hex 32)"
                echo "$salt_value" > "$salt_out"
                echod "Salt generated and saved to $salt_out"

                echov "Encrypting with Argon2id-derived key..."
                # Use Argon2id-derived key with password: prefix (the method that works)
                if ! _create_argon2id_derived_key_pw "$password" "$salt_value" | openssl genpkey \
                    -algorithm EC \
                    -pkeyopt ec_paramgen_curve:secp384r1 \
                    -aes-256-cbc \
                    -password stdin \
                    -out "$out_file" >/dev/null 2>&1; then
                    echoe "Failed to generate encrypted private key with Argon2id"
                    return 1
                fi
                echod "Encrypted private key generated with Argon2id"
                echov "Validating generated private key..."
                if ! _create_argon2id_derived_key_pw "$password" "$salt_value" | openssl ec \
                    -in "$out_file" \
                    -check \
                    -noout \
                    -passin stdin \
                      >/dev/null 2>&1; then
                    echoe "'$out_file' is not a valid private key"
                    return 1
                fi
                echod "Private key validation successful"
            elif [ -n "$no_argon" ] && [ "$no_argon" = "true" ]; then
                echov "Encrypting with pbkdf2 key..."
                if ! printf "%s" "$password" | openssl genpkey \
                    -algorithm EC \
                    -pkeyopt ec_paramgen_curve:secp384r1 \
                    -aes-256-cbc \
                    -password stdin \
                    -out "$out_file" >/dev/null 2>&1; then
                          echoe "Failed to generate encrypted private key with Argon2id"
                          return 1
                fi
                echod "Encrypted private key generated with pbkdf2"
                echov "Validating generated private key..."
                # Decrypt and verify the private key
                if ! printf "%s" "$password" | openssl ec \
                    -check \
                    -passin stdin \
                    -in "$out_file" >/dev/null 2>&1 ; then
                    echoe "Failed to validate encrypted private key: decryption or key check failed"
                    return 1
                fi
                echod "Private key validation successful"
            fi

            chmod 400 "$out_file" 2>/dev/null || {
                echoe "Failed to set permissions on $salt_out or $out_file"
                return 1
            }
            echov "Set permissions (400) on key files"

            chown root:"${DC_USER}" "$out_file" 2>/dev/null || {
                echoe "Failed to set owner on $out_file"
                return 1
            }
            echov "Set owner (root:${DC_USER}) on key files"

            # Prevent from writing to database
            if [ "$nodb" -eq 0 ]; then
                echod "Adding salt and key to SSL index with RAND: $RAND"
                _add_to_ssl_keys_database "$RAND" "key" "$out_file"
            fi

            if [ -n "$salt_out" ]; then
                chmod 400 "$out_file" 2>/dev/null || {
                echoe "Failed to set permissions on $salt_out"
                return 1
                }
                echov "Set permissions (400) on salt files"

                chown root:"${DC_USER}" "$salt_out" 2>/dev/null || {
                    echoe "Failed to set owner on $salt_out"
                    return 1
                }
                echov "Set owner (root:${DC_USER}) on salt files"
                if [ "$nodb" -eq 0 ]; then
                    echod "Adding salt and key to SSL index with RAND: $RAND"
                    _add_to_ssl_keys_database "$RAND" "salt" "$salt_out"
                fi
            fi
        )
    fi
    status=$?
    echod "Private key creation subprocess exited with status: $status"

    if [ "$status" -eq 0 ] && [ -n "$out_file" ]; then
        echod "Private key creation completed successfully"
        echos "Created private key ${out_file}"
        return 0
    elif [ "$status" -ne 0 ]; then
        echod "Private key creation failed with status: $status"
        echoe "Private key creation failed"
        _shorthelp "ssl create-key"
        exit 1
    fi
}

create_certificate_signing_request() {
    key_file="$1"
    csr_outfile="$2"
    domains="$3"
    client="$4"
    server="$5"
    email="$6"
    password="$7"
    country="$8"
    state="$9"
    locality="${10}"
    organization="${11}"
    orgunit="${12}"
    crldist="${13}"

    echod "Starting create_certificate_signing_request with parameters:"
    echod "      key_file: $key_file"
    echod "   csr_outfile: $csr_outfile"
    echod "       domains: $domains"
    echod "        client: $client"
    echod "        server: $server"
    echod "         email: $email"
    echod "      password: $password"
    echod "       country: $country"
    echod "         state: $state"
    echod "      locality: $locality"
    echod "  organization: $organization"
    echod "       orgunit: $orgunit"
    echod "       crldist: $crldist"
    echod "          user: $DC_USER"

    echoi "Validating input parameters"
    # Validate required parameters
    if [ "$server" = "true" ] && [ "$client" = "true" ]; then
        echoe "--server and --client can't be set at the same time"
        return 1
    elif [ -z "$server" ] && [ -z "$client" ]; then
        echov "Neither server nor client specified, defaulting to client"
        client="true"
    fi

    if [ -z "$domains" ]; then
        echoe "Domains parameter is required"
        return 1
    fi

    if [ ! -f "$key_file" ]; then
        echoe "Key import_file $key_file does not exist"
        return 1
    fi
    echos "Domains parameter and key import_file validated successfully"

    key_file="$(realpath "$key_file")"
    # Get key import_file directory and base name
    key_dir="$(dirpath "$key_file")"
    key_basename="$(basename "$key_file")"
    key_name="${key_basename%.*}"  # Remove extension
    echod "Parsed key import_file details: directory=$key_dir, basename=$key_basename, name=$key_name"

    # Determine output directory - use key directory unless it's in /etc/dcrypto/
    if echo "$key_file" | grep -q "^/etc/dcrypto/"; then
        # Key is in dcrypto directory, use standard dcrypto private directory
        output_dir="$DC_KEY"
        echov "Key import_file in /etc/dcrypto/, setting output directory to $DC_KEY"
    else
        # Key is outside dcrypto directory, use same directory as key
        output_dir="$key_dir"
        echov "Key import_file outside /etc/dcrypto/, setting output directory to $key_dir"
    fi
    echod "Output directory set to: $output_dir"

    # Generate CSR filename based on key filename if not provided
    if [ -z "$csr_outfile" ]; then
        csr_outfile="${output_dir}/${key_name}.csr"
        echowv "Generated CSR filename based on key filename: $csr_outfile"
    else
        echod "Using provided CSR filename: $csr_outfile"
    fi

    # Set defaults based on type if not provided
    if [ "$server" = "true" ]; then
        key_file="${key_file:-"$DC_KEY/server-key.pem"}"
        csr_outfile="${csr_outfile:-"$DC_KEY/server.csr"}"
        type="server"
        echov "Server mode selected, using key_file=$key_file, csr_outfile=$csr_outfile"
    elif [ "$client" = "true" ]; then
        key_file="${key_file:-"$DC_KEY/key.pem"}"
        type="client"
        echov "Client mode selected, using key_file=$key_file"
    fi
    echod "Certificate type set to: $type"

    # Get index from key import_file
    echoi "Checking SSL keys index for key import_file"
    index=$(_find_index_by_key_value "key" "$key_file")
    echod "Index lookup result: $index"

    if [ -f "$key_file" ] && [ -z "$index" ]; then
        echowv "Key not found in database. Recreating index for import_file."
        _add_to_ssl_keys_database "$RAND" "key" "$key_file"
        index=$(_find_index_by_key_value "key" "$key_file")
        echod "New index created: $index"
    fi

    # Create SSL config if not already created
    if [ -z "$DC_SSLCFG" ]; then
        echoi "Creating SSL configuration for $type certificate"
        _create_sslconfig "$type" "$domains" "$email" "$country" \
          "$state" "$locality" "$organization" "$orgunit" "" "$crldist"
        echosv "SSL configuration generated successfully"

        # Create config import_file in output directory with same base name as key
        config_file="${output_dir}/${key_name}.conf"
        echod "Writing SSL configuration to: $config_file"
        echo "$DC_SSLCFG" > "$config_file"

        # Set proper permissions and ownership
        echov "Setting permissions on config import_file: $config_file"
        chmod 644 "$config_file" 2>/dev/null || {
            echoe "Failed to set permissions on config import_file"
            return 1
        }
        echod "Config import_file permissions set to 644"

        # Try to set ownership to current user if running as root
        if [ "$(id -u)" -eq 0 ]; then
            echov "Running as root, attempting to set ownership to root:$DC_USER"
            chown root:"$DC_USER" "$config_file" 2>/dev/null || {
                echow "Could not set ownership on config import_file"
            }
            echosv "Config import_file ownership set successfully"
        fi
    fi
    echod "Config import_file in use: $config_file"

    _add_to_ssl_keys_database "$index" "cfg" "$config_file"
    echod "Added config import_file to SSL keys index at index $index"

    # In case user wants to keep csr import_file after signing
    if [ -f "$csr_outfile" ]; then
        echow "CSR import_file already exists. Backing up old one..."
        _backup_and_rename "csr" "$index" "$csr_outfile" || {
            echoe "Failed to backup existing CSR import_file"
            return 1
        }
        echov "Existing CSR import_file backed up successfully"
    fi

    _add_to_ssl_keys_database "$index" "csr" "$csr_outfile"
    echod "Added CSR import_file to SSL keys, index at index $index"

    # Create output directory if it doesn't exist
    if [ ! -d "$output_dir" ]; then
        echov "Creating output directory: $output_dir"
        mkdir -p "$output_dir" || {
            echoe "Failed to create directory '$output_dir'"
            return 1
        }
        echov "Output directory created successfully"
    fi

    # Final check that config import_file exists and is readable
    if [ ! -f "$config_file" ] || [ ! -r "$config_file" ]; then
        echoe "Config import_file $config_file does not exist or is not readable"
        return 1
    fi
    echod "Config import_file $config_file exists and is readable"

    echoi "Generating Certificate Signing Request"
    (
        # Handle encrypted private key if password is provided
        if [ -n "$password" ]; then
            echov "Password provided, handling encrypted private key"
            # Generate derived key from password and salt
            salt_file="$(_get_ssl_keys_key_value "$index" "salt")"
            echod "Salt import_file: $salt_file"

            if [ ! -f "$salt_file" ]; then
                echoe "Salt import_file $salt_file does not exist"
                return 1
            fi

            # Get password content
            if [ -f "$password" ]; then
                echov "Reading password from import_file: $password"
                pass_content="$(cat "$password")"
            else
                echov "Using provided password directly"
                pass_content="$password"
            fi
            echod "Password content retrieved"

            # Get salt content
            echov "Reading salt from import_file: $salt_file for derived key generation"
            salt_content="$(cat "$salt_file")"
            echod "Salt content retrieved"

            # Generate derived key
            echov "Generating Argon2id derived key"
            derived_key="$(_create_argon2id_derived_key_pw "$pass_content" "$salt_content")"
            echod "Derived key: $derived_key"

            if [ -n "$derived_key" ] && echo "$derived_key" | grep -q '^[0-9a-fA-F]\{64\}$'; then
                echov "Using Argon2id derived key for CSR generation"
                openssl req -new -key "$key_file" -out "$csr_outfile" \
                    -config "$config_file" \
                    -passin "password:$derived_key" \
                    2>/dev/null || {
                    echoe "Failed to generate CSR (with Argon2 derived key)"
                    return 1
                }
                echov "CSR generated successfully with Argon2 derived key"
            else
                echow "Argon2id key derivation failed, using original password"
                echo "$pass_content" | openssl req -new -key "$key_file" -out "$csr_outfile" \
                    -config "$config_file" -passin stdin 2>/dev/null || {
                    echoe "Failed to generate CSR (with original password)"
                    return 1
                }
                echov "CSR generated successfully with original password"
            fi
        else
            echov "No password provided, generating CSR without password"
            openssl req -new -key "$key_file" -out "$csr_outfile" \
                -config "$config_file" 2>/dev/null || {
                echoe "Failed to generate CSR"
                return 1
            }
            echov "CSR generated successfully without password"
        fi

        # Set permissions
        echov "Setting permissions on CSR import_file: $csr_outfile"
        chmod 644 "$csr_outfile" 2>/dev/null || {
            echoe "Failed to set permissions on $csr_outfile"
            return 1
        }
        echov "CSR import_file permissions set to 644"

        # Add CSR to index
        _add_to_ssl_keys_database "$index" "csr" "$csr_outfile"
        echod "Updated SSL keys index with CSR: $csr_outfile"
    )
    status=$?
    if [ "$status" -eq 0 ]; then
        echov "Created Certificate Signing Request: ${csr_outfile}"
        return 0
    else
        echoe "Creating certificate signing request failed."
        return 1
    fi
}

create_cert_chain() {
    cert_file="${1:-"$DC_CERT/cert.pem"}"
    ca_file="${2:-"$DC_CA/ca.pem"}"
    chain_outfile="${3:-"$DC_CERT/fullchain.pem"}"
    index="${4:-}"

    # Validate input files exist
    if [ ! -f "$cert_file" ]; then
        echoe "Certificate import_file '$cert_file' does not exist"
        return 1
    fi

    if [ ! -f "$ca_file" ]; then
        echoe "CA import_file '$ca_file' does not exist"
        return 1
    fi

    # Validate files are actually certificates
    if ! openssl x509 -in "$cert_file" -noout -text >/dev/null 2>&1; then
        echoe "'$cert_file' is not a valid certificate"
        return 1
    fi

    if ! openssl x509 -in "$ca_file" -noout -text >/dev/null 2>&1; then
        echoe "'$ca_file' is not a valid certificate"
        return 1
    fi

    # Create output directory if it doesn't exist
    chain_dir="$(dirpath "$chain_outfile")"
    if [ ! -d "$chain_dir" ]; then
        mkdir -p "$chain_dir" || {
            echoe "Failed to create directory '$chain_dir'"
            return 1
        }
    fi

    # Backup existing chain import_file if it exists
    if [ -f "$chain_outfile" ]; then
        backup_file="${chain_outfile%.*}-backup-$(date +%Y%m%d-%H%M%S).${chain_outfile##*.}"
        cp "$chain_outfile" "$backup_file" || {
            echo "Warning: Failed to backup existing chain import_file"
        }
        echo "Existing chain import_file backed up as: $backup_file"
    fi

    # Create fullchain cert (cert first, then CA)
    {
        cat "$cert_file" || {
            echoe "Failed to read certificate import_file"
            return 1
        }
        echo
        cat "$ca_file" || {
            echoe "Failed to read CA import_file"
            return 1
        }
    } > "$chain_outfile" || {
        echoe "Failed to create certificate chain"
        return 1
    }

    # Set appropriate permissions
    chmod 644 "$chain_outfile" || {
        echoe "Failed to set permissions on '$chain_outfile'"
        return 1
    }

    # Verify the chain is valid
    if ! openssl verify -CAfile "$ca_file" "$cert_file" >/dev/null 2>&1; then
        echo "Warning: Certificate chain may not be valid - verification failed"
    fi

    # Add to index if index parameter provided
    if [ -n "$index" ]; then
        _add_to_ssl_keys_database "$index" "fullchain" "$chain_outfile" || {
            echo "Warning: Failed to add chain import_file to index"
        }
    fi

    echo "Certificate chain created successfully: $chain_outfile"

    # Display chain info
    echo "Chain contains:"
    openssl crl2pkcs7 -nocrl -certfile "$chain_outfile" | \
        openssl pkcs7 -print_certs -noout | \
        grep "subject=" | \
        sed 's/subject=/  - /' 2>/dev/null || true

    return 0
}


create_certificate_revocation_list() {
    ca_key_file="$1"
    ca_cert_file="$2"
    crl_outfile="$3"
    ca_pass="$4"
    crl_days="$5"

    # Check for default CA in index.json if CA files not provided
    default_ca=""
    if [ -z "$ca_cert_file" ] || [ -z "$ca_key_file" ]; then
        default_ca=$(jq -r '.ssl.defaultCA // empty' "$DC_DB")
        if [ -n "$default_ca" ] && [ "$default_ca" != "null" ]; then
            echov "Using default CA: $default_ca"
            # Get CA files from the default CA entry
            ca_cert_file="${ca_cert_file:-$(_get_storage "ca" "$default_ca" | jq -r '.cert // empty')}"
            ca_key_file="${ca_key_file:-$(_get_storage "ca" "$default_ca" | jq -r '.key // empty')}"
        fi
    fi

    # Validate required files exist
    if [ ! -f "$ca_key_file" ]; then
        echoe "CA private key import_file '$ca_key_file' does not exist"
        if [ -n "$default_ca" ]; then
            echoe "Check if default CA '$default_ca' is properly configured"
        fi
        return 1
    fi

    if [ ! -f "$ca_cert_file" ]; then
        echoe "CA certificate import_file '$ca_cert_file' does not exist"
        if [ -n "$default_ca" ]; then
            echoe "Check if default CA '$default_ca' is properly configured"
        fi
        return 1
    fi

    # Validate CA certificate
    if ! openssl x509 -in "$ca_cert_file" -noout -text >/dev/null 2>&1; then
        echoe "'$ca_cert_file' is not a valid CA certificate"
        return 1
    fi

    # Validate CA private key
    if ! openssl rsa -in "$ca_key_file" -check -noout >/dev/null 2>&1 && \
       ! openssl ec -in "$ca_key_file" -check -noout >/dev/null 2>&1; then
        echoe "'$ca_key_file' is not a valid private key"
        return 1
    fi

    # Create CRL output directory if it doesn't exist
    crl_dir="$(dirpath "$crl_outfile")"
    if [ ! -d "$crl_dir" ]; then
        mkdir -p "$crl_dir" || {
            echoe "Failed to create directory '$crl_dir'"
            return 1
        }
    fi

    # Get or create CA index for tracking certificates
    ca_index=$(_find_index_by_key_value "cert" "$ca_cert_file")
    if [ -z "$ca_index" ]; then
        ca_index=$(_find_index_by_key_value "key" "$ca_key_file")
        if [ -z "$ca_index" ]; then
            echoe "Can't find CA index: $ca_index"
        fi
    fi

    # Handle import_file naming like create_private_key does
    if [ -f "$crl_outfile" ]; then
        echo "CRL import_file already exists. Changing name to... "
        crl_outfile="${crl_outfile%.*}-${RAND}.${crl_outfile##*.}"
        basename "$crl_outfile"
    fi


    # Determine config import_file to use - following create_certificate_signing_request pattern
    config_file=""

    # First check if config already exists in index
    config_file=$(_get_ssl_keys_key_value "$ca_index" "cfg")

    # Create SSL config only if no existing config found and DC_SSLCFG is empty
    if [ -z "$config_file" ] || [ ! -f "$config_file" ]; then
        if [ -z "$DC_SSLCFG" ]; then
            # Extract CA subject for config generation
            ca_subject=$(openssl x509 -in "$ca_cert_file" -noout -subject | sed 's/subject=//')
            ca_cn=$(echo "$ca_subject" | sed -n 's/.*CN=\([^,]*\).*/\1/p' | sed 's/^ *//;s/ *$//')

            _create_sslconfig "rootca" "$ca_cn" "" "" "" "" "" "" "$ca_cn" ""
        fi

        # Create temporary config import_file and add to index
        config_file="$DC_KEY/crl-${ca_index}.conf"
        echo "$DC_SSLCFG" > "$config_file"
        chmod 400 "$config_file"
    fi

    # In case user wants to keep cfg import_file after CRL generation
    if [ -n "$config_file" ] && [ -f "$config_file" ]; then
        echo "Config import_file already exists. Backing up old one..."
        _backup_and_rename "cfg" "$ca_index" "$config_file" || {
            echoe "Failed to backup existing config import_file"
            return 1
        }
    fi

    _add_to_ssl_keys_database "$ca_index" "cfg" "$config_file"

    # Initialize OpenSSL CA database files if they don't exist
    index_txt="$DC_DIR/index.txt"
    crlnumber_file="$DC_DIR/crlnumber"
    newcerts_dir="$DC_DIR/newcerts"

    if [ ! -f "$index_txt" ]; then
        touch "$index_txt"
        chmod 600 "$index_txt"
    fi

    if [ ! -f "$crlnumber_file" ]; then
        echo "01" > "$crlnumber_file"
        chmod 600 "$crlnumber_file"
    fi

    if [ ! -d "$newcerts_dir" ]; then
        mkdir -p "$newcerts_dir"
        chmod 700 "$newcerts_dir"
    fi

    # Generate the CRL - following create_certificate_signing_request pattern
    echo "Generating Certificate Revocation List..."
    echo "CA Certificate: $ca_cert_file"
    echo "CA Private Key: $ca_key_file"
    echo "Output CRL: $crl_outfile"
    echo "Valid for: $crl_days days"

    (
        # Handle encrypted private key if password is provided - same pattern as create_certificate_signing_request
        if [ -n "$ca_pass" ]; then

            salt_file="$(_get_ssl_keys_key_value "$ca_index" "salt")"

            if [ ! -f "$salt_file" ]; then
                echoe "Salt import_file $salt_file does not exist"
                rm -f "$config_file"
                return 1
            fi

            # Get password content
            if [ -f "$ca_pass" ]; then
                ca_pass_content="$(cat "$ca_pass")"
            else
                ca_pass_content="$ca_pass"
            fi

            # Generate derived key for decryption
            _create_argon2id_derived_key_pw "$ca_pass_content" "$salt_file" | \
                openssl ca -gencrl \
                    -keyfile "$ca_key_file" \
                    -cert "$ca_cert_file" \
                    -out "$crl_outfile" \
                    -config "$config_file" \
                    -passin "stdin" 2>/dev/null || {
                echoe "Failed to generate CRL (with encrypted key)"
                rm -f "$config_file"
                return 1
            }
        else
            # Generate CRL without password
            openssl ca -gencrl \
                -keyfile "$ca_key_file" \
                -cert "$ca_cert_file" \
                -out "$crl_outfile" \
                -config "$config_file" 2>/dev/null || {
                echoe "Failed to generate CRL"
                rm -f "$config_file"
                return 1
            }
        fi

        # Set permissions
        chmod 644 "$crl_outfile" 2>/dev/null || {
            echoe "Failed to set permissions on $crl_outfile"
            rm -f "$config_file"
            return 1
        }

        # Add CRL to index
        _add_to_ssl_keys_database "$ca_index" "crl" "$crl_outfile"

        # Verify the generated CRL
        if openssl crl -in "$crl_outfile" -noout -text >/dev/null 2>&1; then
            echo "✓ CRL generated and verified successfully"
        else
            echo "Warning: CRL was generated but verification failed"
        fi

        # Display CRL information
        echo ""
        echo "CRL Details:"
        crl_issuer=$(openssl crl -in "$crl_outfile" -noout -issuer | sed 's/issuer=//')
        echo "  Issuer: $crl_issuer"
        openssl crl -in "$crl_outfile" -noout -lastupdate -nextupdate | sed 's/^/  /'

        # Count revoked certificates
        revoked_count=$(openssl crl -in "$crl_outfile" -noout -text | grep -c "Serial Number:" || echo "0")
        echo "  Revoked Certificates: $revoked_count"

        echo ""
        echo "Certificate Revocation List generated successfully!"

        return 0
    )

    return $?
}


revoke_certificate() {
    cert_file="$1"
    ca_key_file="$2"
    ca_cert_file="$3"
    ca_pass="$4"
    reason="$5"

    # Check for default CA in index.json if CA files not provided
    default_ca=""
    if [ -z "$ca_cert_file" ] || [ -z "$ca_key_file" ]; then
        default_ca=$(jq -r '.ssl.defaultCA // empty' "$DC_DB")
        if [ -n "$default_ca" ] && [ "$default_ca" != "null" ]; then
            echov "Using default CA: $default_ca"
            ca_cert_file="${ca_cert_file:-$(_get_storage "ca" "$default_ca" | jq -r '.cert // empty')}"
            ca_key_file="${ca_key_file:-$(_get_storage "ca" "$default_ca" | jq -r '.key // empty')}"
        fi
    fi

    # Set defaults
    ca_key_file="${ca_key_file:-"$DC_CA/ca-key.pem"}"
    ca_cert_file="${ca_cert_file:-"$DC_CA/ca.pem"}"

    # Validate inputs
    if [ ! -f "$cert_file" ]; then
        echoe "Certificate import_file '$cert_file' does not exist"
        return 1
    fi

    if [ ! -f "$ca_key_file" ] || [ ! -f "$ca_cert_file" ]; then
        echoe "CA key or certificate does not exist"
        return 1
    fi

    # Find CA index and config
    ca_index=$(_find_index_by_key_value "cert" "$ca_cert_file")
    if [ -z "$ca_index" ]; then
        ca_index=$(_find_index_by_key_value "key" "$ca_key_file")
    fi

    # Look for existing config files
    config_file=$(_get_ssl_keys_key_value "$ca_index" "cfg")

    if [ -z "$config_file" ] || [ ! -f "$config_file" ]; then
        echoe "No CA config import_file found for revocation"
        echo "Run create-crl first to generate the necessary config"
        return 1
    fi

    echo "Revoking certificate: $cert_file"
    echo "Reason: $reason"

    # Revoke the certificate - following create_certificate_signing_request password pattern
    (
        if [ -n "$ca_pass" ]; then

            salt_file="$(_get_ssl_keys_key_value "$ca_index" "salt")"

            if [ ! -f "$salt_file" ]; then
                echoe "Salt import_file $salt_file does not exist"
                return 1
            fi

            # Get password content
            if [ -f "$ca_pass" ]; then
                ca_pass_content="$(cat "$ca_pass")"
            else
                ca_pass_content="$ca_pass"
            fi

            # Generate derived key for decryption
            _create_argon2id_derived_key_pw "$ca_pass_content" "$salt_file" | \
                openssl ca -revoke "$cert_file" \
                    -keyfile "$ca_key_file" \
                    -cert "$ca_cert_file" \
                    -config "$config_file" \
                    -crl_reason "$reason" \
                    -passin "stdin" 2>/dev/null || {
                echoe "Failed to revoke certificate (with encrypted key)"
                return 1
            }
        else
            # Revoke certificate without password
            openssl ca -revoke "$cert_file" \
                -keyfile "$ca_key_file" \
                -cert "$ca_cert_file" \
                -config "$config_file" \
                -crl_reason "$reason" 2>/dev/null || {
                echoe "Failed to revoke certificate"
                return 1
            }
        fi

        return 0
    )
    status=$?
    if [ "$status" -eq 0 ]; then
        echos "Certificate revoked successfully"
        echov "Remember to regenerate the CRL to publish this revocation"
        return 0
    else
        echoe "Certificate revoke failed"
        return 1
    fi
}

verify_certificate() {
    cert_file="$1"
    ca_cert="$2"
    cert_chain="$3"
    check_expiry="$4"
    verbose="$5"

    # shellcheck disable=SC2153
    if [ "$VERBOSE" -eq 1 ] || [ "$verbose" = "true" ]; then
        verbose="true"
    fi
    # Validate input files exist
    if [ ! -f "$cert_file" ]; then
        echoe "Certificate import_file '$cert_file' does not exist"
        return 1
    fi

    if [ ! -f "$ca_cert" ]; then
        echoe "CA certificate import_file '$ca_cert' does not exist"
        return 1
    fi

    # Validate files are actually certificates
    if ! openssl x509 -in "$cert_file" -noout -text >/dev/null 2>&1; then
        echoe "'$cert_file' is not a valid certificate"
        return 1
    fi

    if ! openssl x509 -in "$ca_cert" -noout -text >/dev/null 2>&1; then
        echoe "'$ca_cert' is not a valid CA certificate"
        return 1
    fi

    # Get certificate details for reporting
    cert_subject=$(openssl x509 -in "$cert_file" -noout -subject | sed 's/subject=//')
    cert_issuer=$(openssl x509 -in "$cert_file" -noout -issuer | sed 's/issuer=//')
    ca_subject=$(openssl x509 -in "$ca_cert" -noout -subject | sed 's/subject=//')

    # Check if certificate is expired or will expire soon
    if [ "$check_expiry" = "true" ]; then
        if ! openssl x509 -in "$cert_file" -noout -checkend 0 >/dev/null 2>&1; then
            echow "Certificate '$cert_file' has expired"
        elif ! openssl x509 -in "$cert_file" -noout -checkend 2592000 >/dev/null 2>&1; then
            echow "Certificate '$cert_file' expires within 30 days"
        fi
    fi

    # Verify certificate chain
    verification_output=$(openssl verify -CAfile "$ca_cert" "$cert_file" 2>&1)
    verification_result=$?

    if [ $verification_result -eq 0 ]; then
        echosv "Certificate verification successful: $cert_file"

        if [ "$verbose" = "true" ]; then
            echov ""
            echov "Certificate Details:"
            echov "  Subject: $cert_subject"
            echov "  Issuer:  $cert_issuer"
            echov "  CA Subject: $ca_subject"
            echov ""

            # Show validity dates
            echov "Validity Period:"
            openssl x509 -in "$cert_file" -noout -dates | sed 's/^/  /'
            echov ""

            # Show SAN if present
            san=$(openssl x509 -in "$cert_file" -noout -ext subjectAltName 2>/dev/null | grep -A1 "Subject Alternative Name" | tail -n1)
            if [ -n "$san" ]; then
                echov "Subject Alternative Names:"
                echov "  $san"
                echov ""
            fi

            # Show key usage
            key_usage=$(openssl x509 -in "$cert_file" -noout -ext keyUsage 2>/dev/null | grep -A1 "Key Usage" | tail -n1)
            if [ -n "$key_usage" ]; then
                echov "Key Usage:"
                echov "  $key_usage"
                echov ""
            fi

            # Show extended key usage
            ext_key_usage=$(openssl x509 -in "$cert_file" -noout -ext extendedKeyUsage 2>/dev/null | grep -A1 "Extended Key Usage" | tail -n1)
            if [ -n "$ext_key_usage" ]; then
                echov "Extended Key Usage:"
                echov "  $ext_key_usage"
                echov ""
            fi
        fi

        return 0
    else
        echow "Certificate verification failed: $cert_file"
        echow "Error details: $verification_output"

        # Try to provide more specific error information
        if echow "$verification_output" | grep -q "certificate signature failure"; then
            echow "The certificate was not signed by the provided CA"
        elif echow "$verification_output" | grep -q "certificate has expired"; then
            echow "The certificate has expired"
        elif echow "$verification_output" | grep -q "certificate is not yet valid"; then
            echow "The certificate is not yet valid (future date)"
        fi

        if [ "$verbose" = "true" ]; then
            echov ""
            echowv "Certificate Subject: $cert_subject"
            echowv "Certificate Issuer:  $cert_issuer"
            echowv "CA Subject:          $ca_subject"
        fi

        return 1
    fi
}

# Helper function for batch verification
verify_certificate_chain() {
    cert_file="$1"
    intermediate_ca="$2"
    root_ca="$3"
    verbose="$4"

    if [ "$VERBOSE" -eq 1 ] || [ "$verbose" = "true" ]; then
        verbose="true"
    fi

    if [ -z "$cert_file" ] || [ -z "$root_ca" ]; then
        echoe "Certificate and root CA are required"
        return 1
    fi

    echo "Verifying certificate chain for: $cert_file"
    echo ""

    if [ -n "$intermediate_ca" ] && [ -f "$intermediate_ca" ]; then
        # Create temporary CA bundle
        ca_bundle="/tmp/ca-bundle-$$.pem"
        cat "$intermediate_ca" "$root_ca" > "$ca_bundle" || {
            echoe "Failed to create CA bundle"
            return 1
        }

        # Verify with intermediate CA
        result=$(verify_certificate "$cert_file" "$ca_bundle" "$verbose" true)
        verify_result=$?

        # Cleanup
        rm -f "$ca_bundle"

        echo "$result"
        return $verify_result
    else
        # Direct verification with root CA
        verify_certificate "$cert_file" "$root_ca" "$verbose" true
        return $?
    fi
}

sign_certificate_request() {
    csr_file="$1"
    ca_cert_file="$2"
    ca_key_file="$3"
    cert_outfile="$4"
    ca_pass="$5"
    validity_days="$6"
    keep_csr="$7"
    keep_cfg="$8"

    echod "Starting sign_certificate_request with parameters:"
    echod "      csr_file: $csr_file"
    echod "  ca_cert_file: $ca_cert_file"
    echod "   ca_key_file: $ca_key_file"
    echod "  cert_outfile: $cert_outfile"
    echod "       ca_pass: $ca_pass"
    echod " validity_days: $validity_days"
    echod "      keep_csr: $keep_csr"
    echod "      keep_cfg: $keep_cfg"
    echod "          user: $DC_USER"

    echoi "Checking for default CA in index.json"
    # Check for default CA in index.json if CA files not provided
    default_ca=""
    if [ -z "$ca_cert_file" ] || [ -z "$ca_key_file" ]; then
        default_ca=$(jq -r '.ssl.defaultCA // empty' "$DC_DB")
        if [ -n "$default_ca" ] && [ "$default_ca" != "null" ]; then
            echoi "Using default CA: $default_ca"
            # Get CA files from the default CA entry, stripping quotes
            ca_cert_file="${ca_cert_file:-$(_get_storage "ca" "$default_ca" | jq -r '.cert // empty' | sed 's/^"\(.*\)"$/\1/')}"
            ca_key_file="${ca_key_file:-$(_get_storage "ca" "$default_ca" | jq -r '.key // empty' | sed 's/^"\(.*\)"$/\1/')}"
            echod "Updated CA files: cert=$ca_cert_file, key=$ca_key_file"
        else
            echow "No default CA found and CA files not provided"
        fi
    else
        # Strip any surrounding quotes from provided CA files
        ca_cert_file=$(echo "$ca_cert_file" | sed 's/^"\(.*\)"$/\1/')
        ca_key_file=$(echo "$ca_key_file" | sed 's/^"\(.*\)"$/\1/')
        echod "Cleaned CA files: cert=$ca_cert_file, key=$ca_key_file"
    fi

    echoi "Validating input files"
    # Validate required files exist, check separately for clarity
    if [ ! -f "$csr_file" ]; then
        echoe "CSR import_file '$csr_file' does not exist"
        return 1
    fi
    echod "CSR import_file found: $csr_file"
    echov "CSR import_file validated successfully"

    if [ ! -f "$ca_cert_file" ]; then
        echoe "CA certificate import_file '$ca_cert_file' does not exist"
        if [ -n "$default_ca" ]; then
            echow "Check if default CA '$default_ca' certificate is properly configured"
        fi
        return 1
    fi
    if [ ! -f "$ca_key_file" ]; then
        echoe "CA key import_file '$ca_key_file' does not exist"
        if [ -n "$default_ca" ]; then
            echow "Check if default CA '$default_ca' key is properly configured"
        fi
        return 1
    fi
    echov "CA certificate and key validated successfully"

    echod "Verifying CSR import_file"
    # Validate CSR import_file
    if ! openssl req -in "$csr_file" -noout -verify >/dev/null 2>&1; then
        echoe "'$csr_file' is not a valid certificate signing request"
        return 1
    fi
    echov "CSR validated successfully: $csr_file"

    echoi "Validating CA certificate"
    # Validate CA certificate
    if ! openssl x509 -in "$ca_cert_file" -noout -text >/dev/null 2>&1; then
        echoe "'$ca_cert_file' is not a valid CA certificate"
        return 1
    fi
    echov "CA certificate validated successfully"

    # Get index from CSR import_file
    echoi "Retrieving index for CSR import_file"
    index=$(_find_index_by_key_value "csr" "$csr_file")
    if [ -z "$index" ]; then
        index="${csr_file##*-}"
        index="${index%.pem}"
        if [ -z "$index" ] || [ "$index" = "csr" ]; then
            index="$RAND"
            echowv "No existing index found for CSR, using: $index"
        fi
    fi
    echod "CSR index: $index"

    # Determine config import_file to use
    config_file=""
    echoi "Determining configuration import_file"
    # First priority: Use global DC_SSLCFG if it exists and not empty
    if [ -n "$DC_SSLCFG" ]; then
        echov "Using config from current session (DC_SSLCFG)"
        config_file="$DC_KEY/signing-${index}.conf"
        printf "%s" "$DC_SSLCFG" > "$config_file"
        chmod 400 "$config_file" 2>/dev/null || {
            echoe "Failed to set permissions on config import_file '$config_file'"
            return 1
        }
        echov "Config import_file created from DC_SSLCFG: $config_file"
    else
        # Second priority: Load config from index.json
        config_file=$(_get_ssl_keys_key_value "$index" "cfg")
        if [ -n "$config_file" ] && [ -f "$config_file" ]; then
            echov "Using config import_file from index: $config_file"
        else
            echoe "No config available. Either run create-csr first or provide config"
            return 1
        fi
    fi
    echod "Config import_file in use: $config_file"

    # Create output directory if it doesn't exist
    echoi "Checking output directory"
    cert_dir="$(dirpath "$cert_outfile")"
    if [ ! -d "$cert_dir" ]; then
        echov "Creating output directory: $cert_dir"
        mkdir -p "$cert_dir" || {
            echoe "Failed to create directory '$cert_dir'"
            return 1
        }
        echov "Output directory created successfully"
    fi
    echod "Output directory: $cert_dir"

    # Backup existing certificate if it exists
    if [ -f "$cert_outfile" ]; then
        echov "Backing up existing certificate: $cert_outfile"
        backup_cert="${cert_outfile%.*}-backup-$(date +%Y%m%d-%H%M%S).${cert_outfile##*.}"
        cp "$cert_outfile" "$backup_cert" || {
            echow "Failed to backup existing certificate"
        }
        echov "Existing certificate backed up as: $backup_cert"
    fi

    # Sign the CSR
    echoi "Signing CSR: $csr_file"
    echod "Using CA certificate: $ca_cert_file"
    echod "Using CA key: $ca_key_file"
    echod "Output certificate: $cert_outfile"
    echod "Validity: $validity_days days"

    (
        if [ -n "$ca_pass" ]; then
            echov "Password provided, handling encrypted CA private key"
            # Handle encrypted CA private key
            if [ -f "$ca_pass" ]; then
                echov "Reading CA password from import_file: $ca_pass"
                ca_pass_content="$(cat "$ca_pass")"
            else
                echov "Using provided CA password directly"
                ca_pass_content="$ca_pass"
            fi
            echod "CA password content retrieved"

            # Check if CA has associated salt for Argon2id
            ca_index=$(_find_index_by_key_value "key" "$ca_key_file")
            echod "CA index: $ca_index"
            if [ -n "$ca_index" ]; then
                ca_salt_file=$(_get_ssl_keys_key_value "$ca_index" "salt")
                echod "CA salt import_file: $ca_salt_file"
                if [ -f "$ca_salt_file" ]; then
                    echov "Using Argon2id derived key for signing"
                    ca_salt_content="$(cat "$ca_salt_file")"
                    echod "CA salt content retrieved"
                    _create_argon2id_derived_key_pw "$ca_pass_content" "$ca_salt_content" | \
                        openssl x509 -req -in "$csr_file" \
                            -CA "$ca_cert_file" \
                            -CAkey "$ca_key_file" \
                            -CAcreateserial \
                            -out "$cert_outfile" \
                            -days "$validity_days" \
                            -sha384 \
                            -extensions req_ext \
                            -extfile "$config_file" \
                            -passin stdin 2>/dev/null || {
                        echoe "Failed to sign CSR with encrypted CA key (Argon2id)"
                        return 1
                    }
                    echov "CSR signed successfully with Argon2id derived key"
                else
                    echov "No salt import_file found, using password directly"
                    openssl x509 -req -in "$csr_file" \
                        -CA "$ca_cert_file" \
                        -CAkey "$ca_key_file" \
                        -CAcreateserial \
                        -out "$cert_outfile" \
                        -days "$validity_days" \
                        -sha384 \
                        -extensions req_ext \
                        -extfile "$config_file" \
                        -passin "password:$ca_pass_content" 2>/dev/null || {
                        echoe "Failed to sign CSR with encrypted CA key"
                        return 1
                    }
                    echov "CSR signed successfully with direct password"
                fi
            else
                echov "No CA index found, using password directly"
                openssl x509 -req -in "$csr_file" \
                    -CA "$ca_cert_file" \
                    -CAkey "$ca_key_file" \
                    -CAcreateserial \
                    -out "$cert_outfile" \
                    -days "$validity_days" \
                    -sha384 \
                    -extensions req_ext \
                    -extfile "$config_file" \
                    -passin "password:$ca_pass_content" 2>/dev/null || {
                    echoe "Failed to sign CSR with encrypted CA key"
                    return 1
                }
                echov "CSR signed successfully with direct password"
            fi
        else
            echov "No password provided, signing with unencrypted CA private key"
            openssl x509 -req -in "$csr_file" \
                -CA "$ca_cert_file" \
                -CAkey "$ca_key_file" \
                -CAcreateserial \
                -out "$cert_outfile" \
                -days "$validity_days" \
                -sha384 \
                -extensions req_ext \
                -extfile "$config_file" 2>/dev/null || {
                echoe "Failed to sign CSR"
                return 1
            }
            echos "CSR signed successfully without password"
        fi

        # Set appropriate permissions
        echov "Setting permissions on certificate: $cert_outfile"
        chmod 644 "$cert_outfile" 2>/dev/null || {
            echoe "Failed to set permissions on '$cert_outfile'"
            return 1
        }
        echov "Certificate permissions set to 644"

        # Add certificate to index
        echov "Adding certificate to SSL keys index"
        _add_to_ssl_keys_database "$index" "cert" "$cert_outfile"
        echod "Updated SSL keys index with certificate: $cert_outfile"

        # Verify the newly signed certificate
        echoi "Verifying signed certificate"
        if verify_certificate "$cert_outfile" "$ca_cert_file" false false >/dev/null 2>&1; then
            echov "Certificate signed and verified successfully"
        else
            echow "Certificate was signed but verification failed"
        fi

        # Display certificate information
        echoi "Displaying certificate details"
        cert_subject=$(openssl x509 -in "$cert_outfile" -noout -subject | sed 's/subject=//')
        cert_serial=$(openssl x509 -in "$cert_outfile" -noout -serial | sed 's/serial=//')
        echoi "  Subject: $cert_subject"
        echoi "  Serial:  $cert_serial"
        openssl x509 -in "$cert_outfile" -noout -dates | sed 's/^/  /'

        # Show SAN if present
        san=$(openssl x509 -in "$cert_outfile" -noout -ext subjectAltName 2>/dev/null | grep -A1 "Subject Alternative Name" | tail -n1)
        if [ -n "$san" ]; then
            echoi "  SAN: $san"
        fi

        # Create certificate chain if CA certificate is available
        echoi "Creating certificate chain"
        chain_file="${cert_outfile%.*}-fullchain.${cert_outfile##*.}"
        if create_cert_chain "$cert_outfile" "$ca_cert_file" "$chain_file" "$index"; then
            echov "Certificate chain created: $chain_file"
        else
            echow "Failed to create certificate chain"
        fi

        # Cleanup CSR and config files based on keep flags
        echoi "Cleaning up temporary files"
        csr_path=$(_get_ssl_keys_key_value "$index" "csr")
        cfg_path=$(_get_ssl_keys_key_value "$index" "cfg")
        echod "CSR path for cleanup: $csr_path"
        echod "Config path for cleanup: $cfg_path"

        _cleanup_after_signing "$index" "csr" "$csr_path" "$keep_csr"
        echosv "CSR cleanup completed (keep_csr=$keep_csr)"
        _cleanup_after_signing "$index" "cfg" "$cfg_path" "$keep_cfg"
        echosv "Config cleanup completed (keep_cfg=$keep_cfg)"

        # Clean up temporary config import_file if we created one from DC_SSLCFG
        if [ -n "$DC_SSLCFG" ] && [ -f "$config_file" ] && echo "$config_file" | grep -q "signing-"; then
            if [ "$keep_cfg" = "false" ]; then
                echov "Removing temporary config import_file: $config_file"
                rm -f "$config_file" 2>/dev/null || {
                    echow "Failed to remove temporary config import_file"
                }
                echosv "Temporary config import_file removed"
            fi
        fi

        echos "Certificate signing completed successfully!"
        return 0
    )

    status=$?
    echod "Signed certificate signing request: ${csr_outfile}"
    if [ $status -ne 0 ]; then

        echos "Certificate signing successful"
    else
        echoe "Certificate signing failed"
    fi
    return $status
}

create_certificate_authority() {
    ca_cert_file="$1"
    ca_key_file="$2"
    ca_name="$3"
    intermediate="$4"
    password="$5"
    email="$6"
    country="$7"
    state="$8"
    locality="$9"
    organization="${10}"
    orgunit="${11}"
    days="${12}"
    no_argon="${13}"
    salt_out="${14}"

    echod "Starting create_certificate_authority with parameters:"
    echod "  ca_cert_file: $ca_cert_file"
    echod "   ca_key_file: $ca_key_file"
    echod "       ca_name: $ca_name"
    echod "  intermediate: $intermediate"
    echod "      password: $([ -n "$password" ] && echo "[SET]" || echo "[EMPTY]")"
    echod "      salt_out: $salt_out"
    echod "      no_argon: $no_argon"
    echod "          days: $days"

    # Set defaults based on CA type
    if [ "$intermediate" = "true" ]; then
        ca_name="${ca_name:-"Intermediate CA"}"
        ca_index="$(echo "$ca_name" | sed -e 's/\ /\_/' -e 's/\-/\_/'  | tr "[:upper:]" "[:lower:]")"
        ca_cert_file="${ca_cert_file:-"$DC_CA/imd-ca.$ca_index.pem"}"
        ca_key_file="${ca_key_file:-"$DC_CA/imd-ca-key.$ca_index.pem"}"
        ca_type="intca"
        ca_storage_type="intermediate"
        echov "Creating intermediate Certificate Authority"
    else
        ca_name="${ca_name:-"Root CA"}"
        ca_index="$(echo "$ca_name" | sed -e 's/\ /\_/' -e 's/\-/\_/'  | tr "[:upper:]" "[:lower:]")"
        ca_cert_file="${ca_cert_file:-"$DC_CA/ca.$ca_index.pem"}"
        ca_key_file="${ca_key_file:-"$DC_CA/ca-key.$ca_index.pem"}"
        ca_type="rootca"
        ca_storage_type="root"
        echov "Creating root Certificate Authority"
    fi

    echod "CA type set to: $ca_type ($ca_storage_type)"
    echod "Final CA name: $ca_name"

    # Validate required parameters
    if [ -z "$ca_name" ]; then
        echoe "CA name is required"
        return 1
    fi

    # Handle import_file naming like create_private_key does
    if [ -f "$ca_cert_file" ] || [ -f "$ca_key_file" ]; then
        echod "CA files already exist, generating new names"
        echowv "CA files already exist. Changing name to... "
        ca_cert_file="${ca_cert_file%.*}-${RAND}.${ca_cert_file##*.}"
        ca_key_file="${ca_key_file%.*}-${RAND}.${ca_key_file##*.}"
        echov "Certificate: $(basename "$ca_cert_file")"
        echov "Private Key: $(basename "$ca_key_file")"
    fi

    # Check if password is import_file - same as create_private_key
    if [ -f "$password" ]; then
        echov "Reading password from import_file: $password"
        password_content="$(cat "$password")"
    else
        password_content="$password"
        if [ -n "$password_content" ]; then
            echov "Using provided password for CA encryption"
        else
            echov "Creating unencrypted CA"
        fi
    fi

    # Determine output directory for config and salt files
    ca_dir="$(dirpath "$ca_key_file")"
    if echo "$ca_key_file" | grep -q "^/etc/dcrypto/"; then
        # CA key is in dcrypto directory, use standard dcrypto private directory
        config_output_dir="$DCRYPTO_PRIVATE"
        echod "Using dcrypto private directory for config: $config_output_dir"
    else
        # CA key is outside dcrypto directory, use same directory as key
        config_output_dir="$ca_dir"
        echod "Using CA directory for config: $config_output_dir"
    fi

    # Generate CA index based on CA name and key filename
    ca_key_basename="$(basename "$ca_key_file")"
    ca_key_name="${ca_key_basename%.*}"  # Remove extension
    echod "CA index: $ca_index"
    echod "CA key name: $ca_key_name"

    # First check if CA already exists using the new CA functions
    config_file=""
    existing_ca_lookup=$(_find_ca_by_key_value_any "cert" "$ca_cert_file")
    if [ -z "$existing_ca_lookup" ]; then
        existing_ca_lookup=$(_find_ca_by_key_value_any "key" "$ca_key_file")
    fi

    if [ -n "$existing_ca_lookup" ]; then
        echod "Found existing CA: $existing_ca_lookup"
        existing_ca_type="${existing_ca_lookup%%:*}"
        existing_ca_index="${existing_ca_lookup##*:}"
        config_file=$(_get_ca_value "$existing_ca_type" "$existing_ca_index" "cfg")
        ca_index="$existing_ca_index"
        ca_storage_type="$existing_ca_type"
        echov "Using existing CA configuration"
    else
        echod "No existing CA found"
    fi

    # Create SSL config only if no existing config found and DC_SSLCFG is empty
    if [ -z "$config_file" ] || [ ! -f "$config_file" ]; then
        echov "Generating SSL configuration..."
        if [ -z "$DC_SSLCFG" ]; then
            echod "Creating new SSL config"
            _create_sslconfig "$ca_type" "$ca_name" "$email" "$country" \
              "$state" "$locality" "$organization" "$orgunit" "$ca_name" ""
        fi

        # Create config import_file in output directory with key-based name
        config_file="$config_output_dir/${ca_key_name}.conf"
        echo "$DC_SSLCFG" > "$config_file"
        chmod 644 "$config_file"
        echod "SSL config saved to: $config_file"
    fi
    # Add config to CA index (no backup needed for CA creation)
    _add_to_ca_database "$ca_storage_type" "$ca_index" "cfg" "$config_file"

    echoi "Creating $ca_type: $ca_name"
    echov "Certificate: $ca_cert_file"
    echov "Private Key: $ca_key_file"
    echov "Valid for: $days days"

    # PRIVATE KEY GENERATION
    create_private_key "$ca_key_file" "$password" "$salt_out" "$no_argon"

    # CERTIFICATE GENERATION
    (
        echov "Generating self-signed CA certificate..."
        if [ -n "$password" ] && [ "$no_argon" = "false" ]; then
            _create_argon2id_derived_key_pw "$password" "$(cat "$salt_out")" | \
            openssl req \
                -x509 \
                -new \
                -key "$ca_key_file" \
                -passin stdin \
                -out "$ca_cert_file" \
                -days "$days" \
                -extensions v3_ca \
                -config "$config_file" || {
                echoe "Failed to generate CA certificate"
                rm -f "$config_file"
                return 1
            }
        elif [ -n "$password" ] && [ "$no_argon" = "true" ]; then
            echo "$password" | openssl req \
                -x509 \
                -new \
                -key "$ca_key_file" \
                -passin stdin \
                -out "$ca_cert_file" \
                -days "$days" \
                -extensions v3_ca \
                -config "$config_file" || {
                echoe "Failed to generate CA certificate"
                rm -f "$config_file"
                return 1
            }
        elif [ -z "$password" ]; then
            openssl req \
                -x509 \
                -new \
                -key "$ca_key_file" \
                -out "$ca_cert_file" \
                -days "$days" \
                -extensions v3_ca \
                -config "$config_file" || {
                echoe "Failed to generate CA certificate"
                rm -f "$config_file"
                return 1
            }
        fi

        # Verify the certificate
        echov "Validating root CA certificate..."
        if ! openssl verify -CAfile "$ca_cert_file" "$ca_cert_file" 2>/dev/null; then
            echoe "Root CA certificate verification failed"
            return 1
        fi

        # Set permissions
        chmod 400 "$ca_key_file" 2>/dev/null || {
            echoe "Failed to set permissions on CA key"
            rm -f "$config_file"
            return 1
        }
        echov "Set secure permissions on CA key"

        # Set certificate permissions
        chmod 644 "$ca_cert_file" 2>/dev/null || {
            echoe "Failed to set permissions on CA certificate"
            rm -f "$config_file"
            return 1
        }
        echov "Set public permissions on CA certificate"

        echov "Registering CA in index..."
        # Add CA files to CA index using new functions
        _add_to_ca_database "$ca_storage_type" "$ca_index" "key" "$ca_key_file"
        _add_to_ca_database "$ca_storage_type" "$ca_index" "cert" "$ca_cert_file"
        _add_to_ca_database "$ca_storage_type" "$ca_index" "name" "$ca_name"
        _add_to_ca_database "$ca_storage_type" "$ca_index" "created" "$(date -Iseconds)"
        echod "CA registered in index with type: $ca_storage_type, index: $ca_index"

        # Set as default CA if this is the first root CA
        current_default=$(jq -r '.ssl.defaultCA // empty' "$DC_DB")
        if [ -z "$current_default" ] || [ "$current_default" = "null" ] && [ "$ca_storage_type" = "root" ]; then
            echov "Setting as default root CA..."
            if jq --arg ca_index "$ca_index" '.ssl.defaultCA = $ca_index' \
                "$DC_DB" > "${DC_DB}.tmp" \
                && mv "${DC_DB}.tmp" "$DC_DB" \
                && chmod 600 "$DC_DB" && chown root:"$DC_USER" "$DC_DB"; then
                echod "Successfully set as default CA"
            else
                echoe "Warning: Failed to set as default CA"
                rm -f "${DC_DB}.tmp"  # Clean up temp import_file on failure
            fi
            echos "Set as default CA: $ca_index"
        fi

        # Verify the generated certificate
        echod "Validating generated certificate..."
        if ! openssl x509 -in "$ca_cert_file" -noout -text >/dev/null 2>&1; then
            echoe "Warning: CA certificate was generated but verification failed"
        else
            echos "Certificate validation successful"
        fi

        # Display CA information
        echov ""
        echov "CA Details:"
        ca_subject=$(openssl x509 -in "$ca_cert_file" -noout -subject | sed 's/subject=//')
        echov "  Subject: $ca_subject"
        echov "  Serial: $(openssl x509 -in "$ca_cert_file" -noout -serial | sed 's/serial=//')"
        echov "  Valid from: $(openssl x509 -in "$ca_cert_file" -noout -startdate | sed 's/notBefore=//')"
        echov "  Valid until: $(openssl x509 -in "$ca_cert_file" -noout -enddate | sed 's/notAfter=//')"
        echov ""
        echov "Certificate Authority created successfully!"
        echod "Index: $ca_storage_type:$ca_index"
        return 0
    )
    status=$?
    echod "CA creation subprocess exited with status: $status"

    if [ "$status" -eq 0 ]; then
        echos "Created Certificate Authority: $ca_name"
        return 0
    else
        echod "CA creation failed with status: $status"
        echoe "Certificate authority creation failed"
        exit 1
    fi
}

# TODO: Finish SSL encrypt and decrypt functions
ssl_encrypt() (
    cert="$1"
    input="$2"
    output="$3"
    password="$4"
    asymmetric="$5"

    if [ -f "$input" ]; then
        input="$(cat "$input")"
    elif [ -z "$input" ]; then
        echoe "Input is missing."
        return 1

    fi

    if [ "$asymmetric" = "false" ]; then
        # --- Symmetric Encryption ---
        if [ -z "$password" ]; then
            echoe "--password is required for asymmetric encryption (--asymmetric)."
            return 1
        fi

        # 1. Generate a cryptographically secure random salt.
        salt=$(openssl rand -hex 16)
        if [ -z "$salt" ]; then
            echoe "Failed to generate a salt for encryption."
            return 1
        fi

        # 2. Encrypt the data to a temporary import_file, piping the derived key directly.
        echo "Info: Performing asymmetric encryption."
        if ! { _create_argon2id_derived_key_pw "$password" "$salt" | openssl aes-256-cbc -e -pbkdf2 -in "$input" -out "$output" -password stdin; }; then
            echoe "Symmetric encryption failed. This could be a KDF or an OpenSSL error."
            return 1
        fi

        # 3. Combine salt and ciphertext into the final output import_file.
        printf "%s" "$salt" > "$output_file"

    else

        if [ -n "$password" ]; then
             echowv "Warning: --password is ignored for asymmetric encryption."
        fi

        if [ -z "$cert_file" ]; then

            default_ca_cert=$(jq -r '.ssl.ca[] | select(.default == true) | .cert' "$DCRYPTO_IDX" 2>/dev/null)
            if [ -z "$default_ca_cert" ]; then
                echoe "--cert was not specified and no default CA was found."
                echoe "Use --cert <import_file> or set a default CA with the 'set-default-ca' command."
                return 1
            fi
            echov "Info: Using default CA certificate: $default_ca_cert"
            cert_file="$default_ca_cert"
        fi

        if [ ! -f "$cert_file" ] || [ ! -f "$input" ]; then
            echoe "Certificate or input import_file not found."
            return 1
        fi

        if ! openssl pkeyutl -encrypt -pubin -inkey "$cert_file" -in "$input" -out "$output_file"; then
            echoe "Asymmetric encryption failed."
            return 1
        fi
    fi
)


ssl_decrypt() (
    key_file="$1"
    input="$2"
    output="$3"
    password="$4"
    asymmetric="$5"

    if [ -z "$input" ] || [ -z "$output_file" ]; then
        echoe "--in and --out are required for decrypt"
        exit 1
    fi

    if [ "$asymmetric" = "false" ]; then
        # --- Symmetric Decryption ---
        if [ -z "$password" ]; then
            echoe "--password is required for asymmetric decryption (--asymmetric)."
            return 1
        fi

        # 1. Extract the salt from the beginning of the import_file.
        salt=$(head -c 32 "$input")
        if [ "$(printf "%s" "$salt" | wc -c)" -ne 32 ]; then
            echoe "Could not extract a valid 32-character salt from the input import_file."
            return 1
        fi

        # 2. Decrypt, piping the derived key from the KDF directly to OpenSSL.
        if ! { _create_argon2id_derived_key_pw "$password" "$salt" | openssl enc -d -aes-256-cbc -pbkdf2 -in "" -out "$output_file" -password stdin; }; then
            echoe "Symmetric decryption failed. Check your password. This could also be a KDF or an OpenSSL error."
            return 1
        fi

    else
        if [ -z "$key_file" ]; then
            if ! command -v jq >/dev/null; then
                echoe "'jq' is not installed. It is required to find the default CA."
                return 1
            fi
            default_ca_key=$(jq -r '.ssl.ca[] | select(.default == true) | .key_path' "$DCRYPTO_IDX" 2>/dev/null)
            if [ -z "$default_ca_key" ]; then
                echoe "--key was not specified and no default CA was found."
                echoe "Use --key <import_file> or set a default CA with the 'set-default-ca' command."
                return 1
            fi
            echo "Info: Using default CA private key: $default_ca_key"
            key_file="$default_ca_key"
        fi

        if [ ! -f "$key_file" ] || [ ! -f "$input" ]; then
            echoe "Private key or input import_file not found."
            return 1
        fi

        # The decryption command depends on whether a password is provided for the key.
        if [ -n "$password" ]; then
            # Pipe the output of the KDF directly to OpenSSL for the key's password.
            # Note: This assumes the private key was created using a password processed by the same KDF.
            if ! { _create_argon2id_derived_key_pw "$password" | openssl pkeyutl -decrypt -inkey "$key_file" -in "$input" -out "$output_file" -passin stdin; }; then
                echoe "Asymmetric decryption failed. Check your private key and password."
                return 1
            fi
        else
            # No password provided for the key.
            if ! openssl pkeyutl -decrypt -inkey "$key_file" -in "$input" -out "$output_file"; then
                echoe "Asymmetric decryption failed. Check your private key."
                return 1
            fi
        fi
    fi
)


import_ssl() {
    import="$1"
    scan_depth="$2"
    copy_files="$3"
    move_files="$4"

    echod "Starting import_ssl with parameters:"
    echod "           import: $import"
    echod "       scan_depth: $scan_depth"
    echod "       copy_files: $copy_files"
    echod "       move_files: $move_files"
    echod "             user: $DC_USER"

    : "${filecount:=0}"

    if [ "$copy_files" = "true" ] && [ "$move_files" = "true" ]; then
        echoe "--copy-files and --move-files can't be set both as parameter"
        return 1
    fi

    if [ -f "$import" ]; then
        echod "Importing import_file at $import"
    elif [ -d "$import" ]; then
        echod "Importing files in directory at $import"
        files=$(find "$import" \
            -type f \
            -maxdepth "$scan_depth" \
            -name "*.pem" \
            -o -name "*.conf" \
            -o -name "*.cert" \
            -o -name "*.crt" \
            -o -name "*.cer" \
            2>/dev/null);

        for file in $files; do
            ftype=""
            ca_type=""
            ca_index=""
            filepath="$(realpath "$file")"
            filename="$(basename "$file")"
            dirpath="$(dirname "$filepath")"
            ftype="$(_get_file_type "$filepath")"

            if [ "$ftype" = "root" ] || [ "$ftype" = "intermediate" ]; then
                ca_issuer=$(openssl x509 -in "$ca_cert_file" -noout -issuer | sed 's/issuer=//')
                ca_cn=$(echo "$ca_issuer" | sed -n 's/.*CN=\([^,]*\).*/\1/p' | sed 's/^ *//;s/ *$//')
                ca_index="$(echo "$ca_cn" | sed -e 's/\ /\_/' -e 's/\-/\_/' | tr "[:upper:]" "[:lower:]")"
            fi

            if [ "$copy_files" = "true" ] || [ "$move_files" = "true" ]; then
                if [ "$ftype" = "key" ] && [ -n "$ca_type" ]; then
                    dirpath="$DC_CAKEY"
                elif [ "$ftype" = "key" ] && [ -z "$ca_type" ]; then
                    dirpath="$DC_KEY"
                elif [ "$ftype" = "cert" ] && [ -n "$ca_type" ]; then
                    dirpath="$DC_CA"
                elif [ "$ftype" = "cert" ] && [ -z "$ca_type" ]; then
                    dirpath="$DC_CERT"
                elif [ "$ftype" = "cfg" ]; then
                    if grep -qE "CA:TRUE"; then
                        dirpath="$DC_CA"
                    else
                        dirpath="$DC_CERT"
                    fi
                fi
            fi
            if [ "$copy_files" = "true" ]; then
                cp -f "$filepath" "$dirpath/$filename"
                echov "Copied file $filepath into dcrypto directory: $dirpath"
            elif [ "$move_files" = "true" ]; then
                mv "$filepath" "$dirpath/$filename"
                echov "Moved file $filepath into dcrypto directory: $dirpath"
            fi

            if [ -n "$ftype" ] && [ -n "$ca_type" ] && [ -n "$ca_index" ]; then
                echod "Importing file into database:"
                echod "${ca_type}CA Name: $ca_index Type: $ftype Path: $dirpath/$filename"
                _add_to_ca_database "$ca_type" "$ca_index" "$ftype" "$dirpath/$filename"
                echosv "Imported file $dirpath/$filename into database"
                filecount=$(("$filecount" + 1))
            elif [ -n "$ftype" ]; then
                echod "Importing file into database:"
                echod "Name/Index: $RAND Type: $ftype Path: $dirpath/$filename"
                _add_to_ssl_keys_database "$RAND" "$ftype" "$dirpath/$filename"
                echosv "Imported file $dirpath/$filename into database"
                filecount=$(("$filecount" + 1))
            else
                echow "Was not able to identify file: $dirpath/$filename"
            fi
        done
    fi
    echos "Importing files successful. Imported $filecount files."
}

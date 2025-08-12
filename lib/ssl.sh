# shellcheck shell=sh
# shellcheck disable=SC2001
# shellcheck disable=SC2181


_create_argon2id_derived_key_pw() {

    # Check the exit status of the pipeline
    if openssl kdf \
        -keylen 32 \
        -kdfopt pass:"${1:+"$([ -s "$1" ] && cat -- "$(absolutepath "$1")" || echo "$1")"}" \
        -kdfopt salt:"${2:+"$([ -s "$2" ] && cat -- "$(absolutepath "$2")" || echo "$2")"}" \
        -kdfopt memcost:"524288" \
        -kdfopt early_clean:1 \
        -kdfopt lanes:"$(nproc)" ARGON2ID 2>/dev/null | \
        tr -d ':\n '; then
        if [ -t 1 ]; then
            printf "\n"
        fi
        return 0
    else
        echoe "Failed to generate Argon2id key"
        return 1
    fi

}

_create_pbkdf2_derived_key_pw() {
    printf "%s" "${1:+"$([ -s "$1" ] && cat -- "$(absolutepath "$1")" || echo "$1")"}"
}

_create_saltfile() {
    printf "%s" "$(openssl rand -hex 32)" > "$1"
    if [ ! -s "$1" ]; then
        echoe "Couldn't write to file: $1"
        return 1
    fi
    set_permissions_and_owner "$1" 440
}

_create_serialfile() {
    serial="$1"
    serial_out="$2"
    printf "%s" "$serial" >> "$serial_out"
    if [ ! -s "$serial_out" ]; then
        echoe "Couldn't write to file: $serial_out"
        return 1
    fi
    set_permissions_and_owner "$serial_out" 440
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
        if is_ip "$domain"; then
            ips="${ips}\nIP.$ipc = $domain"
            ipc=$(("$ipc" + 1))
        else
            dns="${dns}\nDNS.$dnsc = $domain"
            dnsc=$(("$dnsc" + 1))
        fi
    done
    set -- "$orig_args"
}

_create_sslconfig() {
    : "${dnsc:=1}"
    : "${ipc:=1}"
    cfg_type="$1"
    domains_ips="$2"
    email="$3"
    country="$4"
    state="$5"
    locality="$6"
    organization="$7"
    orgunit="$8"
    common_name="$9"
    crldistpoints="${10}"
    config_out="${11}"
    domains_ips=$(printf "%s" "$domains_ips" | sed 's/,/ /g')
    domcount=$(printf "%s" "$domains_ips" | wc -w | tr -d ' ')
    ips=""
    dns=""
    for domain in $domains_ips; do

        if is_ip "$domain"; then
            ips="${ips}\nIP.$ipc = $domain"
            ipc=$(("$ipc" + 1))
        else
            dns="${dns}\nDNS.$dnsc = $domain"
            dnsc=$(("$dnsc" + 1))
        fi
    done

    if [ "$cfg_type" = "server" ]; then
        common_name="${domains_ips%% *}"
    elif [ "$cfg_type" = "client" ]; then
        if [ -z "$common_name" ]; then
            common_name="$domains_ips"
        fi
    fi

    (
        # shellcheck disable=SC2030
        ssl_cfg=""
        ssl_cfg=$(cat <<EOF
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
        if [ "$cfg_type" = "intermediate" ] || [ "$cfg_type" = "root" ]; then
            ssl_cfg="${ssl_cfg}\nx509_extensions = v3_ca\n\n"
        elif [ "$cfg_type" = "server" ] || [ "$cfg_type" = "client" ]; then
            ssl_cfg="${ssl_cfg}\nreq_extensions = req_ext\n\n"
        fi
        ssl_cfg="${ssl_cfg}[ req_distinguished_name ]\n"

        if [ -n "$country" ]; then
            ssl_cfg="${ssl_cfg}C = ${country}\n"
        fi
        if [ -n "$state" ]; then
            ssl_cfg="${ssl_cfg}ST = ${state}\n"
        fi
        if [ -n "$locality" ]; then
            ssl_cfg="${ssl_cfg}L = ${locality}\n"
        fi
        if [ -n "$organization" ]; then
            ssl_cfg="${ssl_cfg}O = ${organization}\n"
        fi
        if [ "$cfg_type" = "root" ]; then
            if [ -z "$orgunit" ]; then
                ssl_cfg="${ssl_cfg}OU = Certificate Authority\n"
            else
                ssl_cfg="${ssl_cfg}OU = ${orgunit}\n"
            fi
            if [ -z "$common_name" ]; then
                ssl_cfg="${ssl_cfg}CN = $common_name CA\n"
            else
                ssl_cfg="${ssl_cfg}CN = ${common_name}\n"
            fi

        elif [ "$cfg_type" = "intermediate" ]; then
            if [ -z "$orgunit" ]; then
                ssl_cfg="${ssl_cfg}OU = Intermediate Certificate Authority\n"
            else
                ssl_cfg="${ssl_cfg}OU = ${orgunit}\n"
            fi
            if [ -z "$common_name" ]; then
                ssl_cfg="${ssl_cfg}CN = $common_name Intermediate CA\n"
            else
                ssl_cfg="${ssl_cfg}CN = ${common_name}\n"
            fi
        elif [ "$cfg_type" = "server" ] || [ "$cfg_type" = "client" ]; then
            ssl_cfg="${ssl_cfg}CN = $common_name\n"
        fi
        if [ -n "$email" ]; then
            ssl_cfg="${ssl_cfg}emailAddress = $email\n"
        fi
        ssl_cfg="${ssl_cfg}\n"
        if [ "$cfg_type" = "server" ] || [ "$cfg_type" = "client" ]; then
            ssl_cfg="${ssl_cfg}[ req_ext ]\n"
            ssl_cfg="${ssl_cfg}subjectKeyIdentifier = hash\n"
            ssl_cfg="${ssl_cfg}basicConstraints = CA:FALSE\n"
            if [ "$cfg_type" = "server" ]; then
                ssl_cfg="${ssl_cfg}keyUsage = critical, digitalSignature, keyEncipherment\n"
                ssl_cfg="${ssl_cfg}extendedKeyUsage = serverAuth\n"
            elif [ "$cfg_type" = "client" ]; then
                ssl_cfg="${ssl_cfg}keyUsage = critical, digitalSignature\n"
                ssl_cfg="${ssl_cfg}extendedKeyUsage = clientAuth\n"
            fi
        fi

        if [ "$domcount" -gt 1 ]; then
            ssl_cfg="${ssl_cfg}subjectAltName = @alt_names\n\n"
            ssl_cfg="${ssl_cfg}[ alt_names ]$ips$dns\n"
        fi
        if [ "$cfg_type" = "intermediate" ] || [ "$cfg_type" = "root" ]; then
            ssl_cfg="${ssl_cfg}[ v3_ca ]\n"
            ssl_cfg="${ssl_cfg}subjectKeyIdentifier = hash\n"
            ssl_cfg="${ssl_cfg}authorityKeyIdentifier = keyid:always,issuer\n"
            if [ "$cfg_type" = "intermediate" ]; then
                ssl_cfg="${ssl_cfg}basicConstraints = critical, CA:TRUE, pathlen:0\n"
            elif [ "$cfg_type" = "root" ]; then
                ssl_cfg="${ssl_cfg}basicConstraints = critical, CA:TRUE\n"
            fi
            ssl_cfg="${ssl_cfg}keyUsage = critical, digitalSignature, cRLSign, keyCertSign\n"
        fi
        if [ -n "$crldistpoints" ]; then
            ssl_cfg="${ssl_cfg}\n\ncrlDistributionPoints = URI:$crldistpoints"
        fi
        printf "%b" "$ssl_cfg" > "$config_out"
        if [ ! -s "$config_out" ]; then
            echoe "Config file $config_out was not created"
        return 1
    fi
    )
    status=$?
    echod "Subshell for ssl_config creation ended with status: $status"
    if [ "$status" -eq 0 ];then
        set_permissions_and_owner "$config_out" 440
        echod "SSL config contents:"
        echod "$(cat "$config_out" 2>/dev/null || echo "Failed to read $config_out")"
        return 0
    fi
    return 1
}


_get_parent_cert_index() {
    cert_file="$1"

    # Check if server certificate exists
    if [ ! -s "$cert_file" ]; then
        echoe "Error: Server certificate file is missing or empty"
        return 1
    fi

    # Get the issuer of the server certificate
    issuer_cn="$(openssl x509 -in "$cert_file" -noout -issuer | sed -n 's/.*CN[ =]\+\([^/]*\).*/\1/p')"
    echo "$issuer_cn" | sed -e 's/\-/\_/g' -e 's/\ /\_/g' | tr "[:upper:]" "[:lower:]"
    return 0
}


_create_and_verify_key() {
    key_out="$1"
    password="$2"
    salt_out="$3"
    no_argon="$4"
    passphrasedbg=$({ [ "${2}" = "gui" ] || [ "${2}" = "GUI" ]; } && echo "[GUI]")
    passphrasedbg=$({ [ -n "${2}" ]  && [ ! -f "${2}" ]; } && echo "[SET]" || echo "${2}")

    echod "Starting _create_and_verify_key with parameters:"
    echod "    key_out: $key_out"
    echod "   password: $passphrasedbg"
    echod "   salt_out: $salt_out"
    echod "   no_argon: $no_argon"

    (
        if [ -z "$password" ]; then
            echoi "Generating unencrypted secp384r1 private key..."

            # Generate key
            echod "Calling openssl ecparam -genkey -name secp384r1 -out $key_out -outform PEM"
            if ! openssl ecparam \
                -genkey \
                -name secp384r1 \
                -out "$key_out" \
                -outform PEM 2>/dev/null; then
                    echoe "Failed to generate private key"
                    return 1
            fi
            echosv "Private key generation successful"
            echov "Validating generated private key..."

            # Verify key
            echod "Calling openssl ec -check -noout -in $key_out"
            if ! openssl ec -check -noout -in "$key_out" >/dev/null 2>&1; then
                    echoe "Failed to validate private key: key check failed"
                    return 1
            fi
            echosv "Private key validation successful"
        else
            echoi "Generating encrypted secp384r1 private key..."
            if [ "$no_argon" = "true" ]; then
                echov "Encrypting with PBKDF2 key..."

                # Generate key
                echov "Calling _create_pbkdf2_derived_key_pw $password | openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:secp384r1 -aes-256-cbc -pass stdin -out $key_out"
                if ! _create_pbkdf2_derived_key_pw "$password" | \
                    openssl genpkey \
                    -algorithm EC \
                    -pkeyopt ec_paramgen_curve:secp384r1 \
                    -aes-256-cbc \
                    -pass stdin \
                    -out "$key_out" 2>/dev/null; then
                        echoe "Failed to generate encrypted private key with PBKDF2"
                        return 1
                fi
                echosv "Encrypted private key generated with PBKDF2"

                # Verify key
                echov "Validating generated private key..."
                echod "Calling _create_pbkdf2_derived_key_pw $password | openssl ec -check -passin stdin -in $key_out"
                if ! _create_pbkdf2_derived_key_pw "$password" | \
                    openssl ec -check -passin stdin -in "$key_out" >/dev/null 2>&1; then
                    echoe "Failed to validate encrypted private key: decryption or key check failed"
                    return 1
                fi
                echosv "Private key validation successful"

            else
                echov "Encrypting with Argon2id-derived key..."

                # Generate Key
                echod "Calling _create_argon2id_derived_key_pw $password $salt_out | openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:secp384r1 -aes-256-cbc -pass stdin -out $key_out"
                if ! _create_argon2id_derived_key_pw "$password" "$salt_out" | \
                    openssl genpkey \
                    -algorithm EC \
                    -pkeyopt ec_paramgen_curve:secp384r1 \
                    -aes-256-cbc \
                    -pass stdin \
                    -out "$key_out" 2>/dev/null; then
                    echoe "Failed to generate encrypted private key with Argon2id"

                    return 1
                fi
                echosv "Encrypted private key generated with Argon2id"
                echov "Validating generated private key..."
                echod "Calling _create_argon2id_derived_key_pw $password $salt_out | openssl ec -in $key_out -passin stdin -noout -check"
                if ! _create_argon2id_derived_key_pw "$password" "$salt_out" | \
                    openssl ec -in "$key_out" -check -noout -passin stdin >/dev/null 2>&1; then
                    echoe "'$key_out' is not a valid private key"
                    return 1
                fi
                echosv "Private key validation successful"
            fi
        fi
    )
    status=$?
    echod "Private key creation subshell exited with status: $status"
    if [ "$status" -eq 0 ]; then
        set_permissions_and_owner "$key_out" 440
        return 0
    else
        return 1
    fi
}

_create_and_verify_csr() {
    csr_out="$1"
    key_file="$2"
    password="$3"
    salt="$4"
    config_file="$5"
    passphrasedbg=$({ [ "${3}" = "gui" ] || [ "${3}" = "GUI" ]; } && echo "[GUI]")
    passphrasedbg=$({ [ -n "${3}" ]  && [ ! -f "${3}" ]; } && echo "[SET]" || echo "${3}")
    saltdbg=$({ [ -n "${4}" ]  && [ ! -f "${4}" ]; } && echo "[SET]" || echo "${4}")

    echod "Starting _create_and_verify_csr with parameters:"
    echod "     csr_out: $csr_out"
    echod "    key_file: $key_file"
    echod "    password: $passphrasedbg"
    echod "        salt: $saltdbg"
    echod " config_file: $config_file"

    (
        # Handle password and salt
        if [ -n "$password" ]; then
            if [ -n "$salt" ]; then
                echov "Using Argon2id derived key for CSR generation"
                echod "Calling _create_argon2id_derived_key_pw [pass] [salt] | openssl req -new -key $key_file -out $csr_out -config $config_file -passin stdin"
                if ! _create_argon2id_derived_key_pw "$password" "$salt" | \
                openssl req \
                    -new \
                    -key "$key_file" \
                    -out "$csr_out" \
                    -config "$config_file" \
                    -passin stdin 2>/dev/null; then
                    echoe "Failed to generate CSR with Argon2id"
                    return 1
                fi
                echosv "CSR generated successfully with Argon2id"
            else
                echov "Using PBKDF2 derived key for CSR generation"
                echod "Calling _create_pbkdf2_derived_key_pw [password] | openssl req -new -key $key_file -out $csr_out -config $config_file -passin stdin"
                if ! _create_pbkdf2_derived_key_pw "$password" | \
                openssl req \
                    -new \
                    -key "$key_file" \
                    -out "$csr_out" \
                    -config "$config_file" \
                    -passin stdin 2>/dev/null; then
                    echoe "Failed to generate CSR with PBKDF2"
                    return 1
                fi
                echosv "CSR generated successfully with PBKDF2"
            fi
        else
            echov "No password provided, generating CSR without password"
            echod "Calling openssl req -new -key $key_file -out $csr_out -config $config_file"
            if ! openssl req \
                -new \
                -key "$key_file" \
                -out "$csr_out" \
                -config "$config_file" 2>/dev/null; then
                echoe "Failed to generate CSR"
                return 1
            fi
            echov "CSR generated successfully without password"
        fi

        # Verify CSR
        echov "Verifying CSR content & signature ..."
        echod "Calling openssl req -in $csr_out -noout -verify"
        if ! openssl req -in "$csr_out" -noout -verify >/dev/null 2>&1; then
            echoe "CSR signature verification failed"
            return 1
        fi

        echod "Calling openssl req -in $csr_out -noout -text"
        if ! openssl req -in "$csr_out" -noout -text >/dev/null 2>&1; then
            echoe "CSR content verification failed"
            return 1
        fi
        echosv "CSR verification successful"
    )
    status=$?
    echod "CSR creation subshell exited with status: $status"
    if [ "$status" -eq 0 ]; then
        set_permissions_and_owner "$csr_out" 440
        return 0
    fi
    return 1
}


_create_and_verify_cert() {
    cert_out="$1"
    csr_file="$2"
    config_file="$3"
    ca_key_file="$4"
    ca_cert_file="$5"
    pass="$6"
    salt="$7"
    extensions="$8"
    days="$9"
    passdbg=$({ [ "${6}" = "gui" ] || [ "${6}" = "GUI" ]; } && echo "[GUI]")
    passdbg=$({ [ -n "${6}" ]  && [ ! -f "${6}" ]; } && echo "[SET]" || echo "${6}")
    saltdbg=$({ [ -n "${7}" ]  && [ ! -f "${7}" ]; } && echo "[SET]" || echo "${7}")

    echod "Starting _create_and_verify_cert with parameters:"
    echod "      cert_out: $cert_out"
    echod "      csr_file: $csr_file"
    echod "   config_file: $config_file"
    echod "   ca_key_file: $ca_key_file"
    echod "  ca_cert_file: $ca_cert_file"
    echod "          pass: $passdbg"
    echod "          salt: $saltdbg"
    echod "    extensions: $extensions"
    echod "          days: $days"

    (
        # Handle CA password and salt
        if [ -n "$pass" ]; then
            if [ -f "$salt" ]; then
                echov "Using Argon2id derived key for signing"
                echod "_create_argon2id_derived_key_pw \"$passdbg\" \"$saltdbg\" | openssl x509 -req -in $csr_file -CA $ca_cert_file -CAkey $ca_key_file -CAcreateserial -out $cert_out -days $days -sha384 -extensions $extensions -extfile $config_file -passin stdin"
                if ! _create_argon2id_derived_key_pw "$pass" "$salt" | \
                    openssl x509 \
                    -req \
                    -in "$csr_file" \
                    -CA "$ca_cert_file" \
                    -CAkey "$ca_key_file" \
                    -CAcreateserial \
                    -out "$cert_out" \
                    -days "$days" \
                    -sha384 \
                    -extensions "$extensions" \
                    -extfile "$config_file" \
                    -passin stdin 2>/dev/null; then
                        echoe "Failed to sign CSR with Argon2id"
                        return 1
                fi
                echosv "CSR signed successfully with Argon2id"
            else
                echov "No salt file found, using password directly"
                echod "_create_pbkdf2_derived_key_pw \"$passdbg\" | openssl x509 -req -in $csr_file -CA $ca_cert_file -CAkey $ca_key_file -CAcreateserial -out $cert_out -days $days -sha384 -extensions $extensions -extfile $config_file -passin stdin"
                if ! _create_pbkdf2_derived_key_pw "$pass" | \
                    openssl x509 \
                    -req \
                    -in "$csr_file" \
                    -CA "$ca_cert_file" \
                    -CAkey "$ca_key_file" \
                    -CAcreateserial \
                    -out "$cert_out" \
                    -days "$days" \
                    -sha384 \
                    -extensions "$extensions" \
                    -extfile "$config_file" \
                    -passin stdin 2>/dev/null; then
                        echoe "Failed to sign CSR with PBKDF2"
                        return 1
                fi
                echosv "CSR signed successfully with PBKDF2"
            fi
        else
            echov "No password provided, signing with unencrypted CA private key"
            echod "Calling openssl x509 -req -in $csr_file -CA $ca_cert_file -CAkey $ca_key_file -CAcreateserial -out $cert_out -days $days -sha384 -extensions $extensions -extfile $config_file"
            if ! openssl x509 \
                -req \
                -in "$csr_file" \
                -CA "$ca_cert_file" \
                -CAkey "$ca_key_file" \
                -CAcreateserial \
                -out "$cert_out" \
                -days "$days" \
                -sha384 \
                -extensions "$extensions" \
                -extfile "$config_file" 2>/dev/null; then
                    echoe "Failed to sign CSR"
                    return 1
            fi
            echosv "CSR signed successfully without password"
        fi

        # Verify certificate
        echov "Verifying certificate signature"

        echod "Calling openssl x509 -in $cert_out -noout -text"
        if ! openssl x509 -in "$cert_out" -noout -text >/dev/null 2>&1; then
            echoe "Certificate verification failed"
            return 1
        fi

        echod "Calling openssl verify -CAfile $ca_cert_file $cert_out"
        if ! openssl verify -CAfile "$ca_cert_file" "$cert_out" >/dev/null 2>&1; then
            echoe "Certificate chain verification failed"
            return 1
        fi

        echosv "Certificate verification successful"
    )
    status=$?
    echod "CSR signing / certificate creation subshell exited with status: $status"
    if [ "$status" -eq 0 ]; then
        set_permissions_and_owner "$cert_out" 444
        return 0
    fi
    return 1
}


_create_and_verify_sscert() {
    ca_key_out="$1"
    ca_cert_out="$2"
    pass="$3"
    salt="$4"
    ca_conf_out="$5"
    no_argon="$6"
    days="$7"
    passdbg=$({ [ "${3}" = "gui" ] || [ "${3}" = "GUI" ]; } && echo "[GUI]")
    passdbg=$({ [ -n "${3}" ]  && [ ! -f "${3}" ]; } && echo "[SET]" || echo "${3}")
    saltdbg=$({ [ -n "${4}" ]  && [ ! -f "${4}" ]; } && echo "[SET]" || echo "${4}")

    echod "Starting _create_and_verify_sscert with parameters:"
    echod "   ca_key_out: $ca_key_out"
    echod "  ca_cert_out: $ca_cert_out"
    echod "         pass: $passdbg"
    echod "         salt: $saltdbg"
    echod "  ca_conf_out: $ca_conf_out"
    echod "     no_argon: $no_argon"
    echod "         days: $days"
    echod "         user: $DC_USER"

    (
        # Log the OpenSSL command

        if [ -z "$pass" ]; then
            echoi "Generating self-signed certificate without password"
            echod "Running OpenSSL command: openssl req -x509 -new -noenc -keyout $ca_key_out -out $ca_cert_out -days $days -sha384 -extensions v3_ca -config $ca_conf_out"
            if ! openssl req \
                  -x509 \
                  -new \
                  -keyout "$ca_key_out" \
                  -out "$ca_cert_out" \
                  -days "$days" \
                  -noenc \
                  -sha384 \
                  -keyform PEM \
                  -extensions v3_ca \
                  -config "$ca_conf_out" 2>/dev/null; then
                echoe "Failed to generate self-signed certificate"
                return 1
            fi
        elif [ -n "$pass" ] && [ "$no_argon" = "false" ]; then
            echoi "Generating self-signed certificate with password using Argon2id KDF"
            echod "Running OpenSSL command: openssl req -x509 -new -keyout $ca_key_out -out $ca_cert_out -days $days -sha384 -extensions v3_ca -config $ca_conf_out"
            if ! _create_argon2id_derived_key_pw "$pass" "$salt" | \
            openssl req \
                  -x509 \
                  -new \
                  -keyout "$ca_key_out" \
                  -out "$ca_cert_out" \
                  -passout stdin \
                  -days "$days" \
                  -sha384 \
                  -extensions v3_ca \
                  -config "$ca_conf_out" 2>/dev/null; then
                echoe "Failed to generate self-signed certificate"
                return 1
            fi
        elif [ -n "$pass" ] && [ "$no_argon" = "true" ]; then
            echoi "Generating self-signed certificate with password using PBKDF2 KDF"
            echod "Running OpenSSL command: openssl req -x509 -new -keyout $ca_key_out -out $ca_cert_out -days $days -sha384 -extensions v3_ca -config $ca_conf_out"
            if ! _create_pbkdf2_derived_key_pw "$ca_pass" | \
            openssl req \
                  -x509 \
                  -new \
                  -keyout "$ca_key_out" \
                  -out "$ca_cert_out" \
                  -days "$days" \
                  -passout stdin \
                  -sha384 \
                  -extensions v3_ca \
                  -config "$ca_conf_out" 2>/dev/null; then
                echoe "Failed to generate self-signed certificate"
                return 1
            fi
        fi

        # Check if certificate was created
        if [ ! -f "$ca_cert_out" ]; then
            echoe "Certificate file $ca_cert_out was not created"
            return 1
        fi

        # Verify certificate
        echov "Verifying generated self-signed certificate..."

        echod "Calling: openssl x509 -in $ca_cert_out -noout -text"
        if ! openssl x509 -in "$ca_cert_out" -noout -text >/dev/null 2>&1; then
            echoe "Self-signed certificate verification failed"
            return 1
        fi
        echov "Self-signed certificate verification successful"

        echod "Calling: openssl verify -CAfile $ca_cert_out $ca_cert_out"
        if ! openssl verify -CAfile "$ca_cert_out" "$ca_cert_out" >/dev/null 2>&1; then
            echoe "Self-signed certificate chain verification failed"
            return 1
        fi
        echov "Self-signed certificate chain verification successful"
    )
    status=$?
    echod "Self-signed certificate subshell exited with status: $status"
    if [ "$status" -eq 0 ]; then
        if set_permissions_and_owner "$ca_key_out" 440 && \
           set_permissions_and_owner "$ca_cert_out" 444 ; then
            echosv "Creating self-signed certificate successful"
            return 0
        fi
    else
        return 1
    fi
}

_create_and_verify_fullchain() {
    cert_file="$1"
    fullchain_out="$2"

    echod "Starting _create_and_verify_fullchain with parameters:"
    echod "     cert_file: $cert_file"
    echod " fullchain_out: $fullchain_out"

    (
        echoi "Creating certificate chain"
        parent_cert_index="$(_get_parent_cert_index "$cert_out")"
        parent_cert="$(get_value_from_index "$parent_cert_index" "cert")"
        echod "Parent_cert_index $parent_cert_index parent_cert $parent_cert"
        # Create chain
        cat "$cert_out" "$parent_cert" > "$fullchain_out" || {
            echoe "Error while concatenating cert files and writing to fullchain_out: $fullchain_out"
            return 1
        }

        # Validate chain file
        if [ ! -f "$fullchain_out" ] || [ ! -r "$fullchain_out" ]; then
            echoe "File not found or readable: $fullchain_out"
        fi

        # Verify chain file
        if ! openssl verify -CAfile "$parent_cert" "$fullchain_out" 2>/dev/null; then
            echoe "Fullchain certificate verification failed."
            exit 1
        fi

        echosv "Certificate chain successfully created"
        return 0
    )
    status=$?
    echod "Fullchain certification creation subshell exited with status: $status"
    if [ "$status" -eq 0 ]; then
        set_permissions_and_owner "$fullchain_out" 444
        return 0
    fi
    return 1
}


create_private_key() {
    key_name="${1:-}" && [ -z "$key_name" ] && echoe "Key name is required" && return 1
    index="${key_name:+"$(echo "$1" | sed -e 's/\ /\_/g' -e 's/\-/\_/g' | tr "[:upper:]" "[:lower:]")"}"
    if index_exists "$index"; then
        echoe "Normalized key_name:$key_name ($index) already exists in database"
        return 1
    fi

    key_out="${2:+$(absolutepathidx "$2" "$index")}"
    key_out="${2:-$(absolutepathidx "$DC_KEY/key.pem" "$index")}"

    password="${3:+$([ -s "$3" ] && absolutepath "$3")}"

    salt_out="${4:+$(absolutepathidx "$4" "$index")}"
    salt_out="${4:-$(absolutepathidx "$DC_KEY/key.salt" "$index")}"

    no_argon="${5:-false}"

    echod "Starting create_private_key with parameters:"
    echod "      key_name: $key_name"
    echod "         index: $index"
    echod "       key_out: $key_out"
    echod "      password: $([ -n "$password" ] && echo "[SET]")"
    echod "      salt_out: $salt_out"
    echod "      no-argon: $no_argon"

    # Validate inputs
    if [ -z "$key_name" ] && [ -z "$key_out" ]; then
        echoe "Either key_name or key_out is required"
        return 1
    fi

    # Validate output directory
    for d in "$(dirpath "$key_out")" "$(dirpath "$salt_out")"; do
        if [ ! -d "$d" ]; then
            echow "Output directory $d does not exist"
            mkdir -p "$d" || {
                echoe "Creating directory failed: $d"
                return 1
            }

            set_permissions_and_owner "$d" 750 || {
                echoe "Failed calling set_permissions_and_owner $d 750"
                return 1
            }
        fi
    done

    # Auto-generate salt if password is provided and salt_out is empty
    if [ -n "$password" ] && [ "$no_argon" = "false" ]; then
        echov "Creating and writing salt"
        echod "Calling _create_saltfile $salt_out"
        _create_saltfile "$salt_out" || {
            echoe "Salt file creation failed: $salt_out"
            return 1
        }
        echosv "Creating saltfile: $salt_out successful"
    fi

    # Generate and verify key
    echoi "Creating openssl private key..."
    echod "Calling _create_and_verify_key $key_out $password $salt_out $no_argon"
    _create_and_verify_key "$key_out" "$password" "$salt_out" "$no_argon" || {
        echoe "Failed to generate private key for $key_out"
        if [ -n "$salt_out" ] && [ ! -f "$salt_out" ]; then
            echoe "Salt file $salt_out does not exist"
        elif [ -n "$password" ] && [ ! -s "$password" ]; then
            echoe "Password file $password is empty or inaccessible"
        else
            echoe "Check OpenSSL error output for details"
        fi
        return 1
    }
    echosv "OpenSSL Private Key file created and verified"

    # Update database with basename and directory
    add_to_ssl_keys_database "$index" "key" "$key_out"
    if [ -n "$password" ] && [ -n "$salt_out" ] && [ "$no_argon" = "false" ]; then
        add_to_ssl_keys_database "$index" "salt" "$salt_out"
        add_to_ssl_keys_database "$index" "kdf" "argon2id"
    elif [ -n "$password" ] && { [ -z "$salt_out" ] || [ "$no_argon" = "true" ]; }; then
        add_to_ssl_keys_database "$index" "kdf" "pbkdf2"
    fi
    add_to_ssl_keys_database "$index" "name" "$1"

    echos "Private key creation successful"
    return 0
}

create_certificate_authority() {
    ca_name="$1" && [ -z "$1" ] && echoe "CA name is required" && return 1
    index="${ca_name:+$(echo "$ca_name" | sed -e 's/\-/\_/g' -e 's/\ /\_/g' | tr "[:upper:]" "[:lower:]")}"

    if index_exists "$index"; then
        echoe "Normalized $ca_name ($index) already exists in database"
        return 1
    fi

    ca_key_out="${2:+$(absolutepathidx "$2" "$index")}"
    ca_key_out="${2:-$(absolutepathidx "$DC_CAKEY/ca-key.pem" "$index")}"

    ca_cert_out="${3:+$(absolutepathidx "$3" "$index")}"
    ca_cert_out="${3:-$(absolutepathidx "$DC_CA/ca.pem" "$index")}"

    ca_pass="${4:+$([ -s "$4" ] && absolutepath "$4")}"
    no_argon="${6:-false}"

    ca_salt_out="${5:+$(absolutepathidx "$5" "$index")}"
    ca_salt_out="${5:-$([ "$no_argon" = "false" ] \
                        && [ -n "$ca_pass" ] \
                        && absolutepathidx "$DC_CAKEY/ca-key.salt" "$index")}"

    ca_conf_out="${7:+$(absolutepathidx "$7" "$index")}"
    ca_conf_out="${7:-$(absolutepathidx "$DC_CA/ca.conf" "$index")}"

    ca_csr_out="${8:+$(absolutepathidx "$8" "$index")}"
    ca_csr_out="${8:-$(absolutepathidx "$DC_CA/ca.csr" "$index")}"

    keep_ca_csr="${9:-false}"
    intermediate="${10:-false}"
    email="${11:-}"
    country="${12:-}"
    state="${13:-}"
    locality="${14:-}"
    organization="${15:-}"
    orgunit="${16:-}"
    days="${17:-3650}"

    if [ "$intermediate" = "true" ]; then
        root_ca_index="${18:+$(echo "${18}" | sed -e 's/\ /\_/g' -e 's/\-/\_/g' | tr "[:upper:]" "[:lower:]")}"
        root_ca_index="${root_ca_index:-$(jq -r '.ssl.defaultCA // empty' "$DC_DB")}"

        if [ -z "$root_ca_index" ] && [ "$intermediate" = "true" ]; then
            echoe "Root CA Index must be set."
            return 1
        fi

        root_ca_key="${19:+$([ -s "${19}" ] && absolutepath "${19}")}"
        root_ca_key="${root_ca_index:+$(get_value_from_ca_index "$root_ca_index" "key")}"

        root_ca_cert="${20:+$([ -s "${20}" ] && absolutepath "${20}")}"
        root_ca_cert="${root_ca_index:+$(get_value_from_ca_index "$root_ca_index" "cert")}"

        root_ca_pass="${21:+$([ -s "${21}" ] && absolutepath "${21}")}"
        root_no_argon="${23:-false}"

        root_ca_salt="${22:+$([ -s "${22}" ] && absolutepath "${22}")}"
        root_ca_salt="${root_ca_index:+$([ "$root_no_argon" = "false" ] \
                                         && [ -n "$root_ca_pass" ] \
                                         && get_value_from_ca_index "$root_ca_index" "salt")}"
    fi

    set_as_default="${24:-false}"

    echod "Starting create_certificate_authority with parameters:"
    echod "           ca_name: $ca_name"
    echod "       ca_cert_out: $ca_cert_out"
    echod "        ca_key_out: $ca_key_out"
    echod "           ca_pass: $([ -n "$ca_pass" ] && echo "[SET]" || echo "[EMPTY]")"
    echod "       ca_salt_out: $ca_salt_out"
    echod "          no_argon: $no_argon"
    echod "       ca_conf_out: $ca_conf_out"
    echod "        ca_csr_out: $ca_csr_out"
    echod "       keep_ca_csr: $keep_ca_csr"
    echod "      intermediate: $intermediate"
    echod "             email: $email"
    echod "           country: $country"
    echod "             state: $state"
    echod "          locality: $locality"
    echod "      organization: $organization"
    echod "           orgunit: $orgunit"
    echod "              days: $days"
    echod "     ca_serial_out: $ca_serial_out"
    echod "     root_ca_index: $root_ca_index"
    echod "       root_ca_key: $root_ca_key"
    echod "      root_ca_cert: $root_ca_cert"
    echod "     root_no_argon: $root_no_argon"
    echod "      root_ca_pass: $([ -n "$root_ca_pass" ] && echo "[SET]" || echo "[EMPTY]")"
    echod "      root_ca_salt: $([ -n "$root_ca_salt" ] && echo "[SET]" || echo "[EMPTY]")"

    # Validate root CA parameters for intermediate CA
    if [ "$intermediate" = "true" ]; then
        if ! default_ca_exists && [ -z "$root_ca_index" ] && { [ -z "$root_ca_key" ] || [ -z "$root_ca_cert" ]; }; then
            echoe "Root CA name or Root CA key and certificate are required for intermediate CA"
            return 1
        fi
        ca_storage_type="intermediate"
    else
        ca_storage_type="root"
    fi

    # Set default file paths
    ca_cert_dir="$(dirpath "$ca_cert_out")"
    ca_key_dir="$(dirpath "$ca_key_out")"
    ca_conf_dir="$(dirpath "$ca_conf_out")"
    ca_salt_dir="$(dirpath "$ca_salt_out")"
    ca_csr_dir="$(dirpath "$ca_csr_out")"
    ca_serial_out="$(dirpath "$ca_serial_out")"

    for d in "$ca_cert_dir" "$ca_key_dir" "$ca_conf_dir" "$ca_salt_dir" "$ca_csr_dir" "$ca_serial_out"; do
        # Validate directories and fix permissions
        if [ ! -d "$d" ]; then
            echow "Directory $d does not exist"
            mkdir -p "$d" || {
                echoe "Not able to create directory $d"
                return 1
            }
            set_permissions_and_owner "$d" 750
        fi
    done

    # Status
    echod "Final ca_cert_file: $ca_cert_out"
    echod "Final ca_key_file: $ca_key_out"
    echod "Final ca_conf_file: $ca_conf_out"
    [ -n "$ca_salt_out" ] && echod "Final ca_salt_file: $ca_salt_out"
    [ "$intermediate" = "true" ] && echod "Final ca_csr_file: $ca_csr_out"


    # Generate salt if needed
    if [ -n "$ca_pass" ] && [ "$no_argon" = "false" ]; then
      echod "Calling _create_saltfile with $ca_salt_out"
        if ! _create_saltfile "$ca_salt_out"; then
            echoe "Failed to write salt file $ca_salt_out"
            return 1
        fi
        echod "Generated new salt file: $ca_salt_out"
    fi

    # Create SSL config
    echov "Generating SSL configuration..."
    echod "Calling _create_sslconfig with: $ca_storage_type, , $email, $country, $state, $locality, $organization, $orgunit, $ca_name, , $ca_conf_out"
    if ! _create_sslconfig "$ca_storage_type" "$domains,$ips" "$email" "$country" "$state" "$locality" \
        "$organization" "$orgunit" "$ca_name" "" "$ca_conf_out"; then
        echoe "Failed to generate SSL configuration"
        return 1
    fi
    echosv "Creating ssl config file succesful"

    echoi "Creating $ca_storage_type: $ca_name"
    echov "Certificate path: $ca_cert_out"
    echov "Private Key path: $ca_key_out"
    echov "Valid for: $days days"

    # Generate certificate
    if [ "$intermediate" = "false" ]; then
        echoi "Generating self-signed root CA certificate"
        # Create self signed cert and key
        echod "Calling _create_and_verify_sscert with: $ca_key_out, $ca_cert_out, ${ca_pass:-"PASSWORD"}, ${ca_salt_out:+"SALT"}, $ca_conf_out, $no_argon, $days"
        if ! _create_and_verify_sscert "$ca_key_out" "$ca_cert_out" "$ca_pass" "$ca_salt_out" "$ca_conf_out" "$no_argon" "$days"; then
            rm -f -- -- "$ca_key_out" "$ca_cert_out"
            echoe "Failed to generate self-signed CA certificate"
            return 1
        fi
        echosv "Creating self signed certificate and private key successful"
    elif [ "$intermediate" = "true" ]; then
        echoi "Generating intermediate CA certificate signed by $root_ca_index"
        # Create and verify key
        echod "Calling _create_and_verify_key with: $ca_key_out, ${ca_pass:-"PASSWORD"}, ${ca_salt_out:+"SALT"}, $no_argon"
        if ! _create_and_verify_key "$ca_key_out" "$ca_pass" "$ca_salt_out" "$no_argon"; then
            echoe "Failed to generate CA private key"
            return 1
        fi
        echosv "Creating and verifying KEY successful"

        # Create csr and verify
        echod "Calling _create_and_verify_csr with: $ca_csr_out, $ca_key_out, ${ca_pass:-"PASSWORD"}, ${ca_salt_out:+"SALT"}, $ca_conf_out"
        if ! _create_and_verify_csr "$ca_csr_out" "$ca_key_out" "$ca_pass" "$ca_salt_out" "$ca_conf_out"; then
            echoe "Failed to generate CSR for intermediate CA"
            return 1
        fi
        echosv "Creating and verifying CSR successful"

        # Create cert and verify
        echod "Calling _create_and_verify_cert with: $ca_cert_out, $ca_csr_out, $ca_conf_out, $root_ca_key, $root_ca_cert, ${root_ca_pass:-"ROOT CA PASS"}, ${root_ca_salt:-"ROOT_CA_SALT"}, v3_ca, $days"
        if ! _create_and_verify_cert "$ca_cert_out" "$ca_csr_out" "$ca_conf_out" "$root_ca_key" "$root_ca_cert" "$root_ca_pass" "$root_ca_salt" "v3_ca" "$days"; then
            echoe "Failed to sign intermediate CA certificate"
            return 1
        fi
        echosv "Creating and verifying CERT successful"

        if [ "$keep_ca_csr" != "true" ]; then
            rm -f -- -- "$ca_csr_out"
        fi

        # Adding issuer to index dictionary if intermediate
        add_to_ca_database "$ca_storage_type" "$index" "issuer" "$root_ca_index"
    fi

    # Register CA in database
    echod "Registering CA in database..."
    add_to_ca_database "$ca_storage_type" "$index" "key" "$ca_key_out"
    add_to_ca_database "$ca_storage_type" "$index" "cert" "$ca_cert_out"

    # Store name
    add_to_ca_database "$ca_storage_type" "$index" "name" "$ca_name"

    # Store Date
    created=$(date -Iseconds 2>/dev/null || date -u +"%Y-%m-%dT%H:%M:%SZ")
    add_to_ca_database "$ca_storage_type" "$index" "created" "$created"

    # Store validity dates
    valid_from_raw=$(openssl x509 -in "$ca_cert_out" -noout -startdate | sed 's/notBefore=//')
    valid_until_raw=$(openssl x509 -in "$ca_cert_out" -noout -enddate | sed 's/notAfter=//')
    valid_from=$(date -u -d "$valid_from_raw" +"%Y-%m-%dT%H:%M:%SZ" 2>/dev/null || echo "$valid_from_raw")
    valid_until=$(date -u -d "$valid_until_raw" +"%Y-%m-%dT%H:%M:%SZ" 2>/dev/null || echo "$valid_until_raw")
    add_to_ca_database "$ca_storage_type" "$index" "valid_from" "$valid_from"
    add_to_ca_database "$ca_storage_type" "$index" "valid_until" "$valid_until"

    # Store serial
    serial=$(openssl x509 -in "$ca_cert_out" -noout -serial | sed 's/serial=//')
    add_to_ca_database "$ca_storage_type" "$index" "serial" "$serial"

    # Store fingerprint
    fingerprint=$(openssl x509 -in "$ca_cert_out" -noout -fingerprint | sed 's/SHA1 Fingerprint=//')
    add_to_ca_database "$ca_storage_type" "$index" "fingerprint" "$fingerprint"

    # Store salt if was created
    if [ -n "$ca_pass" ] && [ -n "$ca_salt_out" ]; then
        add_to_ca_database "$ca_storage_type" "$index" "salt" "$ca_salt_out"
        add_to_ca_database "$ca_storage_type" "$index" "kdf" "argon2id"
    elif [ -n "$ca_pass" ] && [ -z "$ca_salt_out" ]; then
        add_to_ca_database "$ca_storage_type" "$index" "kdf" "pbkdf2"
    fi

    # Set as default CA if first root CA
    current_default=$(jq -r '.ssl.defaultCA // empty' "$DC_DB")
    if [ "$set_as_default" = "true" ] || { [ -z "$current_default" ] && [ "$ca_storage_type" = "root" ]; }; then
        echod "Setting as default root CA..."
        if jq --arg ca_index "$index" '.ssl.defaultCA = $ca_index' "$DC_DB" > "${DC_DB}.tmp"; then
            mv "${DC_DB}.tmp" "$DC_DB" || {
                echoe "Failed saving database file."
            }
            echod "Successfully set as default CA"
        else
            echoe "Warning: Failed to set as default CA"
            rm -f -- "${DC_DB}.tmp"
        fi
        echoi "Set as default CA: $index"
    fi

    # Display CA information
    ca_subject=$(openssl x509 -in "$ca_cert_out" -noout -subject | sed 's/subject=//')
    ca_issuer=$(openssl x509 -in "$ca_cert_out" -noout -issuer | sed 's/issuer=//')
    echosv ""
    echosv "CA Details:"
    echosv "  Issuer: $ca_issuer"
    echosv "  Subject: $ca_subject"
    echosv "  Serial: $serial"
    echosv "  Valid from: $valid_from"
    echosv "  Valid until: $valid_until"
    echosv ""
    echos "Certificate Authority $ca_name created successfully"
    return 0
}

create_certificate_signing_request() {
    key_name="$1" && [ -z "$key_name" ] && echoe "Key name is required" && return 1
    index="${key_name:+$(echo "$1" | sed -e 's/\ /\_/g' -e 's/\-/\_/g' | tr "[:upper:]" "[:lower:]")}"

    if ! index_exists "$index" ; then
        echow "Normalized $ca_name $index doesn't exist in database. Fallback to fetching from filename..."
    fi

    key_file="${2:+$([ -s "${2}" ] && absolutepath "${2}")}"
    key_file="${index:+$(get_value_from_keys_index "$index" "key")}"

    password="${3:+$([ -s "$3" ] && absolutepath "$3")}"

    salt="${4:+$([ -s "$4" ] && absolutepath "$4")}"
    salt="${index:+$(get_value_from_keys_index "$index" "salt")}"

    csr_out="${5:+$(absolutepathidx "$5" "$index")}"
    csr_out="${5:-$(absolutepathidx "$DC_CERT/cert.csr" "$index")}"

    cfg_out="${6:+$(absolutepathidx "$6" "$index")}"
    cfg_out="${6:-$(absolutepathidx "$DC_CERT/cert.conf" "$index")}"

    type="$([ "$client" = "true" ] && echo "client" || echo "server")"

    domains="$7"
    ips="$8"
    client="${9:-true}"
    server="${10:-false}"
    email="${11}"
    country="${12}"
    state="${13}"
    locality="${14}"
    organization="${15}"
    orgunit="${16}"
    common_name="${17:-${key_name}}"
    crldist="${18}"

    echod "Starting create_certificate_signing_request with parameters:"
    echod "      key_name: $key_name"
    echod "      key_file: $key_file"
    echod "      password: $([ -n "$password" ] && echo "[SET]" || echo "[EMPTY]")"
    echod "          salt: $([ -n "$salt" ] && echo "[SET]" || echo "[EMPTY]")"
    echod "       csr_out: $csr_out"
    echod "       cfg_out: $cfg_out"
    echod "       domains: $domains"
    echod "           ips: $ips"
    echod "        client: $client"
    echod "        server: $server"
    echod "         email: $email"
    echod "       country: $country"
    echod "         state: $state"
    echod "      locality: $locality"
    echod "  organization: $organization"
    echod "       orgunit: $orgunit"
    echod "   common_name: $common_name"
    echod "       crldist: $crldist"
    echod "          user: $DC_USER"

    echod "Validating input parameters"
    # Validate required parameters

    if [ "$server" = "true" ] && [ "$client" = "true" ]; then
        echoe "--server and --client can't be set at the same time"
        return 1
    fi

    if [ -z "$index" ]; then
        echoe "Not able to parse index from DB or files"
        return 1
    fi

    echod "Certificate type set to: $type"

    # Create SSL config
    echoi "Creating SSL configuration for $type certificate"
    echod "Calling _create_sslconfig $type, \"$domains,$ips\" $email $country $state $locality $organization $orgunit $common_name $crldist $cfg_out"
    _create_sslconfig "$type" "$domains,$ips" "$email" "$country" "$state" "$locality" \
        "$organization" "$orgunit" "$common_name" "$crldist" "$cfg_out" || {
            echoe "Failed calling function _create_sslconfig"
            return 1
    }
    echosv "Creating ssl config file successful."

    # Create output directories if necessary
    for d in "$(dirpath "$csr_out")" "$(dirpath "$cfg_out")"; do
        if [ ! -d "$d" ]; then
            echow "Couldn't find output directory: $d"
            echov "Creating output directory: $d"
            mkdir -p "$d" || {
                echoe "Failed to create directory: $d"
                return 1
            }
            set_permissions_and_owner "$d" 750 || {
                echoe "Calling set_permissions_and_owner $d 750 failed."
                return 1
            }
            echosv "Output directory created successfully"
        fi
    done

    echod "Config file $cfg_out exists and is readable"

    # Create CSR
    echoi "Generating Certificate Signing Request"
    echod "Calling _create_and_verify_csr $csr_out $key_file $password $salt $cfg_out"
    _create_and_verify_csr "$csr_out" "$key_file" "$password" "$salt" "$cfg_out" || {
        echoe "Failed calling _create_and_verify_key"
        rm -f -- "$cfg_out" "$csr_out"
        return 1
    }
    echosv "Creating and verifying CSR file succesful"

    # Add CSR to index
    add_to_ssl_keys_database "$index" "csr" "$csr_out"
    add_to_ssl_keys_database "$index" "cfg" "$cfg_out"
    add_to_ssl_keys_database "$index" "type" "$type"

    echos "Created Certificate Signing Request (CSR) successfully"
    return 0
}


sign_certificate_request() {
    csr_name="$1" && [ -z "$1" ] && echoe "CSR name is required" && return 1

    csr_file="${2:+$([ -s "${2}" ] && absolutepath "${2}")}"
    index="${csr_name:+$(echo "$csr_name" | sed -e 's/\-/\_/g' -e 's/\ /\_/g' | tr "[:upper:]" "[:lower:]")}"

    csr_file="${index:+$(get_value_from_keys_index "$index" "csr")}"
    index="${index:-${csr_file:+$(get_index_from_filename "$csr_file")}}"

    if ! index_exists "$index"; then
        echoe "Normalized $csr_name ($index) doesn't exist in database."
        return 1
    fi

    cert_out="${3:+$(absolutepathidx "$3" "$index")}"
    cert_out="${3:-$(absolutepathidx "$DC_CERT/cert.pem" "$index")}"

    ca_index="${4:+$(echo "${4}" | sed -e 's/\ /\_/g' -e 's/\-/\_/g' | tr "[:upper:]" "[:lower:]")}"
    ca_cert_file="${5:+$([ -s "${5}" ] && absolutepath "${5}")}"
    ca_key_file="${6:+$([ -s "${6}" ] && absolutepath "${6}")}"
    ca_pass="${7:+$([ -s "${7}" ] && absolutepath "${7}")}"
    ca_salt="${8:+$([ -s "${8}" ] && absolutepath "${8}")}"

    ca_index="${ca_index:-$(jq -r '.ssl.defaultCA // empty' "$DC_DB")}"
    ca_cert_file="${ca_index:+$(get_value_from_ca_index "$ca_index" "cert")}"
    ca_key_file="${ca_index:+$(get_value_from_ca_index "$ca_index" "key")}"
    ca_salt="${ca_index:+$(get_value_from_ca_index "$ca_index" "salt")}"

    validity_days="${9:-1}"

    keep_csr="${10:-false}"
    keep_cfg="${11:-true}"

    config_file="${12:+$([ -s "${12}" ] && absolutepath "${12}")}"
    config_file="${index:+$(get_value_from_keys_index "$index" "cfg")}"

    fullchain_out="${13:+$(absolutepathidx "${13}" "$index")}"
    fullchain_out="${13:-$(absolutepathidx "${DC_CERT}/fullchain.pem" "$index")}"

    echod "Starting sign_certificate_request with parameters:"
    echod "      csr_name: $csr_name"
    echod "      csr_file: $csr_file"
    echod "   config_file: $config_file"
    echod "       ca_index: $ca_index"
    echod "  ca_cert_file: $ca_cert_file"
    echod "   ca_key_file: $ca_key_file"
    echod "      cert_out: $cert_out"
    echod "       ca_pass: $ca_pass"
    echod " validity_days: $validity_days"
    echod "      keep_csr: $keep_csr"
    echod "      keep_cfg: $keep_cfg"
    echod " fullchain_out: $fullchain_out"
    echod "          user: $DC_USER"

    # Try to parse index from csr_file or get csr_file via index
    if [ -z "$csr_name" ] && [ ! -f "$csr_file" ]; then
        echoe "Either csr_name or csr_file must be set"
        return 1
    fi

    # Validate certificate output directory
    cert_dir="$(dirpath "$cert_out")"
    if [ ! -d "$cert_dir" ]; then
        echov "Creating output directory: $cert_dir"
        mkdir -p "$cert_dir" || {
            echoe "Failed to create directory '$cert_dir'"
            return 1
        }
        echov "Output directory created successfully"
        set_permissions_and_owner "$cert_dir" 750 || {
            echoe "Failed calling set_permissions_and_owner $cert_dir 750"
            return 1
        }
    fi

    # Show config when running in debug
    echod "SSL config contents:"
    echod "$(cat "$config_out" 2>/dev/null || echo "Failed to read $config_out")"

    # Sign the CSR
    echoi "Signing CSR: $csr_file"
    echod "Using CA certificate: $ca_cert_file"
    echod "Using CA key: $ca_key_file"
    echod "Output certificate: $cert_out"
    echod "Validity: $validity_days days"

    echod "Calling _create_and_verify_cert $cert_out $csr_file $config_file $ca_key_file $ca_cert_file $ca_pass $ca_salt"
    _create_and_verify_cert "$cert_out" "$csr_file" "$config_file" "$ca_key_file" \
        "$ca_cert_file" "$ca_pass" "$ca_salt" "req_ext" 1 || {
            echoe "Failed signing CSR and creating certificate"
            return 1
    }
    echosv "Creating and verifying $cert_out successful"

    add_to_ssl_keys_database "$index" "issuer" "$ca_index"
    # Store Date
    add_to_ssl_keys_database "$index" "cert" "$cert_out"
    created=$(date -Iseconds 2>/dev/null || date -u +"%Y-%m-%dT%H:%M:%SZ")
    add_to_ssl_keys_database "$index" "created" "$created"

    # Store validity dates
    valid_from_raw=$(openssl x509 -in "$cert_out" -noout -startdate | sed 's/notBefore=//')
    valid_until_raw=$(openssl x509 -in "$cert_out" -noout -enddate | sed 's/notAfter=//')
    valid_from=$(date -u -d "$valid_from_raw" +"%Y-%m-%dT%H:%M:%SZ" 2>/dev/null || echo "$valid_from_raw")
    valid_until=$(date -u -d "$valid_until_raw" +"%Y-%m-%dT%H:%M:%SZ" 2>/dev/null || echo "$valid_until_raw")
    add_to_ssl_keys_database "$index" "valid_from" "$valid_from"
    add_to_ssl_keys_database "$index" "valid_until" "$valid_until"

    # Store serial & fingerprint
    serial=$(openssl x509 -in "$cert_out" -noout -serial | sed 's/serial=//')
    add_to_ssl_keys_database "$index" "serial" "$serial"
    fingerprint=$(openssl x509 -in "$cert_out" -noout -fingerprint | sed 's/SHA1 Fingerprint=//')
    add_to_ssl_keys_database "$index" "fingerprint" "$fingerprint"

    # Display certificate information
    echoi "Displaying certificate details"
    cert_subject=$(openssl x509 -in "$cert_out" -noout -subject | sed 's/subject=//')
    cert_serial=$(openssl x509 -in "$cert_out" -noout -serial | sed 's/serial=//')
    echoi "  Subject: $cert_subject"
    echoi "  Serial:  $cert_serial"
    openssl x509 -in "$cert_out" -noout -dates | sed 's/^/  /'

    # Show SAN if present
    san=$(openssl x509 -in "$cert_out" -noout -ext subjectAltName 2>/dev/null | grep -A1 "Subject Alternative Name" | tail -n1)
    if [ -n "$san" ]; then
        echoi "  SAN: $san"
    fi

    # Create certificate chain if CA certificate is available
    echoi "Creating certificate chain"
    if _create_and_verify_fullchain "$cert_out" "$fullchain_out"; then
        echosv "Creating and verifying certificate chain file successful"
        add_to_ssl_keys_database "$index" "fullchain" "$fullchain_out"
    else
        echow "Calling _create_and_verify_fullchain $cert_out $fullchain_out failed."
    fi

    # Cleanup CSR and config files based on keep flags
    echov "Cleaning up temporary files"
    if [ "$keep_csr" = "false" ]; then
        file=$(get_value_from_keys_index "$index" "csr")
        rm -f -- "$file"
        if ! delete_key_from_keys_index "$index" "csr"; then
            echoe "Cleaning up after signing failed"
            return 1
        fi
    fi
    if [ "$keep_cfg" = "false" ]; then
        file=$(get_value_from_keys_index "$index" "cfg")
        rm -f -- "$file"
        if ! delete_key_from_keys_index "$index" "cfg"; then
            echoe "Cleaning up after signing failed"
            return 1
        fi
    fi
    echosv "Cleaning up temporary files succesful"

    echos "Certificate creation & signing successful"
    return 0
}


create_cert_chain() {
    cert_file="$1"
    ca_file="$2"
    chain_outfile="${3:-"$DC_CERT/fullchain.pem"}"
    index="${4:-}"

    # Validate input files exist
    if [ ! -s "$cert_file" ]; then
        echoe "Certificate file '$cert_file' does not exist"
        return 1
    fi
    if [ ! -s "$ca_file" ]; then
        echoe "CA file '$ca_file' does not exist"
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

    # Backup existing chain file if it exists
    if [ -f "$chain_outfile" ]; then
        backup_file="${chain_outfile%.*}-backup-$(date +%Y%m%d-%H%M%S).${chain_outfile##*.}"
        cp "$chain_outfile" "$backup_file" || {
            echo "Warning: Failed to backup existing chain file"
        }
        echo "Existing chain file backed up as: $backup_file"
    fi

    # Create fullchain cert (cert first, then CA)
    {
        cat "$cert_file" || {
            echoe "Failed to read certificate file"
            return 1
        }
        echo
        cat "$ca_file" || {
            echoe "Failed to read CA file"
            return 1
        }
    } > "$chain_outfile" || {
        echoe "Failed to create certificate chain"
        return 1
    }

    # Verify the chain is valid
    if ! openssl verify -CAfile "$ca_file" "$cert_file" >/dev/null 2>&1; then
        echow "Warning: Certificate chain may not be valid - verification failed"
    fi

    # Add to index if index parameter provided
    if [ -n "$index" ]; then
        add_to_ssl_keys_database "$index" "fullchain" "$chain_outfile" || {
            echow "Warning: Failed to add chain file to index"
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
    default_ca=$(jq -r '.ssl.defaultCA // empty' "$DC_DB")
    if [ -z "$ca_cert_file" ] || [ -z "$ca_key_file" ]; then
        if [ -n "$default_ca" ] && [ "$default_ca" != "null" ]; then
            echov "Using default CA: $default_ca"
            # Get CA files from the default CA entry
            ca_cert_file="${ca_cert_file:-$(get_storage "ca" "$default_ca" | jq -r '.cert // empty')}"
            ca_key_file="${ca_key_file:-$(get_storage "ca" "$default_ca" | jq -r '.key // empty')}"
        fi
    fi

    # Validate required files exist
    if [ ! -f "$ca_key_file" ]; then
        echoe "CA private key file '$ca_key_file' does not exist"
        if [ -n "$default_ca" ]; then
            echoe "Check if default CA '$default_ca' is properly configured"
        fi
        return 1
    fi

    if [ ! -f "$ca_cert_file" ]; then
        echoe "CA certificate file '$ca_cert_file' does not exist"
        if [ -n "$default_ca" ]; then
            echoe "Check if default CA '$default_ca' is properly configured"
        fi
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
    ca_index=$(find "cert" "$ca_cert_file")
    if [ -z "$ca_index" ]; then
        ca_index=$(find_name_by_key_value "key" "$ca_key_file")
        if [ -z "$ca_index" ]; then
            echoe "Can't find CA index: $ca_index"
        fi
    fi

    # Handle file naming like create_private_key does
    if [ -f "$crl_outfile" ]; then
        echo "CRL file already exists. Changing name to... "
        crl_outfile="${crl_outfile%.*}-${RAND}.${crl_outfile##*.}"
        basename "$crl_outfile"
    fi


    # First check if config already exists in index
    config_file=$(get_value_from_index "$ca_index" "cfg")

    # Create SSL config only if no existing config found and ssl_cfg is empty
    if [ -z "$config_file" ] || [ ! -f "$config_file" ]; then
        # Create temporary config file and add to index
        echoe "Couldn't find ssl_config file: $config_file"
    fi

    # In case user wants to keep cfg file after CRL generation
    if [ -n "$config_file" ] && [ -f "$config_file" ]; then
        echo "Config file already exists. Backing up old one..."
        backup_and_rename "cfg" "$ca_index" "$config_file" || {
            echoe "Failed to backup existing config file"
            return 1
        }
    fi

    add_to_ssl_keys_database "$ca_index" "cfg" "$config_file"

    # Initialize OpenSSL CA database files if they don't exist
    index_txt="$DC_DIR/index.txt"
    crlnumber_file="$DC_DIR/crlnumber"

    if [ ! -f "$index_txt" ]; then
        touch "$index_txt"
        chmod 600 "$index_txt"
    fi

    if [ ! -f "$crlnumber_file" ]; then
        echo "01" > "$crlnumber_file"
        chmod 600 "$crlnumber_file"
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

            salt_file="$(get_value_from_index "$ca_index" "salt")"

            if [ ! -f "$salt_file" ]; then
                echoe "Salt file $salt_file does not exist"
                rm -f -- "$config_file"
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
                echoe "Failed to generate CRL with encrypted key"
                rm -f -- "$config_file"
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
                rm -f -- "$config_file"
                return 1
            }
        fi

        # Set permissions

        # Add CRL to index
        add_to_ssl_keys_database "$ca_index" "crl" "$crl_outfile"

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


_revoke_certificate() {
    cert_file="$1"
    ca_key_file="$2"
    ca_cert_file="$3"
    pass="$4"
    salt="$5"
    reason="$6"

    # Check for default CA in index.json if CA files not provided
    if [ -z "$ca_cert_file" ] || [ -z "$ca_key_file" ]; then
        default_ca=$(jq -r '.ssl.defaultCA // empty' "$DC_DB")
        if [ -n "$default_ca" ] && [ "$default_ca" != "null" ]; then
            echov "Using default CA: $default_ca"
            ca_cert_file="${ca_cert_file:-$(get_storage "ca" "$default_ca" | jq -r '.cert // empty')}"
            ca_key_file="${ca_key_file:-$(get_storage "ca" "$default_ca" | jq -r '.key // empty')}"
        fi
    fi

    # Set defaults
    ca_key_file="${ca_key_file:-$(absolutepath "$DC_CA/ca-key.pem")}"
    ca_cert_file="${ca_cert_file:-$(absolutepath "$DC_CA/ca.pem")}"

    # Find CA index and config
    ca_index=$(find_name_by_key_value "cert" "$ca_cert_file")
    if [ -z "$ca_index" ]; then
        ca_index=$(find_name_by_key_value "key" "$ca_key_file")
    fi

    # Look for existing config files
    config_file=$(get_value_from_index "$ca_index" "cfg")

    if [ -z "$config_file" ] || [ ! -f "$config_file" ]; then
        echoe "No CA config file found for revocation"
        echo "Run create-crl first to generate the necessary config"
        return 1
    fi

    (
        if [ -n "$pass" ] && [ "$no_argon" = "false" ]; then
            # Generate derived key for decryption
            echod "Calling _create_argon2id_derived_key_pw pass salt | openssl ca ..."
            _create_argon2id_derived_key_pw "$pass" "$salt" | \
            openssl ca \
                    -revoke "$cert_file" \
                    -keyfile "$ca_key_file" \
                    -cert "$ca_cert_file" \
                    -config "$config_file" \
                    -crl_reason "$reason" \
                    -passin "stdin" 2>/dev/null || {
                echoe "Failed to revoke certificate (with encrypted key)"
                return 1
            }
        elif [ -n "$pass" ] && [ "$no_argon" = "true" ]; then
            echod "Calling _create_pbkdf2_derived_key_pw pass salt | openssl ca ..."
            _create_pbkdf2_derived_key_pw "$pass" | \
            openssl ca \
                    -revoke "$cert_file" \
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
            echod "Calling openssl ca ..."
            openssl ca \
                -revoke "$cert_file" \
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
    echod "Subshell for certificate revocation exited with status: $status"
    if [ "$status" -eq 0 ]; then
        return 0
    fi
    return 1
}

verify_certificate() {
    cert_file="$1"
    ca_cert="$2"
    check_expiry="$3"

    # Validate input files exist
    if [ ! -f "$cert_file" ]; then
        echoe "Certificate file '$cert_file' does not exist"
        return 1
    fi

    if [ ! -f "$ca_cert" ]; then
        echoe "CA certificate file '$ca_cert' does not exist"
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

        echov ""
        echowv "Certificate Subject: $cert_subject"
        echowv "Certificate Issuer:  $cert_issuer"
        echowv "CA Subject:          $ca_subject"
    fi
}


# TODO: Finish SSL encrypt and decrypt functions
ssl_encrypt() (
    input="$1"
    output="${2:-stdout}"
    password="$3"
    asymmetric="${4:-false}"

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

        # 2. Encrypt the data to a temporary file, piping the derived key directly.
        echo "Info: Performing asymmetric encryption."
        if ! { _create_argon2id_derived_key_pw "$password" "$salt" | openssl aes-256-cbc -e -pbkdf2 -in "$input" -out "$output" -password stdin; }; then
            echoe "Symmetric encryption failed. This could be a KDF or an OpenSSL error."
            return 1
        fi

        # 3. Combine salt and ciphertext into the final output file.
        printf "%s" "$salt" > "$chain_out"

    else

        if [ -n "$password" ]; then
             echowv "Warning: --password is ignored for symmetric encryption."
        fi

        if [ -z "$cert_file" ]; then

            default_ca_cert=$(jq -r '.ssl.ca[] | select(.default == true) | .cert' "$DCRYPTO_IDX" 2>/dev/null)
            if [ -z "$default_ca_cert" ]; then
                echoe "--cert was not specified and no default CA was found."
                echoe "Use --cert <file> or set a default CA with the 'set-default-ca' command."
                return 1
            fi
            echov "Info: Using default CA certificate: $default_ca_cert"
            cert_file="$default_ca_cert"
        fi

        if [ ! -f "$cert_file" ] || [ ! -f "$input" ]; then
            echoe "Certificate or input file not found."
            return 1
        fi

        if ! openssl pkeyutl -encrypt -pubin -inkey "$cert_file" -in "$input" -out "$chain_out"; then
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

    if [ -z "$input" ] || [ -z "$chain_out" ]; then
        echoe "--in and --out are required for decrypt"
        exit 1
    fi

    if [ "$asymmetric" = "false" ]; then
        # --- Symmetric Decryption ---
        if [ -z "$password" ]; then
            echoe "--password is required for asymmetric decryption (--asymmetric)."
            return 1
        fi

        # 1. Extract the salt from the beginning of the file.
        salt=$(head -c 32 "$input")
        if [ "$(printf "%s" "$salt" | wc -c)" -ne 32 ]; then
            echoe "Could not extract a valid 32-character salt from the input file."
            return 1
        fi

        # 2. Decrypt, piping the derived key from the KDF directly to OpenSSL.
        if ! { _create_argon2id_derived_key_pw "$password" "$salt" | openssl enc -d -aes-256-cbc -pbkdf2 -in "" -out "$chain_out" -password stdin; }; then
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
                echoe "Use --key <file> or set a default CA with the 'set-default-ca' command."
                return 1
            fi
            echo "Info: Using default CA private key: $default_ca_key"
            key_file="$default_ca_key"
        fi

        if [ ! -f "$key_file" ] || [ ! -f "$input" ]; then
            echoe "Private key or input file not found."
            return 1
        fi

        # The decryption command depends on whether a password is provided for the key.
        if [ -n "$password" ]; then
            # Pipe the output of the KDF directly to OpenSSL for the key's password.
            # Note: This assumes the private key was created using a password processed by the same KDF.
            if ! { _create_argon2id_derived_key_pw "$password" | \
                   openssl pkeyutl -decrypt -inkey "$key_file" -in "$input" -out "$chain_out" -passin stdin; }; then
                echoe "Asymmetric decryption failed. Check your private key and password."
                return 1
            fi
        else
            # No password provided for the key.
            if ! openssl pkeyutl -decrypt -inkey "$key_file" -in "$input" -out "$chain_out"; then
                echoe "Asymmetric decryption failed. Check your private key."
                return 1
            fi
        fi
    fi
)



import_ssl() {
    name="${1:-}"
    index="${name:+$(echo "$name" | sed -e 's/\ /\_/g' -e 's/\-/\_/g' | tr "[:upper:]" "[:lower:]")}"

    import="${2:+$(absolutepath "$2")}"
    scan_depth="${3:-1}"
    copy_files="${4:-true}"
    move_files="${5:-false}"

    echod "Starting import_ssl with parameters:"
    echod "           import: $import"
    echod "       scan_depth: $scan_depth"
    echod "       copy_files: $copy_files"
    echod "       move_files: $move_files"
    echod "             user: $DC_USER"

    : "${filecount:=0}"

    if [ -z "$index" ]; then
        echow "Index must be set for import files. Falling back to random value."
        index="$RAND"
    fi

    if [ "$copy_files" = "true" ] && [ "$move_files" = "true" ]; then
        echoe "--copy-files and --move-files can't be set both as parameter"
        return 1
    fi

    if [ ! -f "$import" ] && [ ! -d "$import" ]; then
        echoe "--import must be either a directory or file"
        return 1
    fi

    if [ -f "$import" ]; then
        echod "Importing file at $import"
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
            filepath="$(absolutepath "$file")"
            filename="$(basename "$file")"
            dirpath="$(dirname "$filepath")"
            ftype="$(get_file_type "$filepath")"

            if [ "$ftype" = "root" ] || [ "$ftype" = "intermediate" ]; then
                ca_issuer=$(openssl x509 -in "$ca_cert_file" -noout -issuer | sed 's/issuer=//')
                ca_cn=$(echo "$ca_issuer" | sed -n 's/.*CN=\([^,]*\).*/\1/p' | sed 's/^ *//;s/ *$//')
                ca_index="$(echo "$ca_cn" | sed -e 's/\ /\_/g' -e 's/\-/\_/g' | tr "[:upper:]" "[:lower:]")"
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
                add_to_ca_database "$ca_type" "$ca_index" "$ftype" "$dirpath/$filename"
                echosv "Imported file $dirpath/$filename into database"
                filecount=$(("$filecount" + 1))
            elif [ -n "$ftype" ]; then
                echod "Importing file into database:"
                echod "Name/Index: $RAND Type: $ftype Path: $dirpath/$filename"
                add_to_ssl_keys_database "$RAND" "$ftype" "$dirpath/$filename"
                echosv "Imported file $dirpath/$filename into database"
                filecount=$(("$filecount" + 1))
            else
                echow "Was not able to identify file: $dirpath/$filename"
            fi
        done
    fi
    echos "Importing files successful. Imported $filecount files."
}

renew_certificate() {
    echo
}



set_as_default_CA() {
    index="$1"

    echod "Starting set_as_default_CA with parameters:"
    echod " index: $index"

    # Check index exists in database
    if ! index_exists "$index"; then
        echoe "Index: $index not found in database."
        return 1
    fi
    jq -r --arg idx "$index" '.ssl.defaultCA = $idx' "$DC_DB" > "${DC_DB}.tmp" || {
        echoe "Setting $index as defaultCA failed"
        rm -f -- "${DC_DB}.tmp"
        return 1
    }

    mv "${DC_DB}.tmp" "$DC_DB" || {
        echoe "Overwriting database with temporary db failed"
        rm -f -- "${DC_DB}.tmp"
        return 1
    }

    echos "Setting $index as dcrypto's .ssl.defaultCA succesful"
    return 0
}

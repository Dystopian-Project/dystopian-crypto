# shellcheck shell=sh
# shellcheck disable=SC2001
# shellcheck disable=SC2154


_gpg_export_public() {
    fingerprint="$1"
    key_id=${fingerprint:20}
    out_path="$2"
    no_armor="$3"
    homedir="${4:-$DC_GNUPG}"
    with_subs="$5"

    echod "Starting _gpg_export_public with parameters:"
    echod " fingerprint: $fingerprint"
    echod "      key_id: $key_id"
    echod "    out_path: $out_path"
    echod "    no_armor: $no_armor | $3"
    echod "     homedir: $homedir"
    echod "   with_subs: $with_subs | $5"

    echod "Building gpg command..."
    gpg_build_cmd "$homedir" "exp" "$with_subs" "$no_armor"
    echod "Calling ${gpg_cmd} \"$fingerprint\" > \"$out_path\""
    if ! $gpg_cmd "$fingerprint" > "$out_path"; then
        echoe "Failed exporting all subkeys with primary"
        return 1
    fi

    if [ ! -s "$out_path" ] ; then
        echoe "Failed exporting Public Key to $out_path"
        rm -f "$out_path"
        return 1
    fi

    set_permissions_and_owner "$out_path" 444
    return 0
}


_gpg_export_secret_primary() {
    fingerprint="$1"
    out_path="$2"
    passphrase="$3"
    no_armor="$4"
    homedir="${5:-$DC_GNUPG}"
    with_ssbs="$6"
    openssl_encrypt="${7:-true}"
    passphrasedbg=$({ [ "$3" = "gui" ] || [ "$3" = "GUI" ]; } && echo "[GUI]")
    passphrasedbg=$([ -n "$3" ]  && [ ! -f "$3" ] && echo "[SET]" || echo "$3")

    echod "Starting _gpg_export_secret_primary with parameters:"
    echod "fingerprint: $fingerprint"

    echod "   out_path: $out_path"
    echod " passphrase: $passphrasedbg"
    echod "   no_armor: $no_armor | $4"
    echod "    homedir: $homedir"
    echod "  with_ssbs: $with_ssbs | $6"
    echod "ssl_encrypt: $openssl_encrypt"

    echod "Building gpg command..."
    gpg_build_cmd "$homedir" "expsec" "$with_subs" "$no_armor" "$passphrase"

    # Use GUI to ask for passphrase
    if [ "$passphrase" = "gui" ] || [ "$passphrase" = "GUI" ]; then
        printf "\033[1m\033[1;33m>\033[0m\033[1m Enter passphrase:\033[0m "
        stty -echo
        read -r openssl_passphrase
        stty echo
        printf "\n"

        if [ "$openssl_encrypt" = "true" ]; then
            echod "Calling $gpg_cmd \"$fingerprint\" | openssl aes-256-cbc -e -pbkdf2 -pass \"pass:$passphrasedbg\" -out \"$out_path\""
            $gpg_cmd "$fingerprint" | \
            openssl aes-256-cbc -e -pbkdf2 -pass pass:"$openssl_passphrase" -out "$out_path"
        else
            echod "Calling $gpg_cmd \"$fingerprint\" > \"$out_path\""
            $gpg_cmd "$fingerprint" > "$out_path"
        fi
        unset openssl_passphrase

    # No passphrase at all
    elif [ -z "$passphrase" ]; then
        echod "Calling printf \"%s\" \"\" | $gpg_cmd \"$fingerprint\" > \"$out_path\""
        printf "%s" "" | $gpg_cmd "$fingerprint" > "$out_path"

    # Passphrase from parameter
    elif [ -n "$passphrase" ] && [ ! -f "$passphrase" ]; then
        if [ "$openssl_encrypt" = "true" ]; then
            echod "Calling printf \"%s\" \"$passphrasedbg\" | $gpg_cmd \"$fingerprint\" | openssl aes-256-cbc -e -pbkdf2 -pass \"pass:$passphrasedbg\" -out \"$out_path\""
            printf "%s" "$passphrase" | $gpg_cmd "$fingerprint" | \
            openssl aes-256-cbc -e -pass "pass:$passphrase" -pbkdf2 -out "$out_path"
        else
            echod "Calling printf \"%s\" \"$passphrasedbg\" | $gpg_cmd \"$fingerprint\" > \"$out_path\""
            printf "%s" "$passphrase" | $gpg_cmd "$fingerprint" > "$out_path"
        fi

    # Passphrase from file
    elif [ -s "$passphrase" ]; then
        if [ "$openssl_encrypt" = "true" ]; then
            echod "Calling $gpg_cmd \"$fingerprint\" | openssl aes-256-cbc -e -pbkdf2 -k \"$passphrasedbg\" -out \"$out_path\""
            $gpg_cmd "$fingerprint" | openssl aes-256-cbc -e -k "$passphrase" -pbkdf2 -out "$out_path"

        else
            echod "Calling $gpg_cmd \"$fingerprint\" > \"$out_path\""
            $gpg_cmd "$fingerprint" > "$out_path"
        fi
    fi

    if [ ! -s "$out_path" ]; then
        echoe "Failed exporting Secret Key to $out_path"
        return 1
    fi

    set_permissions_and_owner "$out_path" 440
    return 0
}


# Exports dummy primary and either all or one ssb
_gpg_export_secret_ssb_with_dummy() {
    fingerprint="${1}"
    key_id="${fingerprint:20}"
    out_path="$2"
    no_armor="$3"
    homedir="${4:-$DC_GNUPG}"
    with_subkeys="$5"
    openssl_encrypt="$6:-true}"
    passphrase="$7"
    passphrasedbg=$({ [ "$7" = "gui" ] || [ "$7" = "GUI" ]; } && echo "[GUI]")
    passphrasedbg=$([ -n "$7" ]  && [ ! -f "$7" ] && echo "[SET]" || echo "$7")

    if [ "$with_subkeys" = "false" ]; then
        fingerprint="${fingerprint}!"
        key_id="${key_id}!"
    fi

    echod "Starting _gpg_export_secret_ssb_with_dummy with parameters:"
    echod "   fingerprint: $fingerprint"
    echod "        key_id: $key_id"
    echod "      out_path: $out_path"
    echod "      no_armor: $no_armor"
    echod "       homedir: $homedir"
    echod "    passphrase: $passphrasedbg"
    echod "   ssl_encrypt: $openssl_encrypt"
    echod "  with_subkeys: $with_subkeys"

    if [ -z "$passphrase" ]; then
        echoe "Can't export dummy primary & subkeys without passphrase"
        return 1
    fi

    echod "Building gpg command..."
    gpg_build_cmd "$homedir" "expsecsub" "$with_subs" "$no_armor" "$passphrase"

    # Use GUI to ask for passphrase
    if [ "$passphrase" = "gui" ] || [ "$passphrase" = "GUI" ]; then
        printf "\033[1m\033[1;33m>\033[0m\033[1m Enter passphrase:\033[0m "
        stty -echo
        read -r openssl_passphrase
        stty echo
        printf "\n"

        if [ "$openssl_encrypt" != "true" ]; then
            echod "Calling $gpg_cmd \"$fingerprint\" > \"$out_path\""
            if ! $gpg_cmd "$fingerprint" > "$out_path"; then
                echoe "Failed exporting all ssbkeys with dummy"
                return 1
            fi
        else
            echod "Calling gpg --homedir \"$homedir\" $no_armor --export-secret-subkeys $with_subkeys \"$fingerprint\" | openssl aes-256-cbc -e -pbkdf2 -pass pass:$passphrasedbg -out \"$out_path\""
            if ! $gpg_cmd "$fingerprint" | \
                 openssl aes-256-cbc -e -pbkdf2 -pass pass:"${openssl_passphrase}" -out "$out_path"; then
                echoe "Failed exporting all ssbkeys with dummy"
                return 1
            fi
        fi
        unset openssl_passphrase

    # No passphrase at all
    elif [ -z "$passphrase" ]; then
        echod "Calling printf \"%s\" \"\" | $gpg_cmd \"$fingerprint\" > \"$out_path\""
        if ! printf "%s" "" | $gpg_cmd "$fingerprint" > "$out_path"; then
            echoe "Failed"
            return 1
        fi

    # Passphrase from parameter
    elif [ -n "$passphrase" ] && [ ! -f "$passphrase" ]; then
        if [ "$openssl_encrypt" != "true" ]; then
            echod "Calling printf \"%s\" \"$passphrasedbg\" | $gpg_cmd \"$fingerprint\" > \"$out_path\""
            if ! printf "%s" "$passphrase" | $gpg_cmd "$fingerprint" > "$out_path"; then
                echoe "Failed"
                return 1
            fi
        else
            echod "Calling printf \"%s\" \"$passphrasedbg\" | $gpg_cmd \"$fingerprint\" | openssl aes-256-cbc -e -pbkdf2 -pass pass:$passphrasedbg -out \"$out_path\""
            if ! printf "%s" "$passphrase" | $gpg_cmd "$fingerprint" | \
                 openssl aes-256-cbc -e -pbkdf2 -pass pass:"${passphrase}" -out "$out_path"; then
                echoe "Failed"
                return 1
            fi
        fi

    # Passphrase from file
    elif [ -s "$passphrase" ]; then
        if [ "$openssl_encrypt" != "true" ]; then
            echod "Calling $gpg_cmd \"$fingerprint\" > \"$out_path\""
            if ! $gpg_cmd "$fingerprint" > "$out_path"; then
                echoe "Failed exporting dummy primary with all ssbs."
                return 1
            fi
        else
            echod "Calling $gpg_cmd \"$fingerprint\" | openssl aes-256-cbc -e -pbkdf2 -k \"$passphrase\" -out \"$out_path\""
            if ! $gpg_cmd "$fingerprint" | openssl aes-256-cbc -e -pbkdf2 -k "$passphrase" -out "$out_path"; then
                echoe "Failed exporting dummy primary with all ssbs."
                return 1
            fi
        fi
    fi
    set_permissions_and_owner "$out_path" 440
    return 0
}


_gpg_create_primary_key() {
    uid="$1"
    passphrase="$2"
    homedir="$3"
    expiry_date="$4"
    usage="${5:-cert,sign}"
    passphrasedbg=$({ [ "$2" = "gui" ] || [ "$2" = "GUI" ]; } && echo "[GUI]")
    passphrasedbg=$([ -n "$2" ]  && [ ! -f "$2" ] && echo "[SET]" || echo "$2")

    echod "Starting _gpg_create_primary_key with parameters:"
    echod "           uid: $uid"
    echod "    passphrase: $passphrasedbg"
    echod "       homedir: $homedir"
    echod "   expiry_date: $expiry_date"
    echod "         usage: $usage"

    echod "Building gpg command..."
    gpg_build_cmd "$homedir" "gen" "" "" "$passphrase"

    # Use GUI to ask for passphrase
    if [ "$passphrase" = "gui" ] || [ "$passphrase" = "GUI" ]; then
        echod "Calling $gpg_cmd \"$uid\" \"ed25519\" \"$usage\" \"$expiry_date\""
        $gpg_cmd "$uid" "ed25519" "$usage" "$expiry_date" 2>&1

    # No passphrase at all
    elif [ -z "$passphrase" ]; then
        echoe "TEST"
        echod "Calling printf \"\" | $gpg_cmd \"$uid\" \"ed25519\" \"$usage\" \"$expiry_date\""
        printf "%s" "" | $gpg_cmd "$uid" "ed25519" "$usage" "$expiry_date" 2>&1

    # Passphrase from cmdline
    elif [ -n "$passphrase" ] && [ ! -f "$passphrase" ]; then
        echoe "CMDLINE"
        echod "Calling printf \"%s\" \"$passphrasedbg\" | $gpg_cmd \"$uid\" \"ed25519\" \"$usage\" \"$expiry_date\""
        printf "%s" "$passphrase" | $gpg_cmd "$uid" "ed25519" "$usage" "$expiry_date" 2>&1

    # Passphrase from file
    elif [ -s "$passphrase" ]; then
      echoe "FILE"
        echod "Calling $gpg_cmd \"$uid\" \"ed25519\" \"$usage\" \"$expiry_date\""
        $gpg_cmd "$uid" "ed25519" "$usage" "$expiry_date" 2>&1
    fi

    # shellcheck disable=SC2181
    if [ "$?" -ne 0 ]; then
        echoe "Generating primary keypair failed."
        return 1
    fi

    created_fp=$(gpg --homedir "$homedir" \
                     --list-keys | \
                     grep -B1 "$uid" | \
                     head -n 1 | \
                     sed 's/\ //g')
    return 0
}


_gpg_add_subkey() {
    primary_key_id="$1"
    passphrase="$2"
    homedir="$3"
    curve="$4"
    usage="$5"
    expiry_date="$6"
    uid="$7"
    passphrasedbg=$({ [ "$2" = "gui" ] || [ "$2" = "GUI" ]; } && echo "[GUI]")
    passphrasedbg=$([ -n "$2" ]  && [ ! -f "$2" ] && echo "[SET]" || echo "$2")

    echod "Starting _gpg_add_subkey with parameters:"
    echod " primary_key_id: $primary_key_id"
    echod "     passphrase: $passphrasedbg"
    echod "        homedir: $homedir"
    echod "          curve: $curve"
    echod "          usage: $usage"
    echod "    expiry_date: $expiry_date"
    echod "            uid: $uid"

    echod "Add UID: gpg --batch --homedir \"$homedir\" --quick-add-uid \"$fingerprint\" \"$uid\""
    gpg --batch --homedir "$homedir" --quick-add-uid "$fingerprint" "$uid" 2>&1

    echod "Trust UID: printf \"trust\n5\ny\nsave\" | gpg --homedir \"$homedir\" --command-fd 0 --edit-key \"$primary_key_id\" 2>&1"
    printf "trust\n5\ny\nsave\n" | gpg --batch --homedir "$homedir" --command-fd 0 --edit-key "$primary_key_id" 2>/dev/null


    # Use GUI to ask for passphrase
    if [ "$passphrase" = "gui" ] || [ "$passphrase" = "GUI" ]; then
        echod "Add $usage Key: $gpg_cmd \"$primary_key_id\" \"$curve\" \"$usage\" \"$expiry_date\""
        $gpg_cmd "$primary_key_id" "$curve" "$usage" "$expiry_date" 2>&1

    # No passphrase at all
    elif [ -z "$passphrase" ]; then
        echod "Add $usage Key: printf \"%s\" \"\" | $gpg_cmd \"$primary_key_id\" \"$curve\" \"$usage\" \"$expiry_date\""
        printf "%s" "" | $gpg_cmd "$primary_key_id" "$curve" "$usage" "$expiry_date" 2>&1

    # Read pass from cmdline
    elif [ -n "$passphrase" ] && [ ! -f "$passphrase" ]; then
        echod "Add $usage Key: printf \"%s\" \"$passphrasedbg\" | gpg --batch --homedir \"$homedir\" --pinentry-mode loopback --passphrase-fd 0 --quick-add-key \"$primary_key_id\" \"$curve\" \"$usage\" \"$expiry_date\""
        printf "%s" "$passphrase" | $gpg_cmd "$primary_key_id" "$curve" "$usage" "$expiry_date" 2>&1

    # Read pass from file
    elif [ -s "$passphrase" ]; then
        echod "Add $usage Key: $gpg_cmd \"$primary_key_id\" \"$curve\" \"$usage\" \"$expiry_date\""
        $gpg_cmd "$primary_key_id" "$curve" "$usage" "$expiry_date" 2>&1
    fi

    # shellcheck disable=SC2181
    if [ "$?" -ne 0 ]; then
        echoe "Adding subkey pair failed."
        return 1
    fi

    # Getting subkey fingerprint
    echod "Getting subkey fingerprint"
    sub_fingerprint=$(gpg --homedir "$homedir" --list-keys --with-subkey-fingerprints "$fingerprint" | \
      grep -A 1 sub | \
      tail -1 | \
      sed 's/\ //g')

    return 0
}


gpg_create_keypair() {
    name_real="$1"
    passphrase="$2"
    name_email="${3:+<$3>}"
    name_comment="${4:+ ($4)}"
    expiry_date="${5:-2y}"
    homedir="${6:-$DC_GNUPG}"
    sign="${7:-false}"
    auth="${8:-false}"
    encrypt="${9:-false}"
    index="${10:-${name_real:+$(echo "$name_real" | sed -e 's/\-/\_/g' -e 's/\ /\_/g' | tr "[:upper:]" "[:lower:]")}}"
    no_subs="${11:-false}"

    sname_real="${12:-$name_real}"
    sname_email="${13:+<${13}>}"
    sname_email="${13:-$name_email}"
    sname_comment="${14:+ (${14})}"
    sname_comment="${14:-$name_comment}"
    sexpiry_date="${15:-$expiry_date}"
    spassphrase="${16:-passphrase}"

    ename_real="${17:-$name_real}"
    ename_email="${18:+<${18}>}"
    ename_email="${18:-$name_email}"
    ename_comment="${19:+ (${19})}"
    ename_comment="${19:-$name_comment}"
    eexpiry_date="${20:-$expiry_date}"
    epassphrase="${21:-$passphrase}"

    aname_real="${22:-$name_real}"
    aname_email="${23:+<${23}>}"
    aname_email="${23:-$name_email}"
    aname_comment="${24:+ (${24})}"
    aname_comment="${24:-$name_comment}"
    aexpiry_date="${25:-$expiry_date}"
    apassphrase="${26:-$passphrase}"

    passphrasedbg="$({ [ "$2" = "gui" ] || [ "$2" = "GUI" ]; } && echo "[GUI]")"
    passphrasedbg=$([ -n "$2" ]  && [ ! -f "$2" ] && echo "[SET]" || echo "$2")
    spassphrasedbg="$({ [ "${16}" = "gui" ] || [ "${16}" = "GUI" ]; } && echo "[GUI]")"
    spassphrasedbg=$([ -n "${16}" ]  && [ ! -f "${16}" ] && echo "[SET]" || echo "${16}")
    apassphrasedbg="$({ [ "${21}" = "gui" ] || [ "${21}" = "GUI" ]; } && echo "[GUI]")"
    epassphrasedbg=$([ -n "${21}" ]  && [ ! -f "${21}" ] && echo "[SET]" || echo "${21}")
    apassphrasedbg="$({ [ "${26}" = "gui" ] || [ "${26}" = "GUI" ]; } && echo "[GUI]")"
    apassphrasedbg=$([ -n "${26}" ]  && [ ! -f "${26}" ] && echo "[SET]" || echo "${26}")

    echod "Starting gpg_create_keypair with parameters:"
    echod "     name_real: $name_real"
    echod "    name_email: $name_email"
    echod "  name_comment: $name_comment"
    echod "    passphrase: $passphrasedbg"
    echod "   expiry_date: $expiry_date"
    echod "       homedir: $homedir"
    echod "          sign: $sign"
    echod "          auth: $auth"
    echod "       encrypt: $encrypt"
    echod "         index: $index"
    echod "       no_subs: $no_subs"

    echod "    sname_real: $sname_real"
    echod "   sname_email: $sname_email"
    echod " sname_comment: $sname_comment"
    echod "  sexpiry_date: $sexpiry_date"
    echod "   spassphrase: $spassphrasedbg"

    echod "    ename_real: $ename_real"
    echod "   ename_email: $ename_email"
    echod " ename_comment: $ename_comment"
    echod "  eexpiry_date: $eexpiry_date"
    echod "   epassphrase: $epassphrasedbg"

    echod "    aname_real: $aname_real"
    echod "   aname_email: $aname_email"
    echod " aname_comment: $aname_comment"
    echod "  aexpiry_date: $aexpiry_date"
    echod "   apassphrase: $apassphrasedbg"

    if [ -z "$name_real" ] || [ -z "$name_email" ]; then
        echoe "name or email can not be empty."
        return 1
    fi

    # Check if index exists
    if gpg_index_exists "$index"; then
        echow "Primary Key already exists. "
        oldidx="$index"
        newindex=""
        n=1
        if askyesno "Do you want to set a new index? (No will add random value to index)" "y"; then
            while true; do
                printf "\033[1m\033[1;33m>\033[0m\033[1m Enter new index:\033[0m "
                read -r newindex
                if gpg_index_exists "$newindex"; then
                    echow "Primary Key already exists."
                else
                    break
                fi
            done
        else
            while gpg_index_exists "$newindex"; do
                newindex="${index}_$n"
                n=$((n + 1))
            done
        fi
        echoi "Changed index from $oldidx to $newindex"
        index="$newindex"
    fi

    if [ "$no_subs" = "true" ] && [ "$encrypt" = "false" ]; then
        astr=$([ "$auth" = "true" ] && echo ",auth" || echo "")
        usage="cert,sign$astr"
    else
        usage="cert,sign"
    fi

    # Create primary key
    echoi "Creating primary key:"
    uid="$name_real$name_comment $name_email"
    echod "Calling _gpg_create_primary_key \"$uid\" \"$passphrasedbg\" \"$homedir\" \"$expiry_date\" \"$usage\""
    _gpg_create_primary_key "$uid" "$passphrase" "$homedir" "$expiry_date" "$usage"
    echosv "Creating primary key successful"

    fingerprint="$created_fp"
    # Add key to database
    echod "Adding GPG primary key to database:"
    add_to_gpg_database "$index" "uid" "$uid"
    add_to_gpg_database "$index" "fingerprint" "$fingerprint"
    add_to_gpg_database "$index" "keyId" "${fingerprint:20}"
    add_to_gpg_database "$index" "expires" "$expiry_date"
    add_to_gpg_database "$index" "usage" "$usage"
    add_to_gpg_database "$index" "name_real" "$name_real"


    # Add subkey to primary key if set
    if [ "$no_subs" = "false" ] && [ "$sign" = "true" ]; then
        suid="$sname_real$sname_comment $sname_email"
        echod "Calling _gpg_add_subkey \"$fingerprint\" \"$spassphrasedbg\" \"$homedir\" \"ed25519\" \"sign\" \"$sexpiry_date\" \"$suid\""
        _gpg_add_subkey "$fingerprint" "$spassphrase" "$homedir" "ed25519" "sign" "$sexpiry_date" "$suid"
        echosv "Adding subkey for signing successful."
        add_to_gpg_subkeys "$index" "${sub_fingerprint:20}" "usage" "sign"
        add_to_gpg_subkeys "$index" "${sub_fingerprint:20}" "fingerprint" "$sub_fingerprint"
        add_to_gpg_subkeys "$index" "${sub_fingerprint:20}" "expires" "$sexpiry_date"
        add_to_gpg_subkeys "$index" "${sub_fingerprint:20}" "uid" "$suid"
        add_to_gpg_subkeys "$index" "${sub_fingerprint:20}" "name_real" "$sname_real"
    fi

    if [ "$encrypt" = "true" ]; then
        euid="$ename_real$ename_comment $ename_email"
        echod "Calling _gpg_add_subkey \"$fingerprint\" \"$epassphrasedbg\" \"$homedir\" \"cv25519\" \"encrypt\" \"$eexpiry_date\" \"$euid\""
        _gpg_add_subkey "$fingerprint" "$epassphrase" "$homedir" "cv25519" "encrypt" "$eexpiry_date" "$euid"
        echosv "Adding subkey for encryption successful."
        add_to_gpg_subkeys "$index" "${sub_fingerprint:20}" "usage" "encrypt"
        add_to_gpg_subkeys "$index" "${sub_fingerprint:20}" "fingerprint" "$sub_fingerprint"
        add_to_gpg_subkeys "$index" "${sub_fingerprint:20}" "expires" "$eexpiry_date"
        add_to_gpg_subkeys "$index" "${sub_fingerprint:20}" "uid" "$euid"
        add_to_gpg_subkeys "$index" "${sub_fingerprint:20}" "name_real" "$ename_real"
    fi

    if [ "$no_subs" = "false" ] && [ "$auth" = "true" ]; then
        auid="$aname_real$aname_comment $aname_email"
        echod "Calling _gpg_add_subkey \"$fingerprint\" \"$apassphrasedbg\" \"$homedir\" \"ed25519\" \"auth\" \"$aexpiry_date\" \"$auid\""
        _gpg_add_subkey "$fingerprint" "$apassphrase" "$homedir" "ed25519" "auth" "$aexpiry_date" "$auid"
        echosv "Adding subkey for authentication successful."
        add_to_gpg_subkeys "$index" "${sub_fingerprint:20}" "usage" "auth"
        add_to_gpg_subkeys "$index" "${sub_fingerprint:20}" "fingerprint" "$sub_fingerprint"
        add_to_gpg_subkeys "$index" "${sub_fingerprint:20}" "expires" "$aexpiry_date"
        add_to_gpg_subkeys "$index" "${sub_fingerprint:20}" "uid" "$auid"
        add_to_gpg_subkeys "$index" "${sub_fingerprint:20}" "name_real" "$aname_real"
    fi

    echos "Creating GPG Keypair was successful with index: $index"
}


gpg_export_keypair() {
    fingerprint="$1"
    name_real="${2:-}"
    key_id="${3:-${fingerprint:20}}"
    index="${4:-${name_real:+$(echo "$name_real" | sed -e 's/\-/\_/g' -e 's/\ /\_/g' | tr "[:upper:]" "[:lower:]")}}"

    no_armor="${5:-false}"
    homedir="${6:-$DC_GNUPG}"

    out_dir="${7:+$(dirpath "$6")}"
    out_dir="${7:-$(dirpath ".")}"

    public_key_out="$8"
    private_key_out="$9"

    with_subkeys="${10:-false}"
    passphrase=${11}
    openssl_encrypt="${12:-true}"


    # Check if gpg key exists
    if ! gpg_index_exists "$index"; then
        echoe "Key with index: $index doesn't exist"
        return 1
    fi

    # Fetch additional params if not set
    if { [ -z "$fingerprint" ] || [ -z "$key_id" ]; } && [ -n "$index" ]; then
        fingerprint=$(get_value "$index" "fingerprint")
    elif { [ -z "$fingerprint" ] || [ -z "$key_id" ]; } && [ -n "$name_real" ]; then
        index=$(echo "$name_real" | sed -e 's/\-/\_/g' -e 's/\ /\_/g' | tr "[:upper:]" "[:lower:]")
        fingerprint=$(get_value "$index" "fingerprint")
    fi

    index=${index:-$(get_value_by_key_match "index" "fingerprint" "$fingerprint")}
    key_id=${key_id:-${fingerprint:20}}
    uid=${uid:-$(get_value "$index" "uid")}
    name_real=${name_real:-$(get_name_real_from_uid "$uid")}

    echod "Starting gpg_export_keypair with parameters:"
    if [ "$passphrase" = "gui" ] || [ "$passphrase" = "GUI" ]; then
        passphrasedbg="[GUI]"
    else
        passphrasedbg=$([ -n "$passphrase" ]  && [ ! -f "$passphrase" ] && echo "[SET]" || echo "$passphrase")
    fi
    echod "      fingerprint: $fingerprint"
    echod "        name_real: $name_real"
    echod "           key_id: $key_id"
    echod "            index: $index"
    echod "         no_armor: $no_armor"
    echod "          homedir: $homedir"
    echod "          out_dir: $out_dir"
    echod "   public_key_out: $public_key_out"
    echod "  private_key_out: $private_key_out"
    echod "     with_subkeys: $with_subkeys"
    echod "       passphrase: $passphrasedbg"
    echod "  openssl_encrypt: $openssl_encrypt"

    # Validate params
    if [ -z "$fingerprint" ] || [ -z "$key_id" ] || [ -z "$index" ] || [ -z "$name_real" ]; then
        echoe "fingerprint, name_real, index and key_id must be set"
        return 1
    fi

    # Set default values for Public & Private Keys
    if [ -z "$public_key_out" ]; then
        ext=$([ "$no_armor" = "false" ] && echo "asc" || echo "gpg")
        public_key_out="$out_dir/$index.public.$ext"
    elif [ -n "$public_key_out" ]; then
        public_key_dir=$(dirpath "$public_key_out")
        public_key_out=$(absolutepath "$public_key_out")
        [ "$public_key_dir" != "$out_dir" ] && out_dir=""
    fi

    if [ -z "$private_key_out" ]; then
        ext=$([ "$no_armor" = "false" ] && echo "asc" || echo "key")
        private_key_out="$out_dir/$index.secret.$ext"
    elif [ -n "$private_key_out" ]; then
        private_key_dir=$(dirpath "$private_key_out")
        private_key_out=$(absolutepath "$private_key_out")
        [ "$private_key_dir" != "$out_dir" ] && out_dir=""
    fi

    # Create output directory if not exists
    if [ "$out_dir" != "" ] && [ ! -d "$out_dir" ]; then
        mkdir -p "$out_dir" || {
            echoe "Error creating output directory $out_dir"
            return 1
        }
    elif [ "$out_dir" == "" ]; then
        if [ ! -d "$public_key_dir" ]; then
            mkdir -p "$public_key_dir" || {
                echoe "Error creating output directory $public_key_dir"
                return 1
            }
        fi

        if [ ! -d "$private_key_dir" ]; then
            mkdir -p "$private_key_dir" || {
                echoe "Error creating output directory $private_key_dir"
                return 1
            }
        fi
    fi

    # Find out if key_id is subkey
    subkey="false"
    for index in jq -r '.gpg.keys | to_entries[] | .key // empty' "$DC_DB"; do
        # shellcheck disable=SC2016
        for sidx in jq -r --arg idx "$index" '.gpg.keys[$idx].subkeys | to_entries[] | .key // empty' "$DC_DB"; do
            if [ "$sidx" = "${fingerprint:20}" ]; then
                subkey="true"
                echod "$fingerprint is subkey"
            fi
        done
    done

    echod "Final public_key_out: $public_key_out"
    echod "Final private_key_out: $private_key_out"
    [ -n "$out_dir" ] && echod "Final out_dir: $out_dir"

    # Export public
    echod "Calling _gpg_export_public \"$fingerprint\" \"$public_key_out\" \"$no_armor\" \"$homedir\" \"$with_subkeys\""
    if ! _gpg_export_public "$fingerprint" "$public_key_out" "$no_armor" "$homedir" "$with_subkeys"; then
        echoe "Failed calling _gpg_export_public"
        return 1
    fi

    # Export Primary Secret Key with one or all subkeys
    if [ "$subkey" = "false" ]; then
        _gpg_export_secret_primary "$fingerprint" "$private_key_out" "$passphrase" "$no_armor" "$homedir" "$with_subkeys" "$openssl_encrypt"
        echosv "Exported secret GPG key successfully."

    # Export Dummy Primary Key with one or all subkey
    elif [ "$subkey" = "true" ]; then
        _gpg_export_secret_ssb_with_dummy "$fingerprint" "$private_key_out" "$no_armor" "$homedir" "$with_subkeys" "$openssl_encrypt" "$passphrase"
        echosv "Exported secret GPG subkey successfully."
    fi

    echos "Exporting Keypair successful."
}

gpg_import_keys() {
    import_path="${1:+$(absolutepath "$1")}"
    import_path="${1:-$(absolutepath ".")}"
    passphrase="$2"
    scan_depth="${3:-1}"
    index="${4:+$(echo "$4" | sed -e 's/\-/\_/g' -e 's/\ /\_/g' | tr "[:upper:]" "[:lower:]")}"
    remove_keys="${5:-false}"
    openssl_decrypt="${6:-true}"

    echod "Starting gpg_import_keys with parameters:"
    echod "        index: $index"
    echod "  import-path: $import_path"
    echod "   passphrase: $([ -n "$passphrase" ] && [ ! -f "$passphrase" ] && echo "[SET]")"
    echod "   scan_depth: $scan_depth"
    echod "  remove_keys: $remove_keys"

    echos "Importing GPG Keys successful. Amount: $c"
}


sign_pkgbuild() {
    fingerprint="$1"
    name_real="$2"
    index="${3:-${name_real:+$(echo "$name_real" | sed -e 's/\-/\_/g' -e 's/\ /\_/g' | tr "[:upper:]" "[:lower:]")}}"
    key_id="${4:-${fingerprint:20}}"
    path="$5"
    passphrase="$6"
    homedir="${7:-$DC_GNUPG}"
    makepkg="${8:-false}"

    echod "Starting sign_pkgbuild with parameters:"
    echod " fingerprint: $fingerprint"
    echod "   name_real: $name_real"
    echod "       index: $index"
    echod "      key_id: $key_id"
    echod "        path: $path"
    echod "  passphrase: $([ -n "$passphrase" ] && [ ! -f "$passphrase" ] && echo "[SET]")"
    echod "     homedir: $homedir"
    echod "     makepkg: $makepkg"

    # Validating input params
    if [ -z "$fingerprint" ] && [ -z "$name_real" ] && [ -z "$index" ] && [ -z "$key_id" ]; then
        echoe "Either one of fingerprint, name_real, index or key_id must be set."
        return 1
    fi

    if [ -d "$path" ]; then
        path=$(dirpath "$path")
        tar -I "zstd" -cf "$path.tar.zst" "$path"
    fi

    if [ -f "$path" ] && file "$path" | grep -iv "zstandard"; then
        echoe "Unknown file type: $(file "$path" | awk -F',' '{print $1}')"
        return 1
    fi


    if [ "$makepkg" = "false" ] || ! which makepkg >/dev/null 2>&1; then
        if [ -z "$passphrase" ]; then
            gpg --homedir "$homedir" \
                --detach-sign
        elif [ -n "$passphrase" ] && [ ! -f "$passphrase" ]; then
            printf "%s" "$passphrase" | \
            gpg --homedir "$homedir" \
                --pinentry-mode loopback \
                --passphrase-fd 0 \
                --detach-sign
        elif [ -s "$passphrase" ]; then
            gpg --homedir "$homedir" \
                --pinentry-mode loopback \
                --passphrase-file "$passphrase" \
                --detach-sign
        fi
    fi
}
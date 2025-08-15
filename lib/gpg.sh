# shellcheck shell=sh
# shellcheck disable=SC2001
# shellcheck disable=SC2154
# shellcheck disable=SC2181


_gpg_export_public() {
    fingerprint="$1"
    key_id=${fingerprint:24}
    out_path="${2}"
    no_armor="${3:-false}"
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

    echod "Calling $GPG_CMD \"$fingerprint\" > \"$out_path\""
    if ! $GPG_CMD "$fingerprint" > "$out_path"; then
        echoe "Failed exporting all subkeys with primary"
        return 1
    fi

    if [ ! -s "$out_path" ] ; then
        echoe "Failed exporting Public Key to $out_path"
        rm -f -- "$out_path"
        return 1
    fi

    set_permissions_and_owner "$out_path" 444
    return 0
}


_gpg_export_secret_primary() {
    fingerprint="$1"
    key_id="${fingerprint:+${fingerprint:24}}"
    out_path="$2"
    passphrase="$3"
    no_armor="$4"
    homedir="${5:-$DC_GNUPG}"
    with_ssbs="$6"
    openssl_encrypt="${7:-true}"
    passphrasedbg=$({ [ "$3" = "gui" ] || [ "$3" = "GUI" ]; } && echo "[GUI]")
    passphrasedbg=$({ [ -n "$3" ]  && [ ! -f "$3" ]; } && echo "[SET]" || echo "$3")

    echod "Starting _gpg_export_secret_primary with parameters:"
    echod "fingerprint: $fingerprint"

    echod "   out_path: $out_path"
    echod " passphrase: $passphrasedbg"
    echod "   no_armor: $no_armor | $4"
    echod "    homedir: $homedir"
    echod "  with_ssbs: $with_ssbs | $6"
    echod "ssl_encrypt: $openssl_encrypt"

    echov "Exporting Secret Primary Key"

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
            echod "Calling $GPG_CMD \"$fingerprint\" | encrypt_gpg_key \"$out_path\" \"$passphrasedbg\""
            encrypt_gpg_key "$out_path" "$openssl_passphrase" "$($GPG_CMD "$fingerprint")"
            add_to_gpg_key "$(basename -- "${out_path%%.*}")" "salt" "$salt"

        else
            echod "Calling $GPG_CMD \"$fingerprint\" > \"$out_path\""
            $GPG_CMD "$fingerprint" > "$out_path"
        fi
        unset openssl_passphrase

    # No passphrase at all
    elif [ -z "$passphrase" ]; then
        echoe TEST
        echod "Calling printf \"%s\" \"\" | $GPG_CMD \"$fingerprint\" > \"$out_path\""
        printf "%s" "" | $GPG_CMD "$fingerprint" > "$out_path"

    # Passphrase from parameter
    elif [ -n "$passphrase" ] && [ ! -f "$passphrase" ]; then
        if [ "$openssl_encrypt" = "true" ]; then
            echod "Calling printf \"%s\" \"$passphrasedbg\" | $GPG_CMD \"$fingerprint\" | encrypt_gpg_key \"$out_path\" \"$passphrasedbg\""
            encrypt_gpg_key "$out_path" "$passphrase" "$(printf "%s" "$passphrase" | $GPG_CMD "$fingerprint")"
            add_to_gpg_key "$(basename -- "${out_path%%.*}")" "salt" "$salt"
        else
            echod "Calling printf \"%s\" \"$passphrasedbg\" | $GPG_CMD \"$fingerprint\" > \"$out_path\""
            printf "%s" "$passphrase" | $GPG_CMD "$fingerprint" > "$out_path"
        fi

    # Passphrase from file
    elif [ -s "$passphrase" ]; then
        if [ "$openssl_encrypt" = "true" ]; then
            echod "Calling $GPG_CMD \"$fingerprint\" | encrypt_gpg_key \"$out_path\" \"$passphrasedbg\""
            encrypt_gpg_key "$out_path" "$passphrase" "$($GPG_CMD "$fingerprint")"
            add_to_gpg_key "$(basename -- "${out_path%%.*}")" "salt" "$salt"
        else
            echod "Calling $GPG_CMD \"$fingerprint\" > \"$out_path\""
            $GPG_CMD "$fingerprint" > "$out_path"
        fi
    fi

    if [ "$openssl_encrypt" = "true" ] && [ ! -s "$out_path.enc" ]; then
        echoe "Failed exporting Secret Key to $out_path.enc"
        return 1
    elif   [ "$openssl_encrypt" = "false" ] && [ ! -s "$out_path" ]; then
        echoe "Failed exporting Secret Key to $out_path"
        return 1
    fi

    if [ "$openssl_encrypt" != "true" ]; then
        set_permissions_and_owner "$out_path" 440
    fi

    return 0
}


# Exports dummy primary and either all or one ssb
_gpg_export_secret_ssb_with_dummy() {
    fingerprint="${1}"
    key_id="${fingerprint:24}"
    out_path="$2"
    no_armor="$3"
    homedir="${4:-$DC_GNUPG}"
    with_subkeys="$5"
    openssl_encrypt="${6:-true}"
    passphrase="$7"
    passphrasedbg=$({ [ "$7" = "gui" ] || [ "$7" = "GUI" ]; } && echo "[GUI]")
    passphrasedbg=$({ [ -n "$7" ]  && [ ! -f "$7" ]; } && echo "[SET]" || echo "$7")

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

    echov "Exporting Dummy Primary Key with secret sub key$([ "$with_subkeys" = "true" ] && echo "s")"

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
            echod "Calling $GPG_CMD \"$fingerprint\" > \"$out_path\""
            if ! $GPG_CMD "$fingerprint" > "$out_path"; then
                echoe "Failed exporting all ssbkeys with dummy"
                return 1
            fi
        else
            echod "Calling gpg --homedir \"$homedir\" $no_armor --export-secret-subkeys $with_subkeys \"$fingerprint\" | encrypt_gpg_key \"$out_path\" \"$passphrasedbg\""
            if ! encrypt_gpg_key "$out_path" "${openssl_passphrase}" "$($GPG_CMD "$fingerprint")"; then
                echoe "Failed exporting all ssbkeys with dummy"
                return 1
            fi
        fi
        unset openssl_passphrase

    # No passphrase at all
    elif [ -z "$passphrase" ]; then
        echod "Calling printf \"%s\" \"\" | $GPG_CMD \"$fingerprint\" > \"$out_path\""
        if ! printf "%s" "" | $GPG_CMD "$fingerprint" > "$out_path"; then
            echoe "Failed"
            return 1
        fi

    # Passphrase from parameter
    elif [ -n "$passphrase" ] && [ ! -f "$passphrase" ]; then
        if [ "$openssl_encrypt" != "true" ]; then
            echod "Calling printf \"%s\" \"$passphrasedbg\" | $GPG_CMD \"$fingerprint\" > \"$out_path\""
            if ! printf "%s" "$passphrase" | $GPG_CMD "$fingerprint" > "$out_path"; then
                echoe "Failed"
                return 1
            fi
        else
            echod "Calling printf \"%s\" \"$passphrasedbg\" | $GPG_CMD \"$fingerprint\" | encrypt_gpg_key \"$out_path\" \"$passphrasedbg\""
            if ! encrypt_gpg_key "$out_path" "${passphrase}" "$(printf "%s" "$passphrase" | $GPG_CMD "$fingerprint")"; then
                echoe "Failed"
                return 1
            fi
        fi

    # Passphrase from file
    elif [ -s "$passphrase" ]; then
        if [ "$openssl_encrypt" != "true" ]; then
            echod "Calling $GPG_CMD \"$fingerprint\" > \"$out_path\""
            if ! $GPG_CMD "$fingerprint" > "$out_path"; then
                echoe "Failed exporting dummy primary with all ssbs."
                return 1
            fi
        else
            echod "Calling $GPG_CMD \"$fingerprint\" | encrypt_gpg_key \"$out_path\" \"$passphrasedbg\""
            if ! encrypt_gpg_key "$out_path" "${passphrase}" "$($GPG_CMD "$fingerprint")"; then
                echoe "Failed exporting dummy primary with all ssbs."
                return 1
            fi
        fi
    fi

    if [ "$openssl_encrypt" = "true" ]; then
        set_permissions_and_owner "$out_path.enc" 440
    else
        set_permissions_and_owner "$out_path" 440
    fi
    return 0
}


_gpg_create_primary_key() {
    uid="$1"
    passphrase="$2"
    homedir="$3"
    expiry_date="$4"
    usage="${5:-cert,sign}"
    passphrasedbg=$({ [ "$2" = "gui" ] || [ "$2" = "GUI" ]; } && echo "[GUI]")
    passphrasedbg=$({ [ -n "$2" ]  && [ ! -f "$2" ]; } && echo "[SET]" || echo "$2")

    echod "Starting _gpg_create_primary_key with parameters:"
    echod "           uid: $uid"
    echod "    passphrase: $passphrasedbg"
    echod "       homedir: $homedir"
    echod "   expiry_date: $expiry_date"
    echod "         usage: $usage"

    echov "Create Primary Key..."

    echod "Building gpg command..."
    gpg_build_cmd "$homedir" "gen" "" "" "$passphrase"

    # Use GUI to ask for passphrase
    if [ "$passphrase" = "gui" ] || [ "$passphrase" = "GUI" ]; then
        echod "Calling $GPG_CMD \"$uid\" \"ed25519\" \"$usage\" \"$expiry_date\""
        $GPG_CMD "$uid" "ed25519" "$usage" "$expiry_date" >/dev/null 2>&1

    # No passphrase at all
    elif [ -z "$passphrase" ]; then
        echod "Calling printf \"\" | $GPG_CMD \"$uid\" \"ed25519\" \"$usage\" \"$expiry_date\""
        printf "%s" "" | $GPG_CMD "$uid" "ed25519" "$usage" "$expiry_date" >/dev/null 2>&1

    # Passphrase from cmdline
    elif [ -n "$passphrase" ] && [ ! -f "$passphrase" ]; then
        echod "Calling printf \"%s\" \"$passphrasedbg\" | $GPG_CMD \"$uid\" \"ed25519\" \"$usage\" \"$expiry_date\""
        printf "%s" "$passphrase" | $GPG_CMD "$uid" "ed25519" "$usage" "$expiry_date" >/dev/null 2>&1

    # Passphrase from file
    elif [ -s "$passphrase" ]; then
        echod "Calling $GPG_CMD \"$uid\" \"ed25519\" \"$usage\" \"$expiry_date\""
        $GPG_CMD "$uid" "ed25519" "$usage" "$expiry_date" >/dev/null 2>&1
    fi

    # shellcheck disable=SC2181
    if [ "$?" -ne 0 ]; then
        echoe "Generating primary keypair failed."
        return 1
    fi

    fingerprint=$(gpg --homedir "$homedir" \
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
    passphrasedbg=$({ [ -n "$2" ]  && [ ! -f "$2" ]; } && echo "[SET]" || echo "$2")

    echod "Starting _gpg_add_subkey with parameters:"
    echod " primary_key_id: $primary_key_id"
    echod "     passphrase: $passphrase"
    echod "        homedir: $homedir"
    echod "          curve: $curve"
    echod "          usage: $usage"
    echod "    expiry_date: $expiry_date"
    echod "            uid: $uid"

    echod "Building gpg command..."
    gpg_build_cmd "$homedir" "add" "" "" "$passphrase"

    # Use GUI to ask for passphrase
    if [ "$passphrase" = "gui" ] || [ "$passphrase" = "GUI" ]; then
        if [ -n "$uid" ] && [ "$uid" != " " ]; then
            echod "Add UID: gpg --batch --homedir \"$homedir\" --quick-add-uid \"$fingerprint\" \"$uid\""
            gpg --homedir "$homedir" --quick-add-uid "$fingerprint" "$uid" 2>&1

            echod "Trust UID: printf \"trust\n5\ny\nsave\" | gpg --homedir \"$homedir\" --command-fd 0 --edit-key \"$primary_key_id\" 2>&1"
            printf "trust\n5\ny\nsave\n" | gpg --batch --homedir "$homedir" --command-fd 0 --edit-key "$primary_key_id" 2>/dev/null
        fi
        echod "Add $usage Key: $GPG_CMD \"$primary_key_id\" \"$curve\" \"$usage\" \"$expiry_date\""
        $GPG_CMD "$primary_key_id" "$curve" "$usage" "$expiry_date" 2>&1

    # No passphrase at all
    elif [ -z "$passphrase" ]; then
        if [ -n "$uid" ] && [ "$uid" != " " ]; then
            echod "Add UID: gpg --batch --homedir \"$homedir\" --quick-add-uid \"$fingerprint\" \"$uid\""
            printf "%s" "" | gpg --batch --homedir "$homedir"  --pinentry-mode loopback --passphrase-fd 0 --quick-add-uid "$fingerprint" "$uid" 2>&1

            echod "Trust UID: printf \"trust\n5\ny\nsave\" | gpg --homedir \"$homedir\" --command-fd 0 --edit-key \"$primary_key_id\" 2>&1"
            printf "trust\n5\ny\nsave\n" | gpg --batch --homedir "$homedir" --command-fd 0 --edit-key "$primary_key_id" 2>/dev/null
        fi
        echod "Add $usage Key: printf \"%s\" \"\" | $GPG_CMD \"$primary_key_id\" \"$curve\" \"$usage\" \"$expiry_date\""
        printf "%s" "" | $GPG_CMD "$primary_key_id" "$curve" "$usage" "$expiry_date" 2>&1

    # Read pass from cmdline
    elif [ -n "$passphrase" ] && [ ! -f "$passphrase" ]; then
        if [ -n "$uid" ] && [ "$uid" != " " ]; then
            echod "Add UID: gpg --batch --homedir \"$homedir\" --quick-add-uid \"$fingerprint\" \"$uid\""
            printf "%s" "$passphrase" | gpg --batch --homedir "$homedir" --pinentry-mode loopback --passphrase-fd 0 --quick-add-uid "$fingerprint" "$uid" 2>&1

            echod "Trust UID: printf \"trust\n5\ny\nsave\" | gpg --homedir \"$homedir\" --command-fd 0 --edit-key \"$primary_key_id\" 2>&1"
            printf "trust\n5\ny\nsave\n" | gpg --batch --homedir "$homedir" --command-fd 0 --edit-key "$primary_key_id" 2>/dev/null
        fi
        echod "Add $usage Key: printf \"%s\" \"$passphrasedbg\" | gpg --batch --homedir \"$homedir\" --pinentry-mode loopback --passphrase-fd 0 --quick-add-key \"$primary_key_id\" \"$curve\" \"$usage\" \"$expiry_date\""
        printf "%s" "$passphrase" | $GPG_CMD "$primary_key_id" "$curve" "$usage" "$expiry_date" 2>&1

    # Read pass from file
    elif [ -s "$passphrase" ]; then
        if [ -n "$uid" ] && [ "$uid" != " " ]; then
            echod "Add UID: gpg --batch --homedir \"$homedir\" --passphrase-file \"$passphrase\" --quick-add-uid \"$fingerprint\" \"$uid\""
            gpg --batch --homedir "$homedir" --pinentry-mode loopback --passphrase-file "$passphrase" --quick-add-uid "$fingerprint" "$uid" 2>&1

            echod "Trust UID: printf \"trust\n5\ny\nsave\" | gpg --homedir \"$homedir\" --command-fd 0 --edit-key \"$primary_key_id\" 2>&1"
            printf "trust\n5\ny\nsave\n" | gpg --batch --homedir "$homedir" --command-fd 0 --edit-key "$primary_key_id" 2>/dev/null
        fi
        echod "Add $usage Key: $GPG_CMD \"$primary_key_id\" \"$curve\" \"$usage\" \"$expiry_date\""
        $GPG_CMD "$primary_key_id" "$curve" "$usage" "$expiry_date" 2>&1
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
    echod "Sub-Fingerprint: $sub_fingerprint"
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
    spassphrase="${16:-$passphrase}"

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
    passphrasedbg=$({ [ -n "$2" ]  && [ ! -f "$2" ]; } && echo "[SET]" || echo "$2")
    spassphrasedbg="$({ [ "${16}" = "gui" ] || [ "${16}" = "GUI" ]; } && echo "[GUI]")"
    spassphrasedbg=$({ [ -n "${16}" ]  && [ ! -f "${16}" ]; } && echo "[SET]" || echo "${16}")
    apassphrasedbg="$({ [ "${21}" = "gui" ] || [ "${21}" = "GUI" ]; } && echo "[GUI]")"
    epassphrasedbg=$({ [ -n "${21}" ]  && [ ! -f "${21}" ]; } && echo "[SET]" || echo "${21}")
    apassphrasedbg="$({ [ "${26}" = "gui" ] || [ "${26}" = "GUI" ]; } && echo "[GUI]")"
    apassphrasedbg=$({ [ -n "${26}" ]  && [ ! -f "${26}" ]; } && echo "[SET]" || echo "${26}")

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

    usage="cert,sign"
    if [ "$no_subs" = "true" ]; then
        [ "$auth" = "true" ] && usage="$usage,auth"
        [ "$encrypt" = "true" ] && \
            echow "Can't add encryption functionality when option no-subkeys is set."
    fi

    # Create primary key
    echoi "Creating primary key:"
    uid="$name_real$name_comment $name_email"
    echod "Calling _gpg_create_primary_key \"$uid\" \"$passphrasedbg\" \"$homedir\" \"$expiry_date\" \"$usage\""
    _gpg_create_primary_key "$uid" "$passphrase" "$homedir" "$expiry_date" "$usage"
    echosv "Creating primary key successful"

    key_id="${fingerprint:24}"

    # Add key to database
    echod "Adding GPG primary key to database:"
    add_gpg_key "$index"
    add_to_gpg_key "$index" "uid" "$uid"
    add_to_gpg_key "$index" "fingerprint" "$fingerprint"
    add_to_gpg_key "$index" "keyId" "$key_id"
    add_to_gpg_key "$index" "expires" "$expiry_date"
    add_to_gpg_key "$index" "usage" "$usage"
    add_to_gpg_key "$index" "name_real" "$name_real"


    # Add subkey to primary key if set
    if [ "$no_subs" = "false" ] && [ "$sign" = "true" ]; then
        suid="$sname_real$sname_comment $sname_email"
        echod "Calling _gpg_add_subkey \"$fingerprint\" \"$spassphrase\" \"$homedir\" \"ed25519\" \"sign\" \"$sexpiry_date\" \"$suid\""
        if ! _gpg_add_subkey "$fingerprint" "$spassphrase" "$homedir" "ed25519" "sign" "$sexpiry_date" "$suid"; then
            echoe "Failed calling _gpg_add_subkey"
            return 1
        fi
        echosv "Adding subkey for signing successful."
        sub_key_id="${sub_fingerprint:24}"
        add_gpg_sub "$index" "$sub_key_id"
        add_to_gpg_key "$index" "$sub_key_id" "usage" "sign"
        add_to_gpg_key "$index" "$sub_key_id" "fingerprint" "$sub_fingerprint"
        add_to_gpg_key "$index" "$sub_key_id" "expires" "$sexpiry_date"
        [ -n "$suid" ] && add_to_gpg_key "$index" "$sub_key_id" "uid" "$suid"
        add_to_gpg_key "$index" "$sub_key_id" "keyId" "$sub_key_id"
        [ -n "$sname_real" ] && add_to_gpg_key "$index" "$sub_key_id" "name_real" "$sname_real"
    fi

    if [ "$encrypt" = "true" ]; then
        euid="$ename_real$ename_comment $ename_email"
        echod "Calling _gpg_add_subkey \"$fingerprint\" \"$epassphrasedbg\" \"$homedir\" \"cv25519\" \"encrypt\" \"$eexpiry_date\" \"$euid\""
        if ! _gpg_add_subkey "$fingerprint" "$epassphrase" "$homedir" "cv25519" "encrypt" "$eexpiry_date" "$euid"; then
            echoe "Failed calling _gpg_add_subkey"
            return 1
        fi
        echosv "Adding subkey for encryption successful."
        sub_key_id="${sub_fingerprint:24}"
        add_gpg_sub "$index" "$sub_key_id"
        add_to_gpg_key "$index" "$sub_key_id" "usage" "encrypt"
        add_to_gpg_key "$index" "$sub_key_id" "fingerprint" "$sub_fingerprint"
        add_to_gpg_key "$index" "$sub_key_id" "expires" "$eexpiry_date"
        [ -n "$euid" ] && add_to_gpg_key "$index" "$sub_key_id" "uid" "$euid"
        add_to_gpg_key "$index" "$sub_key_id" "keyId" "$sub_key_id"
        [ -n "$ename_real" ] && add_to_gpg_key "$index" "$sub_key_id" "name_real" "$ename_real"
    fi

    if [ "$no_subs" = "false" ] && [ "$auth" = "true" ]; then
        auid="$aname_real$aname_comment $aname_email"
        echod "Calling _gpg_add_subkey \"$fingerprint\" \"$apassphrasedbg\" \"$homedir\" \"ed25519\" \"auth\" \"$aexpiry_date\" \"$auid\""
        if ! _gpg_add_subkey "$fingerprint" "$apassphrase" "$homedir" "ed25519" "auth" "$aexpiry_date" "$auid"; then
            echoe "Failed calling _gpg_add_subkey"
            return 1
        fi
        echosv "Adding subkey for authentication successful."
        sub_key_id="${sub_fingerprint:24}"
        add_gpg_sub "$index" "$sub_key_id"
        add_to_gpg_key "$index" "$sub_key_id" "usage" "auth"
        add_to_gpg_key "$index" "$sub_key_id" "fingerprint" "$sub_fingerprint"
        add_to_gpg_key "$index" "$sub_key_id" "expires" "$aexpiry_date"
        [ -n "$auid" ] && add_to_gpg_key "$index" "$sub_key_id" "uid" "$auid"
        add_to_gpg_key "$index" "$sub_key_id" "keyId" "$sub_key_id"
        [ -n "$aname_real" ] && add_to_gpg_key "$index" "$sub_key_id" "name_real" "$aname_real"
    fi

    echos "Creating GPG Keypair was successful with index: $index"
}


gpg_create_subkey() {
    homedir="${1:-$DC_GNUPG}"
    name_real="$2"
    name_email="${3:+<$3>}"
    name_comment="${4:+ ($4)}"
    uid="${5:-}"
    fingerprint="$6"
    key_id="${7:-${fingerprint:+${fingerprint:24}}}"
    passphrase="$8"
    encrypt="${9:-false}"
    sign="${10:-false}"
    auth="${11:-false}"
    index="${12:-}"
    expires="${13:-2y}"
    sub_passphrase=${14:-$passphrase}
    passphrasedbg=$({ [ "${8}" = "gui" ] || [ "${8}" = "GUI" ]; } && echo "[GUI]")
    passphrasedbg=$({ [ -n "${8}" ]  && [ ! -f "${8}" ]; } && echo "[SET]" || echo "${8}")
    sub_passphrasedbg=$({ [ "${14}" = "gui" ] || [ "${14}" = "GUI" ]; } && echo "[GUI]")
    sub_passphrasedbg=$({ [ -n "${14}" ]  && [ ! -f "${14}" ]; } && echo "[SET]" || echo "${14}")


    echoi "Adding subkey to primary key"

    echod "Starting gpg_create_subkey with parameters:"
    echod "       homedir: $homedir"
    echod "     name_real: $name_real"
    echod "    name_email: $name_email"
    echod "  name_comment: $name_comment"
    echod "           uid: $uid"
    echod "   fingerprint: $fingerprint"
    echod "        key_id: $key_id"
    echod "    passphrase: $passphrasedbg"
    echod "       encrypt: $encrypt"
    echod "          sign: $sign"
    echod "          auth: $auth"
    echod "         index: $index"
    echod "       expires: $expires"
    echod "sub_passphrase: $sub_passphrasedbg"

    # Validate params
    if [ -n "$name_real" ] && [ -z "$name_email" ]; then
        echoe "To create a full uid, name and email has to be set"
        return 1
    fi

    if [ -z "$key_id" ] && [ -z "$index" ]; then
        echoe "You have to set either index, fingerprint or key_id as option to add a subkey."
        return 1
    fi

    if [ "$sign" = "false" ] && [ "$auth" = "false" ] && [ "$encrypt" = "false" ]; then
        echoe "One of sign, auth, encrypt has to be set / need to be true"
        return 1
    elif { [ "$sign" = "true" ] || [ "$auth" = "true" ]; } && [ "$encrypt" = "true" ]; then
        echoe "encrypt cant't be set or true together with sign or auth"
        return 1
    fi

    if [ -n "$name_real" ] && [ -n "$name_email" ]; then
        uid="$name_real$name_comment $name_email"
    fi

    usage=""
    if [ "$sign" = "true" ]; then
        usage="sign"
        curve="ed25519"
    fi
    if [ "$auth" = "true" ]; then
        usage="$usage${usage:+,auth}"
        usage="${usage:-auth}"
        curve="ed25519"
    fi
    if [ "$encrypt" = "true" ]; then
        usage="encrypt"
        curve="cv25519"
    fi

    if [ -z "$index" ] && [ -n "$key_id" ]; then
        index=$(get_index_by_key_match "keyId" "$key_id")
    fi
    if [ -z "$fingerprint" ] && [ -n "$index" ]; then
        fingerprint=$(get_gpg_value "$index" "fingerprint")
    elif [ -z "$fingerprint" ] && [ -n "$key_id" ]; then
        fingerprint=$(get_value_by_key_match "fingerprint" "keyId" "$key_id")
    elif [ -z "$fingerprint" ] && [ -n "$uid" ]; then
        fingerprint=$(get_value_by_key_match "fingerprint" "uid" "$uid")
    fi

    echod "Calling _gpg_add_subkey \"$fingerprint\" \"$sub_passphrasedbg\" \"$homedir\" \"$curve\" \"$usage\" \"$expires\" \"$uid\""
    if ! _gpg_add_subkey "$fingerprint" "$sub_passphrase" "$homedir" "$curve" "$usage" "$expires" "$uid"; then
        echoe "Failed calling _gpg_add_subkey"
        return 1
    fi
    echosv "Creating subkey successful"

    sub_key_id="${sub_fingerprint:24}"
    add_gpg_sub "$index" "$sub_key_id"
    add_to_gpg_key "$index" "$sub_key_id" "usage" "$usage"
    add_to_gpg_key "$index" "$sub_key_id" "fingerprint" "$sub_fingerprint"
    add_to_gpg_key "$index" "$sub_key_id" "keyId" "$sub_key_id"
    add_to_gpg_key "$index" "$sub_key_id" "expires" "$expires"
    if [ -z "$uid" ]; then
        uid=$(get_gpg_value "$index" "uid")
    fi
    if [ -z "$name_real" ]; then
        name_real=$(get_gpg_value "$index" "name_real")
    fi
    add_to_gpg_key "$index" "$sub_key_id" "uid" "$uid"
    add_to_gpg_key "$index" "$sub_key_id" "name_real" "$name_real"

    echos "Adding subkey for $usage successful: $sub_fingerprint"
}


gpg_export_keypair() {
    fingerprint="$1"
    name_real="${2:-}"
    key_id="${3:-${fingerprint:24}}"
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
    passphrasedbg=$({ [ "${11}" = "gui" ] || [ "${11}" = "GUI" ]; } && echo "[GUI]")
    passphrasedbg=$({ [ -n "${11}" ]  && [ ! -f "${11}" ]; } && echo "[SET]" || echo "${11}")


    # Check if gpg key exists
    if ! gpg_index_exists "$index"; then
        echoe "Key with index: $index doesn't exist"
        return 1
    fi

    # Fetch additional params if not set
    if { [ -z "$fingerprint" ] || [ -z "$key_id" ]; } && [ -n "$index" ]; then
        fingerprint=$(get_gpg_value "$index" "fingerprint")
    elif { [ -z "$fingerprint" ] || [ -z "$key_id" ]; } && [ -n "$name_real" ]; then
        index=$(echo "$name_real" | sed -e 's/\-/\_/g' -e 's/\ /\_/g' | tr "[:upper:]" "[:lower:]")
        fingerprint=$(get_gpg_value "$index" "fingerprint")
    fi

    index=${index:-$(get_gpg_value_by_key_match "index" "fingerprint" "$fingerprint")}
    key_id=${key_id:-${fingerprint:24}}
    uid=${uid:-$(get_gpg_value "$index" "uid")}
    name_real=${name_real:-$(get_name_real_from_uid "$uid")}

    echod "Starting gpg_export_keypair with parameters:"
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
    for index in jq -r '.gpg.keys | to_entries[] | .key // empty' -- "$DC_DB"; do
        # shellcheck disable=SC2016
        for sidx in jq -r --arg idx "$index" '.gpg.keys[$idx].subkeys | to_entries[] | .key // empty' -- "$DC_DB"; do
            if [ "$sidx" = "${fingerprint:24}" ]; then
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
        echod "Calling _gpg_export_secret_primary \"$fingerprint\" \"$private_key_out\" \"$passphrasedbg\" \"$no_armor\" \"$homedir\" \"$with_subkeys\" \"$openssl_encrypt\""
        if _gpg_export_secret_primary "$fingerprint" "$private_key_out" "$passphrase" "$no_armor" "$homedir" "$with_subkeys" "$openssl_encrypt"; then
            echosv "Exported secret GPG key successfully."
        fi

    # Export Dummy Primary Key with one or all subkeys
    elif [ "$subkey" = "true" ]; then
        echod "_gpg_export_secret_ssb_with_dummy \"$fingerprint\" \"$private_key_out\" \"$no_armor\" \"$homedir\" \"$with_subkeys\" \"$openssl_encrypt\" \"$passphrasedbg\""
        if _gpg_export_secret_ssb_with_dummy "$fingerprint" "$private_key_out" "$no_armor" "$homedir" "$with_subkeys" "$openssl_encrypt" "$passphrase"; then
            echosv "Exported secret GPG subkey successfully."
        fi
    fi

    if [ "$?" -ne 0 ]; then
        echoe "Failed exporting secret key"
        return 1
    fi

    echos "Exporting Keypair successful."
}

gpg_import_keys() {
    import_path="${1:+$(absolutepath "$1")}"
    import_path="${1:-$(dirpath ".")}"
    passphrase="$2"
    scan_depth="${3:-1}"
    index="${4:+$(echo "$4" | sed -e 's/\-/\_/g' -e 's/\ /\_/g' | tr "[:upper:]" "[:lower:]")}"
    remove_keys="${5:-false}"
    homedir="${6:-$DC_GNUPG}"
    passphrasedbg=$({ [ "$2" = "gui" ] || [ "$2" = "GUI" ]; } && echo "[GUI]")
    passphrasedbg=$({ [ -n "$2" ]  && [ ! -f "$2" ]; } && echo "[SET]" || echo "$2")

    echod "Starting gpg_import_keys with parameters:"
    echod "             index: $index"
    echod "       import_path: $import_path"
    echod "        passphrase: $passphrasedbg"
    echod "        scan_depth: $scan_depth"
    echod "       remove_keys: $remove_keys"
    echod "           homedir: $homedir"

    echoi "Importing keys from path: $import_path"

    imports=0
    files=$(find "$import_path" -maxdepth "$scan_depth" -name "*.asc" -o -name "*.gpg" -o -name "*.asc.enc" -o -name "*.gpg.enc")
    for file in $files; do
        file=$(absolutepath "$file")
        mime=$(file "$file" | awk -F': ' '{print $2}')
        echov "Found file: $file"
        if [ "${file##*.}" = "enc" ] || [ "$mime" = "openssl enc'd data with salted password" ]; then
            gpg_build_cmd "$homedir" "imp" "" "" "$passphrase"
            echod "Calling decrypt_gpg_key \"$(basename "$file")\" \"$index\" \"$passphrasedbg\" | $GPG_CMD"
            if ! decrypt_gpg_key "$(basename "$file")" "$index" "$passphrase" | $GPG_CMD; then
                echoe "Faile calling decrypt_gpg_key"
                return 1
            fi
            imports=$(( imports + 1 ))
            echosv "Imported Secret Key successfully"
        elif { [ "${file##*.}" = "asc" ] || [ "${file##*.}" = "gpg" ]; } && ! { file "$file" | grep -qE "openssl enc'd data with salted password"; };  then
            gpg_build_cmd "$homedir" "imp"
            echod "Calling $GPG_CMD \"$file\""
            if ! $GPG_CMD "$file"; then
                echoe "Faile calling decrypt_gpg_key"
                return 1
            fi
            imports=$(( imports + 1 ))
            echosv "Imported Public Key successfully"
        fi

    done

    echos "Importing GPG Keys successful. Amount: $imports"
}


sign_pkgbuild() {
    fingerprint="$1"
    name_real="$2"
    index="${3:-${2:+$(echo "$name_real" | sed -e 's/\-/\_/g' -e 's/\ /\_/g' | tr "[:upper:]" "[:lower:]")}}"
    key_id="${4:-${fingerprint:24}}"
    path="$5"
    passphrase="$6"
    homedir="${7:-$DC_GNUPG}"
    makepkg="${8:-false}"
    passphrasedbg=$({ [ "$6" = "gui" ] || [ "$6" = "GUI" ]; } && echo "[GUI]")
    passphrasedbg=$({ [ -n "$6" ]  && [ ! -f "$6" ]; } && echo "[SET]" || echo "$6")

    echod "Starting sign_pkgbuild with parameters:"
    echod " fingerprint: $fingerprint"
    echod "   name_real: $name_real"
    echod "       index: $index"
    echod "      key_id: $key_id"
    echod "        path: $path"
    echod "  passphrase: $passphrasedbg"
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
# dystopian-crypto Shell Script

## TODO:

#### ssl create-config
- [x] for server cert
- [x] for client cert
- [x] for intermediate CA
- [x] for rootCA
- [x] handle domain list
- [x] handle ip list
- [x] set CN
- [x] set email
- [x] set country
- [x] set state
- [x] set locality
- [x] set org
- [x] set orgunit
- [ ] set crldistpoints

#### ssl create-key
- [x] create unencrypted key
- [x] create encrypted key (pbkdf2)
- [x] create encrypted key (argon2id)
- [x] key verification (unencrypted)
- [x] key verification (encrypted)

#### ssl create-csr
- [x] create CSR with unencrypted key
- [x] create CSR with encrypted key (pbkdf2)
- [x] create CSR with encrypted key (argon2id)
- [x] CSR verification (unencrypted CA key)
- [x] CSR verification (encrypted CA key)

#### ssl sign-csr|create-cert
- [x] sign with unencrypted CA key
- [x] sign with encrypted CA key (pbkdf2)
- [x] sign with encrypted CA key (argon2id)
- [x] cert signature verification (unencrypted)
- [x] cert signature verification (encrypted)
- [x] cert content verification (unencrypted)
- [x] cert content verification (encrypted)

#### ssl create-ca
- [x] create rootCA self-signed (key not encrypted)
- [x] create rootCA self-signed (pbkdf2 encrypted key)
- [x] create rootCA self-signed (argon2id encrypted key)
- [x] create intermediate CA (key not encrypted)
- [x] create intermediate CA (pbkdf2 encrypted key)
- [x] create intermediate CA (argon2id encrypted key)

### ssl create-crl
- [ ] complete

### ssl revoke-cert
- [ ] complete

### ssl verify-cert
- [ ] complete

### ssl encrypt
- [ ] asymmetric
- [ ] symmetric (pbkdf2)
- [ ] symmetric (argon2id)

### ssl decrypt
- [ ] asymmetric
- [ ] symmetric (pbkdf2)
- [ ] symmetric (argon2id)

### gpg genpair
- [x] complete
- [x] with subkeys
- [x] with passphrase from gui
- [x] with passphrase from file
- [x] with passphrase from arg
- [x] without passphrase
- [x] optional with uid, passphrase for each type of subkey
- 
### gpg addsubkey
- [x] complete
- [x] with passphrase from gui
- [x] with passphrase from file
- [x] with passphrase from arg
- [x] without passphrase
- [x] optional with uid

### gpg import
- [ ] complete

### gpg export
- [x] complete
- [x] with passphrase from gui
- [x] with passphrase from file
- [x] with passphrase from arg
- [x] without passphrase
- [x] encrypted secret key 

### show-index
- [x] normal output
- [x] json output

### reset-dcrypto
- [x] ssl reset
- [x] gpg reset

### misc
- [x] debug mode
- [x] verbose mode
- [x] quiet mode (no stdout)


A POSIX-compliant shell script to manage SSL certificates and GPG keys with strong encryption and Argon2id key derivation.

## Table of Contents
- [Overview](#overview)
- [Usage](#usage)
- [SSL Commands](#ssl-commands)
  - [ssl create-ca](#ssl-create-ca)
  - [ssl create-key](#ssl-create-key)
  - [ssl create-csr](#ssl-create-csr)
  - [ssl sign-csr](#ssl-sign-csr)
  - [ssl verify-cert](#ssl-verify-cert)
  - [ssl list-ca](#ssl-list-ca)
  - [ssl show-ca](#ssl-show-ca)
  - [ssl encrypt](#ssl-encrypt)
  - [ssl decrypt](#ssl-decrypt)
  - [ssl create-crl](#ssl-create-crl)
  - [ssl revoke-cert](#ssl-revoke-cert)
  - [ssl create-config](#ssl-create-config)
- [GPG Commands](#gpg-commands)
  - [gpg import](#gpg-import)
  - [gpg export](#gpg-export)
  - [gpg encrypt](#gpg-encrypt)
  - [gpg decrypt](#gpg-decrypt)
  - [gpg genpair](#gpg-genpair)
- [Maintenance Commands](#maintenance-commands)
  - [show-index](#show-index)
  - [cleanup](#cleanup)
  - [backup](#backup)
  - [restore](#restore)
  - [set-default-ca](#set-default-ca)
- [Other Commands](#other-commands)
- [Examples](#examples)
- [Files](#files)
- [Notes](#notes)

## Overview
dystopian-crypto is a POSIX shell script that simplifies the management of SSL certificates and GPG keys. It uses strong encryption with Argon2id key derivation to secure private keys and provides a user-friendly interface to handle complex OpenSSL and GPG operations.

## Usage

## SSL Commands

### ssl create-ca
Create a Root or Intermediate Certificate Authority.

### ssl create-key
Create a private key with optional Argon2id encryption.

### ssl create-csr
Create a Certificate Signing Request.

### ssl sign-csr
Sign a Certificate Signing Request.

### ssl verify-cert
Verify certificate signature and validity.

### ssl list-ca
List Certificate Authorities.

### ssl show-ca
Show detailed CA information.

### ssl encrypt
Encrypt data using certificate.

### ssl decrypt
Decrypt data using private key.

### ssl create-crl
Create Certificate Revocation List.

### ssl revoke-cert
Revoke a certificate.

### ssl show-index
Show SSL index information.

### ssl create-config
Create SSL configuration file for OpenSSL operations.

## GPG Commands

### gpg import
Import GPG key to keyring.

### gpg export
Export GPG key from keyring.

### gpg genpair
Generate GPG key pair.

### gpg addsubkey
Add subkey to GPG key.

## Maintenance Commands

### show-index
Show SSL index information.

- `--keys`: (Optional) Show key entries
- `--ca`: (Optional) Show CA entries
- `--verbose`: (Optional) Show detailed information
- `--json`: (Optional) Output raw JSON index

### cleanup
Clean up dystopian-crypto files and index.

- `--index <index>`: (Optional) Clean up specific index entry
- `--orphaned`: (Optional) Remove orphaned files not in index
- `--backups`: (Optional) Remove backup files
- `--dry-run`: (Optional) Show what would be cleaned without doing it

### backup
Create backup of dystopian-crypto directory.

- `--out <file>`: (Optional) Backup output file (default: `/tmp/dystopian-crypto-backup-YYYYMMDD_HHMMSS.tar`)
- `--compress`: (Optional) Compress backup with gzip
- `--exclude-keys`: (Optional) Exclude private keys from backup

### restore
Restore dystopian-crypto directory from backup.

- `--from <file>`: (Required) Backup file to restore from
- `--force`: (Optional) Force restore without confirmation

### set-default-ca
Set default Certificate Authority.

- `--index <index>`: (Required) CA index to set as default
- `--type <root|intermediate>`: (Optional) CA type (default: root)

## Other Commands
- `--verbose` or `-v`: Show verbose status information
- `--debug`: Show debug status information
- `version`: Show version information
- `help`: Show this help message

## Examples

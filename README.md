# DCrypto Shell Script

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
- [ ] sign with unencrypted CA key
- [ ] sign with encrypted CA key (pbkdf2)
- [ ] sign with encrypted CA key (argon2id)
- [ ] cert signature verification (unencrypted)
- [ ] cert signature verification (encrypted)
- [ ] cert content verification (unencrypted)
- [ ] cert content verification (encrypted)

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
- [x] symmetric (pbkdf2)
- [ ] symmetric (argon2id)

### ssl decrypt
- [ ] asymmetric
- [x] symmetric (pbkdf2)
- [ ] symmetric (argon2id)

### gpg import
- [ ] complete

### gpg export
- [ ] complete

### gpg encrypt
- [ ] complete

### gpg decrypt
- [ ] complete

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
DCrypto is a POSIX shell script that simplifies the management of SSL certificates and GPG keys. It uses strong encryption with Argon2id key derivation to secure private keys and provides a user-friendly interface to handle complex OpenSSL and GPG operations.

## Usage

## SSL Commands

### ssl create-ca
Create a Root or Intermediate Certificate Authority.

- `--name <string>`: (Required) Common Name (CN) for the CA
- `--outcert <file>`: (Optional) Output certificate file (default: `ca.pem` or `intermediate-ca.pem`)
- `--outkey <file>`: (Optional) Output private key file (default: `ca-key.pem` or `intermediate-ca-key.pem`)
- `--intermediate`: (Optional) Create intermediate CA instead of root CA
- `--password <file|string>`: (Optional) Password for private key encryption (default: Argon2id)
- `--email <string>`: (Optional) Email address for certificate
- `--country <string>`: (Optional) Country code (e.g., US, DE)
- `--state <string>`: (Optional) State or province (ST)
- `--locality <string>`: (Optional) City or locality (C)
- `--org <string>`: (Optional) Organization name (O)
- `--orgunit <string>`: (Optional) Organizational unit (OU)
- `--days <number>`: (Optional) Certificate validity in days (default: 3650)

### ssl create-key
Create a private key with optional Argon2id encryption.

- `--out <file|stdout>`: (Optional) Output file (default: `$DCRYPTO_KEY/key.pem`)
- `--password <file|string>`: (Optional) Password for encryption (enables Argon2id)
- `--salt <file|string>`: (Optional) Custom salt (auto-generated if not provided)
- `--user <string>`: (Optional) Makes key accessible for user group

### ssl create-csr
Create a Certificate Signing Request.

- `--domains <string>`: (Required for server certs) Comma-separated domains/IPs
- `--key <file>`: (Required) Private key file
- `--cn <string>`: (Required for client certs) Common Name
- `--out <file>`: (Optional) Output CSR file
- `--server`: (Optional) Creates CSR for a server certificate (default: false)
- `--client`: (Optional) Creates CSR for a client certificate (default: true)
- `--pass <file|string>`: (Optional) Private key password
- `--email <string>`: (Optional) Email address
- `--country <string>`: (Optional) Country code
- `--state <string>`: (Optional) State or province
- `--locality <string>`: (Optional) City or locality
- `--org <string>`: (Optional) Organization name
- `--orgunit <string>`: (Optional) Organizational unit
- `--crldist <url>`: (Optional) CRL distribution point URL

### ssl sign-csr
Sign a Certificate Signing Request.

- `--csr <file>`: (Required) CSR file to sign
- `--ca-cert <file>`: (Optional) CA certificate file (default: defaultCA)
- `--ca-key <file>`: (Optional) CA private key file (default: defaultCA)
- `--out <file>`: (Optional) Output certificate file
- `--ca-pass <file|string>`: (Optional) CA private key password
- `--days <number>`: (Optional) Certificate validity in days
- `--keep-csr`: (Optional) Keep CSR file after signing
- `--keep-cfg`: (Optional) Keep configuration file after signing

### ssl verify-cert
Verify certificate signature and validity.

- `--cert <file>`: (Required) Certificate file to verify
- `--ca <file>`: (Required) CA certificate for verification
- `--chain <file>`: (Optional) Certificate chain file

### ssl list-ca
List Certificate Authorities.

- `--type <all|root|intermediate>`: (Optional) CA type to list (default: all)
- `--verbose`: (Optional) Show detailed information

### ssl show-ca
Show detailed CA information.

- `--index <index>`: (Required) CA index to show
- `--type <root|intermediate>`: (Optional) CA type (default: root)
- `--cert`: (Optional) Show certificate details

### ssl encrypt
Encrypt data using certificate.

- `--cert <file>`: (Required) Certificate file for encryption
- `--in <file>`: (Required) Input file to encrypt
- `--out <file>`: (Required) Output encrypted file

### ssl decrypt
Decrypt data using private key.

- `--in <file|stdin>`: (Required) Input encrypted file
- `--pass <file|string>`: (Required) Passphrase to decrypt input file
- `--key <file>`: (Optional) Private key file for decryption
- `--out <file>`: (Optional) Output decrypted file (default: stdout)

### ssl create-crl
Create Certificate Revocation List.

- `--ca-key <file>`: (Optional) CA private key file (default: defaultCA)
- `--ca-cert <file>`: (Optional) CA certificate file (default: defaultCA)
- `--out <file>`: (Optional) Output CRL file (default: `$DCRYPTO_CRL/<file>.crl`)
- `--ca-pass <file|string>`: (Optional) CA private key password
- `--days <number>`: (Optional) CRL validity in days

### ssl revoke-cert
Revoke a certificate.

- `--cert <file>`: (Required) Certificate file to revoke
- `--ca-key <file>`: (Required) CA private key file
- `--ca-cert <file>`: (Required) CA certificate file
- `--ca-pass <file|string>`: (Optional) CA private key password
- `--reason <reason>`: (Optional) Revocation reason

### ssl show-index
Show SSL index information.

- `--keys`: (Optional) Show key entries
- `--ca`: (Optional) Show CA entries
- `--verbose`: (Optional) Show detailed information
- `--json`: (Optional) Output raw JSON index

### ssl create-config
Create SSL configuration file for OpenSSL operations.

- `--type <rootca|intca|client|server>`: (Required) Certificate type to generate config for
- `--domains-ips <string>`: (Optional) Comma-separated domains/IPs (for server certs)
- `--email <string>`: (Optional) Email address for certificate
- `--country <string>`: (Optional) Country code (e.g., US, DE)
- `--state <string>`: (Optional) State or province
- `--locality <string>`: (Optional) City or locality
- `--organization <string>`: (Optional) Organization name
- `--orgunit <string>`: (Optional) Organizational unit
- `--common-name <string>`: (Optional) Common Name (CN) for the certificate
- `--crldistributionpoint <string>`: (Optional) CRL distribution point URL

## GPG Commands

### gpg import
Import GPG key to keyring.

- `--key <file>`: (Required) Key file to import
- `--armor`: (Optional) Import ASCII armored key

### gpg export
Export GPG key from keyring.

- `--public <keyid>`: (Required) Export public key (or `--private`)
- `--private <keyid>`: (Required) Export private key (or `--public`)
- `--out <file>`: (Required) Output file
- `--armor`: (Optional) Export in ASCII armor format

### gpg encrypt
Encrypt data with GPG.

- `--recipient <keyid>`: (Required) Recipient key ID or email
- `--in <file>`: (Required) Input file to encrypt
- `--out <file>`: (Required) Output encrypted file
- `--armor`: (Optional) ASCII armor output

### gpg decrypt
Decrypt GPG encrypted data.

- `--in <file>`: (Required) Input encrypted file
- `--out <file>`: (Required) Output decrypted file
- `--pass <file|string>`: (Optional) Private key passphrase

### gpg genpair
Generate GPG key pair.

- `--name <name>`: (Required) Real name for key
- `--email <email>`: (Required) Email address for key
- `--comment <comment>`: (Optional) Comment for key
- `--keysize <bits>`: (Optional) Key size in bits (default: 4096)
- `--expire <date>`: (Optional) Expiration date (0 = never)

## Maintenance Commands

### show-index
Show SSL index information.

- `--keys`: (Optional) Show key entries
- `--ca`: (Optional) Show CA entries
- `--verbose`: (Optional) Show detailed information
- `--json`: (Optional) Output raw JSON index

### cleanup
Clean up DCrypto files and index.

- `--index <index>`: (Optional) Clean up specific index entry
- `--orphaned`: (Optional) Remove orphaned files not in index
- `--backups`: (Optional) Remove backup files
- `--dry-run`: (Optional) Show what would be cleaned without doing it

### backup
Create backup of DCrypto directory.

- `--out <file>`: (Optional) Backup output file (default: `/tmp/dcrypto-backup-YYYYMMDD_HHMMSS.tar`)
- `--compress`: (Optional) Compress backup with gzip
- `--exclude-keys`: (Optional) Exclude private keys from backup

### restore
Restore DCrypto directory from backup.

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

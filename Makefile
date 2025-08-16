PREFIX = /usr

SHELL := sh

.PHONY: \
	install uninstall setup remove all backup \
	setup-shared setup-dcrypto-part setup-dsecboot-part setup-dhosts-part \
	remove-shared remove-dcrypto remove-hosts remove-secboot \
	bkp-tool


install: setup
uninstall: remove
remove: remove-dcrypto remove-hosts remove-secboot remove-shared
setup-dcrypto: setup-shared setup-dcrypto-part
setup-dsecboot: setup-shared setup-dsecboot-part
setup-dhosts: setup-shared setup-dhosts-part
setup: setup-shared setup-dcrypto-part setup-dhosts-part setup-dsecboot-part
all: setup

setup-shared:
	install -d $(PREFIX)/lib/dystopian-tools
	install -m 640 lib/variables.sh $(PREFIX)/lib/dystopian-tools/variables.sh
	install -m 640 lib/helper.sh $(PREFIX)/lib/dystopian-tools/helper.sh
	install -d $(PREFIX)/share/doc/dystopian-tools
	install -m 644 README.md $(PREFIX)/share/doc/dystopian-tools/README.md

setup-dcrypto-part:
	install -m 750 bin/dystopian-crypto $(PREFIX)/bin/dystopian-crypto
	install -d -m 755 /etc/dystopian-crypto
	install -d -m 755 /etc/dystopian-crypto/ca
	install -d -m 750 /etc/dystopian-crypto/ca/private
	install -d -m 755 /etc/dystopian-crypto/cert
	install -d -m 750 /etc/dystopian-crypto/cert/private
	install -d -m 750 /etc/dystopian-crypto/old
	install -d -m 700 /etc/dystopian-crypto/gnupg
	install -d -m 755 /etc/dystopian-crypto/crl
	install -m 600 conf/crypto-db.json /etc/dystopian-crypto/crypto-db.json
	install -m 640 lib/crypto-db.sh $(PREFIX)/lib/dystopian-tools/crypto-db.sh
	install -m 640 lib/ssl.sh $(PREFIX)/lib/dystopian-tools/ssl.sh
	install -m 640 lib/gpg.sh $(PREFIX)/lib/dystopian-tools/gpg.sh

setup-dsecboot-part:
	install -m 750 bin/dystopian-secboot $(PREFIX)/bin/dystopian-secboot
	install -d -m 700 /etc/dystopian-secboot
	install -d -m 700 /etc/dystopian-secboot/ms
	install -m 600 conf/secboot-db.json /etc/secboot-crypto/secboot-db.json
	install -m 640 lib/crypto-db.sh $(PREFIX)/lib/dystopian-tools/secboot-db.sh
	install -m 640 lib/secboot.sh $(PREFIX)/lib/dystopian-tools/secboot.sh

setup-dhosts-part:
	install -m 750 bin/dystopian-hosts $(PREFIX)/bin/dystopian-hosts
	install -d -m 755 /etc/dystopian-hosts
	install -m 600 conf/hosts-db.json /etc/hosts-crypto/hosts-db.json
	install -m 640 lib/crypto-db.sh $(PREFIX)/lib/dystopian-tools/hosts-db.sh
	install -m 640 lib/hosts.sh $(PREFIX)/lib/dystopian-tools/hosts.sh

remove-shared:
	rm -f $(PREFIX)/lib/dystopian-tools/variables.sh
	rm -f $(PREFIX)/lib/dystopian-tools/helper.sh
	rm -f $(PREFIX)/lib/dystopian-tools/ssl.sh
	rm -f $(PREFIX)/lib/dystopian-tools/gpg.sh
	rm -f $(PREFIX)/lib/dystopian-tools/secboot.sh
	rm -f $(PREFIX)/lib/dystopian-tools/crypto-db.sh
	rm -f $(PREFIX)/lib/dystopian-tools/secboot-db.sh
	rm -f $(PREFIX)/lib/dystopian-tools/hosts.sh
	rmdir $(PREFIX)/lib/dystopian-tools || true
	rm -f $(PREFIX)/share/doc/dystopian-tools/README.md
	rmdir $(PREFIX)/share/doc/dystopian-tools || true

remove-dcrypto: SRC = dystopian-crypto
remove-dcrypto: bkp-tool
remove-dcrypto:
	rm -f $(PREFIX)/bin/dystopian-crypto
	rm -f /etc/dystopian-crypto/crypto-db.json
	rmdir /etc/dystopian-crypto/ca/private || true
	rmdir /etc/dystopian-crypto/ca || true
	rmdir /etc/dystopian-crypto/cert/private || true
	rmdir /etc/dystopian-crypto/cert || true
	rmdir /etc/dystopian-crypto/old || true
	rmdir /etc/dystopian-crypto/gnupg || true
	rmdir /etc/dystopian-crypto/crl || true
	rmdir /etc/dystopian-crypto || true

remove-secboot: SRC = dystopian-secboot
remove-secboot: bkp-tool
remove-secboot:
	rm -f $(PREFIX)/bin/dystopian-secboot
	rm -f /etc/dystopian-secboot/secboot-db.json
	rmdir /etc/dystopian-secboot/ms || true
	rmdir /etc/dystopian-secboot/ || true
	rmdir /etc/dystopian-secboot || true

remove-hosts: SRC = dystopian-hosts
remove-hosts: bkp-tool
remove-hosts:
	rm -f $(PREFIX)/bin/dystopian-hosts
	rm -f $(PREFIX)/lib/dystopian-tools/hosts-db.sh
	rm -f /etc/dystopian-hosts/hosts-db.json
	rmdir /etc/dystopian-hosts/ || true
	rmdir /etc/dystopian-hosts || true


bkp-tool:
	@set -eu; \
	. $(PREFIX)/lib/dystopian-tools/variables.sh; \
	. $(PREFIX)/lib/dystopian-tools/helper.sh; \
	: "$${SRC:?Set SRC to a directory name (e.g. dystopian-crypto) or absolute path}"; \
	case "$$SRC" in \
		/*) _path="$$SRC" ;; \
		*)  _path="/etc/$$SRC" ;; \
	esac; \
	backup_targz "$$_path"

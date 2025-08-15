PREFIX = /usr/local

install: setup
uninstall: remove

setup:
	install -d $(PREFIX)/bin
	install -m 750 bin/dystopian-crypto $(PREFIX)/bin/dystopian-crypto
	install -d -m 755 /etc/dystopian-crypto
	install -d -m 755 /etc/dystopian-crypto/ca
	install -d -m 750 /etc/dystopian-crypto/ca/private
	install -d -m 755 /etc/dystopian-crypto/cert
	install -d -m 750 /etc/dystopian-crypto/cert/private
	install -d -m 750 /etc/dystopian-crypto/old
	install -d -m 700 /etc/dystopian-crypto/gnupg
	install -d -m 755 /etc/dystopian-crypto/crl
	install -d -m 700 /etc/dystopian-crypto/secboot
	install -d -m 700 /etc/dystopian-crypto/secboot/ms
	install -m 600 conf/db.json /etc/dystopian-crypto/db.json
	install -d $(PREFIX)/lib/dystopian-crypto
	install -m 640 lib/variables.sh $(PREFIX)/lib/dystopian-crypto/variables.sh
	install -m 640 lib/db.sh $(PREFIX)/lib/dystopian-crypto/db.sh
	install -m 640 lib/helper.sh $(PREFIX)/lib/dystopian-crypto/helper.sh
	install -m 640 lib/ssl.sh $(PREFIX)/lib/dystopian-crypto/ssl.sh
	install -m 640 lib/gpg.sh $(PREFIX)/lib/dystopian-crypto/gpg.sh
	install -m 640 lib/secboot.sh $(PREFIX)/lib/dystopian-crypto/secboot.sh
	install -d $(PREFIX)/share/doc/dystopian-crypto
	install -m 644 README.md $(PREFIX)/share/doc/dystopian-crypto/README.md

remove:
	# remove installed executables and library files
	rm -f $(PREFIX)/bin/dystopian-crypto
	rm -f $(PREFIX)/lib/dystopian-crypto/variables.sh
	rm -f $(PREFIX)/lib/dystopian-crypto/db.sh
	rm -f $(PREFIX)/lib/dystopian-crypto/helper.sh
	rm -f $(PREFIX)/lib/dystopian-crypto/ssl.sh
	rm -f $(PREFIX)/lib/dystopian-crypto/gpg.sh
	rm -f $(PREFIX)/lib/dystopian-crypto/secboot.sh
	# try to remove lib dir if empty
	rmdir $(PREFIX)/lib/dystopian-crypto || true

	# remove documentation
	rm -f $(PREFIX)/share/doc/dystopian-crypto/README.md
	rmdir $(PREFIX)/share/doc/dystopian-crypto || true

	# remove configuration/db file
	rm -f /etc/dystopian-crypto/db.json

	# attempt to remove directories created under /etc; rmdir will only remove if empty
	rmdir /etc/dystopian-crypto/ca/private || true
	rmdir /etc/dystopian-crypto/ca || true
	rmdir /etc/dystopian-crypto/cert/private || true
	rmdir /etc/dystopian-crypto/cert || true
	rmdir /etc/dystopian-crypto/old || true
	rmdir /etc/dystopian-crypto/gnupg || true
	rmdir /etc/dystopian-crypto/crl || true
	rmdir /etc/dystopian-crypto/secboot/ms || true
	rmdir /etc/dystopian-crypto/secboot || true
	# final attempt to remove top-level config directory if it's empty
	rmdir /etc/dystopian-crypto || true

PREFIX = /usr/local

install: setup

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

PREFIX = /usr/local

install: setup

setup:
	install -d $(PREFIX)/bin
	install -m 750 bin/dcrypto $(PREFIX)/bin/dcrypto
	install -d -m 755 /etc/dcrypto
	install -d -m 755 /etc/dcrypto/ca
	install -d -m 750 /etc/dcrypto/ca/private
	install -d -m 755 /etc/dcrypto/cert
	install -d -m 750 /etc/dcrypto/cert/private
	install -d -m 750 /etc/dcrypto/old
	install -d -m 700 /etc/dcrypto/gnupg
	install -d -m 755 /etc/dcrypto/crl
	install -m 600 conf/db.json /etc/dcrypto/db.json
	install -d $(PREFIX)/lib/dcrypto
	install -m 640 lib/variables.sh $(PREFIX)/lib/dcrypto/variables.sh
	install -m 640 lib/db.sh $(PREFIX)/lib/dcrypto/db.sh
	install -m 640 lib/helper.sh $(PREFIX)/lib/dcrypto/helper.sh
	install -m 640 lib/ssl.sh $(PREFIX)/lib/dcrypto/ssl.sh
	install -m 640 lib/gpg.sh $(PREFIX)/lib/dcrypto/gpg.sh
	install -d $(PREFIX)/share/doc/dcrypto
	install -m 644 README.md $(PREFIX)/share/doc/dcrypto/README.md

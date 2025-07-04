PREFIX = /usr/local

install:
    install -d $(PREFIX)/bin
    install -m 750 bin/dcrypto $(PREFIX)/bin/dcrypto
    install -d $(PREFIX)/lib/dcrypto
    install -m 640 lib/db.sh $(PREFIX)/lib/dcrypto/db.sh
    install -m 640 lib/helper.sh $(PREFIX)/lib/dcrypto/helper.sh
    install -m 640 lib/ssl.sh $(PREFIX)/lib/dcrypto/ssl.sh
    install -d $(PREFIX)/share/doc/dcrypto
    install -m 644 README.md $(PREFIX)/share/doc/dcrypto/README.md

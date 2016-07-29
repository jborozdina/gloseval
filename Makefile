KEYPASS   = keypassword
STOREPASS = keystorepassword

KEYSTORE = src/main/resources/keystore.jks
PEM      = src/test/resources/gloseval.pem

all: keystore

keystore: $(KEYSTORE)

pem: $(PEM)

$(KEYSTORE):
	keytool -genkey \
		-alias domain \
		-keyalg RSA \
		-validity 365 \
		-keystore $@ \
		-keypass $(KEYPASS) \
		-storepass $(STOREPASS) \
		-dname "CN=Unknown, OU=Unknown, O=Unknown, L=Unknown, ST=Unknown, C=Unknown"

$(PEM): $(KEYSTORE)
	keytool -exportcert \
		-rfc \
		-alias domain \
		-keystore $(KEYSTORE) \
		-file $@ \
		-storepass $(STOREPASS) \

clean:
	rm -f $(KEYSTORE)
	rm -f $(PEM)

.PHONY: all clean keystore pem

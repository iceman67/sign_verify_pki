CFLAGS = -I $(HOME)/cryptopp -Wall -g -O2 
OPENSSL_INC=/usr/local/opt/openssl/include
OPENSSL_LIB=/usr/local/opt/openssl/lib

all: sign_veifify test_sodum x.509

sign_verify: sign_verify.cpp
	g++  -o sign_verify $(CFLAGS) sign_verify.cpp -lcryptopp

test_sodum: test_sodum.c
	gcc -o test_sodum  test_sodum.c -lsodium

x.509: x.509.cpp
	g++  -o x.509 $(CFLAGS) x.509.cpp -L ${OPENSSL_LIB}  -lssl -lcrypto
	
test_crypto_box: crypto_box.c
	gcc crypto_box.c -lsodium -o crypto_box

clean:
	rm -r sign_verify.dSYM
	rm sign_verify

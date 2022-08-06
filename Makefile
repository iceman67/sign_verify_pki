CFLAGS = -I $(HOME)/cryptopp -Wall -g -O2

sign_verify: sign_verify.cpp
	g++  -o sign_verify $(CFLAGS) sign_verify.cpp -lcryptopp

clean:
	rm -r sign_verify.dSYM
	rm sign_verify

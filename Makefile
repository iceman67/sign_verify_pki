CFLAGS = -I $(HOME)/cryptopp -Wall -g -O2

sign_verify: sign_verify.cpp
	g++  -o sign_veify $(CFLAGS) sign_verify.cpp -lcryptopp

clean:
	rm *.o sign_verify

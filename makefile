uplink: uplink.cpp uplink.h mainmode.cpp peermode.cpp common.cpp sha-256.c base58.c
	g++ uplink.cpp mainmode.cpp peermode.cpp common.cpp sha-256.c base58.c -g -o uplink -march=native -lssl -lcrypto -lsecp256k1 -lsodium

uplink: uplink.cpp uplink.h mainmode.cpp peermode.cpp common.cpp sha-256.c base58.c ripple.pb.cc config.h makefile
	g++ ripple.pb.cc ip.cpp common.cpp uplink.cpp mainmode.cpp peermode.cpp sha-256.c base58.c -g -o uplink -march=native -lssl -lcrypto -lsecp256k1 -lsodium -lprotobuf -lgmp --std=c++20
ripple.pb.cc: ripple.proto
	protoc --cpp_out=. ripple.proto

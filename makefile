uplink: uplink.cpp uplink.h mainmode.cpp peermode.cpp common.cpp sha-256.c base58.c ripple.pb.cc config.h makefile
	clang++  -march=x86-64 -msse4.2 -mcrc32 ripple.pb.cc ip.cpp common.cpp uplink.cpp mainmode.cpp peermode.cpp sha-256.c base58.c -g -o uplink -lssl -lcrypto -lsecp256k1 -lsodium -lprotobuf -lgmp --std=c++20
ripple.pb.cc: ripple.proto
	protoc --cpp_out=. ripple.proto

uplink: uplink.cpp uplink.h mainmode.cpp peermode.cpp common.cpp sha-256.c base58.c ripple.pb.cc 
	g++ ripple.pb.cc uplink.cpp mainmode.cpp peermode.cpp common.cpp sha-256.c base58.c -g -o uplink -march=native -lssl -lcrypto -lsecp256k1 -lsodium -lprotobuf
ripple.pb.cc: ripple.proto
	protoc --cpp_out=. ripple.proto

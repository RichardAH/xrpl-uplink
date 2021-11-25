uplink: uplink.cpp uplink.h mainmode.cpp peermode.cpp common.cpp
	g++ uplink.cpp mainmode.cpp peermode.cpp common.cpp -g -o uplink -march=native

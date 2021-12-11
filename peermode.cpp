#include "uplink.h"

// ---------
// PEER MODE
// ---------
//
// In this file: peer refers to TCP endpoint connecting out to the XRPL node.
// RH NOTE: `peer_path` (uplink.cpp) == `main_path` (peermode.cpp)
//           typically: /var/run/xrpl-uplink/peer.sock

#define print_hash(h, before, after)\
{\
    fprintf(stderr, "%s%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X"\
                    "%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%s",\
                    before,\
               h.b[0], h.b[1], h.b[2], h.b[3], h.b[4], h.b[5], h.b[6], h.b[7],\
               h.b[8], h.b[9], h.b[10], h.b[11], h.b[12], h.b[13], h.b[14], h.b[15],\
               h.b[16], h.b[17], h.b[18], h.b[19], h.b[20], h.b[21], h.b[22], h.b[23],\
               h.b[24], h.b[25], h.b[26], h.b[27], h.b[28], h.b[29], h.b[30], h.b[31], after);\
}


int connect_peer(char* ip, int port, int* peer_fd)
{
    if ((*peer_fd = socket(AF_INET, SOCK_STREAM, 0)) < 0)
    {
        printl("Could not create TCP socket for peer %s:%d\n", ip, port);
        return EC_TCP;
    }

    struct sockaddr_in peer_addr;
    memset(&peer_addr, '0', sizeof(peer_addr));

    peer_addr.sin_family = AF_INET;
    peer_addr.sin_port = htons(port);

    if (inet_pton(AF_INET, ip, &peer_addr.sin_addr) <= 0)
    {
        printl("Could not parse ip %s while trying to connect to peer\n", ip);
        return EC_TCP;
    }

    if (connect(*peer_fd, (struct sockaddr *)&peer_addr, sizeof(peer_addr)) < 0)
    {
        printl("Could not connect to peer %s:%d\n", ip, port);
        return EC_TCP;
    }

    int optval = 1;
    if (setsockopt(*peer_fd, IPPROTO_TCP, TCP_NODELAY, &optval, sizeof(optval)) == -1)
    {
        printl("Could not set peer socket to TCP_NODELAY\n");
        return EC_TCP;
    }

    return EC_SUCCESS;
}

int connect_main(char* main_path, int* main_fd)
{
    struct sockaddr_un addr;
    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    strncpy(addr.sun_path, main_path, sizeof(addr.sun_path) - 1);

    // create socket
    if ((*main_fd = socket(AF_UNIX, SOCK_SEQPACKET, 0)) < 0)
    {
        printl("Could not create peer unix domain socket (connecting)\n");
        return EC_UNIX;
    }

    // connect
    if (connect(*main_fd, (const struct sockaddr*)&addr, sizeof(addr)) < 0)
    {
        printl("Could not connect to main unix domain socket %s\n", main_path);
        return EC_UNIX;
    }

    return EC_SUCCESS;
}


int peer_mode(
    char* ip, int port, char* main_path, uint8_t* our_seckey,
    ddmode dd_default, std::map<uint8_t, ddmode>& dd_specific, int rnd_fd)
{

    my_pid = getpid();    

    // we will decompose the passed IP for use later in packet headers
    uint8_t ip_int[4];
    if (sscanf(ip, "%hhu.%hhu.%hhu.%hhu", ip_int, ip_int+1, ip_int+2, ip_int+3) != 4)
        die(EC_ADDR, "failed to parse ipv4: `%s` into integer format\n", ip);

    // connect to peer (TCP/IP)
    int peer_fd = -1;  ASSERT(connect_peer(ip, port, &peer_fd));

    // connect to main (unix)
    int main_fd = -1;  ASSERT(connect_main(main_path, &main_fd));

    // setup SSL
    uint8_t our_pubkey[32] = {0,0,0,0, 0,0,0,0, 0,0,0,0, 0,0,0,0, 0,0,0,0, 0,0,0,0, 0,0,0,0, 0,0,0,0};
    uint8_t peer_pubkey[32] = {0,0,0,0, 0,0,0,0, 0,0,0,0, 0,0,0,0, 0,0,0,0, 0,0,0,0, 0,0,0,0, 0,0,0,0};
    SSL_CTX* sslctx = NULL;
    SSL* ssl = NULL;
    ASSERT(ssl_handshake_and_upgrade(peer_fd, &ssl, &sslctx, our_seckey, our_pubkey, peer_pubkey));

    // sanity check
    if (main_fd < 0 || peer_fd < 0)
        die(EC_GENERIC, "main_fd or peer_fd invalid\n");

    // set up counters and variables 
    int packet_in_type = -1;               // type of the current packet we're receiving, -1 for not yet known
    // uncompressed size of the current packet or 0 if already uncompressed
    uint32_t packet_in_uncompressed_size = 0;
    uint32_t packet_in_expected_size = 0;       // expected bytes
    uint32_t packet_in_received_size = 0;       // received bytes

    // these buffers are used to store a whole packet for processing
    size_t   packet_in_buffer_size = PACKET_BUFFER_NORM;
    size_t   packet_out_buffer_size = PACKET_BUFFER_NORM;
    uint8_t* packet_in_buffer = (uint8_t*)(malloc(packet_in_buffer_size));
    uint8_t* packet_out_buffer = (uint8_t*)(malloc(packet_out_buffer_size));

    uint8_t header_in[10];
    size_t  header_in_upto = 0;

    if (!packet_in_buffer || !packet_out_buffer)
        die(EC_BUFFER, "malloc failed while creating packet_buffer\n");

    std::map<Hash, uint32_t, HashComparator> seen_p2s; // packets already seen from peers to subscribers
    std::map<Hash, uint32_t, HashComparator> seen_s2p; // packets already seen from subscribers to peers
    

    // setup poll
    struct pollfd fdset[2];
    {
        memset(&fdset, 0, sizeof(fdset));
        fdset[0].fd = peer_fd;
        fdset[1].fd = main_fd;
        fdset[0].events = POLLERR | POLLHUP | POLLNVAL | POLLIN;
        fdset[1].events = POLLERR | POLLHUP | POLLNVAL | POLLIN;
    }

    if (DEBUG)
        printl("Starting poll loop for peer %s\n", ip);
    

    // primary poll loop
    int poll_result = -1;
    int timeout = 0; // counter for number of times the poll timesout, should not be large
    while((poll_result = poll(&fdset[0], 2, POLL_TIMEOUT)) >= 0)
    {

        // zero means a timeout, continue
        if (poll_result == 0)
        {
            timeout++;
            if (DEBUG)
                printl("poll timeout");
            if (timeout < MAX_TIMEOUTS)
                continue;
            exit(EC_TIMEOUT);
        }

        // check if the peer socket died
        {
            bool peer_dead = (fdset[0].revents & (POLLERR | POLLHUP | POLLNVAL)) || read(peer_fd, 0, 0);
            bool main_dead = (fdset[1].revents & (POLLERR | POLLHUP | POLLNVAL)) || read(main_fd, 0, 0);
            if (peer_dead || main_dead)
            {
                if (peer_dead)
                    printl("Peer connection lost %s:%d\n", ip, port);
                if (main_dead)
                    printl("Main connection lost %s\n", main_path);
                return EC_LOST;
            }
        }

        // check if there are incoming bytes from TCP
        if (fdset[0].revents & POLLIN)
        while(1)
        {
            size_t dummy = 0;
            SSL_read_ex(ssl, 0, 0, &dummy);
            size_t pending = SSL_pending(ssl);
            if (pending == 0)
                break;
            
            // new packet
            if (packet_in_type == -1)
            {

                size_t to_read = (10 - header_in_upto);
                if (pending < to_read)
                    to_read = pending;

                size_t bytes_read = SSL_read(ssl, header_in + header_in_upto, to_read);


                header_in_upto += bytes_read;

                if (header_in_upto < 6)
                {
                    printl("reading packet header, upto: %ld\n", header_in_upto);
                    break;
                }

                uint32_t payload_size =
                    (header_in[0] << 24) + (header_in[1] << 16) + (header_in[2] << 8) + header_in[3];

                int compressed = payload_size >> 28U;

                if (compressed && header_in_upto < 10)
                {
                    printl("reading extended packet header, upto: %ld\n", header_in_upto);
                    break;
                }


                if (compressed)
                    payload_size &= 0x0FFFFFFFU;

                packet_in_expected_size = payload_size;

                packet_in_type = (header_in[4] << 8) + header_in[5];

                uint32_t uncompressed_size = payload_size;

                if (compressed)
                    uncompressed_size =
                        (header_in[6] << 24) + (header_in[7] << 16) + (header_in[8] << 8) + header_in[9];

                int header_size = (compressed ? 10 : 6);

                // copy left over bytes into the real packet header_in
                for (int i = header_size; i < header_in_upto; ++i)
                    packet_in_buffer[i - header_size] = header_in[i];

                packet_in_received_size = header_in_upto - header_size;


                // edge case: payload fits in already read bytes
                // we may have extra bytes to write back into the next header
                if (packet_in_received_size >= packet_in_expected_size)
                {
                    header_in_upto = packet_in_received_size - packet_in_expected_size;
                    if (header_in_upto > 0)
                        memcpy(header_in, packet_in_buffer + packet_in_expected_size, header_in_upto);
                    packet_in_received_size = packet_in_expected_size;
                }
                else
                    header_in_upto = 0;

                printl("packet header[%ld]: type=%d size=%ld\n", header_size,
                        packet_in_type, packet_in_expected_size);
                
                // resize packet buffer if needed
                ASSERT(resize_buffer(&packet_in_buffer,
                    packet_in_expected_size, &packet_in_buffer_size, PACKET_BUFFER_NORM, PACKET_BUFFER_MAX));

                size_t dummy = 0;
                SSL_read_ex(ssl, 0, 0, &dummy);
                pending = SSL_pending(ssl);

                printl("after header pending=%ld\n", pending);
                // fall through if there are more bytes
            }

            // more of an existing packet we are currently reading
            {
                size_t to_read = packet_in_expected_size - packet_in_received_size;

                
                if (pending < to_read)
                    to_read = pending;

                if (to_read > 0)
                {
                    size_t bytes_read = 
                        SSL_read(ssl, packet_in_buffer + packet_in_received_size, to_read);
                    packet_in_received_size += bytes_read;
                    printl("packet %d - bytes read: %ld\n", packet_in_type, packet_in_received_size);
                }
            }

            if (packet_in_received_size == packet_in_expected_size)
            {
                // full packet received
                printl("packet %d received (%d bytes)\n", packet_in_type, packet_in_expected_size);
                if (packet_in_type == mtPING)
                {
                    // send back a pong
                    protocol::TMPing ping;
                    if (!ping.ParseFromArray(packet_in_buffer, packet_in_expected_size))
                        die(EC_PROTO, "could not parse mtPING");

                    ping.set_type(protocol::TMPing_pingType_ptPONG);

                    int pong_size = ping.ByteSizeLong();
                    uint8_t pong_buf[32];
                    write_header(pong_buf, mtPING, pong_size);
                    if (!ping.SerializeToArray(pong_buf + 6, pong_size))
                        die(EC_GENERIC, "could not serialize pong");
                    
                    SSL_write(ssl, pong_buf, pong_size + 6);

                    printh(pong_buf, pong_size + 6, "wrote pong:");
                }

                packet_in_type = -1;
                packet_in_expected_size = 0;
                packet_in_received_size = 0;
                packet_in_uncompressed_size = 0;
            }
        } 


        // check if there are pending messages to read from main-mode process
        if (fdset[1].revents & POLLIN)
        {
            // first peek the message to find out what sort of message it is
            Message message;
            if (recv(fdset[1].fd, &message, sizeof(message), MSG_PEEK) == -1)
            {
                printl("peeking failed\n");
                return EC_UNIX;
            }
                

            int msg_type = message.unknown.flags >> 28U;

            printl("message received from mainmode type=%d\n", msg_type);
            
            switch (msg_type)
            {
                // incoming packet from subscriber
                case M_PACKET:
                {

                    Hash* packet_out_hash = reinterpret_cast<Hash*>(&message.packet.hash);
                    uint16_t packet_out_type = message.packet.type;
                    uint32_t packet_out_size = message.packet.size;
                    uint32_t packet_out_expected_size = message.packet.size + sizeof(Message);
                   
                    // check if we're allowed to send the packet according to our dd rules
                    {
                        ddmode d = dd_default;
                        if (d == DD_NOT_SET)
                            d = DD_ALL;

                        if (dd_specific.find(packet_out_type) != dd_specific.end())
                            d = dd_specific[packet_out_type];

                        bool drop =     d == DD_BLACKHOLE   || d == DD_SQUELCH  || d == DD_SQUELCH_N;
                        bool dedup =    d == DD_ALL         || d == DD_SUB      || d == DD_DROP;

                        if (dedup && 
                                (seen_s2p.find(*packet_out_hash) != seen_s2p.end() ||
                                 d == DD_ALL &&
                                     seen_p2s.find(*packet_out_hash) != seen_p2s.end()))
                            drop = true;

                        // perform drop by doing a null read and breaking out
                        if (drop)
                        {
                            printl("dropping outgoing packet %d according to ddmode\n", packet_out_type);
                            recv(main_fd, 0, 0, 0);
                            break;
                        }

                        if (dedup)
                        {
                            seen_s2p.emplace(*packet_out_hash, time(NULL));
                            random_eviction(seen_s2p, rnd_fd, EVICTION_SPINS);
                        }
                    }
                    // resize packet buffer if needed
                    ASSERT(resize_buffer(&packet_out_buffer,
                        packet_out_expected_size, &packet_out_buffer_size, 
                        PACKET_BUFFER_NORM, PACKET_BUFFER_MAX));

                    // read the packet
                    if (recv(main_fd, packet_out_buffer, packet_out_expected_size, 0) 
                            != packet_out_expected_size)
                        die(EC_UNIX, "error while reading message (type=packet) from main-mode process\n");

                    // forward packet to peer
                    {
                        uint8_t header[6];
                        write_header(header, packet_out_type, packet_out_size);
                       
                        SSL_write(ssl, header, 6);
                        SSL_write(ssl, packet_out_buffer + sizeof(Message), packet_out_size); 
                    }
                    break;
                }

                // ddmodes
                case M_DDMODE:
                {
                    printl("processing m_ddmode\n");
                    if (dd_default == DD_NOT_SET)
                    {
                        dd_default = (ddmode)(message.ddmode.mode[0] & 0xFFU);
                        printl("default ddmode set to %d\n", dd_default);
                    }
                    else
                        printl("not changing dd_default because it was set specifically at cmdline\n");

                    for (int i = 1; i < 62 && message.ddmode.mode[i] != 0; ++i)
                    {
                        uint8_t ptype = (uint8_t)(message.ddmode.mode[i] >> 8U);
                        uint8_t dtype = (uint8_t)(message.ddmode.mode[i] & 0XFFU);

                        if (dd_specific.find(ptype) == dd_specific.end())
                        {
                            printl("adding ddmode p=%d d=%d\n", ptype, dtype);
                            dd_specific.emplace(ptype, (ddmode)dtype);
                        }
                        else
                            printl("skipping ddmode p=%d d=%d, already set\n", ptype, dtype);
                    }

                    // pull the message this time (no peek)
                    recv(main_fd, &message, sizeof(message), 0);

                    break;
                }

                // peer status       
                case M_PEERSTATUS:
                {
                    printl("peer received peer status message, discarding.\n");
                    break;
                }
            }
        }

    }

    printl("poll returned -1\n");
    free(packet_in_buffer);
    free(packet_out_buffer);
    // todo: should also deallocate a bunch of other things here e.g. ssl context
    // but process terminates, so OS will do it
    return EC_POLL;
}

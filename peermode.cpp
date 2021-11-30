#include "uplink.h"
#include <openssl/ssl.h>
#include <openssl/sha.h>
#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/pem.h>
#include <secp256k1.h>

#define POLL_TIMEOUT 2000 /* ms */
#define DEFAULT_BUF_SIZE 64

#define DEBUG 1
#define VERBOSE_DEBUG 1
#define HTTP_BUFFER_SIZE 4096
#define SSL_BUFFER_SIZE 65536
#define PACKET_BUFFER_NORM 65536
#define PACKET_BUFFER_MAX  67108864

// ---------
// PEER MODE
// ---------
//
// In this file: peer refers to TCP endpoint connecting out to the XRPL node.
// RH NOTE: `peer_path` (uplink.cpp) == `main_path` (peermode.cpp)
//           typically: /var/run/xrpl-uplink/peer.sock

inline pid_t my_pid;

std::map<Hash, uint64_t, HashComparator> seen_p2s;

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

int generate_node_keys(
    secp256k1_context* ctx,
    uint8_t* keyin,
    uint8_t* outpubraw64,
    uint8_t* outpubcompressed33,
    char* outnodekeyb58,
    size_t* outnodekeyb58size)
{
    secp256k1_pubkey* pubkey = (secp256k1_pubkey*)((void*)(outpubraw64));

    if (!secp256k1_ec_pubkey_create(ctx, pubkey, (const unsigned char*)keyin)) {
        printl("Could not generate secp256k1 keypair\n");
        exit(EC_SECP256K1);
    }

    size_t out_size = 33;
    secp256k1_ec_pubkey_serialize(ctx, outpubcompressed33, &out_size, pubkey, SECP256K1_EC_COMPRESSED);

    unsigned char outpubcompressed38[38];

    // copy into the 38 byte check version
    for(int i = 0; i < 33; ++i) outpubcompressed38[i+1] = outpubcompressed33[i];

    // pub key must start with magic type 0x1C
    outpubcompressed38[0] = 0x1C;
    // generate the double sha256
    unsigned char hash[crypto_hash_sha256_BYTES];
    crypto_hash_sha256(hash, outpubcompressed38, 34);

    unsigned char hash2[crypto_hash_sha256_BYTES];
    crypto_hash_sha256(hash2, hash, crypto_hash_sha256_BYTES);

    // copy checksum bytes to the end of the compressed key
    for (int i = 0; i < 4; ++i)
        outpubcompressed38[34+i] = hash2[i];

    // generate base58 encoding
    b58enc(outnodekeyb58, outnodekeyb58size, outpubcompressed38, 38);
    outnodekeyb58[*outnodekeyb58size] = '\0';

    return EC_SUCCESS;
}

int generate_upgrade(
        secp256k1_context* secp256k1ctx,
        SSL* ssl,
        uint8_t* keyin,
        char* bufout, int* buflen)
{
    unsigned char buffer[1024];
    ssize_t len = 0;

    len = SSL_get_finished(ssl, buffer, 1024);
    if (len < 12)
    {
        printl("Could not SSL_get_finished\n");
        return EC_SSL;
    }

    // SHA512 SSL_get_finished to create cookie 1
    unsigned char cookie1[64];
    crypto_hash_sha512(cookie1, buffer, len);

    len = SSL_get_peer_finished(ssl, buffer, 1024);
    if (len < 12)
    {
        printl("Could not SSL_get_peer_finished\n");
        return EC_SSL;
    }

    // SHA512 SSL_get_peer_finished to create cookie 2
    unsigned char cookie2[64];
    crypto_hash_sha512(cookie2, buffer, len);

    // xor cookie2 onto cookie1
    for (int i = 0; i < 64; ++i) cookie1[i] ^= cookie2[i];

    // the first half of cookie2 is the true cookie
    crypto_hash_sha512(cookie2, cookie1, 64);

    // generate keys
    uint8_t pub[64], pubc[33];
    char b58[100];
    size_t b58size = 100;

    int rc = generate_node_keys(secp256k1ctx, keyin, pub, pubc, b58, &b58size);
    if (rc != EC_SUCCESS)
        return rc;

    secp256k1_ecdsa_signature sig;
    secp256k1_ecdsa_sign(secp256k1ctx, &sig, cookie2, keyin, NULL, NULL);

    unsigned char buf1[200];
    size_t buflen1 = 200;
    secp256k1_ecdsa_signature_serialize_der(secp256k1ctx, buf1, &buflen1, &sig);

    char buf2[200];
    size_t buflen2 = 200;
    sodium_bin2base64(buf2, buflen2, buf1, buflen1, sodium_base64_VARIANT_ORIGINAL);
    buf2[buflen2] = '\0';

    int bytes_written =
        snprintf(bufout, *buflen,
            "GET / HTTP/1.1\r\n"
            "User-Agent: %s-%s\r\n"
            "Upgrade: XRPL/2.0\r\n"
            "Connection: Upgrade\r\n"
            "Connect-As: Peer\r\n"
            "Crawl: private\r\n"
            "Session-Signature: %s\r\n"
            "Public-Key: %s\r\n\r\n", USER_AGENT, VERSION, buf2, b58);

    if (bytes_written < *buflen)
    {
        *buflen = bytes_written;
        return EC_SUCCESS;
    }
    else
    {
        printl("Could not create upgrade request, buffer too small. Wrote=%d Buflen=%d.\n", bytes_written, *buflen);
        *buflen = 0;
        return EC_BUFFER;
    }
}


int peer_mode(
    char* ip, int port, char* main_path, uint8_t* key,
    ddmode dd_default, std::map<uint8_t, ddmode>& dd_specific)
{

    my_pid = getpid();

    // create secp256k1 context
    secp256k1_context* secp256k1ctx = secp256k1_context_create(
                SECP256K1_CONTEXT_VERIFY |
                SECP256K1_CONTEXT_SIGN) ;

    // connect to peer (TCP/IP)
    int peer_fd = -1;
    {
        struct sockaddr_in serv_addr;

        if ((peer_fd = socket(AF_INET, SOCK_STREAM, 0)) < 0)
        {
            printl("Could not create TCP socket for peer %s:%d\n", ip, port);
            return EC_TCP;
        }

        memset(&serv_addr, '0', sizeof(serv_addr));

        serv_addr.sin_family = AF_INET;
        serv_addr.sin_port = htons(port);

        if (inet_pton(AF_INET, ip, &serv_addr.sin_addr) <= 0)
        {
            printl("Could not parse ip %s while trying to connect to peer\n", ip);
            return EC_TCP;
        }

        if (connect(peer_fd, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0)
        {
            printl("Could not connect to peer %s:%d\n", ip, port);
            return EC_TCP;
        }
    }

    // connect to main (unix)
    int main_fd = -1;
    {
        struct sockaddr_un addr;
        memset(&addr, 0, sizeof(addr));
        addr.sun_family = AF_UNIX;
        strncpy(addr.sun_path, main_path, sizeof(addr.sun_path) - 1);

        // create socket
        if ((main_fd = socket(AF_UNIX, SOCK_SEQPACKET, 0)) < 0)
        {
            printl("Could not create peer unix domain socket (connecting)\n");
            return EC_UNIX;
        }

        // connect
        if (connect(main_fd, (const struct sockaddr*)&addr, sizeof(addr)) < 0)
        {
            printl("Could not connect to main unix domain socket %s\n", main_path);
            return EC_UNIX;
        }
    }

    // sanity check
    if (main_fd < 0 || peer_fd < 0)
    {
        printl("main_fd or peer_fd invalid\n");
        return EC_GENERIC;
    }

    // setup SSL
    SSL_CTX* ctx = 0;
    BIO* rbio = 0;
    BIO* wbio = 0;
    char*  ssl_write_buf = 0;
    size_t ssl_write_len = 0;
    char*  ssl_encrypt_buf = 0;
    size_t ssl_encrypt_len = 0;
    char ssl_buf[SSL_BUFFER_SIZE];

    // these buffers are used to store a whole packet for processing
    uint8_t* packet_buffer =
        (uint8_t*)(malloc(PACKET_BUFFER_NORM));

    if (!packet_buffer)
    {
        printl("Malloc failed while creating packet_buffer\n");
        return EC_BUFFER;
    }

    size_t packet_buffer_len = PACKET_BUFFER_NORM;

    int packet_type = -1;               // type of the current packet we're receiving
    uint32_t packet_uncompressed = 0;   // uncompressed size of the current packet or 0 if already uncompressed
    uint32_t packet_expected = 0;       // expected bytes
    uint32_t packet_received = 0;       // received bytes


    #define SSL_FAILED(x) (\
        (x) != SSL_ERROR_WANT_WRITE &&\
        (x) != SSL_ERROR_WANT_READ &&\
        (x) != SSL_ERROR_NONE )

    #define SSL_FLUSH_OUT()\
    {\
        ssize_t bytes_read = 0;\
        do\
        {\
            bytes_read = BIO_read(wbio, ssl_buf, sizeof(ssl_buf));\
            if (DEBUG)\
                printl("flushing %ld bytes\n", bytes_read);\
            if (bytes_read > 0)\
            {\
                ssl_write_buf = (char*)realloc(ssl_write_buf, ssl_write_len + bytes_read);\
                memcpy(ssl_write_buf + ssl_write_len, ssl_buf, bytes_read);\
                ssl_write_len += bytes_read;\
            }\
            else if (!BIO_should_retry(wbio))\
            {\
                printl("Could not enqueue outward SSL bytes\n");\
                return EC_SSL;\
            }\
        } while (bytes_read > 0);\
    }

    #define SSL_ENQUEUE(buf, len)\
    {\
        ssl_encrypt_buf = (char*)realloc(ssl_encrypt_buf, ssl_encrypt_len + len);\
        memcpy(ssl_encrypt_buf + ssl_encrypt_len, buf, len);\
        ssl_encrypt_len += len; \
    }

    // configure SSL method
    {
        const SSL_METHOD* method = SSLv23_method();
        ctx = SSL_CTX_new(method);
        if (!ctx) {
            perror("Unable to create SSL context");
            ERR_print_errors_fp(stderr);
            return EC_SSL;
        }
    }

    SSL_CTX_set_ecdh_auto(ctx, 1);

    SSL* ssl = SSL_new(ctx);
    rbio = BIO_new(BIO_s_mem()); /* SSL reads from, we write to. */
    wbio = BIO_new(BIO_s_mem()); /* SSL writes to, we read from. */
    SSL_set_bio(ssl, rbio, wbio);
    SSL_set_connect_state(ssl);
    if (DEBUG)
        printl("trying to start ssl handshake\n");
    int n = SSL_do_handshake(ssl);
    SSL_FLUSH_OUT();

    // make fds non-blocking
    fd_set_flags(peer_fd, O_NONBLOCK);
    fd_set_flags(main_fd, O_NONBLOCK);

    // setup poll
    struct pollfd fdset[2];
    memset(&fdset, 0, sizeof(fdset));

    fdset[0].fd = peer_fd;
    fdset[1].fd = main_fd;

    int connection_upgraded = 0;

    if (DEBUG)
        printl("Starting poll loop for peer %s\n", ip);

    // primary poll loop
    while(1)
    {

        SSL_FLUSH_OUT();

        // check if there are enqueued bytes ready to be encrypted
        while (ssl_encrypt_len > 0)
        {
            int bytes_written = SSL_write(ssl, ssl_encrypt_buf, ssl_encrypt_len);

            if (bytes_written > 0)
            {
                /* consume the waiting bytes that have been used by SSL */
                if ((size_t)bytes_written < ssl_encrypt_len)
                    memmove(ssl_encrypt_buf, ssl_encrypt_buf+bytes_written, ssl_encrypt_len-bytes_written);
                ssl_encrypt_len -= bytes_written;
                ssl_encrypt_buf = (char*)realloc(ssl_encrypt_buf, ssl_encrypt_len);
                SSL_FLUSH_OUT();
            }

            int status = SSL_get_error(ssl, bytes_written);

            if (status == SSL_ERROR_WANT_WRITE)
                SSL_FLUSH_OUT()
            else if (SSL_FAILED(status))
                printl("Unable to complete out going write\n");

            if (bytes_written == 0)
              break;
        }


        // setup and execute poll such that a free outgoing buffer will trigger if we have pending bytes to write out
        fdset[0].events =  POLLERR | POLLHUP | POLLNVAL | POLLIN |
            (ssl_write_len > 0  ? POLLOUT : 0);
        fdset[1].events =  POLLERR | POLLHUP | POLLNVAL | POLLIN ;
        int poll_result = poll(&fdset[0], 2, POLL_TIMEOUT);

        if (poll_result < 0)
        {
            printl("poll returned -1\n");
            return EC_POLL;
        }

        if (poll_result == 0)
        {
            // if poll returns with no active fds then two seconds have passed without activity
            // this is ok unless we're still doing an SSL connection to the peer, in which case it's time to end
            if (SSL_is_init_finished(ssl))
                continue;

            printl("SSL handshake timed out with peer %s:%d\n", ip, port);
            return EC_SSL;
        }

        // execution to here means the poll returned with one or more active fds / events

        // check if the peer socket died
        if (fdset[0].revents & (POLLERR | POLLHUP | POLLNVAL) || read(peer_fd, 0, 0))
        {
            int error = 0;
            socklen_t errlen = sizeof(error);
            getsockopt(peer_fd, SOL_SOCKET, SO_ERROR, (void *)&error, &errlen);
            printl("Peer connection lost %s:%d, socket err: %d, errno: %d\n", ip, port, error, errno);

            return EC_TCP;
        }

        // check if main socket died
        if (fdset[1].revents & (POLLERR | POLLHUP | POLLNVAL) || read(main_fd, 0, 0))
        {
            int error = 0;
            socklen_t errlen = sizeof(error);
            getsockopt(peer_fd, SOL_SOCKET, SO_ERROR, (void *)&error, &errlen);
            printl("Main connection lost %s, socket err: %d, errno: %d\n", main_path, error, errno);

            return EC_UNIX;
        }


        /*
         * struct iovec {         // Scatter/gather array items 
    void  *iov_base;              // Starting address 
    size_t iov_len;               // Number of bytes to transfer 
};

struct msghdr {
    void         *msg_name;       // optional address 
    socklen_t     msg_namelen;    // size of address 
    struct iovec *msg_iov;        // scatter/gather array 
    size_t        msg_iovlen;     // # elements in msg_iov 
    void         *msg_control;    // ancillary data, see below 
    size_t        msg_controllen; // ancillary data buffer len 
    int           msg_flags;      // flags on received message 
};
*/
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
            

            // pull it from the queue
            recv(fdset[1].fd, &message, sizeof(message), 0);

//            for (int i = 0; i < sizeof(message); ++i)
//                printf("%02X", message[i]);
//            printf("\n");
            /*
            struct iovec iov[1] = {{ .iov_base = message, .iov_len = sizeof(message)}};

            struct msghdr header = {0,0,0,0,0,0,0};

            printl("incoming packet from main-mode\n");
//            while
            if (recvmsg(fdset[1].fd, &header, MSG_PEEK) != -1)
            {
                printl("received mainmode packet: %d\n", header.msg_iov[0].iov_len);
            }
            else
                printl("peeking failed\n");
*/
        }


        // check if there are pending bytes to write from the SSL buffer to the TCP socket
        if (fdset[0].revents & POLLOUT && ssl_write_len)
        {
            ssize_t bytes_written = write(peer_fd, ssl_write_buf, ssl_write_len);
            if (DEBUG)
                printl("RAW outgoing data %ld\n", bytes_written);

            if (bytes_written <= 0)
            {
                printl("Could not write encrypted bytes to socket\n");
                return EC_SSL;
            }

            if (bytes_written < ssl_write_len)
                memmove(ssl_write_buf, ssl_write_buf + bytes_written, ssl_write_len - bytes_written);
            ssl_write_len -= bytes_written;
            ssl_write_buf = (char*)realloc(ssl_write_buf, ssl_write_len);
            if (DEBUG)
                printl("RAW bytes remaining to write: %ld\n", ssl_write_len);
        }

        // check if there are incoming bytes from TCP
        if (fdset[0].revents & POLLIN)
        {

            if (DEBUG && VERBOSE_DEBUG)
                printl("incoming data - connection_upgraded: %d\n", connection_upgraded);



            for (int loop_count = 0; ; ++loop_count)
            {
                ssize_t bytes_read = read(peer_fd, ssl_buf, sizeof(ssl_buf));
                if (bytes_read == -1 && errno == EAGAIN)
                    break;

                if (DEBUG && VERBOSE_DEBUG)
                {
                    printl("RAW incoming data %d bytes from peer:\n", bytes_read);
//                    for (int i = 0; i < bytes_read; ++i)
//                        fprintf(stderr, "%02X", (uint8_t)(ssl_buf[i]));
//                    fprintf(stderr, "\n");
                }

                if (bytes_read < 0 || (bytes_read == 0 && loop_count == 0))
                {
                    printl("Could not read raw bytes from TCP socket: "
                            "bytes_read=%d, loop_count=%d\n", bytes_read, loop_count);
                    return EC_TCP;
                }

                if (bytes_read == 0)
                    break;

                ssize_t bytes_written = BIO_write(rbio, ssl_buf, bytes_read);
                if (bytes_written < 0 || (bytes_written == 0 && loop_count == 0))
                {
                    printl("Could not write raw bytes to SSL buffer from TCP socket\n");
                    return EC_SSL;
                }


                if (DEBUG && VERBOSE_DEBUG)
                {
                    printl("wrote %d RAW bytes to SSL bio\n", bytes_written);
                }

            }

            if (!SSL_is_init_finished(ssl))
            {
                int n = SSL_do_handshake(ssl);
                int e = SSL_get_error(ssl, n);
                SSL_FLUSH_OUT();
                continue;
            }


            if (connection_upgraded == 0)
            {
                //int generate_upgrade(SSL* ssl, char* keyin, char* bufout, int buflen)
                char upgrade_request[HTTP_BUFFER_SIZE];
                int len = sizeof(upgrade_request);
                int rc = generate_upgrade(secp256k1ctx, ssl, key, upgrade_request, &len);
                if (rc != EC_SUCCESS)
                    return rc;

                if (DEBUG)
                printl("Connection upgrade request to %s:%d\n%.*s%s",
                    ip, port,
                    (VERBOSE_DEBUG ? len : 0),
                    (VERBOSE_DEBUG ? upgrade_request : ""),
                    (VERBOSE_DEBUG ? "\n" : "")
                );

                SSL_ENQUEUE(upgrade_request, len);
                SSL_FLUSH_OUT();
                connection_upgraded = 1;

                // fall through
            }

            if (connection_upgraded == 1)
            {

                char buffer[HTTP_BUFFER_SIZE];
                size_t bytes_read = 0;
                int rc = -1;
                if ((rc = SSL_peek_ex(ssl, buffer, sizeof(buffer), &bytes_read)) > 0)
                {
                    for (int i = 0; i < bytes_read - 3; ++i)
                    {
                        // looking for \r\n\r\n
                        if (buffer[i + 0] == 0xD &&
                            buffer[i + 1] == 0xA &&
                            buffer[i + 2] == 0xD &&
                            buffer[i + 3] == 0xA)
                        {
                            if (DEBUG)
                                printl("Connection upgrade response from %s:%d\n%.*s%s",
                                    ip, port,
                                    (VERBOSE_DEBUG ? i + 4 : 0),
                                    (VERBOSE_DEBUG ? buffer : ""),
                                    (VERBOSE_DEBUG ? "\n" : "")
                                );

                            SSL_read(ssl, buffer, i + 4);
                            connection_upgraded = 2;
                            break;
                        }
                    }
                }
                else
                {
                    int ec = SSL_get_error(ssl, rc);
                    if (ec == 2)
                    {
                        if (DEBUG && VERBOSE_DEBUG)
                            printl("SSL want_read during peek, bytes_read=%d\n", bytes_read);
                        continue;
                    }
                    else
                    {
                        printl("SSL error=%d during peek\n", ec);
                        return EC_SSL;
                    }
                }
            }

            if (connection_upgraded != 2)
                continue;

            // execution to here means we are in a fully upgraded connection (with incoming data)

            // task 1: peek data on incoming to find packet type and length
            if (packet_type == -1)
            {
                uint8_t header_buffer[10] = { 0,0,0,0,0, 0,0,0,0,0 };
                int rc = -1;
                size_t bytes_read = 0;
                rc = SSL_peek_ex(ssl, header_buffer, 6, &bytes_read);
                if (bytes_read == 6)
                do {
                    packet_received = 0;
                    packet_expected =
                        (header_buffer[0] << 24) +
                        (header_buffer[1] << 16) +
                        (header_buffer[2] << 8) +
                        header_buffer[3];

                    int header_size = 6;
                    packet_uncompressed = 0;
                    if (packet_expected >> 28U)
                    {
                        // compressed
                        rc = SSL_peek_ex(ssl, header_buffer, 10, &bytes_read);
                        if (bytes_read != 10)
                        {
                            // in this rare edge case a compressed packet has a partially sent header
                            // wait for the whole header to arrive before continuing
                            packet_expected = 0;
                            break;
                        }

                        packet_expected &= 0x0FFFFFFFU;
                        packet_uncompressed =
                            (header_buffer[6] << 24) +
                            (header_buffer[7] << 16) +
                            (header_buffer[8] << 8) +
                            header_buffer[9];
                        header_size = 10;
                    }

                    packet_type = (header_buffer[4] << 8) + header_buffer[5];

                    if (DEBUG)
                        printl("Peeked packet type %d, size: %d\n", packet_type, packet_expected);

                    // clear out the header bytes by actually reading them this time instead of peeking
                    if (!((rc = SSL_read_ex(ssl, header_buffer, header_size, &bytes_read)) > 0) &&
                            bytes_read == header_size)
                    {
                        printl("SSL error=%d during packet read\n", SSL_get_error(ssl, rc));
                        return EC_SSL;
                    }

                    // upgrade to a larger buffer if needed
                    if (packet_expected > packet_buffer_len)
                    {
                        if (packet_expected <= PACKET_BUFFER_MAX)
                        {
                            free(packet_buffer);
                            packet_buffer_len = PACKET_BUFFER_MAX;
                            packet_buffer = (uint8_t*)malloc(packet_buffer_len);
                            if (!packet_buffer)
                            {
                                printl("Malloc failed while upsizing packet_buffer\n");
                                return EC_BUFFER;
                            }
                        }
                        else
                        {
                            printl("Received a packet which exceeds maximum buffer size. "
                               "buffer_size=%d packet_size=%d packet_type=%d\n",
                               PACKET_BUFFER_MAX, packet_expected, packet_type);
                            return EC_BUFFER;
                        }
                    }
                    else if (packet_expected <= PACKET_BUFFER_NORM && packet_buffer_len > PACKET_BUFFER_NORM)
                    {
                        // downgrade to the smaller buffer
                        free(packet_buffer);
                        packet_buffer_len = PACKET_BUFFER_NORM;
                        packet_buffer = (uint8_t*)malloc(packet_buffer_len);
                        if (!packet_buffer)
                        {
                            printl("Malloc failed while downsizing packet_buffer\n");
                            return EC_BUFFER;
                        }
                    }



                    // now we're ready to drop through to a payload read
                } while (0);

                int ec = SSL_get_error(ssl, rc);

                if (ec == 2 || ec == 0)
                {
                    continue;
                }
                else
                {
                    printl("SSL error=%d during peek\n", ec);
                    return EC_SSL;
                }
            }

            if (packet_type == -1)
                continue;

            // execution to here means we are in process of reading a packet
            {
                int rc = -1;
                int32_t remaining = packet_expected - packet_received;
                size_t bytes_read = 0;
                while (remaining > 0 && (rc =
                    SSL_read_ex(ssl, packet_buffer + remaining,
                    packet_buffer_len - packet_received, &bytes_read) > 0) &&
                    bytes_read > 0)
                {
                    packet_received += bytes_read;
                    remaining -= bytes_read;
                }

                if (remaining > 0)
                    continue;

                if (packet_uncompressed > 0)
                {
                    // RH TODO: decompress packet before handoff(lz4)
                    printl("FIXME Compressed packets currently unsupported, dropping\n");

                    continue;
                }

                // route to subscribers
                {
                    uint32_t packet_len = packet_expected;

                    Hash h = hash(packet_type, packet_buffer, packet_len);

                    int seen_before = 0;
                    if (seen_p2s.find(h) == seen_p2s.end())
                        seen_p2s.emplace(h, 1);
                    else
                        seen_before = 1;

                    if (DEBUG)
                    {
                        printl("Packet route_to_subscribers type=%d size=%d ", packet_type, packet_len);

                        print_hash(h, (seen_before ? "seen=" : "hash="), "\n");
                    }

                    if (packet_type == 3) //mtPING packets are processed directly
                    {
                        protocol::TMPing ping;
                        ping.ParseFromArray(packet_buffer, packet_len);
                        ping.set_type(protocol::TMPing_pingType_ptPONG);
                        ping.SerializeToArray(packet_buffer, packet_len);

                        
                        uint8_t header[6];
                        header[0] = (packet_len >> 24) & 0xff;
                        header[1] = (packet_len >> 16) & 0xff;
                        header[2] = (packet_len >> 8) & 0xff;
                        header[3] =  packet_len & 0xff;
                        header[4] = (packet_type >> 8) & 0xff;
                        header[5] =  packet_type & 0xff;

                        SSL_ENQUEUE(header, 6);
                        SSL_ENQUEUE(packet_buffer, packet_len);
                    }


                }



                // reset
                packet_type = -1;
                packet_expected = 0;
                packet_uncompressed = 0;
                packet_received = 0;
                continue;
            }
        }

            // task 2: continue looping until full packet received in buffer
            // task 3: process any pings
            // task 4: run de-duplication logic
            // task 5: send de-duplicated packets to main
        // task A: read initial packet from main which contains de-duplication rules
        // task B: read incoming packets from main and apply de-duplication rules then relay them to peer

    }
    return 0;
}

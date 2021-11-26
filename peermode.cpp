#include "uplink.h"
#include <openssl/ssl.h>
#include <openssl/sha.h>
#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/pem.h>
#include <secp256k1.h>

#define POLL_TIMEOUT 2000 /* ms */
#define DEFAULT_BUF_SIZE 64

#define DEBUG 0
#define VERBOSE_DEBUG 0
#define HTTP_BUFFER_SIZE 4096
#define SSL_BUFFER_LENGTH 65536

pid_t my_pid = 0;

// ---------
// PEER MODE
// ---------
//
// In this file: peer refers to TCP endpoint connecting out to the XRPL node.
// RH NOTE: `peer_path` (uplink.cpp) == `main_path` (peermode.cpp)
//           typically: /var/run/xrpl-uplink/peer.sock

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
        fprintf(stderr, "[%s:%d pid=%d] Could not generate secp256k1 keypair\n",
                __FILE__, __LINE__, my_pid);
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
        fprintf(stderr, "[%s:%d pid=%d] Could not SSL_get_finished\n", __FILE__, __LINE__, my_pid);
        return EC_SSL;
    }

    // SHA512 SSL_get_finished to create cookie 1
    unsigned char cookie1[64];
    crypto_hash_sha512(cookie1, buffer, len);
    
    len = SSL_get_peer_finished(ssl, buffer, 1024);
    if (len < 12)
    {
        fprintf(stderr, "[%s:%d pid=%d] Could not SSL_get_peer_finished\n", __FILE__, __LINE__, my_pid);
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
        fprintf(stderr, "[%s:%d pid=%d] Could not create upgrade request, buffer too small.\n",
                __FILE__, __LINE__, my_pid);
        *buflen = 0;
        return EC_BUFFER;
    }
}


int peer_mode(
    char* ip, int port, char* main_path, uint8_t* key, 
    ddmode dd_default, std::map<int32_t, ddmode>& dd_specific)
{

    // global
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
            fprintf(stderr, "[%s:%d pid=%d] Could not create TCP socket for peer %s:%d\n",
                    __FILE__, __LINE__, my_pid, ip, port);
            return EC_TCP;
        }

        memset(&serv_addr, '0', sizeof(serv_addr)); 

        serv_addr.sin_family = AF_INET;
        serv_addr.sin_port = htons(port); 

        if (inet_pton(AF_INET, ip, &serv_addr.sin_addr) <= 0)
        {
            fprintf(stderr, "[%s:%d pid=%d] Could parse ip %s while trying to connect to peer\n",
                    __FILE__, __LINE__, my_pid, ip);
            return EC_TCP;
        }

        if (connect(peer_fd, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0)
        {
            fprintf(stderr, "[%s:%d pid=%d] Could not connect to peer %s:%d\n",
                    __FILE__, __LINE__, my_pid, ip, port);
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
            fprintf(stderr, "[%s:%d pid=%d] Could not create peer unix domain socket (connecting)\n",
                    __FILE__, __LINE__, my_pid);
            return EC_UNIX;
        }

        // connect
        if (connect(main_fd, (const struct sockaddr*)&addr, sizeof(addr)) < 0)
        {
            fprintf(stderr, "[%s:%d pid=%d] Could not connect to peer %s:%d\n", 
                    __FILE__, __LINE__, my_pid, ip, port);
            return EC_UNIX;
        }
    }

    // sanity check
    if (main_fd < 0 || peer_fd < 0)
    {
        fprintf(stderr, "[%s:%d pid=%d] main_fd or peer_fd invalid\n",
                __FILE__, __LINE__, my_pid);
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
    char ssl_buf[SSL_BUFFER_LENGTH];

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
                fprintf(stderr, "[%s:%d pid=%d] flushing %ld bytes\n", __FILE__, __LINE__, my_pid, bytes_read);\
            if (bytes_read > 0)\
            {\
                ssl_write_buf = (char*)realloc(ssl_write_buf, ssl_write_len + bytes_read);\
                memcpy(ssl_write_buf + ssl_write_len, ssl_buf, bytes_read);\
                ssl_write_len += bytes_read;\
            }\
            else if (!BIO_should_retry(wbio))\
            {\
                fprintf(stderr, "[%s:%d pid=%d] Could not enqueue outward SSL bytes\n",\
                        __FILE__, __LINE__, my_pid);\
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


    // setup poll
    struct pollfd fdset[2];
    memset(&fdset, 0, sizeof(fdset));    

    fdset[0].fd = peer_fd;
    fdset[1].fd = main_fd;

    fdset[0].events =  POLLERR | POLLHUP | POLLNVAL | POLLIN ;
    fdset[1].events =  POLLERR | POLLHUP | POLLNVAL | POLLIN ;
   
    int connection_upgraded = 0;

    // primary poll loop
    while(1)
    {

        fdset[0].events &= ~POLLOUT;

        if (ssl_write_len > 0)
            fdset[0].events |= POLLOUT;

        int poll_result = poll(&fdset[0], 2, POLL_TIMEOUT);

        if (poll_result < 0)
        {
            fprintf(stderr, "[%s:%d pid=%d] poll returned -1\n",
                __FILE__, __LINE__, my_pid);
            return EC_POLL;
        }

        if (poll_result == 0)
        {
            // if poll returns with no active fds then two seconds have passed without activity
            // this is ok unless we're still doing an SSL connection to the peer, in which case it's time to end
            if (SSL_is_init_finished(ssl))
                continue;

            fprintf(stderr, "[%s:%d pid=%d] SSL handshake timed out with peer %s:%d\n",
                __FILE__, __LINE__, my_pid, ip, port);
            return EC_SSL;
        }

        // execution to here means the poll returned with one or more active fds / events
 
        // check if the peer socket died       
        if (fdset[0].revents & (POLLERR | POLLHUP | POLLNVAL) || read(peer_fd, 0, 0))
        {
            int error = 0;
            socklen_t errlen = sizeof(error);
            getsockopt(peer_fd, SOL_SOCKET, SO_ERROR, (void *)&error, &errlen);
            fprintf(stderr, "[%s:%d pid=%d] Peer connection lost %s:%d, socket err: %d, errno: %d\n",
                 __FILE__, __LINE__, my_pid, ip, port, error, errno);

            return EC_TCP;
        }

        // check if main socket died
        if (fdset[1].revents & (POLLERR | POLLHUP | POLLNVAL) || read(main_fd, 0, 0))
        {
            int error = 0;
            socklen_t errlen = sizeof(error);
            getsockopt(peer_fd, SOL_SOCKET, SO_ERROR, (void *)&error, &errlen);
            fprintf(stderr, "[%s:%d pid=%d] Main connection lost %s, socket err: %d, errno: %d\n",
                __FILE__, __LINE__, my_pid, main_path, error, errno);

            return EC_UNIX;
        }

        // check if there are pending bytes to write from the SSL buffer to the TCP socket
        if (fdset[0].revents & POLLOUT && ssl_write_len)
        {
            ssize_t bytes_written = write(peer_fd, ssl_write_buf, ssl_write_len);
            if (DEBUG)
                fprintf(stderr, "[%s:%d pid=%d] RAW outgoing data %ld\n", __FILE__, __LINE__, my_pid, bytes_written);

            if (bytes_written <= 0)
            {
                fprintf(stderr, "[%s:%d pid=%d] Could not write encrypted bytes to socket\n",
                    __FILE__, __LINE__, my_pid); 
                return EC_SSL;
            }

            if (bytes_written < ssl_write_len)
                memmove(ssl_write_buf, ssl_write_buf + bytes_written, ssl_write_len - bytes_written);
            ssl_write_len -= bytes_written;
            ssl_write_buf = (char*)realloc(ssl_write_buf, ssl_write_len);
            if (DEBUG)
                fprintf(stderr, "[%s:%d pid=%d] RAW bytes remaining to write: %ld\n",
                    __FILE__, __LINE__, my_pid, ssl_write_len);
        }        

        // check if there are incoming bytes
        if (fdset[0].revents & POLLIN)
        {

            if (DEBUG && VERBOSE_DEBUG)
                fprintf(stderr, "[%s:%d pid=%d] incoming data\n", __FILE__, __LINE__, my_pid);

            ssize_t bytes_read = read(peer_fd, ssl_buf, sizeof(ssl_buf));
            if (bytes_read <= 0)
            {
                fprintf(stderr, "[%s:%d pid=%d] Could read raw bytes from TCP socket\n",
                        __FILE__, __LINE__, my_pid);
                return EC_TCP;
            }

            ssize_t bytes_written = BIO_write(rbio, ssl_buf, bytes_read);
            if (bytes_written <= 0)
            {
                fprintf(stderr, "[%s:%d pid=%d] Could not write raw bytes to SSL buffer from TCP socket\n",
                        __FILE__, __LINE__, my_pid);
                return EC_SSL;
            }

            if (!SSL_is_init_finished(ssl))
            {
                if (DEBUG)
                    fprintf(stderr, "[%s:%d pid=%d] Trying SSL handshake with peer %s:%d\n",
                           __FILE__, __LINE__,  my_pid, ip, port);

                int n = SSL_do_handshake(ssl);
                int e = SSL_get_error(ssl, n);
                // RH TODO: evaluate possible errors above
                SSL_FLUSH_OUT()
            }

            if (!SSL_is_init_finished(ssl))
                continue;

            if (connection_upgraded == 0)
            {
                //int generate_upgrade(SSL* ssl, char* keyin, char* bufout, int buflen)
                char upgrade_request[HTTP_BUFFER_SIZE];
                int len = 0;
                int rc = generate_upgrade(secp256k1ctx, ssl, key, upgrade_request, &len);
                if (rc != EC_SUCCESS)
                    return rc;

                if (DEBUG)
                    fprintf(stderr, "[%s:%d pid=%d] Connection upgrade request to %s:%d\n%.*s%s",
                        __FILE__, __LINE__,  my_pid, ip, port,
                        (VERBOSE_DEBUG ? len : 0),
                        (VERBOSE_DEBUG ? upgrade_request : ""),
                        (VERBOSE_DEBUG ? "\n" : "")
                    );

                SSL_ENQUEUE(upgrade_request, len);
                SSL_FLUSH_OUT();
                connection_upgraded = 1;
                continue;
            }

            if (connection_upgraded == 1)
            {
                char buffer[HTTP_BUFFER_SIZE];
                size_t bytes_read = 0;
                if (SSL_peek_ex(ssl, buffer, sizeof(buffer), &bytes_read))
                {
                    for (int i = 0; i < bytes_read - 4; ++i)
                    {
                        // looking for \r\n\r\n
                        if (buffer[i + 0] == '\r' &&
                            buffer[i + 1] == '\n' &&
                            buffer[i + 2] == '\r' &&
                            buffer[i + 3] == '\n')
                        {
                            if (DEBUG)
                                fprintf(stderr, "[%s:%d pid=%d] Connection upgrade response from %s:%d\n%.*s%s",
                                    __FILE__, __LINE__,  my_pid, ip, port,
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
            }

            if (connection_upgraded != 2)
                continue;

            // execution to here means we are in a fully upgraded connection (with incoming data)

            // task 1: peek data on incoming to find packet type and lengthh
            // task 2: continue looping until full packet received in buffer
            // task 3: process any pings
            // task 4: run de-duplication logic
            // task 5: send de-duplicated packets to main
            
        }

        // task A: read initial packet from main which contains de-duplication rules
        // task B: read incoming packets from main and apply de-duplication rules then relay them to peer
        

        sleep(1);
    }
    return 0;
}


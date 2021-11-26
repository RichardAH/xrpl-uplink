#include "uplink.h"
#include <openssl/ssl.h>
#include <openssl/sha.h>
#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/pem.h>

#define POLL_TIMEOUT 2000 /* ms */
#define DEFAULT_BUF_SIZE 64
#define DEBUG 0

// ---------
// PEER MODE
// ---------
int peer_mode(char* ip, int port, char* peer_path, uint8_t* key, 
        ddmode dd_default, std::map<int32_t, ddmode>& dd_specific)
{
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
            fprintf(stderr, "[%s:%d pid=%d] Could parse ip %s while trying to connect to peer\n"
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
        strncpy(addr.sun_path, peer_path, sizeof(addr.sun_path) - 1);
        
        // create socket
        if ((main_fd = socket(AF_UNIX, SOCK_SEQPACKET, 0)) < 0)
        {
            fprintf(stderr, "[%s:%d pid=%d] Could not create peer unix domain socket (connecting)\n"
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

    pid_t my_pid = getpid();

    #define SSL_FAILED(x) (\
        (x) != SSL_ERROR_WANT_WRITE &&\
        (x) != SSL_ERROR_WANT_READ &&\
        (x) != SSL_ERROR_NONE )

    #define SSL_FLUSH_OUT()\
    {\
        ssize_t bytes_read = 0;\
        do {\
            bytes_read = BIO_read(wbio, ssl_buf, sizeof(ssl_buf));\
            if (DEBUG)\
            fprintf(stderr, "[peermode.cpp pid=%08X] flushing %d bytes\n", my_pid, bytes_read);\
            if (bytes_read > 0) {\
                ssl_write_buf = (char*)realloc(ssl_write_buf, ssl_write_len + bytes_read);\
                memcpy(ssl_write_buf + ssl_write_len, ssl_buf, bytes_read);\
                ssl_write_len += bytes_read;\
            }\
            else if (!BIO_should_retry(wbio))\
            GOTO_ERROR("ssl could not enqueue outward bytes", ssl_error);\
        } while (bytes_read > 0);\
    }

    #define SSL_ENQUEUE(buf, len)\
    {\
        ssl_encrypt_buf = (char*)realloc(ssl_encrypt_buf, ssl_encrypt_len + len);\
        memcpy(ssl_encrypt_buf + ssl_encrypt_len, buf, len);\
        ssl_encrypt_len += len; \
    }

    SSL_load_error_strings();
    OpenSSL_add_ssl_algorithms();
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
    
    ssl = SSL_new(ctx);
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
            return 3;
        }

        if (poll_result == 0)
        {
            // if poll returns with no active fds then two seconds have passed without activity
            // this is ok unless we're still doing an SSL connection to the peer, in which case it's time to end
            if (SSL_is_init_finished(ssl))
                continue;

            fprintf(stderr, "[%s:%d pid=%d] SSL handshake timed out with peer %s:%d\n",
                    __FILE__, __LINE__, my_pid, ip, port);
            return 4;
        }

        // execution to here means the poll returned with one or more active fds / events
 
        // check if the peer socket died       
        if (fdset[0].revents & (POLLERR | POLLHUP | POLLNVAL) || read(client_fd, ssl_buf, 0))
        {
            fprintf(stderr, "[%s:%d pid=%d] Peer connection lost %s:%d\n",
                    __FILE__, __LINE__, my_pid, ip, port);

            return 5;
        }


        sleep(1);
    }
    return 0;
}


#include "uplink.h"

Hash hash(int packet_type, const void* mem, int len)
{
    Hash h { .q = { 0, 0, 0, (uint64_t)(packet_type) } };
    uint64_t state = 0;
    uint8_t* ptr = (uint8_t*)mem;
    int i = 0, j = 0;
    if (len >= 8)
        for (; i < len ; i += 8, ++j)
        {
            state = _mm_crc32_u64(state, *(reinterpret_cast<uint64_t*>(ptr + i)));
            h.d[j % 8] ^= state;
            h.q[j % 4] ^= *(reinterpret_cast<uint64_t*>(ptr + i));
        }

    if (len == i)
        return h;

    uint64_t last = 0;
    for (; i < len; ++i)
    {
        last <<= 8U;
        last += ptr[i];
    }

    state = _mm_crc32_u64(state, last);
    h.d[j % 8] ^= state;

    return h;
}

// configure an fd to be nonblocking and close on exec
int fd_set_flags(int fd, int new_flags)
{
    int existing_flags = fcntl(fd, F_GETFL);
    if (existing_flags == -1)
    {
        fprintf(stderr, "Could not get fd flags: %d\n", errno);
        return 0;
    }
    if (fcntl(fd, F_SETFL, existing_flags | new_flags) == -1)
    {
        fprintf(stderr, "Could not set fd flags: %d\n", errno);
        return 0;
    }
    return 1;
}

// create a SEQPACKET unix domain socket at path
int create_unix_accept(char* path)
{
    int fd = -1;
    struct sockaddr_un server_sockaddr;
    memset(&server_sockaddr, 0, sizeof(struct sockaddr_un));
    if ((fd = socket(AF_UNIX, SOCK_SEQPACKET, 0)) == -1)
    {
        fprintf(stderr, "Could not create unix domain socket: %d\n", errno);
        return -EC_UNIX;
    }

    server_sockaddr.sun_family = AF_UNIX;
    strcpy(server_sockaddr.sun_path, path);
    size_t len = sizeof(server_sockaddr);
    unlink(path);

    if (bind(fd, (struct sockaddr *) &server_sockaddr, len) == -1)
    {
        fprintf(stderr, "Could not bind to unix domain socket: %d\n", errno);
        return -EC_UNIX;
    }

    return fd;
}

const char* mtUNKNOWN = "mtUNKNOWN_PACKET";

const char* packet_name(
        uint8_t packet_type, int padded)
{
    switch(packet_type)
    {
        case 2:  return (padded ? "mtMANIFESTS               " : "mtMANIFESTS");
        case 3:  return (padded ? "mtPING                    " : "mtPING");
        case 5:  return (padded ? "mtCLUSTER                 " : "mtCLUSTER");
        case 15: return (padded ? "mtENDPOINTS               " : "mtENDPOINTS");
        case 30: return (padded ? "mtTRANSACTION             " : "mtTRANSACTION");
        case 31: return (padded ? "mtGET_LEDGER              " : "mtGET_LEDGER");
        case 32: return (padded ? "mtLEDGER_DATA             " : "mtLEDGER_DATA");
        case 33: return (padded ? "mtPROPOSE_LEDGER          " : "mtPROPOSE_LEDGER");
        case 34: return (padded ? "mtSTATUS_CHANGE           " : "mtSTATUS_CHANGE");
        case 35: return (padded ? "mtHAVE_SET                " : "mtHAVE_SET");
        case 41: return (padded ? "mtVALIDATION              " : "mtVALIDATION");
        case 42: return (padded ? "mtGET_OBJECTS             " : "mtGET_OBJECTS");
        case 50: return (padded ? "mtGET_SHARD_INFO          " : "mtGET_SHARD_INFO");
        case 51: return (padded ? "mtSHARD_INFO              " : "mtSHARD_INFO");
        case 52: return (padded ? "mtGET_PEER_SHARD_INFO     " : "mtGET_PEER_SHARD_INFO");
        case 53: return (padded ? "mtPEER_SHARD_INFO         " : "mtPEER_SHARD_INFO");
        case 54: return (padded ? "mtVALIDATORLIST           " : "mtVALIDATORLIST");
        case 55: return (padded ? "mtSQUELCH                 " : "mtSQUELCH");
        case 56: return (padded ? "mtVALIDATORLISTCOLLECTION " : "mtVALIDATORLISTCOLLECTION");
        case 57: return (padded ? "mtPROOF_PATH_REQ          " : "mtPROOF_PATH_REQ");
        case 58: return (padded ? "mtPROOF_PATH_RESPONSE     " : "mtPROOF_PATH_RESPONSE");
        case 59: return (padded ? "mtREPLAY_DELTA_REQ        " : "mtREPLAY_DELTA_REQ");
        case 60: return (padded ? "mtREPLAY_DELTA_RESPONSE   " : "mtREPLAY_DELTA_RESPONSE");
        case 61: return (padded ? "mtGET_PEER_SHARD_INFO_V2  " : "mtGET_PEER_SHARD_INFO_V2");
        case 62: return (padded ? "mtPEER_SHARD_INFO_V2      " : "mtPEER_SHARD_INFO_V2");
        case 63: return (padded ? "mtHAVE_TRANSACTIONS       " : "mtHAVE_TRANSACTIONS");
        case 64: return (padded ? "mtTRANSACTIONS            " : "mtTRANSACTIONS");
        default: return (padded ? "mtUNKNOWN_PACKET          " : mtUNKNOWN);
    }
}


ddmode parse_dd(char* dd)
{
    if (strcmp(dd, "all") == 0)
        return DD_ALL;
    else if (strcmp(dd, "none") == 0)
        return DD_NONE;
    else if (strcmp(dd, "sub") == 0)
        return DD_SUB;
    else if (strcmp(dd, "peer") == 0)
        return DD_PEER;
    else if (strcmp(dd, "drop") == 0)
        return DD_DROP;
    else if (strcmp(dd, "dropn") == 0)
        return DD_DROP_N;
    else if (strcmp(dd, "blackhole") == 0)
        return DD_BLACKHOLE;
    else if (strcmp(dd, "squelch") == 0)
        return DD_SQUELCH;
    else if (strcmp(dd, "squelchn") == 0)
        return DD_SQUELCH_N;
    else
        return DD_INVALID;
}

// 0 == invalid
uint8_t packet_id(char* packet_name)
{
    if (strcmp("mtMANIFESTS", packet_name) == 0) return 2;
    if (strcmp("mtPING", packet_name) == 0) return 3;
    if (strcmp("mtCLUSTER", packet_name) == 0) return 5;
    if (strcmp("mtENDPOINTS", packet_name) == 0) return 15;
    if (strcmp("mtTRANSACTION", packet_name) == 0) return 30;
    if (strcmp("mtGET_LEDGER", packet_name) == 0) return 31;
    if (strcmp("mtLEDGER_DATA", packet_name) == 0) return 32;
    if (strcmp("mtPROPOSE_LEDGER", packet_name) == 0) return 33;
    if (strcmp("mtSTATUS_CHANGE", packet_name) == 0) return 34;
    if (strcmp("mtHAVE_SET", packet_name) == 0) return 35;
    if (strcmp("mtVALIDATION", packet_name) == 0) return 41;
    if (strcmp("mtGET_OBJECTS", packet_name) == 0) return 42;
    if (strcmp("mtGET_SHARD_INFO", packet_name) == 0) return 50;
    if (strcmp("mtSHARD_INFO", packet_name) == 0) return 51;
    if (strcmp("mtGET_PEER_SHARD_INFO", packet_name) == 0) return 52;
    if (strcmp("mtPEER_SHARD_INFO", packet_name) == 0) return 53;
    if (strcmp("mtVALIDATORLIST", packet_name) == 0) return 54;
    if (strcmp("mtSQUELCH", packet_name) == 0) return 55;
    if (strcmp("mtVALIDATORLISTCOLLECTION", packet_name) == 0) return 56;
    if (strcmp("mtPROOF_PATH_REQ", packet_name) == 0) return 57;
    if (strcmp("mtPROOF_PATH_RESPONSE", packet_name) == 0) return 58;
    if (strcmp("mtREPLAY_DELTA_REQ", packet_name) == 0) return 59;
    if (strcmp("mtREPLAY_DELTA_RESPONSE", packet_name) == 0) return 60;
    if (strcmp("mtGET_PEER_SHARD_INFO_V2", packet_name) == 0) return 61;
    if (strcmp("mtPEER_SHARD_INFO_V2", packet_name) == 0) return 62;
    if (strcmp("mtHAVE_TRANSACTIONS", packet_name) == 0) return 63;
    if (strcmp("mtTRANSACTIONS", packet_name) == 0) return 64;
    return 0;
}


int random_eviction(std::map<Hash, uint32_t, HashComparator>& map, int rnd_fd, int iterations)
{
    static uint32_t seed = -1;

    if (seed == -1)
    {
        read(rnd_fd, &seed, sizeof(seed));
        srand(seed ^ time(NULL));
    }


    if (iterations > EVICTION_MAX)
        iterations = EVICTION_MAX;

    uint32_t size = map.size();

    std::set<uint32_t> rnd_set;

    for (int i = 0; i < iterations; ++i)
        rnd_set.emplace(rand() % size);


    int upto = 0;

    uint32_t ct = time(NULL);

    std::set<Hash, HashComparator> to_evict;

    auto iter = map.begin();

    uint32_t last = 0;
    for (auto rnd : rnd_set)
    {
        if (rnd - last == 0)
            continue;

        std::advance(iter, rnd - last);

        if (iter == map.end())
            break;
        if (iter->second + EVICTION_TIME < ct)
            to_evict.emplace(iter->first);
        last = rnd;
    }    

    if (to_evict.size() > 0 && DEBUG)
        printl("evicting %ld entries from map[%d]\n", to_evict.size(), size);

    for (auto const& i : to_evict)
        map.erase(i);

    return EC_SUCCESS;
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

//todo: clean up and optimise, check for overrun 
// if peerips vector ptr is provided then a 503 will populate the vector with ip:port pairs
int ssl_handshake_and_upgrade(
        int fd,
        SSL** ssl,
        SSL_CTX** ctx,
        uint8_t* seckey_in,
        uint8_t* our_pubkey_out,
        uint8_t* peer_pubkey_out,
        std::vector<std::pair<IP, int>>& peerips_out)
{

    // create secp256k1 context
    secp256k1_context* secp256k1ctx = secp256k1_context_create(
            SECP256K1_CONTEXT_VERIFY |
            SECP256K1_CONTEXT_SIGN) ;

    const SSL_METHOD *method = TLS_client_method(); 

    *ctx = SSL_CTX_new(method);
    SSL_CTX_set_ecdh_auto(*ctx, 1);
    SSL_CTX_set_verify(*ctx, SSL_VERIFY_NONE, NULL);


    *ssl = SSL_new(*ctx);
    SSL_set_fd(*ssl, fd); 

    int status = -100;
    status = SSL_connect(*ssl);

    if (status != 1)
    {
        status = SSL_get_error(*ssl, status);
        printl("SSL_connect failed with error: %d\n", status);
        return EC_SSL;
    }    

    unsigned char buffer[1024];
    size_t len = SSL_get_finished(*ssl, buffer, 1024);
    if (len < 12)
    {
        printl("Could not SSL_get_finished\n");
        return EC_SSL;
    }

    // SHA512 SSL_get_finished to create cookie 1
    unsigned char cookie1[64];
    crypto_hash_sha512(cookie1, buffer, len);

    len = SSL_get_peer_finished(*ssl, buffer, 1024);
    if (len < 12)
    {
        printl("Could not SSL_get_peer_finished\n");
        return EC_SSL;
    }   

    // SHA512 SSL_get_peer_finished to create cookie 2
    unsigned char cookie2[64];
    crypto_hash_sha512(cookie2, buffer, len);

    // xor cookie2 onto cookie1
    for (int i = 0; i < 64; ++i)
        cookie1[i] ^= cookie2[i];

    // the first half of cookie2 is the true cookie
    crypto_hash_sha512(cookie2, cookie1, 64);

    // generate keys
    unsigned char pub[64], pubc[33];
    char b58[100];
    size_t b58size = 100;
    int rc = generate_node_keys(secp256k1ctx, seckey_in, pub, pubc, b58, &b58size);

    if (rc != EC_SUCCESS)
        return rc;

    for (int i = 0; i < 32; ++i)
        our_pubkey_out[i] = pubc[1+i];

    secp256k1_ecdsa_signature sig;
    secp256k1_ecdsa_sign(secp256k1ctx, &sig, cookie2, seckey_in, NULL, NULL);

    unsigned char buf[200];
    size_t buflen = 200;
    secp256k1_ecdsa_signature_serialize_der(secp256k1ctx, buf, &buflen, &sig);

    char buf2[200];
    size_t buflen2 = 200;
    sodium_bin2base64(buf2, buflen2, buf, buflen, sodium_base64_VARIANT_ORIGINAL);
    buf2[buflen2] = '\0';


    char buf3[2048];
    size_t buf3len = 0;
    buf3len = snprintf(buf3, 2047, 
            "GET / HTTP/1.1\r\n"
            "User-Agent: rippled-1.8.0\r\n"
            "Upgrade: XRPL/2.0\r\n"
            "Connection: Upgrade\r\n"
            "Connect-As: Peer\r\n"
            "Crawl: private\r\n"
            "Session-Signature: %s\r\n"
            "Public-Key: %s\r\n\r\n", buf2, b58);


    if (SSL_write(*ssl, buf3, buf3len) <= 0)
    {
        printl("Failed to write bytes to openssl fd during handshake\n");
        return EC_SSL;
    }

    for (int i = 0; i < sizeof(buf3); ++i)
        buf3[i] = 0;

    // wait for reply
    size_t bytes_read = SSL_read(*ssl, buf3, sizeof(buf3));
    if (bytes_read <= 0)
    {
        printl("Failed to read reply during handshake\n");
        return EC_SSL;
    }

    buf3[sizeof(buf3)-1] = '\0'; // ensure string ops are safe

    if (DEBUG)
        printl("handshake reply: `%s`\n", buf3);

    // find their key
    int found_key = 0;
    char* found_peers = 0;
    for (int j = 0; j < bytes_read - 12; ++j)
    {
        if (memcmp(buf3 + j, "peer-ips\":[", 11) == 0)
        {
            found_peers = buf3 + j;
            break;
        }

        if (memcmp(buf3 + j, "Public-Key: ", 12) == 0)
        {
            j += 12;

            // scan forward to \r\n and replace with a \0
            int k = j;
            for (; k < bytes_read - 3; ++k)
            {
                if (buf3[k] == 0xD)
                {
                    buf3[k] = '\0';
                    break;
                }
            }

            if (buf3[k] != '\0')
            {
                printl("peer sent Public-Key: but we could not find end of line\n");
                return EC_PROTO;
            }

            const char* pubkey = reinterpret_cast<const char*>(buf3 + j);
            printl("peer connected: %s\n", pubkey);


            uint8_t buf[38];
            size_t bytes_written = sizeof(buf);

            bool b58rc = b58tobin(buf, &bytes_written, pubkey, strlen(pubkey));
            if (!(b58rc && bytes_written >= 33))
            {
                printl("could not decode peer key `%s`\n", pubkey);
                return EC_PROTO;
            }

            for (int z = 2; z < 34; ++z)
                peer_pubkey_out[z - 2] = buf[z];
            if (DEBUG)
                printl("peer key raw: " FORMAT32 "\n", COPY32(peer_pubkey_out));
            found_key = 1;
            break;
        }
    }

    if (found_peers)
    {
        // this is a 503, returning peer ips
        char* ptr = strtok(found_peers, ",\"}");
        while (ptr)
        {
            int len = strlen(ptr);

            if (len >= 9)
            {
                if (DEBUG && VERBOSE_DEBUG)
                    printl("parsing: `%s`\n", ptr);
                std::optional<std::pair<IP, int>> parsed = parse_endpoint(ptr, len);
                if (parsed)
                {
                    if (DEBUG)
                        printl("parsed: `%s`\n", ptr);
                    peerips_out.emplace_back(std::move(*parsed));
                }
            }
                
            ptr = strtok(NULL, ",\"}");
        }

        return EC_BUSY;
    }
    
    if (!found_key)
    {
        printl("peer did not send a public key during connection upgrade\n");
        return EC_PROTO;
    }

    secp256k1_context_destroy(secp256k1ctx);

    return EC_SUCCESS;
}


// resize a malloced buffer between large and small sizes depending on what the current requirement is
int resize_buffer(uint8_t** buffer, size_t needed, size_t* current, size_t small, size_t large)
{
    // upgrade to a larger buffer if needed
    if (needed > *current)
    {
        if (needed <= large)
        {
            free(*buffer);
            *current = large;
            *buffer = (uint8_t*)malloc(*current);
            if (!*buffer)
            {
                printl("malloc failed while upsizing buffer\n");
                return EC_BUFFER;
            }
        }
        else
        {
            printl("required buffer exceeds maximum size. "
                    "buffer_size=%ld packet_size=%ld\n", *current, needed);
            return EC_BUFFER;
        }
    }
    else if (needed <= small && *current > small)
    {
        // downgrade to the smaller buffer
        free(*buffer);
        *current = small;
        *buffer = (uint8_t*)malloc(*current);
        if (!*buffer)
        {
            printl("malloc failed while downsizing buffer\n");
            return EC_BUFFER;
        }
    }

    return EC_SUCCESS;
}

void write_header(uint8_t* header, int packet_type, int packet_len)
{
    header[0] = (uint8_t)((packet_len >> 24U) & 0xFFU);
    header[1] = (uint8_t)((packet_len >> 16U) & 0xFFU);
    header[2] = (uint8_t)((packet_len >>  8U) & 0xFFU);
    header[3] = (uint8_t)((packet_len >>  0U) & 0xFFU);
    header[4] = (uint8_t)((packet_type >> 8U) & 0xFFU);
    header[5] = (uint8_t)((packet_type >> 0U) & 0xFFU);
}

int parse_endpoints(uint8_t* packet_buffer, int packet_len, std::vector<std::pair<IP, int>>& ips)
{
    protocol::TMEndpoints eps;
    bool success = eps.ParseFromArray(packet_buffer, packet_len);
    if (DEBUG)
        printl("parsed endpoints: %s\n", (success ? "yes" : "no") );

    int counter = 0;

    if (DEBUG)
        printl("mtEndpoints contains %d entries\n", eps.endpoints_v2_size());

    for (int k = 0; k < eps.endpoints_v2_size(); ++k)
    {
        auto const& ep = eps.endpoints_v2(k);
        std::string const& endpoint = ep.endpoint();
        const char* str = endpoint.c_str();
        size_t len = endpoint.size();
        uint32_t hops = ep.hops();

        if (hops == 0)
            continue;

        std::optional<std::pair<IP, int>> parsed = parse_endpoint(str, len);

        if (parsed)
        {
            ips.emplace_back(std::move(*parsed));
            counter++;
        }
    }

    return counter;
}


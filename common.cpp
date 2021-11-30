#include "uplink.h"

Hash hash(int packet_type, const void* mem, int len)
{
    Hash h { .q = { 0, 0, 0, packet_type } };
    uint64_t state = 0;
    uint8_t* ptr = (uint8_t*)mem;
    int i = 0, j = 0;
    if (len >= 8)
    for (; i < len ; i += 8, ++j)
    {
        state = _mm_crc32_u64(state, *(reinterpret_cast<uint64_t*>(ptr + i)));
        h.d[j % 8] ^= state;
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


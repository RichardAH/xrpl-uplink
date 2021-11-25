#include "uplink.h"

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
        return -1;
    }
  
    server_sockaddr.sun_family = AF_UNIX;   
    strcpy(server_sockaddr.sun_path, path); 
    size_t len = sizeof(server_sockaddr);
    unlink(path);

    if (bind(fd, (struct sockaddr *) &server_sockaddr, len) == -1)
    {
        fprintf(stderr, "Could not bind to unix domain socket: %d\n", errno);
        return -1;
    }

    return fd;
}

int32_t packet_id(char* packet_name)
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
    return -1;
}


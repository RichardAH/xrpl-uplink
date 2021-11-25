#define VERSION             "0.1"
#define SOCK_PATH           "/var/run/xrpl-uplink"
#define PEER_FN             "peer.sock"
#define SUBSCRIBER_FN       "subscriber.sock"
#define MAX_FDS 1024
#include <stdio.h>
#include <sys/socket.h>
#include <linux/limits.h>
#include <string.h>
#include <sys/un.h>
#include <sys/stat.h>
#include <errno.h>
#include <unistd.h>
#include <fcntl.h>
#include <poll.h>
#include <cstdlib>
#include <stdint.h>
#include <map>
enum ddmode : int8_t 
{
    DD_INVALID = -1,
    DD_ALL = 0,
    DD_NONE = 1,
    DD_SUB = 2,
    DD_PEER = 3
};

int print_usage(int argc, char** argv, const char* error)
{
    fprintf(stderr, 
    "XRPL-Uplink v%s by Richard Holland / XRPL-Labs\n%s%s"
    "An XRPL peer-protocol endpoint for connecting local subscribers (applications) to the XRPL mesh network.\n"
    "Usage: %s <max-peers> <peer-ip> <peer-port> [<default-de-duplication-mode> [mtPACKET:ddmode] ...] -run as main\n"
    "       %s connect <peer-ip> <peer-port> [<default-de-duplication-mode> [mtPACKET:ddmode] ...]     -run as peer\n"
    "De-duplication modes (ddmode):\n"
    "\tall     - de-duplicate all packets in both directions (subscriber <-> peers)\n"
    "\tnone    - do not de-duplicate any packets in either direction\n"
    "\tpeer    - only de-duplicate inbound packets from peers (forward all duplicates from subscribers)\n"
    "\tsub     - only de-duplicate outgoing packets from subscribers (forward all duplicates from peers)\n"
    "Note: The first de-duplication mode specified on the command-line is the default mode applied to all packets\n"
    "Subsequent modes can be attached to specific packet types, e.g. mtGET_LEDGER:none mtTRANSACTION:all\n"
    "Packet Types:\n"
    "\tmtMANIFESTS mtPING mtCLUSTER mtENDPOINTS mtTRANSACTION mtGET_LEDGER mtLEDGER_DATA mtPROPOSE_LEDGER\n"
    "\tmtSTATUS_CHANGE mtHAVE_SET mtVALIDATION mtGET_OBJECTS mtGET_SHARD_INFO mtSHARD_INFO mtGET_PEER_SHARD_INFO\n"
    "\tmtPEER_SHARD_INFO mtVALIDATORLIST mtSQUELCH mtVALIDATORLISTCOLLECTION mtPROOF_PATH_REQ mtPROOF_PATH_RESPONSE\n"
    "\tmtREPLAY_DELTA_REQ mtREPLAY_DELTA_RESPONSE mtGET_PEER_SHARD_INFO_V2 mtPEER_SHARD_INFO_V2 mtHAVE_TRANSACTIONS\n"
    "\tmtTRANSACTIONS\n"
    "Example:\n"
    "       %s 10 r.ripple.com 51235 all mtGET_LEDGER:none\n",
    VERSION, (error ? error : ""), (error ? "\n" : ""), argv[0], argv[0], argv[0]); 
    return 1;
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


// ---------
// MAIN MODE
// ---------

int main_mode(char* ip, int port, int peer_max)
{
    // task 1: open /var/run/xrpl-uplink/peer.sock accept mode
    int peer_accept = -1;
    {
    
        char path[PATH_MAX];
        if (snprintf(path, PATH_MAX, "%s/%s", SOCK_PATH, PEER_FN) < 0)
        {
            fprintf(stderr, "Could not evaluate peer socket path\n");
            return 1;
        }

        printf("Peer socket: %s\n", path);

        if ((peer_accept = create_unix_accept(path)) == -1)
        {
            fprintf(stderr, "Could not create peer accept socket\n");
            return 1;
        }

        if (!fd_set_flags(peer_accept, O_CLOEXEC | O_NONBLOCK))
            return 2;
    }


    // task 2: open /var/run/xrpl-uplink/subscriber.sock accept mode
    int subscriber_accept = -1;
    {
        char path[PATH_MAX];
        if (snprintf(path, PATH_MAX, "%s/%s", SOCK_PATH, SUBSCRIBER_FN) < 0)
        {
            fprintf(stderr, "Could not evaluate subscriber socket path\n");
            return 1;
        }

        printf("Subscriber socket: %s\n", path);

        if ((subscriber_accept = create_unix_accept(path)) == -1)
        {
            fprintf(stderr, "Could not create subscriber accept socket\n");
            return 1;
        }

        if (!fd_set_flags(subscriber_accept, O_CLOEXEC | O_NONBLOCK))
            return 2;

    }


    // task 3: poll loop on connected/ing peers and connected/ing subscribers
    struct pollfd fds[MAX_FDS];
    // clear fd structure
    for (int i = 0; i < MAX_FDS; ++i)
    {
        fds[i].fd = -1;
        fds[i].events = 0;
    }

    // preload our listening fds
    fds[0].fd = peer_accept;
    fds[0].events = POLLIN;
    fds[1].fd = subscriber_accept;
    fds[1].events = POLLIN;

    while (1)
    {

        int poll_result = poll(fds, MAX_FDS, -1);
        if (poll_result == -1)
        {
            fprintf(stderr, "Poll returned -1. Errno=%d\n", errno);
            return 5;
        }

        printf("poll result %d\n");

        sleep(1);
    }
    return 0;
}


// ---------
// PEER MODE
// ---------
int peer_mode(char* ip, int port)
{

    while(1)
    {
        sleep(1);
    }
    return 0;
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
    else
        return DD_INVALID;
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

int main(int argc, char** argv)
{
    if (!(mkdir(SOCK_PATH, 0700) == 0 || errno == EEXIST))
    {
        fprintf(stderr, "Could not create directory: `%s` for socket files\n", SOCK_PATH);
        return 1;
    }
    
    if (argc < 4)
    {
        print_usage(argc, argv, 0);
        return 1;
    }

    char* ip = argv[2];
    int port = 0;
    if (sscanf(argv[3], "%d", &port) != 1 || port < 1 || port > 65525)
    {
        print_usage(argc, argv, "port must be a number between 1 and 65535 inclusive");
        return 1;
    }

    ddmode default_dd = DD_ALL;
    if (argc >= 5)
        default_dd = parse_dd(argv[4]);

    if (default_dd == DD_INVALID)
    {
        print_usage(argc, argv, "default de-duplication mode may only be one of: all, none, sub, peer.");
        return 1;
    }

    std::map<int32_t, ddmode> specific_dd; // packet_type => de-duplication mode

    // parse the specific dd's
    {
        for (int i = 5; i < argc; ++i)
        {
            char pktype[32]; pktype[0] = '\0'; char* pk = pktype;
            char ddtype[32]; ddtype[0] = '\0'; char* dd = ddtype;
            char* x = argv[i];
            for (; *x != '\0' && *x != ':' && (pk - pktype < 31); *pk++ = *x++);
            if (*x != ':')
            {
                print_usage(argc, argv,
                    "invalid specific de-duplication specified, must be of format: packet:ddmode");
                return 1;
            }
            for (++x; *x != '\0' && (dd - ddtype < 31); *dd++ = *x++);
            *pk = '\0'; *dd = '\0';
            int packet = packet_id(pktype);
            ddmode mode = parse_dd(ddtype);
            if (packet > -1 && mode != DD_INVALID)
            {
                printf("packet: %d mode: %d\n", packet, mode);
                specific_dd.emplace(packet, mode);
            }
            else
            {
                print_usage(argc, argv,
                        "invalid specific de-duplication specified... check allowable dd/packet types.");
                return 1;
            }
        }
    }    

    int peer_max = 0;

    if (strlen(argv[1]) == 7 && memcmp(argv[1], "connect", 7) == 0)
    {
        // peer mode
        return peer_mode(ip, port);
    }
    else if (sscanf(argv[1], "%d", &peer_max) == 1 && peer_max > 1)
    {
        // main mode

        // spawn first peer before continuing to main mode
        if (fork() == 0)
        {
            // all our FDs are close on exec
            execlp(argv[0], argv[0], "connect", argv[2], argv[3], (char*)0);

            // should be unreachable
            fprintf(stderr, "Execlp failed, could not spawn peer process\n");
            return 10;
        }

        // continue to main mode
        return main_mode(ip, port, peer_max);
    }
    else
    {
        print_usage(argc, argv, "max-peers must be at least 1");
        return 1;
    }

}


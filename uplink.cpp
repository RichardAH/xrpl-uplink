#include "uplink.h"

#define SPACES \
"                                                                                                                    "
int print_usage(int argc, char** argv, const char* error)
{
    fprintf(stderr,
    "XRPL-Uplink v%s by Richard Holland / XRPL-Labs\n%s%s%s%s"
    "An XRPL peer-protocol endpoint for connecting local subscribers (applications) to the XRPL mesh network.\n"
    "Main-mode:\n"
    "\tThe process that subscribers connect to. Maintains a swarm of peer mode processes up to max-peers\n"
    "\tUsage: %s <max-peers> <first-peer-ip> <first-peer-port> \\\n"
    "\t       %.*s [<default-ddmode> [mtPACKET:ddmode] ...] \\\n"
    "\t       %.*s [sockdir=<path>] [dbdir=<path>] [keyfile=<path>]\n"
    "Peer-mode:\n"
    "\tConnects over TCP/IP to a specified XRPL peer, then bridges that peer to the hub (main-mode process).\n"
    "\tUsage: %s connect <peer-ip> <peer-port> \\\n"
    "\t       %.*s [sockdir=<path>] [keyfile=<path>]\n"
    "Path arguments:\n"
    "\tsockdir   - location of peer.sock and subscriber.sock.     [default = /var/run/xrpl-uplink/]\n"
    "\tdbdir     - (main mode only) location of peer database.    [default = /var/lib/xrpl-uplink/]\n"
    "\tkeyfile   - private key file for peer connections.         [default = /var/lib/xrpl-uplink/peer.key]\n"
    "De-duplication modes (ddmode):\n"
    "\tall       - de-duplicate all packets in both directions (subscriber <-> peers)\n"
    "\tnone      - do not de-duplicate any packets in either direction\n"
    "\tpeer      - only de-duplicate inbound packets from peers (forward all duplicates from subscribers)\n"
    "\tsub       - only de-duplicate outgoing packets from subscribers (forward all duplicates from peers)\n"
    "Note:\tThe first de-duplication mode specified on the command-line is the default mode applied to all packets.\n"
    "\tSubsequent modes can be attached to specific packet types, e.g. mtGET_LEDGER:none mtTRANSACTION:all\n"
    "Special ddmodes:\n"
    "\tdrop      - drop inbound packets from peers, de-duplicate outbound packets from subscribers\n"
    "\tdropn     - drop inbound packets from peers, do NOT de-duplicate outbound packets from subscribers\n"
    "\tblackhole - drop packets in both directions\n"
    "\tsquelch   - drop subscriber's outbound packets, but de-duplicate peer's inbound packets\n"
    "\tsquelchn  - drop subscriber's outbound packets, do NOT de-duplicate peer's inbound packets\n"
    "Packet Types:\n"
    "\tmtMANIFESTS mtPING mtCLUSTER mtENDPOINTS mtTRANSACTION mtGET_LEDGER mtLEDGER_DATA mtPROPOSE_LEDGER\n"
    "\tmtSTATUS_CHANGE mtHAVE_SET mtVALIDATION mtGET_OBJECTS mtGET_SHARD_INFO mtSHARD_INFO mtGET_PEER_SHARD_INFO\n"
    "\tmtPEER_SHARD_INFO mtVALIDATORLIST mtSQUELCH mtVALIDATORLISTCOLLECTION mtPROOF_PATH_REQ mtPROOF_PATH_RESPONSE\n"
    "\tmtREPLAY_DELTA_REQ mtREPLAY_DELTA_RESPONSE mtGET_PEER_SHARD_INFO_V2 mtPEER_SHARD_INFO_V2 mtHAVE_TRANSACTIONS\n"
    "\tmtTRANSACTIONS\n"
    "Example:\n"
    "       %s 10 r.ripple.com 51235 all mtGET_LEDGER:none\n",
    VERSION, 
    (error ? "\n" : ""), 
    (error ? "\u001b[31mError: " : ""),
    (error ? error : ""), 
    (error ? "\u001b[30m\n\n" : ""), 
    argv[0],
    (int)(strlen(argv[0])), SPACES,
    (int)(strlen(argv[0])), SPACES, argv[0],
    (int)(strlen(argv[0])), SPACES, argv[0]);
    return EC_PARAMS;
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

int main(int argc, char** argv)
{
    b58_sha256_impl = calc_sha_256; 
    if (sodium_init() < 0) {
        fprintf(stderr, "Could not init libsodium\n");
        return EC_SODIUM;
    }

    SSL_library_init();
    SSL_load_error_strings();
    OpenSSL_add_ssl_algorithms();

    if (argc < 4)
    {
        print_usage(argc, argv, 0);
        return EC_PARAMS;
    }

    uint32_t ip[4];
    char host[256]; host[sizeof(host) - 1] = '\0';
    strncpy(host, argv[2], sizeof(host) - 1);

    printf("host prelookup: %s\n", host);

    // check for valid ipv4 address and perform nslookup
    if (sscanf(host, "%u.%u.%u.%u", ip, ip+1, ip+2, ip+3) != 4 || 
        ip[0] > 255 || ip[1] > 255 || ip[2] > 255 || ip[3] > 255)
    {
        struct hostent* hn = gethostbyname(host);
        if (!hn)
        {
            print_usage(argc, argv, "invalid IP/hostname (IPv4 ONLY)");
            return EC_ADDR;
        }
       
        struct in_addr** addr_list = (struct in_addr **)hn->h_addr_list;
        char* new_host = inet_ntoa(*addr_list[0]);
        if (sscanf(new_host, "%u.%u.%u.%u", ip, ip+1, ip+2, ip+3) != 4 || 
            ip[0] > 255 || ip[1] > 255 || ip[2] > 255 || ip[3] > 255)
        {
            print_usage(argc, argv, "invalid IP after resolving hostname (IPv4 ONLY)");
            return EC_ADDR;
        }

        strncpy(host, new_host, sizeof(host) - 1);
    }

    printf("host postlookup: %s\n", host);

    int port = 0;
    if (sscanf(argv[3], "%d", &port) != 1 || port < 1 || port > 65525)
    {
        print_usage(argc, argv, "port must be a number between 1 and 65535 inclusive");
        return EC_PARAMS;
    }

    ddmode dd_default = DD_ALL;
    if (argc >= 5)
        dd_default = parse_dd(argv[4]);

    if (dd_default == DD_INVALID)
    {
        print_usage(argc, argv, "default de-duplication mode may only be one of: all, none, sub, peer.");
        return EC_PARAMS;
    }

    std::map<int32_t, ddmode> dd_specific; // packet_type => de-duplication mode

    char sock_path[PATH_MAX]; memset(sock_path, 0, PATH_MAX);
    char db_path[PATH_MAX];   memset(db_path, 0, PATH_MAX);
    char key_path[PATH_MAX];  memset(key_path, 0, PATH_MAX);

    // parse dds and remaining arguments
    {
        for (int i = 5; i < argc; ++i)
        {
            char pktype[PATH_MAX]; pktype[0] = '\0'; char* pk = pktype;
            char ddtype[PATH_MAX]; ddtype[0] = '\0'; char* dd = ddtype;
            char* x = argv[i];
            for (; *x != '\0' && *x != ':' && *x != '=' && (pk - pktype < (PATH_MAX-1)); *pk++ = *x++);

            int is_path = *x == '=';

            if (*x != ':' && *x != '=')
            {
                print_usage(argc, argv,
                    "invalid argment expecting packet:ddmode or sockdir=path or dbdir=path");
                return EC_PARAMS;
            }

            for (++x; *x != '\0' && (dd - ddtype < (PATH_MAX-1)); *dd++ = *x++);
            *pk = '\0'; *dd = '\0';

            if (is_path)
            {
                if (strcmp(pktype, "sockdir") == 0)
                {
                    if (sock_path[0] != 0)
                    {
                        print_usage(argc, argv,
                            "sockdir specified more than once");
                        return EC_PARAMS;
                    }

                    strcpy(sock_path, ddtype);
                }
                else if (strcmp(pktype, "dbdir") == 0)
                {
                    if (db_path[0] != 0)
                    {
                        print_usage(argc, argv,
                            "dbdir specified more than once");
                        return EC_PARAMS;
                    }
                    if (strcmp(argv[1], "connect") == 0)
                    {
                        print_usage(argc, argv,
                            "cannot specify dbdir in peer (connect) mode");
                        return EC_PARAMS;
                    }
                    strcpy(db_path, ddtype);
                }
                else if (strcmp(pktype, "keyfile") == 0)
                {
                    if (key_path[0] != 0)
                    {
                        print_usage(argc, argv,
                            "keyfile specified more than once");
                        return EC_PARAMS;
                    }
                    strcpy(key_path, ddtype);
                }
                else
                {
                    print_usage(argc, argv,
                        "invalid argument expecting sockdir=path or dbdir=path");
                    return EC_PARAMS;
                }
            }
            else
            {
                int packet = packet_id(pktype);
                ddmode mode = parse_dd(ddtype);
                if (packet > -1 && mode != DD_INVALID)
                {
                    printf("packet: %d mode: %d\n", packet, mode);
                    dd_specific.emplace(packet, mode);
                }
                else
                {
                    print_usage(argc, argv,
                        "invalid specific de-duplication specified... check allowable dd/packet types.");
                    return EC_PARAMS;
                }
            }
        }
    }

    if (db_path[0] == 0)
        strncpy(db_path, DEFAULT_DB_PATH, sizeof(db_path) - 1);

    if (sock_path[0] == 0)
        strncpy(sock_path, DEFAULT_SOCK_PATH, sizeof(sock_path) - 1);

    // build keyfile path
    if (key_path[0] == 0)
    {
        strncpy(key_path, DEFAULT_DB_PATH, sizeof(key_path) - 1);
        strncat(key_path, "/", sizeof(key_path) - 1);
        strncat(key_path, KEY_FN, sizeof(key_path) - 1);
    }

    // build peer.sock path
    char peer_path[PATH_MAX]; memset(peer_path, 0, PATH_MAX);
    {
        strncpy(peer_path, sock_path, sizeof(peer_path) - 1);
        strncat(peer_path, "/", sizeof(peer_path) - 1);
        strncat(peer_path, PEER_FN, sizeof(peer_path) - 1);
    }

    // build subscriber.sock path
    char subscriber_path[PATH_MAX]; memset(subscriber_path, 0, PATH_MAX);
    {
        strncpy(subscriber_path, sock_path, sizeof(subscriber_path) - 1);
        strncat(subscriber_path, "/", sizeof(subscriber_path) - 1);
        strncat(subscriber_path, SUBSCRIBER_FN, sizeof(subscriber_path) - 1);
    }

    // ensure db path exists
    if (!(mkdir(db_path, 0700) == 0 || errno == EEXIST))
    {
        fprintf(stderr, "Could not create/access directory: `%s` for database files\n", db_path);
        return EC_PARAMS;
    }

    // build peer.db path
    {
        strncat(db_path, "/", sizeof(db_path) - 1);
        strncat(db_path, DB_FN, sizeof(db_path) - 1);
    }

    // ensure socket path exists
    if (!(mkdir(sock_path, 0700) == 0 || errno == EEXIST))
    {
        fprintf(stderr, "Could not create/access directory: `%s` for socket files\n", sock_path);
        return EC_PARAMS;
    }

    // load the private key or create specified keyfile if it doesn't already exist
    uint8_t key[32];
    if (access(key_path, F_OK) == 0)
    {
        int fd = open(key_path, O_RDONLY);
        if (fd < 0 || read(fd, key, 32) != 32)
        {
            fprintf(stderr, "Could not open keyfile %s for reading\n", key_path);
            return EC_PARAMS;
        }
        close(fd);
    }
    else
    {
        fprintf(stderr, "Warning: creating keyfile %s with random key (file doesn't yet exist)\n", key_path);

        // create the keyfile
        int fd = open(key_path, O_WRONLY | O_CREAT, 0600);
        if (fd < 0)
        {
            fprintf(stderr, "Could not open keyfile %s for writing\n", key_path);
            return EC_PARAMS;
        }
        int rnd = open("/dev/urandom", O_RDONLY);
        if (rnd < 0 || read(rnd, key, 32) != 32) // RH TODO: not every random 32 byte seq is a valid secp256k1 key
        {
            fprintf(stderr, "Could read /dev/urandom to generate key\n");
            return EC_PARAMS;
        }

        if (write(fd, key, 32) !=32)
        {
            fprintf(stderr, "Could not write key to keyfile %s\n", key_path);
            return EC_PARAMS;
        }
        close(rnd);
        close(fd);
    }

    int peer_max = 0;

    if (strlen(argv[1]) == 7 && memcmp(argv[1], "connect", 7) == 0)
    {
        // peer mode
        return peer_mode(host, port, peer_path, key, dd_default, dd_specific);
    }
    else if (sscanf(argv[1], "%d", &peer_max) == 1 && peer_max >= 1)
    {
        // main mode

        // spawn first peer before continuing to main mode
        if (fork() == 0)
        {
            if (strcmp(sock_path, DEFAULT_SOCK_PATH) == 0)
            {
                // all our FDs are close on exec
                execlp(argv[0], argv[0], "connect", host, argv[3], (char*)0);
            }
            else
            {
                char sock_arg[48];
                strcpy(sock_arg, "sockdir=");
                strcat(sock_arg, sock_path);

                // all our FDs are close on exec
                execlp(argv[0], argv[0], "connect", argv[2], argv[3], sock_arg, (char*)0);
            }

            // should be unreachable
            fprintf(stderr, "Execlp failed, could not spawn peer process\n");
            return EC_SPAWN;
        }

        // continue to main mode
        return main_mode(host, port, peer_max, peer_path, subscriber_path, db_path, key, dd_default, dd_specific);
    }
    else
    {
        print_usage(argc, argv, "max-peers must be at least 1");
        return EC_PARAMS;
    }

}


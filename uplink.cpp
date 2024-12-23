#include "uplink.h"

#define SPACES \
"                                                                                                                    "
int print_usage(int argc, char** argv, const char* error)
{
    fprintf(stderr,
    "XRPL-Uplink v%s by Richard Holland / XRPL-Labs\n%s%s%s"
    "An XRPL peer-protocol endpoint for connecting local subscribers (applications) to the XRPL mesh network.\n"
    "Main-mode:\n"
    "\tThe process that subscribers connect to. Maintains a swarm of peer mode processes up to max-peers\n"
    "\tUsage: %s <max-peers> <first-peer-ip> <first-peer-port> <network id>\\\n"
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
    "Packet types:\n"
    "\tmtMANIFESTS mtPING mtCLUSTER mtENDPOINTS mtTRANSACTION mtGET_LEDGER mtLEDGER_DATA mtPROPOSE_LEDGER\n"
    "\tmtSTATUS_CHANGE mtHAVE_SET mtVALIDATION mtGET_OBJECTS mtGET_SHARD_INFO mtSHARD_INFO mtGET_PEER_SHARD_INFO\n"
    "\tmtPEER_SHARD_INFO mtVALIDATORLIST mtSQUELCH mtVALIDATORLISTCOLLECTION mtPROOF_PATH_REQ mtPROOF_PATH_RESPONSE\n"
    "\tmtREPLAY_DELTA_REQ mtREPLAY_DELTA_RESPONSE mtGET_PEER_SHARD_INFO_V2 mtPEER_SHARD_INFO_V2 mtHAVE_TRANSACTIONS\n"
    "\tmtTRANSACTIONS\n"
    "Note:\tmtPING and mtENDPOINTS packets are processed by uplink but are not normally forwarded to subscribers, unless\n"
    "\ta non-dropping ddmode is attached to that packet type (see above). In this case they are still processed but\n"
    "\tare also forwarded to peers according to that ddmode.\n"
    "Example:\n"
    "       %s 10 r.ripple.com 51235 all mtGET_LEDGER:none\n",
    VERSION, 
    (error ? "\n" : ""), 
    (error ? error : ""), 
    (error ? "\n" : ""), 
    argv[0],
    (int)(strlen(argv[0])), SPACES,
    (int)(strlen(argv[0])), SPACES, argv[0],
    (int)(strlen(argv[0])), SPACES, argv[0]);
    return EC_PARAMS;
}

// turn this process into a connect process
void exec_connect(const char* bin, IP const& ip, int port, int netid, const char* sock_path = 0, const char* msg = 0)
{
    
    std::string host = str_ip(ip);
    char port_str[10];
    snprintf(port_str, 10, "%d", port);

    char netid_str[10];
    snprintf(netid_str, 10, "%d", netid);

    if (DEBUG)
        printl("%s %s %s\n", (msg ? msg : "exec_connect"), host.c_str(), port_str);

    // all our FDs are close on exec
    if (sock_path)
    {
        char sock_arg[256];
        strcpy(sock_arg, "sockdir=");
        strcat(sock_arg, sock_path);
        execlp(bin, bin, "connect", host.c_str(), port_str, netid_str, sock_arg, (char*)0);
    }
    else
        execlp(bin, bin, "connect", host.c_str(), port_str, (char*)0);
    die(EC_SPAWN, "could not spawn connect processor");
}

int main(int argc, char** argv)
{

    pid_t my_pid = getpid();


    b58_sha256_impl = calc_sha_256; 
    if (sodium_init() < 0) {
        printl("Could not init libsodium\n");
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

    // parse cmdline host/IP
    IP host_ip;
    {
        char host_str[256]; host_str[sizeof(host_str) - 1] = '\0';
        strncpy(host_str, argv[2], sizeof(host_str) - 1);
        struct hostent* hn = gethostbyname(host_str);
        if (hn)
        {
            struct in_addr** addr_list = (struct in_addr **)hn->h_addr_list;
            char* new_host = inet_ntoa(*addr_list[0]);
            host_str[0] = 0;
            strncpy(host_str, new_host, sizeof(host_str) - 1);
        }
        
        if (DEBUG)
            printl("host lookup: %s\n", host_str);

        std::optional<IP> p = canonicalize_ip(host_str);
        if (!p)
        {
            printl("invalid IP/hostname: %s\n", argv[2]);
            return EC_ADDR;
        }

        // copy into host_ip
        host_ip = *p;

        if (DEBUG)
            printh(host_ip.b, 16, "host ip (canonical):");
    }
    
    // parse cmdline port
    int port = 0;
    {
        char port_str[10];
        if (sscanf(argv[3], "%d", &port) != 1 || port < 1 || port > 65535)
        {
            print_usage(argc, argv, "port must be a number between 1 and 65535 inclusive");
            return EC_PARAMS;
        }
        snprintf(port_str, sizeof(port_str), "%u", port);
    }

    int netid = 0;
    {
        char netid_str[10];
        if (sscanf(argv[3], "%d", &netid) != 1 || port < 0 || port > 65535)
        {
            print_usage(argc, argv, "netid must be a number between 1 and 65535 inclusive");
            return EC_PARAMS;
        }
        snprintf(netid_str, sizeof(netid_str), "%u", netid);
    }

    ddmode dd_default = DD_NOT_SET;
    if (argc >= 6)
        dd_default = parse_dd(argv[5]);

    if (dd_default == DD_INVALID)
    {
        print_usage(argc, argv, "default de-duplication mode may only be one of: all, none, sub, peer.");
        return EC_PARAMS;
    }

    std::map<uint8_t, ddmode> dd_specific; // packet_type => de-duplication mode

    char sock_path[PATH_MAX]; memset(sock_path, 0, PATH_MAX);
    char db_path[PATH_MAX];   memset(db_path, 0, PATH_MAX);
    char key_path[PATH_MAX];  memset(key_path, 0, PATH_MAX);

    // parse dds and remaining arguments
    {
        for (int i = 6; i < argc; ++i)
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
                uint8_t packet = packet_id(pktype);
                ddmode mode = parse_dd(ddtype);
                if (packet > -1 && mode != DD_INVALID)
                {
                    printl("parsed ddmode -- packet: %d mode: %d\n", packet, mode);
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

    bool db_path_is_default = false;
    bool sock_path_is_default = false;

    if (db_path[0] == 0)
    {
        strncpy(db_path, DEFAULT_DB_PATH, sizeof(db_path) - 1);
        db_path_is_default = true;
    }

    if (sock_path[0] == 0)
    {
        sock_path_is_default = true;
        strncpy(sock_path, DEFAULT_SOCK_PATH, sizeof(sock_path) - 1);
    }

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
        printl("Could not create/access directory: `%s` for database files\n", db_path);
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
        printl("Could not create/access directory: `%s` for socket files\n", sock_path);
        return EC_PARAMS;
    }


    int rnd_fd = open("/dev/urandom", O_RDONLY);
    if (rnd_fd < 0)
    {
        printl("can't open /dev/urandom");
        return EC_RNG;
    }
    fd_set_flags(rnd_fd, O_CLOEXEC);

    // load the private key or create specified keyfile if it doesn't already exist
    uint8_t key[32];
    if (access(key_path, F_OK) == 0)
    {
        int fd = open(key_path, O_RDONLY);
        if (fd < 0 || read(fd, key, 32) != 32)
        {
            printl("Could not open keyfile %s for reading\n", key_path);
            return EC_PARAMS;
        }
        close(fd);
    }
    else
    {
        printl("Warning: creating keyfile %s with random key (file doesn't yet exist)\n", key_path);

        // create the keyfile
        int fd = open(key_path, O_WRONLY | O_CREAT, 0600);
        if (fd < 0)
        {
            printl("Could not open keyfile %s for writing\n", key_path);
            return EC_PARAMS;
        }
        if (read(rnd_fd, key, 32) != 32) // RH TODO: not every random 32 byte seq is a valid secp256k1 key
        {
            printl("Could read /dev/urandom to generate key\n");
            return EC_PARAMS;
        }

        if (write(fd, key, 32) !=32)
        {
            printl("Could not write key to keyfile %s\n", key_path);
            return EC_PARAMS;
        }
        close(fd);
    }
    

    int peer_max = 0;

    if (strlen(argv[1]) == 7 && memcmp(argv[1], "connect", 7) == 0)
    {
        // peer mode
        int rc = peer_mode(&host_ip, &port, netid, peer_path, key, dd_default, dd_specific, rnd_fd);
        if (rc == EC_BUSY)
            // the peer may be busy, however since we want the commandline of the process
            // to always reflect the actual peer the process is connected to we will exec again
            exec_connect(argv[0], host_ip, port, netid, (sock_path_is_default ? 0 : sock_path), "peer busy, trying:");
        else
            return rc;
    }
    else if (sscanf(argv[1], "%d", &peer_max) == 1 && peer_max >= 1)
    {
        // main mode

        if (peer_max > MAX_FDS)
        {
            printl("peer_max can't exceed MAX_FDS = %d\n", MAX_FDS);
            return EC_GENERIC;
        }

        // spawn first peer before continuing to main mode
        if (fork() == 0)
            exec_connect(argv[0], host_ip, port, netid, (sock_path_is_default ? 0 : sock_path), "peer busy, trying:");


        // continue to main mode
        int rc = 
            main_mode(&host_ip, &port, netid, peer_max, peer_path, subscriber_path, db_path, key,
                dd_default == DD_NOT_SET ? DD_ALL : dd_default, dd_specific, rnd_fd);

        // mainmode can return asking to become a peer (it forks internally to do this)
        // if so service the request here
        if (rc == EC_BECOME_PEER)
            exec_connect(argv[0], host_ip, port, netid, (sock_path_is_default ? 0 : sock_path),
                "spawning peermode process...");
        
        return rc;
    }
    else
    {
        print_usage(argc, argv, "max-peers must be at least 1");
        return EC_PARAMS;
    }

}


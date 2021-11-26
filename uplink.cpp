#include "uplink.h"

#define SPACES \
"                                                                                                                    "    
int print_usage(int argc, char** argv, const char* error)
{
    fprintf(stderr, 
    "XRPL-Uplink v%s by Richard Holland / XRPL-Labs\n%s%s"
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
    "\tsockdir - location of peer.sock and subscriber.sock.     [default = /var/run/xrpl-uplink/]\n"
    "\tdbdir   - (main mode only) location of peer database.    [default = /var/lib/xrpl-uplink/]\n"
    "\tkeyfile - private key file for peer connections.         [default = /var/lib/xrpl-uplink/peer.key]\n"
    "De-duplication modes (ddmode):\n"
    "\tall     - de-duplicate all packets in both directions (subscriber <-> peers)\n"
    "\tnone    - do not de-duplicate any packets in either direction\n"
    "\tpeer    - only de-duplicate inbound packets from peers (forward all duplicates from subscribers)\n"
    "\tsub     - only de-duplicate outgoing packets from subscribers (forward all duplicates from peers)\n"
    "\tNote: The first de-duplication mode specified on the command-line is the default mode applied to all packets\n"
    "\tSubsequent modes can be attached to specific packet types, e.g. mtGET_LEDGER:none mtTRANSACTION:all\n"
    "Packet Types:\n"
    "\tmtMANIFESTS mtPING mtCLUSTER mtENDPOINTS mtTRANSACTION mtGET_LEDGER mtLEDGER_DATA mtPROPOSE_LEDGER\n"
    "\tmtSTATUS_CHANGE mtHAVE_SET mtVALIDATION mtGET_OBJECTS mtGET_SHARD_INFO mtSHARD_INFO mtGET_PEER_SHARD_INFO\n"
    "\tmtPEER_SHARD_INFO mtVALIDATORLIST mtSQUELCH mtVALIDATORLISTCOLLECTION mtPROOF_PATH_REQ mtPROOF_PATH_RESPONSE\n"
    "\tmtREPLAY_DELTA_REQ mtREPLAY_DELTA_RESPONSE mtGET_PEER_SHARD_INFO_V2 mtPEER_SHARD_INFO_V2 mtHAVE_TRANSACTIONS\n"
    "\tmtTRANSACTIONS\n"
    "Example:\n"
    "       %s 10 r.ripple.com 51235 all mtGET_LEDGER:none\n",
    VERSION, (error ? error : ""), (error ? "\n" : ""), argv[0],
    strlen(argv[0]), SPACES,
    strlen(argv[0]), SPACES,
    argv[0], 
    strlen(argv[0]), SPACES,
    argv[0]); 
    return 1;
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
/*
#define TEST_HASH(x)\
    { \
        Hash h = hash(x, strlen(x));\
        printf("%.*s: ", 32, x);\
        for (int i = 0; i < 32; ++i)\
            printf("%02x", (unsigned char)(h.b[i]));\
        printf("\n");\
    }
    TEST_HASH("hello world");
    TEST_HASH("hello world");
    TEST_HASH(
            "hello world hello world hello world hello world "
            "hello world hello world hello world hello world "
            "hello world hello world hello world hello world "
            "hello world hello world hello world hello world "
            "hello world hello world hello world hello world "
            "hello world hello world hello world hello world "
            "hello world hello world hello world");

    TEST_HASH(
            "hello world hell1 world hello world hello world "
            "hello world hello world hello world hello world "
            "hello world hello world hello world hello world "
            "hello world hello world hello world hello world "
            "hello world hello world hello world hello world "
            "hello world hello world hello world hello world "
            "hello world hello world hello world");
   
    return 0;
*/
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

    ddmode dd_default = DD_ALL;
    if (argc >= 5)
        dd_default = parse_dd(argv[4]);

    if (dd_default == DD_INVALID)
    {
        print_usage(argc, argv, "default de-duplication mode may only be one of: all, none, sub, peer.");
        return 1;
    }

    std::map<int32_t, ddmode> dd_specific; // packet_type => de-duplication mode

    char sock_path[PATH_MAX];   sock_path[0] = '\0';
    char db_path[PATH_MAX];     db_path[0] = '\0';
    char key_path[PATH_MAX];    key_path[0] = '\0';
    
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
                return 1;
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
                        return 1;
                    }
                    
                    strcpy(sock_path, ddtype);
                }
                else if (strcmp(pktype, "dbdir") == 0)
                {
                    if (db_path[0] != 0)
                    {
                        print_usage(argc, argv,
                            "dbdir specified more than once");
                        return 1;
                    }
                    if (strcmp(argv[1], "connect") == 0)
                    {
                        print_usage(argc, argv,
                            "cannot specify dbdir in peer (connect) mode");
                        return 1;
                    }
                    strcpy(db_path, ddtype);
                }
                else if (strcmp(pktype, "keyfile") == 0)
                {
                    if (key_path[0] != 0)
                    {
                        print_usage(argc, argv,
                            "keyfile specified more than once");
                        return 1;
                    }
                    strcpy(key_path, ddtype);
                }
                else
                {
                    print_usage(argc, argv,
                        "invalid argument expecting sockdir=path or dbdir=path");
                    return 1;
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
                    return 1;
                }
            }
        }
    }    

    if (db_path[0] == 0)
        strcpy(db_path, DEFAULT_DB_PATH);

    if (sock_path[0] == 0)
        strcpy(sock_path, DEFAULT_SOCK_PATH);

    if (key_path[0] == 0)
    {
        strcpy(key_path, DEFAULT_DB_PATH);
        strcat(key_path, "/");
        strcat(key_path, KEY_FN);
    }
    
    // ensure socket path exists
    if (!(mkdir(sock_path, 0700) == 0 || errno == EEXIST))
    {
        fprintf(stderr, "Could not create/access directory: `%s` for socket files\n", sock_path);
        return 1;
    }

    // ensure db path exists
    if (!(mkdir(db_path, 0700) == 0 || errno == EEXIST))
    {
        fprintf(stderr, "Could not create/access directory: `%s` for database files\n", db_path);
        return 1;
    }

    // load the private key or create specified keyfile if it doesn't already exist
    uint8_t key[32];
    if (access(key_path, F_OK) == 0)
    {
        int fd = open(key_path, O_RDONLY);
        if (fd < 0 || read(fd, key, 32) != 32)
        {
            fprintf(stderr, "Could not open keyfile %s for reading\n", key_path);
            return 1;
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
            return 1;
        }
        int rnd = open("/dev/urandom", O_RDONLY);
        if (rnd < 0 || read(rnd, key, 32) != 32) // RH TODO: not every random 32 byte seq is a valid secp256k1 key
        {
            fprintf(stderr, "Could read /dev/urandom to generate key\n");
            return 1;
        }

        if (write(fd, key, 32) !=32)
        {
            fprintf(stderr, "Could not write key to keyfile %s\n", key_path);
            return 1;
        }
        close(rnd);
        close(fd);
    }
    
    int peer_max = 0;

    if (strlen(argv[1]) == 7 && memcmp(argv[1], "connect", 7) == 0)
    {
        // peer mode
        return peer_mode(ip, port, sock_path, key, dd_default, dd_specific);
    }
    else if (sscanf(argv[1], "%d", &peer_max) == 1 && peer_max > 1)
    {
        // main mode

        // ensure the db path exists
        if (!(mkdir(db_path, 0700) == 0 || errno == EEXIST))
        {
            fprintf(stderr, "Could not create directory: `%s` for database files\n", db_path);
            return 1;
        }

        // spawn first peer before continuing to main mode
        if (fork() == 0)
        {
            if (strcmp(sock_path, DEFAULT_SOCK_PATH) == 0)
            {
                // all our FDs are close on exec
                execlp(argv[0], argv[0], "connect", argv[2], argv[3], (char*)0);
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
            return 10;
        }

        // continue to main mode
        return main_mode(ip, port, peer_max, sock_path, db_path, key, dd_default, dd_specific);
    }
    else
    {
        print_usage(argc, argv, "max-peers must be at least 1");
        return 1;
    }

}

